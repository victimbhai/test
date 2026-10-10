# KB-44: Cloud IAM Privilege Escalation Chains

## Overview

Advanced cloud IAM attacks across AWS, Azure, and GCP covering confused deputy, PRT theft, service account impersonation, and cross-account escalation chains.

---

## 1. AWS IAM Privilege Escalation

### 1.1 Confused Deputy Attack

```
Scenario: Third-party service assumes IAM role on your behalf
Attack: Attacker uses the same service to assume YOUR role

Vulnerable trust policy:
{
  "Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::THIRD_PARTY:root"},
  "Action": "sts:AssumeRole"
  // Missing ExternalId condition!
}

Fix: Always require aws:SourceArn or ExternalId condition
```

### 1.2 Common Escalation Paths

| Starting Permission | Escalation Path | Result |
|---------------------|-----------------|--------|
| iam:CreatePolicyVersion | Create new policy version with admin | Admin |
| iam:SetDefaultPolicyVersion | Set old permissive version as default | Elevated |
| iam:PassRole + lambda:CreateFunction | Create Lambda with admin role | Admin |
| iam:PassRole + ec2:RunInstances | Launch EC2 with admin instance profile | Admin |
| sts:AssumeRole | Assume cross-account role | Lateral |
| ssm:SendCommand | Execute commands on EC2 with attached role | Varies |
| lambda:UpdateFunctionCode | Inject code into existing Lambda | Lambda's role |

### 1.3 CI/CD OIDC Trust Weakness

```bash
# Check if GitHub Actions OIDC role has weak trust
aws iam get-role --role-name github-deploy-role \
  --query 'Role.AssumeRolePolicyDocument' --output json

# Weak: no branch/workflow restriction
# Any workflow in the repo can assume the role
# Any fork PR (if allowed) can assume the role
```

---

## 2. Azure AD / Entra ID Attacks

### 2.1 Primary Refresh Token (PRT) Theft

```
PRT = SSO token that provides access to all Azure AD-integrated apps

Theft methods:
1. Mimikatz: sekurlsa::cloudap (from LSASS)
2. ROADtools: roadtx prt (from device TPM)
3. AADInternals: Export-AADIntUserPRT

Usage: PRT can be used to get access tokens for any Azure resource
```

### 2.2 Guest User Abuse

```
Azure AD guests may have excessive permissions:
1. List all users in tenant (default guest permission)
2. Read group memberships
3. Enumerate applications and service principals
4. Access SharePoint/Teams if not restricted

Escalation: Guest -> Member via invitation policy abuse
```

### 2.3 Tenant Confusion

```
Multi-tenant apps may not properly validate tenant ID
Attack: Authenticate in attacker's tenant, access victim's resources

Test: Change tid claim in token (if signature not validated properly)
Or: Register app in attacker tenant, request access to victim tenant
```

---

## 3. GCP IAM Attacks

### 3.1 Service Account Impersonation Chain

```bash
# If you have iam.serviceAccounts.getAccessToken on a SA:
gcloud auth print-access-token --impersonate-service-account=target-sa@project.iam.gserviceaccount.com

# Chained impersonation:
# SA-A can impersonate SA-B, SA-B can impersonate SA-C (admin)
# User -> SA-A -> SA-B -> SA-C (admin access)

# Find impersonation paths:
gcloud iam service-accounts get-iam-policy target-sa@project.iam.gserviceaccount.com
```

### 3.2 Metadata Server Token Theft

```bash
# From compromised GCP VM/Cloud Function/Cloud Run:
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Get project-level access token
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform"
```

### 3.3 Default Service Account Abuse

```
GCP default compute SA has Editor role on the project
Any VM/function using default SA can:
- Read/write Cloud Storage
- Manage Compute instances
- Access Cloud SQL
- Modify IAM (if not restricted)
```

---

## 4. Cross-Cloud Escalation

### 4.1 OIDC Federation Abuse

```
Cloud providers trust OIDC tokens from each other:
- AWS -> Azure AD (via OIDC federation)
- GCP -> GitHub Actions (via Workload Identity)
- Azure -> AWS (via external identity)

Attack: Compromise one cloud, pivot to another via federated trust
```

## References

- AWS IAM Privilege Escalation (Rhino Security Labs)
- Azure AD Attack Paths (SpecterOps)
- GCP Privilege Escalation (GitLab research)
- Confused Deputy Problem (AWS documentation)
