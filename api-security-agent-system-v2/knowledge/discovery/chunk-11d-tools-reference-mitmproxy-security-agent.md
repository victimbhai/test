# Tools Reference: mitmproxy Security Testing & Custom Python API Testing — Agent Chunk 11d
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Use mitmproxy with custom security testing addons and build reusable Python scripts for automated API security testing (IDOR, auth bypass, mass assignment, method enumeration, rate limiting)
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Deploy mitmproxy in interactive, web, dump, reverse proxy, or transparent mode for API traffic interception. Use the APISecurityTester mitmproxy addon to automatically detect in real-time: missing security headers, server version disclosure, stack traces in responses, secrets in response bodies, permissive CORS configurations, CORS origin reflection, JWT algorithm weaknesses. Build custom Python testing scripts using the APISecurityTester class for: IDOR testing (iterating resource IDs), HTTP method enumeration, rate limit testing, auth bypass testing (no auth, empty bearer, null token, undefined token), and mass assignment testing (injecting hidden fields like role, is_admin, permissions).

---

### 8.10 mitmproxy

**Purpose:** Interactive TLS-capable intercepting proxy for API traffic analysis
with powerful scripting capabilities in Python.

**Installation:**
```bash
pip3 install mitmproxy

# Or via Docker
docker pull mitmproxy/mitmproxy
docker run --rm -it -p 8080:8080 mitmproxy/mitmproxy
```

**API-Specific Usage:**

```bash
# Interactive console mode
mitmproxy --listen-port 8080

# Web interface mode
mitmweb --listen-port 8080 --web-port 8081

# Dump mode with API filtering
mitmdump --listen-port 8080 \
  --set flow_detail=3 \
  "~d api.target.com & ~c 200"

# Record traffic for replay
mitmdump --listen-port 8080 -w api_traffic.flow

# Replay recorded traffic
mitmdump -c api_traffic.flow

# Reverse proxy mode (for testing without client proxy configuration)
mitmproxy --mode reverse:https://api.target.com --listen-port 8443

# Transparent proxy mode
mitmproxy --mode transparent --listen-port 8080
```

**mitmproxy API Security Testing Script:**

```python
# api_security_test.py - mitmproxy addon for API security testing
from mitmproxy import http, ctx
import json
import re

class APISecurityTester:
    """Addon that analyzes API traffic for security issues in real time."""

    def __init__(self):
        self.findings = []

    def response(self, flow: http.HTTPFlow):
        self._check_security_headers(flow)
        self._check_information_disclosure(flow)
        self._check_cors(flow)
        self._check_auth_tokens(flow)

    def _check_security_headers(self, flow):
        headers = flow.response.headers
        missing = []
        if 'x-content-type-options' not in headers:
            missing.append('X-Content-Type-Options')
        if 'x-frame-options' not in headers:
            missing.append('X-Frame-Options')
        if 'strict-transport-security' not in headers:
            missing.append('Strict-Transport-Security')
        if 'cache-control' not in headers:
            content_type = headers.get('content-type', '')
            if 'application/json' in content_type:
                missing.append('Cache-Control (API response)')
        if missing:
            self._add_finding('MISSING_HEADERS', flow,
                              f"Missing: {', '.join(missing)}")

    def _check_information_disclosure(self, flow):
        headers = flow.response.headers
        # Check for server version disclosure
        server = headers.get('server', '')
        if re.search(r'[\d.]+', server):
            self._add_finding('SERVER_VERSION', flow,
                              f"Server header discloses version: {server}")
        # Check for technology headers
        for header in ('x-powered-by', 'x-aspnet-version',
                       'x-aspnetmvc-version'):
            if header in headers:
                self._add_finding('TECH_DISCLOSURE', flow,
                                  f"{header}: {headers[header]}")
        # Check response body for sensitive patterns
        if flow.response.content:
            try:
                body = flow.response.content.decode('utf-8', errors='ignore')
                if 'stack trace' in body.lower() or 'traceback' in body.lower():
                    self._add_finding('STACK_TRACE', flow,
                                      "Response contains stack trace")
                if re.search(r'(password|secret|api.?key)\s*[:=]', body, re.I):
                    self._add_finding('SECRET_IN_RESPONSE', flow,
                                      "Response may contain secrets")
            except Exception:
                pass

    def _check_cors(self, flow):
        headers = flow.response.headers
        acao = headers.get('access-control-allow-origin', '')
        if acao == '*':
            acac = headers.get('access-control-allow-credentials', '')
            if acac.lower() == 'true':
                self._add_finding('CORS_CRITICAL', flow,
                                  "ACAO:* with credentials=true")
            else:
                self._add_finding('CORS_PERMISSIVE', flow,
                                  "Wildcard CORS origin")
        elif acao and acao != '':
            origin = flow.request.headers.get('origin', '')
            if origin and acao == origin:
                self._add_finding('CORS_REFLECTION', flow,
                                  f"CORS reflects origin: {origin}")

    def _check_auth_tokens(self, flow):
        auth = flow.request.headers.get('authorization', '')
        if auth.startswith('Bearer '):
            token = auth[7:]
            parts = token.split('.')
            if len(parts) == 3:
                # JWT token detected
                try:
                    import base64
                    header = json.loads(
                        base64.urlsafe_b64decode(parts[0] + '==')
                    )
                    if header.get('alg', '').lower() == 'none':
                        self._add_finding('JWT_ALG_NONE', flow,
                                          "JWT uses 'none' algorithm")
                    if header.get('alg', '').lower() == 'hs256':
                        self._add_finding('JWT_WEAK_ALG', flow,
                                          "JWT uses HS256 (check for key weakness)")
                except Exception:
                    pass

    def _add_finding(self, finding_type, flow, details):
        finding = {
            'type': finding_type,
            'url': flow.request.pretty_url,
            'method': flow.request.method,
            'details': details,
        }
        self.findings.append(finding)
        ctx.log.warn(f"[{finding_type}] {flow.request.method} "
                     f"{flow.request.pretty_url}: {details}")

addons = [APISecurityTester()]
```

### 8.11 Custom Python Scripting for API Testing

**Purpose:** Python's requests and httpx libraries provide the most flexible approach
for custom API security testing scripts.

**Core API Testing Library:**

```python
#!/usr/bin/env python3
"""Reusable API security testing utilities."""
import requests
import json
import time
import urllib3
from urllib.parse import urlparse

# Disable SSL warnings for testing environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class APISecurityTester:
    """Base class for API security testing."""

    def __init__(self, base_url, auth_token=None, proxy=None,
                 verify_ssl=True, rate_limit=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = verify_ssl

        if auth_token:
            self.session.headers['Authorization'] = f'Bearer {auth_token}'
        self.session.headers['Content-Type'] = 'application/json'
        self.session.headers['User-Agent'] = 'APISecurityTester/1.0'

        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

        self.rate_limit = rate_limit  # requests per second
        self.last_request_time = 0

    def _rate_limit_wait(self):
        if self.rate_limit:
            elapsed = time.time() - self.last_request_time
            wait = (1.0 / self.rate_limit) - elapsed
            if wait > 0:
                time.sleep(wait)
            self.last_request_time = time.time()

    def request(self, method, path, **kwargs):
        self._rate_limit_wait()
        url = f"{self.base_url}{path}"
        response = self.session.request(method, url, **kwargs)
        return response

    def test_idor(self, path_template, id_list, expected_status=403):
        """Test for IDOR by accessing resources with different IDs."""
        results = []
        for resource_id in id_list:
            path = path_template.replace('{id}', str(resource_id))
            response = self.request('GET', path)
            is_vulnerable = response.status_code == 200
            results.append({
                'id': resource_id,
                'status': response.status_code,
                'vulnerable': is_vulnerable,
                'response_size': len(response.content),
            })
            if is_vulnerable:
                print(f"  [VULN] IDOR: {path} returned {response.status_code}")
        return results

    def test_method_enumeration(self, path):
        """Test which HTTP methods are accepted for an endpoint."""
        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE',
                   'OPTIONS', 'HEAD', 'TRACE']
        results = {}
        for method in methods:
            response = self.request(method, path)
            results[method] = {
                'status': response.status_code,
                'content_length': len(response.content),
            }
        return results

    def test_rate_limiting(self, path, method='GET', count=100):
        """Test rate limiting by sending rapid requests."""
        results = []
        for i in range(count):
            response = self.request(method, path)
            results.append({
                'request_num': i + 1,
                'status': response.status_code,
                'retry_after': response.headers.get('Retry-After'),
            })
            if response.status_code == 429:
                print(f"  Rate limited at request #{i + 1}")
                break
        return results

    def test_auth_bypass(self, path):
        """Test authentication bypass techniques."""
        results = {}
        original_auth = self.session.headers.get('Authorization')

        # Test without auth
        del self.session.headers['Authorization']
        r = self.request('GET', path)
        results['no_auth'] = r.status_code

        # Test with empty bearer
        self.session.headers['Authorization'] = 'Bearer '
        r = self.request('GET', path)
        results['empty_bearer'] = r.status_code

        # Test with null token
        self.session.headers['Authorization'] = 'Bearer null'
        r = self.request('GET', path)
        results['null_bearer'] = r.status_code

        # Test with "undefined" token
        self.session.headers['Authorization'] = 'Bearer undefined'
        r = self.request('GET', path)
        results['undefined_bearer'] = r.status_code

        # Restore original auth
        if original_auth:
            self.session.headers['Authorization'] = original_auth

        for technique, status in results.items():
            if status == 200:
                print(f"  [VULN] Auth bypass via {technique}: "
                      f"status {status}")

        return results

    def test_mass_assignment(self, path, known_fields, hidden_fields):
        """Test for mass assignment by including hidden fields in requests."""
        results = []
        for field_name, field_value in hidden_fields.items():
            payload = {**known_fields, field_name: field_value}
            response = self.request('POST', path, json=payload)
            result = {
                'field': field_name,
                'value': field_value,
                'status': response.status_code,
            }
            if response.status_code in (200, 201):
                try:
                    resp_data = response.json()
                    if field_name in json.dumps(resp_data):
                        result['accepted'] = True
                        print(f"  [VULN] Mass assignment: {field_name} "
                              f"accepted")
                except json.JSONDecodeError:
                    pass
            results.append(result)
        return results
