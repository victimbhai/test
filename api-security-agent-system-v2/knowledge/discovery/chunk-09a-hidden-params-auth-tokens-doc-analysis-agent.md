# Hidden Parameter Discovery, Auth Token Analysis & Documentation Security — Agent Chunk 09a
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Discover hidden API parameters using Arjun/x8/Param Miner, analyze authentication tokens (JWT, OAuth), and perform security analysis of OpenAPI specifications to find weaknesses before active testing
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
For each discovered endpoint, run parameter discovery tools (Arjun for GET/POST params, x8 for JSON body and header params, Param Miner in Burp for reflection-based detection). Analyze JWT tokens for algorithm weaknesses (alg:none, HS256 key weakness). Test OAuth token endpoints for misconfigurations. When you have an OpenAPI spec, run the security analysis script to check for: missing global security schemes, API keys in query params, OAuth implicit flow usage, state-changing endpoints without auth, sensitive data in path parameters, file upload endpoints, and admin endpoints in public specs.

---

#### 3.4.2 Hidden Parameter Discovery

**Arjun:**
```bash
# Installation
pip3 install arjun

# Discover hidden GET parameters
arjun -u https://api.target.com/api/v1/users

# Discover hidden POST parameters (JSON)
arjun -u https://api.target.com/api/v1/users -m POST \
  --headers "Content-Type: application/json"

# Discover hidden POST parameters (form)
arjun -u https://api.target.com/api/v1/users -m POST

# Use custom wordlist
arjun -u https://api.target.com/api/v1/users -w custom_params.txt

# Discover parameters for multiple URLs
arjun -i urls.txt -oJ arjun_results.json

# With authentication
arjun -u https://api.target.com/api/v1/users \
  --headers "Authorization: Bearer <token>"
```

**x8:**
```bash
# Installation
cargo install x8

# Discover hidden parameters
x8 -u "https://api.target.com/api/v1/users" -w params.txt

# With custom method and headers
x8 -u "https://api.target.com/api/v1/users" -w params.txt \
  -m POST -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json"

# Discover parameters in headers
x8 -u "https://api.target.com/api/v1/users" -w params.txt --headers

# JSON body parameter discovery
x8 -u "https://api.target.com/api/v1/users" -w params.txt \
  -m POST -b '{"known_param":"value"}' --json
```

**Param Miner (Burp Extension):**
```
1. Install Param Miner from BApp Store
2. Right-click on a request in Burp
3. Select Extensions > Param Miner > Guess Parameters
4. Configure:
   - Parameter type: query, body, headers, cookies
   - Wordlist: built-in or custom
   - Mining strategy: response length, reflection, error
5. Review results in the Param Miner output tab
```

#### 3.4.3 Authentication Token Analysis

```bash
# Extract and analyze JWT tokens
# Decode JWT without verification
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" | \
  cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Test for algorithm confusion
# Send token with alg:none
python3 -c "
import base64, json
header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')
payload = base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).decode().rstrip('=')
print(f'{header}.{payload}.')
"

# Analyze OAuth token responses
curl -s -X POST "https://target.com/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=test&client_secret=test" | \
  python3 -m json.tool

# Check for token endpoint enumeration
for endpoint in "/oauth/token" "/token" "/auth/token" "/api/token" \
  "/oauth2/token" "/api/oauth/token" "/connect/token" "/oidc/token"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com${endpoint}" \
    -d "grant_type=client_credentials" --max-time 5)
  echo "${endpoint}: ${code}"
done
```

---

## 4. API Documentation Analysis

### 4.1 OpenAPI 3.x Specification Security Analysis

The OpenAPI specification contains a wealth of security-relevant information that can
guide the testing process. A thorough analysis of the specification itself can reveal
security weaknesses before any active testing begins.

**Security Scheme Analysis:**

```python
#!/usr/bin/env python3
"""Analyze OpenAPI spec for security weaknesses."""
import json
import sys

def analyze_security(spec_file):
    with open(spec_file) as f:
        spec = json.load(f)

    findings = []

    # Check global security
    global_security = spec.get('security', [])
    if not global_security:
        findings.append({
            'severity': 'HIGH',
            'finding': 'No global security scheme defined',
            'description': 'The API does not define a global security requirement. '
                           'Each endpoint must define its own security, and any '
                           'endpoint without explicit security is unauthenticated.'
        })

    # Analyze security schemes
    security_schemes = spec.get('components', {}).get('securitySchemes', {})
    for name, scheme in security_schemes.items():
        scheme_type = scheme.get('type', '')

        if scheme_type == 'apiKey':
            location = scheme.get('in', '')
            if location == 'query':
                findings.append({
                    'severity': 'MEDIUM',
                    'finding': f'API key in query parameter: {name}',
                    'description': 'API key transmitted in URL query string. '
                                   'This exposes the key in server logs, browser '
                                   'history, and proxy logs.'
                })
            if location == 'cookie':
                findings.append({
                    'severity': 'LOW',
                    'finding': f'API key in cookie: {name}',
                    'description': 'API key in cookie may be vulnerable to CSRF '
                                   'if no additional protections are in place.'
                })

        elif scheme_type == 'http':
            http_scheme = scheme.get('scheme', '').lower()
            if http_scheme == 'basic':
                findings.append({
                    'severity': 'MEDIUM',
                    'finding': f'HTTP Basic authentication: {name}',
                    'description': 'HTTP Basic auth sends credentials in every '
                                   'request (base64-encoded, not encrypted). '
                                   'Ensure TLS is enforced.'
                })

        elif scheme_type == 'oauth2':
            flows = scheme.get('flows', {})
            if 'implicit' in flows:
                findings.append({
                    'severity': 'HIGH',
                    'finding': f'OAuth2 Implicit flow: {name}',
                    'description': 'The OAuth2 Implicit flow is deprecated and '
                                   'considered insecure. Access tokens are exposed '
                                   'in browser history and URL fragments.'
                })
            if 'password' in flows:
                findings.append({
                    'severity': 'MEDIUM',
                    'finding': f'OAuth2 Resource Owner Password flow: {name}',
                    'description': 'The Password Grant flow requires the client to '
                                   'handle user credentials directly, which is not '
                                   'recommended for public clients.'
                })

    # Analyze endpoints for security issues
    paths = spec.get('paths', {})
    for path, methods in paths.items():
        for method, details in methods.items():
            if method not in ('get', 'post', 'put', 'patch', 'delete',
                              'head', 'options'):
                continue

            operation_id = details.get('operationId', f'{method.upper()} {path}')
            endpoint_security = details.get('security')

            # Check for endpoints with no authentication
            if endpoint_security is not None and len(endpoint_security) == 0:
                # Explicitly set to empty array = no auth required
                if method.upper() in ('POST', 'PUT', 'PATCH', 'DELETE'):
                    findings.append({
                        'severity': 'HIGH',
                        'finding': f'State-changing endpoint without auth: '
                                   f'{method.upper()} {path}',
                        'description': f'Endpoint {operation_id} explicitly '
                                       f'requires no authentication for a '
                                       f'state-changing operation.'
                    })

            # Check for sensitive data in path parameters
            params = details.get('parameters', [])
            for param in params:
                if param.get('in') == 'path':
                    name_lower = param.get('name', '').lower()
                    if any(s in name_lower for s in (
                        'ssn', 'social', 'credit', 'card', 'password',
                        'secret', 'token', 'key'
                    )):
                        findings.append({
                            'severity': 'HIGH',
                            'finding': f'Sensitive data in path parameter: '
                                       f'{param["name"]} in {path}',
                            'description': 'Sensitive data in URL path is logged '
                                           'by servers, proxies, and CDNs.'
                        })

            # Check for file upload endpoints
            request_body = details.get('requestBody', {})
            content = request_body.get('content', {})
            if 'multipart/form-data' in content:
                findings.append({
                    'severity': 'MEDIUM',
                    'finding': f'File upload endpoint: {method.upper()} {path}',
                    'description': 'File upload endpoints require careful validation '
                                   'of file types, sizes, and content.'
                })

            # Check for admin/internal endpoints
            tags = details.get('tags', [])
            if any(t.lower() in ('admin', 'internal', 'management', 'debug')
                   for t in tags):
                findings.append({
                    'severity': 'MEDIUM',
                    'finding': f'Admin/internal endpoint in public spec: '
                               f'{method.upper()} {path}',
                    'description': f'Tags {tags} suggest this is an admin or '
                                   f'internal endpoint exposed in the public spec.'
                })

    # Print findings
    print(f"\n{'='*70}")
    print("API SPECIFICATION SECURITY ANALYSIS")
    print(f"{'='*70}")

    severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
    findings.sort(key=lambda x: severity_order.get(x['severity'], 99))

    for f in findings:
        print(f"\n  [{f['severity']}] {f['finding']}")
        print(f"    {f['description']}")

    print(f"\n  Total findings: {len(findings)}")
    high = sum(1 for f in findings if f['severity'] == 'HIGH')
    medium = sum(1 for f in findings if f['severity'] == 'MEDIUM')
    low = sum(1 for f in findings if f['severity'] == 'LOW')
    print(f"  HIGH: {high}, MEDIUM: {medium}, LOW: {low}")

    return findings

if __name__ == '__main__':
    analyze_security(sys.argv[1])
```
