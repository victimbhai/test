# Testing Hypotheses: Configuration — Agent Chunk 48b
> Source: 10-authorized-testing-hypotheses.md
> Purpose: Execute structured configuration test hypotheses: CORS misconfiguration, verbose errors, debug endpoints, missing security headers, TLS issues, API documentation exposure, HTTP method allowance, Content-Type enforcement, rate limiting, and cache control
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Execute each hypothesis: H-CONFIG-01 (CORS — test with arbitrary Origin headers, check for reflect-origin), H-CONFIG-02 (verbose errors — trigger errors, check for stack traces/internal paths), H-CONFIG-03 (debug endpoints — check /debug, /actuator, /console, /_profiler), H-CONFIG-04 (security headers — verify HSTS, X-Content-Type-Options, CSP), H-CONFIG-05 (TLS — check certificate validity, protocol versions, cipher suites), H-CONFIG-06 (API docs exposure — check /swagger, /api-docs in production), H-CONFIG-07 (HTTP methods — send OPTIONS, test unexpected methods), H-CONFIG-08 (Content-Type — send wrong content types), H-CONFIG-09 (rate limiting — verify existence per endpoint), H-CONFIG-10 (cache control — check no-store on sensitive responses).

---

### 2.5 Configuration Testing Hypotheses

Configuration tests verify the security of the API's deployment and
configuration.

---

#### H-CONFIG-01: CORS Misconfiguration

**Hypothesis**: CORS configuration may be overly permissive, allowing
unauthorized cross-origin access to API resources.

**Risk level of test**: NONE -- passive header analysis.

**Test procedure**:

1. Send requests with various `Origin` headers and analyze
   `Access-Control-Allow-Origin` responses:
   - `Origin: https://evil.com`
   - `Origin: https://evil-target.com` (includes the target domain)
   - `Origin: https://target.com.evil.com` (subdomain of evil)
   - `Origin: null`
   - No Origin header

2. For each response, check:
   - `Access-Control-Allow-Origin`: Does it reflect the attacker's origin?
   - `Access-Control-Allow-Credentials`: Is it `true`? (the critical concern)
   - `Access-Control-Allow-Methods`: Which methods?
   - `Access-Control-Allow-Headers`: Which custom headers?
   - `Access-Control-Expose-Headers`: Which response headers?

3. Send a preflight request (OPTIONS) with:
   - `Access-Control-Request-Method: PUT`
   - `Access-Control-Request-Headers: X-Custom-Header`

**Expected results**:
- **Vulnerable**: Origin is reflected blindly with `Allow-Credentials: true`,
  or `null` origin is allowed with credentials.
- **Not vulnerable**: Strict allow-list of origins. No wildcard with
  credentials. Null origin rejected.

---

#### H-CONFIG-02: Verbose Error Messages

**Hypothesis**: API error responses may contain excessive technical detail
useful for further attacks.

**Risk level of test**: NONE -- analyzes existing error responses.

**Test procedure**:

1. Trigger various error conditions and analyze the responses:
   - 400 Bad Request (malformed input)
   - 401 Unauthorized (invalid credentials)
   - 403 Forbidden (unauthorized access)
   - 404 Not Found (non-existent resource)
   - 405 Method Not Allowed (wrong HTTP method)
   - 500 Internal Server Error (trigger with malformed input)

2. Check each error response for:
   - Stack traces
   - Database query fragments
   - File system paths
   - Framework/library version numbers
   - Internal IP addresses
   - Server configuration details
   - Debug information

---

#### H-CONFIG-03: Debug Endpoints in Production

**Hypothesis**: Debug or development endpoints may be active in the production
environment.

**Risk level of test**: LOW -- checks for known debug endpoints.

**Test procedure**:

1. Check for common debug endpoints:
   - `/debug`, `/debug/vars`, `/debug/pprof`
   - `/_debug`, `/_profiler`
   - `/actuator`, `/actuator/env`, `/actuator/health`, `/actuator/beans`
   - `/elmah.axd`, `/trace.axd`
   - `/phpinfo.php`, `/info.php`
   - `/server-info`, `/server-status`
   - `/.env`, `/config`, `/settings`
   - `/graphql` with introspection enabled
   - `/swagger`, `/swagger-ui`, `/api-docs`
   - `/metrics`, `/prometheus`

2. For each accessible endpoint, document what information is exposed.

---

#### H-CONFIG-04: Missing Security Headers

**Hypothesis**: API responses may lack security headers that protect against
common attacks.

**Risk level of test**: NONE -- passive header analysis.

**Test procedure**:

1. Send a request and analyze response headers for the presence and correct
   values of:
   - `Strict-Transport-Security` (HSTS): Should be present with `max-age`
     of at least 31536000 and `includeSubDomains`
   - `X-Content-Type-Options`: Should be `nosniff`
   - `X-Frame-Options`: Should be `DENY` or `SAMEORIGIN` (for HTML responses)
   - `Content-Security-Policy`: Should be present (for HTML responses)
   - `Cache-Control`: Should be `no-store` for sensitive responses
   - `X-Request-ID` or similar: Should be present for tracing (without leaking
     internal info)
   - `Referrer-Policy`: Should be `strict-origin-when-cross-origin` or stricter

2. For APIs returning only JSON, some headers (X-Frame-Options, CSP) are less
   critical but Content-Type, Cache-Control, and HSTS remain important.

---

#### H-CONFIG-05: TLS Configuration Issues

**Hypothesis**: The API's TLS configuration may have weaknesses that reduce
transport security.

**Risk level of test**: NONE -- passive analysis of the TLS handshake.

**Test procedure**:

1. Analyze the TLS configuration:
   - Protocol versions supported (TLS 1.0 and 1.1 should be disabled)
   - Cipher suites offered (weak ciphers should be disabled)
   - Certificate validity and chain
   - Certificate key size (minimum RSA 2048 or EC 256)
   - OCSP stapling support
   - CAA DNS records

2. Check for mixed-content issues:
   - Does the API redirect HTTP to HTTPS?
   - Are there any HTTP-only endpoints?

---

#### H-CONFIG-06: API Documentation Exposure

**Hypothesis**: API documentation (OpenAPI/Swagger, GraphQL introspection)
may be publicly accessible in production, revealing the attack surface.

**Risk level of test**: NONE -- checks for publicly accessible documentation.

**Test procedure**:

1. Check for exposed API documentation at common paths (listed in H-CONFIG-03).
2. Check if documentation requires authentication.
3. If accessible, compare documented endpoints with discovered endpoints for
   discrepancies that may indicate hidden or deprecated functionality.
4. Check for GraphQL introspection in production.

---

#### H-CONFIG-07: HTTP Method Allowance

**Hypothesis**: Unnecessary HTTP methods may be enabled, including potentially
dangerous methods like TRACE, DELETE, or PUT on endpoints that should be
read-only.

**Risk level of test**: NONE -- sends OPTIONS and tests method responses.

**Test procedure**:

1. Send OPTIONS to each endpoint and check `Allow` header.
2. Attempt each listed method and any unstated methods (TRACE, PATCH, HEAD).
3. Check if TRACE is enabled (returns the request in the response body,
   enabling credential theft in some scenarios).
4. Check if unexpected methods perform unexpected operations.

---

#### H-CONFIG-08: Content-Type Enforcement

**Hypothesis**: The API may not enforce Content-Type validation, accepting
input in unexpected formats.

**Risk level of test**: LOW.

**Test procedure**:

1. For a JSON API endpoint, test with different Content-Type headers:
   - `application/xml` with XML body
   - `application/x-www-form-urlencoded` with URL-encoded body
   - `multipart/form-data` with form data
   - `text/plain` with JSON body
   - No Content-Type header

2. Check if the server processes the alternative format. An API documented
   as JSON-only that also processes XML may be vulnerable to XXE.

---

#### H-CONFIG-09: Rate Limiting Existence

**Hypothesis**: API endpoints may lack rate limiting entirely, allowing
unconstrained request volumes.

**Risk level of test**: LOW-MEDIUM -- sends elevated request volumes.

**Test procedure**:

1. Select a representative endpoint (not one that triggers side effects).

2. Send requests at increasing rates:
   - 1/second (baseline)
   - 10/second
   - 50/second
   - 100/second

3. At each rate, check for:
   - 429 Too Many Requests
   - `Retry-After` header
   - Response degradation (increasing latency)
   - Rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`)

4. Stop as soon as rate limiting is confirmed or 100/second is reached
   without limiting.

---

#### H-CONFIG-10: Cache Control

**Hypothesis**: Sensitive API responses may be cached by intermediaries
(CDN, proxies, browsers), exposing data to unintended recipients.

**Risk level of test**: NONE -- passive header analysis.

**Test procedure**:

1. For endpoints returning sensitive data (user profiles, financial data,
   health data):
   - Check `Cache-Control` header: should be `no-store` or
     `private, no-cache, no-store, must-revalidate`
   - Check `Pragma` header: should be `no-cache` for HTTP/1.0 compatibility
   - Check `Expires` header: should be `0` or a past date
   - Check for `ETag` or `Last-Modified` headers that might enable cache
     validation

2. Check if CDN/proxy cache headers are present:
   - `X-Cache`, `X-Cache-Hit`, `CF-Cache-Status`, `Age`

3. If caching headers indicate the response is cached, check if different
   authenticated users receive each other's cached data.

---

