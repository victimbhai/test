# Detection and Prevention Matrix: Comprehensive Security Reference

## Overview

This document provides a comprehensive detection and prevention matrix for API authentication security threats, including security control tables, WAF rules, tool references, a full CVE index, and key recommendations. All content is derived from adversarially-verified research covering 24 confirmed findings across JWT, OAuth, HTTP protocol, API, and cloud infrastructure attack surfaces.

---

## 1. JWT Security Controls

| Attack | Detection | Prevention |
|--------|-----------|------------|
| JKU/X5U injection | Monitor for external URLs in JWT headers; WAF rule for untrusted jku domains; alert on tokens containing jku/x5u headers if application does not use them | Pin allowed algorithms server-side; strict JWKS URL allowlist; never fetch keys from token-supplied URLs; use asymmetric algorithms with pinned public keys |
| Algorithm confusion (RS256->HS256) | Alert on HS256 tokens on RS256 endpoints; monitor for algorithm changes in tokens | Pin allowed algorithms server-side; never read `alg` from token for verification decisions; use asymmetric algorithms (RS256/ES256) |
| Issuer array injection (CVE-2025-30144) | Check iss type is string, not array; WAF: inspect decoded JWT for iss values starting with `[`; flag fast-jwt < 5.0.6 | Upgrade fast-jwt to 5.0.6+; application-level validation that iss is a string before library processing |
| kid SQL injection | WAF rules for SQL patterns in JWT kid field; monitor kid values for injection characters | Validate kid against known set; parameterized queries; never use kid in SQL or file path operations without sanitization |
| kid path traversal | Monitor for `../` or encoded traversal sequences in kid values | Validate kid against known key set; reject path separators in kid values |
| Embedded JWK injection (CVE-2018-0114) | Alert on JWTs containing `jwk` header field | Reject tokens with embedded JWK headers; upgrade node-jose past 0.11.0 |
| alg:none bypass | Detect tokens with `alg:none`; should never appear in production | Reject tokens with none algorithm server-side; explicit algorithm allowlist |
| Nested JSON DoS (CVE-2025-53864) | Request size monitoring; stack depth monitoring; JVM StackOverflowError logging | Upgrade Nimbus JOSE+JWT to 10.0.2+; payload size limits; nesting depth limits |
| JWT claim type confusion | Log unexpected claim value types; alert on array-typed claims where strings expected | Strict claim type validation before library processing; schema enforcement on JWT payloads |

---

## 2. OAuth Security Controls

| Attack | Detection | Prevention |
|--------|-----------|------------|
| Redirect URI bypass (open redirect chain) | Log redirect_uri variations per client_id; monitor for redirect chains after OAuth callbacks | Exact string matching for redirect_uri (no wildcards); mandatory PKCE (RFC 7636); remove open redirects from registered domains |
| Redirect URI URL parsing bypass (CVE-2024-2419) | Alert on redirect_uri containing encoded characters, @, #, or backslashes | Exact string matching; normalize URLs before comparison; test with URL parsing edge cases |
| AiTM token theft (Evilginx) | Impossible travel detection; new MFA registration after sign-in; sign-ins from VPS/hosting provider IPs | FIDO2/WebAuthn passkeys; Token Protection (device binding); short session lifetimes; Conditional Access requiring managed devices |
| Device code flow phishing (EvilTokens) | Alert on device code flows from unexpected applications or user agents | Conditional Access policies restricting device code flow; block device code flow for sensitive accounts |
| Open redirect chain for code theft | Monitor for redirect chains to external domains after OAuth callbacks | Remove all open redirects; enforce exact redirect_uri matching; PKCE mandatory |
| OAuth2-Proxy skip-auth bypass (CVE-2025-54576) | Compare auth decisions against request paths; alert on skip decisions for protected paths; grep logs for 'Skipping auth' on non-public paths | Upgrade oauth2-proxy to 7.11.0+; use exact path matches; implement backend auth as defense-in-depth; strip query parameters before oauth2-proxy |
| Supply-chain OAuth abuse (Salesloft/Drift) | Monitor token usage from unexpected IP ranges; audit third-party OAuth consents | Least-privilege scoping; per-organization token isolation; vendor breach response procedures |
| OAuth state parameter bypass | Alert on OAuth flows missing state parameter or with predictable state values | Cryptographically random state parameter; validate state on callback |
| PKCE downgrade | Alert on authorization requests missing code_challenge | Enforce PKCE with S256 method; reject plain method |
| Microsoft OAuth redirect abuse (2026) | Monitor app registrations for external redirect URIs; alert on OAuth apps from unverified publishers | Restrict app registration to verified publishers; monitor and disable suspicious OAuth applications |

---

## 3. HTTP Protocol Security Controls

| Attack | Detection | Prevention |
|--------|-----------|------------|
| Request smuggling (CL.TE/TE.CL) | Differential timing probes; Burp HTTP Request Smuggler extension; alert on dual CL/TE headers | Reject requests with both CL and TE headers; use HTTP/2 end-to-end; strict HTTP parsing |
| Chunk extension smuggling (CVE-2025-55315) | Monitor for chunk extensions with control characters; alert on unusual chunked encoding | Upgrade ASP.NET Core Kestrel; strip chunk extensions at proxy; normalize chunked framing |
| Request smuggling via obs-fold (CVE-2025-32094) | Detect obsolete line folding in headers | Reject headers with continuation whitespace (obs-fold) |
| HEAD method body confusion (CVE-2024-33452) | Alert on HEAD requests with Content-Length > 0 | Reject HEAD requests with bodies; upgrade OpenResty/Kong |
| Path normalization bypass | Compare gateway vs backend access logs for path mismatches; automated scanning with cerberauth/proxyaudit | Normalize paths before auth decisions; test all encoding variants; ensure gateway and backend agree on canonical path form |
| Trailing slash bypass | Alert on auth decision differences between /path and /path/ | Enforce consistent trailing slash policy before authorization |
| Double/triple encoding bypass | WAF rules blocking %2e%2e, %252e, %2f, %252f, %5c in URL paths | Iterative URL decoding before auth checks; reject requests with encoded path separators |
| Double slash bypass (CVE-2025-71399) | Alert on URLs containing // (except protocol://) | Collapse double slashes before routing; upgrade Better Auth to 1.4.5+ |
| Header override (X-Forwarded-For) | Log unexpected XFF values; alert on non-proxy sources sending XFF | Overwrite (not append) XFF at proxy: `proxy_set_header X-Forwarded-For $remote_addr` |
| X-Original-URL / X-Rewrite-URL bypass | Alert on requests containing these headers | Strip X-Original-URL and X-Rewrite-URL at the edge |
| Header normalization smuggling (CVE-2025-64484) | Monitor for headers with underscores targeting auth-proxy-controlled headers | Update oauth2-proxy to 7.13.0+; normalize header matching for underscores/hyphens |
| CORS misconfiguration (CVE-2024-41659) | Scan with CORStest; monitor ACAO response headers; alert on reflected external origins | Explicit origin allowlist; never reflect arbitrary origins with credentials; Vary: Origin |
| Host header injection (CVE-2025-43930) | Alert on Host values differing from canonical domain; WAF reject non-matching Host | Strict hostname allowlist at server/LB/app; generate links from config, not Host header |

---

## 4. API-Level Security Controls

| Attack | Detection | Prevention |
|--------|-----------|------------|
| Mass assignment (API3:2023 BOPLA) | Log unexpected fields in write requests; alert on role/is_admin/permissions in PUT/PATCH body | `additionalProperties: false` in JSON Schema; strict allowlisted field binding; code review for `.permit!` (Rails), direct JPA binding (Spring) |
| BOLA/IDOR (API1:2023) | Alert on cross-account object access patterns; monitor rapid sequential ID enumeration from single session | Centralized authorization middleware; ownership checks on every object access; use Autorize/BOLABuster for testing |
| API version downgrade (CVE-2026-23760) | Monitor traffic to deprecated API paths; alert on version switching within single session | Apply auth middleware at gateway before version routing; decommission old versions; honeypot at deprecated paths |
| GraphQL alias batching | Alert on >N aliases per request (pattern: `a0:`, `a1:`, `a2:`); monitor large request bodies | Query cost analysis with field weights; per-operation rate limits (not per-request); cap batch size at 3-5; block bodies over 64KB |
| GraphQL APQ bypass (CVE-2025-32032) | Monitor APQ registration from non-CI/CD sources; alert on deep fragment nesting | Strict persisted query mode; validate hash integrity (compute SHA-256); require auth for APQ registration |
| GraphQL introspection leak (CVE-2026-35413) | Block unauthenticated requests to /graphql/system; alert on `server_specs_graphql` queries | Ensure introspection controls cover ALL schema disclosure endpoints including SDL resolvers |
| Token leakage via URL (CVE-2026-44883) | Scan logs for JWT patterns (`eyJ...`); alert on tokens in query strings | Never pass tokens in URL parameters; use Authorization header only; Referrer-Policy: no-referrer |
| Axios credential leakage (CVE-2025-27152) | Dependency scanning for Axios < 1.8.2 | Upgrade Axios to 1.8.2+; strip Authorization header on cross-origin redirects |
| IDOR to account takeover (CVE-2026-32103) | Alert on account modification where auth user ID differs from target resource ID; monitor rapid sequential access | Server-side ownership verification; never rely on obscurity (UUIDs, hashing) as authorization |
| CSRF on password/email change | Monitor for cross-origin Referer on state-changing endpoints; alert on missing CSRF tokens | Anti-CSRF tokens; SameSite=Strict cookies; require current password for changes; block _method parameter override |
| Password reset poisoning via Host header | Monitor reset request logs for Host values differing from canonical domain | Hardcoded application base URL from config, never from request headers; set SERVER_NAME in Flask |

---

## 5. Cloud Infrastructure Security Controls

| Attack | Detection | Prevention |
|--------|-----------|------------|
| SSRF to AWS IMDSv1 | Monitor outbound connections to 169.254.169.254; alert on CloudTrail API calls from instance role credentials at unexpected IPs | Enforce IMDSv2 with `HttpTokens=required`; egress firewall blocking metadata IP; hop limit 1 |
| SSRF to Azure IMDS | Monitor outbound to 169.254.169.254 with Metadata:true header | Network security groups restricting IMDS access; Workload Identity |
| SSRF to GCP metadata | Monitor outbound to metadata.google.internal | Workload Identity instead of node-level service accounts |
| DNS rebinding SSRF bypass | Alert on TTL=0 DNS responses from application hosts; monitor DNS queries for metadata hostnames | Pin resolved IP for connection (resolve once, use that IP); validate on each redirect |
| IP encoding bypass (CVE-2026-69192) | Normalize all IP forms to canonical 128-bit before comparison | Allowlist-based validation; test all encoding variants (decimal, octal, hex, IPv6) |
| IPv6 denylist bypass (CVE-2026-44589) | Test denylist against IPv6 forms like `[::ffff:7f00:1]` | Match against normalized 128-bit IP representation, not regex on dotted-quad |
| Redirect-based SSRF bypass | Monitor for redirect chains from application servers to internal IPs | Disable redirect following; re-validate each redirect target; HTTPS-only outbound |
| Header injection for IMDSv2 | Monitor for unexpected Metadata headers in outbound requests | Restrict header control in user-facing features; validate outbound request headers |
| WebSocket auth bypass (CVE-2024-55591 FortiOS) | Monitor for jsconsole activity from unexpected sources; detect new admin accounts; track VPN config changes | Patch FortiOS/FortiProxy; validate WebSocket authentication tokens cryptographically; monitor CISA KEV |
| CSWSH (Cross-Site WebSocket Hijacking) | Alert on WebSocket upgrade requests with unexpected Origin headers | Validate Origin against explicit allowlist; post-handshake re-authentication on sensitive operations |
| Local WebSocket hijacking (CVE-2025-52882) | Inventory local WebSocket servers from IDE extensions | Origin validation on all local WebSocket servers; per-session authentication tokens; random port with URL secret |

---

## 6. Comprehensive WAF Rule Set (ModSecurity)

### 6.1 JWT Protection Rules

```apache
# JWT JKU Injection - Block tokens with untrusted JKU domains
SecRule REQUEST_HEADERS:Authorization "@rx \"jku\"\s*:\s*\"https?://(?!trusted\.domain\.com)" \
  "id:1001,phase:1,deny,status:403,msg:'Untrusted JKU domain in JWT',severity:2,tag:'jwt/jku-injection'"

# JWT Algorithm None - Block alg:none tokens
SecRule REQUEST_HEADERS:Authorization "@rx \"alg\"\s*:\s*\"none\"" \
  "id:1002,phase:1,deny,status:403,msg:'JWT alg:none detected',severity:1,tag:'jwt/alg-none'"

# JWT Issuer Array Injection - Detect array-type issuer claims
SecRule REQUEST_HEADERS:Authorization "@rx \"iss\"\s*:\s*\[" \
  "id:1003,phase:1,deny,status:403,msg:'JWT issuer array injection attempt',severity:2,tag:'jwt/iss-array'"
```

### 6.2 Path Normalization Protection Rules

```apache
# Path Normalization Bypass - Block encoded traversal
SecRule REQUEST_URI "@rx (%2e|%252e|%2f|%252f|%5c|%255c)" \
  "id:1010,phase:1,deny,status:400,msg:'Encoded path traversal attempt',severity:2,tag:'path/normalization-bypass'"

# Double Slash Bypass - Alert on double slashes in path
SecRule REQUEST_URI "@rx //[a-zA-Z]" \
  "id:1011,phase:1,log,msg:'Double slash in URL path - potential bypass',severity:3,tag:'path/double-slash'"

# Semicolon Path Parameter - Block path parameter injection
SecRule REQUEST_URI "@rx ;[a-zA-Z]+" \
  "id:1012,phase:1,log,msg:'Semicolon path parameter detected',severity:3,tag:'path/semicolon-param'"
```

### 6.3 OAuth2-Proxy Protection Rules

```apache
# OAuth2-Proxy Skip-Auth Bypass - Detect skip patterns in query strings
SecRule REQUEST_URI "@rx \?.*(/health|/ready|/public/)" \
  "id:1020,phase:1,log,msg:'Potential oauth2-proxy skip-auth bypass',severity:2,tag:'oauth/proxy-bypass'"

# OAuth Redirect URI Manipulation - Alert on encoded redirects
SecRule ARGS:redirect_uri "@rx (%2e|%2f|%5c|@|%23|%40)" \
  "id:1021,phase:1,log,msg:'OAuth redirect_uri manipulation attempt',severity:2,tag:'oauth/redirect-bypass'"
```

### 6.4 Request Smuggling Protection Rules

```apache
# Request Smuggling - Block requests with both CL and TE headers
SecRule &REQUEST_HEADERS:Content-Length "@gt 0" \
  "id:1030,phase:1,chain,msg:'Potential request smuggling - dual CL/TE'"
  SecRule &REQUEST_HEADERS:Transfer-Encoding "@gt 0" \
    "deny,status:400,severity:1,tag:'smuggling/cl-te'"

# Non-standard Transfer-Encoding - Block non-chunked TE values
SecRule REQUEST_HEADERS:Transfer-Encoding "!@streq chunked" \
  "id:1031,phase:1,deny,status:400,msg:'Non-standard Transfer-Encoding',severity:2,tag:'smuggling/te-obfuscation'"

# Chunk Extension Abuse - Alert on control characters in chunked bodies
SecRule REQUEST_BODY "@rx [0-9a-fA-F]+;[^\r\n]*[\r\n]" \
  "id:1032,phase:2,log,msg:'Chunk extension with control characters',severity:2,tag:'smuggling/chunk-ext'"
```

### 6.5 CORS Protection Rules

```apache
# CORS Abuse Detection - Alert on unexpected reflected origins
SecRule RESPONSE_HEADER:Access-Control-Allow-Origin "@rx ^https?://(?!trusted\.domain\.com)" \
  "id:1040,phase:4,log,msg:'Unexpected CORS origin reflected',severity:2,tag:'cors/reflection'"

# CORS Credentials with Wildcard - Block dangerous combination
SecRule RESPONSE_HEADER:Access-Control-Allow-Origin "@streq *" \
  "id:1041,phase:4,chain,msg:'CORS wildcard with credentials'"
  SecRule RESPONSE_HEADER:Access-Control-Allow-Credentials "@streq true" \
    "deny,status:500,severity:1,tag:'cors/wildcard-credentials'"
```

### 6.6 GraphQL Protection Rules

```apache
# GraphQL Batch Abuse - Detect alias batching patterns
SecRule REQUEST_BODY "@rx [a-z]+[0-9]{2,}:" \
  "id:1050,phase:2,log,msg:'Potential GraphQL alias batching attack',severity:2,tag:'graphql/alias-batch'"

# GraphQL Oversized Request - Block excessively large queries
SecRule REQUEST_BODY "@gt 65536" \
  "id:1051,phase:2,deny,status:413,msg:'Oversized GraphQL request',severity:3,tag:'graphql/oversized'"

# GraphQL Introspection Leak - Block unauthenticated introspection
SecRule REQUEST_BODY "@rx __schema|__type|server_specs_graphql" \
  "id:1052,phase:2,log,msg:'GraphQL introspection/schema query detected',severity:3,tag:'graphql/introspection'"
```

### 6.7 Header Injection Protection Rules

```apache
# X-Original-URL/X-Rewrite-URL - Block path override headers
SecRule REQUEST_HEADERS:X-Original-URL "." \
  "id:1060,phase:1,deny,status:403,msg:'X-Original-URL header blocked',severity:2,tag:'header/path-override'"

SecRule REQUEST_HEADERS:X-Rewrite-URL "." \
  "id:1061,phase:1,deny,status:403,msg:'X-Rewrite-URL header blocked',severity:2,tag:'header/path-override'"

# Host Header Injection - Alert on Host mismatch
SecRule REQUEST_HEADERS:Host "!@rx ^(www\.)?trusted-domain\.com$" \
  "id:1062,phase:1,log,msg:'Unexpected Host header value',severity:2,tag:'header/host-injection'"

# SSRF Metadata IP - Block requests to cloud metadata
SecRule ARGS "@rx (169\.254\.169\.254|metadata\.google\.internal|168\.63\.129\.16)" \
  "id:1063,phase:2,deny,status:403,msg:'Cloud metadata URL in request parameter',severity:1,tag:'ssrf/metadata'"
```

### 6.8 Token Leakage Protection Rules

```apache
# Token in URL - Alert on JWT patterns in query strings
SecRule QUERY_STRING "@rx eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+" \
  "id:1070,phase:1,log,msg:'Potential JWT token in URL query string',severity:2,tag:'token/url-leakage'"

# Bearer Token in Referer - Alert on token leakage via Referer
SecRule REQUEST_HEADERS:Referer "@rx (token=|access_token=|Bearer%20)" \
  "id:1071,phase:1,log,msg:'Potential token leakage via Referer header',severity:2,tag:'token/referer-leakage'"
```

---

## 7. Tool Reference

| Tool | Purpose | URL/Install | Category |
|------|---------|-------------|----------|
| jwt_tool | JWT attack automation (alg confusion, JKU injection, kid SQLi, brute force) | github.com/ticarpi/jwt_tool | JWT |
| Evilginx | AiTM reverse-proxy phishing framework for MFA bypass and token theft | github.com/kgretzky/evilginx2 | Phishing/MFA |
| BatchQL | GraphQL batching attack automation | github.com/assetnote/batchql | GraphQL |
| InQL | GraphQL introspection and attack query generation (Burp Suite extension) | github.com/doyensec/inql | GraphQL |
| graphql-cop | GraphQL security configuration audit | github.com/dolevf/graphql-cop | GraphQL |
| CORStest | CORS misconfiguration scanner | github.com/RUB-NDS/CORStest | CORS |
| cors-misconfig-scanner | Automated CORS policy vulnerability scanner | github.com/RodneyRoger5/cors-misconfig-scanner | CORS |
| smuggler.py | HTTP request smuggling detection and exploitation | github.com/defparam/smuggler | Smuggling |
| Burp HTTP Request Smuggler | Request smuggling detection extension for Burp Suite Professional | BApp Store | Smuggling |
| Burp Autorize | BOLA/IDOR automated testing via two-account comparison | BApp Store | IDOR/BOLA |
| BOLABuster | LLM-assisted BOLA/IDOR detection tool | github.com/paloaltonetworks/BOLABuster | IDOR/BOLA |
| proxyaudit | API gateway path normalization configuration testing | github.com/cerberauth/proxyaudit | Path Normalization |
| wscat | WebSocket client for Origin and auth testing | npm install -g wscat | WebSocket |
| Nuclei | Template-based vulnerability scanner (includes CORS, OAuth, auth bypass templates) | github.com/projectdiscovery/nuclei | General |
| DOMPurify | Client-side HTML sanitizer for XSS prevention | github.com/cure53/DOMPurify | XSS Prevention |

---

## 8. Full CVE Index

| CVE | Component | Category | Severity | Key Detail |
|-----|-----------|----------|----------|------------|
| CVE-2018-0114 | node-jose | Embedded JWK injection | Critical | Library trusted public key in JWT header; fixed in 0.11.0 |
| CVE-2024-2419 | Keycloak | URL parsing redirect bypass | High (CVSS 7.1) | Host-allowlist bypass through URI parsing inconsistency |
| CVE-2024-21893 | Ivanti Connect Secure | SSRF via SAML | Critical | Unauthenticated SSRF in /dana-ws/saml20.ws; CISA KEV; 170+ attacker IPs |
| CVE-2024-21887 | Ivanti Connect Secure | Command injection | Critical | Chained with CVE-2024-21893 for unauthenticated RCE |
| CVE-2024-27982 | Node.js | Leading space Content-Length | High | Space-prefixed CL header enables request smuggling |
| CVE-2024-28143 | Various | CSRF account takeover | High | CSRF on password change without current password check |
| CVE-2024-33452 | Kong/OpenResty | HEAD method smuggling | Critical | HEAD requests with bodies split into two pipelined requests; WAF bypass |
| CVE-2024-41659 | Memos | CORS misconfiguration | High (CVSS 8.1) | Reflected arbitrary origins with credentials; fixed in 0.21.0 |
| CVE-2024-47070 | authentik | XFF exception bypass | Critical (CVSS 9.1) | Malformed XFF caused policy exception, skipped password stage |
| CVE-2024-51382 | JATOS | CSRF admin password reset | High (CVSS 8.4) | CSRF flaw allowing admin password reset |
| CVE-2024-51504 | Apache ZooKeeper | XFF IP spoofing | High (CVSS 9.1) | IPAuthenticationProvider trusted X-Forwarded-For; admin command execution |
| CVE-2024-53008 | HAProxy | Message framing bypass | High (CVSS 5.3) | Inconsistent request interpretation bypasses ACL-restricted paths |
| CVE-2024-54150 | cjwt C library | Algorithm confusion | Critical (CVSS 9.1-10.0) | RS256 to HS256 confusion; fixed in 2.3.0 |
| CVE-2024-55591 | FortiOS/FortiProxy | WebSocket auth bypass | Critical (CVSS 9.6-9.8) | Zero-day since Nov 2024; super-admin via jsconsole WebSocket; CISA KEV |
| CVE-2025-4427 | Ivanti EPMM | Auth bypass | Critical | Authentication bypass in API component; chained with CVE-2025-4428 |
| CVE-2025-4428 | Ivanti EPMM | EL injection RCE | Critical | Expression Language injection via error messages; exploited against NHS |
| CVE-2025-13915 | IBM API Connect | Auth bypass | Critical (CVSS 9.8) | CWE-305; affects API management infrastructure itself |
| CVE-2025-15602 | Snipe-IT | Mass assignment | High (CVSS 8.8) | CWE-915; low-priv user modifies Super Admin fields; fixed in 8.3.7 |
| CVE-2025-24472 | FortiOS | Auth bypass via CSF proxy | High (CVSS 8.1) | Separate authentication bypass via CSF proxy request path |
| CVE-2025-27152 | Axios | Credential leakage via redirect | High | Forwards Authorization header on cross-origin redirects to absolute URLs; fixed in 1.8.2 |
| CVE-2025-30144 | fast-jwt | Issuer array injection | High | Array.some() on iss claim allows attacker domain in array; fixed in 5.0.6 |
| CVE-2025-32032 | Apollo Router | Named fragment DoS | High (CVSS 7.5) | Deeply nested reused fragments exhaust query planner thread pool |
| CVE-2025-32094 | Akamai | Obs-fold smuggling | Critical | OPTIONS + obsolete line folding; Black Hat USA 2025 research |
| CVE-2025-43930 | Hashview (Flask) | Host header injection | Critical (CVSS 9.8) | url_for with _external=True used unvalidated Host header |
| CVE-2025-52882 | Claude Code MCP | Local WebSocket hijacking | High (CVSS 8.8-9.3) | No Origin validation; any webpage connects to localhost MCP server; CWE-1385 |
| CVE-2025-53864 | Nimbus JOSE+JWT | Nested JSON DoS | High (CVSS 5.8) | Uncontrolled recursion in JWT claim parsing; stack exhaustion; CWE-674 |
| CVE-2025-54576 | oauth2-proxy | Query parameter auth bypass | Critical (CVSS 9.1) | skip_auth_routes matched full URI including query params; fixed in 7.11.0 |
| CVE-2025-55315 | ASP.NET Kestrel | Chunk extension smuggling | Critical (CVSS 9.9) | Microsoft's highest-ever ASP.NET Core CVSS; lone newline in chunk extension |
| CVE-2025-61882 | Oracle EBS | SSRF + XSLT RCE | Critical (CVSS 9.8) | Multi-stage chain; exploited by Cl0p ransomware since Aug 2025; CISA KEV |
| CVE-2025-64484 | OAuth2-Proxy | Header normalization smuggling | High | Underscore-to-hyphen normalization bypasses auth header stripping |
| CVE-2025-66202 | Astro | Double encoding path bypass | Critical | %2561dmin bypasses middleware checking for /admin |
| CVE-2025-71399 | Better Auth | Double slash bypass | High | //sign-in/email bypasses disabledPaths; rou3 router normalization after check |
| CVE-2026-14916 | Kong API Gateway Enterprise | JWT algorithm confusion | High (CVSS 7.7) | JWT plugin did not validate algorithm compatibility with key type |
| CVE-2026-23760 | SmarterMail | Version downgrade auth bypass | Critical (CVSS 9.8-10) | ForceResetPassword with IsSysAdmin=true; unauthenticated admin takeover; CISA KEV |
| CVE-2026-27812 | sub2api | Password reset poisoning | High (CVSS 8.0-9.1) | Host header injection in password reset link generation |
| CVE-2026-32103 | StudioCMS | IDOR account takeover | Critical | create-reset-link returns JWT in response; any admin resets any user |
| CVE-2026-35413 | Directus | SDL schema leak | High (CVSS 5.3) | server_specs_graphql bypasses introspection=false; full schema exposure |
| CVE-2026-44589 | nuxt-og-image | IPv6 denylist bypass | High | Regex matching dotted-quad misses [::ffff:7f00:1] |
| CVE-2026-44883 | Portainer | Token in URL parameter | High (CVSS 7.5) | JWT via ?token= with 8-hour lifetime; exposed in logs/history/Referer |
| CVE-2026-69192 | ip-address npm | Leading-zero octet confusion | High | 012.0.0.1 parsed as decimal by validator but octal by OS |
| CVE-2026-93556 | Kompini Tankuam Places | Unauthenticated password reset | Critical (CVSS 9.3) | Reset any account including admin via user-controlled identifier |

---

## 9. Key Recommendations

### Recommendation 1: Implement Defense-in-Depth Authentication

Never rely on a single authentication layer. Apply authentication at the gateway AND the backend. Test that removing one layer does not expose endpoints. This is critical because:

- OAuth2-proxy bypass (CVE-2025-54576) shows proxy-only auth fails
- Path normalization bypasses can skip gateway-level auth
- Request smuggling bypasses all proxy-level authentication
- Backend must independently verify identity, not trust proxy-asserted headers

### Recommendation 2: Normalize Before Authorizing

All path normalization, URL decoding, header processing, and input sanitization must occur BEFORE authorization decisions. Test with encoding variants:

- Double-encoded paths: `%2561dmin` -> `%61dmin` -> `admin`
- Dot segments: `/api/../admin/`
- Double slashes: `//sign-in/email`
- Trailing slashes: `/accounts/` vs `/accounts`
- Semicolons: `/admin;jsessionid=fake`
- Case variations: `/Admin`, `/ADMIN`
- Unicode normalization: full-width characters
- Backslash substitution: `/api\../admin`

### Recommendation 3: Deploy Phishing-Resistant MFA

FIDO2/WebAuthn is the only MFA that defeats AiTM attacks. SMS, TOTP, and push notifications are all vulnerable to real-time proxy interception.

- Deploy hardware security keys (YubiKey) or platform authenticators (Windows Hello, Touch ID)
- Configure Conditional Access to require phishing-resistant authentication strength
- Enable Token Protection for device-bound tokens
- Block device code flow for sensitive accounts
- Reduce sign-in session lifetimes

### Recommendation 4: Enforce Strict Input Typing

Validate JWT claim types (iss must be string, not array), enforce JSON Schema with `additionalProperties: false`, implement strict Content-Type checking, and reject ambiguous HTTP framing:

- JWT `iss` claim must be validated as a string type before library processing
- JSON Schema validation at the API gateway with `additionalProperties: false`
- Reject requests with both Content-Length and Transfer-Encoding headers
- Validate Transfer-Encoding is exactly "chunked" with no obfuscation
- Enforce strict Content-Type matching for API endpoints

### Recommendation 5: Treat All Object References as Authorization Boundaries

Every endpoint that accepts an object identifier must verify ownership. Use automated testing tools:

- **Autorize** (Burp Suite): Automated two-account BOLA/IDOR testing
- **BOLABuster** (Palo Alto): LLM-assisted endpoint analysis
- Test every write endpoint with cross-account identifiers
- Monitor for rapid sequential ID enumeration patterns
- Never rely on UUID obscurity as authorization control

### Recommendation 6: Harden Cloud Metadata Access

- **AWS:** Enforce IMDSv2 with `HttpTokens=required` and hop limit 1
- **Azure:** Network security groups restricting 169.254.169.254 access
- **GCP:** Workload Identity instead of node-level service accounts
- **All clouds:** Block metadata IP at network level (egress firewall)
- Monitor CloudTrail/Cloud Audit for unexpected credential usage from instance roles
- Validate resolved IP addresses (not hostnames) against denylist
- Pin resolved IP for the connection to prevent DNS rebinding

### Recommendation 7: Adopt Zero-Trust for Internal Services

Do not trust X-Forwarded-For, localhost connections, or proxy-asserted identity without verification:

- Overwrite (do not append to) forwarded headers at every trust boundary
- All WebSocket servers must validate Origin against explicit allowlist
- localhost connections are NOT safe -- any website can connect to localhost WebSocket servers
- Strip X-Original-URL and X-Rewrite-URL headers at the edge
- Use mutual TLS (mTLS) for service-to-service communication
- Behind Cloudflare, use CF-Connecting-IP instead of X-Forwarded-For

### Recommendation 8: Test All Protocol Layers

Include the following in regular security testing:

| Test Category | Tools | What to Test |
|--------------|-------|--------------|
| HTTP smuggling | smuggler.py, Burp HTTP Request Smuggler | CL.TE, TE.CL, TE.TE obfuscation, chunk extensions, obs-fold |
| WebSocket auth | wscat, custom scripts | Origin validation, post-handshake re-auth, CSWSH |
| GraphQL batching | BatchQL, InQL, graphql-cop | Alias batching limits, array batching, APQ registration |
| Path normalization | proxyaudit, manual curl | All encoding variants, double slashes, trailing slashes, dot segments |
| CORS policy | CORStest, cors-misconfig-scanner | Origin reflection, null origin, subdomain trust, regex bypass |
| OAuth flow | Manual, Burp Suite | Redirect URI validation, PKCE enforcement, state parameter, device code flow |
| API versioning | Manual enumeration | Version downgrade, shadow API discovery, deprecated endpoint access |
| JWT security | jwt_tool | Algorithm confusion, JKU injection, kid injection, claim type confusion |
| Token leakage | Log scanning, dependency audit | Tokens in URLs, Referer headers, logs, cross-origin redirects |
| Cloud metadata | Manual SSRF testing | IMDSv1/v2, DNS rebinding, IP encoding bypasses, redirect chains |

---

## 10. SSRF-to-Authentication-Bypass Chain Reference

This section documents the most critical multi-step chains observed in the wild.

### Chain 1: SSRF -> Internal API -> Auth Bypass -> RCE

```
CVE-2024-21893 (Ivanti SSRF via SAML)
  -> CVE-2024-21887 (command injection)
  -> Unauthenticated RCE
  -> 170+ attacker IPs observed
  -> CISA KEV

CVE-2025-4427 (Ivanti EPMM auth bypass)
  -> CVE-2025-4428 (EL injection RCE)
  -> KrustyLoader malware delivery
  -> NHS trusts targeted

CVE-2025-61882 (Oracle EBS SSRF)
  -> CRLF header injection
  -> Path traversal
  -> XSLT processing RCE
  -> Cl0p ransomware (since Aug 9, 2025)
  -> CISA KEV
```

### Chain 2: XSS -> OAuth Token Theft -> Account Takeover

```
XSS injection point (Hotjar returnURL=javascript:)
  -> Open popup to OAuth authorization endpoint
  -> Silent OAuth flow completion (user has active session)
  -> Read token from popup window
  -> Exfiltrate to attacker server
  -> Full account takeover
  -> 1M+ websites at risk
```

### Chain 3: IDOR -> Email Change -> Password Reset -> Account Takeover

```
Authenticate as attacker
  -> Intercept account update request
  -> Substitute victim's user ID
  -> Change victim's email to attacker-controlled
  -> Trigger password reset to new email
  -> Complete reset
  -> Full account takeover
```

### Chain 4: Host Header Injection -> Password Reset Poisoning -> Account Takeover

```
Attacker initiates password reset for victim
  -> Inject malicious Host header (or X-Forwarded-Host)
  -> Application generates reset link using injected Host
  -> Victim receives legitimate email with attacker-controlled link
  -> Victim clicks link
  -> Token captured by attacker's server
  -> Password reset completed
  -> 1-click account takeover
```
