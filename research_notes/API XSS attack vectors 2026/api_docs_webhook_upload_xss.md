# XSS in API Documentation Interfaces, Webhook/Callback Systems, and File Upload API Endpoints

## Swagger UI XSS Vulnerabilities (2024-2026)

### Takeaway
Swagger UI has a long history of XSS vulnerabilities stemming from insufficient sanitization of OpenAPI spec content, OAuth flow URLs, and query parameters. The most impactful recent flaw (versions 3.14.1 through 3.38.0) uses an outdated DOMPurify library combined with remote spec loading to achieve DOM-based XSS. No 2024-2026 CVE matching the description of CVE-2024-47878 (badge rendering XSS) was found in official sources.

### Cited Findings
- Swagger UI versions 3.14.1 through 3.38.0 contain a DOM-based XSS vulnerability caused by an outdated DOMPurify sanitization library. A crafted malicious specification file linked through the `url` or `configURL` query parameters enables arbitrary JavaScript execution in the victim's browser. — [Acunetix Advisory](https://www.acunetix.com/vulnerabilities/web/swagger-ui-dom-xss-vulnerability/); [Tenable Plugin 113267](https://www.tenable.com/plugins/was/113267)
- Swagger UI versions before 3.20.9 fail to sanitize URLs used in the OAuth authentication flow, enabling script execution (GHSA-4f9m-pxwh-68hg). — [Snyk SNYK-JS-SWAGGERUI-449921](https://security.snyk.io/vuln/SNYK-JS-SWAGGERUI-449921)
- Swagger UI versions before 2.2.1 allowed unsanitized HTML in `apiInfo` description fields (GHSA-w992-2gmj-9xxj) and unsanitized JSON schema method descriptions (GHSA-vp93-gcx5-4w52), both enabling arbitrary JavaScript execution. — [npm Advisory 988](https://www.npmjs.com/advisories/988); [npm Advisory 976](https://www.npmjs.com/advisories/976)
- Loading remote OpenAPI specs via the `?url` query parameter was treated as a phishing vector; the maintainers disabled query parameters by default starting in version 4.1.3 (GHSA-qrmm-w75w-3wpx). The advisory states that non-interactive attacks such as cross-site scripting or code injection are not possible through this mechanism alone. — [GitHub Advisory GHSA-qrmm-w75w-3wpx](https://advisories.ecosyste.ms/advisories/GSA_kwCzR0hTQS1xcm1tLXc3NXctM3dweM0agw)
- Swagger UI versions before 3.4.2 allowed insertion of `javascript:` and `data:` URLs from user-influenced `href` fields. — [Snyk npm:swagger-ui:20171031](https://security.snyk.io/vuln/npm:swagger-ui:20171031)
- A 2024 HackerOne report (#2534300) on Ionity GmbH describes XSS exploitation in a Swagger UI deployment, though the report's details are not publicly disclosed. — [HackerOne Report 2534300](https://hackerone.com/reports/2534300)
- OpenAPI spec injection vectors include crafting malicious `description` fields with embedded HTML/JavaScript, injecting payloads into `example` values that are rendered without sanitization, and manipulating parameter `default` values that populate the TryItOut panel. — [Medium: Exploiting XSS in Swagger UI](https://medium.com/@eabubakr21/exploiting-xss-in-swagger-ui-turning-apis-into-xss-playground-47ece3069d24)

### Inferences
- The pattern of Swagger UI XSS revolves around three attack surfaces: (1) OpenAPI spec content rendered as HTML (descriptions, examples, schemas), (2) query parameters that control which spec is loaded or how the UI is configured, and (3) OAuth flow URLs that are reflected into the page. Deployments using versions older than 4.1.3 with query parameters enabled remain at highest risk.
- CVE-2024-47878 was specifically asked about but could not be found in NVD, GitHub Security Advisories for swagger-api/swagger-ui, Snyk, or any aggregator. It may be a misidentified CVE number, not yet published, or associated with a different product.

### Gaps
- CVE-2024-47878 (described as badge rendering XSS in Swagger UI) was not found in any authoritative vulnerability database or the swagger-ui GitHub security advisories page. The swagger-ui security advisories page on GitHub lists only one advisory (GHSA-qrmm-w75w-3wpx from 2021). No reliable source confirms this CVE exists for Swagger UI.
- No TryItOut panel-specific injection CVE was found from 2024-2026. The TryItOut panel populates fields from spec defaults but no advisory specifically targets this as an XSS vector.


## Redoc XSS Vulnerabilities

### Takeaway
No Redoc-specific XSS advisory was found from 2024-2026 in any searched database. However, the underlying Markdown rendering libraries used by tools like Redoc have had relevant vulnerabilities, including markdown-it XSS via custom highlight functions (CVE-2025-7969) and Nuxt MDC's JavaScript URL filter bypasses.

### Cited Findings
- markdown-it 14.1.0 (CVE-2025-7969): A reflected XSS allows arbitrary JavaScript execution when custom highlight functions are used. The maintainers do not consider this a vulnerability and no vendor patch has been released. — [Fluid Attacks Advisory](https://fluidattacks.com/es/advisories/fito); [Ubuntu CVE Tracker](https://ubuntu.com/security/CVE-2025-7969)
- @nuxtjs/mdc (CVE-2025-24981): A bypass of the `javascript:` URL filter using hex-encoded HTML entities. Fixed in version 0.13.3. — [OpenCVE CVE-2025-24981](https://app.opencve.io/cve/CVE-2025-24981)
- @nuxtjs/mdc (CVE-2025-54075): A stored XSS where a Markdown author can inject a `<base>` element, redirecting all relative URLs on the page. Fixed in version 0.17.2. — [GCVE Database](https://db.gcve.eu/vuln/cve-2025-54075)
- MarkTwo (CVE-2025-51691): The Markdown editor does not properly sanitize user-supplied Markdown before rendering it, enabling script execution. — [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2025-51691)

### Inferences
- While no Redoc-specific CVE exists, Redoc renders OpenAPI descriptions as Markdown/HTML. Any deployment using vulnerable Markdown parsing libraries (particularly markdown-it with custom plugins) is potentially exposed. The attack vector would be a malicious API description containing crafted Markdown that bypasses the sanitizer.
- Schema example injection in Redoc would follow the same pattern as Swagger UI description injection: user-controlled spec content rendered without adequate sanitization.

### Gaps
- No Redoc-specific XSS advisory was found in NVD, Snyk, GitHub Advisories, or any aggregator for 2024-2026. The Redocly GitHub repository's security advisories were not searchable through web search, so a manual check of https://github.com/Redocly/redoc/security/advisories is recommended.
- No information was found on schema example injection specific to Redoc's rendering pipeline.


## GraphiQL XSS Vectors

### Takeaway
CVE-2026-42794 is a confirmed reflected XSS in GraphiQL caused by a backslash bypass in the query parameter escaping routine. The CVSS score is 2.3 (Low). Older CVEs (2021-41248 and 2021-41249) cover introspection schema injection and query-parameter endpoint manipulation respectively.

### Cited Findings
- CVE-2026-42794: A reflected XSS in GraphiQL where the escaping routine fails to escape backslashes when it escapes single quotes and newlines, allowing a crafted `query` GET parameter to break out of the string context. CVSS 2.3 (Low). Affects version 1.2.0 and above, and version 20241017cb and above. — [CVEMon](https://cvemon.intruder.io/cves/technologies/graphql-vulnerabilities?page=2)
- CVE-2021-41248 (GraphiQL): Versions older than 1.4.7 are vulnerable to compromised schema introspection responses or `schema` prop values containing malicious GraphQL type names that inject JavaScript. — [CVEFeed CVE-2021-41248](https://cvefeed.io/vuln/detail/CVE-2021-41248); [Fluid Attacks](https://db.fluidattacks.com/adv/npm/graphiql/CVE-2021-41248)
- CVE-2021-41249 (GraphQL Playground): The `endpoint` query parameter allows loading a malicious schema URL directly. Fixed in graphql-playground-react 1.7.28 and later. — [GitHub Advisory GHSA-59r9-6jp6-jcm7](https://redirect.github.com/advisories/GHSA-59r9-6jp6-jcm7)

### Inferences
- The backslash bypass (CVE-2026-42794) is a classic escaping oversight: the code handles single quotes and newlines but not backslashes, allowing `\'` sequences to neutralize the quote escaping. Despite the Low CVSS, it is exploitable in any deployment that accepts GET-parameterized queries, which is a common configuration for shareable GraphiQL links.
- GET parameter injection remains the primary GraphiQL attack surface since many deployments accept `query`, `variables`, and `operationName` as URL parameters for link-sharing purposes.
- Custom header injection in GraphiQL Explorer (a plugin that adds a headers panel) was not found as a reported CVE. The theoretical vector would be unsanitized header values reflected into the DOM.

### Gaps
- No fixed version was found for CVE-2026-42794 in the sources accessed. The primary GraphiQL GitHub security advisory for this CVE was not returned by search results.
- No CVE or advisory was found for custom header injection in GraphiQL Explorer as a specific XSS vector.
- The CVE-2026-42794 details come from a third-party aggregator, not the official GraphiQL advisory. The exact affected version range should be verified against the GraphiQL GitHub repository.


## API Playground Injection Techniques

### Takeaway
The most significant finding is CVE-2025-1087, a critical (CVSS 9.8) template injection vulnerability in Kong Insomnia Desktop before version 11.0.2 that enables remote code execution. Postman collection injection for XSS within Postman itself was not found as a reported CVE from 2024-2025.

### Cited Findings
- CVE-2025-1087 (Kong Insomnia): A critical template injection vulnerability (CVSS v3.0: 9.8, CVSS v4.0: 9.3) in Insomnia Desktop Application before version 11.0.2. The flaw allows attackers to execute arbitrary code through malicious API responses, imports, or cookies due to improper input validation of template strings (CWE-20, CWE-94). — [Tenable CVE-2025-1087](https://www.tenable.com/cve/CVE-2025-1087); [Tantosec Blog](https://tantosec.com/blog/2025/06/insomnia-api-client-template-injection/)
- One researcher claims the Insomnia fix was bypassed and the issue remains remotely exploitable in version 11.2.0 via cookies, imports, and other vectors. This is a single-source claim and not confirmed by the vendor. — [CVELogic](https://www.cvelogic.com/cve/CVE-2025-1087)
- Sonar's "Scripting Outside the Box" research series covers security risks in Electron-based API clients (Postman, Insomnia, Bruno, Hoppscotch), noting that disabled security features like `nodeIntegration` and `contextIsolation` expand the impact of XSS from DOM-level to full system access. — [SonarSource Blog Part 1](https://www.sonarsource.com/blog/scripting-outside-the-box-api-client-security-risks-part-1/) (page inaccessible during research)
- A BSides Canberra 2025 talk covers API client security risks, referencing the same class of vulnerabilities. — [BSides Canberra 2025](https://pretalx.com/bsides-canberra-2025/talk/MEXLVK/)

### Inferences
- API clients that support template strings (e.g., `{{ response.body.token }}`) in environment variables, request bodies, and headers are vulnerable to injection when those templates process attacker-controlled data (API responses, imported collections, cookies set by malicious servers).
- Postman's sandboxed scripting model (pre-request and test scripts run in a Node.js sandbox) provides more isolation than Insomnia's template system, which may explain why Insomnia has the more severe CVE.
- Collection/workspace sharing (via Git, export files, or team sync) is the primary delivery mechanism for poisoned configurations. A malicious collection file could contain template injection payloads in environment variables, request URLs, or headers.

### Gaps
- No Postman-specific CVE for collection injection or workspace poisoning XSS was found from 2024-2025. Postman's security advisories were not accessible through the search.
- The Sonar research article could not be fetched due to DNS resolution failure. Its detailed findings on specific API client vulnerabilities are not included.
- No Bruno or Hoppscotch specific CVEs were found in this research.


## Webhook Payload Stored XSS

### Takeaway
CVE-2026-11855 in the Simple Membership WordPress plugin (CVSS 8.8) demonstrates the canonical webhook stored XSS pattern: Stripe webhook payloads are stored and rendered in admin notices without HTML escaping or signature verification. No stored XSS was found in Stripe, GitHub, or Slack's own webhook dashboard interfaces.

### Cited Findings
- CVE-2026-11855 (Simple Membership plugin): Before version 4.7.5, the plugin does not verify the authenticity of Stripe webhook requests when no signing secret is configured, nor escape a value taken from them before outputting it in an administrator notice. CVSS 8.8. — [OpenCVE CVE-2026-11855](https://app.opencve.io/cve/CVE-2026-11855); [Lutra Security Fieldguide](https://fieldguide.lutrasecurity.com/CVE-2026-11855/)
- Stripe signs all webhook payloads with HMAC-SHA256 using a webhook signing secret and includes a timestamp to prevent replay attacks. The webhook signature is in the `Stripe-Signature` header. — [Pinggy Webhooks Deep Dive](https://pinggy.io/blog/webhooks_explained_technical_deep_dive/)
- Slack uses a similar signing approach for its webhook payloads. Both providers document signature verification as the primary defense against payload forgery. — [Pinggy Webhooks Deep Dive](https://pinggy.io/blog/webhooks_explained_technical_deep_dive/)
- GitHub Enterprise had a stored XSS on pull request pages where branches with HTML in the name injected attacker-controlled HTML. Fixed in GitHub Enterprise v2.1.6. This is not webhook-specific but demonstrates HTML injection in GitHub's UI from user-controlled data. — [GitHub Bug Bounty](https://bounty.github.com/researchers/hughdavenport.html)

### Inferences
- The webhook stored XSS pattern occurs when: (1) webhook payloads containing user-controlled fields (names, descriptions, metadata) are stored in a database, (2) an admin dashboard renders those stored values without HTML encoding, and (3) webhook signature verification is absent or optional. All three conditions must be present.
- Stripe, GitHub, and Slack's own dashboard interfaces appear to properly sanitize webhook data for display. The vulnerability surface is in third-party applications that receive and display webhook data, not in the webhook providers themselves.
- The pattern extends beyond the named providers: any SaaS webhook (Twilio, SendGrid, Shopify, etc.) that includes user-controlled fields (customer names, message bodies, product descriptions) can be an XSS vector if the receiving application renders them without sanitization.

### Gaps
- No stored XSS was found in Stripe's own dashboard, GitHub's webhook delivery logs, or Slack's webhook management interface.
- No Twilio webhook-specific XSS CVE was found from 2024-2026.
- Bug bounty writeups on HackerOne/Bugcrowd for webhook XSS were not accessible through search results (most reports are private).


## Callback URL Injection and XSS

### Takeaway
OAuth callback/redirect_uri handling remains a significant XSS vector in 2025-2026. The better-auth library's stored XSS via `javascript:` redirect_uri (pre-1.6.13) and Spotipy's unsanitized OAuth callback error parameters (CVE-2025-66040) demonstrate that URI scheme validation and output encoding at callback endpoints are essential but frequently missing.

### Cited Findings
- better-auth (pre-1.6.13): The oidc-provider and mcp plugins failed to validate the scheme of `redirect_uri` values registered by clients. An attacker could register a client with a `javascript:` redirect_uri, which the authorization server returned unchanged. When a consent page assigned the returned value to `window.location.href`, attacker script executed in the authorization server's origin. Fixed by rejecting `javascript:`, `data:`, and `vbscript:` schemes at registration. — [SecureLayer7 Lab](https://securelayer7.net/lab/better-auth-stored-xss-javascript-redirect-uri-oidc-provider) (page inaccessible during research; information from search snippet)
- CVE-2025-66040 (Spotipy): An unsanitized error parameter in the library's local OAuth callback server allowed attackers to execute JavaScript in the user's browser during OAuth authentication. — [GitLab Advisory Database](https://advisories.gitlab.com/pkg/pypi/spotipy/CVE-2025-66040/)
- CVE-2026-27191 (Feathers.js): Concatenating a user-supplied `redirect` parameter onto a base origin allowed attackers to alter the URL authority during callback handling, leading to token leakage via open redirect. Affects versions up to 5.0.39, patched in 5.0.40. Not XSS directly, but chainable with XSS. — [Wiz Vulnerability Database](https://www.wiz.io/vulnerability-database/cve/cve-2026-27191)
- Salt Security research (November 2025): Demonstrates that DOM-based XSS can be chained with OAuth login flows to bypass HTTP-only cookies and extract tokens. HTTP-only cookies block direct JavaScript access to cookie values but do not prevent script execution or malicious redirects. — [NHI Management Group](https://nhimg.org/articles/xss-and-oauth-combine-into-a-modern-account-takeover-path/)
- GitHub bug bounty: A callback URL inserted into an anchor `href` on a redirect page could carry a `javascript:` URL. Impact was limited because a user had to manually click the link to trigger execution. GitHub responded by blocking dangerous schemes in callback URLs. — [GitHub Bug Bounty](https://bounty.github.com/researchers/WHHackersBR.html)

### Inferences
- The `javascript:` URI scheme in callback/redirect URLs is the most common callback injection pattern. Defenses must validate URI schemes at registration time (for OAuth clients) and at redirect time (for dynamic callbacks). Allowlisting `https://` only is the most robust approach.
- The chain of XSS + OAuth is particularly dangerous because it can elevate a reflected XSS into full account takeover by stealing authorization codes or tokens from the redirect flow.
- Callback URL injection applies beyond OAuth: any system that accepts a user-provided URL for post-action redirects (payment completion, email verification, SSO) is potentially vulnerable if it does not validate the scheme and domain.

### Gaps
- The better-auth advisory could not be fetched directly. CVE assignment status and CVSS score for this vulnerability are unknown.
- No CVE-specific information was found for redirect-to-XSS via multi-hop callback chains as a named technique.


## Notification Template XSS

### Takeaway
Notification template XSS occurs when admin-facing previews or dashboards render user-controlled data (event titles, usernames, form submissions) without HTML encoding. The impact is typically limited to authenticated administrators viewing previews, not end-user email recipients, because most email clients strip JavaScript.

### Cited Findings
- CVE-2024-25151 (Liferay): Calendar notification email templates did not escape user-supplied data, allowing remote authenticated users to inject script or HTML through calendar event titles or user names. Impact depends on the recipient's mail client. — [GCVE Database](https://db.gcve.eu/vuln/cve-2024-25151)
- CVE-2024-31946 (Stormshield SNS): Malicious JavaScript in an alert email template ran in the template's preview on the management console. CVSS 3.9 (Low). Exploitation required write access to the email alerts page. Affects SNS 3.7.0-3.7.41, 3.10.0-3.11.29, 4.0-4.3.24, 4.4.0-4.7.4. Fixed in 3.7.42, 3.11.30, 4.3.25, 4.7.5. — [Stormshield Advisory 2024-007](https://advisories.stormshield.eu/2024-007)
- CVE-2025-32426 (Formie/Craft CMS): Injected code in an email notification's HTML rendered in the admin preview, but not when the email was delivered normally. Exploitation needed access to the form's notification settings. — [GitLab Advisory Database](https://advisories.gitlab.com/composer/verbb/formie/CVE-2025-32426/)
- CVE-2025-58873 (Pushe Web Push): A stored XSS in a WordPress web push notification plugin affecting versions up to 0.5.0. Exploitation requires a high-privileged authenticated attacker. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-58873/)
- CVE-2025-31311 (All Push Notification for WP): A reflected XSS in an admin page where request parameters were echoed without validation. — [Fluid Attacks Advisory](https://fluidattacks.com/advisories/fka)

### Inferences
- The common pattern is that notification template XSS affects the admin preview/management interface, not the delivered notification itself. Most email clients strip `<script>` tags and event handlers, limiting the impact of template injection in actual delivered emails.
- Push notification template XSS is more impactful than email template XSS because push notification content may be rendered in contexts (browser notification UI, in-app webviews) that execute JavaScript.
- SMS notification template XSS is largely theoretical since SMS is plaintext. The risk exists only if SMS content is later displayed in a web-based dashboard without encoding.

### Gaps
- No SMS notification template XSS CVE was found from 2024-2026.
- No cases of push notification payload XSS affecting end-user devices (as opposed to admin dashboards) were found.


## Multipart File Upload XSS via API Endpoints

### Takeaway
File upload XSS via API endpoints exploits three main vectors: filename injection in Content-Disposition headers, MIME type confusion when browsers sniff content types, and serving uploaded files inline without sanitization. A recent Netty CVE demonstrates CRLF injection through filenames in multipart requests.

### Cited Findings
- Netty multipart encoder (CVE number in 2026 range, exact ID unconfirmed): The multipart encoder builds Content-Disposition headers from unvalidated filenames. An attacker-controlled filename containing line breaks (CRLF) can inject extra MIME headers, with XSS listed as a possible impact. CVSS 8.1. Affects Netty 4.2.12.Final and all prior versions with codec-http multipart. — [TuxCare CVE Tracker](https://tuxcare.com/cve-tracker/cve/details/cve-2026-59921/)
- Firefox Content-Disposition bypass (CVE-2010-1197): Firefox ignored the `Content-Disposition: attachment` header when a multipart Content-Type was also present, enabling uploaded HTML to render inline. Fixed in Firefox 3.5.10 and 3.6.4. Historical context for why attachment disposition alone is not sufficient. — [Mozilla Advisory MFSA 2010-32](https://www.mozilla.org/security/advisories/mfsa2010-32/)
- MIME type confusion attack: When a web application serves a file with a Content-Type header that does not match the file's actual content, browsers may sniff the content and render it as HTML. The `X-Content-Type-Options: nosniff` header mitigates this. — [Security Scientist](https://www.securityscientist.net/blog/12-questions-and-answers-about-xss-using-mime-type-mismatch/)

### Inferences
- API-specific file upload XSS differs from form-based upload XSS primarily in how the uploaded content is served back. APIs that return uploaded filenames in JSON responses (e.g., `{"filename": "<script>alert(1)</script>"}`) create reflected XSS if the response Content-Type is `text/html` or if a frontend renders the filename without encoding.
- The filename XSS pattern works when: (1) the API accepts multipart uploads with user-controlled filenames, (2) the filename is stored or echoed without sanitization, and (3) the filename appears in a context where HTML is rendered (admin file listing, download page, Content-Disposition header reflected in a page).
- Polyglot files (valid as multiple formats simultaneously, e.g., a file that is both a valid JPEG and valid JavaScript) bypass content-type validation that checks only the file header/magic bytes. They are most effective when the serving endpoint uses the uploaded file's extension to set Content-Type rather than validating the actual content.

### Gaps
- The Netty CVE number (reported as CVE-2026-59921) was found only in a third-party tracker and should be verified against the official Netty advisory.
- No specific CVE for polyglot file upload bypasses was found from 2024-2026. The technique is well-documented in older research but no recent advisory was identified.
- No API-endpoint-specific (as opposed to web form) file upload XSS CVE was found; the distinction is architectural rather than vulnerability-class-specific.


## Presigned URL Abuse for XSS

### Takeaway
Presigned URL abuse for XSS is a recognized but under-documented attack surface. The primary risk is that presigned upload URLs on custom domains allow uploading HTML, JavaScript, or SVG files that execute in the domain's origin. No specific CVE for presigned URL XSS was found from 2024-2025.

### Cited Findings
- AWS-adjacent vendor documentation warns that sharing presigned upload URLs on a custom domain lets users upload HTML, JS, or SVG files, which creates XSS risk on that domain if the uploaded content is served inline. — [Tigris Data Docs](https://www.tigrisdata.com/docs/objects/presigned/)
- A CDN in front of a storage bucket may ignore query parameter overrides (like `response-content-type` or `response-content-disposition`), so the presigned URL's content-type override may not apply when the file is accessed through the CDN. — [Penetrify Cloud Guide](https://www.penetrify.cloud/guides/en/s3-presigned-url-security.html)
- Regenerated presigned URLs differ in signature and expiry parameters, so caches often treat each as a new resource, causing cache misses rather than poisoning. — [Codemia Knowledge Hub](https://codemia.io/knowledge-hub/path/s3_signed-urls_and_caching)
- BSides Joburg 2025 and Melbourne 2025 CyberCon sessions describe presigned URL implementation mistakes that expose data, though their abstracts do not specifically mention XSS or cache poisoning. — [BSides Joburg 2025](https://pretalx.com/bsides-joburg-2025/talk/9VZHPJ); [Melbourne CyberCon 2025](https://melbourne2025.cyberconference.com.au/sessions/session-ovqkxt6fcy)

### Inferences
- The presigned URL XSS attack chain is: (1) obtain a presigned upload URL for a storage bucket served on a custom domain, (2) upload an HTML or SVG file containing JavaScript, (3) the file is served from the custom domain's origin, (4) scripts in the file execute with the domain's cookies and permissions. The fix is to serve user uploads from a separate domain, enforce `Content-Disposition: attachment`, and validate content types server-side.
- S3 presigned URL parameter injection (manipulating `response-content-type` or `response-content-disposition` overrides) is theoretically possible if the signing process does not bind these parameters. AWS S3 signs all query parameters, making tampering detectable, but misconfigured signing (omitting these from the signature) would be exploitable.
- CDN cache poisoning via presigned URLs is limited because the signature parameters make each URL unique, defeating cache key matching. The exception is when a CDN strips query parameters from the cache key while preserving them in the origin request.

### Gaps
- No specific CVE for S3/GCS/Azure Blob presigned URL parameter injection leading to XSS was found.
- AWS's presigned URL best practices PDF was returned as a search result but could not be fetched; its specific guidance on XSS prevention is not included.
- No concrete exploitation examples or proof-of-concept payloads for presigned URL XSS were found in the searched sources.


## CDN Cache Poisoning Leading to XSS via API Endpoints

### Takeaway
CDN cache poisoning for XSS relies on unkeyed inputs (headers the cache ignores but the origin reflects) and path normalization differences between the CDN and the origin server. The axios-cache-interceptor flaw (CVE-2025-69202) demonstrates how API-layer caching that ignores the Vary header can serve wrong responses.

### Cited Findings
- Cache poisoning uses unkeyed inputs: headers the cache ignores when building its key but the origin reflects into the response. Example: `X-Forwarded-Host: evil.com` reflected into `<link rel="canonical">` or absolute URLs, leading to stored XSS for all visitors hitting the cached response. — [HackTricks Cache Deception](https://book.hacktricks.xyz/pentesting-web/cache-deception) (page inaccessible; information from search snippet)
- CVE-2025-69202 (axios-cache-interceptor): The cache key is generated only from the URL, ignoring request headers like Authorization. When the server responds with `Vary: Authorization`, the library ignores this, causing all requests to share the same cache entry regardless of authentication state. Fixed in version 1.11.1. — [OSV CVE-2025-69202](https://osv.dev/vulnerability/CVE-2025-69202)
- Cache deception vs. poisoning distinction: Cache deception tricks the cache into storing a victim's private response (e.g., via path confusion like `/api/profile/nonexistent.css`). Cache poisoning stores an attacker-controlled response for every later visitor. Both can be chained with XSS. — [GitHub Advisory GHSA-x4m5-4cw8-vc44](https://osv.dev/vulnerability/GHSA-x4m5-4cw8-vc44)
- James Kettle's 2024 research on path-normalization Web Cache Deception against Cloudflare, Fastly, and GCP was referenced in search results but the actual research paper/blog post was not returned. — Referenced in [Tessl skill page](https://tessl.io/registry/skills/github/PurpleAILAB/Decepticon/web-cache-poisoning)

### Inferences
- API endpoints are particularly vulnerable to cache poisoning when: (1) they sit behind a CDN that caches GET responses, (2) they reflect user-controlled headers (X-Forwarded-Host, X-Forwarded-Proto, Origin) into response bodies, and (3) those reflected headers are not included in the cache key. JSON API responses with JSONP callbacks or HTML error pages are the most exploitable.
- The Vary header is the primary mechanism for ensuring per-user cache entries, but it is frequently misconfigured. API endpoints that vary responses by Authorization header must include `Vary: Authorization`; omitting it means the CDN may serve one user's authenticated response to another.
- Web Cache Deception on API routes exploits path normalization differences: the CDN sees `/api/user/profile.css` as cacheable static content while the API server ignores the extension and returns the user's profile data. This leaks data rather than enabling XSS directly, but can be chained with XSS if the cached response includes user-controlled content.

### Gaps
- James Kettle's 2024 path-normalization research details could not be fetched. The specific techniques for Cloudflare, Fastly, and GCP are not included.
- No specific CVE for CDN cache poisoning leading to XSS via API endpoints was found from 2024-2026. The technique is documented in PortSwigger research but no API-specific advisory was identified.
- `Vary` header abuse as a specific attack technique (manipulating which headers appear in Vary to expand or contract the cache key) was referenced but no concrete exploitation example was found.


## SVG/PDF Upload XSS via API Endpoints

### Takeaway
SVG upload XSS is the most common file-type-specific XSS vector in 2025, with at least six CVEs across different products (FileRise, WordPress plugins, Nextcloud, Seafile, Foxit). The root cause is consistently serving SVG files inline without sanitization, Content-Disposition: attachment, or restrictive CSP.

### Cited Findings
- CVE-2025-66403 (FileRise): Before version 2.2.3, the file manager accepted SVG uploads without sanitizing embedded scripts. Stored XSS triggered when users viewed the files. — [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2025-66403)
- CVE-2025-9698 (Plus Addons for Elementor): Versions before 6.3.16 did not sanitize uploaded SVGs. An authenticated Author-level user could upload an SVG that ran JavaScript when an administrator previewed it. Impact includes stealing authentication cookies, performing REST API actions as admin, creating privileged users, or installing backdoor plugins. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-9698/)
- CVE-2025-66512 (Nextcloud): Versions before 31.0.12 and 32.0.3 lacked SVG sanitization. When SVGs were viewed outside the application (direct URL), the browser did not enforce Nextcloud's CSP, allowing embedded scripts to execute. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-66512/)
- CVE-2025-65516 (Seafile): The Golang file server did not force safe content types or attachment disposition for SVGs. Attackers could share a public link to deliver the XSS payload without needing the victim's session. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-65516/)
- CVE-2025-66520 (Foxit PDF Editor Cloud): The Portfolio feature inserted uploaded SVG content into the page without sanitizing it. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-66520/)
- Additional 2025 SVG XSS cases: Fiora (CVE-2025-56515), Emlog Pro (CVE-2025-60448), OpenCart 4.1.0.4 (CVE-2025-45893), Bludit 3.16.2 (Full Disclosure). — [GitLab Advisory (Fiora)](https://advisories.gitlab.com/pkg/npm/fiora/CVE-2025-56515); [GCVE (OpenCart)](https://db.gcve.eu/vuln/cve-2025-45893); [Full Disclosure (Bludit)](https://seclists.org/fulldisclosure/2025/Jul/2)
- CVE-2024-8029: An SVG upload XSS in an unspecified product from the 2024 timeframe. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2024-8029/)

### Inferences
- SVG is XML that can contain `<script>` elements, event handler attributes (`onload`, `onclick`), `<foreignObject>` elements embedding HTML, and `<use>` elements referencing external resources. All of these must be stripped during sanitization. Libraries like DOMPurify with SVG-specific configuration are the standard approach.
- The API-specific angle for SVG XSS is that APIs often serve uploaded files from the same origin as the application. When an API endpoint returns an SVG with `Content-Type: image/svg+xml` and no `Content-Disposition: attachment`, browsers render it with full script execution in the application's origin.
- PDF upload XSS (via embedded JavaScript in PDF forms or actions) is a smaller attack surface than SVG because modern browsers' PDF viewers sandbox JavaScript execution. However, Foxit's cloud product (CVE-2025-66520) shows that PDF-adjacent features (portfolios, annotations) that render user content in the web UI remain vulnerable.
- The Seafile case (CVE-2025-65516) is particularly relevant for API endpoints: the Golang file server component is a REST API that serves files, and the fix was to add Content-Disposition and content-type enforcement at the API layer.

### Gaps
- No polyglot file (valid as two formats) XSS CVE was found from 2024-2026. The polyglot technique is documented in older research (e.g., PoC||GTFO) but no recent advisory uses it as the primary attack vector.
- PDF-specific XSS through API endpoints (as opposed to SVG) had only one example (Foxit Cloud). No cases of PDF JavaScript execution leading to origin-level XSS via API-served PDFs were found.
- No comparison was found of SVG sanitization libraries and their bypass rates in 2024-2025.
