# API Parameter Handling, Error Handling, and Multi-Step XSS Attack Chaining

## HTTP Parameter Pollution (HPP) to XSS Techniques (2024-2026)

### Takeaway
HPP remains a viable XSS vector in 2025-2026, particularly through ASP.NET's parameter concatenation behavior combined with JavaScript's comma operator to bypass WAFs. Research by Bruno Mendes showed only 3 of 17 major WAF configurations blocked sophisticated HPP attacks.

### Cited Findings
- ASP.NET's `HttpUtility.ParseQueryString()` concatenates duplicate parameter values with commas. Combined with JavaScript's comma operator, this enables XSS payloads split across multiple parameters to reassemble on the backend. Research tested 17 WAF configurations including AWS, Google Cloud, Azure, and Cloudflare; only 3 blocked the attack. One secondary source claims a 70.6% bypass rate against tested configurations, though the primary source for that figure could not be confirmed. -- [CybersecurityNews: WAFs Protection Bypassed](https://cybersecuritynews.com/wafs-protection-bypassed/)
- Framework-specific parameter handling differences create the core vulnerability: PHP takes the last parameter value, ASP.NET concatenates with commas, Apache Tomcat uses the first value, and Node.js Express creates arrays. When a WAF inspects one value and the backend renders another, the filter check and execution context diverge. -- [Medium: HTTP Parameter Pollution](https://medium.com/@pavankumarck684/http-parameter-pollution-hpp-78197aef60b7)
- Payload fragmentation across multiple parameters that are later joined client-side is described as a broader pattern in a February 2026 guide update. For example, splitting `<script>alert(1)</script>` across `?a=<script>alert&b=(1)</script>` where the application concatenates `a+b`. -- [CHS.us: XSS Prevention Guide 2026](https://chs.us/guides/xss/)
- A March 2026 report describes reflected XSS via OAuth error parameters where the application's OAuth handler failed to properly escape the `error_description` parameter during string interpolation. The vendor was not named. -- [GitHub: Advanced-XSS](https://github.com/Karthikdude/Advanced-XSS)
- HPP was originally presented by Stefano di Paola and Luca Carettoni in 2009 and is covered in OWASP's Web Security Testing Guide under WSTG-INPV-04. -- [Wikipedia: HTTP Parameter Pollution](https://en.wikipedia.org/wiki/HTTP_parameter_pollution); [Cobalt: HPP to XSS](https://www.cobalt.io/vulnerability-wiki/v5-validation-sanitization/http-parameter-pollution)

### Inferences
- The divergence between WAF parameter parsing and backend framework parsing is the root cause. Defenses must normalize duplicate parameters the same way the backend does.
- Array parameter handling in Node.js Express (creating arrays from duplicate params) opens a distinct attack surface compared to ASP.NET's concatenation -- type confusion when an array is rendered as a string could produce unexpected output.
- The OAuth error_description case suggests that OAuth/OIDC redirect flows remain a high-value target for HPP, since error parameters are often reflected in user-facing pages.

### Gaps
- The exact Bruno Mendes research paper or Ethiack publication could not be fetched to verify the 70.6% bypass rate or the specific payload examples used.
- No primary-source data on HPP behavior differences in modern frameworks like FastAPI, Go's net/http, or Rust's Actix-web.


## Mass Assignment to Stored XSS Chains

### Takeaway
Mass assignment vulnerabilities in APIs that merge incoming JSON into server models without field allow-listing can inject XSS payloads into fields not exposed in the UI, creating stored XSS that persists and renders across customer instances.

### Cited Findings
- A researcher discovered a major chatbot platform that merged incoming JSON into server models without an allow-list. Combined with inconsistent sanitization and a permissive Content-Security-Policy, persisted HTML was stored and later rendered in customer websites and internal agent consoles, affecting approximately 500 customer instances. The root cause was unsafe mass-assignment where extra fields in API requests were accepted and stored without validation. -- [Medium: How Mass Assignment Led to Stored XSS and CSP Bypass](https://medium.com/@melodicbook/how-mass-assignment-led-to-stored-xss-and-a-csp-bypass-in-a-major-chatbot-platform-3c6569d7c9e9)
- An EASE 2024 academic paper on mining API specifications for mass assignment found that in a study of 100 APIs, 25 were flagged for potential mass assignment, and nine vulnerable operations across six APIs were confirmed. The paper does not specifically cover XSS but confirms the prevalence of the underlying flaw. -- [arXiv: Mass Assignment in REST APIs](https://arxiv.org/html/2405.01111v2)
- A Grafana chain (CVE-2025-6023) demonstrates a stored XSS in a dashboard leading to API token theft and privilege escalation through the API, though the root cause was not mass assignment. -- [CHS.us: XSS Prevention Guide 2026](https://chs.us/guides/xss/)
- Langflow CVE-2025-34291 describes a critical account takeover and RCE vulnerability where XSS was needed to read a non-HttpOnly token cookie, demonstrating the chain potential of stored XSS in API-driven applications. -- [Obsidian Security: CVE-2025-34291](https://www.obsidiansecurity.com/blog/cve-2025-34291-critical-account-takeover-and-rce-vulnerability-in-the-langflow-ai-agent-workflow-platform)

### Inferences
- The chatbot platform case illustrates the canonical mass-assignment-to-stored-XSS pattern: (1) identify writable fields via API that are not in the UI, (2) inject HTML/JS into those hidden fields, (3) the payload renders when displayed in admin panels, dashboards, or other users' views.
- CSP bypass was a necessary second step in the chatbot case, suggesting that mass-assignment XSS alone is often blocked by CSP. Attackers must chain mass assignment with CSP bypass (e.g., finding allowed script sources, using `unsafe-inline`, or exploiting JSONP endpoints on allowed domains).
- The 25% flagged rate from the EASE 2024 study suggests mass assignment is common enough in production APIs to be a reliable first link in attack chains.

### Gaps
- The chatbot platform vendor name was not disclosed, preventing independent verification against CVE databases.
- No reliable source found for mass-assignment-to-XSS chains in GraphQL mutation endpoints specifically.
- Could not retrieve the full Medium article due to DNS resolution failure during research.


## IDOR + XSS Chaining Techniques

### Takeaway
IDOR and XSS are frequently chained in bug bounty reports: IDOR provides write access to other users' data, and XSS payloads injected through that access execute in victims' browsers, often escalating to account takeover.

### Cited Findings
- A writeup database lists "Zero Click To Account Takeover (IDOR + XSS)" (published 2022-12-21), "Exploiting a Self Stored XSS with an IDOR," and "How I Pwned a company using IDOR & Blind XSS" as documented chain examples. -- [Writeup-DB](https://www.writeup-db.com/writeups-list/page/15/?search=IDOR)
- A 2026 bug bounty checklist describes the chain pattern: stored XSS injected into a field visible to admins, combined with IDOR to write into other users' profiles. It also notes that GUID-based access controls can be bypassed if another endpoint leaks or lists those GUIDs, forming a complete chain. -- [GitHub: 2026 Bug Bounty Guide](https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md)
- An IDOR cheat sheet explicitly discusses chaining IDOR with XSS to increase impact, noting that IDOR alone may be low severity but chained with XSS becomes high or critical. -- [Notion: IDOR Cheat Sheet](https://jasper-join-7e5.notion.site/IDOR-Cheat-Sheet-9f7c9e3285bf4c7cae5ea38243cd0391)
- A curated list of bug bounty writeups categorizes IDOR and XSS separately but includes cross-chain examples like "XSS to account takeover" and "chaining self XSS with UI redressing leading to session hijacking." -- [GitHub: Awesome Bugbounty Writeups](https://github.com/devanshbatham/Awesome-Bugbounty-Writeups)

### Inferences
- The canonical IDOR+XSS chain follows this pattern: (1) Identify an IDOR in a profile/settings/data API endpoint, (2) Use the IDOR to write an XSS payload into another user's profile field (bio, name, custom field), (3) The payload executes when the victim or an admin views the profile, (4) The XSS steals session tokens or performs actions as the victim.
- Self-XSS (normally unexploitable because it only fires in the attacker's own browser) becomes exploitable when chained with IDOR -- the attacker can write the self-XSS payload into another user's context.
- API endpoints that accept rich text or HTML in profile fields are primary targets, especially when the same data is rendered in admin dashboards without additional sanitization.

### Gaps
- No primary-source 2024-2025 IDOR+XSS writeup with full technical details and verified payout was found in this search. The most specific writeups predate 2024.
- HackerOne Hacktivity was not directly searchable; it likely contains more recent verified examples.


## Race Condition XSS in APIs (TOCTOU)

### Takeaway
No documented case of a TOCTOU race condition specifically leading to XSS sanitization bypass was found in 2024-2025 research. The technique is theoretically plausible but appears extremely rare in practice, with academic research noting that race conditions in web applications are less studied than XSS or SQLi.

### Cited Findings
- OWASP defines the race window as the period in which a collision between concurrent actors is possible, and TOCTOU as a common subtype where two concurrent actors both pass a check before either completes its action, leaving the system in an inconsistent state. -- [OWASP: Race Conditions](https://owasp.org/www-community/pages/vulnerabilities/race_conditions)
- An Information Processing Society of Japan paper from December 2025 studies race conditions in WordPress plugins and notes that "the flaw is not as well-known as Cross Site Scripting and SQL injection," suggesting the XSS-plus-race combination is rarely documented in practice. -- [IPSJ: Race Conditions in WordPress Plugins](https://www.jstage.jst.go.jp/article/ipsjjip/33/0/33_1181/_pdf)
- A September 2026 SecureFlag blog post provides a general overview of TOCTOU, citing recent CVEs including CVE-2025-23359 (NVIDIA Container Toolkit) and CVE-2024-50379 (Apache Tomcat), but none involve XSS. -- [SecureFlag: TOCTOU](https://blog.secureflag.com/2026/09/10/toctou-race-condition/)
- CVE-2024-50379 in Apache Tomcat is a TOCTOU during JSP compilation that allows code execution, not XSS. CVE-2025-22224 in VMware ESXi is an out-of-bounds write from TOCTOU, also not XSS. -- [Extreme Networks: SA-2025-007](https://community.extremenetworks.com/t5/security-advisories-formerly/sa-2025-007-apache-tomcat-toctou-race-condition-vulnerability/ba-p/117603)

### Inferences
- The theoretical attack pattern would be: (1) Submit data that passes XSS sanitization, (2) Before the sanitized value is persisted, a concurrent request overwrites it with an unsanitized payload via a race condition, (3) The unsanitized payload is stored and later rendered. This requires the application to have separate sanitize-then-store steps that are not atomic.
- Modern ORM patterns that sanitize on write (or use parameterized queries) make this less likely, but applications that sanitize in a middleware layer before passing to a separate persistence service could be vulnerable.
- Async/event-driven architectures (Node.js, Python asyncio) where sanitization and storage are separate async operations could theoretically expose this gap.

### Gaps
- No confirmed CVE or bug bounty report combining TOCTOU with XSS was found. This is either extremely rare or underreported.
- No academic research specifically modeling race-condition XSS was found.
- "Mutation XSS" (mXSS) in sanitizer libraries is a related but distinct concept -- sanitizers that mutate DOM in unexpected ways. This was not covered in the TOCTOU search results.


## API Error Handling XSS Vectors

### Takeaway
API error handling remains a significant XSS vector in 2024-2026, with multiple CVEs demonstrating reflected XSS through validation error messages, JSON parse errors, and debug/stack trace pages that echo user input without encoding.

### Cited Findings
- LibreChat security advisory (GHSA-q6c5-gvj5-c264): Invalid JSON payloads in API requests were reflected entirely in the HTTP response, leading to XSS risk when the user includes HTML/JavaScript code in the request body. The advisory states "user supplied input in error messages on a production application should not need to be reflected at all." -- [GitHub: LibreChat Security Advisory](https://github.com/danny-avila/LibreChat/security/advisories/GHSA-q6c5-gvj5-c264)
- BC Government STRR project (PR #1847): Fixes flagged reflected-XSS findings by returning JSON from API responses instead of HTML, ensuring Content-Type is set correctly. -- [GitHub: bcgov/STRR PR #1847](https://github.com/bcgov/STRR/pull/1847)
- Developer guidance identifies validation error messages as a primary sink: "every error message that includes a request parameter is a candidate sink." Form re-rendering after validation failure is also flagged when values are not attribute-encoded. -- [SecureCodingHub: Reflected XSS Guide](https://www.securecodinghub.com/blog/reflected-cross-site-scripting-xss-developer-guide)
- GraphQL error responses are specifically flagged: "if invalid input is shown back to the user, make sure to apply a very strong output sanitization." GraphQL's structured error format can still contain reflected user input in the `message` field. -- [Escape.tech: GraphQL XSS](https://escape.tech/blog/cross-site-scripting-xss-in-graphql/)
- Microsoft's MSRC published a September 2025 perspective on why XSS still matters after 25 years, noting that XSS continues to be a significant attack vector. -- [Microsoft MSRC: Why XSS Still Matters](https://www.microsoft.com/en-us/msrc/blog/2025/09/why-xss-still-matters-msrcs-perspective-on-a-25-year-old-threat)

### Inferences
- The pattern is consistent: APIs that return error messages containing user input, especially when the response Content-Type is text/html or when `X-Content-Type-Options: nosniff` is missing, are vulnerable to reflected XSS.
- JSON APIs are not immune: if a browser renders a JSON response as HTML (missing or wrong Content-Type), script tags in JSON values can execute. The fix is explicit `Content-Type: application/json` plus `X-Content-Type-Options: nosniff` on every response, including errors.
- Framework debug pages (Django DEBUG=True, Rails development mode, Express error handler with stack traces) that display the request path, parameters, or body are a well-known class of this vulnerability, but are typically production-only risks when debug mode is accidentally left enabled.

### Gaps
- No specific CVE for XSS through framework debug pages in production was found from 2024-2025, though the pattern is well-documented in older advisories.
- Stack trace reflection with user input was not found in any specific 2024-2025 advisory.


## Rate Limit Response XSS Vectors

### Takeaway
No confirmed XSS through rate-limiting responses or Retry-After header injection was found. The attack is theoretically possible if a rate-limit error page reflects request details (IP, path, or parameters) without encoding, but no documented case was identified.

### Cited Findings
- Rate-limited responses return HTTP 429 with a `Retry-After` header indicating how long to wait (in seconds or as an HTTP date). The header value is typically generated server-side from limiter state, not from user input. -- [Givebutter API: Rate Limits](https://docs.givebutter.com/api-reference/rate-limits)
- Header injection through request headers reflected into responses (Location, Set-Cookie, Content-Type, Content-Disposition, Link, or custom X-* headers) is a documented attack surface via CRLF injection. However, no source specifically mentions Retry-After as a vector. -- [Tessl.io: Header Injection](https://tessl.io/registry/skills/github/PurpleAILAB/Decepticon/header-injection)
- X-Forwarded-For rate-limit bypass is a related class of bug focused on evading limits rather than injecting into responses. -- [Tessl.io: Header Injection](https://tessl.io/registry/skills/github/PurpleAILAB/Decepticon/header-injection)

### Inferences
- The most plausible rate-limit XSS scenario is: a custom 429 error page that includes the request path, IP address, or user-agent in its HTML response without encoding. For example: "Too many requests from <script>alert(1)</script> for endpoint /api/users" where the user-agent or a parameter is reflected.
- Retry-After header injection would require CRLF injection to control the header value and then a client or proxy that renders the header in an HTML context, which is a narrow attack surface.
- Rate limit responses that return JSON with reflected request details and wrong Content-Type could also be exploitable.

### Gaps
- No CVE or bug bounty report demonstrating XSS through rate-limit responses was found.
- No documented case of Retry-After header injection leading to XSS was found. This appears to be a theoretical vector rather than a demonstrated one.


## 404/500 Error Page Injection in API Contexts

### Takeaway
404 and 500 error pages that reflect the requested path or query parameters remain a common and well-documented XSS vector, with multiple CVEs from 2024-2026 confirming the pattern across diverse applications including Pi-hole, StoneFly, Better Auth, and WordPress plugins.

### Cited Findings
- Pi-hole Admin Interface (CVE-2025-53533): The 404 page reflects the URL path into a `class` attribute, enabling script injection. Affects versions <= 6.2.1. CVSS 6.1 (Medium). -- [ProjectDiscovery: CVE-2025-53533](https://cloud.projectdiscovery.io/library/CVE-2025-53533)
- StoneFly Storage Concentrator (CVE-2026-50040): The 404 handler echoes request path or query content without HTML entity encoding or contextual output escaping in the response body. -- [SentinelOne: CVE-2026-50040](https://www.sentinelone.com/vulnerability-database/cve-2026-50040/)
- Better Auth (CVE-2025-71404): The `/api/auth/error` page reflects the `error` parameter as HTML. Fixed in version 1.1.16. CVSS v4 score 5.1. This is notable because it is an API authentication library error page. -- [MITRE: CVE-2025-71404](https://cveawg.mitre.org/api/cve/CVE-2025-71404); [npm Advisory](https://corgea.com/advisories/vulnerabilities/CVE-2025-71404)
- WordPress Smart Custom 404 plugin (CVE-2024-9204): Reads `$_SERVER['REQUEST_URI']` and reflects the value into response HTML without sanitization or context-aware output escaping. -- [SentinelOne: CVE-2024-9204](https://www.sentinelone.com/vulnerability-database/cve-2024-9204/)
- General guidance identifies the pattern: "The server generates an error page, such as a 404 or 500 error" that includes the requested URL or parameter values. -- [SecurityScientist: XSS Targeting Error Pages](https://www.securityscientist.net/blog/12-questions-and-answers-about-xss-targeting-error-pages/)

### Inferences
- API contexts are particularly affected because: (1) custom error handlers often include the API version string or endpoint path in error messages, (2) API gateways may generate error pages that reflect the original request URI, (3) authentication libraries (like Better Auth) provide error endpoints that render parameters.
- The pattern `https://api.example.com/<script>alert(1)</script>` triggering a 404 page that renders the path is the simplest form. API version string reflection (e.g., "API version v3<script>..." not found") is a variation.
- Prevention requires: generic error pages that never echo request data, explicit Content-Type headers, and output encoding in any custom error template.

### Gaps
- No specific 2024-2025 CVE for API version string reflection XSS was found, though the pattern is described in guides.
- No documented case of API gateway-level (e.g., Kong, Apigee, AWS API Gateway) error page XSS was found from this period.


## API Parameter Encoding Bypass Techniques for XSS

### Takeaway
Double URL encoding, Unicode normalization exploits, and mixed encoding chains remain effective against WAFs and input filters that decode at a different layer than the application. The core issue is mismatched decode/normalize stages between the security filter and the rendering engine.

### Cited Findings
- Double URL encoding: `<` becomes `%3C` after one encode and `%253C` after two. The first decoding by the HTTP layer produces `%3C`, which may pass a filter checking for literal `<`. The application then decodes `%3C` to `<` at render time. -- [OWASP: Double Encoding](https://owasp.org/www-community/Double_Encoding); [Wikipedia: Double Encoding](https://en.wikipedia.org/wiki/Double_encoding)
- Unicode normalization: Full-width characters (e.g., U+FF1C `<` for `<`) are normalized to ASCII equivalents under NFKC normalization. A filter checking raw input misses them; the application normalizes before rendering. -- [Medium: Reflected XSS Bypass Using Double Encoding](https://medium.com/@randixploit.shtml/reflected-xss-bypass-using-double-encoding-846cb9dc1814)
- A March 2026 WAF gap analysis recommends NFC/NFKC normalization and iterative decoding at the same layer as the application, and identifies the mismatch between WAF decoding and application decoding as a systemic issue. -- [Windshock: WAF/IPS/IDS Detection Gap Analysis](https://windshock.github.io/en/post/2026-03-13-waf-ips-ids-detection-gap-analysis/)
- Data sanitized for one context and rendered by a downstream service that decodes JSON Unicode escapes (e.g., `<` for `<`) creates a cross-context encoding issue specific to API architectures. -- [Medium: Encoding Bypasses Complete Guide](https://medium.com/@amrsmooke321/encoding-bypasses-complete-guide-438c1aaa6320)
- PayloadsAllTheThings documents encoding bypass patterns including HTML entity encoding, JavaScript Unicode escapes (`alert`), and overlong UTF-8 sequences. -- [PayloadsAllTheThings: XSS Filter Bypass](https://swisskyrepo.github.io/PayloadsAllTheThings/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass/)

### Inferences
- API-specific encoding chains are particularly dangerous because APIs typically process data through multiple layers (API gateway -> middleware -> application -> template engine), each of which may decode at a different stage. A payload encoded for the final rendering context can pass through intermediate filters undetected.
- JSON Unicode escapes (`<script>`) are a significant API-specific vector because JSON parsers decode these escapes automatically, but WAFs inspecting the raw JSON body may not.
- Overlong UTF-8 sequences (e.g., encoding `<` as the 2-byte sequence `0xC0 0xBC`) are largely blocked by modern UTF-8 validators but may still work against legacy systems or custom parsers.

### Gaps
- No specific detection rate statistics for encoding bypasses against modern WAFs (2024-2025) were found from a primary source. A tool page claims 42% detection for double URL encoding, but the methodology is unverified.
- No documented CVE combining API-specific encoding bypass with XSS was found from 2024-2025.


## Chunked Transfer Encoding XSS Filter Bypass

### Takeaway
Chunked transfer encoding can bypass WAFs by splitting payloads across chunks that are inspected individually, but documented cases in 2025 focus on HTTP request smuggling (CVE-2025-55315, CVE-2025-66373) rather than XSS specifically. The technique is described in WAF bypass guides but lacks primary-source XSS-specific evidence.

### Cited Findings
- F5 documented CVE-2025-55315, where attackers abused chunk extensions in chunked transfer encoding to craft ambiguous request boundaries. Microsoft assigned it CVSS 9.9, the highest for ASP.NET Core to that date. This is request smuggling, not XSS directly, but the smuggled request could carry an XSS payload. -- [F5 Community: SIRT](https://community.f5.com/tag/f5%20sirt)
- Akamai disclosed CVE-2025-66373, a smuggling vector from incorrect processing of requests containing an invalid chunk-encoded body, fixed on November 17, 2025. -- [Akamai: CVE-2025-66373](https://www.akamai.com/blog/security/2025/dec/cve-2025-66373-http-request-smuggling-chunked-body-size)
- The WAFFLED paper (arXiv 2503.10846v3, March 2025) held the attack string constant and changed only the HTTP structure. It minimized 1,207 bypass requests into parser-behaviour classes: 557 for JSON, 351 for multipart, and 299 for XML. The paper found that WAFs that inspect the full body may not reassemble chunks before matching. -- [arXiv: WAFFLED](https://arxiv.org/html/2503.10846v3)
- Packetlabs describes the technique: splitting a keyword like `<script>` across chunks (`<scr` in one chunk, `ipt>` in the next) so a WAF inspecting each chunk sees only harmless fragments, while the backend reassembles the full payload. -- [Packetlabs: WAF Evasion](https://packetlabs.net/posts/an-attackers-perspective-to-waf-evasion/)
- Historical precedent: CVE-2005-2092 (BEA WebLogic) and CVE-2005-2088 (Apache) used requests with both Transfer-Encoding and Content-Length headers to "poison the web cache, bypass web application firewall protection, and conduct XSS attacks." -- [Vulners: CVE-2005-2092](https://vulnerability.cert.dk/vuln/CVE-2005-2092)

### Inferences
- The chunked encoding XSS bypass works when: (1) the WAF inspects chunk by chunk without reassembly, (2) the backend reassembles all chunks before processing, and (3) the reassembled payload is rendered in an HTML context.
- Modern request smuggling CVEs (2025) demonstrate that chunk parsing discrepancies between proxies and backends remain active, and any request that can be smuggled past a WAF can carry an XSS payload to the backend.
- Combining chunked encoding with multipart boundaries (double reassembly requirement) further increases bypass probability according to multiple sources.

### Gaps
- No 2024-2025 CVE was found specifically documenting a chunked-encoding XSS bypass (as distinct from request smuggling).
- The WAFFLED paper could not be fetched in full to extract specific chunked encoding bypass rates and payload examples.


## API-Specific WAF Bypass Techniques for XSS

### Takeaway
The WAFFLED paper (2025) provides the strongest evidence that WAFs systematically fail to inspect JSON bodies, multipart boundaries, and XML payloads as thoroughly as URL parameters, with 1,207 bypass requests documented across these formats. JSON body XSS is particularly effective because many WAFs skip or incompletely inspect JSON.

### Cited Findings
- WAFFLED (arXiv 2503.10846v3): Held the attack payload constant and mutated only the HTTP structure. Minimized 1,207 bypass requests: 557 for JSON, 351 for multipart, 299 for XML. Found that "the second largest portion, which uses application/json, is affected by all the relevant bypass findings." More than 90% of tested applications processed URL-encoded and multipart forms equivalently. -- [arXiv: WAFFLED](https://arxiv.org/html/2503.10846v3)
- Content-Type switching: Changing the media type (e.g., from `application/x-www-form-urlencoded` to `application/json`) so the WAF applies a different parser or skips body inspection entirely, while the backend framework still parses the data correctly. -- [GitHub: Protocol-Level WAF Bypass](https://github.com/dmbs335/the-map/blob/main/03-http-protocol/http-parsing-discrepancy/protocol-level-waf-bypass.md)
- Multipart mutations: WAFFLED lists boundary string variations, per-part header mutations, and Content-Disposition field variations as mutation axes. Some WAFs fail to parse non-standard but RFC-valid boundary strings. -- [arXiv: WAFFLED](https://arxiv.org/html/2503.10846v3)
- Size/padding limits: Some WAFs stop inspecting the body after a size threshold. Padding a JSON body with large junk values before the malicious field can push the payload past the inspection limit. -- [JSmon.sh: WAF Bypass Using Payload Padding](https://blogs.jsmon.sh/how-to-bypass-wafs-using-payload-padding-and-inspection-limits/)
- Request body vs URL parameter treatment: WAFs often apply stricter inspection to URL parameters and less thorough checks on request bodies, especially JSON and multipart. This is a systematic design gap. -- [HackTricks: Proxy/WAF Protections Bypass](https://hacktricks.wiki/en/pentesting-web/proxy-waf-protections-bypass.html)
- LazyHackers documents combined techniques: encoding plus parameter pollution plus Content-Type switching as a multi-layer evasion strategy. -- [LazyHackers: WAF Bypass Techniques](https://lazyhackers.in/article/waf-bypass-encoding-parameter-pollution-evasion)

### Inferences
- JSON body XSS is the most promising API-specific WAF bypass because: (1) WAFs historically focused on URL parameters, (2) JSON parsing is more complex than URL decoding, (3) JSON Unicode escapes add an extra decoding layer, and (4) many WAFs do not reassemble JSON values across nested structures.
- The WAFFLED finding that 90%+ of applications treat URL-encoded and multipart forms equivalently means that switching the Content-Type from one to the other while keeping the same payload can bypass WAFs that only inspect one format.
- A layered bypass strategy (Content-Type switch + encoding + padding) compounds the evasion probability.

### Gaps
- Specific vendor bypass rates (Cloudflare, AWS WAF, Azure WAF, etc.) from the WAFFLED paper could not be extracted due to fetch failure.
- CVE-2025-12642 and CVE-2025-53628, cited in one taxonomy for chunked trailer handling bypasses, could not be verified against official advisories.


## Advanced XSS Chaining Strategies in API Contexts

### Takeaway
XSS in API contexts is most impactful when chained with other vulnerability classes. Documented chains include XSS to privilege escalation to admin takeover (with payouts up to $2,350), XSS to API token theft, and SSRF combined with XSS for cloud credential exfiltration. Bug bounty programs explicitly value chaining.

### Cited Findings
- Stored XSS to privilege escalation to admin takeover: Three stored XSS scenarios were escalated into privilege escalation and admin takeover in a single engagement, triaged as High severity and paying $2,350 total. -- [Medium: Stored XSS to Privilege Escalation to Admin Takeover](https://ahmdhalabi.medium.com/stored-xss-to-privilege-escalation-to-admin-takeover-to-data-breach-6239d0cc3a5c)
- Grafana CVE-2025-6023: Stored XSS in a dashboard leads to API token theft, which enables privilege escalation through the API. This is a clean XSS-to-API-abuse chain. -- [CHS.us: XSS Prevention Guide 2026](https://chs.us/guides/xss/)
- SSRF in webhooks and file processing paid well in 2025 bounties, "often $3,000+, especially when it reaches cloud IAM roles." SSRF chained with XSS (XSS steals internal URLs, SSRF accesses them) and SSRF to cloud metadata to credential exfiltration are documented chain patterns. -- [Medium: Top Bugs That Paid Bounties in 2025](https://medium.com/@ProwlSec/top-bugs-that-actually-paid-bounties-in-2025-871eb0874400)
- A 2026 bug bounty guide lists chain examples: XSS + CSRF bypass leading to session hijack, SSRF to cloud metadata to account compromise, and notes that "chaining lower-severity issues often earns the largest bounties." -- [CHS.us: Bug Bounty Guide](https://chs.us/guides/bug-bounty/)
- A Skill Vault checklist maps: SSRF to cloud metadata to IAM credential exfiltration, stored XSS to session hijack when session cookie lacks HttpOnly, and notes "a low-severity SSRF or self-XSS can become a valid bug when chained." -- [Skill Vault: Bug Bounty](https://skillvault.md/shuvonsec/claude-bug-bounty/bug-bounty)
- PivotX CMS CVE-2025-52367: Stored XSS in subtitle field leads to admin session hijacking and RCE. -- [Medium: CVE-2025-52367](https://medium.com/@hayton1088/cve-2025-52367-stored-xss-to-rce-via-privilege-escalation-in-pivotx-cms-v3-0-0-rc-3-a1b870bcb7b3)
- Langflow CVE-2025-34291: Critical account takeover and RCE where XSS reads a non-HttpOnly token cookie. -- [Obsidian Security: CVE-2025-34291](https://www.obsidiansecurity.com/blog/cve-2025-34291-critical-account-takeover-and-rce-vulnerability-in-the-langflow-ai-agent-workflow-platform)

### Inferences
- The most common API XSS chain patterns in 2024-2026 are:
  1. **XSS -> API Token Theft -> Privilege Escalation**: XSS steals API keys/tokens from the DOM, localStorage, or cookies, then uses them to call privileged API endpoints.
  2. **XSS -> CSRF Bypass -> Account Takeover**: XSS executes same-origin requests that bypass CSRF protections, changing email/password or creating admin accounts.
  3. **XSS -> SSRF**: XSS in an admin panel triggers server-side requests to internal services (e.g., via a "preview URL" feature), enabling SSRF to cloud metadata endpoints.
  4. **Mass Assignment + XSS -> Stored XSS at Scale**: Mass assignment writes XSS into hidden fields rendered across customer instances.
  5. **IDOR + XSS -> Cross-User Account Takeover**: IDOR writes XSS payload into victim's profile; XSS fires when victim views their own data.
  6. **XSS -> Business Logic Exploitation**: XSS performs authorized actions as the victim (transferring funds, approving requests, changing configurations).
- API-specific considerations: APIs that return tokens in response bodies (rather than HttpOnly cookies) are especially vulnerable to XSS-based token theft. Single-page applications that store JWTs in localStorage are the canonical example.

### Gaps
- No single 2024-2025 disclosure demonstrates a full XSS -> SSRF -> cloud credential chain with verified payout and technical details.
- XSS + business logic exploitation chains are described in guides but no specific 2024-2025 writeup with reproduction steps was found.


## GraphQL-Specific XSS Vectors

### Takeaway
GraphQL APIs introduce XSS risks through error message reflection, introspection-disclosed mutations that accept unsanitized input, and structured error responses that include user-controlled values.

### Cited Findings
- GraphQL error messages can reflect user input: "if invalid input is shown back to the user, make sure to apply a very strong output sanitization." The structured error format's `message` field is a primary sink. -- [Escape.tech: GraphQL XSS](https://escape.tech/blog/cross-site-scripting-xss-in-graphql/)
- Introspection, when enabled in production, "discloses the types and operations that are supported by the API, including (sometimes) queries and mutations that are only available to high privilege users." Most popular GraphQL servers now disable introspection in production by default. -- [Checkmarx: GraphQL Verbose Error Messages](https://checkmarx.com/blog/move-over-verbose-error-messages-graphql-apis-are-here/)
- Error-handling flaws allow automated schema mapping: "Threat actors who spot error handling flaws can start sending automated, randomized queries and analyze error responses to find out as much as possible about your GraphQL schema." -- [Wiz: GraphQL API Security Risks](https://www.wiz.io/api/md/academy/api-security/graphql-api-security-risks)
- When introspection is disabled, schema reconstruction through error messages is possible using tools like Clairvoyance. -- [Skills.sh: GraphQL Introspection Attack](https://www.skills.sh/plurigrid/asi/performing-graphql-introspection-attack)
- A security assessment skill file includes a sample stored XSS test: sending a mutation with a `<script>alert('XSS')</script>` payload in a profile bio field and checking the returned value. -- [Anthropic Cybersecurity Skills: GraphQL Security Assessment](https://moltchat-agent-commons.onrender.com/wiki/performing-graphql-security-assessment_skill_(Anthropic-Cybersecurity-Skills).md)

### Inferences
- GraphQL mutations that accept free-text fields (bio, description, comments) and return those fields in query responses are the primary stored XSS vector. The attack is: (1) send a mutation with XSS payload in a text field, (2) the payload is stored, (3) a query returns the field to another user's browser, (4) the browser renders it.
- GraphQL's typed schema can provide a false sense of security: field type validation (String, Int) does not prevent XSS in String fields.
- Batch queries in GraphQL can amplify XSS testing by sending multiple mutation variants in a single request.

### Gaps
- No specific 2024-2025 CVE for GraphQL-specific XSS was found.
- No documentation on GraphQL subscription-based XSS (where a malicious payload is pushed to subscribers via WebSocket) was found.


## Detection and Prevention Summary

### Takeaway
Prevention across all these vectors converges on a consistent set of practices: output encoding in the final rendering context, explicit Content-Type headers with nosniff, framework-level parameter normalization, and defense-in-depth beyond WAFs.

### Cited Findings
- Always set `Content-Type: application/json` and `X-Content-Type-Options: nosniff` on all API responses, including error responses. This prevents browsers from interpreting JSON as HTML. -- [TwitterAPI.io: XSS Prevention in APIs](https://twitterapi.io/articles/xss-prevention-in-apis-json-vs-html-responses)
- Never echo user input in error messages. When error context is needed, use structured error formats with fixed message templates and separate user input into a `details` or `value` field that is never rendered as HTML. -- [GitHub: LibreChat Security Advisory](https://github.com/danny-avila/LibreChat/security/advisories/GHSA-q6c5-gvj5-c264)
- For HPP: normalize duplicate parameters at the application layer the same way the backend framework does, before any security check. -- [OWASP: WSTG-INPV-04](https://en.wikipedia.org/wiki/HTTP_parameter_pollution)
- For mass assignment: use explicit allow-lists for API input fields. Never merge raw request bodies into database models. -- [Medium: Mass Assignment to Stored XSS](https://medium.com/@melodicbook/how-mass-assignment-led-to-stored-xss-and-a-csp-bypass-in-a-major-chatbot-platform-3c6569d7c9e9)
- For encoding bypasses: normalize and decode input at the same layer as the application. Validate output in its final rendering context, not at the edge. Use iterative decoding to handle multi-layer encoding. -- [Windshock: WAF/IPS/IDS Detection Gap Analysis](https://windshock.github.io/en/post/2026-03-13-waf-ips-ids-detection-gap-analysis/)
- For WAF bypass: WAFs should be treated as defense-in-depth, not primary protection. Application-level output encoding is the authoritative defense. -- [arXiv: WAFFLED](https://arxiv.org/html/2503.10846v3)
- CSP as a secondary defense: deploy Content-Security-Policy headers that restrict script sources, which mitigates XSS even when injection occurs. -- [Medium: Mass Assignment to Stored XSS](https://medium.com/@melodicbook/how-mass-assignment-led-to-stored-xss-and-a-csp-bypass-in-a-major-chatbot-platform-3c6569d7c9e9)

### Inferences
- The defense hierarchy for API XSS is: (1) Output encoding at the rendering layer (primary), (2) Input validation and normalization (secondary), (3) CSP headers (tertiary), (4) WAF rules (defense-in-depth only).
- API architectures with multiple processing stages (gateway -> middleware -> service -> template) need encoding at the final output stage, not at an intermediate layer, because intermediate layers may decode or transform data.
- Automated scanning tools should test all response codes (200, 400, 404, 429, 500) for reflected input, not just successful responses.

### Gaps
- Quantitative data on the effectiveness of CSP in preventing API XSS chains was not found.
- No comprehensive benchmark comparing WAF detection rates across all these vector categories was found from a single authoritative source.
