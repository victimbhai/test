# API Response Rendering XSS Attack Vectors (2024-2026)

## REST API Response Rendering XSS: Recent CVEs and JSON-to-HTML Sniffing

### Takeaway
REST API endpoints remain vulnerable to XSS when they reflect user input without encoding, serve responses with incorrect Content-Type headers (especially text/html instead of application/json), or omit X-Content-Type-Options: nosniff, allowing browsers to sniff JSON responses as HTML.

### Cited Findings
- CVE-2025-53528: Cadwyn (FastAPI framework) reflected the `version` parameter of the `/docs` endpoint without sanitization in versions before 5.4.3, enabling one-click XSS against any application built on Cadwyn. — [INCIBE Advisory](https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2025-53528); [Akaoma Analysis](https://cve.akaoma.com/CVE-2025-53528)
- CVE-2025-32960: Jmix REST API add-on allowed uploads to the `/files` endpoint that could be served back with `text/html` Content-Type for `.html` files, enabling stored XSS. Fixed in version 7.2.7. Mitigated by authentication requirements. — [GitLab Advisory Database](https://advisories.gitlab.com/pkg/maven/com.haulmont.addon.restapi/restapi-rest-api/CVE-2025-32960/)
- CVE-2025-15562: NesterSoft WorkTime API endpoint `/report/internet/urls` reflects received data into the HTML response without encoding or filtering. Vendor unresponsive as of February 2026. — [Lutra Security Fieldguide](https://fieldguide.lutrasecurity.com/CVE-2025-15562)
- CVE-2025-11925: BLU-IC2/IC4 devices used `text/html` Content-Type instead of `application/json` in API replies, potentially allowing injection of HTML/JavaScript into responses. Affects versions through 1.19.5. — [Kodem Security](https://www.kodemsecurity.com/cve-database/cve-2025-11925)
- JSON responses are not inherently safe from XSS: if client-side code uses JSON contents to update the DOM, client-side XSS results. The `X-Content-Type-Options: nosniff` header prevents browsers from sniffing `application/json` as HTML, but does not protect against client-side DOM injection. — [Elixir Forum Discussion](https://elixirforum.com/t/can-json-have-a-xss-bug/13201)
- Chrome's Opaque Response Blocking (ORB) blocks cross-origin no-cors reads of responses that look like HTML/JSON/XML, but ORB does nothing for same-origin loads, so the `nosniff` header remains essential for same-origin API endpoints. — [CentralCSP Documentation](https://next.centralcsp.com/en/docs/web-security/security-headers/x-content-type-options.md)
- Google Research paper "Content Sniffing with Comma Chameleon" describes how MIME type sniffing has led to a class of web security problems related to polyglots where content can be valid as multiple types simultaneously. — [Google Research](https://research.google/pubs/pub46273)

### Inferences
- The most common REST API XSS pattern in 2024-2026 is serving user-uploaded content or API responses with incorrect or missing Content-Type headers, rather than direct JSON body sniffing.
- Modern browsers have reduced (but not eliminated) Content-Type sniffing attacks through ORB and stricter MIME checking, making the `nosniff` header the primary server-side defense.
- Client-side DOM XSS from API responses (where JSON values are inserted into HTML without encoding) is a growing vector that Content-Type headers alone cannot prevent.

### Gaps
- No 2024-2026 CVE was found demonstrating pure browser MIME sniffing of a correctly-typed `application/json` response into HTML execution. The technique appears to be mostly mitigated in modern browsers.
- No specific academic papers from 2024-2026 on REST API response rendering XSS were found in this search.


## GraphQL-Specific XSS Vectors

### Takeaway
GraphQL XSS vectors span from introspection response rendering in GraphiQL (CVE-2021-41248, still affecting deployments in 2026) to reflected XSS through query parameters in GraphQL IDEs (CVE-2026-42794), and missing Subresource Integrity on CDN-loaded scripts in Spring for GraphQL (CVE-2026-59286). No CVEs were found specifically for persisted query abuse or subscription message XSS.

### Cited Findings
- CVE-2024-24556 (@urql/next): All versions before 1.1.1 failed to escape HTML-like characters in the response stream. Specifically, @urql/next failed to escape HTML characters in JSON payloads injected into React Server Component (RSC) hydration bodies. Exploitation requires the response to contain HTML tags and the app to use streamed (non-RSC) responses. GHSA-qhjf-hm5j-335w. CVSS scores conflict: NVD says 6.1 (Medium), Wiz and Fluidattacks say High, HOL Guard lists 7.2. Fix commit: 4b7011b. — [Tenable CVE Entry](https://tenable.com/cve/CVE-2024-24556); [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-24556); [Wiz](https://www.wiz.io/vulnerability-database/cve/cve-2024-24556)
- CVE-2026-42794 (absinthe_plug/GraphiQL): Reflected XSS in GraphiQL's escaping function. The escaping fails to handle backslashes, allowing an attacker to break out of a string context via the query GET parameter. Affects versions 1.2.0+ and 20241017cb+. Severity conflicts: one source gives CVSS 2.3, notcve.org lists 6.1. — [Stack.watch](https://stack.watch/vuln/CVE-2026-42794/); [notcve.org](https://notcve.org/vendors/graphql/)
- CVE-2026-59286 (Spring for GraphQL): Missing Subresource Integrity (SRI) on CDN-loaded scripts in GraphiQL integration creates XSS risk through CDN compromise or MITM. Affects versions 1.0.0 through 2.0.4. — [Stack.watch](https://stack.watch/vuln/CVE-2026-59286/)
- CVE-2026-59288 (Spring for GraphQL): Information leak via malicious URL in GraphiQL. Affects versions 1.0.0 through 2.0.4. — [Stack.watch](https://stack.watch/vuln/CVE-2026-59288/)
- CVE-2021-41248 (GraphiQL): All versions before 1.4.7 were vulnerable to XSS through malicious schema introspection responses or crafted type names during operation autocomplete. Still affecting deployments in 2026: IBM's April 2026 bulletin says it affects watsonx.data 2.3. — [IBM Support](https://www.ibm.com/support/pages/node/7268847); [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2021-41248)
- WS-2016-0142 (express-graphql): HTML not properly escaped in queries or variables. Versions 0.4.0 to 0.4.10 affected. Fixed in 0.4.11. — [Mend.io](https://aws-stg.mend.io/vulnerability-database/WS-2016-0142/)
- GraphQL injection occurs when user data goes into the document string itself rather than the variables map, allowing the parser to interpret attacker-controlled syntax. — [Payatu Blog](https://payatu.com/blog/graphql-exploitation-part-3/)

### Inferences
- The most persistent GraphQL XSS vector is through GraphiQL and similar IDE tools that render introspection responses or query parameters without proper escaping. The 2021 CVE continues to affect enterprise deployments (IBM watsonx) in 2026.
- The @urql/next CVE (2024-24556) represents a newer class of GraphQL XSS where the vulnerability is in the client-side framework's streaming/hydration mechanism rather than the GraphQL layer itself.
- CDN integrity (SRI) for GraphiQL's JavaScript dependencies is a supply-chain XSS risk that Spring for GraphQL only addressed in 2026.

### Gaps
- No CVEs or public research were found for GraphQL subscription message XSS (where malicious payloads in subscription data execute in subscriber browsers).
- No CVEs were found for persisted query abuse leading to XSS. The theoretical vector (attacker registers a persisted query containing XSS, which is later rendered) has no documented real-world exploitation.
- No specific introspection response rendering XSS was found beyond the 2021 GraphiQL CVE.


## gRPC-Web and tRPC XSS Vectors

### Takeaway
No XSS vulnerabilities were found in gRPC-Web or tRPC for 2024-2026. The tRPC ecosystem has seen a WebSocket DoS (CVE-2025-43855) and a prototype pollution (CVE-2025-68130), but neither is XSS. gRPC-Web returned no security advisories at all in this search.

### Cited Findings
- CVE-2025-43855 (tRPC WebSocket DoS): An unhandled error when validating bad connection parameters lets an unauthenticated user crash a tRPC 11 WebSocket server. Affects versions 11.0.0 to 11.1.0, fixed in 11.1.1. Published April 24, 2025. This is denial of service, not XSS. — [INCIBE](https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2025-43855); [Mend.io](https://mend.io/vulnerability-database/CVE-2025-43855)
- CVE-2025-68130 (tRPC prototype pollution): Prototype pollution in `formDataToObject` of `@trpc/server`, used by Next.js App Router adapter. Only present when using `experimental_caller` / `experimental_nextAppDirCaller`. Fixed in 10.45.3 and 11.8.0. Published December 16, 2025. This is prototype pollution, not XSS, though prototype pollution can sometimes be chained into XSS. — [Sonatype Guide](https://guide.sonatype.com/vulnerability/CVE-2025-68130)

### Inferences
- gRPC-Web's binary protocol and strict Content-Type handling (application/grpc-web+proto or application/grpc-web-text) likely make traditional XSS vectors less applicable compared to text-based APIs.
- tRPC's type-safe RPC mechanism and TypeScript-first design may reduce the attack surface for response rendering XSS, since responses are typically consumed programmatically rather than rendered as HTML.
- The tRPC prototype pollution (CVE-2025-68130) could theoretically be chained with client-side rendering to achieve XSS, but no such chain has been publicly documented.

### Gaps
- No gRPC-Web XSS CVEs or public research were found. It is unclear whether this is because the attack surface is genuinely small or because researchers have not focused on it.
- No tRPC streaming response XSS research was found. The theoretical vector (malicious data in tRPC streaming responses rendered unsafely) has no documented exploitation.
- No research was found on gRPC-Web JSON mode (where gRPC responses are transcoded to JSON) as an XSS vector.


## JSONP Callback Injection Techniques (2025-2026)

### Takeaway
JSONP callback injection remains a live vulnerability class in 2025-2026, with multiple CVEs demonstrating the same root cause: the server echoes the `callback` or `jsonp` parameter into a `application/javascript` response without validating it as a legal JavaScript identifier.

### Cited Findings
- CVE-2025-15144 (XunRuiCMS): Reflected XSS in JSONP error handlers via `dr_show_error` and `dr_exit_msg` functions. The endpoints echo the callback request parameter directly into the HTTP response. Exploit is public. Vendor unresponsive. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-15144/)
- GHSA-6mp4-q625-mxjp (YOURLS): The `callback` and `jsonp` parameters are concatenated into output unsanitized. With public API mode enabled, any unauthenticated attacker can exploit it. Even in private mode, the payload is injected into the 403 response body (browser execution blocked by auth requirement). — [Wiz](https://www.wiz.io/vulnerability-database/cve/ghsa-6mp4-q625-mxjp)
- CVE-2026-42548 (Flight PHP): The `?jsonp=` value is not validated as a legal JavaScript identifier. Fixed in 3.18.1. CVSS 4.0 score: 8.6. — [GitLab Advisory Database](https://advisories.gitlab.com/composer/flightphp/core/CVE-2026-42548/); [Lutra Security Fieldguide](https://fieldguide.lutrasecurity.com/CVE-2026-42548/)
- CVE-2026-49294 (Valhalla routing engine): Affects 3.6.3 and earlier, unfixed at publication. Injected script runs in the serving origin, enabling session token theft. CVSS 6.1 (Medium) per Nixpkgs tracker. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-49294/); [Nixpkgs Tracker](https://tracker.security.nixos.org/suggestions/by-id/8840/)
- CVE-2024-29882 (SRS video server): An older example of the same JSONP callback injection pattern. Fixed in versions 5.0.210 and 6.0.121. — [GCVE Database](https://db.gcve.eu/vuln/CVE-2024-29882)
- CORS misconfiguration chain: A well-documented attack pattern where an API trusts wildcard subdomains (e.g., `*.target.com`), allowing XSS on any subdomain to make credentialed requests to the API. SameSite cookies are sent because subdomains are same-site. — [Yaklang CORS Skill](https://www.typingmind.com/skills/yaklang-cors-cross-origin-misconfiguration)
- CVE-2024-8024 (QAnything): CORS misconfiguration in netease-youdao/qanything 1.4.1 allows an attacker to bypass Same-Origin Policy. CVSS 7.5 (High). Published March 2025. Not directly combined with JSONP but demonstrates the CORS misconfiguration class. — [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2024-8024)

### Inferences
- JSONP endpoints continue to be shipped in production software in 2025-2026, despite CORS being widely available as a replacement. The vulnerability is almost always the same: missing identifier validation on the callback parameter.
- The standard mitigations are: (1) validate callback against a strict JavaScript identifier pattern (`/^[$_a-zA-Z][$_a-zA-Z0-9]*$/`), (2) set `X-Content-Type-Options: nosniff`, (3) deprecate JSONP in favor of CORS, and (4) set `Content-Type: application/javascript` (not text/html).
- CORS misconfigurations can amplify JSONP and other XSS issues by allowing cross-origin credential leakage.

### Gaps
- No specific research on "callback parameter pollution" (multiple callback parameters in one request) was found in this search.
- No 2024-2025 published chain combining JSONP hijacking with CORS misconfiguration into a complete attack was found, though the theoretical chain is well-documented in testing playbooks.


## Content-Type Confusion Attacks Enabling XSS

### Takeaway
Content-Type confusion remains a viable XSS vector in 2024-2026, primarily through: (1) servers serving user-uploaded content with incorrect MIME types, (2) missing XML/SVG extension blocklists in file upload handlers, and (3) APIs responding with text/html when application/json is expected.

### Cited Findings
- CVE-2026-32728 (Parse Server): Stored XSS filter bypass via Content-Type MIME parameter and missing XML extension blocklist entries. An attacker could upload content that bypasses MIME checks and is served as HTML/XML. — [Vulners](https://vulners.com/cvelist/CVELIST:CVE-2026-32728)
- CVE-2026-61448 (Parse Server): Stored XSS from malformed Content-Type bypassing MIME checks. Fixed in 9.10.0-alpha.2 and 8.6.84. — [Vulners](https://vulners.com/cvelist/CVELIST:CVE-2026-61448)
- CVE-2024-10461 (Firefox/Thunderbird): In multipart/x-mixed-replace responses, `Content-Disposition: attachment` was not respected and did not force a download, allowing XSS. Affects Firefox < 132, Firefox ESR < 128.4, Thunderbird < 128.4 and < 132. — [GCVE Database](https://db.gcve.eu/vuln/cve-2024-10461)
- CVE-2026-56670 (ComfyUI): The `/view` endpoint stored and served uploaded SVG/XML content inline due to missing handling for `image/svg+xml` and related XML content types, enabling stored XSS. Fixed in 0.28.0. — [Feedly CVE](https://feedly.com/cve/CVE-2026-56670)
- CVE-2025-11925 (BLU-IC2/IC4): Incorrect Content-Type header (`text/html` instead of `application/json`) in API replies allows injection of HTML/JavaScript into responses. Affects versions through 1.19.5. — [Kodem Security](https://www.kodemsecurity.com/cve-database/cve-2025-11925)

### Inferences
- SVG/XML uploaded content is the most common Content-Type confusion vector in 2024-2026, because SVG files can contain inline JavaScript (`<script>` tags or event handlers) and are often served with permissive MIME types.
- The Parse Server CVEs (two in 2026) demonstrate that even applications with XSS filters can be bypassed through Content-Type manipulation, suggesting that allowlist-based approaches (rather than blocklists) are more robust.
- The Firefox multipart/x-mixed-replace CVE shows that browser-side Content-Type handling bugs still exist, though they are increasingly rare and quickly patched.

### Gaps
- No specific research on JSON-to-HTML polyglot files (files valid as both JSON and HTML) being used for XSS in 2024-2026 was found, though the Google Research "Comma Chameleon" paper describes the theoretical basis.
- No CVEs for multipart API response rendering XSS (where multipart boundaries are manipulated to inject HTML) were found in this search.


## Server-Sent Events (SSE) Injection Techniques

### Takeaway
SSE injection is an emerging vulnerability class with three CVEs in 2026 alone (NestJS, cowlib, HTTP.jl). The root cause is consistent: user-controlled data reaches SSE output fields (type, id, data) without CR/LF sanitization, allowing event splitting, event type spoofing, and XSS when clients render event data as HTML.

### Cited Findings
- CVE-2026-35515 (@nestjs/core): `SseStream._transform()` writes `message.type` and `message.id` into SSE output without removing CR/LF characters. All versions through 11.1.17 affected. Fixed in 11.1.18. CVSS 3.1: 6.1 (Medium) per GitHub advisory; Red Hat gives 6.5 and classifies as CWE-93. XSS occurs only if the client renders SSE data as HTML without sanitization. Exploitation requires developer code that passes user-controlled data into SSE type or id fields. GHSA-36xv-jgw5-4q75. — [Wiz](https://www.wiz.io/vulnerability-database/cve/cve-2026-35515); [OSV](https://osv.dev/vulnerability/GHSA-36xv-jgw5-4q75); [NVD](https://nvd.nist.gov/vuln/detail/cve-2026-35515)
- CVE-2026-43968 (cowlib, Erlang): `cow_sse:event/1` filters `\n` in `id` and `event` fields but not bare `\r`. The SSE spec treats `\r` as a line terminator, so an attacker can forge whole events. Affects versions 2.6.0 through 2.16.1. Workaround: reject or strip values containing `\r` or `\n` before passing to the function. Enables event splitting, client-side logic manipulation, and stored-XSS-equivalent behavior when event data is inserted into the DOM. — [Erlang Ecosystem Foundation CNA](https://cna.erlef.org/cves/CVE-2026-43968.html); [Feedly](https://feedly.com/cve/CVE-2026-43968)
- JLSEC-2026-619 (HTTP.jl, Julia): The serializer wrote `event`, `id`, and `retry` verbatim, and split `data` only on `\n`. Fixed in v2.4.0 by rejecting CR/LF in control fields and normalizing all line-break forms in `data`. — [OSV](https://osv.dev/vulnerability/JLSEC-2026-619)

### Inferences
- SSE injection is a cross-language problem: the three 2026 CVEs affect JavaScript (NestJS), Erlang (cowlib), and Julia (HTTP.jl), suggesting that SSE serialization libraries across all languages may be affected.
- The attack pattern is analogous to HTTP header injection (CRLF injection) but in the SSE protocol context. The SSE spec's treatment of `\r`, `\n`, and `\r\n` as equivalent line terminators creates a subtle trap where filtering only `\n` is insufficient.
- The XSS impact depends entirely on the client side: if the EventSource consumer inserts `event.data` into the DOM via `innerHTML` or similar, the injected data executes as HTML. Applications using `textContent` or framework-level escaping are not affected.
- The `event.type` field is particularly dangerous because it controls which event handler is dispatched: a spoofed event type can redirect data to a handler that does not expect or sanitize untrusted input.

### Gaps
- No research was found on EventSource API abuse beyond CRLF injection (e.g., reconnection manipulation via injected `retry` fields, or comment-based cache poisoning).
- No research was found on SSE injection in specific frameworks beyond NestJS (e.g., Express.js SSE middleware, Django SSE, Spring WebFlux SSE).


## WebSocket Message XSS Vectors

### Takeaway
WebSocket message XSS is a well-established stored XSS variant primarily affecting real-time chat and collaboration applications, where messages relayed via WebSocket are rendered as HTML without sanitization. CVE-2024-48059 (ChuanhuChatGPT) is the most documented recent example. The fundamental issue is that WebSocket frames receive less security scrutiny than HTTP request/response cycles.

### Cited Findings
- CVE-2024-48059 (ChuanhuChatGPT): Versions up to 20240802 allowed a WebSocket message to carry script that executed in another user's browser when they opened the session. CVSS 3.1: 6.1 (Medium). The payload persists as a stored XSS. — [Tenable](https://tenable.com/cve/CVE-2024-48059); [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2024-48059); [Researcher Writeup](https://rumbling-slice-eb0.notion.site/Stored-XSS-via-Chat-message-in-gaizhenbiao-chuanhuchatgpt-104e3cda9e8c80b4b611dfc491c488d8)
- A PHP chat application (code-projects.org v1.0) has an unpatched stored XSS in real-time messaging with no output encoding when stored messages are rendered. The payload persists in the database and executes in every user's browser, including administrators'. — [CERT.dk GHSA](https://vulnerability.cert.dk/vuln/ghsa-96xr-jq73-gwf6)
- Client-side filtering of chat input is insufficient: relying only on client-side security is never safe because users can easily bypass it and modify the outgoing data using a proxy tool. Server-side validation and output encoding are required. — [Medium writeup](https://medium.com/p/9b979311eb4a)

### Inferences
- WebSocket XSS is essentially stored XSS with a different transport mechanism. The vulnerability is in the rendering layer, not the WebSocket protocol itself.
- AI chat applications (like ChuanhuChatGPT) are a growing attack surface because they relay user messages that may contain HTML/JavaScript and render them in web interfaces, often with markdown rendering that can be abused.
- The lack of standardized security middleware for WebSocket messages (compared to HTTP request/response middleware that can add CSP headers, sanitize input, etc.) means developers must implement sanitization manually at the application layer.
- Binary WebSocket frame injection is theoretically possible but no public CVEs or research were found demonstrating this as an XSS vector.

### Gaps
- No 2025-2026 WebSocket XSS CVEs were found in this search beyond the 2024 ChuanhuChatGPT example.
- No research was found on binary WebSocket frame injection as an XSS vector.
- No research was found on WebSocket message XSS in major collaboration platforms (Slack, Teams, Discord) or real-time frameworks (Socket.io, Phoenix LiveView, SignalR).
- No research was found on WebSocket subprotocol confusion attacks leading to XSS.
