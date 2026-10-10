# Exotic and Unconventional XSS Attack Vectors (2024-2026)

## HTTP/3 and QUIC-Specific Header Injection and XSS Techniques

### Takeaway
No confirmed HTTP/3 or QUIC-specific XSS attack has been publicly documented as of mid-2026. The most relevant HTTP/3 security issues are denial-of-service flaws and protocol-level implementation bugs, not injection attacks that lead to script execution.

### Cited Findings
- XRING (disclosed July 2026) is a QPACK integer underflow in XQUIC (Alibaba's open-source QUIC/HTTP/3 library) that causes a server crash, not code execution. FoxIO reported no exploitation in the wild -- [CSA Research Note](https://labs.cloudsecurityalliance.org/research/csa-research-note-xring-xquic-http3-zeroday-20260711-csa-sty/); [The Hacker News](https://thehackernews.com/2026/07/unpatched-xring-flaw-in-xquic-lets.html)
- CVE-2023-25950 in HAProxy's HTTP/3 implementation fails to block malformed HTTP header field names, but was described as a protocol violation, not XSS -- [Telegram CVEhub](https://t.me/s/CVEhub/18929)
- A 2024 Sorint analysis of QUIC described protocol impersonation attacks (CSRF-like), noting that QUIC's connection-oriented design can introduce new attack vectors, but did not describe header-injection XSS -- [Sorint/Dock12](https://dock12.sorint.com/post/quic-csrf/)
- General HTTP header injection guidance notes that exploitation can lead to response splitting, unauthorized redirection, or XSS, but this is not specific to HTTP/3 -- [Akto Academy](https://www.akto.io/academy/http-header-injection)

### Inferences
- HTTP/3's binary framing (as opposed to HTTP/1.1's text-based headers) makes classic header injection (CRLF injection) structurally harder. The QPACK header compression scheme transmits headers as indexed references or Huffman-encoded literals, not raw text, reducing the surface for injection.
- The primary HTTP/3-specific attack surface is implementation bugs in QPACK decoders and stream multiplexing logic, which tend to produce DoS rather than XSS.
- XSS via HTTP/3 is more likely to occur at the application layer (where decompressed headers are rendered into HTML) than at the protocol layer itself.

### Gaps
- No confirmed HTTP/3 header-injection-to-XSS exploit chain was found in any source. This may be because HTTP/3 adoption in vulnerable contexts is still limited, or because the binary framing genuinely reduces the attack surface.
- No research paper specifically analyzing QUIC/HTTP/3 header injection for XSS was found.


## WebSocket and Server-Sent Events (SSE) XSS Opportunities

### Takeaway
WebSocket and SSE channels create XSS opportunities primarily when servers relay unsanitized user input to other clients, or when client-side code renders server-pushed data without output encoding. SSE has a unique injection vector through CRLF injection in event stream fields.

### Cited Findings
- PortSwigger notes that if attacker-controlled data is relayed over WebSockets to other users, it can lead to XSS. The attack surface is analogous to stored XSS: one user sends a payload, the server relays it, and another user's browser executes it -- [PortSwigger](https://portswigger.net/web-security/websockets)
- OWASP lists XSS among the payloads that can ride WebSocket messages, and recommends treating every message as untrusted input -- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
- SSE fields are delimited by CRLF, so unescaped carriage returns in data values can inject extra fields (e.g., injecting an `event:` or `data:` line). This is analogous to HTTP response splitting -- [DEV Community](https://dev.to/rxkov/server-sent-events-security-how-eventsource-breaks-your-api-authentication-model-3643)
- CVE-2026-46431 in Algernon: a hardcoded wildcard CORS header (`Access-Control-Allow-Origin: *`) allowed any third-party page to read a live SSE stream, enabling cross-origin data theft via EventSource -- [DEV Community](https://dev.to/rxkov/server-sent-events-security-how-eventsource-breaks-your-api-authentication-model-3643)
- SSE GET requests skip CORS preflight (simple requests), so the server's CORS headers are the only gate against cross-origin reads -- [DEV Community](https://dev.to/rxkov/server-sent-events-security-how-eventsource-breaks-your-api-authentication-model-3643)
- CSP blocks XSS execution but does not stop a malicious site from connecting to a WebSocket endpoint, so CSP is not an anti-CSRF defense for WebSockets -- [Solita](https://dev.solita.fi/2018/11/07/securing-websocket-endpoints.html)
- Ably recommends server-side validation with an allowlist and removing unsafe HTML tags from WebSocket messages -- [Ably](https://ably.com/topic/websocket-security)

### Inferences
- WebSocket XSS is most dangerous in chat applications, collaborative editors, and real-time dashboards where user-generated content is broadcast to other clients.
- SSE's CRLF injection vector is underappreciated because SSE is often used for "server-to-client only" data, leading developers to assume the data is trusted.
- The combination of SSE's skip-preflight behavior and misconfigured CORS headers creates a cross-origin data exfiltration risk that is distinct from but can be chained with XSS.
- WebSocket connections established during an XSS attack persist beyond the triggering page context in some implementations, allowing long-lived command-and-control channels.

### Gaps
- No specific 2024-2025 CVE for WebSocket-relayed XSS was found; the attack pattern is well-documented but appears in application-specific bugs rather than protocol-level CVEs.


## File Upload XSS Vectors Beyond Basic SVG

### Takeaway
File format XSS extends well beyond SVG to include PDF (via PDF.js font parsing), Office Open XML documents (DOCX/XLSX/PPTX via embedded XML and relationships), and XML/XSLT transforms. CVE-2024-4367 in PDF.js is the most significant 2024 disclosure in this category.

### Cited Findings
- **PDF.js (CVE-2024-4367):** A missing type check in PDF.js's font handling allows arbitrary JavaScript execution. The flaw is in glyph path compilation for Type 1 fonts: the font matrix, which should contain numbers for transformation, can be replaced with executable code. Affected versions: prior to 4.2.67. Firefox versions before 126 are also affected. Public exploits exist -- [Wordfence](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/pdfjs-viewer-for-elementor/pdfjs-4267-arbitrary-javascript-execution); [Open-Xchange Advisory OXAS-ADV-2024-0004](https://documentation.open-xchange.com/appsuite/security/advisories/html/2024/oxas-adv-2024-0004.html)
- **PDF.js exploitation chain (academic case study):** Researchers documented a chain combining an open redirect in a host platform's sign-out handler, a prefix-match URL validation weakness in a PDF.js viewer wrapper, and CVE-2024-4367's font parsing behavior to achieve XSS on an Open Journal Systems deployment -- [Academic paper](https://ejournal.uin-suka.ac.id/saintek/JISKA/article/download/6353/3098/19996)
- **Office Open XML (DOCX/XLSX/PPTX):** A Black Hat webcast deck covers the XML-based attack surface in OOXML formats: XXE through embedded XML parts, XSS through rendering of embedded HTML content, and XSLT transform features that can execute code. Libraries that parse XML on one part of a site may differ from those parsing uploaded files -- [Black Hat Webcast](https://blackhat.com/docs/webcast/11192015-exploiting-xml-entity-vulnerabilities-in-file-parsing-functionality.pdf)
- **docem tool:** The open-source tool docem can embed XXE and XSS payloads in DOCX, ODT, PPTX, and XLSX files by modifying internal XML parts -- [GitHub/docem](https://github.com/whitel1st/docem)
- **Filename XSS (2024):** Ibexa DXP's file upload widget was vulnerable to XSS payloads in filenames (IBEXA-SA-2024-004). Fixed in Ibexa DXP 3.3.39 and 4.6.9 -- [Ibexa Security Advisory](https://developers.ibexa.co/security-advisories/ibexa-sa-2024-004-dom-based-xss-in-file-upload)
- **Dynamic upload XSS (Feb 2024):** Decidim's dynamic file upload feature was vulnerable to XSS if an attacker modified the file names of uploaded records -- [GitHub Advisory GHSA-9w99-78rj-hmxq](https://github.com/decidim/decidim/security/advisories/GHSA-9w99-78rj-hmxq)
- **OWASP defense:** The OWASP File Upload Cheat Sheet recommends Content Disarm & Reconstruct (CDR) for types like PDF and DOCX, and using random generated filenames -- [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

### Inferences
- PDF.js remains a high-value target because it is embedded in Firefox and widely used in web applications for inline PDF rendering. Any application that renders uploaded PDFs in-browser via PDF.js without upgrading to 4.2.67+ is vulnerable.
- XLSX/DOCX XSS is most dangerous when the application renders document previews in-browser rather than forcing downloads, since the browser interprets the embedded XML/HTML content.
- The docem tool demonstrates that XSS payloads can be hidden in any XML part of an OOXML file (document.xml, styles.xml, sharedStrings.xml for XLSX), not just the main content body.
- Filename-based XSS is still a live vector in 2024, suggesting that many applications fail to sanitize filenames before rendering them in upload confirmation UIs or file listings.

### Gaps
- No 2024 source was found specifically on ICS (calendar) file upload XSS. ICS files are text-based with VCALENDAR/VEVENT structure and could theoretically carry script in DESCRIPTION or SUMMARY fields if rendered as HTML.
- No 2024 XSLT-specific upload advisory was found. XSLT transforms remain a theoretical vector (the `xsl:script` element and `document()` function can execute code), but no recent real-world case was identified.
- No source was found on XSS in Excel Online or Google Sheets rendering of malicious XLSX content.


## Browser API Abuse for XSS (Web Bluetooth, Web USB, Web NFC, Web Serial, File System Access API)

### Takeaway
No direct XSS vulnerability in the Web Bluetooth, Web USB, Web NFC, Web Serial, or File System Access APIs was found. These APIs require user gestures and permission prompts, and their attack surface is more about data exfiltration and device manipulation than script injection. However, they extend the post-exploitation capabilities of an existing XSS.

### Cited Findings
- Safari and Firefox have declined to implement Web USB, Web Bluetooth, Web NFC, and Web Serial, citing privacy and security concerns. Apple's list includes 16 Web APIs rejected for similar reasons -- [UsefulAngle](https://usefulangle.com/web-updates/post/80/firefox-decines-to-implement-web-usb-api)
- Web Bluetooth and WebUSB have only been implemented by Chromium-based browsers (Chrome, Edge). The Serial API is available in Chromium 89+ -- [minhvo blog](https://minhvo.is-a.dev/blogs/web-bluetooth-and-web-usb-hardware-access-from-the-browser)
- Chrome 117 added Web Serial over Bluetooth, expanding the attack surface for paired Bluetooth devices -- [Chrome Developer Blog](https://developer.chrome.com/blog/serial-over-bluetooth)
- A W3C device APIs assessment noted that hardware access APIs should be gated behind secure contexts, user activation, and permission prompts -- [W3C Archives](https://lists.w3.org/Archives/Public/www-archive/2022Sep/att-0017/device-apis.pdf)

### Inferences
- These APIs are relevant as post-exploitation tools: once an attacker achieves XSS, they can abuse Web Bluetooth to scan for and connect to nearby BLE devices, Web USB to interact with connected USB devices, or the File System Access API to read/write local files -- all actions that traditional XSS cannot perform.
- The File System Access API is the highest-risk member of this group for XSS amplification, since it can read and write arbitrary files (with user permission), enabling an XSS payload to exfiltrate sensitive local files or plant malware.
- The user-gesture and permission-prompt requirements limit the practicality of blind exploitation, but social engineering (e.g., "click Allow to continue") can bypass these controls.
- In kiosk or embedded browser scenarios (digital signage, IoT dashboards), these APIs may be pre-authorized, removing the permission barrier.

### Gaps
- No CVE or published exploit was found demonstrating XSS-to-hardware-API abuse in the wild.
- No research paper specifically analyzing the security boundaries of these APIs under XSS conditions was found.


## Prototype Pollution to XSS Chains in Common Libraries

### Takeaway
Prototype pollution to XSS remains an active and expanding attack class, with 2024-2026 disclosures in Vue.js, vue-i18n, DOMPurify, and Handlebars. Academic research (GaLA framework) found 133 zero-day gadgets across one million websites, turning 23 previously "no-impact" pollution bugs into end-to-end XSS exploits.

### Cited Findings
- **Vue.js (CVE-2024-6783):** XSS vulnerability allowing arbitrary JavaScript execution via prototype pollution. Published to NVD on 2024-07-23 -- [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2024-6783/)
- **vue-i18n (GHSA-9r9m-ffp6-9x4v, Nov 2024):** If locale message AST is used in development mode, XSS is possible through third-party injection via prototype pollution -- [GitHub Advisory](https://github.com/intlify/vue-i18n/security/advisories/GHSA-9r9m-ffp6-9x4v)
- **DOMPurify (CVE-2024-48910):** Rated critical (9.3 by Snyk). Improper property checks during HTML sanitization allow prototype pollution to bypass the sanitizer in versions below 2.4.2 -- [Snyk](https://security.snyk.io/vuln/SNYK-JS-DOMPURIFY-8318045)
- **Handlebars (GHSA-2qvq-rjwj-gvw9, March 2026):** A polluted string value whose key matches a partial reference in a template is rendered without HTML escaping. Affected versions: 4.0.0 through 4.7.8, fixed in 4.7.9 -- [GitHub Advisory](https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-2qvq-rjwj-gvw9)
- **GaLA/GHunter research (2025 paper, July 2024 preprint):** Introduced a framework for finding client-side prototype pollution gadgets. Found 133 zero-day gadgets across one million websites and turned 23 previously "no-impact" sites into working end-to-end exploits (XSS, cookie manipulation, URL manipulation). The paper is "GHunter: Universal Prototype Pollution Gadgets in JavaScript Runtimes" -- [arXiv](https://arxiv.org/pdf/2407.10812)
- **Common gadget patterns (from HackTricks summary):** Prototype pollution gadgets commonly exploit: `innerHTML` sinks where a polluted property controls the HTML content; `script.src` assignments where a polluted `__proto__.src` value is used; `document.write` calls that concatenate polluted properties; jQuery's `$.extend` deep merge; and lodash's `_.merge`/`_.set`/`_.setWith` functions -- [HackTricks](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/client-side-prototype-pollution)

### Inferences
- The DOMPurify prototype pollution bypass is particularly dangerous because DOMPurify is the most widely used HTML sanitizer. A pollution-to-DOMPurify-bypass chain effectively neutralizes the primary defense against XSS in many applications.
- The GaLA/GHunter research demonstrates that the gap between "prototype pollution with no obvious impact" and "working XSS" is far smaller than previously assumed. Security teams should treat any client-side prototype pollution as a potential XSS vector.
- Handlebars template engines are especially vulnerable because they trust property lookups on the data object, and prototype pollution makes the entire prototype chain part of the data surface.

### Gaps
- No 2024-2025 prototype pollution to XSS chain was found specifically for lodash, jQuery, or underscore. The HackTricks summary mentions jQuery's `$.extend` and lodash's `_.merge` as known gadget sources, but no new CVE was found for these libraries in the research window.


## DOM Clobbering Techniques That Bypass Security Checks and Enable XSS

### Takeaway
DOM clobbering remains a potent XSS enabler, with the most significant 2024 disclosure being CVE-2024-43788 in webpack's AutoPublicPathRuntimeModule, which was exploited in the wild against Canvas LMS. Multiple DOMPurify bypasses in 2024 used DOM clobbering to defeat the sanitizer's internal state tracking.

### Cited Findings
- **CVE-2024-43788 (webpack):** A DOM clobbering gadget in webpack's `AutoPublicPathRuntimeModule` allows XSS when a page contains attacker-controlled HTML elements (e.g., an `<img>` tag with an unsanitized `name` attribute). Affected versions: 5.0.0-beta.32 through 5.93.0. Fixed in 5.94.0. Real-world exploitation was reported in Canvas LMS. No known workarounds -- [Tenable](https://tenable.com/cve/CVE-2024-43788); [Red Hat](https://access.redhat.com/security/cve/CVE-2024-43788); [GitHub Advisory GHSA-4vvj-4cpr-p986](https://db.fluidattacks.com/adv/npm/webpack/CVE-2024-43788)
- **DOMPurify 3.1.0 bypass (April 2024):** A mistake in how `.parentNode` is accessed in DOMPurify 3.1.1's fix allowed an attacker to clobber that property and reset the depth count, bypassing sanitization -- [mizu.re](https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes) (search result summary; page was not fetchable)
- **DOMPurify 3.1.2 bypass:** Second-order clobbering was used to clobber the `__depth` attribute itself, defeating the fix applied in 3.1.1 -- [mizu.re](https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes) (search result summary)
- **DOMPurify `cid:` protocol trick:** DOMPurify allows the `cid:` protocol, which does not URL-encode double-quotes. This allows an injected payload to survive sanitization and execute when a clobbered variable is read -- [PortSwigger Lab](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering)
- **Wild exploitation (Feb 2024):** A researcher published a writeup titled "Go Go XSS Gadgets: Chaining a DOM Clobbering Exploit in the Wild," documenting a real-world DOM clobbering chain -- [buer.haus](https://buer.haus/2024/02/23/go-go-xss-gadgets-chaining-a-dom-clobbering-exploit-in-the-wild/) (page was not fetchable)
- **Possible 2025 CVEs (unverified):** A GitHub README lists DOMPurify CVE-2025-26791 and CVE-2025-1647 ("evolved DOM clobbering") among late-2025 techniques. These need primary-source confirmation -- [GitHub/Karthikdude/Advanced-XSS](https://github.com/Karthikdude/Advanced-XSS)

### Inferences
- DOM clobbering is most dangerous in contexts where HTML sanitization is applied but the application also uses named element access patterns (`document.getElementById`, `window.someName`, or bare global variable lookups). The webpack CVE demonstrates that build tool runtime code, not just application code, can contain clobberable gadgets.
- The pattern of repeated DOMPurify bypasses via DOM clobbering (3.1.0, 3.1.1, 3.1.2) suggests that the interaction between sanitizers and DOM clobbering is fundamentally difficult to secure.
- The `cid:` protocol allowlisting in DOMPurify is a design choice (needed for email clients) that creates an XSS vector in web contexts.

### Gaps
- The full technical details of the buer.haus DOM clobbering exploit chain were not retrievable due to DNS restrictions.
- CVE-2025-26791 and CVE-2025-1647 were found only in a secondary summary and could not be verified against NVD or vendor advisories.


## GraphQL/REST API Response XSS When Rendered

### Takeaway
GraphQL APIs create XSS opportunities primarily through two paths: (1) unsanitized rendering of query/mutation responses in the frontend, enabling both stored and reflected XSS, and (2) XSS in GraphQL development tools (GraphiQL, GraphQL Playground) via malicious schema introspection responses. The most notable 2024 disclosure is CVE-2024-24556 in the `@urql/next` package.

### Cited Findings
- **General mechanism:** GraphQL responses become an XSS vector when a frontend renders them unsanitized. Both reflected and stored variants are possible, depending on whether the vulnerable operation is a query or a mutation -- [Payatu](https://payatu.com/blog/graphql-exploitation-part-3/)
- **CVE-2024-24556 (@urql/next):** The `@urql/next` package is XSS-vulnerable when a response contains HTML tags and the web application uses streamed responses (non-RSC). The cause is improper escaping of HTML-like characters in the response stream. CVSS v3 6.1 (Medium). Fixed in 1.1.1 -- [Tenable](https://tenable.com/cve/CVE-2024-24556)
- **GraphiQL (CVE-2021-41248):** All GraphiQL versions older than 1.4.7 are vulnerable to XSS via compromised HTTP schema introspection responses or schema prop values with malicious GraphQL type names -- [GCVE Database](https://db.gcve.eu/vuln/CVE-2021-41248)
- **GraphQL Playground (CVE-2020-4038):** Reflected XSS fixed in version 1.6.22. NVD record updated in 2024 -- [GCVE Database](https://db.gcve.eu/vuln/cve-2020-4038)
- **GraphiQL (CVE-2026-42794):** Reflected XSS via backslash bypass in the escaping of the query GET parameter. Rated Low (CVSS 2.3) -- [Intruder CVEmon](https://cvemon.intruder.io/cves/technologies/graphql-vulnerabilities)

### Inferences
- GraphQL's typed schema gives a false sense of security: developers assume that because fields are typed (String, Int, etc.), the data is safe to render. But a String field can contain `<script>` tags, and the type system does not perform output encoding.
- The @urql/next vulnerability is particularly instructive: streaming/SSR frameworks that serialize GraphQL responses into the HTML document create a new injection context that traditional client-side rendering does not have.
- GraphQL development tools remain a persistent XSS target because they render schema metadata (type names, field descriptions) which may come from untrusted sources.

### Gaps
- No specific 2024 research on REST API response XSS was found. The attack pattern is the same (unsanitized rendering of API responses), but no notable CVE or writeup was identified.


## Email Client XSS Vectors (HTML Email Rendering, AMP for Email)

### Takeaway
Email client XSS is constrained by aggressive sanitization in major webmail clients, but AMP for Email introduces a JavaScript-capable rendering context that has been exploited. The most notable finding is a DOM clobbering bypass in Gmail's AMP for Email, and a 2026 XSS in FairEmail's AMP renderer.

### Cited Findings
- **Gmail AMP DOM clobbering:** A researcher found that allowed `id` attributes in AMP for Email enabled DOM clobbering, and Google patched it. AMP for Email relies on an allowlist of tags and attributes to block XSS -- [PortSwigger](https://portswigger.net/daily-swig/google-fixes-xss-bug-in-gmails-dynamic-email-feature); [Sophos](https://news.sophos.com/?p=459857)
- **FairEmail AMP XSS (CVE-2026-54521):** The Android email app FairEmail enabled JavaScript in its WebView but didn't fully sanitize message HTML, so a crafted AMP email could run script when opened with the AMP toggle enabled. Rated 6.1 (Medium). Fixed in version 1.2319. Exposure is limited because AMP email is uncommon -- [OpenCVE](https://app.opencve.io/cve/CVE-2026-54521)
- **AMP-capable clients are few:** Gmail, Yahoo, Mail.ru, and FairEmail are the main AMP-capable email clients. Apple Mail, Outlook, and most others fall back to HTML -- [Mailmodo](https://mailmodo.com/guides/amp-email-support)

### Inferences
- AMP for Email is the most dangerous email rendering context because it is designed to execute JavaScript (unlike standard HTML email which strips scripts). Any flaw in the AMP sanitizer directly leads to XSS.
- The limited number of AMP-capable clients reduces the attack surface, but also means those clients receive less security scrutiny from the broader research community.
- DOM clobbering in email contexts is particularly effective because email HTML is typically sanitized by removing script tags and event handlers, but `id` and `name` attributes on allowed elements often survive the sanitizer.

### Gaps
- No 2024-2025 survey of XSS issues across email clients (Outlook, Thunderbird, Apple Mail webmail) was found.
- No specific research on HTML email rendering XSS in Microsoft Outlook's WebView2-based renderer was found.


## Markdown Parser XSS (marked.js, markdown-it, showdown)

### Takeaway
Markdown parsers remain a persistent XSS vector, with Showdown receiving two 2026 CVEs for stored XSS through unescaped table header IDs and unescaped URL attributes. Showdown explicitly states it does not include XSS filtering. Older marked.js XSS issues exist but no 2024 advisory was found.

### Cited Findings
- **Showdown CVE-2026-59710:** Stored XSS through table header ID injection. The `parseHeaders` function in `src/subParsers/makehtml/tables.js` does not escape table header ID attributes. A fix was pushed to the master branch but not yet published to npm at the time of disclosure -- [OpenCVE](https://app.opencve.io/cve/CVE-2026-59710); [Snyk](https://security.snyk.io/vuln/SNYK-JS-SHOWDOWN-17874450); [Vulert](https://vulert.com/vuln-db/CVE-2026-59710)
- **Showdown CVE-2026-104477:** The `makehtml` link and image subparsers fail to escape double quotes in destination URLs placed into `href` and `src` attributes in versions through 2.1.0. CVSS 5.3 (Medium) -- [OpenCVE](https://app.opencve.io/cve/CVE-2026-104477)
- **Showdown XSS policy:** Showdown's documentation explicitly states it doesn't include an XSS filter, and that filtering should be done after Showdown has processed input -- [CodeClimate/Showdown](https://codeclimate.com/github/showdownjs/showdown/docs/xss.md/source)
- **marked (older):** marked version 0.3.6 and earlier is vulnerable to XSS in the `data:` URI parser (circa 2018). No 2024 XSS advisory for marked was found -- [CVEDetails](https://www.cvedetails.com/vulnerability-list/vendor_id-15209/Marked-Project.html)

### Inferences
- Markdown parsers that generate `id` attributes from heading or table header content are vulnerable to attribute injection if the content is not escaped. This is a systemic issue, not specific to Showdown.
- The "XSS filtering is not our job" stance of Showdown (and historically marked) means that applications must add a post-processing sanitization step, which many developers fail to do.
- The pattern of unescaped double quotes in URL attributes (`href`, `src`) is a classic attribute injection vector that allows breaking out of the attribute context and injecting event handlers.

### Gaps
- No 2024 XSS advisory was found for marked.js or markdown-it.
- No comparative analysis of markdown parser XSS resistance across libraries was found.


## OAuth/OIDC Flow XSS Vectors

### Takeaway
OAuth XSS vectors center on unsanitized rendering of callback parameters (`redirect_uri`, `state`, `code`, `error`) and flawed redirect URI validation that allows attacker-controlled domains. An ACSAC 2023 study found path confusion and parameter pollution issues affecting 10 of 16 identity providers tested.

### Cited Findings
- **CVE-2020-26938 (node-oauth2-server):** The package checked `redirect_uri` against a flawed URI pattern, allowing XSS payloads through the redirect_uri parameter during authorization requests. Last updated November 2024 -- [GCVE Database](https://db.gcve.eu/vuln/CVE-2020-26938)
- **ACSAC 2023 research (Northeastern University):** Studied OAuth 2.0 redirect URI validation across identity providers. Findings include XSS, HTML injection, open redirect, and token leakage. Path confusion was a root cause. OAuth parameter pollution affected 10 of 16 identity providers tested -- [ACSAC Slides](https://acsac.org/2023/files/web/slides/innocenti-97-oauthvalidation.pdf)
- **Callback rendering XSS:** When an OAuth callback endpoint renders untrusted values (redirect_uri, state, code, error) into HTML or JavaScript without escaping, XSS results. Single-page apps that parse URL fragments directly are at higher risk -- [Outpost24](https://outpost24.com/?p=8904); [MojoAuth](https://mojoauth.com/blog/oauth2-implementation-mistakes-security-vulnerabilities)
- **Mitigations:** Standard advice is to use exact, pre-registered redirect URIs compared byte-for-byte, require HTTPS, and make the `state` parameter a random, single-use value -- [Decryption Digest](https://www.decryptiondigest.com/blog/oauth2-security-common-misconfigurations)

### Inferences
- The OAuth `error` and `error_description` parameters are an underappreciated XSS vector: identity providers may include user-controlled data in error responses, and many callback handlers render error messages without escaping.
- SPA OAuth implementations that use `window.location.hash` parsing are especially vulnerable because the fragment is never sent to the server, bypassing server-side WAF rules.
- The `state` parameter is designed for CSRF protection, but if its value is rendered into the page (e.g., for debugging or logging), it becomes an XSS vector.

### Gaps
- No new 2024 CVE specifically about XSS via the OAuth `state` parameter was found.
- No research on OIDC-specific XSS vectors (e.g., through ID token claims rendered in the UI) was found.


## Browser DevTools Protocol Exploitation

### Takeaway
The Chrome DevTools Protocol (CDP) is a powerful post-exploitation tool that enables cookie theft, file system access, and session hijacking when the debugging port is exposed. The most significant recent development is SpecterOps's CDP-Enable-BOF (2026), which activates the debugging server inside an already-running browser process.

### Cited Findings
- **XSS-chained exploit (older, patched):** A proof of concept combined clickjacking with an XSS flaw in the DevTools discovery portal to capture the WebSocket token, then used the debugging protocol to read and write files on a machine running headless Chrome in debug mode. Chromium was patched to prevent embedding the DevTools discovery page in an iframe -- [PortSwigger](https://portswigger.net/daily-swig/severe-chrome-bug-allowed-rce-on-devices-running-remote-headless-interface)
- **Cookie theft via `--remote-debugging-port`:** Attackers have long abused this flag to extract cookies. Chrome 136 now ignores debugging switches when they target the default data directory unless a non-standard `--user-data-dir` is also set -- [CSA Research](https://labs.cloudsecurityalliance.org/research/csa-research-note-chrome-devtools-session-hijacking-20260817/)
- **CDP-Enable-BOF (SpecterOps, August 2026):** A Beacon Object File that activates the debugging server inside an existing, authenticated chrome.exe or msedge.exe process. Requires existing code execution on the endpoint. Defenders should monitor for process injection targeting chrome.exe and msedge.exe using Sysmon Event IDs 8 and 10 -- [CSA Research Note](https://labs.cloudsecurityalliance.org/research/csa-research-note-chrome-devtools-session-hijacking-20260817/); [The Hacker News](https://thehackernews.com/2026/08/chrome-devtools-technique-enables.html)
- **Chrome's threat model:** Compromising the CDP backend via tampered protocol messages is in scope. Social engineering (convincing developers to paste payloads into the Console) is out of scope -- [Chromium Security Policy](https://chromium.googlesource.com/devtools/devtools-frontend/%2B/HEAD/SECURITY.md)

### Inferences
- CDP is the most powerful post-exploitation capability available through a browser. An attacker who gains access to the debugging port can execute arbitrary JavaScript, read all cookies (including HttpOnly), access the file system, and intercept network traffic.
- The SpecterOps technique of injecting into an existing browser process is a significant escalation because it bypasses the traditional defense of "don't start Chrome with `--remote-debugging-port`."
- Applications that run headless Chrome (Puppeteer, Playwright, Selenium) in server-side rendering or PDF generation pipelines are at risk if the debugging port is bound to a non-localhost interface.

### Gaps
- No new XSS-in-DevTools-frontend disclosure from 2024-2026 was found beyond the older iframe-embedding issue.


## Payment Processing Integration XSS Risks

### Takeaway
No XSS vulnerability in Stripe Elements or the PayPal JavaScript SDK was found. These integrations use iframe isolation (Stripe Elements runs in a cross-origin iframe) which limits XSS exposure. The main risks are in application code surrounding the payment flow, not the SDKs themselves.

### Cited Findings
- **Stripe Elements architecture:** Stripe describes Elements as prebuilt UI components that tokenize sensitive payment details within an Element without them touching the merchant's server. The Elements run in a cross-origin iframe hosted on `js.stripe.com` -- [Stripe Docs](https://docs.stripe.com/docs/payments/elements)
- **PayPal PHP SDK (CVE-2017-6099):** The PayPal PHP Merchant SDK version 3.9.1 is vulnerable to XSS. This is a server-side PHP package, not the browser-side PayPal JavaScript SDK -- [Vulert](https://vulert.com/vuln-db/CVE-2017-6099)

### Inferences
- The iframe isolation used by Stripe Elements is an effective defense against XSS: even if the merchant's page is compromised, the payment form runs in a separate origin and cannot be read or manipulated by scripts on the parent page.
- The primary XSS risk in payment integrations is in the surrounding application code: order confirmation pages that render transaction details, receipt emails, and admin dashboards that display customer-submitted data.
- Custom payment form implementations (not using hosted fields or elements) have the highest risk because they handle card data in the merchant's DOM.

### Gaps
- No security research specifically analyzing the XSS attack surface of payment SDK integrations was found.


## WebRTC SDP Injection and ICE Candidate Manipulation

### Takeaway
No direct SDP-injection-to-XSS exploit was found. The WebRTC security discussion focuses on CSP bypass (WebRTC traffic is not covered by `connect-src`), data exfiltration via ICE candidates, and protocol-level injection in signaling channels. XSS risk exists primarily in the signaling layer, not in SDP/ICE themselves.

### Cited Findings
- **CSP gap:** The `connect-src` CSP directive covers WebSockets but does not mention DataChannels or WebRTC, creating a policy gap that allows WebRTC connections to bypass CSP restrictions -- [W3C public-webrtc mailing list](https://lists.w3.org/Archives/Public/public-webrtc/2018Jan/0106.html)
- **ICE-lite attack:** A mailing-list poster described a scenario where the browser does not verify that the remote party has ever seen its SDP. Under this condition, injected JavaScript could carry a static offer pointing to an attacker's server -- [W3C public-webrtc](https://lists.w3.org/Archives/Public/public-webrtc/2018Jan/0098.html)
- **Exfiltration via ICE:** Controlling the IP or port used for STUN/TURN also conveys information. ICE was described as worth protecting if exfiltration is in the threat model -- [W3C public-webrtc](https://lists.w3.org/Archives/Public/public-webrtc/2018Jan/0135.html)
- **Proposed CSP fix:** A proposal would treat STUN, TURN, and remote ICE candidates as allowlist entries when CSP is active, with WebRTC disabled by default -- [W3C public-webrtc](https://lists.w3.org/Archives/Public/public-webrtc/2018Jan/0073.html)

### Inferences
- The primary XSS vector in WebRTC applications is the signaling channel (typically WebSocket-based), not SDP or ICE themselves. If the signaling server relays unsanitized messages between peers, any field (display name, chat message, room name) can carry XSS payloads.
- SDP munging (modifying SDP before passing it to `setLocalDescription`/`setRemoteDescription`) is a common practice in WebRTC applications, and if the application renders SDP fields (codec names, candidate addresses) in the UI, those fields become injection points.
- WebRTC's CSP gap means that an XSS payload can establish covert data exfiltration channels via DataChannels that CSP cannot block.

### Gaps
- No SDP-injection XSS CVE or published exploit was found.
- No research paper on WebRTC signaling channel XSS was found.
- The CSP gap discussion is from 2018; its current status in the CSP specification was not confirmed.


## Custom URL Schemes and Deep Links XSS in Mobile Browsers

### Takeaway
Custom URL schemes create XSS opportunities when mobile apps load deep-linked URLs in WebViews without sanitization. The attack requires the app to use a WebView with JavaScript enabled and to pass URL parameters directly into the rendered content. Universal Links and App Links are more secure alternatives.

### Cited Findings
- **WebView XSS via deep links:** A penetration-testing writeup lists XSS through WebView implementation among the attacks possible via deep links, alongside session hijacking, open redirect, and LFI. An attacker creates a link with a registered URI scheme that the OS passes to the app, which renders it in a WebView -- [Hacking Articles](https://www.hackingarticles.in/?p=26212); [Hacking Articles (Android)](https://hackingarticles.in/android-pentest-deep-link-exploitation/)
- **JavaScript bridge exposure:** Apps that expose JavaScript bridges to WebView content may make those bridges reachable from deep-link-loaded URLs, escalating XSS to native code execution -- [OpenSkillIndex](https://openskillindex.com/skills/plurigrid-asi-exploiting-deeplink-vulnerabilities)
- **Scheme hijacking:** A malicious app can register the same custom scheme to intercept links intended for the legitimate app. This is a separate issue from XSS but can be chained with it -- [LevelUp/GitConnected](https://levelup.gitconnected.com/how-custom-url-schemes-could-be-putting-your-app-at-risk-0548e03405ad)
- **Deprecation of custom schemes:** Apple deprecated custom URL schemes for iOS 9+ in favor of Universal Links, and a 2026 guide says URI schemes lack the security, reliability, and fallback capabilities of Universal Links and App Links -- [LinkRunner](https://linkrunner.io/glossary/what-is-a-deeplink-uri-scheme)

### Inferences
- The most dangerous configuration is an app that (1) registers a custom URL scheme, (2) opens the URL in a WebView with JavaScript enabled, and (3) passes URL parameters into the WebView content (via `loadUrl("javascript:...")` or by rendering them into the HTML).
- JavaScript bridge abuse via deep links is more severe than traditional XSS because it can lead to local file access, contact exfiltration, or arbitrary native code execution, depending on what the bridge exposes.
- The shift toward Universal Links and App Links mitigates scheme hijacking but does not eliminate WebView XSS if the app still renders link parameters unsafely.

### Gaps
- No specific 2024 CVE or bug bounty writeup for deep-link XSS in a mobile browser or popular app was found.
- No research comparing the XSS attack surface of custom schemes vs. Universal Links/App Links was found.
