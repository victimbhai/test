# DOMPurify Bypasses, Sanitizer API, and mXSS Techniques (2024-2026)

## DOMPurify CVEs Disclosed 2024-2026: Root Causes and Exploit Payloads

### Takeaway
DOMPurify has had a sustained stream of security-relevant bypasses from 2024 through 2026, with root causes spanning nesting-based mXSS, prototype pollution, namespace confusion, template/shadow DOM traversal gaps, and configuration precedence errors. Upgrading to at least 3.4.15 is necessary to address all known issues.

### Cited Findings

**CVE-2024-45801 (September 2024):** Nesting-based mXSS bypass. Special nesting bypassed DOMPurify's depth check, allowing deeply nested structures to produce a different DOM tree after serialize-reparse. Fixed in DOMPurify 2.5.4 and 3.1.3. — [SentinelOne CVE Database](https://www.sentinelone.com/vulnerability-database/cve-2024-45801/); [DOMPurify Wiki: Attack Classes & Bypass History](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**CVE-2024-47875 (GHSA-gx9m-whjm-85jf, October 2024):** Nesting-based mXSS via form/math/mtext/table/mglyph/style chain. Reported by @icesfont. Payload shape: `<form><math><mtext><table><mglyph><style><img src=x onerror=alert(1)>`. Root cause: flattening, foreign-content repair, and serialization instability combined to produce executable markup after reparse. DOMPurify added a depth cap in 3.1.1 and later removed it in 3.1.5. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**CVE-2025-15599 (published 2026):** Textarea rawtext bypass in SAFE_FOR_XML mode. The SAFE_FOR_XML regex omitted some rawtext element names (e.g., textarea), allowing attribute values to escape their context. Payload shape: rawtext element breakout via closing tag injection. Fixed in 3.2.7 (3.x branch); the 2.x branch was never patched. — [VulnCheck Advisory](https://www.vulncheck.com/advisories/dompurify-xss-via-textarea-rawtext-bypass-in-safe-for-xml); [GitHub Advisory GHSA-v8jm-5vwx-cfxm](https://github.com/advisories/GHSA-v8jm-5vwx-cfxm)

**CVE-2025-26791 (2025):** Template reassembly bypass. Removing elements and merging text nodes rebuilt a template expression. Payload: `<div id=app>{<foo></foo>{constructor.constructor("alert(1)")()}<foo></foo>}</div>`. Root cause: incorrect `${ ... }` handling during node removal. Fixed in 3.2.4. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**CVE-2026-0540 (2026):** SAFE_FOR_XML attribute regex omitted some rawtext element names, enabling mXSS via rawtext/RCDATA breakouts. Payloads include noscript, textarea, and style attribute-selector variants: `<noscript><p title="</noscript><img src=x onerror=alert(1)>">`. Fixed in 3.x line. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**CVE-2026-41238 (GHSA-v9jr-rg53-9pgp, 2026):** Prototype pollution to XSS bypass via CUSTOM_ELEMENT_HANDLING fallback. After `Object.prototype.tagNameCheck = /.*/` and `Object.prototype.attributeNameCheck = /.*/`, the payload `<x-x autofocus tabindex=0 onfocus=alert(1)>` survives sanitization. Root cause: an inherited `|| {}` fallback in the CUSTOM_ELEMENT_HANDLING code path. Affected 3.0.1 through 3.3.3. Fixed in 3.4.0. Versions 3.0.0 and 2.x were unaffected. — [GitHub Advisory GHSA-v9jr-rg53-9pgp](https://github.com/advisories/GHSA-v9jr-rg53-9pgp); [GitLab Advisory](https://advisories.gitlab.com/npm/dompurify/CVE-2026-49978/)

**CVE-2026-47423 (GHSA-87xg-pxx2-7hvx, 2026):** selectedcontent element bypass. The browser (Chrome 130+) re-clones option content after the sanitizer's walk, reintroducing unsanitized nodes. Payload: `<select><button><selectedcontent></selectedcontent></button><option selected=javascript:1><img src=x onerror=alert(1)>x</option></select>`. Affected DOMPurify 3.4.4. Fixed in 3.4.5. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**CVE-2026-49978 (2026):** IN_PLACE sanitization bypass via attached shadow root inside `<template>.content`. Content inside a template's shadow root was skipped during IN_PLACE sanitization. All versions before 3.4.7 are affected. Fixed in 3.4.7. — [GitLab Advisory](https://advisories.gitlab.com/npm/dompurify/CVE-2026-49978/)

**CVE-2026-66010 (2026):** Hooks skipped for some custom elements during afterSanitizeElements. Reported by @Rikuxx0. Fixed in 3.4.12. Related: GHSA-c2j3-45gr-mqc4. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**Additional hardening fixes (no CVE, 2026):**
- GHSA-cj63-jhhr-wcxv: USE_PROFILES array pollution, fixed in 3.3.2.
- GHSA-76mc-f452-cxcm (fixed 3.4.7) and GHSA-cmwh-pvxp-8882 (fixed 3.4.11): allow-list objects shared across calls.
- 3.4.13: depth-limit flattening fix (moved children instead of cloning during KEEP_CONTENT hoisting), DOM clobbering fix (ownerDocument read through cached getter).
- 3.4.14-3.4.15: mixed document context fixes (case-sensitive attribute handling in XHTML, node-built style/xmp elements with injected text nodes), removeAttributeNode/getAttributeNode called via cached prototypes against DOM clobbering.

### Inferences
- The frequency of DOMPurify CVEs has accelerated in 2025-2026, reflecting both increased scrutiny from security researchers and expanding browser attack surface (e.g., selectedcontent, declarative partial updates).
- Prototype pollution as an XSS gadget via DOMPurify is a significant class because it can be triggered by any upstream prototype pollution vulnerability in the application, turning a non-XSS bug into XSS.
- Server-side usage of DOMPurify (via jsdom) has a fundamentally different parser than browsers, creating a distinct class of bypasses (noscript parsing differences, missing form clobbering).

### Gaps
- Could not access the full trace37.com writeup on CVE-2026-41238 for exact code-level root cause details (DNS resolution failure).
- CVE-2026-65900, CVE-2026-65903, CVE-2026-65898, and CVE-2026-65911 appeared in search results relating to ADD_TAGS/ADD_ATTR configuration issues but could not be fully cross-referenced against NVD.


## mXSS Vectors Exploiting Parser Differentials Between Chrome, Firefox, and Safari

### Takeaway
mXSS fundamentally exploits the gap between how a sanitizer parses HTML and how the browser re-parses the serialized output. The core attack classes -- namespace confusion, integration-point re-entry, rawtext breakouts, depth-limit flattening, and foster parenting -- remain the primary vectors, with browser-specific parser behaviors (nesting limits, foreign-content error recovery) creating per-engine variants.

### Cited Findings

**Core mXSS mechanism:** The sanitizer inspects a DOM tree, but the browser produces a different tree after serialize (innerHTML) and reparse. The divergence creates executable nodes that the sanitizer did not see. Payload: `<svg></p><style><a id="</style><img src=x onerror=alert(1)>"></svg>` -- the style element's content is parsed as raw text in HTML but as elements in SVG namespace. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**Browser nesting depth limits:** WebKit (bug 63082) and Firefox (bug 256180) cap DOM nesting depth. When a sanitizer creates deeply nested structures, the browser flattens them, making child elements become siblings. This changes ancestry relationships that the sanitizer relied on for safety decisions. Payload shape: 512+ nested `<svg>` wrapping `<style><img src=x onerror=alert(1)>`. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**Foster parenting:** HTML table insertion rules relocate nodes outside the table structure. `<table><script>alert(1)</script></table>` -- the script is foster-parented before the table in the DOM, but the sanitizer may inspect it as a table child. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**"Parse Me, Baby, One More Time" (2024):** David Klein et al. (TU Braunschweig, Martin Johns's group) built a generator for hard-to-parse HTML fragments and tested 11 sanitizers across five programming languages. Each assessed sanitizer had at least several functional deficiencies, and the authors automatically bypassed all but two of the 11. Presented at Black Hat Europe 2024. — [CASA RUB Publication](https://casa.rub.de/forschung/publikationen/detail/parse-me-baby-one-more-time-bypassing-html-sanitizer-via-parsing-differentials); [Citation Thinkst](https://citation.thinkst.com/talk/94104)

**HTML spec serialization change (May 2025):** The HTML specification was updated on May 20, 2025 to escape `<` and `>` in attribute values during serialization (innerHTML, outerHTML, getHTML()). This change, authored by Michal Bentkowski, landed in Chrome 138 (stable June 24, 2025), Firefox 140, and Safari 26 beta. It directly mitigates the class of mXSS where unescaped angle brackets in attribute values produce different parse trees on reparse. — [Chrome Developer Blog: Escape Attributes](https://developer.chrome.com/blog/escape-attributes)

**jsdom vs browser parser divergence:** Server-side sanitization via jsdom has fundamentally different behavior: noscript is parsed differently (jsdom always treats it as raw text, browsers depend on scripting context), form element clobbering may not apply, and depth limits differ. This means a payload safe in jsdom may be unsafe in a browser and vice versa. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**CVE-2024-37383 (Roundcube):** SVG animate element whitespace bypass used in state-sponsored attacks. Listed in CISA KEV. A namespace-confusion variant where SVG animate elements with crafted whitespace bypassed the server-side sanitizer. — [Search results, secondary sources]

### Inferences
- The Chrome 138 serialization change is the most impactful structural mitigation against mXSS in years, as it eliminates the entire class of attribute-value-based reparse mutations. However, it does not address namespace confusion, depth-limit flattening, or foster-parenting attacks.
- Server-side sanitization (jsdom, lxml, Bleach, etc.) will always be fundamentally weaker than client-side sanitization because the server parser cannot perfectly replicate each browser's parser behavior.
- Browser parser specification changes can both fix and create mXSS opportunities -- any divergence in adoption timing across Chrome, Firefox, and Safari creates a window where the same markup is handled differently.

### Gaps
- Could not access the Sonar blog post on mXSS for detailed payloads (DNS resolution failure).
- Could not access the Jorian Woltjer blog post on mutation XSS for detailed browser-specific differentials (DNS resolution failure).
- The exact venue for "Parse Me, Baby, One More Time" could not be confirmed as USENIX Security 2024 from available sources.


## Namespace Confusion Attacks (SVG/MathML/HTML Namespace Switching)

### Takeaway
Namespace confusion remains the most potent and frequently exploited mXSS class. It exploits the fact that HTML, SVG, and MathML have different parsing rules -- particularly for elements like `<style>`, `<script>`, and `<xmp>` -- and that integration points allow re-entry between namespaces, creating a gap between sanitizer-time and render-time DOM trees.

### Cited Findings

**SVG namespace style breakout:** In HTML, `<style>` is a raw-text element (its content is not parsed as HTML). In SVG namespace, `<style>` content IS parsed as elements. Payload: `<svg><p><style><img src=x onerror=alert(1)></style></p></svg>`. The sanitizer sees the img as text content of style (HTML rules), but after reparse within SVG context, it becomes an executable element. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**MathML integration-point re-entry:** MathML elements mi, mo, mn, ms, mtext, and annotation-xml (with encoding="text/html" or "application/xhtml+xml") are "integration points" that switch parsing back to HTML rules. Payload: `<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>`. The mglyph element's parent switches from an HTML form context to MathML mtext context between sanitizer pass and browser parse, changing the namespace of descendants. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History); [Vovohelo Medium Post](https://vovohelo.medium.com/from-svg-and-back-yet-another-mutation-xss-via-namespace-confusion-for-dompurify-2-2-2-bypass-5d9ae8b1878f)

**SVG foreignObject re-entry:** `<svg><foreignObject><xmp><img src=x onerror=alert(1)></xmp></foreignObject></svg>`. foreignObject is an HTML integration point that lets HTML content execute inside an SVG context. The xmp element is treated as raw text in HTML but not in SVG. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**Bentkowski's ownership mutation gadget (foundational):** The original DOMPurify namespace confusion bypass used an mglyph element whose parent moved from an HTML form into a MathML mtext element, causing descendants to change namespace between the sanitizer's tree walk and the browser's reparse. Gareth Heyes followed up with a comment-based variant. — [DOMPurify PR #495](https://github.com/cure53/DOMPurify/pull/495); [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**MathML xlink:href data URI:** `<math><mi xlink:href="data:x,<script>alert(1)</script>"></mi></math>`. The xlink:href attribute in MathML namespace can carry data URIs, and if ALLOW_UNKNOWN_PROTOCOLS is enabled, the data URI payload survives. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**Angular namespaced script bypass:** Angular's template preparser did not recognize svg:script as a script element. GHSA-f3m7-gqxr-g87x. — [Angular Security Advisory](https://github.com/angular/angular/security/advisories/GHSA-f3m7-gqxr-g87x)

**Ammonia (Rust) namespace bypass (GHSA-mm7x-qfjj-5g2c):** Elements violating namespace rules were kept rather than removed, enabling XSS through namespace-switched elements. — [Miggo Vulnerability Database](https://www.miggo.io/vulnerability-database/cve/GHSA-mm7x-qfjj-5g2c)

**lxml_html_clean namespace gap (CVE-2024-52595):** The lxml-based cleaner does not support SVG or MathML namespaces, so foreign-content elements are not properly handled, enabling namespace confusion. — [Search results, secondary source]

**DOMPurify mitigation (current):** The recommended defense is sanitize, serialize, reparse, and inspect again -- verifying the output after the round trip rather than trusting the first parse. DOMPurify's fix added namespace verification per node against its parent's namespace. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

### Inferences
- Namespace confusion is inherent to the HTML specification's design of foreign content (SVG and MathML embedded in HTML). As long as sanitizers operate on a single parse tree and output serialized HTML for reparsing, the gap between parse-time and render-time namespaces will be exploitable.
- The Chrome 138 spec change (escaping < and > in attributes) addresses one pathway but not the core namespace-switching mechanism.
- Libraries that do not implement foreign-content parsing at all (lxml, older server-side cleaners) are fundamentally vulnerable to namespace confusion because they cannot detect or reason about namespace transitions.

### Gaps
- No detailed browser-specific differential analysis found showing exactly where Chrome (Blink), Firefox (Gecko), and Safari (WebKit) diverge in namespace handling during error recovery.


## Browser-Native Sanitizer API: Current State and Bypass Techniques

### Takeaway
The browser-native Sanitizer API (setHTML/getHTML) reached cross-browser availability in 2025-2026, with its main advantage being elimination of the parse-serialize-reparse cycle that enables mXSS. However, bypasses have already been found in Chrome's implementation, including a UXSS (CVE-2026-7939), and the API's design has required significant reworking (Mozilla dropped the string-accepting sanitize() method to avoid context-dependent bypass risks).

### Cited Findings

**API rollout status:**
- Chrome: Sanitizer API available since Chrome 146 (approximately early 2026). — [Searchlight Cyber Research](https://www.slcyber.io/research/two-bypasses-for-chromes-sanitizer-api)
- Firefox: Available in Firefox 148 nightly as of late 2025. — [ibit.blog](https://www.ibit.blog/articles/html-sanitizer-api)
- Safari: Safari 26 (September 2025) includes support. — [Chrome Developer Blog](https://developer.chrome.com/blog/escape-attributes)
- The API became "Baseline" (available in all major browsers) in 2026. — [keith.is](https://keith.is/post/html-sanitizer-api/)

**Two Chrome Sanitizer API bypasses (Chrome 146):** Security researchers at Searchlight Cyber (Adam Kues) reported two bypasses in Chrome's Sanitizer API implementation. One was discovered by the author and one by another party. The empty configuration (`new Sanitizer({})`) is the most permissive configuration but should still block scripts. The bypasses demonstrate that even browser-native implementations are not immune to implementation bugs. — [Searchlight Cyber](https://www.slcyber.io/research/two-bypasses-for-chromes-sanitizer-api) (page could not be fetched for full technical details)

**CVE-2026-7939 (May 2026):** Inappropriate implementation in SanitizerAPI in Google Chrome before 148.0.7778.96. Severity: Medium (Google), CVSS 3.1 score 5.4 (CISA-ADP). Allows remote attacker to inject scripts or HTML (UXSS) via crafted HTML page. Fixed in Chrome 148.0.7778.96. — [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-7939); [Red Hat Bugzilla](https://bugzilla.redhat.com/show_bug.cgi?id=2467415)

**Mozilla srcdoc design decision:** Mozilla bug 1669945 documented a sanitizer bypass when sanitized markup is assigned to srcdoc. Mozilla chose to change the API design rather than patch the bypass -- they removed the context-free sanitize() function that accepts an HTML string. The rationale: a string-in/string-out sanitizer cannot know the insertion context, so it cannot guarantee safety. This is why the API became setHTML() (element method) rather than Sanitizer.sanitize(string). — [Mozilla Bugzilla 1669945](https://bugzilla.mozilla.org/show_bug.cgi?id=1669945); [Frederik Braun: Why the Sanitizer API is just setHTML()](https://frederikbraun.de/why-sethtml.html)

**Advantage over DOMPurify:** The browser Sanitizer API eliminates mXSS by design: it parses and sanitizes in the same engine that will render the content, removing the parse-serialize-reparse gap. There is no serialization step -- the sanitized DOM tree is inserted directly. — [ibit.blog](https://www.ibit.blog/articles/html-sanitizer-api); [keith.is](https://keith.is/post/html-sanitizer-api/)

**HtmlSanitizer (.NET) template tag bypass (CVE-2026-25543):** Separate from the browser API. A template-tag bypass in the .NET HtmlSanitizer library. — [GitLab Advisory](https://advisories.gitlab.com/pkg/nuget/htmlsanitizer/CVE-2026-25543/)

### Inferences
- The Sanitizer API's design (setHTML as an element method rather than a string sanitizer) is a direct response to the fundamental mXSS problem. By operating on the same parser that will render the content, it eliminates the class of bugs that arise from parser differentials.
- However, implementation bugs (CVE-2026-7939) show that even browser-native sanitization is not a silver bullet. The implementation must correctly handle all edge cases in the HTML parser specification.
- The API's restrictive design (no string output, element-method-only) may limit adoption in scenarios where developers need sanitized HTML as a string (e.g., for server-side rendering, email templates, or storage).

### Gaps
- Could not fetch the full Searchlight Cyber writeup on the two Chrome Sanitizer API bypasses (DNS resolution failure). The specific payloads and root causes are unknown.
- The upstream Chromium bug for CVE-2026-7939 (issues.chromium.org/issues/492963096) was not accessed.
- Whether the selectedcontent element is specifically involved in CVE-2026-7939 could not be confirmed.


## Trusted Types Bypass Techniques (2024-2026)

### Takeaway
Trusted Types reached Baseline browser support in early 2026 (Firefox 148 in February 2026, joining Chrome 83+ and Safari 26+). The primary known bypass technique exploits the fact that CSP require-trusted-types-for is not propagated to cross-origin iframes, allowing attacker-controlled frames to create their own policies. No other specific Trusted Types bypass techniques were found in public research from this period.

### Cited Findings

**Cross-origin iframe bypass ("MutantBedrog", 2024):** Confiant's research describes a bypass where CSP's `require-trusted-types-for 'script'` is not propagated to network-served iframes (only local scheme iframes inherit it). An attacker-controlled iframe can create its own trustedTypes policy and operate outside the parent's restrictions. The Trusted Types specification explicitly warns about this collusion risk. — [Search results, secondary sources]

**Browser adoption timeline:**
- Chrome/Edge: Trusted Types supported since version 83.
- Safari: Trusted Types supported since Safari 26 (September 2025).
- Firefox: Trusted Types shipped in Firefox 148 (February 2026), completing Baseline status.
- Interop 2025 included Trusted Types as a focus area. — [Interop Issue 1465](https://github.com/web-platform-tests/interop/issues/1465); [DEV Community](https://dev.to/grimicorn/trusted-types-is-baseline-dom-xss-is-now-a-type-error-1k1h)

**Defensive model:** Trusted Types enforces sink-level controls, requiring all DOM XSS sinks (innerHTML, document.write, eval, etc.) to receive a TrustedHTML/TrustedScript/TrustedScriptURL object rather than a raw string. Applications must define a policy that creates these objects, making the policy the single auditable chokepoint. — [URIPorts Blog](https://www.uriports.com/blog/csp-trusted-types/)

### Inferences
- Trusted Types is primarily a defense-in-depth mechanism that makes DOM XSS bugs harder to write rather than impossible. The iframe bypass is an architectural limitation of CSP inheritance, not a flaw in Trusted Types itself.
- The effectiveness of Trusted Types depends on application adoption. If a default policy is overly permissive (e.g., `createHTML: (s) => s`), it provides no security benefit.
- DOMPurify is commonly used as the implementation behind a Trusted Types policy (`trustedTypes.createPolicy('default', { createHTML: (s) => DOMPurify.sanitize(s) })`), so DOMPurify bypasses directly translate to Trusted Types bypasses when this pattern is used.

### Gaps
- Could not access the original Confiant MutantBedrog research paper for detailed technical specifics.
- No additional Trusted Types bypass techniques beyond the iframe inheritance issue were found in public research. This may indicate genuine robustness or limited research attention.


## DOMPurify Configuration Pitfalls

### Takeaway
Several DOMPurify configuration options dramatically weaken sanitization when misused. The most dangerous are ALLOW_UNKNOWN_PROTOCOLS, function-form ADD_TAGS combined with FORBID_TAGS, ADD_URI_SAFE_ATTR, CUSTOM_ELEMENT_HANDLING with broad regex patterns, RETURN_DOM, IN_PLACE, SAFE_FOR_XML: false, and SANITIZE_DOM: false. Stale state across sanitize() calls on a single instance with function-based configs is an additional, subtle pitfall.

### Cited Findings

**ALLOW_UNKNOWN_PROTOCOLS:** Enables all URI schemes. Dangerous payloads include `javascript:`, `data:`, and `vbscript:` URIs. An Adobe community thread shows it being enabled for custom schemes (like `aem:`), with a warning that it could introduce security risks. The safer alternative is a per-attribute hook that allows only specific schemes. — [Adobe Community Thread](https://experienceleaguecommunities.adobe.com/adobe-experience-manager-sites-8/dompurify-sanitizing-issue-31372)

**ADD_TAGS function-form bypassing FORBID_TAGS:** Versions before 3.4.0 have a logic error where a function-form ADD_TAGS can let tags that FORBID_TAGS lists through. Root cause: a condition returns early when the tag check passes, so the forbid check never runs. Payload: `<iframe src="https://evil.example">` with `ADD_TAGS: () => true` and `FORBID_TAGS: ['iframe']`. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History); [Fluid Attacks](https://db.fluidattacks.com/vul/FLAT-GWP3J/)

**Stale ADD_TAGS/ADD_ATTR state:** Function predicates passed through ADD_ATTR or ADD_TAGS persist on a DOMPurify instance across later sanitize() calls. A later call passing an array does not clear the function handler. One source claims that removeAllHooks(), clearConfig(), and passing a fresh cfg do not recover the state -- only constructing a new instance clears it. This claim could not be verified against upstream. — [Telegram CVE Notifications](https://t.me/s/cveNotify/225794)

**CUSTOM_ELEMENT_HANDLING with broad regex:** Using `tagNameCheck: /.*/` with `allowCustomizedBuiltInElements: true` allows all custom elements and customized built-in elements through, including those with dangerous event handlers. This is the attack surface exploited by CVE-2026-41238 (prototype pollution setting these regexes). — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**ADD_URI_SAFE_ATTR:** Marks additional attributes as safe for URI content. Combined with ALLOW_UNKNOWN_PROTOCOLS, this expands the set of attributes that can carry javascript: or data: URIs. Payload: `<math><mi xlink:href="data:x,<script>alert(1)</script>"></mi></math>`. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**RETURN_DOM and RETURN_DOM_FRAGMENT:** Return the DOM tree directly instead of a serialized string. If the returned DOM is later serialized (e.g., via innerHTML), it undergoes the same serialize-reparse cycle that mXSS exploits, negating DOMPurify's output verification. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**IN_PLACE:** Sanitizes a live DOM tree in place rather than cloning it. Introduces additional attack surface: shadow roots, live event handlers on rejected nodes, and cross-realm instanceof failures. CVE-2026-49978 is an IN_PLACE-specific bypass via shadow roots in template content. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**SAFE_FOR_XML: false:** Disables XML-safe serialization checks. Combined with rawtext elements, this can enable breakouts. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**SANITIZE_DOM: false:** Disables DOM clobbering protection. Allows form elements with name attributes that shadow DOM properties used by DOMPurify itself (e.g., `<form><input name=nodeName>`). — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

### Inferences
- The safest DOMPurify configuration is the default. Every configuration option that adds permissions or changes output mode is a potential bypass vector.
- Instance reuse with changing configurations is a subtle and dangerous pattern. Applications should either use a fresh DOMPurify instance per sanitization context or carefully validate that configuration state is fully reset.
- The interaction between ADD_TAGS and FORBID_TAGS (additions overriding forbids) is a design flaw that was present for many versions and likely affected many deployments.

### Gaps
- The exact behavior of clearConfig() and removeAllHooks() with respect to function-based ADD_TAGS/ADD_ATTR predicates could not be confirmed against upstream source code.


## Fuzzing Techniques and Tools for mXSS Discovery

### Takeaway
The primary publicly documented tool for systematic mXSS discovery is MutaGen (from the "Parse Me, Baby, One More Time" research, 2024), which generates hard-to-parse HTML fragments and tests them against sanitizers. DOMPurify itself uses a Playwright-based browser matrix for verification. No other dedicated mXSS fuzzers were found in public research from 2024-2026.

### Cited Findings

**MutaGen (2024):** A generator for hard-to-parse HTML fragments, developed by David Klein et al. (TU Braunschweig). Used to test 11 sanitizers across five programming languages. The tool automatically bypassed all but two of the 11 tested sanitizers. Presented at Black Hat Europe 2024. The approach relies on generating fragments that exercise parser edge cases (namespace transitions, error recovery, rawtext boundaries, nesting limits) and checking whether the sanitized output produces a different DOM tree on reparse. — [CASA RUB Publication](https://casa.rub.de/forschung/publikationen/detail/parse-me-baby-one-more-time-bypassing-html-sanitizer-via-parsing-differentials); [RuhrSec Slides](https://ruhrsec.de/downloads/slides/Parse-Me-Baby-One-More-Time-Bypassing-HTML-Sanitizer-via-Parsing-Differentials-David-Klein-RuhrSec.pdf)

**mutagen (GitHub, Robert-Doe):** A GitHub project described as "Mutation XSS built from scratch: why parse(serialize(parse(x))) != parse(x), and how sanitizers get bypassed on re-parse." This appears to be an educational/research tool demonstrating the parse-serialize-reparse differential. — [GitHub: Robert-Doe/mutagen](https://github.com/Robert-Doe/mutagen)

**DOMPurify's own verification approach:** The DOMPurify wiki states that the "closed" status of attack classes is verified using jsdom, but acknowledges that jsdom does not reproduce several browser-parser classes. The authoritative verification uses a Playwright browser matrix (testing across Chrome, Firefox, and Safari). — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**Checkmarx Bleach fuzzing (2020, foundational):** Checkmarx researchers used fuzzing to discover mXSS vulnerabilities in Mozilla Bleach. While predating the 2024-2026 window, the methodology -- generating mutations of known-dangerous HTML fragments and testing them against the sanitizer -- remains the standard approach. — [Checkmarx Blog](https://www.checkmarx.com/blog/vulnerabilities-discovered-in-mozilla-bleach)

**Sonar/Insomnihack 2024:** Sonar published a writeup on mXSS tied to an Insomnihack 2024 talk, reportedly describing systematic testing methodology for mXSS discovery. The page could not be fetched. — [Sonarsource Blog](https://www.sonarsource.com/blog/mxss-the-vulnerability-hiding-in-your-code/)

### Inferences
- The state of publicly available mXSS fuzzing tools is surprisingly sparse. MutaGen appears to be the only dedicated, research-grade tool, and it was developed in an academic context rather than as a community tool.
- The most effective mXSS discovery approach combines: (1) understanding the HTML parser specification's edge cases (namespace transitions, error recovery, rawtext boundaries), (2) generating fragments that exercise those edge cases, and (3) comparing sanitizer output DOM trees against browser reparse DOM trees.
- DOMPurify's reliance on jsdom for initial verification, despite jsdom's known parser differences from real browsers, suggests that the project's own testing may miss browser-specific bypasses.

### Gaps
- Could not access the Sonarsource blog post on mXSS for fuzzing methodology details.
- No open-source, actively maintained mXSS fuzzing tool comparable to established web security fuzzers (like wfuzz, ffuf) was found.
- The full MutaGen tool source code availability and license could not be confirmed from search results alone.


## Browser HTML Parser Specification Changes Creating mXSS Opportunities

### Takeaway
The most significant parser specification change in this period is the May 2025 HTML spec update mandating escape of `<` and `>` in attribute values during serialization, which directly eliminates one major mXSS class. Browser-specific new features (selectedcontent in Chrome 130+, declarative partial updates in Chrome 150) create new attack surface that sanitizers must track.

### Cited Findings

**HTML spec attribute escaping (May 20, 2025):** The HTML specification was updated to require that `<` and `>` be escaped to `&lt;` and `&gt;` in attribute values during serialization (innerHTML, outerHTML, getHTML()). Authored by Michal Bentkowski. This prevents the class of mXSS where unescaped angle brackets in attribute values create different parse trees when the serialized output is reparsed. Shipped in Chrome 138 (stable June 24, 2025), Firefox 140, and Safari 26 beta. Parsing behavior is unchanged -- only serialization output changes. — [Chrome Developer Blog](https://developer.chrome.com/blog/escape-attributes)

**selectedcontent element (Chrome 130+, 2026):** A new HTML element that causes the browser to re-clone option content after the sanitizer's walk. DOMPurify 3.4.4 had a default allowlist misconfiguration that let selectedcontent through, enabling XSS (CVE-2026-47423). Fixed in 3.4.5. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**Declarative partial updates (Chrome 150, 2026):** A new feature where template elements with a `for` attribute can patch named markers in the DOM. Payload: `<svg><?marker name="x"></svg><template for="x"><style><img src onerror=alert()></style></template>`. DOMPurify's defense is to remove the `for` attribute. The DOMPurify wiki notes that Chrome 150 does not expand patches after sanitization, so the attribute removal is defense-in-depth. — [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

**Breakage from attribute escaping:** The Chrome team warns that serialized-HTML comparisons (CI tests matching exact HTML strings) may break, and that code parsing outerHTML with regex may break. — [Chrome Developer Blog](https://developer.chrome.com/blog/escape-attributes)

### Inferences
- New browser platform features (selectedcontent, declarative partial updates) represent an ongoing arms race: each new element or API that manipulates DOM content post-sanitization is a potential mXSS vector until sanitizers explicitly handle it.
- The attribute escaping spec change is a rare case of the HTML specification being changed specifically to address a security vulnerability class. This sets a precedent for spec-level security fixes.
- The window between spec change and browser adoption (Chrome 138 shipped June 2025, but other browsers may lag) creates a period where applications relying on the new behavior are not universally protected.

### Gaps
- Whether any browsers deviate from the spec in their implementation of the attribute escaping change could not be determined.
- The full list of new HTML elements or APIs in development that could create similar post-sanitization DOM manipulation risks was not surveyed.
