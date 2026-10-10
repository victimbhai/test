# Modern JavaScript Framework XSS Vulnerabilities and Emerging Web Platform XSS Vectors (2024-2026)

## Next.js App Router, Server Components, and Server Actions XSS

### Takeaway
No confirmed XSS vulnerability has been publicly disclosed specifically in Next.js Server Components or Server Actions as of mid-2026. The critical vulnerabilities found in this area are server-side prototype pollution leading to RCE (CVE-2025-55182 / React2Shell) and SSRF (CVE-2024-34351), not traditional XSS. However, the React Server Components (RSC) serialization protocol introduces a novel attack surface where server-side prototype pollution -- which in client-side contexts typically leads to XSS -- escalates directly to remote code execution on the server.

### Cited Findings
- **React2Shell (CVE-2025-55182):** A CVSS 10.0 server-side prototype pollution vulnerability in React Server Components packages (`react-server-dom-parcel`, `react-server-dom-webpack`, `react-server-dom-turbopack`) versions 19.0 through 19.2.0. Exploitation is over HTTP via crafted multipart POST requests with a `Next-Action` header. The upstream patch changes `requireModule` so it returns a module export only if the property is an own property of the module's exports object. Exploitation was confirmed against default `create-next-app` projects without authentication. In-the-wild payloads executed shell commands to download scripts or exfiltrate `.env` files. -- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/)
- **Next.js tracking (CVE-2025-66478):** Next.js versions 15.x, 16.x, and 14.3.0-canary.77+ were affected. Patched in 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, and 16.0.7. Next.js 13.x, 14.x stable, Pages Router applications, and Edge Runtime are not affected. -- [Next.js Security Advisory](https://nextjs.org/blog/CVE-2025-66478); [CSA Singapore Alert](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2025-112/)
- **Server Actions SSRF (CVE-2024-34351):** An SSRF vulnerability in Next.js Server Actions discovered by Assetnote, patched in Next.js 14.1.1 via PR #62561. -- [GitHub Advisory GHSA-fr5h-rqp8-mj6g](https://github.com/vercel/next.js/security/advisories/GHSA-fr5h-rqp8-mj6g)
- **Source code exposure (CVE-2025-55183):** Compiled Server Function source exposure was listed in one security summary, though details are sparse. -- [Endor Labs](https://www.endorlabs.com/learn/critical-remote-code-execution-rce-vulnerabilities-in-react-and-next-js)
- The Datadog article notes that server-side prototype pollution "is usually exploited client-side for XSS, but on the server it can lead to RCE or arbitrary file reads." -- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/)
- The only historically confirmed Next.js XSS is from version 7.0.0-7.0.2 in the `/_error` page, predating the App Router entirely. -- [HackTron Next.js Changelog](https://www.hacktron.ai/security-changelog/nextjs)

### Inferences
- The RSC wire protocol (React Flight) creates a new class of server-side deserialization vulnerability that is structurally similar to Java/PHP deserialization attacks but specific to JavaScript's prototype chain. Traditional XSS sanitization is irrelevant to this vector.
- Server Components that pass `dangerouslySetInnerHTML` content from server to client remain a developer-responsibility XSS risk, but no framework-level bypass has been disclosed.
- The absence of direct XSS CVEs in Next.js App Router may reflect that React's JSX auto-escaping remains effective for the SSR output path, but the RSC serialization payload itself could theoretically carry injection if the protocol evolves.

### Gaps
- No public research was found analyzing the React Flight payload format for XSS injection opportunities (e.g., whether a crafted RSC payload could inject script into client-side hydration).
- No confirmed CVE for hydration mismatch exploitation leading to XSS in Next.js App Router was found.


## Remix Loaders/Actions and SvelteKit Load Functions XSS

### Takeaway
Both Remix (now React Router) and SvelteKit have disclosed XSS vulnerabilities tied to their server-side data loading and action mechanisms. Remix had meta-tag injection and redirect-based XSS; SvelteKit/Svelte had SSR-specific XSS through spread attributes and contenteditable bindings that bypassed auto-escaping.

### Cited Findings
- **Remix/React Router meta-tag XSS (CVE-2025-59057):** One of six CVEs disclosed for the framework. Untrusted input passed into route meta tags could execute JavaScript in the browser. -- [Netlify Changelog](https://www.netlify.com/changelog/2026-01-15-react-router-remix-security-vulnerabilities/)
- **Remix/React Router redirect XSS (CVE-2026-22029):** Actions and experimental RSC Server Functions performing a redirect to a path constructed from untrusted user input could be hijacked to execute JavaScript. -- [Netlify Changelog](https://www.netlify.com/changelog/2026-01-15-react-router-remix-security-vulnerabilities/)
- **Svelte SSR spread attribute XSS:** Event handler properties from untrusted data ended up in SSR HTML output when using spread attributes. Fixed in Svelte 5.51.5. -- [Netlify Changelog](https://www.netlify.com/changelog/2026-01-15-sveltekit-security-vulnerabilities/)
- **Svelte SSR contenteditable XSS (CVE-2026-27901):** `bind:innerText` and `bind:textContent` values were not escaped during server-side rendering. -- [Netlify Changelog](https://www.netlify.com/changelog/2026-01-15-sveltekit-security-vulnerabilities/)
- **Svelte client-side XSS (CVE-2025-15265):** Affects Svelte 5.46.0 through 5.46.3. Client-side only. -- [Netlify Changelog](https://www.netlify.com/changelog/2026-01-15-sveltekit-security-vulnerabilities/)
- **Nuxt `navigateTo` XSS (CVE-2024-34343):** Mishandled `javascript:` URLs in the `navigateTo` function. -- [Vulners Nuxt CVE List](https://vulners.com/search/vendors/nuxt/products/nuxt)
- **Nuxt reflected XSS via server-side `navigateTo` with `external: true` (CVE-2026-45669):** Fixed in Nuxt 3.21.6 and 4.4.6. -- [HackTron Nuxt Changelog](https://www.hacktron.ai/security-changelog/nuxt)
- **Nuxt DevTools DOM-based XSS (CVE-2025-52662):** Fixed in DevTools 2.6.4. Part of a chain that could lead to RCE in development environments. -- [Vercel Changelog](https://vercel.com/changelog/cve-2025-52662-xss-on-nuxt-devtools)
- **Nuxt NoScript slot XSS (CVE-2026-56317):** An additional Nuxt XSS vector. -- [HackTron Nuxt Changelog](https://www.hacktron.ai/security-changelog/nuxt)
- **Nuxt prerendered payload URL XSS (CVE-2023-0878):** Fixed in Nuxt 3.2.1. -- [Vulners Nuxt CVE List](https://vulners.com/search/vendors/nuxt/products/nuxt)

### Inferences
- The Remix meta-tag and redirect XSS vectors share a common pattern: framework APIs that accept developer-provided strings and render them into HTML or HTTP responses without escaping. Loader/action return values that flow into `<meta>` tags or `redirect()` calls are the specific injection points.
- SvelteKit's SSR XSS through spread attributes reveals that auto-escaping in template frameworks can have gaps when dynamic attribute spreading is used, because the framework must decide which attributes are safe (data attributes) vs. dangerous (event handlers like `onclick`).
- Nuxt's repeated `navigateTo` issues suggest that client-side navigation APIs that accept URLs are a persistent XSS surface when `javascript:` protocol URLs are not filtered.

### Gaps
- Specific reproduction steps and vulnerable code patterns for the Remix CVEs were not detailed in the public advisories found. The Netlify changelog describes them in general terms.
- No research was found on SvelteKit `load` function return values being directly injectable into SSR output beyond the spread attribute case.


## Qwik Resumability and Solid.js SSR Hydration XSS Vectors

### Takeaway
Qwik's resumability model creates a unique XSS surface because it serializes application state directly into HTML comments, and a confirmed vulnerability (GHSA-m6jq-g7gq-5w3c) demonstrates that unescaped comment content allows HTML injection. No Solid.js-specific SSR XSS vulnerability was found in public sources.

### Cited Findings
- **Qwik SSR comment injection (GHSA-m6jq-g7gq-5w3c):** An SSR XSS in qwik-city before version 1.19.0. Qwik serializes application state into HTML so the client can resume execution from server-rendered output. The bug is in how component-boundary comments are written: SSR builds comment content for virtual components without escaping or quoting, so an attacker-controlled key or value can close the comment early (`-->`) and inject arbitrary HTML/JS. The advisory also notes that breaking the comment markers can lead to resume/hydration desync and unexpected client-side behavior. Rated Medium severity (CVSS 5.3). -- [OSV Advisory GHSA-m6jq-g7gq-5w3c](https://osv.dev/GHSA-m6jq-g7gq-5w3c)
- Qwik does not use traditional hydration; instead it uses "resumability" where serialized state in HTML comments drives client-side execution resumption. -- [OSV Advisory](https://osv.dev/GHSA-m6jq-g7gq-5w3c)

### Inferences
- Qwik's resumability model is architecturally more exposed to comment-injection XSS than traditional hydration frameworks because it embeds executable metadata (component boundaries, event bindings, state references) directly in HTML comments. In traditional SSR, comments are inert; in Qwik, they drive code execution on the client.
- The comment-closing injection pattern (`-->`) is a well-known HTML injection technique, but its application to framework-specific comment markers that control resumability is novel.
- Solid.js uses fine-grained reactivity with SSR hydration markers, which could in theory have similar comment-injection issues, but no public vulnerability or research was found to confirm this.

### Gaps
- No Solid.js SSR XSS vulnerability or security advisory was found in any public source searched. This may mean Solid.js has not been audited as extensively, or that its hydration marker implementation handles escaping correctly.
- No detailed exploitation writeup for the Qwik comment injection was found beyond the advisory text.


## Astro Partial Hydration (Islands Architecture) XSS Risks

### Takeaway
Astro has a confirmed XSS vulnerability (CVE-2026-59727) specifically in its View Transitions integration with hydrated islands, where `transition:*` directive values are not HTML-escaped in SSR output. The real-world severity is low because exploitation requires a developer to pass untrusted input into these specific directives.

### Cited Findings
- **Astro transition directive XSS (CVE-2026-59727):** Affects Astro versions 3.10.0 through 7.0.3, fixed in 7.0.4. The `transition:persist`, `transition:scope`, and `transition:persist-props` directive values are not HTML-escaped when applied to client-hydrated components (islands). If a developer passes request-derived input into these directives, an attacker can inject arbitrary HTML/script. CVSS v4.0 base score: 2.1 (Low). -- [Corgea Advisory](https://corgea.com/advisories/vulnerabilities/CVE-2026-59727); [OSV](https://osv.dev/vulnerability/CVE-2026-59727); [Vulert](https://vulert.com/vuln-db/CVE-2026-59727)

### Inferences
- Astro's islands architecture introduces XSS risk at the boundary where static HTML meets hydration directives. The framework must escape any attribute values that bridge the static/dynamic boundary, and the `transition:*` directives were a missed case.
- The low CVSS score reflects that the attacker needs the developer to have written code that pipes untrusted input into a `transition:*` attribute, which is an uncommon pattern. However, in applications that generate dynamic page transition identifiers from URL parameters or database values, this could be exploitable.
- Astro's general approach of shipping zero client-side JavaScript by default reduces the overall XSS attack surface compared to fully client-rendered frameworks, but the island hydration boundaries are the specific points where escaping failures can occur.

### Gaps
- No broader security audit of Astro's island hydration boundary was found. It is unknown whether other directive values (e.g., `client:*` directives) have similar escaping gaps.
- No research was found on Astro's partial hydration allowing injection into the hydration script/data payload itself.


## WebAssembly-Based XSS Payloads and Evasion Techniques

### Takeaway
No peer-reviewed or vendor-confirmed research was found on WebAssembly being used as a practical XSS evasion technique as of mid-2026. Claims about WASM-based XSS payloads come from community cheat sheets and GitHub repositories that lack primary-source backing.

### Cited Findings
- One XSS cheat sheet asserts that "WebAssembly modules can host and execute compiled malicious logic, bypassing JavaScript-based detection" but provides no CVE, PoC, or primary source for this claim. -- [yazoul.net XSS Payload Cheat Sheet](https://www.yazoul.net/learn/resource/xss-payload-cheat-sheet/)
- A GitHub repository ("Advanced-XSS") lists WebAssembly under evasion techniques but the code examples are unverified community contributions. -- [GitHub: Karthikdude/Advanced-XSS](https://github.com/Karthikdude/Advanced-XSS)

### Inferences
- WebAssembly requires JavaScript to instantiate (`WebAssembly.instantiate()` or `WebAssembly.compileStreaming()`), so a WASM-based XSS payload still needs a JavaScript execution context as its entry point. WASM cannot register event handlers or access the DOM directly; it must call back into JavaScript. This limits its standalone evasion value.
- The theoretical advantage of WASM for evasion is that WAF signature-based detection targeting JavaScript syntax (e.g., `alert(`, `document.cookie`) would not match compiled WASM bytecode. However, the JavaScript bootstrap code that loads the WASM module would still be detectable.
- WASM may be more useful for post-exploitation (e.g., running cryptominers, complex data processing) than for initial XSS payload delivery.

### Gaps
- No academic paper, vendor advisory, or conference talk was found demonstrating a working WASM-based XSS evasion technique against a real WAF or browser security mechanism.
- The interaction between Content Security Policy and WASM loading (e.g., whether `wasm-unsafe-eval` in CSP affects XSS payloads) was not covered by any source found.


## Service Worker Hijacking via XSS for Persistent Browser Compromise

### Takeaway
Service worker abuse via XSS is a well-documented persistence technique. An attacker who achieves XSS can register a malicious service worker that intercepts all network requests within its scope, persists across page navigations and browser restarts, and survives after the original XSS vulnerability is patched.

### Cited Findings
- **Academic study on SW-XSS:** Researchers identified a vulnerability class they call "SW-XSS" caused by websites using questionable programming practices to install service workers. The study found that "the attacker can stealthily utilize a compromised service worker for an extended period of time." -- [ACM Digital Library](https://dl.acm.org/doi/fullHtml/10.1145/3427228.3427290)
- **Akamai attack chain:** An attacker uploads a malicious script to a sandboxed domain, uses an XSS vulnerability to register it as a service worker, and the worker activates and persists. This works because sandboxed domains designed to store uploaded content serve files from the same origin. -- [Akamai Blog](https://www.akamai.com/blog/security/abusing-the-service-workers-api)
- **TrustedSec clarification:** The service worker code itself must be loaded from the web server (same origin); it cannot be a `data:` URL or `blob:` URL from a different origin. This constrains the attack: the attacker needs either an upload capability on the target origin or an existing JavaScript file on the server they can point the registration to. -- [TrustedSec Blog](https://trustedsec.com/blog/persistence-through-service-workers-part-1-introduction-and-target-application-setup)
- Service workers intercept fetch events, allowing the attacker to modify responses, inject content into pages, exfiltrate data, and serve cached malicious content even when the server has been cleaned. -- [ACM Digital Library](https://dl.acm.org/doi/fullHtml/10.1145/3427228.3427290)

### Inferences
- The service worker scope restriction (must be same-origin, served with `Service-Worker-Allowed` header for broader scope) means the attacker's uploaded script must come from a path within the target scope. CDN or upload domains that share the application's origin are the primary enablers.
- Modern frameworks that serve static assets from the same origin (e.g., Next.js `/_next/static/`, Nuxt `/_nuxt/`) could theoretically be targeted if an attacker can control file content in those paths, though no specific framework exploit for this was found.
- The `Clear-Site-Data` header is the primary remediation, but it requires the server to send it, which may not happen if the attacker's service worker intercepts the response first.

### Gaps
- No 2024-2026 specific CVE or new research on service worker hijacking was found. The core technique has been known since 2017-2020.
- No framework-specific service worker hijacking research (e.g., exploiting Next.js or Nuxt PWA service worker registration) was found.


## Shadow DOM (Open and Closed) and Web Component Lifecycle Exploitation

### Takeaway
Shadow DOM is not a security boundary. Research confirms that closed shadow roots can be accessed through various browser APIs, and Declarative Shadow DOM creates an HTML injection vector that can bypass DOM-based sanitizers. The sanitizer bypass is the most practically significant finding.

### Cited Findings
- **Masato Kinugawa's research:** His talk "Shadow DOM & Security" explores whether placing sensitive content in a closed shadow DOM always blocks access, and identifies a list of APIs that break Shadow DOM encapsulation. -- [Speaker Deck: masatokinugawa](https://speakerdeck.com/masatokinugawa/shadow-dom-and-security-exploring-the-boundary-between-light-and-shadow)
- **Shadow DOM is not a security boundary:** "An attacker who gains script execution on your page can access the shadowRoot" of open shadow DOM via `element.shadowRoot`. Even closed shadow DOM can be accessed through saved references, browser devtools APIs, and certain DOM traversal methods. -- [Medium](https://medium.com/@amarsingh.dhillon11/beyond-xss-leveraging-shadow-dom-for-secured-react-components-c18e6597c1ac)
- **Declarative Shadow DOM sanitizer bypass:** A sanitizer that uses the browser's parser (via DOMParser or innerHTML), does not understand declarative Shadow DOM, and returns the live DOM rather than a sanitized string can be bypassed. The payload hides inside a `<template shadowrootmode="closed">` element, which the sanitizer's tree walk cannot see because the browser creates a closed shadow root that is not enumerable. -- [W3C Public WebApps GitHub Archive](https://lists.w3.org/Archives/Public/public-webapps-github/2020Oct/0624.html)
- **Browser mitigation:** A specification change blocks declarative Shadow DOM from being used by fragment parser entry points (innerHTML, DOMParser) unless an explicit opt-in is toggled. This means the attack works only in full document parsing contexts, not when sanitizing via innerHTML. -- [WHATWG DOM PR #892](https://github.com/whatwg/dom/pull/892)
- The `onslotchange` event handler on `<slot>` elements inside declarative shadow roots is cited as an XSS trigger mechanism in one cheat sheet source, attributed to PortSwigger 2024-2025 additions, but this attribution could not be independently confirmed. -- [Vulnsy XSS Cheat Sheet](https://www.vulnsy.com/cheat-sheets/xss)

### Inferences
- The practical attack scenario is: an attacker injects HTML containing a declarative shadow DOM template into a page that uses a vulnerable server-side or client-side sanitizer. The sanitizer parses the HTML, fails to traverse into the shadow root, and passes the content through with the malicious payload intact.
- Web Components that use `innerHTML` to set content from user input within their shadow DOM create the same XSS risk as regular DOM elements using `innerHTML`. The shadow boundary does not sanitize content.
- Custom element lifecycle callbacks (`connectedCallback`, `attributeChangedCallback`) that process untrusted data are XSS sinks equivalent to any other DOM manipulation code.

### Gaps
- No 2024-2025 PortSwigger research paper specifically on Declarative Shadow DOM XSS was confirmed. The cheat sheet attribution could not be verified.
- No CVE for a specific web component library's shadow DOM XSS vulnerability was found in 2024-2026.


## Import Maps Poisoning for ES Module Hijacking

### Takeaway
Import maps can theoretically be poisoned to redirect ES module imports to attacker-controlled scripts, but no confirmed CVE or detailed exploit writeup was found for this technique in 2024-2026. The technique is described in community repositories without primary-source backing.

### Cited Findings
- A community GitHub repository lists "Import Maps Exploitation" as a 2025 attack vector with an example mapping a module specifier to a `data:` URL containing `alert(1)`. It also cites CVE-2025-0142, which could not be verified in NVD. -- [GitHub: Karthikdude/Advanced-XSS](https://github.com/Karthikdude/Advanced-XSS)
- A cheat sheet suggests loading critical code from "frozen modules" and pinning import order with import maps as a defensive mitigation. -- [Vulnsy XSS Cheat Sheet](https://www.vulnsy.com/cheat-sheets/xss)
- The official Declarative Shadow DOM repository raises the question of whether import maps interact with Shadow DOM content loading. -- [GitHub: mfreed7/declarative-shadow-dom](https://github.com/mfreed7/declarative-shadow-dom/blob/master/README.md)

### Inferences
- The attack model for import map poisoning requires the attacker to inject an `<script type="importmap">` element before the application's own import map is parsed. Browsers accept only the first import map, so the attacker must achieve HTML injection high enough in the document to place their import map before the legitimate one.
- If successful, all bare module specifiers (e.g., `import React from "react"`) would resolve to the attacker's URLs, effectively hijacking the entire module dependency tree.
- Content Security Policy's `script-src` directive should block `data:` and inline import maps if properly configured, but many applications include `unsafe-inline` or use nonces that might also cover the injected import map.

### Gaps
- CVE-2025-0142 cited by the Advanced-XSS repository could not be verified. It may be fabricated or misattributed.
- No browser security advisory or standards body discussion on import map injection as a security concern was found for 2024-2026.
- The interaction between CSP and injected import maps was not covered by any authoritative source found.


## View Transitions API and Speculation Rules API XSS Attack Surfaces

### Takeaway
No confirmed XSS vulnerability in the View Transitions API or Speculation Rules API was found as of mid-2026. The only tangentially related finding is CVE-2026-59727 in Astro, where View Transition directive values were not escaped. The Speculation Rules API has a theoretical CSRF-like risk from prerendering state-changing URLs, but this is not XSS.

### Cited Findings
- **Astro transition directive XSS (CVE-2026-59727):** The only confirmed vulnerability involving View Transitions is in Astro's framework-level implementation, not in the browser API itself. See the Astro section above for details. -- [OSV](https://osv.dev/vulnerability/CVE-2026-59727)
- **Speculation Rules CSRF risk:** One author notes that prerendering via Speculation Rules could trigger state-changing GET requests (add-to-cart, logout). The recommended mitigation is to use POST forms for state-changing actions. This is CSRF, not XSS. -- [adactio.com](https://adactio.com/journal/tag/standards?start=20)
- Cross-document View Transitions are enabled with a CSS `@view-transition` at-rule. Two normal HTML pages opt into a shared transition with a single CSS rule on each. -- [specification.website](https://specification.website/spec/performance/view-transitions.md)

### Inferences
- The View Transitions API operates on visual presentation (CSS animations between page states) and does not introduce new script execution contexts. Its XSS risk is limited to frameworks that fail to escape transition-related attributes they generate (as demonstrated by Astro).
- The Speculation Rules API's `<script type="speculationrules">` element accepts a JSON object, not executable JavaScript. However, if an attacker can inject a `speculationrules` script element, they could cause the browser to prefetch/prerender attacker-controlled URLs, which could be used for CSRF or to populate the browser cache with malicious content.
- Neither API introduces DOM manipulation sinks or new event handlers that would create novel XSS injection points.

### Gaps
- No Chromium security bug tracker entries or W3C security reviews for these APIs were found in the search results.
- The theoretical attack of injecting a `<script type="speculationrules">` to force prerendering of a malicious URL (which could set cookies, trigger CSRF, or cache poison) was not explored in any source found.


## WebSocket and Server-Sent Events XSS Vectors

### Takeaway
WebSocket and SSE channels are confirmed XSS vectors when applications render received messages as HTML without sanitization. A specific SSE injection vulnerability (CVE-2026-35515 in NestJS) demonstrates the risk of insufficient output encoding in server-side SSE implementations.

### Cited Findings
- **NestJS SSE injection (CVE-2026-35515):** In `@nestjs/core`, the `SseStream._transform()` method interpolates `message.type` and `message.id` directly into SSE text output without sanitizing `\r` or `\n` characters. All versions up to 11.1.17 are affected; fixed in 11.1.18. Injected data can lead to XSS if the client renders SSE data as HTML without sanitization. No public PoC or in-the-wild exploitation reported. -- [Wiz Vulnerability Database](https://www.wiz.io/vulnerability-database/cve/cve-2026-35515)
- **OWASP WebSocket guidance:** WebSocket messages can carry injection payloads including SQLi, XSS, and command injection. Recommended defenses include validating message structure and content using JSON schemas and allow-lists. -- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
- **Cross-site WebSocket hijacking (CSWSH):** Proper validation of the Origin header in the initial WebSocket handshake is essential. Without it, an attacker page can open a WebSocket to the target server and read messages intended for the victim. -- [RedFoxSec](https://redfoxsec.com/?p=5913)
- **Chat application XSS pattern:** A PortSwigger-style writeup describes a chat feature where an XSS payload sent over WebSocket executed in another user's browser because the server relayed messages without validation. -- [Sourcery.ai](https://sourcery.ai/vulnerabilities/websocket-security-vulnerabilities)
- **SSE CORS exfiltration:** A third-party source describes cross-origin streaming exfiltration when CORS headers are misconfigured on SSE endpoints, and notes that unsanitized SSE streams could deliver `<script>` payloads to LLM chat clients that render HTML. This source was flagged as critical by Snyk and should be treated with caution. -- [Tessl](https://tessl.io/registry/skills/github/PurpleAILAB/Decepticon/api-server-sent-events)

### Inferences
- The NestJS SSE injection is a server-side output encoding failure, not a browser-side flaw. The SSE protocol uses newline-delimited text fields (`data:`, `event:`, `id:`), and injecting `\n` characters allows an attacker to forge new SSE fields or events. If the client-side EventSource handler renders `event.data` as HTML (e.g., via `innerHTML`), this becomes XSS.
- WebSocket-based XSS is fundamentally a stored/reflected XSS variant where the transport channel is WebSocket instead of HTTP. The same sanitization principles apply: treat all received messages as untrusted input.
- The growing use of SSE for LLM streaming responses creates a new attack surface: if the LLM's response is rendered as HTML and the LLM can be prompt-injected to include script tags, the SSE channel becomes the XSS delivery mechanism.

### Gaps
- No research was found on WebSocket protocol-level attacks that bypass application-layer sanitization (e.g., fragmentation-based evasion).
- The interaction between SSE/WebSocket and Content Security Policy (e.g., whether CSP `connect-src` restrictions prevent CSWSH) was not covered in detail by any source found.


## Declarative Shadow DOM Template Injection for XSS

### Takeaway
Declarative Shadow DOM creates a sanitizer bypass vector that was identified during the W3C specification process. The browser-level mitigation (disabling declarative shadow DOM in fragment parsing) addresses the client-side sanitizer bypass, but server-side sanitizers that do not understand the `<template shadowrootmode>` syntax remain vulnerable.

### Cited Findings
- See the Shadow DOM section above for the core findings on sanitizer bypass via declarative shadow DOM.
- The W3C specification discussion explicitly asks "whether there are XSS concerns with being able to select and copy closed Shadow Root content." -- [GitHub: mfreed7/declarative-shadow-dom README](https://github.com/mfreed7/declarative-shadow-dom/blob/master/README.md)
- A Root-Me CTF writeup demonstrates a practical exploitation of declarative shadow DOM for XSS in a notes application, though the specific details were not fetched. -- [Root-Me Blog](https://blog.root-me.org/posts/writeup_ctf10k_perfect_notes/)

### Inferences
- Server-side HTML sanitizers (e.g., those used in SSR frameworks) that do not strip or neutralize `<template shadowrootmode="open|closed">` elements will pass through shadow DOM content that may contain event handlers or scripts.
- The attack pattern is: inject `<template shadowrootmode="closed"><slot onslotchange="alert(1)"></slot></template>` into user-controlled content. If the sanitizer does not understand this construct, it passes through intact, and the browser creates a shadow root with the XSS payload.

### Gaps
- The specific DOMPurify, sanitize-html, or other popular sanitizer library versions that are vulnerable to this bypass were not identified in the sources found.
- Whether major SSR frameworks (Next.js, Nuxt, SvelteKit) use server-side sanitization that is vulnerable to declarative shadow DOM injection was not established.
