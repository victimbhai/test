# XSS Escalation to RCE in Desktop/Hybrid Apps, postMessage Exploitation, and Advanced Techniques (2024-2026)

## How do Electron apps' XSS vulnerabilities escalate to RCE? What are the latest nodeIntegration, contextIsolation, and preload script bypass techniques?

### Takeaway
Electron XSS-to-RCE remains a live vulnerability class driven primarily by app-level misconfigurations (nodeIntegration enabled, contextIsolation disabled) rather than framework-level bypasses. Recent CVEs (2025-2026) confirm that real-world Electron apps still ship with insecure defaults, and contextBridge-based bypasses have emerged in Electron 39+ affecting Promise-returning functions.

### Cited Findings
- CVE-2025-56459 (OPCConnect desktop client): A stored XSS in a Tag field rendered as HTML in a privileged renderer. The writeup states the attacker could "execute arbitrary JavaScript in the renderer, then pivot to native code execution via Electron's shell.openExternal." — [CVE-2025-56459 Writeup](https://medium.com/@hackerjedi2812/cve-2025-56459-f814005f607a)
- CVE-2026-40322 (SiYuan note-taking app, CVSS 9.0): Stored XSS that escalates to code execution on Electron desktop builds because "windows use nodeIntegration enabled and contextIsolation disabled." Affects versions up to 3.6.3. — [SiYuan XSS to RCE](https://www.thehackerwire.com/siyuan-stored-xss-to-rce-cve-2026-40322/)
- Electron contextIsolation RCE via preload code: When contextIsolation is disabled, "a compromised renderer can overwrite objects in the preload context, including any functions or APIs the preload exposes, allowing escalation into main-process capabilities." A documented chain overrides `Array.prototype.indexOf` so a protocol allowlist check always passes, enabling `file://` links to launch programs. — [HackTricks - Electron contextIsolation RCE](https://github.com/TheSnowWight/hackdocs/blob/master/pentesting/pentesting-web/xss-to-rce-electron-desktop-apps/electron-contextisolation-rce-via-preload-code.md)
- CVE-2020-15215 was a historical context isolation bypass affecting apps using both contextIsolation and sandbox: true, fixed in Electron 11.0.0-beta.6. — [NVD CVE-2020-15215](https://nvd.nist.gov/vuln/detail/cve-2020-15215)
- A newer advisory (Electron 39-42 range) states that "apps that expose Promise-returning functions to web content via contextBridge may be vulnerable to a context isolation bypass." Fixed in versions 39.8.9, 40.9.2, 41.2.2, and 42.0.0-beta.5. — [ReleaseAlert CVE-2026-70601](https://releasealert.dev/cve/CVE-2026-70601)
- Electron v29.0.0 breaking change: "functions called over the contextBridge are now called with the expected receiver (this)." This fixed a potential `this`-binding abuse vector. — [Electron v29 Release Notes via search results]
- CVE-2023-23623: A CSP policy that disables eval is "not respected in renderers that have sandbox disabled." Affected Electron 22 and 23 major versions. — [Electron Security Advisories](https://vulnerabilities.etecs.ru/vendors/electronjs?lang=en)

### Inferences
- The Electron framework's defaults (nodeIntegration off, contextIsolation on since Electron 12) are secure. The ongoing vulnerability class exists because application developers explicitly opt out of these protections.
- The contextBridge Promise bypass (CVE-2026-70601) represents a new class: even with contextIsolation enabled, improperly exposed async APIs can leak the isolated context.
- shell.openExternal remains a reliable escalation primitive when accessible from a compromised renderer, as it can launch arbitrary executables.
- The shift from prototype pollution in the preload to contextBridge-specific bypasses reflects the framework maturing; attackers must find increasingly subtle misuses of the bridge API.

### Gaps
- No public research was found describing a full bypass of contextIsolation + sandbox enabled in Electron v28-v30 specifically. The framework-level bypasses found affect either older versions or the v39+ range.
- Detailed Electron v28-v30 security model change documentation was not accessible via search; the official Electron security tutorial and release notes would need direct review.
- No detailed proof-of-concept code for CVE-2026-40322 (SiYuan) was publicly available at time of research.


## What Tauri-specific XSS-to-RCE techniques exist (IPC command injection, allowlist bypasses)?

### Takeaway
Tauri v2 has seen three significant security advisories in 2024-2026: a CSP nonce bypass via data:/blob: schemes (CVE-2026-95626), an updater plugin IPC parameter injection (CVE-2026-95624), and an iframe-based IPC access control bypass (GHSA-57fm-592m-34r7). Third-party audits confirm that misconfigured Tauri apps with RCE features enabled can reach CVSS 9.0-10.0 severity from XSS.

### Cited Findings
- CVE-2026-95626 (CVSS 8.3, High): "Tauri's CSP nonce hardening doesn't protect against scripts loaded from `data:` or `blob:` sources." Per the CSP Level 3 specification, these scheme sources remain active even when a nonce is present. Affects >= 2.0.0 of the Tauri framework. — [OpenCVE CVE-2026-95626](https://app.opencve.io/cve/CVE-2026-95626); [Strix CVE-2026-95626](https://www.strix.ai/cve/CVE-2026-95626)
- CVE-2026-95624 (CVSS 6.8, Medium): The updater plugin's `check` IPC command "accepts an `allowDowngrades` flag from frontend JavaScript." Because the default permission set grants allow-check to the webview, XSS in the frontend can call it to bypass the updater's anti-rollback check. Affected range: >= 2.8.0, < 2.12.0 in tauri-plugin-updater. Fixed in updater-v2.12.0. — [Vulners CVE-2026-95624](https://vulners.com/osv/OSV:CVE-2026-95624); [Strix CVE-2026-95624](https://www.strix.ai/cve/CVE-2026-95624)
- GHSA-57fm-592m-34r7 (iframe IPC bypass): "Remote-origin iframes could reach Tauri IPC endpoints without being allowlisted in v2 capabilities." The patch stopped injecting the IPC script into iframes on macOS. — [Tauri Security Advisory](https://github.com/tauri-apps/tauri/security/advisories/GHSA-57fm-592m-34r7)
- Bloop/CrabNebula audit: "In the worst case it elevates the impact of cross-site-scripting vulnerabilities to critical (CVSS 9.0-10.0) if Remote Code Execution (RCE) features are enabled and improperly configured." — [CrabNebula Bloop Audit](https://reports.crabnebula.dev/reports/bloop/appendix/adversaries/input_control)

### Inferences
- Tauri v2's capability-based permission model is more granular than Electron's, but the CSP nonce bypass (CVE-2026-95626) shows that web platform quirks can undermine its protections.
- The updater IPC vulnerability demonstrates a recurring pattern: IPC commands that accept security-sensitive parameters from the frontend without additional authorization checks.
- The iframe IPC bypass is platform-specific (macOS), indicating that Tauri's multi-platform WebView strategy introduces per-platform attack surface variations.
- Unlike Electron, Tauri's Rust backend limits the blast radius of renderer compromise in theory, but in practice, overly permissive IPC allowlists can expose shell commands, file system access, and updater controls to a compromised webview.

### Gaps
- No public research was found describing a direct "IPC command injection" vulnerability in the classic sense (injecting into the command name or argument structure). The findings above involve parameter abuse and access control bypasses rather than injection.
- The exact affected version range for CVE-2026-95626 is inconsistent between sources (OpenCVE says no specific range, Strix says >= 2.0.0). The authoritative GitHub advisory should be checked.
- No proof-of-concept code was found for any of these Tauri vulnerabilities.


## How can Capacitor/Cordova hybrid mobile apps be compromised through XSS (plugin bridge exploitation)?

### Takeaway
A critical Capacitor vulnerability (CVE-2026-103922, CVSS 9.3-9.6) disclosed in October 2026 demonstrates that the internal HTTP proxy endpoint can be abused to serve attacker-controlled content under the app's trusted origin, granting access to all registered native plugins. Historically, Cordova's predictable BridgeSecret values and iframe-based bridge access have enabled similar escalation.

### Cited Findings
- CVE-2026-103922 (Capacitor, CVSS 9.3-9.6): "Its internal proxy endpoint can be abused to fetch an attacker-chosen URL, and the response is served under the app's own trusted origin." Impact: "malicious code could potentially access localStorage, cookies, and any privileged native capabilities provided through configured Capacitor plugins." Critically, "the internal proxy handler remained available even when the CapacitorHttp plugin was disabled." Affected: Capacitor 6.0.0-6.2.1, 7.0.0-7.6.8, and several 8.x releases. — [RankIteo Capacitor Vulnerability](https://blog.rankiteo.com/cap1790944040-capacitor-vulnerability-october-2026/); [GBHackers](https://gbhackers.com/capacitor-vulnerability/); [CyberSecurityNews](https://cybersecuritynews.com/critical-capacitor-flaw/)
- Why XSS is more dangerous in Capacitor/Cordova: "The same risk applies to any native app whose web view exposes a JavaScript bridge to native APIs." Capacitor 2.x "exposed all core plugins by default, which 3.x changed." — [Josh Morony Article](https://www.joshmorony.com/why-xss-attacks-are-more-dangerous-for-capacitor-cordova-apps/)
- CVE-2015-8320 (Cordova-Android): Predictable BridgeSecret values enabled bridge hijacking. — [CVE Details Cordova](https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-27153/Apache-Cordova.html)
- CVE-2014-1882 and CVE-2014-1881 (Cordova 3.3.0 and earlier): Bridge bypasses via crafted IFRAME script execution. — [CVE Details Cordova](https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-27153/Apache-Cordova.html)
- CVE-2020-6506 (Cordova Android WebView): iframe-based bypass. Mitigations include "a restrictive allow-list, a content security policy that avoids unsafe inline scripts, loading remote content in an external browser, and avoiding iframes in the main webview." — [Apache Cordova Advisory](https://cordova.apache.org/news/2020/09/29/cve-2020-6506.html)

### Inferences
- The CVE-2026-103922 pattern (internal proxy serving attacker content under the app origin) is particularly dangerous because it bypasses same-origin protections entirely, making any registered plugin accessible to the attacker.
- The Capacitor evolution from 2.x (all plugins exposed) to 3.x+ (explicit registration) reduced default exposure, but the proxy vulnerability shows that infrastructure-level bypasses can negate plugin-level access controls.
- The historical Cordova BridgeSecret predictability shows a long-running pattern of bridge security being an afterthought in hybrid frameworks.

### Gaps
- No detailed proof-of-concept code was found for CVE-2026-103922. The disclosure is very recent (October 2026).
- No research was found on Capacitor-specific plugin bridge exploitation beyond the proxy vulnerability (e.g., exploiting individual plugin APIs after gaining bridge access).


## What complex postMessage exploitation chains have been discovered (origin validation bypasses, message handler gadgets)?

### Takeaway
Microsoft's MSRC published a detailed analysis (August 2025) of postMessage exploitation in Microsoft Teams (CVE-2024-49038, CVSS 9.3), demonstrating a zero-click XSS chain via wildcard origin targets, dangling domain hijacking, and the `isFullTrust` manifest setting. Broader research documents origin validation bypasses via indexOf(), regex coercion, and synchronous gadget-based race attacks for stealing secrets from cross-origin postMessage exchanges.

### Cited Findings
- CVE-2024-49038 (Microsoft Teams/Copilot Studio, CVSS 9.3): The attack chain relied on two manifest settings: "isFullTrust: true, which allows communication with the main Teams window and token access" and "an overly broad validDomains list." A payload hosted under a *.microsoft.com domain could "trigger the host window to return a token." The attack "produced an XSS alert with no user interaction and worked across tenants." — [Microsoft MSRC Blog](https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised)
- Wildcard target origin: Sending sensitive data with `postMessage(message, '*')` lets any embedded frame receive it. In the Bing Travel case, an auth token was sent this way. — [Microsoft MSRC Blog](https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised)
- Dangling domain hijacking: "Abandoned domains still listed in a Teams manifest's validDomains can be re-registered and used to intercept or inject messages." — [Microsoft MSRC Blog](https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised)
- Origin check bypass via indexOf(): "The use of indexOf() for origin validation in PostMessage events may be susceptible to bypassing." E.g., checking `event.origin.indexOf('example.com')` matches `evil-example.com`. — [HackTricks PostMessage Vulnerabilities](https://hacktricks.wiki/en/pentesting-web/postmessage-vulnerabilities/index.html)
- Regex coercion bypass: "Passing anything other than a regexp leads to implicit conversion to regex, making the method potentially insecure." — [HackTricks PostMessage Vulnerabilities](https://hacktricks.wiki/en/pentesting-web/postmessage-vulnerabilities/index.html)
- Synchronous gadget race attacks: A "Postviewer v5" technique where "when the target page was not frameable, the race was still winnable from a popup." The attacker stalls the parent's event loop with a synchronous gadget to install a listener and capture secrets. — [HackTricks Blocking Main Page](https://hacktricks.wiki/en/pentesting-web/postmessage-vulnerabilities/blocking-main-page-to-steal-postmessage.html)
- isTrusted property: Browsers guarantee the origin of MessageEvents sent via postMessage will be the sending window's origin, but the weaknesses lie in how sites validate them. The `isTrusted` property should be checked. — [TEKNKL Blog](https://blog.teknkl.com/you-should-probably-be-checking-istrusted-in-messageevent-listeners/)
- CodeQL detection patterns: Flag `postMessage` calls whose second argument is `"*"` and flag `message` event handlers that never test `event.origin`. — [Microsoft MSRC Blog](https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised)
- PortSwigger nominated a write-up on chaining DOM clobbering with postMessage and CSP bypasses for its 2024 top web hacking techniques. A javascript: URL sent via postMessage was used to exploit XSS on Bing. — [PortSwigger Top 10 2024](https://portswigger.net/research/top-10-web-hacking-techniques-of-2024-nominations-open)

### Inferences
- The Microsoft Teams chain demonstrates that postMessage exploitation is most dangerous in environments with broad trust models (wildcard validDomains, isFullTrust manifests), where a single compromised or abandoned subdomain can serve as the entry point.
- The synchronous gadget race attack pattern represents an evolution beyond simple origin bypass -- it exploits JavaScript's single-threaded event loop to win race conditions against legitimate message handlers.
- Origin validation flaws (indexOf, regex coercion) remain prevalent because developers treat origin checking as a simple string comparison rather than a security-critical parsing operation.

### Gaps
- Full proof-of-concept code for the Teams CVE-2024-49038 chain was not published by Microsoft.
- Masato Kinugawa's specific postMessage research was not surfaced in search results; his work may be behind conference paywalls or in Japanese-language publications.
- The "Postviewer v5" gadget technique details were not fully accessible (HackTricks domain did not resolve for deep fetch).


## How can XSS install malicious Service Workers for persistent browser compromise?

### Takeaway
XSS can be escalated to persistent browser compromise by registering a malicious Service Worker, which continues intercepting and modifying all requests to the origin even after the original XSS is patched. The attack requires either hosting a script file on the same origin (via file upload) or poisoning the Cache Storage API. The worker persists "until a new worker is provided or the site's data is manually cleared."

### Cited Findings
- Service Worker persistence mechanism: A SW-XSS study describes "a worker that keeps running in the background for a long time" where "the attacker can use it to watch the victim or alter pages. Its lifetime lasts until a new worker is provided or the site's data is manually cleared." — [ACM Security Study of Service Worker XSS](https://dl.acm.org/doi/fullHtml/10.1145/3427228.3427290)
- Same-origin registration constraint: "Browsers only accept same-origin worker scripts, so a XSS vulnerability is not sufficient to install a malicious service worker, unless the attacker can host one on the same origin." Attackers bypass this by pairing XSS with a file-upload feature on the same domain. — [Akamai Blog](https://www.akamai.com/blog/security/abusing-the-service-workers-api); [NVISO Blog](https://blog.nviso.eu/2020/01/16/deep-dive-into-the-security-of-progressive-web-apps/)
- Cache Storage poisoning: "The CacheStorage API can be used from the page context to inject a script into the cached copy of index.html." This leads to a scenario where "one transient same-origin XSS leads to code running in later sessions, even after the original bug is patched." — [XenForo AI Chatpage Issue #9](https://github.com/faratech/xenforo-ai-chatpage/issues/9); [SW Cache Attack Research](https://swcacheattack.secpriv.wien/)
- postMessage abuse via Service Workers: A 2023 paper found that "an XSS attacker can exploit postMessage to send a crafted message that abuses the push service in the service worker." — [ACM Honey PostMessage Paper](https://dl.acm.org/doi/fullHtml/10.1145/3579856.3590342)
- Broader attack catalog: A 2021 systematization of service worker attacks covers "botnets, cryptomining, and persistent XSS" and notes that "several open SW security problems are currently unmitigated." — [ArXiv Service Worker Attack Categorization](https://arxiv.org/pdf/2111.07153)
- PWA permission abuse: A 2025 arXiv paper demystifies PWA permission systems and their potential for abuse. — [ArXiv PWA Permissions](https://arxiv.org/pdf/2509.13563)

### Inferences
- The Service Worker persistence technique transforms a one-time XSS into a persistent foothold equivalent to a backdoor: the attacker controls all network traffic to the origin for that user until the worker is explicitly unregistered.
- The Cache Storage poisoning variant is especially dangerous because it does not require file upload -- any XSS that can write to Cache Storage can achieve persistence.
- Push notification abuse via compromised Service Workers adds a social engineering dimension (phishing push notifications from a "trusted" origin).

### Gaps
- No 2024-2026 specific CVEs were found for Service Worker-based persistence attacks. The research is primarily academic (2020-2023).
- Specific PWA manifest.json injection techniques and app install prompt hijacking were not found in search results as distinct attack classes with published research.
- Push notification phishing via compromised PWA Service Workers is mentioned in the literature but no specific real-world case studies with CVEs were found.


## How does AI/LLM output rendered unsanitized in web apps create XSS (prompt injection to XSS pipeline)?

### Takeaway
OWASP classifies LLM output rendered without sanitization as "Improper Output Handling" (LLM05:2025), listing XSS, CSRF, SSRF, and RCE as consequences. The attack pipeline works by using prompt injection (direct or indirect) to make the model generate HTML/JavaScript payloads that are then rendered in the victim's browser. A real-world case in DeepSeek demonstrated Base64-encoded payload delivery through the model.

### Cited Findings
- OWASP LLM05:2025 (Improper Output Handling): Lists "XSS and CSRF among the outcomes, alongside SSRF and remote code execution on backends." Prevention guidance includes "strict Content Security Policies to limit XSS from LLM-generated content." — [OWASP LLM05:2025](https://genai.owasp.org/llmrisk/llm05-supply-chain-vulnerabilities/)
- OWASP LLM02:2023-24 (Insecure Output Handling): Describes "a chatbot-style web app that renders an attacker-crafted JavaScript payload in a victim's browser." — [OWASP LLM02](https://genai.owasp.org/llmrisk2023-24/llm02-insecure-output-handling/)
- DeepSeek real-world case: "The attacker hid the XSS payload in Base64 and instructed the model to decode it and return only the result. The payload was then reflected in the chat interface." — [ArXiv Paper 2608.10281](https://arxiv.org/pdf/2608.10281)
- Indirect prompt injection as XSS vector: PortSwigger documents a pattern where "indirect prompt injection in live chat is used to trigger XSS" and notes that "indirect prompt injection often enables these attacks against other users." — [PortSwigger LLM Attacks Lab](https://portswigger.net/web-security/llm-attacks/lab-exploiting-insecure-output-handling-in-llms); [PortSwigger Web LLM Attacks](https://portswigger.net/web-security/llm-attacks)
- Academic framework: A 2026 arXiv preprint states "the underlying flaw is still unsafe rendering of untrusted content, but the attacker can use prompt injection to have the model generate the HTML or JavaScript payload." — [ArXiv 2608.10281](https://arxiv.org/pdf/2608.10281)
- Auth0/OWASP analysis: "Trusting AI Output? Why Improper Output Handling is the New XSS" frames LLM output as fundamentally untrusted input. — [Auth0 Blog](https://auth0.com/blog/owasp-llm05-improper-output-handling/)

### Inferences
- The prompt-injection-to-XSS pipeline is not a new vulnerability class but a new injection vector for the same old rendering flaw. The model acts as an intermediary that transforms attacker instructions into payloads.
- The DeepSeek Base64 technique shows that payload obfuscation through the model itself is an effective evasion: the model decodes the payload, which bypasses any input-side filtering that looks for script tags or JavaScript patterns.
- Indirect prompt injection is particularly dangerous because the attacker does not need to interact with the victim directly -- poisoned data (emails, documents, web pages) processed by the LLM can inject payloads into other users' sessions.
- Applications that render LLM output as Markdown-to-HTML are at highest risk, because Markdown naturally supports inline HTML and script injection.

### Gaps
- No comprehensive list of 2024-2026 CVEs specifically for LLM-output-XSS was found. The vulnerability class is documented primarily in OWASP guidance and academic papers rather than CVE databases.
- Specific proof-of-concept code for the DeepSeek case was not accessible (the arXiv paper could not be fetched).
- No research was found on AI-specific CSP bypass techniques (e.g., whether LLMs can be prompted to generate payloads that evade specific CSP rules).


## What advanced post-exploitation techniques exist after achieving XSS (credential harvesting, session riding, internal network scanning)?

### Takeaway
Post-exploitation via XSS encompasses credential harvesting through DOM manipulation (login form hijacking, fake OAuth prompts), session riding (using stolen cookies or ambient auth to make authenticated requests), internal network scanning via JavaScript (WebRTC IP disclosure, port scanning via timing side channels), and browser exploitation frameworks like BeEF that automate these capabilities.

### Cited Findings
- Credential harvesting via form hijacking: "An injected script hijacks an existing login form so the user submits information that is captured and then forwarded to the original site without the user noticing." — [Hacking Articles XSS Exploitation](https://hackingarticles.in/cross-site-scripting-exploitation/)
- BeEF (Browser Exploitation Framework): Supports "phishing, credential theft, and internal network mapping" from a compromised browser. — [HackerDNA XSS Course](https://hackerdna.com/courses/web-attacks/xss)
- Session riding: XSS escalation into CSRF-style attacks, including "bypassing CSRF protections" by reading tokens from the DOM. — [Exploit-DB Paper](https://www.exploit-db.com/download/24559)
- Internal network scanning: JavaScript-based port scanning and network discovery from the browser. WebRTC's ICE candidate gathering exposes local IP addresses. — [Palo Alto Cyberpedia](https://www.paloaltonetworks.com/cyberpedia/xss-cross-site-scripting)
- XSS Agent: A CoreSecurity project for browser-based post-exploitation, enabling "persistent control of the victim's browser." — [CoreSecurity XSS Agent](https://www.coresecurity.com/corelabs-research/projects/xss-agent)

### Inferences
- XSS post-exploitation in 2024-2026 benefits from richer browser APIs: fetch() for authenticated requests, WebRTC for network reconnaissance, WebSockets for persistent C2 channels, and the Clipboard API for credential exfiltration.
- The combination of Service Worker persistence (covered above) with post-exploitation techniques creates a persistent attack platform within the browser that survives page reloads and tab closures.
- HttpOnly cookies limit direct session theft, pushing attackers toward session riding (making requests while the session is active) rather than cookie exfiltration.

### Gaps
- No 2024-2026 specific research papers on advanced browser-based internal network scanning techniques were found. Most sources describe established techniques.
- Detailed post-exploitation chains using modern browser APIs (WebTransport, WebCodecs) were not found in search results.


## How do WebRTC, WebTransport, and WebCodecs APIs create new exploitation opportunities via XSS?

### Takeaway
WebRTC creates exploitation opportunities primarily through IP address disclosure (bypassing VPNs/proxies to reveal local network topology) and through XSS in peer-to-peer signaling/messaging channels that bypass server-side sanitization. CVE-2023-7024 demonstrated that WebRTC implementation bugs can lead to heap corruption exploitable from web content. No specific WebTransport or WebCodecs exploitation research via XSS was found.

### Cited Findings
- WebRTC peer-to-peer XSS: "Classical XSS attacks are mostly mitigated by input validation at the server side, but WebRTC applications let users share information directly without a server as a mediator." An attacker can embed malicious code in "a text message, display name, or attachment file name sent peer to peer." — [ArXiv WebRTC Security Paper](https://arxiv.org/pdf/1601.00184)
- Signaling channel injection: Compromising a signaling server allows pushing malicious payloads into signaling messages, producing XSS on the receiving end. — [Medium Land2Cyber](https://medium.com/@Land2Cyber/exploring-the-use-of-xss-in-newer-technologies-such-as-websockets-and-webrtc-649f72bbb160)
- CVE-2023-7024 (Chrome WebRTC, exploited in the wild): "A heap buffer overflow in WebRTC in Chrome before 120.0.6099.129, which allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page." Added to CISA's Known Exploited Vulnerabilities catalog in January 2024. — [Morphisec Threat Bulletin](https://www.morphisec.com/blog/threat-bulletin-cve-2023-7024/)
- WebRTC IP leakage: "WebRTC exposes local IP addresses to any page's JavaScript," enabling network reconnaissance and VPN detection. — [DZone WebRTC Vulnerabilities](https://dzone.com/articles/webrtc-security-vulnerabilities-you-should-know-ab)

### Inferences
- WebRTC's peer-to-peer nature fundamentally changes the XSS threat model: input validation cannot be centralized on a server, making client-side sanitization the sole defense.
- The IP leakage issue is well-documented but remains relevant for post-exploitation reconnaissance (mapping internal network topology after XSS).
- WebTransport and WebCodecs are newer APIs that may have undiscovered XSS-adjacent vulnerabilities, but no published security research was found focusing on their exploitation via XSS.

### Gaps
- No specific WebTransport exploitation research was found. WebTransport is relatively new and may not have attracted dedicated security research yet.
- No WebCodecs exploitation via XSS research was found. WebCodecs security concerns likely center on memory safety in codec implementations (similar to CVE-2023-7024 for WebRTC) rather than XSS-specific vectors.
- The WebRTC academic paper is from 2016; more recent WebRTC XSS research may exist but was not surfaced.


## What browser extension exploitation techniques leverage XSS in web apps?

### Takeaway
Browser extensions create a privileged escalation target for web-page XSS: content scripts that listen for messages from web pages without proper origin validation can be exploited to access extension-level APIs (storage, tabs, cookies, native messaging). Recent cases include the Claude Chrome extension zero-click XSS (2026) and the DeepL extension XSS (CVE-2026-40451), both involving content script message handling flaws.

### Cited Findings
- Claude Chrome extension zero-click XSS (2026): The extension could be "abused via XSS and a weak allowlist to inject prompts from any site." Anthropic patched it in version 1.0.41, "enforcing a strict origin check requiring an exact match to the domain claude.ai." The underlying XSS was in Arkose Labs' component. — [The Hacker News](https://thehackernews.com/2026/03/claude-extension-flaw-enabled-zero.html)
- DeepL Chrome extension (CVE-2026-40451): "An XSS vulnerability was introduced in version v1.22.0 because user input was not properly neutralized before page generation." Incomplete fixes shipped in v1.22.2 and v1.23.0; v1.24.0 is the fully patched release. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-40451/); [GitHub Advisory](https://github.com/DeepLcom/deepl-chrome-extension/security/advisories/GHSA-4x2r-q3p9-xhx4)
- Automa extension (FP-2023-004): The content script's message protocol "routed messages of type 'automa:execute-block' to a handler that ran custom JavaScript." An attacker could inject JavaScript into pages via this message handler from a crafted page in an iframe. — [Flashpoint Research](https://flashpoint.io/resources/research/vulnerability-automa-extension-chrome/)
- Extension escalation model: "An XSS in the context of the content script allows the attacker to compromise the user on that specific website." The extension messaging API can be used "to escalate from a content script to the background page, and from there gain access to extension-level APIs." — [GitHub Blog](https://github.blog/security/vulnerability-research/attacking-browser-extensions/)
- Debugger API abuse: Extensions with the `debugger` permission can "use the Chrome DevTools Protocol to read/write all data, execute arbitrary code, and interact with the filesystem." — [ArXiv Chrowned Paper](https://arxiv.org/pdf/2305.11506)
- Manifest V3 CSP: "The unsafe-inline directive is not allowed in the extension on Manifest V2 and V3." — [GitHub Blog](https://github.blog/security/vulnerability-research/attacking-browser-extensions/)

### Inferences
- The web-page-to-extension escalation path is particularly dangerous because extensions often have permissions far exceeding what the web page itself can access (cookies across domains, native messaging, filesystem via debugger API).
- The Claude and Automa cases demonstrate a common anti-pattern: extensions that accept execution commands from web page content scripts without strict origin validation.
- Manifest V3's restrictions (no remote code loading, stricter CSP) reduce some attack surface but do not eliminate content-script-to-background-page escalation when the extension's own message handlers are flawed.
- AI/LLM-related extensions are an emerging high-value target because they often bridge between web content and AI backends, creating prompt injection and XSS pathways.

### Gaps
- The full details of the Claude extension exploitation chain were not accessible (thehackernews.com did not resolve for fetch).
- No systematic 2024-2025 survey of content script messaging vulnerabilities across popular Chrome extensions was found.
- The 2025 arXiv malicious extension study was surfaced but its full findings could not be retrieved.
