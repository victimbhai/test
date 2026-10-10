# API WAF Bypass, Rate Limiting Evasion, and Novel API-Specific XSS Detection/Prevention

## API-Specific WAF Bypass Techniques for XSS (2024-2026)

### Takeaway
Content-type switching, multipart boundary manipulation, and parser differential attacks are the most effective API-specific WAF bypass vectors in 2024-2026, with the WAFFLED methodology (March 2025) confirming 1,207 bypasses across five major WAF vendors by exploiting how WAFs and backends parse the same HTTP request differently.

### Cited Findings
- The WAFFLED methodology (Northeastern/Dartmouth, March 2025) identified and confirmed 1,207 bypasses across 5 well-known WAFs: AWS WAF, Azure WAF, Google Cloud Armor, Cloudflare, and ModSecurity. The attack keeps the malicious payload intact and instead mutates parts of the request that a WAF and the backend framework parse differently. Targeted content types include application/json, multipart/form-data, and application/xml. Mutations include boundary delimiters in multipart/form-data, character sets in application/json, and namespace features in application/xml. — [WAFFLED Paper (arXiv 2503.10846)](https://arxiv.org/html/2503.10846v1); [Cryptika Coverage](https://www.cryptika.com/new-waffled-attack-exploits-aws-azure-cloud-armor-cloudflare-and-modsecurity-wafs/)
- A measurement study within the WAFFLED paper found more than 90% of websites accepted both application/x-www-form-urlencoded and multipart/form-data interchangeably, widening the attack surface for content-type switching. — [WAFFLED Paper (arXiv 2503.10846)](https://arxiv.org/html/2503.10846v1)
- The researchers released HTTP-Normalizer, a proxy tool designed to rigorously validate HTTP requests against current RFC standards, as a mitigation. All affected vendors acknowledged the vulnerabilities, and some paid bug bounties. — [Cryptika Coverage](https://www.cryptika.com/new-waffled-attack-exploits-aws-azure-cloud-armor-cloudflare-and-modsecurity-wafs/)
- Claroty Team82 demonstrated that prepending JSON syntax to SQL injection payloads left WAFs blind to the attacks, as most WAFs do not parse JSON within SQL contexts. While this research targeted SQLi, the parser-mismatch principle applies equally to XSS payloads embedded in JSON request bodies. — [{JS-ON: Security-OFF} Research](https://claroty.com/team82/research/js-on-security-off-abusing-json-based-sql-to-bypass-waf)
- Specific WAFFLED manipulation examples from secondary coverage include inserting a raw \x00 byte into a multipart boundary and swapping newline characters for horizontal tabs in header continuations. — [ThreatCluster Coverage](https://threatcluster.io/articles/3762)

### Inferences
- WAFs that do not fully parse JSON request bodies before applying signature matching are inherently vulnerable to XSS payloads embedded in JSON values, particularly when the backend framework does parse them.
- The 90%+ acceptance rate of multiple content types suggests that content-type switching attacks have a very wide attack surface in real-world deployments.
- GraphQL queries, which are typically sent as JSON POST bodies, inherit these same JSON-parsing bypass vulnerabilities.

### Gaps
- No source provided specific payload examples for JSON-body XSS bypass (as opposed to SQLi); the JSON-bypass research from Claroty focused on SQL injection.
- GraphQL-specific WAF bypass research for XSS was not found in 2025-2026 sources; vendor documentation (Fastly, F5) describes GraphQL inspection capabilities but no bypass analysis was available.


## Chunked Transfer Encoding XSS Bypass Techniques

### Takeaway
Chunked transfer encoding remains a viable WAF bypass vector, with a concrete 2026 CVE (CVE-2026-44982) in CrowdSec AppSec demonstrating that even modern WAFs can fail when switching from Content-Length to Transfer-Encoding: chunked, though most commercial WAFs now reassemble chunked bodies by default.

### Cited Findings
- CVE-2026-44982 (CrowdSec AppSec): Switching one header from Content-Length to Transfer-Encoding: chunked changed the response from 403 Forbidden to 200 OK. The cause was a body-handling bug in CrowdSec AppSec versions 1.5.0 through 1.7.7, fixed in v1.7.8. — [CVE-2026-44982 Advisory](https://mmartin.me/blog/crowdsec-appsec-bypass-cve-2026-44982)
- The core technique: WAFs that do not reassemble chunked bodies before inspection allow a keyword to be split across chunks so no single chunk contains the complete signature the WAF is matching against. — [WAF Evasion Techniques (isec.pl)](https://blog.isec.pl/waf-evasion-techniques/)
- Most commercial WAFs reassemble chunked bodies by default, though ModSecurity may need explicit configuration to do so. — [WAF Bypass Techniques 2026](https://www.decryptiondigest.com/blog/waf-bypass-techniques-detection-rule-tuning)
- A Cloudflare body-size-limit issue combined with chunked encoding was reported, where requests exceeding certain thresholds bypass inspection entirely. — [Cloudflare Payload Size Bypass](https://bblabs.es/en/academy/avanzado/cloudflare-payload-size-bypass)

### Inferences
- Chunk-splitting XSS payloads (e.g., splitting `<script>` across two chunks as `<scr` and `ipt>`) is a well-understood technique that works primarily against WAFs with incomplete chunked-body reassembly.
- The CrowdSec CVE shows that even in 2026, new WAF products can ship with chunked-encoding handling bugs.

### Gaps
- No detailed technical write-up of the CrowdSec CVE could be fetched (DNS resolution failed); the CVSS score and full PoC details are unconfirmed.
- No source quantified how many currently deployed WAFs still fail to reassemble chunked bodies.


## HTTP/2-Specific WAF Bypass Techniques

### Takeaway
HTTP/2 CONTINUATION frame abuse (CVE-2024-27316) is a DoS vector, not a WAF inspection bypass; the more relevant HTTP/2 WAF bypass vector is HTTP/2-to-HTTP/1.1 downgrade smuggling, where binary framing prevents WAFs from detecting smuggled requests that carry XSS payloads to the backend.

### Cited Findings
- CVE-2024-27316 (Apache HTTP Server, CVSS 7.5 High): Apache httpd's HTTP/2 implementation places insufficient limits on CONTINUATION frames within a single stream. An unauthenticated remote attacker can exhaust memory to cause DoS. Affects Apache HTTP Server 2.4.17 through 2.4.58. This is an availability-only impact, not a WAF bypass for injection attacks. — [CERT/CC VU#421644](https://www.kb.cert.org/vuls/id/421644); [SentinelOne CVE Database](https://www.sentinelone.com/vulnerability-database/cve-2024-27316/); [Red Hat Advisory](https://access.redhat.com/security/cve/cve-2024-27316)
- Related CONTINUATION frame CVEs affect nghttp2 (memory exhaustion from unbounded header buffering) and were patched in Nginx 1.27+, HAProxy 3.0+, and Envoy 1.30+. — [F5 DevCentral Analysis](https://community.f5.com/kb/technicalarticles/the-http2-continuation-frame-attack/329123)
- HTTP/2-to-HTTP/1.1 downgrade smuggling: Front-ends that convert HTTP/2 to HTTP/1.1 can reintroduce Content-Length/Transfer-Encoding ambiguity. One pentest walkthrough describes a front-end passing Transfer-Encoding through during downgrade, enabling request smuggling. — [Outpost24 Walkthrough](https://outpost24.com/blog/request-smuggling-http-2-downgrading/)
- A smuggled request carrying an XSS payload can be reflected in the response meant for the next user's request, achieving stored XSS through request poisoning. — [Sika Security WAF Evasion](https://sikasecurity.com/a-comprehensive-review-of-waf-evasion-and-obfuscation-techniques)
- Protocol-level attacks such as smuggling and HTTP/2 cleartext injection are not reliably caught by CRS at any paranoia level because they operate below the application layer. Most commercial WAFs have closed these vectors, but custom nginx/HAProxy WAF setups often have not. — [WAF Bypass Techniques 2026](https://www.decryptiondigest.com/blog/waf-bypass-techniques-detection-rule-tuning)
- HPACK compression can confuse WAF signature matching by representing header values in ways that differ from the wire-format patterns WAFs expect. The HTTP/2 binary framing means WAFs must fully decode HPACK before applying rules. — [HTTP/2 Security Hardening Guide](https://www.systemshardening.com/articles/network/http2-protocol-security/)

### Inferences
- The real HTTP/2 WAF bypass risk is not CONTINUATION frame abuse (which is DoS) but rather HPACK encoding differences and downgrade smuggling, where the WAF sees the HTTP/2 binary representation while the backend processes the downgraded HTTP/1.1 text.
- End-to-end HTTP/2 (no downgrade to HTTP/1.1) eliminates the smuggling vector but requires the WAF to fully decode HPACK.

### Gaps
- No specific CVE was found for HPACK-based WAF signature evasion leading to XSS; the technique is described in hardening guides but not in vulnerability advisories.
- PortSwigger's original H2 desync research (James Kettle, 2021) was not found in updated 2025-2026 form.


## Unicode Normalization Attacks Bypassing API XSS Filters

### Takeaway
NFKC/NFKD normalization differences between WAFs and backends are a well-documented bypass vector: fullwidth Unicode characters pass WAF inspection and are normalized to their ASCII equivalents by backend frameworks (Python, Java, Kubernetes), enabling XSS execution.

### Cited Findings
- The core technique: WAF inspects input before normalization; the application normalizes afterward using NFKC or NFKD, which decompose fullwidth and compatibility characters to their canonical ASCII equivalents. A blocked `<img>` payload rebuilt with fullwidth characters (`＜`, `＞`, `＂`, `＇`) passes the WAF filter. — [Jorge Lajara WAF Bypass](https://jlajara.gitlab.io/Bypass_WAF_Unicode)
- NFKC normalization is the most common form encountered in practice, used by Kubernetes, Python's `.casefold()`, and Java's `Normalizer`. NFC is a weaker bypass vector because it does not perform compatibility decomposition. — [Jorge Lajara WAF Bypass](https://jlajara.gitlab.io/Bypass_WAF_Unicode)
- Ally Petitt documented five WAF bypass techniques, including Unicode normalization. The approach works for XSS, SQLi, and template injection. — [5 Ways I Bypassed Your WAF](https://ally-petitt.com/en/posts/2023-06-01_5-ways-i-bypassed-your-web-application-firewall--waf--43852a43a1c2/)
- A practitioner attempted emoji steganography and Unicode-based WAF bypass but reported failure because the emoji was an illegal JavaScript token, and many pipelines normalize Unicode early, which collapses obfuscations before they reach the sink. — [Emoji Steganography and XSS](https://medium.com/@d.johnston_19172/emoji-steganography-and-xss-why-my-clever-waf-bypass-failed-84648f66faf1)
- Defensive recommendation: Normalize input using NFKC or NFC before any detection or validation, and use context-aware output escaping (HTML attribute, JS string, CSS, URL) rather than blocklists. — [LazyHackers WAF Bypass Guide](https://lazyhackers.in/article/waf-bypass-encoding-parameter-pollution-evasion)

### Inferences
- Unicode normalization bypasses are most effective against WAFs that operate on raw bytes without normalization, targeting backends that normalize for storage or display.
- The defense is straightforward: normalize before filtering. WAFs that apply NFKC normalization before signature matching close this vector.
- Homograph attacks in XSS context (using visually similar characters from different scripts) are theoretically possible but practically limited by JavaScript's strict identifier requirements.

### Gaps
- No 2025-2026 CVE was found specifically for Unicode normalization XSS bypass; the technique is well-known but not tracked as a specific vulnerability.


## Request Splitting and Smuggling for XSS Through API Security Layers

### Takeaway
HTTP request smuggling remains a viable XSS delivery mechanism in 2025-2026, particularly through HTTP/2-to-HTTP/1.1 downgrade paths and chunked-trailer injection, with new CVEs (CVE-2025-12642, CVE-2025-53628) demonstrating that parser discrepancies in lightweight HTTP libraries continue to emerge.

### Cited Findings
- HTTP/2-to-HTTP/1.1 downgrade smuggling enables XSS when a front-end converts HTTP/2 requests to HTTP/1.1, reintroducing Content-Length/Transfer-Encoding ambiguity. The smuggled request with an XSS payload is reflected in the next user's response. — [Outpost24 Walkthrough](https://outpost24.com/blog/request-smuggling-http-2-downgrading/)
- Chunked-trailer injection: Some intermediaries merge trailer fields into headers before a WAF inspects them. CVE-2025-12642 (lighttpd) and CVE-2025-53628 (cpp-httplib) are cited as 2025 examples of this class. — [Protocol-Level WAF Bypass Map](https://github.com/dmbs335/the-map/blob/main/03-http-protocol/http-parsing-discrepancy/protocol-level-waf-bypass.md)
- A 2025 practitioner article emphasizes distinguishing real desync vulnerabilities from HTTP request pipelining, noting that many claimed smuggling findings are actually pipelining behavior. — [SquidHacker Analysis](https://squidhacker.com/2025/11/http-request-smuggling-in-2025-how-to-distinguish-real-desync-vulnerabilities-from-http-request-pipelining-and-stop-wasting-everyones-time/)
- The hsmug tool (Go, open-source) detects HTTP/1.1, HTTP/2 downgrade, and HTTP/3 desync, and includes a reflected-XSS check. — [hsmug on GitHub](https://github.com/m1kro04/hsmug)
- Defensive recommendation: Reject requests that carry both Transfer-Encoding and Content-Length at the edge, and run HTTP/2 or HTTP/3 end-to-end where possible. — [Vaadata Smuggling Guide](https://www.vaadata.com/en/blog/what-is-http-request-smuggling-exploitations-and-security-best-practices/)

### Inferences
- Request smuggling for XSS is a second-order attack: the attacker poisons the TCP stream so a subsequent user's response includes the XSS payload. This makes it harder to detect with standard XSS scanners.
- End-to-end HTTP/2 or HTTP/3 eliminates the CL/TE ambiguity that makes most smuggling attacks possible.

### Gaps
- CVE-2025-12642 and CVE-2025-53628 are cited from a community-maintained GitHub list; their NVD entries were not independently verified.
- No source was found linking Emil Lerner's or Soroush Dalili's 2025 research to XSS-specific smuggling.


## Vendor-Specific WAF Bypass Findings (Cloudflare, AWS, Azure, ModSecurity CRS)

### Takeaway
All major WAF vendors have demonstrated bypass vulnerabilities in 2024-2026: Cloudflare through body-size limits, AWS WAF through 8KB body inspection limits and parameter pollution, Azure through parser discrepancies, and ModSecurity CRS through multiple CVEs affecting UTF-8 handling, multipart parsing, and comment-removal transformations.

### Cited Findings

#### Cloudflare
- MDSec (October 2024) found Cloudflare ignoring requests over 131,072 bytes (128 KiB) on a public-sector API. — [MDSec WAF Evasion](https://www.mdsec.co.uk/2024/10/when-wafs-go-awry-common-detection-evasion-techniques-for-web-application-firewalls/)
- Black Hills InfoSec found that for Cloudflare free accounts, requests with 8,216+ bytes prepended to a payload bypass the WAF. — [Black Hills Oversized Requests](https://www.blackhillsinfosec.com/bypassing-wafs-using-oversized-requests/)
- WAFFLED reported Cloudflare bypassed for multipart, JSON, and XML content types via parser discrepancies. — [WAFFLED Paper](https://arxiv.org/html/2503.10846v1)

#### AWS WAF
- AWS WAF inspects only the first 8 KB of the request body for Application Load Balancer and AppSync. Attackers pad requests with junk data to push XSS payloads outside this inspection window. — [MDSec WAF Evasion](https://www.mdsec.co.uk/2024/10/when-wafs-go-awry-common-detection-evasion-techniques-for-web-application-firewalls/)
- Bruno Mendes (August 2025) tested 17 WAF configurations; multiple AWS WAF rule sets (Managed Rules, Cyber Security Cloud rule set, F5 rule set) were completely bypassed by every parameter pollution payload tested. — [CyberSecurityNews](https://cybersecuritynews.com/wafs-protection-bypassed/); [Ethiack Blog](https://blog.ethiack.com/blog/bypassing-wafs-for-fun-and-js-injection-with-parameter-pollution)
- WAFFLED reported AWS WAF was the only tested WAF it did NOT bypass with multipart and JSON content-type techniques (contradicting the parameter pollution results, which used a different attack class). — [WAFFLED Paper](https://arxiv.org/html/2503.10846v1)

#### Azure WAF
- Azure WAF with Microsoft's Default Rule Set 2.1 was one of only 3 of 17 configurations that blocked all manually crafted parameter pollution payloads, though an automated hackbot still found a bypass using an escaped-quote parsing discrepancy. — [CyberSecurityNews](https://cybersecuritynews.com/wafs-protection-bypassed/)
- WAFFLED reported Azure WAF bypassed for multipart and JSON content types. — [WAFFLED Paper](https://arxiv.org/html/2503.10846v1)

#### ModSecurity CRS (2026 CVEs)
- CVE-2026-52761: ModSecurity 3.0.0-3.0.15 on i386 (32-bit): t:utf8toUnicode transformation produces incorrect output, allowing full-width UTF-8 XSS payloads to slip past rules. Fixed in 3.0.16. CVSS 5.3-5.8. — [Wiz CVE Database](https://www.wiz.io/vulnerability-database/cve/cve-2026-52761)
- CVE-2026-52747: ModSecurity before 3.0.16: multipart parser strips line breaks from form-field values before rules see them, so rules inspecting ARGS/ARGS_POST miss payloads depending on line breaks. — [SentinelOne CVE Database](https://www.sentinelone.com/vulnerability-database/cve-2026-52747/)
- CVE-2026-104259: ModSecurity v3 up to 3.0.16 and v2 up to 2.9.14: removeComments transformation bypass. Patched in 3.0.17 and 2.9.15. Status listed as "Reserved" in some sources. — [Wiz CVE Database](https://www.wiz.io/vulnerability-database/cve/cve-2026-104259)
- CVE-2026-21876 (CRS): Critical (CVSS 9.3) flaw in CRS rule 922110, which blocks UTF-7 and UTF-16 charsets in multipart requests. The rule only validates the last part of a multipart request, so earlier parts can carry malicious charsets. — [eSecurity Planet](https://www.esecurityplanet.com/threats/owasp-crs-flaw-lets-encoded-attacks-slip-past-wafs/); [CyberSecurityNews](https://cybersecuritynews.com/owasp-crs-vulnerability/amp/)
- ModSecurity versions 3.0.0 to 3.0.11 decoded URL-encoded characters before separating the URL path from the query string, enabling path-based injection bypasses. — [MDSec WAF Evasion](https://www.mdsec.co.uk/2024/10/when-wafs-go-awry-common-detection-evasion-techniques-for-web-application-firewalls/)

### Inferences
- Body-size limits are a systemic weakness: Cloudflare (128 KiB), AWS WAF (8 KB), and likely other vendors have hard inspection limits that can be trivially exploited by padding payloads.
- ModSecurity CRS has had a cluster of 2026 CVEs affecting core transformations (UTF-8, multipart, comments), suggesting that the transformation pipeline is a persistent weak point.
- Parameter pollution bypassed most AWS WAF configurations but not Azure's Default Rule Set, suggesting that parameter merging/deduplication behavior varies significantly by vendor.

### Gaps
- Current vendor patch status for each WAFFLED finding is unknown; the researchers reported acknowledgments but no specific rule-version fixes were cited.
- The user-specified CVE-2026-21876 was found only in secondary news coverage; the official CRS GitHub advisory was not located.


## Modern API-Level XSS Detection Tools and Techniques

### Takeaway
RASP (Runtime Application Self-Protection) provides in-application XSS detection with lower false-positive rates than WAFs by operating at the code-execution level, but Java and .NET have the most mature agent options while Go and Rust ecosystems lack RASP tooling; API-aware WAF rules from WAFFLED's HTTP-Normalizer represent a newer detection approach.

### Cited Findings
- RASP runs inside the application and detects/blocks attacks at the moment of execution, seeing actual code execution rather than request patterns. This produces fewer false positives and stronger zero-day coverage than WAFs. Typical overhead is 2-10% latency. — [Gocodeo RASP Guide](https://www.gocodeo.com/post/what-is-rasp-runtime-application-self-protection-for-web-apps)
- Java and .NET have the most RASP agent options; Go and Rust have almost no RASP options. OpenRASP (Baidu) is described as the only free option among commonly reviewed tools. — [AppSecSanta RASP Tools](https://appsecsanta.com/rasp-tools)
- The RASP market was valued at $2.02 billion in 2025, forecast to reach $7.17 billion by 2030 (Mordor Intelligence, as cited by secondary sources). — [Protectt.ai RASP Guide](https://protectt.ai/feeds/blog/rasp-tools)
- WAFFLED's HTTP-Normalizer is a proxy tool that validates HTTP requests against RFC standards before they reach the WAF or application, closing parser-discrepancy bypasses. — [WAFFLED Paper](https://arxiv.org/html/2503.10846v1)
- Fastly introduced GraphQL inspection for its Next-Gen WAF, blocking OWASP-style injection attacks targeting GraphQL APIs. — [Fastly GraphQL Inspection](https://www.fastly.com/fr/blog/introducing-graphql-inspection-for-the-fastly-next-gen-waf)
- F5 BIG-IP Advanced WAF provides GraphQL-aware protection including query depth limiting, introspection control, and injection detection within GraphQL operations. — [F5 GraphQL WAF](https://www.f5.com/pdf/solution-overview/f5-securing-graphql-apis-with-big-ip-advanced-waf-solution-overview.pdf)

### Inferences
- API-aware WAF rules require the WAF to parse the specific API format (JSON, GraphQL, multipart) before applying signatures, which is why format-agnostic signature matching fails against format-specific obfuscation.
- Taint tracking (following untrusted data from API input through processing to output) is the theoretically strongest XSS detection approach but is not widely implemented outside academic prototypes and some Java RASP agents.

### Gaps
- No source described taint-tracking internals for XSS detection in API frameworks; this would require checking OpenRASP documentation or academic papers directly.
- No source compared RASP XSS detection rates against WAF detection rates with quantitative data.
- Salt Security and Traceable AI (mentioned in the task as suggested sources) were not found in the search results with XSS-specific capabilities.


## API Security Testing Methodologies for XSS

### Takeaway
OWASP API Security Top 10 (2023) does not prominently feature XSS as a standalone API risk, focusing instead on authorization flaws (BOLA) and injection generically; compound testing (BOLA + XSS, authorization bypass + XSS) is described as a gap in current automated testing tools.

### Cited Findings
- BOLA (Broken Object Level Authorization) remains API1 in the OWASP API Security Top 10 and continues to dominate the API vulnerability landscape in 2026, at roughly 12.5% of API vulnerability reports. — [NordicAPIs](https://nordicapis.com/?p=23239); [AppSecure.Security](https://appsecure.security/blog/state-of-api-security-common-misconfigurations)
- Dynamic scanners without proper authentication context cannot test BOLA effectively, which is relevant to compound BOLA+XSS testing since the scanner needs authenticated multi-user sessions. — [Snyk BOLA Analysis](https://snyk.io/de/articles/bola-the-api-vulnerability-hiding-in-plain-sight/)
- Wallarm notes that signature-based WAFs look for patterns like quote characters and SQL comment markers, and that variable GraphQL response formats complicate parsing and may be used to hide attacks. — [Wallarm GraphQL Security](https://lab.wallarm.com/securing-graphql-api/)

### Inferences
- Compound vulnerabilities (BOLA+XSS, where an authorization bypass exposes an endpoint vulnerable to stored XSS) are likely underreported because automated tools test for each class independently.
- API-specific XSS testing requires schema-aware fuzzing that understands which fields accept HTML/rich text and which endpoints render user-supplied data.

### Gaps
- No source was found describing a specific BOLA+XSS compound testing methodology or tool.
- The OWASP API Testing Guide's specific coverage of XSS in API contexts was not located in search results.
- 42Crunch, Salt Security, and Traceable AI XSS-specific testing capabilities were not found.


## Novel Approaches for API XSS Prevention

### Takeaway
The modern API XSS prevention stack layers context-aware output encoding (primary defense), Content-Security-Policy with nonce + strict-dynamic (defense in depth), and Trusted Types (DOM sink protection), with Trusted Types now shipping in Chromium and Firefox and enforced via CSP directives.

### Cited Findings
- Context-aware output encoding at render time, per destination (HTML body, attribute, JS string, CSS, URL), is the primary defense. CSP and Trusted Types are backstops, not substitutes. — [Back4App XSS Prevention](https://www.back4app.com/glossary/cross-site-scripting-xss-prevention/); [MDN XSS Security](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/XSS)
- Trusted Types: Once the `require-trusted-types-for` CSP directive is set, assigning a plain string to sinks like `innerHTML` throws an exception, forcing callers to pass a policy-created object. A common pattern wraps DOMPurify inside a Trusted Types policy. Browser support is Chromium-first, with Firefox shipping. — [MDN CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP); [Andrew Lock Trusted Types Guide](https://andrewlock.net/preventing-client-side-cross-site-scripting-vulnerabilities-with-trusted-types/)
- CSP nonce + strict-dynamic is the recommended form; host allowlists are considered weaker. Teams are advised to start in Report-Only mode before enforcing. CSP nonce + strict-dynamic is not a substitute for encoding. — [DEV Community XSS Guide](https://dev.to/zahidabbasi/how-to-prevent-xss-attacks-output-encoding-csp-dompurify-2026-cheatsheet-5524)
- For APIs returning JSON, the relevant defense is correct Content-Type headers (application/json, not text/html) and encoding in the consuming frontend, not in the API response itself. — Inference from [MDN XSS Security](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/XSS)
- ASP.NET Core middleware example: The NetEscapades.AspNetCore.SecurityHeaders library emits Trusted Types and CSP directives as response headers. — [Andrew Lock Trusted Types Guide](https://andrewlock.net/preventing-client-side-cross-site-scripting-vulnerabilities-with-trusted-types/)
- DOMPurify is the recommended HTML sanitizer for user-generated content, often integrated with Trusted Types via a custom policy. — [SecureCoding XSS Defenses](https://www.securecoding.com/application-security/xss-defenses/)

### Inferences
- For API-driven SPAs, Trusted Types is the most impactful new defense because it prevents the frontend from unsafely rendering API response data into DOM sinks, regardless of whether the API response is sanitized.
- APIs should always return application/json (never text/html) and set X-Content-Type-Options: nosniff to prevent browsers from interpreting JSON responses as HTML.
- Output encoding middleware makes more sense at the rendering layer (frontend) than at the API layer, since the API cannot know the rendering context.

### Gaps
- No source described an API-specific output encoding middleware pattern (i.e., middleware that encodes API response fields before serialization).
- Trusted Types browser support matrix was not confirmed with exact version numbers from a primary source.


## API Fuzzing Tools and Techniques for XSS

### Takeaway
RESTler and Schemathesis are the leading API fuzzers but have no built-in XSS detection; XSS coverage comes from custom payload dictionaries. Schema-driven fuzzing (using OpenAPI specs) combined with OWASP ZAP active scanning provides the most practical API XSS testing approach.

### Cited Findings
- RESTler (Microsoft Research) uses stateful fuzzing to generate and execute test sequences, discovering producer-consumer dependencies between API requests. It infers that creating a user must precede authenticating one, enabling deep API coverage. — [Microsoft REST API Fuzz Testing](https://github.com/microsoft/rest-api-fuzz-testing)
- Schemathesis is a property-based testing tool built on OpenAPI or GraphQL schemas. Its mutation-based and negative-testing modes generate inputs that deliberately violate schema constraints. — [Schemathesis Documentation](https://schemathesis.readthedocs.io/)
- A comparative thesis found Schemathesis excels at finding semantic errors, while RESTler is better at finding server errors. A broader comparison ranked RestTestGen as the most effective tool, with RESTler as the most robust. — [Tokos Thesis (Doria)](https://www.doria.fi/bitstream/handle/10024/187395/tokos_alexander.pdf?sequence=2); [arXiv Open Problems in Fuzzing REST APIs](https://arxiv.org/pdf/2205.05325)
- Neither RESTler nor Schemathesis has built-in XSS detection. XSS coverage comes from dictionary-based approaches using known problematic inputs such as SQL injection and XSS payloads. — [Skills Marketplace API Fuzzer](https://github.com/jeremylongshore/tons-of-skills-marketplace/blob/main/plugins/testing/api-fuzzer/skills/fuzzing-apis/SKILL.md)
- Microsoft's RAFT (REST API Fuzz Testing) platform enables running multiple fuzzers in parallel against API targets, and OWASP ZAP active scanning is listed as a complementary option. — [Microsoft RAFT](https://github.com/microsoft/rest-api-fuzz-testing)

### Inferences
- Effective API XSS fuzzing requires combining a schema-aware fuzzer (RESTler or Schemathesis for endpoint discovery and state management) with an XSS-specific payload library and response analysis (checking if payloads are reflected unescaped).
- OpenAPI spec-driven testing can identify which fields accept string input and which endpoints return HTML content types, narrowing the XSS attack surface.

### Gaps
- No source described a tool that combines schema-aware API fuzzing with automated XSS detection (checking for unescaped reflection in responses).
- EvoMaster's XSS detection capabilities were not investigated.
- 42Crunch's API security testing platform was not found in search results with XSS-specific capabilities.


## Parameter Pollution WAF Bypass for XSS

### Takeaway
Parameter pollution (splitting XSS payloads across multiple HTTP parameters that the backend concatenates) bypassed 14 of 17 major WAF configurations tested in August 2025, making it one of the most effective current WAF bypass techniques for XSS.

### Cited Findings
- Bruno Mendes (Ethiack, August 2025) tested 17 different WAF configurations from major vendors. Only 3 of 17 blocked sophisticated parameter pollution attacks (AWS Managed + F5 Bot Management, Azure Default Rule Set 2.1, and one other). — [CyberSecurityNews](https://cybersecuritynews.com/wafs-protection-bypassed/); [Ethiack Blog](https://blog.ethiack.com/blog/bypassing-wafs-for-fun-and-js-injection-with-parameter-pollution)
- The underlying mechanism is that WAFs and backend frameworks parse duplicate parameters differently. ASP.NET concatenates duplicate parameters with commas, while the WAF inspects each parameter value individually. — [Ethiack Blog](https://blog.ethiack.com/blog/bypassing-wafs-for-fun-and-js-injection-with-parameter-pollution)
- The technique works because the WAF sees individual parameter values that look benign, but the backend concatenates them into a complete XSS payload. — [CyberSecurityNews](https://cybersecuritynews.com/wafs-protection-bypassed/)

### Inferences
- Parameter pollution is particularly dangerous for APIs because APIs often accept complex parameter structures (arrays, nested objects) that WAFs may not fully reconstruct before inspection.
- The 82% bypass rate (14/17 configurations) suggests this is a systemic WAF architecture issue, not a vendor-specific bug.

### Gaps
- Specific payload examples from the Ethiack research could not be fetched (DNS resolution failed).
- Whether the tested WAFs have since patched their parameter-handling behavior is unknown.
