# Emerging and Cutting-Edge API Security Threats (2023-2026)

## GraphQL Advanced Attacks (Beyond Basic Introspection)

### APQ Hash Exploitation Techniques

#### Takeaway
Automatic Persisted Queries (APQ) are a performance optimization, not a security control. When APQ registration is left open alongside a query allowlist, an attacker can register arbitrary queries by supplying their own hash-to-query mappings, effectively bypassing the allowlist and any introspection restrictions.

#### Cited Findings
- APQ does not provide any security features; the benefit of using them is to reduce network overhead. The security feature is trusted persisted queries, where a registered list acts as an operation safelist made by first-party apps. -- [Apollo GraphQL Docs](https://www.apollographql.com/docs/graphos/platform/security/persisted-queries)
- The client generates the SHA-256 hash, so the attacker fully controls the namespace mapping hash to query. The attack flow: (1) attacker sends a hash for a malicious query, (2) server responds "not found," (3) attacker resends the hash with the full query body, (4) server executes and caches the query, (5) all subsequent requests use only the hash. The server's APQ cache becomes an attacker-controlled allowlist. -- [DEV Community: GraphQL APQ Registration Bypasses](https://dev.to/rxkov/graphql-apq-registration-bypasses-query-allowlists-and-introspection-controls-20p2)
- Enabling both APQ registration and a persisted query allowlist simultaneously undermines the safelist, since APQ registration allows new entries to be added at runtime. -- [DEV Community: GraphQL APQ Registration Bypasses](https://dev.to/rxkov/graphql-apq-registration-bypasses-query-allowlists-and-introspection-controls-20p2)
- A potential DDoS vector: an attacker could spam the GraphQL API with persisted operation registrations, exhausting cache resources and degrading APQ benefits. -- [The Guild: Yoga Server APQ Docs](https://the-guild.dev/graphql/yoga-server/docs/features/automatic-persisted-queries)
- Apollo Router CVE-2025-32032: recursive fragments could exhaust thread pools during query planning, bypassing per-operation guardrails. -- [StingRAI: GraphQL API Vulnerabilities 2026](https://www.stingrai.io/blog/graphql-api-vulnerabilities-and-common-attacks)
- If test and production environments share the same persisted query list (PQL) backing store, a tester might poison the production PQL. -- [BreachVex: Pentesting GraphQL APIs 2026](https://breachvex.com/blog/pentesting-graphql-2026)

#### Inferences
- Organizations that deploy APQ for performance without disabling open registration are unknowingly creating a bypass around any query allowlist they also maintain.
- The attack requires no authentication beyond what is needed to send GraphQL requests, making it accessible to any external attacker.

#### Gaps
- No publicly disclosed CVE specifically for APQ hash exploitation as a standalone vulnerability was found; the technique is documented in blog posts but not in NVD entries.

---

### GraphQL Subscription Authorization Bypass Over WebSocket

#### Takeaway
GraphQL subscription endpoints using WebSocket transports frequently bypass HTTP-layer authentication and authorization controls. Multiple 2025-2026 CVEs confirm that subscription handlers accept connections or messages without verifying tokens, skipping middleware that protects query and mutation operations.

#### Cited Findings
- Neo4j `@neo4j/graphql` (GHSA-fcpg-3fw5-vc65, CVE-2026-5423, CVSS 8.2): The subscriptions transport accepts `connectionParams.jwt` without verifying the signature. An unauthenticated client can forge claims such as roles, which are then trusted by the `@authentication` and `@subscriptionsAuthorization` directives. Affects v5.0.0-5.12.13 and v7.0.0-7.5.5. -- [GitHub Advisory GHSA-fcpg-3fw5-vc65](https://github.com/neo4j/graphql/security/advisories/GHSA-fcpg-3fw5-vc65)
- Strawberry GraphQL (GHSA-vpwc-v33q-mq89): The legacy `graphql-ws` subprotocol handler accepts subscription messages without completing `connection_init`, skipping the `on_ws_connect` authentication hook. Versions up to 0.312.3 are affected. Fix: upgrade or restrict `subscription_protocols` to `graphql-transport-ws`. -- [GitHub Advisory GHSA-vpwc-v33q-mq89](https://github.com/strawberry-graphql/strawberry/security/advisories/GHSA-vpwc-v33q-mq89)
- Parse Server (CVE-2026-32594, per secondary source): The WebSocket subscriptions endpoint bypasses the Express middleware that enforces authentication, introspection, and complexity limits. -- [StingRAI: GraphQL API Vulnerabilities 2026](https://www.stingrai.io/blog/graphql-api-vulnerabilities-and-common-attacks) (could not confirm CVE from primary source)
- monster-mq issue #176: The WebSocket GraphQL handler sits outside HTTP auth, so live subscriptions can receive MQTT topic data without ACL checks. -- [GitHub Issue #176](https://github.com/vogler75/monster-mq/issues/176)
- OWASP's GraphQL Cheat Sheet recommends re-checking authorization at message dispatch time for sensitive subscriptions. -- [chs.us GraphQL Security Guide](https://chs.us/guides/graphql/)

#### Inferences
- The root cause is architectural: WebSocket connections are established through a protocol upgrade that often bypasses HTTP middleware stacks (Express, Django, ASP.NET middleware). Authorization checks applied at the HTTP layer are invisible to the WebSocket handler.
- Subscription-specific authorization must be implemented at the resolver or message dispatch level, not relied upon at the transport layer.

#### Gaps
- No comprehensive survey of which GraphQL frameworks correctly enforce subscription-level authorization was found.
- "Directive injection" as a distinct attack category (injecting custom directives into GraphQL operations to alter server behavior) did not appear in search results. The closest related finding was the Neo4j advisory where built-in authorization directives were bypassed via forged JWTs, not via directive injection into queries.

---

### GraphQL Directive Injection and Federated Authorization Bypass

#### Takeaway
No well-documented, specific attack technique called "GraphQL directive injection" was found in the 2023-2026 literature. However, field-level authorization failures in federated GraphQL architectures are a known concern, and the Neo4j advisory above demonstrates that authorization directives can be circumvented at the transport layer.

#### Cited Findings
- In federated GraphQL, each subgraph enforces its own authorization. A pentesting guide notes that testers should check whether the gateway passes authorization context correctly to each subgraph, and whether a direct request to a subgraph bypasses the gateway's auth. -- [AFINE: GraphQL Security from a Pentester's Perspective](https://afine.com/graphql-security-from-a-pentesters-perspective)
- A 2026 vulnerability roundup lists field-level authorization issues where certain fields or nested types are accessible without proper checks when queried through specific paths or aliases. -- [StingRAI: GraphQL API Vulnerabilities 2026](https://www.stingrai.io/blog/graphql-api-vulnerabilities-and-common-attacks)

#### Inferences
- The phrase "directive injection" may refer to an emerging or niche technique not yet widely documented, or it may be conflated with directive bypass (as in the Neo4j case).
- In federated architectures, the attack surface expands because each subgraph may have independent authorization logic, and the composition layer may not enforce a unified policy.

#### Gaps
- No primary source describing a "directive injection" attack (injecting `@skip`, `@include`, or custom directives to bypass authorization) was found. This may be an area where the attack is theoretically possible but not yet publicly documented with a CVE or writeup.

---

## API Caching Attacks

### Web Cache Deception Against API Endpoints

#### Takeaway
Web cache deception exploits mismatches between how a CDN/cache interprets a URL path and how the origin server routes it. When a CDN treats a path like `/api/user/profile/image.css` as a static cacheable resource while the origin serves the authenticated `/api/user/profile` response, the attacker can trick the cache into storing private API responses and then retrieve them unauthenticated.

#### Cited Findings
- The foundational technique was presented by Omer Gil at Black Hat 2017: an attacker appends a static-looking extension (e.g., `.css`, `.js`, `.png`) to a dynamic URL. The cache stores the response keyed to the URL with the static extension, and subsequent unauthenticated requests receive the cached private data. -- [Black Hat 2017 Whitepaper](https://blackhat.com/docs/us-17/wednesday/us-17-Gil-Web-Cache-Deception-Attack-wp.pdf)
- A 2025 attack demonstration showed that discrepancies in URL processing (path normalization and delimiter handling) between a CDN and the origin server can get a CDN to cache protected resources. One cited example involved a ChatGPT session endpoint where a crafted path ending in a static-looking extension got cached. -- [GBHackers: New Cache Deception Attack](https://gbhackers.com/new-cache-deception-attack-exploits/)
- The USENIX 2020 paper "Cached and Confused" measured the prevalence of web cache deception in the wild across major websites. -- [arXiv: Cached and Confused](https://arxiv.org/pdf/1912.10190)
- A DEV Community post describes web cache deception specifically against APIs: the CDN caches based on URL path while the backend returns private data. It cites a Pingora issue, CVE-2026-2836, where the default cache key omitted the host header, so responses from different origins sharing a CDN shared one cache entry. -- [DEV Community: Web Cache Deception Against APIs](https://dev.to/roxdavirox/web-cache-deception-against-apis-cdns-cache-what-backends-serve-privately-339c) (CVE not confirmed from primary source)

#### Inferences
- APIs are particularly vulnerable because they often return JSON with sensitive data, and CDNs may cache responses based on file extension heuristics that do not account for API routing.
- The shift toward API-first architectures with CDN-fronted delivery increases this attack surface.

#### Gaps
- No confirmed 2025 CVE specifically for web cache deception against a named API product was found from a primary source.

---

### Cache Key Normalization Attacks and CDN Cache Poisoning

#### Takeaway
Cache key normalization attacks exploit differences in how CDNs and origin servers parse URL components (path segments, encoding, delimiters, query parameters). When the CDN normalizes a URL to one key but the origin interprets it differently, an attacker can poison the cache with malicious content or cause private responses to be served to other users.

#### Cited Findings
- PortSwigger's "Gotta cache 'em all" research found that resolving dot-segments and encodings in a cache key can let an attacker poison resources when the origin reads the path differently. Cloudflare, Google Cloud, and Fastly did not normalize the path in cache keys; CloudFront, Azure, and Imperva did. The exploit lives in the mismatch between a CDN and its origin. -- [PortSwigger Research: Gotta Cache 'Em All](https://portswigger.net/research/gotta-cache-em-all)
- Unkeyed headers are a classic poisoning vector: the cache key covers the URL, but the origin also reads headers such as `X-Forwarded-Host`, `X-Forwarded-Proto`, or `X-Original-URL`. A poisoned response gets stored under a key that legitimate users later hit. -- [ADHDecode: Cache Poisoning Key Normalization](https://adhdecode.com/network-security/web-application-network-security/web-cache-poisoning-network-attack/)
- Cache key injection via delimiter-escaping flaws: two different requests can produce the same key bytes, so a payload served to one request is served under the victim's key. -- [Crawlex: Anatomy of a CDN Cache Key](https://blog.crawlex.net/blog/cdn-cache-key-poisoning/)
- A HackerOne report (Omise, #3183046) describes cache key flooding: an attacker generates many junk query-string variants to evict popular cache entries, degrading cache performance and potentially enabling poisoning. -- [HackerOne Report #3183046](https://hackerone.com/reports/3183046)
- A 2026 arXiv paper describes "Web Cache Overflow" attacks that exploit imprecise cache keys for cache degradation. -- [arXiv: Web Cache Overflow](https://arxiv.org/pdf/2608.04744)

#### Inferences
- API endpoints are more susceptible than traditional web pages because APIs often rely on query parameters, custom headers, and path parameters that may or may not be included in cache keys.
- Mitigations include strict cache key construction that includes all decision-making inputs (host, path, relevant headers, query parameters), stripping irrelevant query parameters, and consistent normalization between CDN and origin.

#### Gaps
- Specific vendor-by-vendor cache key behavior documentation was not retrieved in full; the PortSwigger research is the most comprehensive comparison but was not fully accessible for deep reading.

---

## SSTI and Expression Language Injection via APIs

### Server-Side Template Injection Through API Parameters

#### Takeaway
SSTI via APIs occurs when JSON body fields, query parameters, or HTTP headers are passed unsanitized into server-side template engines. The attack is frequently missed because API security scanners test for XSS and SQLi payloads, not template syntax. Impact ranges from information disclosure to full remote code execution.

#### Cited Findings
- The injection surface in APIs is JSON parameters and HTTP headers flowing to server-side template engines, not HTML forms. Most API scanners fail here because they probe XSS payloads, not template syntax like `{{7*7}}` or `${7*7}`. -- [DEV Community: SSTI in APIs](https://dev.to/roxdavirox/ssti-in-apis-when-json-parameters-reach-template-engines-and-become-rce-339n)
- Detection methodology: inject arithmetic expressions into potential entry points. If the response contains the evaluated result (e.g., `49` for `{{7*7}}`), the field is being processed as a template. Different engines return different results for the same probe: `{{7*'7'}}` returns `7777777` in Jinja2 and `49` in Twig. -- [HackTricks: SSTI](https://hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html)
- Engine fingerprinting via error messages: the PayloadsAllTheThings polyglot payload triggers engine-specific errors that map error text to language (Python/Jinja2, Java/Freemarker, NodeJS/EJS, PHP/Twig, Ruby/ERB). -- [PayloadsAllTheThings: SSTI README](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md)
- Impact escalation: template engines like Jinja2, FreeMarker, and EJS have full access to the host runtime (Python interpreter, JVM, Node.js), enabling RCE from a template expression. One cited case involved a Fastify view helper where an attacker-controlled string was passed as a raw template with the EJS engine, resulting in RCE. -- [Cobalt: Pentester's Guide to SSTI](https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti)
- A March 2025 talk on advanced server-side template exploitation with "RCE everywhere" was referenced in the PayloadsAllTheThings Python payload list. -- [PayloadsAllTheThings: Python SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md)

#### Specific Payloads by Engine (from PayloadsAllTheThings and HackTricks)
- **Jinja2 (Python):** `{{config.items()}}` for information disclosure; `{{''.__class__.__mro__[1].__subclasses__()}}` to enumerate available classes for RCE chain construction.
- **Twig (PHP):** `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}` for command execution.
- **Freemarker (Java):** `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` for command execution.
- **Velocity (Java):** `#set($x='')##$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")` for command execution.
- **EJS (Node.js):** Exploitation typically through prototype pollution or raw template rendering with attacker-controlled input.

Note: These payloads are widely documented in public security references and are included here for defensive testing purposes.

#### Inferences
- APIs that use template engines for email generation, PDF rendering, dynamic configuration, or notification formatting are at risk even if they do not serve HTML pages.
- Expression Language injection in Spring (SpEL) and Struts (OGNL) follow the same pattern but enter through framework-specific parameter binding rather than explicit template rendering.

#### Gaps
- No 2025 CVE specifically for SSTI via an API JSON parameter was found; the technique is well-documented but specific incidents are reported as generic SSTI without distinguishing the API entry point.
- Thymeleaf-specific API exploitation payloads were not found in the search results, though Thymeleaf SSTI is documented in HackTricks and PayloadsAllTheThings.

---

## File Upload API Attacks

### Unrestricted File Upload, Polyglot Files, and Image Processing Exploits

#### Takeaway
File upload API endpoints are vulnerable to polyglot file attacks (files valid in multiple formats), path traversal via filenames in multipart requests, and exploitation of server-side image processing libraries. CVE-2025-55298 (ImageMagick format string bug) is a notable 2025 example of image processing library exploitation.

#### Cited Findings
- **Polyglot files:** Attackers create files that are valid in multiple formats, such as a file that is both a valid JPEG image (matching magic bytes) and contains executable script code. Validation based solely on magic bytes (file signature) rather than deep content inspection can be bypassed. -- [0xmar: Upload Bypass Using Magic Bytes](https://0xmar.medium.com/upload-bypass-using-magic-bytes-to-execute-php-code-via-polyglot-image-e3f03a1bd3ba)
- **CVE-2025-55298 (ImageMagick, August 2025):** A format string bug in the `InterpretImageFilename` function where user input is directly passed to `FormatLocaleString` without proper sanitization. This could lead to remote code execution when processing attacker-supplied image files. -- [GitHub Advisory GHSA-9ccg-6pjw-x645](https://github.com/advisories/GHSA-9ccg-6pjw-x645)
- **ImageTragick (CVE-2016-3714) background:** The classic image processing command injection arises when an insufficiently filtered filename is passed to a delegate command. Still relevant as a pattern because many image processing libraries use similar delegate architectures. -- [Cobalt: ImageTragick](https://www.cobalt.io/blog/imagetragick)
- **ATR-2026-02644 detection rule:** Flags files that begin with an image header followed immediately by a server-side script opener (e.g., `<?php`), which is a common polyglot pattern. -- [Agent Threat Rule ATR-2026-02644](https://agentthreatrule.org/en/rules/ATR-2026-02644)
- **SVG XSS:** SVG files uploaded through APIs can contain embedded JavaScript. When served with `image/svg+xml` content type, the script executes in the viewer's browser context. -- [LazyHackers: File Upload to RCE](https://lazyhackers.in/article/file-upload-rce-polyglot-imagetragick-svg-xss)
- **Path traversal via filename:** Multipart upload requests where the `filename` field in `Content-Disposition` contains path traversal sequences (e.g., `../../../etc/passwd` or `..%2f..%2f`) can write files to arbitrary locations if the server does not sanitize the filename. -- [Sourcery: Malicious Image Upload](https://www.sourcery.ai/vulnerabilities/image-upload-code-execution)

#### Inferences
- API file upload endpoints are a particularly high-risk attack surface because they often accept binary content with minimal validation, especially in microservice architectures where the upload service is separate from the processing service.
- Defense-in-depth requires: (1) validating content type via deep inspection (not just magic bytes), (2) sanitizing filenames by stripping path components, (3) processing images in sandboxed environments, (4) using allow-lists for file types, and (5) serving uploaded content from a separate domain.

#### Gaps
- No specific 2025 bug bounty writeup combining polyglot upload with API-specific exploitation was found in search results.
- libvips-specific API exploitation techniques were not found; most results focused on ImageMagick.

---

## Deserialization Attacks in APIs

### JSON Deserialization Gadget Chains

#### Takeaway
Insecure deserialization in API backends remains a critical risk, particularly in Java (Jackson, Fastjson), .NET (Newtonsoft.Json), Python (pickle), and PHP (unserialize). Gadget chains allow attackers to achieve RCE by chaining existing library classes through deserialization, without injecting new code. The tooling (Ysoserial) has gone stale, but the vulnerability class is actively exploited.

#### Cited Findings
- **Mechanics:** A gadget chain is a sequence of existing classes that an attacker links through deserialization. Each class triggers the next until the final one executes a system command, achieving RCE without injecting new code. -- [PVS-Studio: Gadget Chains in Java](https://pvs-studio.com/en/blog/posts/java/1296/)
- **Jackson (Java):** Jackson-style JSON type hints (`@class`, `@type`) can turn an API endpoint into a way to instantiate arbitrary classes. Blocklists in Jackson have been bypassed repeatedly; each bypass gets a new CVE and a new blocklist entry. -- [chs.us: Insecure Deserialization Guide](https://chs.us/guides/deserialization/)
- **Newtonsoft.Json (.NET):** Dangerous when `TypeNameHandling` is set to anything other than `None`. A restrictive `SerializationBinder` can block gadget resolution, but many applications use permissive settings. Common gadgets include `ObjectDataProvider` and `ExpandedWrapper`. -- [HackTricks: .NET Deserialization](https://hacktricks.wiki/en/pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.html)
- **Ysoserial staleness:** An April 2025 arXiv paper notes that Ysoserial, the main reference tool for Java gadget chains, has gone stale since its last gadget chain was added in February 2021. The paper introduces GadgetBuilder as a potential successor. -- [Springer: GadgetBuilder](https://link.springer.com/chapter/10.1007/978-3-032-14782-0_11)
- **"Sleeping Giants" (April 2025):** Research on activating dormant Java deserialization gadget chains through stealthy code changes -- an attacker contributes seemingly benign code to open-source libraries that completes a partial gadget chain. -- [arXiv: Sleeping Giants](https://arxiv.org/pdf/2504.20485)
- **CVE-2025-32444 (vLLM, CVSS 10.0):** A pickle-based deserialization vulnerability in the vLLM AI inference framework, showing that deserialization attacks are actively being found in modern API-serving infrastructure. -- [chs.us: Insecure Deserialization Guide](https://chs.us/guides/deserialization/)
- **API-specific context:** Insecure deserialization is listed as OWASP API Security Top 10 risk. APIs that accept serialized objects in request bodies, cookies, or custom headers are vulnerable. Detection includes sending type-annotated JSON payloads and observing class instantiation side effects. -- [APIsec: Insecure Deserialization in APIs](https://www.apisec.ai/blog/insecure-deserialization-in-api)

#### Inferences
- The "Sleeping Giants" research suggests that supply chain attacks could be used to introduce gadget chain components into popular libraries, making this a compounding risk.
- Modern AI/ML serving infrastructure (like vLLM) introduces new deserialization attack surfaces because model serialization formats (pickle, safetensors) are inherently executable.

#### Gaps
- Specific 2025 gadget chains for Fastjson or newer Jackson versions were not found in search results; the tooling landscape appears to be in transition from Ysoserial to newer automated discovery tools.
- PHP `unserialize` gadget chains specific to API frameworks (Laravel, Symfony API endpoints) were not found in this search.

---

## DNS Rebinding Against APIs

### DNS Rebinding Bypass of Same-Origin Policy for Internal APIs

#### Takeaway
DNS rebinding attacks exploit the time-of-check/time-of-use (TOCTOU) gap between hostname validation and the actual HTTP request. Multiple 2025 CVEs confirm this technique is actively used to bypass SSRF protections and access internal APIs, with the MCP (Model Context Protocol) ecosystem being a notable new attack surface.

#### Cited Findings
- **Paperless-ngx (GHSA-6653-vcx4-69mc, December 2025):** Webhook validation resolved the hostname and checked for a public IP, but the actual request resolved again. An attacker uses a DNS rebinding domain that returns a public IP during validation but resolves to an internal IP (e.g., `127.0.0.1`, `10.x.x.x`) during the actual HTTP request. Affects versions 2.1.4.0 through 2.20.1; patched in 2.20.2. -- [GitHub Advisory GHSA-6653-vcx4-69mc](https://github.com/paperless-ngx/paperless-ngx/security/advisories/GHSA-6653-vcx4-69mc)
- **CVE-2025-69660 (simstudioai/sim):** SSRF in proxy and file-parsing endpoints; URL validation was not protected against DNS rebinding. Fixed with DNS pinning (resolving once and connecting to the resolved IP). -- [Aydin Yunus: SSRF DNS Rebinding](https://aydinnyunus.github.io/2026/03/14/ssrf-dns-rebinding-vulnerability/)
- **MCP ecosystem:** The MCP TypeScript SDK prior to version 1.24.0 lacked DNS rebinding protection by default. When an MCP server accepts connections based on hostname validation without proper IP address verification, it becomes susceptible to DNS rebinding. -- [Varonis: MCP DNS Rebind Attack](https://www.varonis.com/blog/model-context-protocol-dns-rebind-attack); [arXiv: MCP-38 Threat Taxonomy](https://arxiv.org/pdf/2603.18063)
- **Browser-based attack methodology:** (1) Attacker hosts a page on their domain, (2) victim visits the page, (3) attacker's DNS initially resolves to the attacker's server, (4) JavaScript on the page makes requests to the same domain, (5) attacker's DNS TTL expires and re-resolves to an internal IP (e.g., `127.0.0.1`), (6) browser treats it as same-origin, bypassing SOP, (7) attacker exfiltrates data from the internal service. -- [GitHub Blog: DNS Rebinding Attacks Explained](https://github.blog/security/application-security/dns-rebinding-attacks-explained-the-lookup-is-coming-from-inside-the-house/)
- **Filter evasion techniques documented by NCC Group's Singularity tool:** Using `0.0.0.0` to reach localhost (bypasses protections that only block `127.0.0.1`); using CNAME records pointing to internal IPs (bypasses protections that only check A record values); using IPv6 `::1` instead of IPv4 localhost. -- [NCC Group Singularity: Protection Bypasses](https://github.com/nccgroup/singularity/wiki/Protection-Bypasses)
- **Tools:** Singularity (NCC Group) and rbndr (taviso) are the primary tools for DNS rebinding attacks. Singularity provides a complete attack framework including DNS server, HTTP server, and payload delivery. -- [NCC Group Singularity](https://github.com/nccgroup/singularity/wiki/Protection-Bypasses)

#### Inferences
- The emergence of MCP servers as a new attack surface for DNS rebinding is significant, as these servers often run locally and expose powerful capabilities to language models.
- The standard mitigation is DNS pinning: resolve the hostname once, validate the IP, and connect to that same resolved IP for the actual request, rather than re-resolving.

#### Gaps
- Quantitative data on how many internal APIs are vulnerable to DNS rebinding in production was not found.

---

## API Authentication Token Attacks

### PASETO, Macaroon, Branca, and Opaque Token Vulnerabilities

#### Takeaway
No specific 2025 CVEs were found for PASETO, Branca, or Macaroon token implementations. The attack surfaces are primarily implementation-level: version/purpose confusion in PASETO, missing expiry caveats in Macaroons, and symmetric-only key management in Branca. Opaque token introspection endpoints are at risk of token scanning when client authentication is not enforced.

#### Cited Findings
- **PASETO attack surfaces:** Version downgrade (forcing v1 instead of v4 when multiple versions are supported) and purpose confusion (local vs. public) are the main concerns. By design, PASETO eliminates algorithm confusion attacks by removing algorithm flexibility and not storing cryptographic details in the token itself. -- [rmrf.tips: JWT Alternatives](https://rmrf.tips/en/posts/jwt-alternatives/)
- **Macaroon risks:** A Macaroon is a bearer token, so anyone who steals it can use it. There is no built-in expiry; without a time-based caveat, it lives forever. Compromise of the root key exposes all derived macaroons, which is worse than a single JWT because attenuated macaroons are handed to third parties. Test areas: caveat bypass, missing time-based caveats, and discharge theft. -- [rmrf.tips: JWT Alternatives](https://rmrf.tips/en/posts/jwt-alternatives/)
- **Branca limitations:** Only supports symmetric encryption (XChaCha20-Poly1305 AEAD), no public keys, not OAuth/OIDC compatible, and requires manual revocation management. These are design tradeoffs rather than vulnerabilities. -- [Security Boulevard: JWT vs PASETO vs Branca 2026](https://securityboulevard.com/2025/11/jwt-vs-paseto-vs-branca-the-future-of-secure-tokens-in-2026/)
- **Opaque token introspection abuse:** RFC 7662 requires the introspection endpoint to require some form of authorization (client authentication) to prevent token scanning attacks. Without it, an attacker can probe tokens to discover valid ones. -- [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)
- **RFC 9701 (January 2025):** Adds JWT-signed introspection responses, addressing cases where a resource server needs stronger assurance that the authorization server issued the response, preventing response forgery. -- [IETF: RFC 9701](https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/)
- **Token theft incident context:** The Salesloft-Drift breach in late 2025 demonstrated how attackers harvested OAuth tokens from an integration provider, though this was token theft rather than introspection abuse. -- [Obsidian Security: OAuth Token Vulnerabilities](https://www.obsidiansecurity.com/blog/what-are-oauth-tokens-vulnerabilities)

#### Inferences
- PASETO's security advantage over JWT (no algorithm confusion) may create a false sense of security if implementations support multiple versions or do not validate the purpose field.
- The main risk with these alternative token formats is not in the cryptographic design but in implementation details: key management, expiry enforcement, and revocation.

#### Gaps
- No specific CVE for any PASETO, Branca, or Macaroon library was found in 2025-2026 search results. These formats have smaller adoption than JWT, so fewer security researchers are testing them.
- The "Phantom Token" approach (Curity) was referenced but not explored in depth; it combines opaque tokens with JWT introspection and may address some abuse vectors.

---

## Kubernetes/Container API Attacks

### Kubernetes API Server, etcd, Kubelet, and Container Runtime Exploitation

#### Takeaway
Kubernetes API attacks in 2025-2026 primarily stem from misconfiguration (anonymous authentication, exposed ports, permissive RBAC) rather than novel exploits. The API server, etcd, and kubelet each expose distinct attack surfaces, with direct etcd access being the most damaging path to cluster compromise.

#### Cited Findings
- **API server anonymous access:** The API server accepts unauthenticated requests by default on ports 10250/10255. One campaign reportedly compromised 60+ clusters through an API server with anonymous authentication enabled. Public exposure of the API server is almost never necessary or justifiable. -- [AlertLogic: Kubernetes Unauthenticated API Access](https://support.alertlogic.com/hc/en-us/articles/360003799632-Kubernetes-Unauthenticated-API-Access)
- **etcd direct access:** An attacker who can read the API server's etcd client certificate private key can gain cluster-admin rights. etcd stores all cluster state, including secrets, in plaintext by default. -- [Kubernetes Docs: API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
- **Unverified CVE-2026-33413 (CVSS 8.8):** Unauthenticated users can invoke etcd backend methods via the gRPC endpoint on port 2379. -- [DEV Community: Kubernetes Attack Surface](https://dev.to/roxdavirox/kubernetes-attack-surface-what-exposed-apis-and-misconfigured-rbac-reveal-14d2) (not confirmed from NVD or Kubernetes security announcements)
- **Kubelet API exploitation:** Aqua Security's honeypot research recorded attackers sending anonymous, unauthenticated API requests to the kubelet, installing scanning tools, and mapping the cluster network. Kubernetes notes that direct access to the kubelet API is not subject to admission control and is not logged by Kubernetes audit logging. -- [Aqua Security: Exploiting the Kubelet API](https://www.aquasec.com/blog/kubernetes-exposed-exploiting-the-kubelet-api/)
- **Container runtime socket:** An attacker with access to the container runtime socket can launch new containers or interact with running containers. This is equivalent to root access on the node. -- [Kubernetes Docs: API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
- **Cross-namespace reference vulnerabilities (July 2025):** A research paper identified vulnerabilities in Kubernetes Operators that allow cross-namespace reference attacks, where an operator in one namespace can be tricked into accessing resources in another namespace. -- [arXiv: Breaking the Bulkhead](https://arxiv.org/pdf/2507.03387)
- **CNCF 2025 guidance:** Common mistakes include overly permissive RBAC roles, exposed dashboards, and unencrypted etcd. Recommendations: restrict etcd to trusted network ranges, control access to etcd and API server client keys, enable audit logging, and use network policies to restrict pod-to-pod communication. -- [CNCF Blog: Kubernetes Mistakes](https://www.cncf.io/blog/2025/04/22/these-kubernetes-mistakes-will-make-you-an-easy-target-for-hackers/)

#### Inferences
- The Kubernetes attack surface is well-documented but frequently misconfigured in practice, making these "known" attacks still highly effective.
- The cross-namespace reference vulnerability class is newer and may be underrepresented in traditional Kubernetes security assessments.
- Container runtime API attacks (containerd, CRI-O) are less documented publicly but equally dangerous, as they bypass all Kubernetes-level controls.

#### Gaps
- Specific 2025 exploit code or step-by-step attack chains for Kubernetes API compromise beyond generic pentesting guides were not found.
- Container runtime API (containerd, CRI-O) specific exploitation techniques were not covered in detail in the search results.
