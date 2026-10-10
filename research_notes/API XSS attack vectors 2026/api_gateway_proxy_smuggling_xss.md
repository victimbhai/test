# XSS Vulnerabilities in API Gateways, Reverse Proxies, Request Smuggling, and Microservice Architectures

## Kong API Gateway XSS Vulnerabilities (2024-2026)

### Takeaway
No XSS-specific CVEs were found for Kong API Gateway in the 2024-2026 timeframe. The closest related findings are request smuggling/desync flaws and authentication bypass vulnerabilities, which could theoretically be chained with XSS but are not XSS themselves.

### Cited Findings
- CVE-2026-6338 is listed as a request smuggling and desynchronization issue caused by a parsing flaw in Kong's HTTP request processing pipeline when handling untrusted HTTP/1.1 traffic -- [OpenCVE - Kong Enterprise Gateway](https://app.opencve.io/cve/?product=kong_enterprise_gateway&vendor=kong)
- CVE-2026-29413 (CVSS 9.8) concerns authentication bypass in Kong Gateway; CVE-2026-29414 concerns rate limiting circumvention. These are not XSS but indicate ongoing security issues in Kong's request handling -- [Kensai Blog](https://kensai.app/blog/kong-api-gateway-cve-2026-authentication-bypass-rate-limiting); note: this source uses placeholder CVE IDs in one variant of the page, reducing confidence
- Kong's Admin API, when exposed without authentication, permits arbitrary plugin configuration and route manipulation. If an attacker installs or reconfigures the response-transformer plugin to inject arbitrary headers or body content, this could serve as an XSS delivery mechanism -- [Acunetix - Unprotected Kong Gateway Admin API](https://www.acunetix.com/vulnerabilities/web/unprotected-kong-gateway-admin-api-interface/)
- CVE-2021-27306 allowed access to authenticated routes through unauthenticated routes in Kong versions before 2.3.2.0, demonstrating the pattern of plugin bypass vulnerabilities -- [Medium - CVE-2021-27306](https://sewan.medium.com/cve-2021-27306-access-an-authenticated-route-on-kong-api-gateway-6ae3d81968a3)

### Inferences
- Kong's response-transformer and request-transformer plugins are the most likely XSS vectors: if these plugins can be manipulated to inject unsanitized content into response bodies or headers, reflected or stored XSS becomes possible.
- The request smuggling flaw (CVE-2026-6338) in Kong's HTTP/1.1 parsing could be chained with a reflected XSS in a backend service to deliver the XSS payload to arbitrary users, following the same pattern as PortSwigger's documented smuggling-to-XSS escalation.
- Exposed Admin APIs remain a critical vector: an attacker who reaches the Admin API can install custom plugins that inject script content into every proxied response.

### Gaps
- No confirmed Kong-specific XSS CVE (CWE-79) was found for 2024-2026 in any search. A direct query against NVD with vendor=kong and CWE=79 would be needed to confirm this absence.
- Kong plugin marketplace third-party plugins were not covered; custom or community plugins that handle response body transformation may contain XSS vulnerabilities not tracked under Kong's vendor CVE assignments.
- Kong's error page rendering (e.g., 404 or 503 pages returned by the gateway itself) was not addressed in any source found; these pages could reflect request path or query parameters.


## Nginx Reverse Proxy Misconfigurations Enabling XSS

### Takeaway
Nginx misconfigurations create XSS attack surfaces primarily through unsafe variable reflection in responses, add_header directive inheritance quirks, and path normalization differences between proxy and backend that enable path traversal to XSS-vulnerable endpoints.

### Cited Findings
- The off-by-slash misconfiguration occurs when a location block lacks a trailing slash but proxy_pass includes one (e.g., `location /api` with `proxy_pass http://backend/v1/`). This can produce unexpected path mappings, potentially routing requests to unintended backend endpoints that may be vulnerable to XSS -- [Detectify - Common Nginx Misconfigurations](https://blog.detectify.com/industry-insights/common-nginx-misconfigurations-that-leave-your-web-server-ope-to-attack/)
- When `merge_slashes` is set to `off`, Nginx does not normalize multiple slashes (`//`) before performing location matching. This can allow requests to bypass location-based access controls and reach endpoints that would otherwise be blocked, potentially including XSS-vulnerable paths -- [Ctrl Blog - Avoid merge_slashes](https://www.ctrl.blog/entry/nginx-requesturi-proxycache.html)
- "When frameworks or configs unsafely use the variables stored by Nginx, this can lead to issues such as XSS, bypassing HttpOnly-protection, information disclosure and in some cases even RCE." This directly establishes the unsafe variable reflection pattern -- [Reverse Proxies - Jorian Woltjer](https://book.jorianwoltjer.com/web/server-side/reverse-proxies)
- The `add_header` directive in a child block completely overrides (not appends to) parent block headers. If a security-critical header like `Content-Security-Policy` or `X-XSS-Protection` is set in the server block but a location block adds its own `add_header`, all parent security headers are silently dropped -- [HackTricks - Nginx](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nginx)
- Nginx variables such as `$uri` and `$document_uri` contain the decoded/normalized URI, while `$request_uri` contains the original. Using `$uri` in a return or rewrite directive that generates a response can reflect decoded user input, enabling XSS if the input contains HTML/JS -- [Attacking Nginx - DevSecOps Guides](https://blog.devsecopsguides.com/p/attacking-nginx)

### Inferences
- The `add_header` inheritance issue is particularly dangerous because operators may believe CSP or X-Content-Type-Options headers are applied globally when they are silently dropped in location blocks that have their own `add_header` directives. This removes the browser-side XSS mitigation layer.
- The `merge_slashes off` + `proxy_pass` combination can create path traversal conditions where an attacker crafts a URL like `/safe-prefix/../vulnerable-endpoint?q=<script>` that passes Nginx's location check but reaches an XSS-vulnerable backend endpoint after the backend normalizes the path differently.
- The `$uri` variable reflection pattern represents the most direct XSS vector: configurations like `return 302 https://$host$uri;` will decode `%3Cscript%3E` to `<script>` in the redirect Location header, and if the browser renders an intermediate page, XSS fires.

### Gaps
- No specific CVE numbers were found for Nginx XSS misconfigurations. These are configuration-level issues rather than software vulnerabilities, so they do not receive CVE assignments.
- The interaction between `proxy_pass` path normalization and WAF bypass was not covered in the sources found.


## AWS API Gateway XSS Vectors

### Takeaway
No specific AWS API Gateway XSS CVEs were found for 2024-2026. The primary XSS risks arise from Lambda proxy integration passing unsanitized function output directly to clients, and from custom error response templates that may reflect request parameters.

### Cited Findings
- AWS documentation states that Gateway Response templates "use simple variable substitution and are not processed by the Velocity Template Language (VTL) engine." This limits template injection risk compared to integration response mapping templates, which do use VTL -- [AWS - Gateway Response Templates](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-swagger-extensions-gateway-responses.responseTemplates.html)
- With Lambda proxy integration, "API Gateway passes through what the function returns," meaning the Lambda function directly controls status code, headers, and body. If the function echoes user input in an HTML response without sanitization, XSS is delivered through the API Gateway without any gateway-level encoding -- [AWS - Lambda Integration](https://docs.aws.amazon.com/lambda/latest/dg/services-apigateway.html)
- API Gateway models, which are JSON Schema definitions, "can define what type of data is accepted as input or what is given as output after execution," providing a validation mechanism that can reject payloads containing script tags -- [DEV Community - API Gateway Integration Response](https://dev.to/awscommunity-asean/api-gateway-integration-response-setup-for-aws-lambda-25km)
- Content-Security-Policy and X-Content-Type-Options headers are recommended mitigations but are not set by default in API Gateway responses -- [Modus Create - Lambda@Edge Security](https://moduscreate.com/blog/simple-security-lambda-edge/)

### Inferences
- The Lambda proxy integration is the highest-risk pattern: the gateway acts as a pure passthrough, so any XSS in the Lambda response reaches the client unmodified. This is functionally equivalent to a direct-to-backend connection for XSS purposes.
- Custom authorizer error messages are a likely XSS vector: when a custom authorizer returns a denial with a message containing reflected request data (e.g., "Access denied for path: /api/<script>alert(1)</script>"), and the API Gateway renders this in a default error page or passes it through, XSS fires.
- VTL mapping templates in integration responses introduce server-side template injection risk: if a template references `$input.params('querystring')` and embeds it in an HTML response body, the template engine does not HTML-encode the output.
- REST API (v1) and HTTP API (v2) have different default behaviors: HTTP APIs have simpler passthrough semantics, making XSS mitigation entirely the Lambda function's responsibility.

### Gaps
- No AWS security bulletin or CVE specifically addresses XSS through API Gateway response templates or Lambda proxy integration in 2024-2026.
- The behavior of API Gateway's default error pages (e.g., 403 Forbidden, 429 Too Many Requests) when they include request path or header values was not covered in any source found.
- CloudFront + API Gateway combinations, where CloudFront's error pages may reflect request parameters, were not addressed.


## Azure API Management / Google Cloud API Gateway XSS Vectors

### Takeaway
Azure has had XSS findings in related services (Bastion, Container Registry, HDInsight, Stack Edge) but no confirmed XSS CVE specifically in Azure API Management was found for 2024-2026. No Google Cloud API Gateway XSS vulnerabilities were found in any search.

### Cited Findings
- Microsoft fixed "three vulnerabilities in the Azure API Management service that could be abused to gain access to sensitive information or backend services" (2023). The specific vulnerability types were not confirmed as XSS in the search snippet -- [The Hacker News](https://thehackernews.com/2023/06/severe-vulnerabilities-reported-in.html?hl=ru)
- Orca Security reported XSS flaws in Azure Bastion and Azure Container Registry, fixed in April and May 2023 -- [SecurityWeek - Azure XSS](https://www.securityweek.com/xss-vulnerabilities-in-azure-led-to-unauthorized-access-to-user-sessions/)
- Eight XSS vulnerabilities in Azure HDInsight were reported and fixed in August 2023 -- [SecurityWeek - Azure HDInsight](https://www.securityweek.com/azure-hdinsight-flaws-allowed-data-access-session-hijacking-payload-delivery/amp/)
- CVE-2026-41098 describes a stored XSS vulnerability affecting Microsoft Azure Stack Edge, published to NVD on 2026-06-09. This affects a different Azure service, not API Management -- [SentinelOne Vulnerability Database](https://www.sentinelone.com/vulnerability-database/cve-2026-41098/)

### Inferences
- Azure API Management's policy expressions (C# code snippets in policy XML) that reflect request data into responses are the most likely XSS vector, similar to AWS VTL templates. A policy like `<set-body>@("Error: " + context.Request.Url.Path)</set-body>` with Content-Type text/html would produce reflected XSS.
- Azure API Management's developer portal, which renders API documentation and test consoles, is another potential XSS surface, especially if API descriptions or parameter examples contain unsanitized HTML.
- Google Cloud API Gateway's relatively newer and simpler architecture (based on Envoy proxy) may have fewer XSS surfaces, but its error page rendering and custom response handling would follow similar patterns.

### Gaps
- No confirmed Azure API Management XSS CVE was found for 2024-2026 in any source.
- No Google Cloud API Gateway XSS vulnerability of any kind was found. This could indicate either a genuinely smaller attack surface or insufficient research coverage.
- Azure API Management's CORS policy handling and its interaction with XSS was not covered.


## HTTP Request Smuggling Leading to XSS

### Takeaway
Request smuggling (CL-TE, TE-CL, and HTTP/2 downgrade variants) is a well-documented technique for upgrading reflected XSS to affect arbitrary users, effectively turning reflected XSS into stored-like XSS. James Kettle's ongoing research through 2025 continues to identify new smuggling vectors.

### Cited Findings
- PortSwigger's lab demonstrates that smuggling a CL-TE request containing a User-Agent header with an XSS payload causes "the next user's request to receive a response containing an XSS exploit." The key mechanism is that the smuggled request poisons the connection so the backend treats the next legitimate user's request as a continuation of the attacker's smuggled request -- [PortSwigger Lab - Deliver Reflected XSS via Smuggling](https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss)
- A TE.CL bug bounty write-up describes chaining request smuggling with header-based XSS into "website takeover," noting that "even though HTTP Request Smuggling is documented back on 2005, it is still one of the least known webapp vulnerability out there" -- [Kleiton0x00 Blog](https://kleiton0x00.github.io/posts/Exploiting-HTTP-Request-Smuggling-(TE.CL)-XSS-to-website-takeover/)
- A 2024 Cybersec Cafe write-up follows the CL.TE approach and uses the HTTP Request Smuggling Extension for detection through response delays -- [Cybersec Cafe](https://www.cyberseccafe.com/p/cybersec-cafe-5-methodology-monday)
- James Kettle's 2025 Black Hat talk "HTTP/1.1 Must Die: The Desync Endgame" lists the progression of techniques: 2024 introduced "Exploit dechunking (TE.0)" and 2025 introduced "chunk-extension TE.TE" (credited to Jeppe Weikop). CVE-2025-4366 is mentioned in the slides -- [Black Hat USA 2025 Slides](https://i.blackhat.com/BH-USA-25/Presentations/US-25-Kettle-HTTP1-Must-Die-The-Desync-Endgame-Wednesday.pdf)
- Kettle's 2021 "HTTP/2: The Sequel is Always Worse" demonstrated H2.CL desync attacks, noting that "HTTP/2 downgrading" is the root cause: front-end proxies that translate HTTP/2 to HTTP/1.1 for backends create smuggling opportunities. The Netflix case study used H2.CL desync to inject requests -- [Black Hat USA 2021 Whitepaper](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Kettle-HTTP2-The-Sequel-Is-Always-Worse-wp.pdf)
- One source notes that request smuggling is "no longer possible with HTTP/2" end-to-end, but this does not account for HTTP/2-to-HTTP/1.1 downgrade scenarios which remain common -- [Pentestpartners](https://www.pentestpartners.com/security-blog/http-request-smuggling-a-how-to/)

### Inferences
- The attack flow for smuggling-to-XSS follows this pattern:

```
Attacker                   Front-end (HTTP/2 or HTTP/1.1)     Back-end (HTTP/1.1)
   |                              |                                |
   |-- Smuggled request --------->|                                |
   |   (CL says X, TE says Y)    |-- Forwards partial request --->|
   |                              |   (back-end sees leftover     |
   |                              |    bytes as next request)      |
   |                              |                                |
   |                              |<-- Victim's real request ------|
   |                              |   (appended to attacker's      |
   |                              |    leftover, including XSS     |
   |                              |    payload in User-Agent)      |
   |                              |                                |
   |                              |<-- Response with XSS ---------|
   |                              |-- Serves XSS to victim ------>|
```

- The 2024 TE.0 technique ("exploit dechunking") targets servers that accept chunked encoding in requests but do not properly handle a zero-length chunk, creating a new class of smuggling that bypasses previous mitigations.
- The 2025 chunk-extension TE.TE technique exploits differences in how front-end and back-end servers handle extensions appended to chunk sizes (e.g., `0;extension`), creating desync even when both servers nominally support chunked encoding.
- HTTP/2 downgrade smuggling remains the most impactful variant because HTTP/2's binary framing makes the smuggled content invisible to HTTP/2-aware WAFs, while the downgraded HTTP/1.1 request on the backend carries the XSS payload.

### Gaps
- The specific details of CVE-2025-4366 mentioned in Kettle's 2025 slides could not be confirmed from the search results alone.
- No published CVE specifically tracks "smuggling-to-XSS" as a combined vulnerability; the smuggling and XSS are typically separate findings.
- Stored XSS via cache poisoning through smuggling (where a smuggled request causes a cache to store an XSS-containing response) was not covered by any 2024-2025 source found, though it is a documented technique in Kettle's earlier work.


## Header Injection Through API Proxies Enabling XSS

### Takeaway
X-Forwarded-Host and similar proxy headers are a confirmed reflected XSS vector when backend applications trust and reflect these headers without sanitization. Bug bounty disclosures in 2024-2025 confirm this remains actively exploited, and CVEs in proxy software (Fabio, OAuth2-proxy) demonstrate the infrastructure-level risk.

### Cited Findings
- A December 2024 Bugcrowd disclosure against NASA describes X-Forwarded-Host manipulation leading to "open redirection and potential reflected XSS." NASA rated the XSS component as informational because it required intercepting the victim's own request -- [Bugcrowd - NASA Disclosure](https://bugcrowd.com/disclosures/3f102232-685e-4f53-ae90-1a1ba2392491/host-header-injection-open-redirection-leading-to-cross-site-scripting-xss)
- CVE-2025-48865 in Fabio (a load balancer) and CVE-2025-64484 in OAuth2-proxy involve "reverse proxies being bypassed through hop-by-hop header abuse and underscore-hyphen normalization differences, which can enable authentication bypass and privilege escalation" -- [Security Boulevard](https://securityboulevard.com/2026/03/when-proxies-become-attack-vectors-through-header-injection/)
- A 2025 bug bounty compilation lists "SSRF in Yandex via X-Forwarded-Host" and "rate-limit bypass via X-Forwarded-For at YNAB" as examples of proxy header abuse, and notes that "a WAF or proxy may inspect X-Forwarded-Host while the app checks the Host header" -- [Medium - Uncommon Headers 2025](https://medium.com/@gasmask/uncommon-headers-that-bypass-everything-almost-bug-bounty-edition-2025-9d2ea65b2076)
- A bug bounty write-up describes XSS via X-Forwarded-Host where "the server echoes the header value directly into its response" -- [Medium - XSS via X-Forwarded-Host](https://jjainam16.medium.com/xss-via-x-forwarded-host-header-small-bounty-of-150-133295afbc48)
- Rails historically trusted X-Forwarded-Host unconditionally in URL generation, meaning `url_for` calls would include attacker-controlled domain names. The recommended fix was to strip the header in middleware or configure trusted proxies -- [Rails Issue #29893](https://github.com/rails/rails/issues/29893)

### Inferences
- The attack pattern for X-Forwarded-Host XSS is:

```
Attacker                   Proxy/LB                Backend Application
   |                          |                          |
   |-- Request with           |                          |
   |   X-Forwarded-Host:      |                          |
   |   evil"><script>...      |-- Forwards with header ->|
   |                          |                          |
   |                          |                          |-- Generates response
   |                          |                          |   using header value
   |                          |                          |   in <base href="...">,
   |                          |                          |   redirect URL, or
   |                          |                          |   asset URL
   |                          |                          |
   |<-- Response with XSS ----|<-- Response with XSS ----|
```

- The underscore-hyphen normalization difference (CVE-2025-48865, CVE-2025-64484) is a newer technique: proxies may treat `X_Forwarded_Host` and `X-Forwarded-Host` differently, allowing an attacker to inject a header that the proxy does not strip but the backend trusts.
- Hop-by-hop header abuse allows an attacker to mark security-relevant headers (like `X-Forwarded-For`) as hop-by-hop using the `Connection` header, causing the proxy to strip them. The backend then falls back to a default or attacker-supplied value.

### Gaps
- The full details of CVE-2025-48865 and CVE-2025-64484 could not be retrieved because the Security Boulevard page was unreachable during research.
- Custom header pollution (injecting non-standard headers that backends reflect) was not covered by any specific source found, though it follows the same pattern as X-Forwarded-Host reflection.


## Service Mesh XSS Propagation Patterns

### Takeaway
No confirmed XSS vulnerabilities through service mesh tracing header reflection (X-Request-ID, traceparent, B3 headers) were found in Istio, Envoy, or Linkerd. The research gap here is notable: tracing headers are widely propagated through service meshes but their reflection in error pages or application responses has not been studied as an XSS vector in any source found.

### Cited Findings
- Envoy sidecars in Istio "automatically inject new headers into the request" when incoming requests lack tracing headers, and "the propagation between services is left to the application" -- [Medium - Propagating Trace Headers with Istio](https://medium.com/@the.real.yushuf/propagate-trace-headers-with-istio-grpc-http-1-1-go-73e7f5382643)
- A GitHub issue reports that "Istio's Envoy Proxy is rewriting the header to its older value," demonstrating that the mesh actively modifies header values in transit -- [Istio Issue #41460](https://github.com/istio/istio/issues/41460)
- Another issue describes "x-request-id generated by nginx get overwritten by the Envoy proxy," showing that Envoy replaces inbound request IDs with its own -- [Istio Issue #10875](https://github.com/istio/istio/issues/10875)
- EnvoyFilter can add or remove response headers such as X-XSS-Protection, indicating that Envoy has the capability to both introduce and mitigate XSS-relevant headers -- [Alibaba Cloud - EnvoyFilter Headers](https://www.alibabacloud.com/blog/use-envoyfilter-to-add-http-request-headers-in-asm_596451)

### Inferences
- The theoretical attack pattern for tracing header XSS in a service mesh is:

```
External Client              Istio Ingress Gateway        Envoy Sidecar (Service A)       Service A App
   |                              |                              |                            |
   |-- Request with               |                              |                            |
   |   X-Request-ID:              |                              |                            |
   |   <script>alert(1)</script>  |-- Propagates header -------->|-- Passes to app ---------->|
   |                              |                              |                            |
   |                              |                              |                            |-- Reflects
   |                              |                              |                            |   X-Request-ID
   |                              |                              |                            |   in error page
   |                              |                              |                            |   or debug output
   |<-- XSS in response ----------|<-----------------------------|<---------------------------|
```

- Envoy's behavior of overwriting X-Request-ID with its own UUID value would actually mitigate this attack in the default configuration, since the attacker's payload would be replaced. However, if `use_remote_address: false` is set or if custom EnvoyFilters pass through the original header, the mitigation is lost.
- The greater risk is in application-level tracing: if services log or display tracing headers (traceparent, B3 trace IDs) in admin dashboards, debug pages, or error responses without HTML encoding, the mesh's header propagation becomes an XSS delivery mechanism across the entire service graph.

### Gaps
- No CVEs or security advisories for Istio, Envoy, or Linkerd address tracing header reflection XSS. This appears to be an unstudied attack surface.
- Envoy's error page rendering (e.g., 503 Service Unavailable pages generated by Envoy itself) and whether they reflect any request headers was not documented in any source found.
- Linkerd's header handling was not covered in the search results.


## Inter-Service XSS via Shared Databases in Microservice Architectures

### Takeaway
The inter-service stored XSS pattern (Service A stores unsanitized data, Service B renders it) is a recognized architectural risk in microservices with shared databases, but no specific CVEs, academic papers, or detailed case studies were found. The available guidance is limited to general best practices.

### Cited Findings
- In shared database patterns, "the data structures stored in the database are open to all; they are shared in their entirety with any other party that has access to the database" -- [DevGnosis - Shared Databases in Microservices](https://devgnosis.substack.com/p/shared-databases-in-microservices)
- Mitigation guidance states: "Never trust HTML coming from other microservices. Treat it as data and encode it again in the final template layer" and "every service that returns HTML or JSON should use shared encoding and sanitizing libraries" -- [Design Gurus](https://www.designgurus.io/answers/detail/how-do-you-mitigate-ssrfcsrfxss-across-a-microservices-stack)
- Shared databases are flagged as an anti-pattern when "more than one microservice directly uses the same database," but remain common in practice for performance and consistency reasons -- [Arpit Substack](https://arpit.substack.com/p/should-some-microservices-share-a)

### Inferences
- The inter-service XSS attack flow in a shared database architecture:

```
Attacker        Service A (Write)       Shared Database       Service B (Read/Render)       Victim
   |                  |                      |                       |                        |
   |-- Submit         |                      |                       |                        |
   |   malicious      |                      |                       |                        |
   |   input -------->|                      |                       |                        |
   |                  |-- Store unsanitized ->|                       |                        |
   |                  |   data (no output     |                       |                        |
   |                  |   encoding because    |                       |                        |
   |                  |   Service A is API-   |                       |                        |
   |                  |   only, never renders)|                       |                        |
   |                  |                      |                       |                        |
   |                  |                      |<-- Read data ---------|                        |
   |                  |                      |                       |-- Render in HTML ------>|
   |                  |                      |                       |   without encoding      |
   |                  |                      |                       |   (trusts database)     |
   |                  |                      |                       |                   XSS! |
```

- The root cause is a misalignment of security responsibilities: Service A does not sanitize because it is an API that never renders HTML, and Service B does not sanitize because it trusts data from the "internal" database. Neither service owns output encoding.
- This pattern is amplified by event sourcing architectures where raw events are stored immutably and rendered by multiple consumers, each of which must independently handle encoding.
- GraphQL federation and API composition patterns create the same risk without a shared database: Service A's resolver returns unsanitized data that Service B's frontend consumes and renders.

### Gaps
- No CVE, bug bounty report, or academic paper was found that documents a specific instance of inter-service XSS through a shared database. This is a well-understood architectural risk but appears underdocumented in the vulnerability literature.
- The role of ORMs and database drivers in encoding/escaping (which typically protect against SQL injection but not XSS) was not addressed by any source.


## Event-Driven Architecture XSS Vectors

### Takeaway
Event-driven XSS is primarily an application-layer concern: the transport (Kafka, Redis, RabbitMQ) is not vulnerable itself, but applications that consume and render event payloads without output encoding are. CVE-2026-49098 in Apache Camel's Kafka component demonstrates that header injection in event systems is a real and recently exploited vulnerability class.

### Cited Findings
- CVE-2026-49098 in the camel-kafka component allows "attackers who send HTTP requests to set Kafka headers that override the destination topic, which lets forged messages reach topics the app never meant to write to." Affected versions: 4.0.0 through 4.20.9. A public exploit exists -- [CraftedSignal Feed](https://feed.craftedsignal.io/tags/kafka/feed.json)
- CVE-2026-5562 in Provectus kafka-ui allows "a crafted request to a smart-filter endpoint to lead to remote code execution in versions up to 0.7.2." This is code injection through a web endpoint that manages Kafka, not XSS in rendered messages -- [GitLab Advisory](https://advisories.gitlab.com/pkg/maven/com.provectus/kafka-ui-serde-api/)
- For Redis, the sidekiq-unique-jobs advisory (CVE-2024-25122) states that "Redis's protocol is length-prefixed and binary safe, so classic command injection is not expected when a normal client library is used." The XSS in this case came from "unescaped GET parameters in the admin UI," not from Redis data itself -- [GitHub Advisory GHSA-cmh9-rx85-xj38](https://github.com/mhenrixon/sidekiq-unique-jobs/security/advisories/GHSA-cmh9-rx85-xj38); [FluidAttacks](https://db.fluidattacks.com/adv/gem/sidekiq-unique-jobs/CVE-2024-25122)

### Inferences
- The event-driven XSS attack flow:

```
Attacker             Event Producer          Message Broker           Event Consumer          Admin UI / Dashboard
   |                      |                      |                       |                        |
   |-- Inject payload --->|                      |                       |                        |
   |   via API or         |-- Publish message -->|                       |                        |
   |   header injection   |   with XSS in body  |                       |                        |
   |                      |   or headers         |-- Deliver to -------->|                        |
   |                      |                      |   consumer            |-- Render message ------>|
   |                      |                      |                       |   metadata/body in      |
   |                      |                      |                       |   web interface    XSS! |
```

- Kafka admin UIs (kafka-ui, AKHQ, Kafdrop, Conduktor) that render message keys, values, and headers in web interfaces are the most direct XSS target. If a Kafka topic contains messages with HTML/JS in the value, any admin tool that renders the raw value in a browser without encoding will execute the XSS.
- Redis pub/sub follows the same pattern: the transport is safe, but web dashboards (Redis Commander, RedisInsight) that display pub/sub messages or key values without encoding are vulnerable.
- RabbitMQ management UI renders message payloads; if a queue contains a message with XSS in the body and an operator inspects it through the management interface, the XSS executes in the operator's browser with the management UI's session.

### Gaps
- No specific CVE was found for XSS through Kafka message rendering in a consumer application (as opposed to an admin UI).
- RabbitMQ management UI XSS was not covered by any source found. A search against RabbitMQ security advisories would be needed.
- NATS streaming XSS was not addressed in any search result.


## HTTP/2 Specific XSS Bypass Techniques

### Takeaway
HTTP/2 creates XSS bypass opportunities primarily through downgrade smuggling (H2.CL, H2.TE) rather than through HPACK compression or stream multiplexing directly. HPACK-related research has focused on DoS and side-channel attacks, not XSS bypass.

### Cited Findings
- Kettle's H2.CL desync technique exploits HTTP/2-to-HTTP/1.1 downgrading: "the answer is HTTP/2 downgrading, which is where smuggling via HTTP/2 comes from." The Netflix case study demonstrated this with a front-end that "performed HTTP downgrading without verifying the content-length" -- [Kettle - HTTP/2 The Sequel Is Always Worse](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Kettle-HTTP2-The-Sequel-Is-Always-Worse-wp.pdf)
- HPACK compression ratio side channels allow "varying the content of a cookie and observing the change in header size to reveal information about the cookie's value." This is a CRIME/BREACH-style information disclosure, not an XSS vector -- [Imperva - HTTP/2 Security](https://imperva.com/blog/?p=415)
- HPACK bomb attacks use "a single header of size 4KB" referenced "16K times" to expand to "64MB on the server side," tracked as CVE-2016-1544 and CVE-2016-2525. This is a DoS technique, not related to XSS -- [Imperva - HTTP/2 Security](https://imperva.com/blog/?p=415)
- Kettle's 2025 slides recommend "upstream or end-to-end HTTP/2" as the mitigation for downgrade-based smuggling, and state that "HTTP/2 downgrading is not secure" -- [Black Hat USA 2025 Slides](https://i.blackhat.com/BH-USA-25/Presentations/US-25-Kettle-HTTP1-Must-Die-The-Desync-Endgame-Wednesday.pdf)
- An academic paper "HTTP Request Synchronization Defeats Discrepancy Attacks" (arXiv 2510.09952) proposes synchronization-based defenses against HTTP desync attacks -- [arXiv](https://arxiv.org/pdf/2510.09952)

### Inferences
- HTTP/2 binary framing makes XSS payloads in headers invisible to text-based WAF rules. A WAF inspecting HTTP/2 frames must decode HPACK-compressed headers before applying signature detection, and many WAFs inspect only the HTTP/1.1 representation after downgrade, creating a detection gap.
- Stream multiplexing does not directly enable XSS but can complicate WAF analysis: multiple interleaved streams mean the WAF must maintain state per stream, and a payload split across multiple HEADERS and CONTINUATION frames on the same stream may evade single-frame inspection.
- The HTTP/2 push mechanism could theoretically be used for cache poisoning (the server pushes a resource with XSS content that the browser caches), but no source confirmed this as a practical attack in the 2024-2026 timeframe.

### Gaps
- No source demonstrated HPACK compression being used to bypass WAF XSS detection specifically. The claim that HPACK enables WAF bypass appears to be theoretical inference rather than demonstrated attack.
- HTTP/2 push for cache poisoning XSS was not documented in any source found. HTTP/2 push has been removed from Chrome and is rarely used, reducing this attack surface.
- The interaction between HTTP/2 CONTINUATION frames and WAF inspection was not covered by any source.


## CRLF Injection / Request Splitting Leading to XSS Through API Infrastructure

### Takeaway
CRLF injection remains an active vulnerability class with recent CVEs (CVE-2025-57804 in python-hyper h2, CVE-2024-45302 in RestSharp). The HTTP/2 downgrade path creates new CRLF injection opportunities because HTTP/2 headers are binary-safe but HTTP/1.1 headers are not, so a header value containing CR/LF characters in HTTP/2 becomes a CRLF injection when downgraded.

### Cited Findings
- CVE-2025-57804 in the python-hyper h2 library (HTTP/2): "HTTP/2 request splitting vulnerability allows attackers to perform request smuggling attacks by injecting CRLF characters into headers. This occurs when servers downgrade HTTP/2 requests to HTTP/1.1 without properly validating header names/values." Fixed in version 4.3.0 -- [GitHub Advisory GHSA-847f-9342-265h](https://github.com/python-hyper/h2/security/advisories/GHSA-847f-9342-265h)
- CVE-2024-45302 in RestSharp (versions 107 through 111) is cited as an example of CRLF risk in server-to-server API client libraries -- [DEV Community](https://dev.to/roxdavirox/crlf-injection-in-api-responses-when-user-input-reaches-http-headers-233o); secondary source, verify against NVD
- The "FrontJacking" technique "involves CRLF injection, HTTP request header injection, and cross-site scripting (XSS) to exploit a poorly configured reverse proxy in a shared hosting environment" -- [The Hacker Recipes](https://www.thehacker.recipes/web/config/http-response-splitting)
- CRLF-to-XSS mechanism: "By injecting a double CRLF sequence (%0D%0A%0D%0A), an attacker can terminate the headers of the original response and start an entirely new response that they control" -- [SecureFlag Knowledge Base](https://knowledge-base.secureflag.com/vulnerabilities/inadequate_input_validation/http_response_splitting_vulnerability.html)
- Mitigations: "Restrict CR (0x13) and LF (0x10) from the user input or properly encode the output" -- [BreachLock](https://www.breachlock.com/resources/blog/crlf-injection-and-http-response-splitting-vulnerability/)

### Inferences
- The HTTP/2 downgrade CRLF injection attack flow:

```
Attacker                     HTTP/2 Front-end              HTTP/1.1 Backend
   |                              |                              |
   |-- HTTP/2 request with        |                              |
   |   header value containing    |                              |
   |   \r\n (valid in HTTP/2      |                              |
   |   binary framing)            |                              |
   |                              |-- Downgrades to HTTP/1.1 --->|
   |                              |   Header value now contains  |
   |                              |   literal CRLF, splitting    |
   |                              |   into multiple headers or   |
   |                              |   terminating headers early  |
   |                              |                              |
   |                              |                              |-- Injected header/body
   |                              |                              |   contains XSS payload
   |                              |                              |
   |<-- Response with XSS --------|<-- Response with XSS --------|
```

- API gateways that accept HTTP/2 from clients and communicate with backends over HTTP/1.1 (a very common architecture) are the primary risk surface for this attack. The gateway must validate that HTTP/2 header values do not contain CR or LF before downgrading.
- The RestSharp CVE (CVE-2024-45302) shows that client libraries used for inter-service communication can also be CRLF injection vectors: if Service A passes user input through a RestSharp header to Service B, and the header contains CRLF, the inter-service HTTP/1.1 connection is split.
- Response splitting via CRLF is the bridge from header injection to XSS: once the attacker controls the response body (by terminating headers early), they can inject arbitrary HTML/JavaScript.

### Gaps
- The CVSS score for CVE-2025-57804 was not found in the search results.
- The CVSS score for CVE-2024-45302 was not found in the search results.
- Whether major API gateways (Kong, AWS API Gateway, Azure API Management) validate HTTP/2 header values for CRLF before downgrading was not addressed by any source.


## Detection and Prevention Strategies

### Takeaway
Defense against API infrastructure XSS requires a layered approach across the request lifecycle: input validation at the gateway, output encoding at the application layer, and architectural controls (end-to-end HTTP/2, WAF placement after protocol normalization, service mesh header sanitization).

### Cited Findings
- Kettle recommends "upstream or end-to-end HTTP/2" as the primary mitigation for smuggling-based attacks, eliminating the HTTP/2-to-HTTP/1.1 downgrade that enables most modern smuggling techniques -- [Black Hat USA 2025 Slides](https://i.blackhat.com/BH-USA-25/Presentations/US-25-Kettle-HTTP1-Must-Die-The-Desync-Endgame-Wednesday.pdf)
- Content-Security-Policy headers are described as "the best method to prevent cross-site scripting (XSS) vulnerabilities" at the API response level -- [Modus Create](https://moduscreate.com/blog/simple-security-lambda-edge/)
- For microservices: "Never trust HTML coming from other microservices. Treat it as data and encode it again in the final template layer" and use "shared encoding and sanitizing libraries" -- [Design Gurus](https://www.designgurus.io/answers/detail/how-do-you-mitigate-ssrfcsrfxss-across-a-microservices-stack)
- For CRLF: "Restrict CR (0x13) and LF (0x10) from the user input or properly encode the output" -- [BreachLock](https://www.breachlock.com/resources/blog/crlf-injection-and-http-response-splitting-vulnerability/)
- For Nginx: use `$request_uri` instead of `$uri` in return/rewrite directives, ensure `add_header` directives are present in all location blocks (not just the server block), and keep `merge_slashes` at its default value of `on` -- [Detectify](https://blog.detectify.com/industry-insights/common-nginx-misconfigurations-that-leave-your-web-server-ope-to-attack/); [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nginx)
- For proxy headers: strip or validate X-Forwarded-Host, X-Forwarded-For, and similar headers at the edge before they reach backend applications. Configure trusted proxy lists rather than blindly trusting all forwarded headers -- [Rails Issue #29893](https://github.com/rails/rails/issues/29893)

### Inferences
- A comprehensive defense architecture against API infrastructure XSS:

```
Internet --> Edge WAF --> API Gateway --> Service Mesh Sidecar --> Application
                |              |                |                      |
                |              |                |                      +-- Output encoding
                |              |                |                          (HTML entity encoding
                |              |                |                           on all rendered data)
                |              |                |
                |              |                +-- Header sanitization
                |              |                    (strip/validate tracing
                |              |                     headers, X-Forwarded-*)
                |              |
                |              +-- Protocol normalization
                |                  (end-to-end HTTP/2, or
                |                   validate headers on downgrade)
                |                  Request validation
                |                  (reject CL/TE conflicts,
                |                   validate Content-Length)
                |                  Response headers
                |                  (CSP, X-Content-Type-Options)
                |
                +-- Signature detection (after protocol normalization)
                    Rate limiting on suspicious patterns
                    CRLF detection in header values
```

- WAF placement is critical: a WAF inspecting HTTP/2 traffic before the gateway downgrades it to HTTP/1.1 will miss smuggling and CRLF payloads that are only visible after downgrade. The WAF should inspect after protocol normalization, not before.
- API schema validation (OpenAPI/JSON Schema) at the gateway layer provides defense-in-depth against XSS payloads in request bodies by rejecting payloads that do not match expected data types and patterns.
- Output encoding must be the last line of defense and must happen at the point of rendering, not at the point of storage. Encoding at storage time is unreliable because different rendering contexts (HTML body, HTML attribute, JavaScript string, CSS value, URL) require different encoding.

### Gaps
- Specific WAF rules or configurations for detecting smuggling-to-XSS chains were not found in any source.
- Service mesh-level XSS detection (e.g., Envoy filters that detect XSS payloads in transit between services) was not covered by any source.
