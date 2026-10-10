# Advanced API Attack Vectors: API Gateways, Service Meshes, gRPC/Protobuf, and HTTP/2-HTTP/3

## API Gateway Bypass Attacks (Kong, AWS API Gateway, Apigee, Azure APIM)

### Takeaway
API gateways are routinely bypassed through path normalization mismatches between the gateway's authorization layer and the backend application, with trailing slashes, double encoding, semicolon path parameters, and header overrides all exploited in the wild during 2024-2026. The root cause is almost always that the gateway evaluates security policy against a differently-normalized version of the path than the backend routes on.

### Cited Findings

**Path Normalization Attacks:**
- The RFC leaves the decoding order of URL-encoded paths to each implementation, creating structural mismatches between gateway and backend. Six CVEs across APISIX, Traefik, AWS API Gateway, Spring MVC, ModSecurity, and Apache httpd all share this same flaw class where the ACL evaluates the path at a different normalization state than the backend serves. -- [API Gateway Path Normalization Bypass - DEV Community](https://dev.to/roxdavirox/api-gateway-path-normalization-bypass-when-haproxy-sees-admin-and-your-app-sees-admin-3heh)
- A researcher found that `GET /v1/accounts` returned 401 Unauthorized while `GET /v1/accounts/` returned 200 OK with full account data on an AWS HTTP API endpoint. The same trailing-slash bypass worked on `POST /v1/transfers/`. The cause was a mismatch between greedy route matching and authorization evaluation: the path `/v1/accounts/` matched `/v1/accounts` as a prefix, the authorizer allowed the request, but the integration dropped the auth context. The backend fell back to a system account. A $12,000 bounty was reported. -- [InfoQ: AWS API Gateway Auth Bypass](https://www.infoq.com/news/2026/06/aws-api-gateway-auth-bypass/); [Ecosistema Startup](https://ecosistemastartup.com/?p=83165)
- A fintech application's gateway did not normalize alternative path representations. Requesting `//admin/config` instead of `/admin/config` bypassed the gateway's access-control rule. -- [Bypassing Authentication in a Major API Gateway - Medium](https://medium.com/@dipanshuchhanikar/bypassing-authentication-in-a-major-api-gateway-a-path-normalization-story-5f1bea6d3f08)
- Appending a semicolon and arbitrary text (e.g., `/admin;anything`) bypassed the gateway's path lookup because the backend framework (likely Tomcat or Spring) stripped the semicolon and everything after it, routing to `/admin`. -- [Bypassing Authentication in a Major API Gateway - Medium](https://medium.com/@dipanshuchhanikar/bypassing-authentication-in-a-major-api-gateway-a-path-normalization-story-5f1bea6d3f08)

**Reproduction methodology for path normalization bypass:**
1. Identify the gateway (Kong, AWS API Gateway, Apigee, HAProxy, nginx, Traefik, APISIX)
2. Identify a protected endpoint (e.g., `/admin` returning 401/403)
3. Test variants: trailing slash (`/admin/`), double slash (`//admin`), semicolon (`/admin;foo`), double-URL-encoding (`/%2561dmin`), dot segments (`/./admin`, `/foo/../admin`), case variation (`/Admin`), null bytes (`/admin%00`), unicode normalization (`/adm%C4%B1n`)
4. Compare HTTP response codes and bodies between the canonical path and each variant
5. Tools: Burp Suite Intruder with a path-fuzzing wordlist, custom curl scripts, Nuclei templates for path normalization

**Header Injection/Override Attacks:**
- The `X-Original-URL` and `X-Rewrite-URL` headers can be interpreted by internal proxies or applications to override the request path the gateway authorized. The `X-HTTP-Method-Override` header can change the effective HTTP method from GET to DELETE or PUT, bypassing method-based access controls. Additional headers: `X-Forwarded-Host`, `X-Forwarded-For` for IP-based ACL bypass, `X-Custom-IP-Authorization`. -- [Bug Bounty Edition 2025: Uncommon Headers That Bypass Everything - Medium](https://medium.com/@gasmask/uncommon-headers-that-bypass-everything-almost-bug-bounty-edition-2025-9d2ea65b2076)
- Recommended defense: Strip or explicitly block `X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override`, and similar override headers at the gateway layer before they reach the backend. -- [Proxy/WAF Protections Bypass - HackTricks](https://hacktricks.wiki/en/pentesting-web/proxy-waf-protections-bypass.html)

**HTTP Request Smuggling at the Gateway Layer:**
- APIsec recommends rejecting requests that carry both Content-Length and Transfer-Encoding headers, and stripping obfuscated header variants before they reach backends. Gateway-level smuggling exploits the mismatch between how the gateway and backend parse HTTP message boundaries. -- [HTTP Request Smuggling in API Gateways - APIsec](https://www.apisec.ai/blog/http-request-smuggling-in-api-gateway)

**Kong-Specific CVEs:**
- CVE-2026-6338: HTTP request smuggling and desynchronization flaw affecting Kong Gateway Enterprise 3.4 through 3.14, caused by a parsing problem with untrusted HTTP/1.1 traffic. -- [stack.watch Kong](https://stack.watch/product/konghq/)
- CVE-2021-27306: Access-control bypass in Kong's JWT plugin allowing authentication bypass, fixed in 2.3.2.0, still listed as high severity. -- [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2021-27306)
- Kong Ingress Controller confirmed NOT affected by the 2025 IngressNightmare vulnerabilities (CVE-2025-24513, -24514, -1097, -1098, -1974), which target ingress-nginx. -- [Kong Developer Support](https://developer.konghq.com/support/kong-ingress-controller-is-not-affected-by-ingressnightmare/)
- CVE-2025-1087: Critical template-injection flaw in Kong's Insomnia API client (not the gateway itself) that could allow code execution, reportedly still working in version 11.2.0 despite attempted patches. -- [stack.watch Kong](https://stack.watch/product/konghq/)

### Inferences
- Path normalization is the single most productive gateway bypass class because every gateway and every backend framework has its own normalization behavior, and the RFC does not mandate a single canonical form.
- AWS HTTP API's greedy matching combined with Lambda authorizer's route evaluation creates a structural vulnerability that REST API (with stricter matching) avoids.
- Header injection attacks are particularly dangerous in multi-proxy architectures where an internal reverse proxy may trust headers that the outer gateway did not strip.
- Kong's gateway-layer smuggling vulnerability (CVE-2026-6338) indicates that even mature API gateways remain susceptible to HTTP parsing discrepancies.

### Gaps
- I could not find a comprehensive 2024-2025 CVE list specifically for Kong Gateway (as opposed to other Kong products). The stack.watch listing was incomplete.
- Apigee and Azure APIM-specific CVEs or bypass techniques were not surfaced by the searches. These may be reported through Google Cloud and Microsoft security bulletins respectively.
- No specific payloads for Apigee or Azure APIM path normalization bypasses were found.

---

## Istio/Envoy/Linkerd Service Mesh Sidecar Attacks and mTLS Bypass

### Takeaway
Service mesh mTLS guarantees can be undermined through PERMISSIVE mode defaults, iptables manipulation by privileged containers, header spoofing against Envoy sidecars, and authorization policy misconfigurations. The 2024-2026 Istio security advisories reveal a pattern of header-handling flaws and fail-open conditions that erode the zero-trust promise of service meshes.

### Cited Findings

**Istio/Envoy CVEs (2024-2026):**
- CVE-2024-45806 (ISTIO-SECURITY-2024-006): Istio Ingress Gateway is vulnerable to `x-envoy` header manipulation by external sources. Attackers can inject or spoof `x-envoy-*` internal headers (such as `x-envoy-original-path`, `x-envoy-decorator-operation`) that Envoy trusts when they originate from within the mesh. When injected from outside through the ingress, these headers can manipulate routing decisions, observability data, or authorization evaluations. The same advisory also covers a JWT filter crash with remote JWKs. -- [Istio Security 2024-006](https://istio.io/latest/news/security/istio-security-2024-006/)
- CVE-2024-23326 (ISTIO-SECURITY-2024-004): Incorrect handling of responses to HTTP/1 upgrade requests in Envoy. Envoy accepted an HTTP 200 response as if a protocol upgrade (101 Switching Protocols) had succeeded. This creates a theoretical request smuggling vulnerability if a server can be tricked into adding an `Upgrade` header into a non-101 response. NVD published 06/04/2024. Severity: MEDIUM to HIGH depending on scorer. -- [NVD CVE-2024-23326](https://nvd.nist.gov/vuln/detail/cve-2024-23326); [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2024-23326)
- ISTIO-SECURITY-2026-006: `BackendTLSPolicy` fails open to plaintext on sidecar proxies when its CA reference (ConfigMap) is unresolved. This means mesh upstream traffic falls back to unencrypted plaintext when the TLS CA configuration is missing, directly undermining mTLS guarantees. -- [Istio Security 2026-006](https://istio.io/latest/news/security/istio-security-2026-006/)
- CVE-2026-31838: Envoy RBAC header matching issue that could allow authorization policy bypass when policies rely on HTTP headers that may contain multiple values. An attacker can craft requests with specific header value arrangements that bypass RBAC rules. -- [Istio Security Advisories](https://istio.io/latest/news/)
- CVE-2026-39350: The `serviceAccounts` and `notServiceAccounts` fields in Istio's `AuthorizationPolicy` incorrectly interpret dots (`.`) as a regular expression wildcard matcher instead of a literal dot, potentially matching unintended service accounts. -- [Istio Security Advisories](https://istio.io/latest/news/)
- CVE-2026-48743: HTTP/3-to-HTTP/1 translation-boundary smuggling flaw in Envoy that lets unauthenticated attackers reach backend paths Envoy had denied. Affects Envoy 1.35.0-1.35.10, 1.36.0-1.36.6, 1.37.0-1.37.2, and 1.38.0. CVSS v3.1 base score 7.5 (High). -- [Wiz Vulnerability Database](https://www.wiz.io/vulnerability-database/cve/cve-2026-48743)

**Architectural mTLS Bypass Techniques:**
- Istio's traffic interception uses iptables rules to redirect all inbound and outbound traffic through the Envoy sidecar. An attacker with `NET_ADMIN` capability or `CAP_NET_RAW` in a compromised pod can modify iptables rules to bypass the sidecar entirely, sending traffic directly to the application port without mTLS. -- [AquiLAX: Service Mesh Security](https://aquilax.ai/blog/service-mesh-istio-mtls-bypass)
- Istio's default mTLS mode is `PERMISSIVE`, which accepts both mTLS and plain-text traffic. This means a compromised pod or an attacker who can bypass the sidecar iptables rules can communicate in plaintext. Setting `STRICT` mode is required to enforce mTLS-only communication. -- [AquiLAX: Service Mesh Security](https://aquilax.ai/blog/service-mesh-istio-mtls-bypass)

**Reproduction methodology for sidecar bypass:**
1. Check mTLS mode: `kubectl get peerauthentication --all-namespaces` -- look for `PERMISSIVE` mode
2. Check for containers with `NET_ADMIN` or `CAP_NET_RAW`: `kubectl get pods -o jsonpath='{...securityContext}'`
3. From inside a compromised pod with privileges, list iptables: `iptables -t nat -L -n -v`
4. Attempt to bypass sidecar: connect directly to the application port (typically 8080) on another pod's IP instead of through the service mesh
5. Test `x-envoy-*` header injection from outside the mesh through the ingress gateway
6. Verify AuthorizationPolicy dot-matching: create policies with service account names containing dots and test whether unintended accounts match

**Detection guidance:**
- Monitor for iptables rule changes in pod network namespaces
- Alert on plaintext traffic between mesh-enabled services (use Istio telemetry)
- Audit `PeerAuthentication` policies for `PERMISSIVE` mode
- Validate `AuthorizationPolicy` rules containing dots in service account patterns
- Strip `x-envoy-*` headers at the ingress gateway

### Inferences
- The combination of PERMISSIVE default mode and iptables-based traffic interception creates a dual vulnerability: attackers who gain container-level privileges can both bypass the sidecar AND communicate in plaintext.
- Envoy's role as the data plane for multiple service meshes (Istio, Consul Connect, AWS App Mesh) means that Envoy CVEs have broad blast radius across the service mesh ecosystem.
- The HTTP/3-to-HTTP/1 translation boundary (CVE-2026-48743) represents an emerging class of smuggling attacks as Envoy and other proxies add QUIC/HTTP/3 support.

### Gaps
- Linkerd-specific CVEs and attack techniques were not surfaced by searches. Linkerd uses a different proxy (linkerd2-proxy in Rust) and may have a different vulnerability profile.
- No specific Consul Connect or AWS App Mesh sidecar bypass techniques were found.
- The AquiLAX blog on mTLS bypass is a vendor blog and may not represent primary research. I was unable to verify its claims against Istio's official documentation because WebFetch could not resolve istio.io.

---

## gRPC Reflection Exploitation, Protobuf Deserialization, gRPC-Web Proxy, and Streaming Abuse

### Takeaway
gRPC server reflection left enabled in production exposes the entire API surface to unauthenticated discovery, and combined with missing per-RPC authorization (especially on streaming methods), creates a significant attack surface. Protobuf deserialization vulnerabilities range from DoS through stack exhaustion (CVE-2024-7254) to RCE through schema poisoning (CVE-2026-41242 in protobuf.js), while HPACK table poisoning (CVE-2024-7246) can corrupt proxy-backend communication.

### Cited Findings

**gRPC Reflection Exploitation:**
- The gRPC server reflection service (grpc.reflection.v1.ServerReflection) allows any client to enumerate all registered services, methods, and message types without authentication. Tools like `grpcurl` and `grpcui` can connect to a reflection-enabled server and discover the full API schema. -- [StackHawk: gRPC API Security Best Practices](https://www.stackhawk.com/blog/grpc-api-security-best-practices)
- In production, the reflection service can be exploited to: (1) discover undocumented or internal-only RPC methods, (2) craft valid protobuf messages for any discovered method, (3) identify methods with missing authorization checks, (4) map the full attack surface including admin and debug RPCs. -- [StackHawk: gRPC API Security Best Practices](https://www.stackhawk.com/blog/grpc-api-security-best-practices)

**Reproduction methodology for reflection exploitation:**
1. Probe for reflection: `grpcurl -plaintext target:port list` (returns service names if reflection is enabled)
2. Enumerate methods: `grpcurl -plaintext target:port describe <service.Name>`
3. Get message structure: `grpcurl -plaintext target:port describe <message.Type>`
4. Invoke methods: `grpcurl -plaintext -d '{"field": "value"}' target:port service/Method`
5. For GUI-based exploration: `grpcui -plaintext target:port` opens a web interface
6. For load testing and fuzzing: `ghz --insecure --call service/Method -d '{"field":"fuzz"}' -n 1000 target:port`

**Protobuf Deserialization Vulnerabilities:**
- CVE-2024-7254 (protobuf-java, 2024): Denial-of-service through stack exhaustion. Any project parsing untrusted Protocol Buffers data containing an arbitrary number of nested groups or series of SGROUP tags can exceed the stack limit, causing a crash. Affects protobuf-java, protobuf-javalite, and Ruby bindings. Fixed in protobuf-java 3.25.5, 4.27.5, 4.28.2. -- [SentinelOne Vulnerability Database](https://www.sentinelone.com/vulnerability-database/cve-2024-7254/); [grpc-java issue #11542](https://github.com/grpc/grpc-java/issues/11542)
- CVE-2026-41242 (protobuf.js, 2026): Remote code execution through schema poisoning. An attacker who can influence a protobuf schema (through a compromised schema registry or a gRPC server reflection response) can achieve code execution on the first decode. Affects protobuf.js versions 8.0.0 and earlier, and 7.5.4 and earlier. The library has 52M+ downloads. -- [Cloud Security Alliance Research Note](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_protobufjs-rce-cve-2026-41242_20260420-csa-styled-3.pdf); [Rankiteo Blog](https://blog.rankiteo.com/goog-r1776771217-grpc-google-cloud-vulnerability-april-2026/)
- CVE-2026-33186 (gRPC-Go): Mentioned alongside the AWS API Gateway trailing-slash bypass, this appears to be a path normalization issue in gRPC-Go. Details were sparse in the search results. -- [InfoQ](https://www.infoq.com/news/2026/06/aws-api-gateway-auth-bypass/)
- dlrover gRPC pickle deserialization (December 2024): Arbitrary code execution through Python pickle data embedded in a protobuf `bytes` field in dlrover's gRPC service. An attacker can send maliciously crafted pickle data through the `Message`'s data field, leading to RCE upon deserialization. This is a pickle flaw, not a protobuf flaw, but it demonstrates the risk of embedding unsafe serialization within protobuf messages. -- [GitHub Issue dlrover #1400](https://github.com/intelligent-machine-learning/dlrover/issues/1400)

**HPACK Table Poisoning:**
- CVE-2024-7246: A gRPC client communicating through an HTTP/2 proxy can poison the HPACK dynamic table between the proxy and the backend. This can cause the proxy to send corrupted or attacker-controlled header values to the backend, potentially bypassing authentication or authorization headers. Fixed in gRPC versions 1.58.3, 1.59.5, 1.60.2, 1.61.3, 1.62.3, 1.63.2, 1.64.3, 1.65.4. -- [Tenable CVE-2024-7246](https://tenable.com/cve/CVE-2024-7246)

**gRPC-Web Proxy Exploitation:**
- gRPC-Web proxies (such as Envoy's gRPC-Web filter or grpc-web-proxy) translate between HTTP/1.1 browser requests and HTTP/2 gRPC backend calls. Attack vectors include: SSRF through the proxy when backend destination is controllable, metadata header injection in the gRPC-Web-to-gRPC translation layer, and bypass of authentication that is only enforced at the HTTP/1.1 layer but not propagated to the gRPC backend. -- [Tessl/PurpleAILAB skill listing](https://tessl.io/registry/skills/github/PurpleAILAB/Decepticon/api-grpc) (secondary source, Snyk-flagged as Critical)
- The gRPC-Web protocol uses base64-encoded protobuf in HTTP/1.1 POST bodies, which some WAFs and API gateways cannot inspect, allowing malicious payloads to pass through unexamined. -- Inference based on protocol design

**Bidirectional Streaming Abuse:**
- Streaming RPCs (server-streaming, client-streaming, bidirectional) require different rate-limiting approaches than unary RPCs. Standard API rate limiters that count requests may not properly account for the volume of messages within a single long-lived stream. -- [StackHawk: gRPC API Security Best Practices](https://www.stackhawk.com/blog/grpc-api-security-best-practices)
- A single bidirectional streaming connection can: (1) hold server resources indefinitely if no timeout is enforced, (2) send an unbounded number of messages within a single gRPC stream, evading per-request rate limits, (3) bypass per-connection authentication checks if auth is only validated at stream establishment. -- Inference based on gRPC protocol design and StackHawk guidance

**Tools for gRPC security testing:**
- `grpcurl` -- CLI tool for interacting with gRPC servers, supports reflection, TLS, and metadata injection
- `grpcui` -- Web-based GUI for gRPC server interaction
- `ghz` -- gRPC benchmarking and load testing tool, useful for DoS testing
- `protoc` -- Protocol buffer compiler, used to decode and craft protobuf messages
- `mitmproxy` with gRPC plugin -- intercepting proxy for gRPC traffic inspection

### Inferences
- The protobuf.js schema-poisoning RCE (CVE-2026-41242) is particularly dangerous in architectures where gRPC reflection is used for dynamic schema discovery, because the reflection response itself becomes the attack vector.
- HPACK table poisoning (CVE-2024-7246) represents a novel class of HTTP/2-layer attacks against gRPC that targets the compression state shared between proxy and backend, not the application-layer protocol.
- gRPC-Web's base64 encoding of protobuf payloads effectively blinds traditional WAFs, making the gRPC-Web proxy a trust boundary that many security tools cannot inspect across.

### Gaps
- No specific CVEs for gRPC-Web proxy implementations (Envoy gRPC-Web filter, grpc-web-proxy) were found in searches.
- Bidirectional streaming abuse techniques are primarily inferred from protocol design rather than documented in published exploits or CVEs.
- No specific bug bounty reports on HackerOne/Bugcrowd for gRPC reflection exploitation were surfaced.

---

## H2C Smuggling, HTTP/2 Desync, and QUIC/HTTP/3 API Attacks

### Takeaway
HTTP/2 introduces request smuggling vectors through cleartext upgrade (h2c) smuggling and HTTP/2-to-HTTP/1.1 downgrade desync (H2.CL and H2.TE), while QUIC/HTTP/3 introduces new attack surfaces through connection migration that disrupts middlebox state, amplification DoS through the handshake, and HTTP/3-to-HTTP/1 translation-boundary smuggling (CVE-2026-48743 in Envoy). The HTTP/2 Rapid Reset attack (CVE-2023-44487) remains the most impactful protocol-level API attack, having set DDoS records at 398 million rps.

### Cited Findings

**H2C Smuggling:**
- H2C smuggling abuses the HTTP/1.1 `Upgrade: h2c` mechanism to switch a connection to cleartext HTTP/2. When a reverse proxy forwards the upgrade request without understanding it, the proxy loses content awareness and can no longer enforce access controls. Subsequent HTTP/2 requests on the upgraded connection bypass the proxy's routing rules, WAF inspection, and authentication checks. -- [Bishop Fox: h2c Smuggling Request](https://bishopfox.com/blog/h2c-smuggling-request); [Assetnote: H2C Smuggling in the Wild](https://blog.assetnote.io/2021/03/18/h2c-smuggling)
- Required headers for h2c upgrade: `Upgrade: h2c`, `HTTP2-Settings: <base64-encoded settings>`, `Connection: Upgrade, HTTP2-Settings`. -- [Bishop Fox](https://bishopfox.com/blog/h2c-smuggling-request)
- The h2cSmuggler tool (released by Bishop Fox, later reimplemented in Go by Assetnote) automates the attack. It upgrades connections to cleartext HTTP/2 and can send multiple requests via HTTP/2 multiplexing. Demonstrated impacts include: forging internal headers, accessing restricted administrative endpoints, and Host header SSRF. -- [Bishop Fox Tools](https://bishopfox.com/tools/h2c-smuggling)
- Assetnote reported finding authentication, routing, and WAF bypasses across cloud providers using this technique. PortSwigger ranked it as the top web hacking technique of 2020. -- [Assetnote](https://blog.assetnote.io/2021/03/18/h2c-smuggling)

**Reproduction methodology for h2c smuggling:**
1. Install h2cSmuggler: `git clone https://github.com/BishopFox/h2csmuggler.git`
2. Test if target proxy forwards h2c upgrade: `python3 h2csmuggler.py -x https://target/` -- if the connection upgrades, the proxy is vulnerable
3. Access restricted paths: `python3 h2csmuggler.py -x https://target/ --header "Host: internal-service" -X GET /admin`
4. Alternative: manual testing with curl: `curl -v --http2 --http2-prior-knowledge http://backend:port/admin` (for direct h2c without upgrade)
5. Tools: h2cSmuggler (Python/Go), Burp Suite with HTTP/2 support, curl with `--http2-prior-knowledge`

**HTTP/2 Desync Attacks (H2.CL and H2.TE):**
- James Kettle's 2021 PortSwigger research documents H2.CL and H2.TE desync attacks. These arise when a front-end speaks HTTP/2 to clients but rewrites (downgrades) requests to HTTP/1.1 for the backend. HTTP/2 uses its own framing for message length, but the rewritten HTTP/1.1 request must use `Content-Length` or `Transfer-Encoding`. If the front-end preserves an attacker-supplied `Content-Length` header during the downgrade, the backend uses it instead of the actual body length, creating a desync. -- [PortSwigger: HTTP/2 The Sequel is Always Worse](https://portswigger.net/research/http2)
- **H2.CL desync**: The attacker sends an HTTP/2 request with a `content-length` header that disagrees with the actual DATA frame length. The front-end uses the DATA frame (HTTP/2 native), the backend uses Content-Length (HTTP/1.1), creating a request boundary mismatch. -- [PortSwigger](https://portswigger.net/research/http2)
- **H2.TE desync**: The attacker injects a `transfer-encoding: chunked` header into the HTTP/2 request. HTTP/2 does not use Transfer-Encoding, so the front-end ignores it, but after downgrade to HTTP/1.1, the backend processes it, creating a desync. -- [PortSwigger](https://portswigger.net/research/http2)
- **Header name injection via HTTP/2 pseudo-headers**: HTTP/2 allows characters in header values that HTTP/1.1 interprets as header separators. By injecting `\r\n` sequences in HTTP/2 header values, an attacker can inject additional HTTP/1.1 headers after the downgrade, including `Transfer-Encoding`. -- [PortSwigger](https://portswigger.net/research/http2)
- Tools: Burp Suite (built-in HTTP/2 request smuggling detection since 2021), http2smugl (Wallarm), turbo-intruder. -- [Wallarm Lab](https://lab.wallarm.com/http2smugl-http2-request-smuggling-security-testing-tool/)
- A 2025 arXiv paper proposes HTTP Request Synchronization as a defense against these discrepancy attacks, suggesting that front-ends should reconstruct requests from parsed components rather than forwarding raw bytes. -- [arXiv:2510.09952](https://arxiv.org/pdf/2510.09952)

**Reproduction methodology for HTTP/2 desync:**
1. Identify an HTTP/2 front-end that downgrades to HTTP/1.1 for the backend
2. Use Burp Suite's HTTP/2 request editor to craft requests with mismatched content-length
3. H2.CL test: Send HTTP/2 request with `content-length: 0` but include a body containing a smuggled request prefix
4. H2.TE test: Send HTTP/2 request with injected `transfer-encoding: chunked` header
5. Detect: Look for timeout behavior differences, response queue poisoning, or reflected responses from other users
6. Tools: Burp Suite (HTTP/2 tab), http2smugl, turbo-intruder with HTTP/2 engine

**CVE-2023-44487: HTTP/2 Rapid Reset:**
- Exploited in the wild as a zero-day from August through October 2023. Attackers open many HTTP/2 streams on a single connection and cancel each one immediately with an RST_STREAM frame. The server processes the request before processing the reset, consuming resources for work that is immediately discarded. -- [Anvilogic Threat Report](https://www.anvilogic.com/threat-reports/http2-rapid-reset-ddos-cve-2023); [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-44487)
- Scale records: Google reported 398 million requests per second, Cloudflare 205 million rps, AWS 155 million rps. -- [Anvilogic](https://www.anvilogic.com/threat-reports/http2-rapid-reset-ddos-cve-2023)
- The flaw is believed to impact every web server implementing HTTP/2, including nghttp2, Netty, Envoy, Eclipse Jetty, Microsoft IIS, and Apache Tomcat. CVSS base score 7.5. Listed in CISA KEV on Oct 10, 2023. 448 public PoC repositories reported. -- [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2023-44487/); [HivePro Advisory](https://hivepro.com/wp-content/uploads/2023/10/HTTP2-Zero-Day-Exploited-for-the-Most-Explosive-DDoS-Attacks_TA2023409.pdf)
- Mitigation: Install vendor patches, limit concurrent streams per connection (e.g., `SETTINGS_MAX_CONCURRENT_STREAMS`), rate-limit RST_STREAM frames, monitor for anomalous stream-reset ratios, disable HTTP/2 as a temporary workaround. -- [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-44487)

**QUIC/HTTP/3 Specific API Attacks:**
- **Amplification DoS**: QUIC servers can be abused for amplification attacks through the handshake and connection migration mechanisms. A 2025 study finds that servers often don't enforce the QUIC spec's anti-DoS mechanisms (3x amplification limit). -- [UCLouvain Research](https://research.dial.uclouvain.be/handle/2078.5/256415)
- **Initial Handshake Flooding**: A 2025 proof-of-concept mimics SYN-flood-style attacks against the QUIC initial handshake. Victim machine CPU peaked at 100% during unprotected states and dropped to ~49.95% with protections. The researchers developed a Suricata IDS signature for detection. -- [Mahidol University Research](https://repository.li.mahidol.ac.th/handle/123456789/110697)
- **Connection Migration Disruption**: QUIC's connection migration feature disrupts Layer 3/4 load balancers, rate limiters, and IDS/IPS that depend on connection state tables keyed by source IP and port. When a client migrates its connection to a new IP/port, middleboxes lose tracking state. The spin bit can also serve as a covert channel. -- [IEEE Xplore](https://ieeexplore.ieee.org/document/10427406)
- **HTTP/3-to-HTTP/1 Translation Smuggling** (CVE-2026-48743): Envoy's HTTP/3 front-end incorrectly translates requests when downgrading to HTTP/1 for backends, allowing unauthenticated attackers to reach backend paths that Envoy's routing rules had denied. CVSS 7.5 High. -- [Wiz Vulnerability Database](https://www.wiz.io/vulnerability-database/cve/cve-2026-48743)
- **Implementation CVEs in quic-go**: CVE-2025-64702 -- QPACK header expansion causes excessive memory allocation in HTTP/3 clients and servers. CVE-2025-59530 -- client crash caused by a malicious server sending a premature HANDSHAKE_DONE frame (rated High). -- [Control Assurance Intel](https://intel.controlassurance.com/products/quic-go/index.html)
- **Attack taxonomy** (Azion): UDP/443 floods pressure bandwidth and packet rate; Initial packet floods strain parsing CPU and key derivation; HTTP/3 stream abuse targets application logic (similar to HTTP/2 Rapid Reset but over QUIC). Defenses: address validation tokens, Retry packets, anti-amplification limits, and connection migration validation. -- [Azion: QUIC Flood](https://www.azion.com/en/learning/ddos/what-is-quic-flood-attack/)

### Inferences
- HTTP/2-to-HTTP/1.1 downgrade desync remains the most practical smuggling attack class because many production architectures use HTTP/2 at the edge but HTTP/1.1 internally. The same pattern is now emerging with HTTP/3-to-HTTP/1 translation boundaries (CVE-2026-48743).
- QUIC's connection migration fundamentally breaks the assumptions of IP-based security controls (rate limiters, IDS/IPS, load balancers), creating a new class of evasion rather than a traditional vulnerability.
- The HTTP/2 Rapid Reset pattern will likely be replicated against HTTP/3 stream handling, since QUIC similarly supports stream multiplexing with cancellation.
- H2C smuggling remains relevant in 2024-2026 because many internal services still accept cleartext HTTP/2 upgrades, and many reverse proxies forward `Upgrade` headers they don't understand.

### Gaps
- I could not fetch the full PortSwigger HTTP/2 research paper due to DNS resolution failures. The detailed payloads and specific exploitation steps for H2.CL and H2.TE attacks should be verified against the original paper at portswigger.net/research/http2.
- No specific 2024-2025 HTTP/2 desync CVEs against API gateways (Kong, AWS API Gateway, Apigee) were found; the technique may be more commonly reported in bug bounty programs than in CVE databases.
- HTTP/3 API-specific attack tooling is immature -- no equivalent of h2cSmuggler for QUIC/HTTP/3 smuggling was found.
- Academic papers on QUIC attacks could not be fetched in full; the findings above are from abstracts and snippets only.

---

## Cross-Cutting: Detection Guidance and Defensive Mitigations

### Takeaway
Defense requires a layered approach: canonicalize paths before authorization evaluation, enforce STRICT mTLS mode, disable gRPC reflection in production, implement protocol-aware WAFs that can inspect HTTP/2 and gRPC traffic, and monitor for anomalous stream behavior and protocol upgrades.

### Cited Findings

**Gateway-layer defenses:**
- Canonicalize the request path (resolve dot segments, normalize encoding, strip semicolons) BEFORE evaluating authorization policies. The gateway and backend must see the identical canonical path. -- [DEV Community](https://dev.to/roxdavirox/api-gateway-path-normalization-bypass-when-haproxy-sees-admin-and-your-app-sees-admin-3heh)
- Strip or reject headers that override routing decisions: `X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override`, `X-Forwarded-*` (unless explicitly expected). -- [HackTricks](https://hacktricks.wiki/en/pentesting-web/proxy-waf-protections-bypass.html)
- Reject requests with both `Content-Length` and `Transfer-Encoding` headers. -- [APIsec](https://www.apisec.ai/blog/http-request-smuggling-in-api-gateway)
- Block or restrict `Upgrade: h2c` headers at the reverse proxy unless explicitly needed. -- [Bishop Fox](https://bishopfox.com/blog/h2c-smuggling-request)

**Service mesh defenses:**
- Set Istio `PeerAuthentication` to `STRICT` mode (not `PERMISSIVE`) in production. -- [AquiLAX](https://aquilax.ai/blog/service-mesh-istio-mtls-bypass)
- Strip `x-envoy-*` headers at the ingress gateway before they enter the mesh. -- [Istio Security 2024-006](https://istio.io/latest/news/security/istio-security-2024-006/)
- Restrict container capabilities: drop `NET_ADMIN` and `CAP_NET_RAW` for all workload containers. -- [AquiLAX](https://aquilax.ai/blog/service-mesh-istio-mtls-bypass)

**gRPC defenses:**
- Disable server reflection in production or restrict it to authenticated internal clients. -- [StackHawk](https://www.stackhawk.com/blog/grpc-api-security-best-practices)
- Enforce per-RPC authorization on ALL methods including streaming RPCs. -- [StackHawk](https://www.stackhawk.com/blog/grpc-api-security-best-practices)
- Set maximum message sizes, stream timeouts, and per-stream rate limits. -- [StackHawk](https://www.stackhawk.com/blog/grpc-api-security-best-practices)
- Pin protobuf library versions and audit schema sources; do not trust reflection-supplied schemas for code generation at runtime (CVE-2026-41242). -- [CSA Research Note](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_protobufjs-rce-cve-2026-41242_20260420-csa-styled-3.pdf)

**HTTP/2-HTTP/3 defenses:**
- Limit `SETTINGS_MAX_CONCURRENT_STREAMS` and rate-limit RST_STREAM frames for Rapid Reset mitigation. -- [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-44487)
- For HTTP/2 desync: reconstruct HTTP/1.1 requests from parsed HTTP/2 components rather than forwarding raw bytes. -- [arXiv:2510.09952](https://arxiv.org/pdf/2510.09952)
- For QUIC/HTTP/3: enforce address validation tokens, Retry packets, and the 3x amplification limit. Validate connection migration with path challenge/response. -- [Azion](https://www.azion.com/en/learning/ddos/what-is-quic-flood-attack/)

### Inferences
- Most of these attacks exploit trust boundaries where one component's output is another component's input, with different parsing or normalization. The general defense is to eliminate parsing differentials by canonicalizing at the outermost layer.
- Protocol upgrade and translation boundaries (HTTP/1.1 to HTTP/2, HTTP/2 to HTTP/1.1, HTTP/3 to HTTP/1) are the most productive targets for smuggling attacks and will remain so as long as mixed-protocol architectures exist.

### Gaps
- Quantitative data on the prevalence of these vulnerabilities in production environments was not found.
- Tool-specific detection signatures (Suricata, Snort, Sigma rules) for each attack class were not systematically compiled. The QUIC handshake DoS paper mentions a Suricata signature but I could not fetch the full paper.
