# Passive API Discovery: Attack Surface Foundations — Agent Chunk 06a
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Understand what constitutes an API attack surface to guide comprehensive discovery and testing
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this knowledge to identify ALL layers of an API's attack surface before testing. When assessing a target, systematically check each layer (endpoint, data, auth, infrastructure, integration). Pay special attention to shadow APIs (undocumented endpoints left in production) and zombie APIs (deprecated but still accessible versions) — these are frequently the most vulnerable targets.

---

## 1. API Attack Surface Discovery

### 1.1 What Constitutes the API Attack Surface

The API attack surface encompasses every point where an attacker can attempt to interact
with, extract data from, or manipulate the behavior of an API. Unlike traditional web
application attack surfaces that focus on rendered HTML pages and form submissions, the API
attack surface is defined by programmatic interfaces, data serialization formats, and
machine-to-machine communication patterns.

The attack surface of an API is composed of:

**Endpoint Layer:**
- Every URI path that accepts HTTP requests
- Every HTTP method supported by each path (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, TRACE)
- Every URL path parameter, query parameter, and fragment
- Versioned endpoints (v1, v2, v3) that may coexist with differing security controls
- Aliased endpoints that route to the same handler through different paths

**Data Layer:**
- Request body schemas (JSON, XML, form-encoded, multipart, protobuf, MessagePack, YAML)
- Request headers (custom headers, authorization headers, content negotiation)
- Response body schemas and data exposure
- Error response content and verbosity
- Pagination mechanisms and data enumeration vectors
- File upload and download mechanisms

**Authentication and Authorization Layer:**
- Authentication endpoints (login, register, password reset, token refresh)
- Token issuance and validation mechanisms
- Session management interfaces
- OAuth 2.0 flows and token exchange endpoints
- API key validation and provisioning endpoints
- Multi-factor authentication interfaces

**Infrastructure Layer:**
- API gateway configuration and routing rules
- Load balancer behavior and header handling
- CDN caching behavior with API responses
- CORS policy configuration
- Rate limiting implementations
- TLS configuration and certificate handling
- WebSocket upgrade endpoints
- Server-Sent Events (SSE) streams
- gRPC service definitions and reflection

**Integration Layer:**
- Webhook registration and delivery endpoints
- Callback URLs and redirect URIs
- Third-party API integrations exposed through the target
- Event streaming interfaces (Kafka consumers/producers exposed via HTTP)
- Message queue interfaces exposed as APIs

### 1.2 External vs. Internal API Surface

Understanding the distinction between external and internal API surfaces is critical
because security controls, documentation practices, and testing rigor differ vastly
between them.

**External API Surface:**
External APIs are those intentionally exposed to consumers outside the organization. They
are typically:
- Published with documentation (Swagger/OpenAPI, developer portals)
- Protected by API gateways with rate limiting, authentication enforcement, and input validation
- Versioned to maintain backward compatibility
- Subject to regulatory compliance (PCI DSS, HIPAA, GDPR data exposure)
- Monitored for abuse and anomalous usage patterns

External APIs include:
- Public APIs offered as a product or service
- Partner APIs with restricted access for B2B integrations
- Mobile application backend APIs
- Single-page application (SPA) backend APIs
- IoT device communication APIs

**Internal API Surface:**
Internal APIs are those designed for communication within the organization's infrastructure.
They are frequently:
- Undocumented or poorly documented
- Lacking authentication entirely (relying on network segmentation)
- Missing authorization checks (trusting the calling service)
- Running on non-standard ports without TLS
- Accessible from unexpected network segments due to misconfigured firewalls, VPNs, or cloud security groups

Internal APIs include:
- Microservice-to-microservice communication
- Service mesh control plane APIs
- Container orchestration APIs (Kubernetes API server)
- Internal admin and management interfaces
- Health check and monitoring endpoints
- Database admin APIs (Elasticsearch, MongoDB HTTP interfaces)
- Message broker management APIs (RabbitMQ management, Kafka REST proxy)

**The Blurred Boundary:**
In practice, the boundary between external and internal is often porous:
- Cloud misconfigurations expose internal APIs to the internet
- VPN split-tunneling allows access to internal APIs from compromised endpoints
- SSRF vulnerabilities turn external APIs into gateways to internal services
- API gateways may route to internal services without proper access controls
- Container networking misconfigurations expose internal service ports
- Service mesh ingress controllers may not enforce mTLS consistently

### 1.3 Shadow APIs

Shadow APIs are undocumented API endpoints that exist in production but are not part of
the official API inventory. They represent one of the most significant and frequently
overlooked components of the API attack surface.

**Sources of Shadow APIs:**

1. **Developer Testing Endpoints Left in Production:**
   - Debug endpoints (`/api/debug/users`, `/api/test/reset`)
   - Data seeding endpoints (`/api/seed`, `/api/fixtures/load`)
   - Feature flag override endpoints (`/api/internal/features/toggle`)
   - Performance profiling endpoints (`/api/profiling/start`)
   - Log level adjustment endpoints (`/api/admin/loglevel`)

2. **Framework-Generated Endpoints:**
   - Spring Boot Actuator endpoints (`/actuator/env`, `/actuator/beans`, `/actuator/heapdump`)
   - Django admin interface (`/admin/`)
   - Rails development tools (`/rails/info/routes`, `/rails/mailers`)
   - ASP.NET diagnostic pages (`/elmah.axd`, `/_diagnostics`)
   - Express.js debug middleware endpoints
   - Laravel Telescope (`/telescope/`)

3. **Auto-Generated CRUD Endpoints:**
   - ORM-generated REST endpoints (Hasura auto-generated GraphQL, PostgREST)
   - Scaffolding tools that generate full CRUD without security review
   - Database admin tools exposed over HTTP (Adminer, phpMyAdmin API endpoints)

4. **Undocumented Feature Endpoints:**
   - Beta feature APIs deployed but not publicly announced
   - A/B testing configuration endpoints
   - Internal analytics collection endpoints
   - Feature-gated endpoints accessible by manipulating headers or tokens

5. **Orphaned Microservice Endpoints:**
   - Services that were partially decommissioned
   - Endpoints from merged services that survived refactoring
   - Development microservices with production data access

**Detecting Shadow APIs:**

```
# Check for common framework debug endpoints
curl -s -o /dev/null -w "%{http_code}" https://target.com/actuator/health
curl -s -o /dev/null -w "%{http_code}" https://target.com/actuator/env
curl -s -o /dev/null -w "%{http_code}" https://target.com/actuator/beans
curl -s -o /dev/null -w "%{http_code}" https://target.com/actuator/heapdump
curl -s -o /dev/null -w "%{http_code}" https://target.com/actuator/mappings
curl -s -o /dev/null -w "%{http_code}" https://target.com/actuator/configprops
curl -s -o /dev/null -w "%{http_code}" https://target.com/actuator/trace
curl -s -o /dev/null -w "%{http_code}" https://target.com/actuator/loggers

# Django admin detection
curl -s -o /dev/null -w "%{http_code}" https://target.com/admin/
curl -s -o /dev/null -w "%{http_code}" https://target.com/admin/login/

# Rails routes
curl -s -o /dev/null -w "%{http_code}" https://target.com/rails/info/routes

# Laravel Telescope
curl -s -o /dev/null -w "%{http_code}" https://target.com/telescope/

# Express.js status
curl -s -o /dev/null -w "%{http_code}" https://target.com/status
curl -s -o /dev/null -w "%{http_code}" https://target.com/__coverage__

# GraphQL introspection endpoint variants
curl -s -o /dev/null -w "%{http_code}" https://target.com/graphql
curl -s -o /dev/null -w "%{http_code}" https://target.com/graphiql
curl -s -o /dev/null -w "%{http_code}" https://target.com/playground
curl -s -o /dev/null -w "%{http_code}" https://target.com/console
curl -s -o /dev/null -w "%{http_code}" https://target.com/explorer
```

### 1.4 Zombie APIs

Zombie APIs are deprecated API versions or endpoints that remain operational in production
despite being officially retired. Unlike shadow APIs, zombie APIs were once documented and
known but have fallen out of active maintenance.

**Why Zombie APIs Are Dangerous:**

1. **Security patches are not applied:** When a vulnerability is found and fixed in the
   current API version, the deprecated version often does not receive the fix.
2. **Monitoring blind spots:** Security monitoring, logging, and alerting are typically
   configured for current API versions. Zombie APIs may generate alerts that are ignored or
   are not monitored at all.
3. **Weaker security controls:** Older API versions may predate security improvements such
   as rate limiting, input validation, or modern authentication mechanisms.
4. **Data model inconsistencies:** Older API versions may expose data fields that have since
   been removed from current versions for privacy or security reasons.
5. **Bypass path:** Attackers can often bypass security controls on `/api/v3/` by accessing
   the same functionality through `/api/v1/` which lacks those controls.

**Common Zombie API Patterns:**

```
# Version-based zombie APIs
/api/v1/users          # Deprecated, no rate limiting
/api/v2/users          # Deprecated, weak auth
/api/v3/users          # Current version

# Date-based zombie APIs
/api/2019-01-01/users  # AWS-style versioning, old version still accessible
/api/2023-06-01/users  # Current version

# Path-based zombie APIs
/api/users             # Original unversioned API
/api/v1/users          # First versioned API
/legacy/users          # Explicitly marked legacy but still running
/old/api/users         # Developer-named legacy path

# Subdomain-based zombie APIs
api-v1.target.com      # Old API subdomain still resolving
api-legacy.target.com  # Legacy subdomain with active services
old-api.target.com     # Deprecated but DNS still points to live server
```

**Zombie API Detection Methodology:**

1. Enumerate all known API version prefixes:
   ```bash
   for version in v0 v1 v2 v3 v4 v5 beta alpha legacy old internal dev staging; do
     code=$(curl -s -o /dev/null -w "%{http_code}" "https://api.target.com/${version}/users")
     echo "${version}: ${code}"
   done
   ```

2. Check for date-based versioning:
   ```bash
   for year in 2018 2019 2020 2021 2022 2023 2024 2025; do
     for month in 01 06; do
       code=$(curl -s -o /dev/null -w "%{http_code}" \
         "https://api.target.com/${year}-${month}-01/users")
       echo "${year}-${month}-01: ${code}"
     done
   done
   ```

3. Compare security controls between versions:
   ```bash
   # Test rate limiting on old vs new version
   for i in $(seq 1 100); do
     curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com/v1/users"
   done | sort | uniq -c

   for i in $(seq 1 100); do
     curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com/v3/users"
   done | sort | uniq -c
   ```

### 1.5 Partner / B2B APIs

Partner APIs (also called B2B APIs) serve a unique position in the attack surface because
they exist at the trust boundary between organizations. These APIs often have elevated
privileges compared to public APIs but receive less security scrutiny than internal APIs.

**Characteristics of Partner APIs:**

- Typically authenticated via API keys, mutual TLS (mTLS), or IP allowlisting
- May provide access to bulk data operations not available in public APIs
- Often have weaker rate limiting to accommodate batch processing
- May expose internal identifiers or data structures
- Documentation may be shared in restricted channels (partner portals, emails)
- Access provisioning may bypass standard security review processes

**Attack Vectors Specific to Partner APIs:**

1. **Key Compromise:** Partner API keys are shared via email, documentation portals, or
   support tickets. These channels are vulnerable to interception.
2. **IP Allowlist Bypass:** If partner access is restricted by source IP, SSRF
   vulnerabilities in the partner's infrastructure can be leveraged.
3. **Privilege Escalation:** Partner tokens may have broader permissions than intended,
   allowing access to other partners' data.
4. **Bulk Data Exfiltration:** Partner APIs often support bulk operations (batch fetch,
   export) that amplify the impact of any authorization flaw.

**Discovering Partner APIs:**

- Look for subdomains: `partner.api.target.com`, `b2b.target.com`, `partners.target.com`
- Check for partner documentation portals: `developers.target.com/partners`
- Search for leaked partner API documentation in public code repositories
- Analyze HTTP responses for references to partner-specific endpoints
- Review JavaScript bundles for partner API base URLs
