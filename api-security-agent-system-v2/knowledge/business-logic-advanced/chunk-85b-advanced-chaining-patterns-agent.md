# Advanced Chaining Patterns (2026 Verified) — Agent Chunk 85b
> Source: Deep Internet Research 2026 (Adversarially Verified)
> Purpose: Understand 5 new verified multi-vulnerability chaining patterns that combine 2026 CVEs into complete attack chains, with step-by-step flow, preconditions, detection points, and agent coordination requirements
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
When planning multi-stage attacks or assessing compound risk, use these 5 verified chaining patterns as blueprints. Each chain combines individually medium-severity vulnerabilities into critical-impact attack paths. Coordinate with the appropriate hunter agents at each stage — no single agent covers an entire chain. Detection is most effective at the TRANSITION POINTS between chain stages, not at individual vulnerability exploitation. These chains represent the real-world attack patterns adversaries use in 2026.

---

## 1. JWE Envelope Cloak Chain

### 1.1 Chain Flow

```
Stage 1: JWKS Public Key Harvesting
    |  GET /.well-known/jwks.json
    |  Extract server RSA public key
    v
Stage 2: JWE-Wrapped Unsigned JWT Construction
    |  Create PlainJWT (alg:none) with admin claims
    |  Wrap in JWE using server public key (RSA-OAEP-256 + A128GCM)
    |  Content-type: JWT signals nested JWT inside JWE
    v
Stage 3: Identity Forgery via CVE-2026-29000
    |  Server decrypts JWE with private key
    |  toSignedJWT() returns null for PlainJWT
    |  Signature verification SKIPPED
    |  Admin identity assumed from unverified claims
    v
Stage 4: Admin BOLA (Broken Object-Level Authorization)
    |  Access admin-only API endpoints with forged identity
    |  Enumerate and access other users' resources
    |  Extract tenant configuration data
    v
Stage 5: SSO Federation Compromise
    |  Use admin access to modify SSO federation settings
    |  Add attacker-controlled IdP to federation trust
    |  Persistent backdoor access across all federated services
```

### 1.2 Preconditions

| Requirement | Detail |
|-------------|--------|
| Target library | pac4j-jwt < 4.5.9, 5.7.9, or 6.3.3 |
| JWKS endpoint | Server publishes RSA public key at /.well-known/jwks.json |
| JWE support | Server accepts JWE tokens (RSA-OAEP-256 algorithm) |
| Admin API | API has admin-only endpoints accessible via JWT claims |
| SSO federation | Target participates in SSO federation with configurable IdPs |

### 1.3 Detection Points

```python
# Detection at each stage transition
DETECTION_POINTS = {
    "Stage 1->2": {
        "indicator": "Unusual JWKS endpoint access patterns",
        "detection": "Monitor /.well-known/jwks.json access frequency and source IPs",
        "log_query": "path='/.well-known/jwks.json' AND src_ip NOT IN known_services"
    },
    "Stage 2->3": {
        "indicator": "JWE token containing PlainJWT (alg:none)",
        "detection": "Decrypt and inspect JWE tokens for unsigned inner JWTs",
        "log_query": "auth_token_type='JWE' AND inner_jwt_alg='none'"
    },
    "Stage 3->4": {
        "indicator": "Admin API access from newly authenticated identity",
        "detection": "Alert on admin endpoint access from identities with no prior activity",
        "log_query": "endpoint LIKE '/admin/%' AND user_first_seen < 5min"
    },
    "Stage 4->5": {
        "indicator": "SSO federation configuration changes",
        "detection": "Alert on any IdP trust modifications",
        "log_query": "action='modify_federation_trust' OR action='add_idp'"
    },
}
```

### 1.4 Agent Coordination

| Stage | Hunter Agent | Role |
|-------|-------------|------|
| 1-3 | JWT/OAuth Hunter | Detect JWE envelope attacks, test pac4j versions |
| 4 | BOLA/BFLA Hunter | Identify and exploit admin-only endpoints |
| 5 | SSO/Federation Hunter | Test federation configuration access controls |
| All | Chaining Coordinator | Orchestrate multi-stage exploitation flow |

---

## 2. Incomplete Patch Chain

### 2.1 Chain Flow

```
Stage 1: Unicode Prefix Preparation
    |  Obtain server RSA public key (JWKS or certificate)
    |  Prepend U+200B (zero-width space) to PEM string
    |  Modified key: "​-----BEGIN PUBLIC KEY-----\n..."
    v
Stage 2: PEM Regex Evasion (CVE-2026-34950, CVE-2026-107722)
    |  Server's patched PEM detection regex: /^-----BEGIN .../
    |  trim() does NOT strip U+200B
    |  Regex ^ anchor sees U+200B, not '-----BEGIN'
    |  PEM detection FAILS — key treated as non-PEM
    v
Stage 3: Algorithm Confusion (RS256 -> HS256)
    |  PEM key falls through to HMAC verification path
    |  Craft HS256 JWT with admin claims
    |  Sign with modified PEM key as HMAC secret
    |  Server verifies: HMAC(token, public_key) == signature
    v
Stage 4: Identity Forgery
    |  JWT validates successfully — arbitrary claims trusted
    |  Attacker assumes admin identity
    |  Access to all role-restricted endpoints
    v
Stage 5: Full Authentication Bypass
    |  Complete control over JWT claim space
    |  Generate tokens for any user, any role, any tenant
    |  Persistent access — no need for valid credentials
```

### 2.2 Preconditions

| Requirement | Detail |
|-------------|--------|
| Target library | fast-jwt (npm) with PEM detection patch applied |
| Public key access | Server RSA public key obtainable (JWKS, cert, or TLS) |
| Algorithm flexibility | Server accepts both RS256 and HS256 JWTs |
| JavaScript runtime | Server uses ECMAScript trim() (does not strip U+200B) |
| Patch deployed | The PEM detection patch must be in place (pre-patch, standard alg confusion works) |

### 2.3 Detection Points

```python
DETECTION_POINTS = {
    "Stage 1->2": {
        "indicator": "JWKS endpoint reconnaissance",
        "detection": "Monitor public key access patterns",
        "log_query": "path LIKE '%.well-known/jwks%' AND user_agent NOT IN known_clients"
    },
    "Stage 2->3": {
        "indicator": "JWT with HS256 algorithm from RS256-configured client",
        "detection": "Alert on algorithm mismatch between client config and token",
        "log_query": "jwt_alg='HS256' AND client_expected_alg='RS256'"
    },
    "Stage 3->4": {
        "indicator": "JWT claims not matching any registered user",
        "detection": "Cross-reference JWT sub/email claims against user database",
        "log_query": "jwt_sub NOT IN registered_users"
    },
    "Stage 4->5": {
        "indicator": "Multiple distinct identities from same source IP",
        "detection": "Track identity-per-IP ratio anomalies",
        "log_query": "COUNT(DISTINCT jwt_sub) BY src_ip WHERE count > 5 IN 1hour"
    },
}
```

### 2.4 Agent Coordination

| Stage | Hunter Agent | Role |
|-------|-------------|------|
| 1-2 | Encoding Evasion Hunter | Test Unicode prefix bypass on PEM detection |
| 2-3 | JWT/Algorithm Hunter | Execute algorithm confusion with modified key |
| 4-5 | Identity Hunter | Validate forged identity access scope |
| All | Patch Verification Agent | Verify patch completeness post-remediation |

---

## 3. Exception Swallowing Chain

### 3.1 Chain Flow

```
Stage 1: Bogus Algorithm JWT Construction
    |  Craft JWT with unsupported algorithm header (e.g., 'XS512')
    |  Set admin claims in payload
    |  Use garbage signature (will never be verified)
    v
Stage 2: Fail-Open Authentication (CVE-2026-5430)
    |  OAuthAuthenticationInterceptor processes token
    |  jwtValidator.validateToken() throws APIManagementException
    |  catch block swallows exception, returns true
    |  Request proceeds as authenticated with admin claims
    v
Stage 3: Admin API Access
    |  Access WSO2 API Manager admin endpoints
    |  /api/am/admin/v4/apis — list all APIs
    |  /api/am/admin/v4/applications — list all applications
    |  /api/am/publisher/v4/apis — manage API definitions
    v
Stage 4: Configuration Poisoning
    |  Modify API definitions to inject malicious backend URLs
    |  Add pre-request/post-response mediation policies
    |  Inject credential-harvesting middleware
    |  Modify rate limits, CORS policies, security schemes
    v
Stage 5: Supply Chain Compromise
    |  Poisoned API definitions serve all consumers
    |  Credentials harvested from API traffic
    |  Malicious backends inject code/data into responses
    |  All downstream API consumers compromised
```

### 3.2 Preconditions

| Requirement | Detail |
|-------------|--------|
| Target | WSO2 API Manager 4.1.0 through 4.6.0 |
| Authentication | JWT-based authentication via OAuthAuthenticationInterceptor |
| Admin APIs | Admin/Publisher API endpoints accessible from attacker network |
| API consumers | Downstream applications consuming managed APIs |
| No CISA patch | Target has not applied patch from CISA KEV 2026-09-24 |

### 3.3 Detection Points

```python
DETECTION_POINTS = {
    "Stage 1->2": {
        "indicator": "JWT with unknown/unsupported algorithm",
        "detection": "Log and alert on unrecognized algorithm values in JWT headers",
        "log_query": "jwt_alg NOT IN ('RS256','RS384','RS512','ES256','ES384','ES512','PS256','PS384','PS512','HS256','HS384','HS512','EdDSA')"
    },
    "Stage 2->3": {
        "indicator": "Admin API access with exception in auth logs",
        "detection": "Correlate auth exceptions with successful admin endpoint access",
        "log_query": "level='ERROR' AND message LIKE '%APIManagementException%' AND http_status=200"
    },
    "Stage 3->4": {
        "indicator": "API definition modifications outside change window",
        "detection": "Monitor API config changes and compare against change management",
        "log_query": "action='update_api_definition' AND user NOT IN approved_admins"
    },
    "Stage 4->5": {
        "indicator": "API backend URL changes to external domains",
        "detection": "Alert on backend URL modifications pointing to non-corporate domains",
        "log_query": "action='modify_backend_url' AND new_url NOT LIKE '%corp.internal%'"
    },
}
```

### 3.4 Agent Coordination

| Stage | Hunter Agent | Role |
|-------|-------------|------|
| 1-2 | Fail-Open Hunter | Test exception handling paths in auth code |
| 3 | API Discovery Hunter | Enumerate admin endpoints and capabilities |
| 4 | Config Poisoning Hunter | Identify mutable configuration surfaces |
| 5 | Supply Chain Hunter | Assess downstream impact of poisoned APIs |

---

## 4. Multimodal SSRF Chain

### 4.1 Chain Flow

```
Stage 1: AI Endpoint Discovery
    |  Identify OpenAI-compatible multimodal API endpoints
    |  /v1/chat/completions with vision/audio/file support
    |  Check accepted content types (image_url, audio_url, file_url)
    v
Stage 2: Redirect Server Setup
    |  Deploy attacker-controlled HTTP server
    |  Configure 302 redirect: public URL -> 169.254.169.254
    |  URL passes initial validation (public domain)
    v
Stage 3: SSRF via Multimodal Input (CVE-2026-63764)
    |  POST /v1/chat/completions with image_url = redirect URL
    |  _load_http_url validates original URL (public — passes)
    |  Follows 302 redirect to metadata endpoint (no re-validation)
    |  Cloud metadata fetched and processed
    v
Stage 4: IAM Credential Exfiltration
    |  Redirect to /latest/meta-data/iam/security-credentials/
    |  Extract AccessKeyId, SecretAccessKey, SessionToken
    |  Temporary IAM credentials with instance role permissions
    v
Stage 5: Lateral Movement to S3/RDS
    |  Use stolen IAM credentials to access AWS services
    |  List and download S3 buckets (aws s3 ls, aws s3 cp)
    |  Connect to RDS databases via IAM authentication
    |  Access secrets in Secrets Manager or Parameter Store
    |  Potential pivot to other accounts via cross-account roles
```

### 4.2 Preconditions

| Requirement | Detail |
|-------------|--------|
| Target | LMDeploy or similar OpenAI-compatible inference server |
| Multimodal support | Endpoint accepts image_url/audio_url/file_url fields |
| Cloud deployment | Target runs on AWS/GCP/Azure with metadata service accessible |
| IAM role | Instance has IAM role with permissions to cloud resources |
| Redirect following | _load_http_url follows HTTP 302 without re-validating target |
| No IMDSv2 enforcement | AWS metadata accessible via IMDSv1 (no session token required) |

### 4.3 Detection Points

```python
DETECTION_POINTS = {
    "Stage 1->2": {
        "indicator": "Probing multimodal endpoints with unusual URLs",
        "detection": "Log and analyze image_url/audio_url values in API requests",
        "log_query": "endpoint='/v1/chat/completions' AND content LIKE '%image_url%' AND url NOT LIKE '%.png' AND url NOT LIKE '%.jpg'"
    },
    "Stage 2->3": {
        "indicator": "Outbound request following redirect to metadata IP",
        "detection": "Network monitoring for connections to 169.254.169.254 from app servers",
        "log_query": "dst_ip='169.254.169.254' AND src_process='python' AND http_status=302 IN upstream"
    },
    "Stage 3->4": {
        "indicator": "Metadata endpoint access from application process",
        "detection": "IMDSv2 enforcement or iptables rules blocking non-system metadata access",
        "log_query": "dst_ip='169.254.169.254' AND path LIKE '%iam/security-credentials%'"
    },
    "Stage 4->5": {
        "indicator": "IAM credential use from unexpected source IP",
        "detection": "CloudTrail analysis for credential use outside expected CIDR",
        "log_query": "eventSource='s3.amazonaws.com' AND sourceIPAddress NOT IN vpc_cidr"
    },
}
```

### 4.4 Agent Coordination

| Stage | Hunter Agent | Role |
|-------|-------------|------|
| 1 | API Discovery Hunter | Identify multimodal endpoints and accepted fields |
| 2-3 | SSRF Hunter | Execute redirect-based SSRF via multimodal input |
| 4 | Cloud Metadata Hunter | Extract and validate cloud credentials |
| 5 | Cloud Lateral Movement Hunter | Assess credential scope and access cloud resources |

---

## 5. GraphQL Directive Collision Chain

### 5.1 Chain Flow

```
Stage 1: Schema Reconnaissance
    |  Introspection query to map all types, fields, directives
    |  Identify type-level @authentication on Query/Mutation
    |  Identify field-level @authentication with role requirements
    |  Map directive conflicts (type-level shadows field-level)
    v
Stage 2: Type-Level Auth Satisfied (CVE-2026-19869)
    |  Obtain basic-role JWT (any valid JWT, no special roles)
    |  Type-level @authentication requires only valid JWT — satisfied
    |  Field-level @authentication(jwt: { roles_INCLUDES: "admin" }) DROPPED
    |  Stricter directive silently discarded due to precedence bug
    v
Stage 3: Admin Field Access (Privilege Escalation)
    |  Query admin-restricted fields with basic JWT
    |  adminDashboard, managerReports, internalConfig accessible
    |  Full data exfiltration from admin-only resolvers
    |  Enumerate all available admin mutations
    v
Stage 4: Subscription Data Exfiltration (CVE-2026-5423)
    |  Establish WebSocket connection to subscription endpoint
    |  Send forged JWT with admin claims in connectionParams
    |  No signature verification on subscription JWT
    |  @subscriptionsAuthorization directive also dropped
    v
Stage 5: Real-Time Admin Data Stream
    |  Subscribe to admin-only notification streams
    |  Receive real-time updates: user activity, system events, config changes
    |  Persistent exfiltration channel via WebSocket
    |  Attacker monitors admin actions in real-time
```

### 5.2 Preconditions

| Requirement | Detail |
|-------------|--------|
| Target library | @neo4j/graphql >= 5.2.0 with features.authorization |
| Schema pattern | Type-level AND field-level @authentication directives on same type |
| Field-level strictness | Field-level directives STRICTER than type-level |
| Subscriptions | WebSocket subscription endpoint enabled |
| Basic JWT | Attacker can obtain any valid JWT (self-registration, leaked, etc.) |

### 5.3 Detection Points

```python
DETECTION_POINTS = {
    "Stage 1->2": {
        "indicator": "Introspection queries probing directive metadata",
        "detection": "Log introspection queries and alert on high frequency",
        "log_query": "query LIKE '%__schema%' OR query LIKE '%__type%'"
    },
    "Stage 2->3": {
        "indicator": "Basic-role user accessing admin-annotated fields",
        "detection": "Cross-reference JWT roles against field-level requirements in schema",
        "log_query": "jwt_role='viewer' AND field IN admin_annotated_fields"
    },
    "Stage 3->4": {
        "indicator": "WebSocket connection with unsigned/forged JWT",
        "detection": "Verify JWT signatures on WebSocket connectionParams",
        "log_query": "ws_connection AND jwt_signature_valid=false"
    },
    "Stage 4->5": {
        "indicator": "Subscription to admin-only data streams",
        "detection": "Monitor subscription registrations against role requirements",
        "log_query": "subscription_type='adminNotifications' AND jwt_role != 'admin'"
    },
}
```

### 5.4 Agent Coordination

| Stage | Hunter Agent | Role |
|-------|-------------|------|
| 1 | GraphQL Discovery Hunter | Schema introspection and directive mapping |
| 2-3 | GraphQL Auth Hunter | Exploit directive precedence for privilege escalation |
| 4-5 | WebSocket/Subscription Hunter | Test subscription auth bypass and establish exfiltration |
| All | Chaining Coordinator | Orchestrate the full escalation chain |

---

## 6. Cross-Chain Coordination Principles

### 6.1 Transition Point Detection

The most effective detection occurs at the TRANSITION between chain stages, not at individual vulnerability exploitation. Monitor for:

1. **Identity transitions:** A new identity appearing immediately after JWKS access
2. **Privilege jumps:** Basic user accessing admin endpoints within minutes of authentication
3. **Protocol pivots:** HTTP authentication followed immediately by WebSocket subscription
4. **Network pivots:** Application server connecting to metadata endpoint after receiving API request
5. **Configuration changes:** Admin config modifications from newly authenticated identities

### 6.2 Agent Handoff Protocol

```python
# Agent coordination for multi-stage chains
class ChainCoordinator:
    def execute_chain(self, chain_definition):
        for stage in chain_definition.stages:
            # Select appropriate hunter agent
            agent = self.select_agent(stage.agent_type)
            
            # Pass context from previous stage
            stage.context = self.accumulated_context
            
            # Execute stage
            result = agent.execute(stage)
            
            # Accumulate findings for next stage
            self.accumulated_context.merge(result)
            
            # Check if chain should continue
            if not result.success:
                self.report_partial_chain(stage.number)
                break
            
            # Log transition for detection testing
            self.log_transition(stage.number, stage.number + 1, result)
```

### 6.3 Priority Matrix

| Chain | Impact | Complexity | Prevalence | Priority |
|-------|--------|------------|------------|----------|
| JWE Envelope Cloak | Critical (SSO compromise) | Medium | Low-Medium | HIGH |
| Incomplete Patch | Critical (full auth bypass) | Low | Medium | CRITICAL |
| Exception Swallowing | Critical (supply chain) | Very Low | Low (WSO2 specific) | HIGH |
| Multimodal SSRF | Critical (cloud takeover) | Low | High (expanding) | CRITICAL |
| GraphQL Directive | High (data exfiltration) | Low | Medium | HIGH |
