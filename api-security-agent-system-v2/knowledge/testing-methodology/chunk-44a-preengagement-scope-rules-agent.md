# Pre-Engagement Planning: Scope & Rules of Engagement — Agent Chunk 44a
> Source: 10-authorized-testing-hypotheses.md
> Purpose: Plan API security assessments with proper scope definition, rules of engagement, environment considerations, and baseline traffic capture methodology
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Before testing, establish: 1) Scope — list all in-scope API endpoints, HTTP methods, authentication mechanisms, and explicitly out-of-scope items. 2) Rules of engagement — define testing hours, rate limits to observe, data modification permissions, account creation limits, escalation contacts. 3) Environment — verify whether testing production, staging, or dedicated test environment; understand data sensitivity. 4) Capture baseline traffic to establish normal patterns before testing.

---

## 1. Pre-Engagement Planning

Pre-engagement planning determines the safety, legality, and effectiveness of an
API security assessment. Skipping or abbreviating this phase leads to scope
disputes, accidental production outages, and legal liability. Every item below
must be resolved before the first request leaves a testing tool.

### 1.1 Scope Definition for API Testing

#### 1.1.1 Defining the API Surface

The scope document must enumerate every API surface included in and excluded
from the engagement. A vague scope such as "test the API" is unacceptable.

Scope elements to specify:

| Element | Example | Why It Matters |
|---------|---------|----------------|
| Base URLs | `https://api.example.com/v2/*` | Prevents testing wrong environments |
| API versions | v1 and v2 only | Legacy versions may be explicitly excluded |
| Authentication endpoints | `/auth/login`, `/auth/token` | May require special care |
| Administrative endpoints | `/admin/*` | May be off-limits in production |
| Third-party integrations | Payment gateway callbacks | Usually excluded unless vendor agrees |
| WebSocket endpoints | `wss://ws.example.com/feed` | Different protocol, different testing |
| GraphQL endpoints | `/graphql` | Single endpoint, deep surface |
| Webhook receivers | `/webhooks/stripe` | Testing may trigger real transactions |

#### 1.1.2 Explicit Exclusions

Document what is NOT in scope:

- Infrastructure-level testing (network scanning, port scanning) unless agreed
- Denial-of-service testing (even unintentional high-volume testing)
- Social engineering against employees
- Physical access testing
- Testing against other tenants in multi-tenant environments
- Production database modification
- Third-party API endpoints called by the target
- Any endpoint that processes real financial transactions without a sandbox

#### 1.1.3 Scope Documentation Template

```
SCOPE DEFINITION DOCUMENT
Assessment ID: [unique identifier]
Date: [date]
Client: [organization name]
Assessor: [firm/individual]

IN-SCOPE APIs:
  - Base URL: [URL]
  - Versions: [list]
  - Methods: [GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD]
  - Authentication: [mechanisms to test]
  - Endpoints: [list or "all under base URL"]
  - Rate limit: [max requests/second the tester may send]

OUT-OF-SCOPE:
  - [list every exclusion]

ENVIRONMENT:
  - [production / staging / development]
  - [any environment-specific restrictions]

TESTING WINDOW:
  - Start: [datetime with timezone]
  - End: [datetime with timezone]
  - Blackout periods: [any times to avoid]

EMERGENCY CONTACTS:
  - Technical: [name, phone, email]
  - Management: [name, phone, email]
  - Incident response: [procedure if something breaks]
```

### 1.2 Rules of Engagement for API Assessments

#### 1.2.1 Communication Protocol

Establish before testing begins:

1. **Daily check-ins**: Brief status update to client contact, covering endpoints
   tested, any anomalies observed, and planned activities for the next period.

2. **Critical finding notification**: Define what constitutes a critical finding
   and the maximum time before the client must be notified (typically 24 hours
   for actively exploitable vulnerabilities, immediately for evidence of
   existing compromise).

3. **Escalation path**: Who to contact if testing causes unexpected behavior.
   This must include a phone number, not just email.

4. **Pause/resume authority**: Who can order testing to stop and under what
   circumstances. Both the client and the tester should have stop authority.

5. **Evidence handling**: How screenshots, response data, and logs are stored,
   transmitted, and ultimately destroyed.

#### 1.2.2 Testing Intensity Levels

Define graduated testing intensity:

**Level 1 -- Passive reconnaissance**:
- Read API documentation
- Analyze client-side code
- Review publicly available information
- No active requests beyond normal API usage

**Level 2 -- Active probing (low impact)**:
- Send legitimate but exploratory requests
- Test authentication flows with test accounts
- Check for information disclosure in error messages
- Verify security headers
- Maximum rate: 10 requests/second

**Level 3 -- Active testing (moderate impact)**:
- Authorization boundary testing (BOLA, BFLA)
- Input validation testing with safe payloads
- Business logic testing
- Maximum rate: 5 requests/second, with delays between test sequences

**Level 4 -- Deep testing (higher impact, staging/dev only)**:
- Injection testing with detection-focused payloads
- Race condition testing
- File upload testing
- Maximum rate: as agreed, with immediate monitoring

#### 1.2.3 Data Handling Rules

- **No real user data exfiltration**: If a vulnerability exposes real user data,
  capture the minimum evidence needed (a single redacted record) and stop.
- **Test data only**: Use only provisioned test accounts and test data.
- **Encryption at rest**: All evidence files must be encrypted.
- **Transmission**: Evidence shared only over encrypted channels.
- **Retention**: Define how long evidence is retained and destruction method.
- **PII handling**: If real PII is inadvertently accessed, notify the client
  immediately and delete local copies.

### 1.3 Environment Considerations

#### 1.3.1 Production Environment Testing

When production testing is unavoidable:

**Constraints**:
- Read-only testing preferred; write operations only where reversible
- No bulk operations (mass deletion, mass update)
- No performance testing or load testing
- Testing during low-traffic windows only
- Real-time monitoring by client operations team
- Immediate stop capability
- No testing of endpoints that trigger external side effects (emails, SMS,
  payment processing, webhook calls to third parties)

**Acceptable in production**:
- GET requests to check authorization boundaries
- Authentication flow testing with test accounts
- Security header verification
- CORS configuration testing
- TLS configuration review
- Error message analysis
- API documentation/specification analysis

**Not acceptable in production without explicit, specific approval**:
- Any POST/PUT/DELETE that modifies real data
- Injection testing of any kind
- Race condition testing
- File upload testing
- Rate limiting testing that involves exceeding limits

#### 1.3.2 Staging Environment Testing

The preferred environment for most API security testing.

**Verify before testing**:
- Staging matches production configuration (not always true)
- Staging has the same authentication mechanisms
- Staging has the same authorization logic
- Staging is isolated from production data
- Staging is not connected to production databases
- Staging does not send real notifications (email, SMS, push)
- Staging does not process real payments

**Common staging pitfalls**:
- Staging may have relaxed security controls (different WAF rules, no rate
  limiting, debug mode enabled) -- note these as findings, but do not assume
  production is the same
- Staging may share databases or caches with production -- verify isolation
- Staging may have different API versions deployed
- Staging secrets may be weaker than production (this is itself a finding)

#### 1.3.3 Development Environment Testing

Broadest testing permitted, but findings may not reflect production.

**Advantages**:
- Full injection testing safe
- Race condition testing safe
- Performance impact testing possible
- Database can be reset
- No risk to real users

**Disadvantages**:
- Configuration may differ significantly from production
- Security controls may be partially implemented
- Infrastructure may differ (different cloud provider, no WAF, no CDN)
- May use mock services instead of real integrations

