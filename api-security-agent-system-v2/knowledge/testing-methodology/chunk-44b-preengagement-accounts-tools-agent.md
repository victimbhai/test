# Pre-Engagement Planning: Accounts, Documentation & Tools — Agent Chunk 44b
> Source: 10-authorized-testing-hypotheses.md
> Purpose: Set up test accounts at multiple privilege levels, review API documentation for security gaps, configure testing tools (Burp Suite, Postman, mitmproxy), and capture baseline API traffic
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Set up accounts: request credentials at every privilege level (unauthenticated, basic user, premium user, moderator, admin, API service account). Review documentation: identify inconsistencies between docs and actual behavior, note endpoints with no documented auth requirements, find deprecated endpoints still in docs. Configure tools: Burp Suite with API-specific extensions (AuthMatrix, Autorize, InQL), Postman collections with environment variables for multiple auth tokens, mitmproxy scripts for traffic analysis.

---

### 1.4 Account Provisioning

#### 1.4.1 Minimum Account Requirements

Every API security assessment requires at least the following test accounts,
each created by the client with known credentials:

| Account | Purpose | Requirements |
|---------|---------|-------------|
| User A (standard) | Baseline legitimate user | Standard permissions, populated profile, some data |
| User B (standard) | Horizontal privilege testing | Same permission level as User A, separate data |
| Admin (elevated) | Vertical privilege testing | Administrative permissions |
| No-privilege | Minimum access testing | Authenticated but minimal permissions |
| Unauthenticated | No-auth testing | No credentials at all |

#### 1.4.2 Account Preparation

For each provisioned account:

1. **Document the exact permissions**: List every role, group, and permission
   assigned. This becomes the authorization baseline.

2. **Create test data**: Each account should own distinct, identifiable test
   records. Use a naming convention that makes test data obvious:
   - `SECTEST-UserA-Order-001`
   - `SECTEST-UserB-Profile`
   - Format: `SECTEST-[Account]-[ResourceType]-[Sequence]`

3. **Record resource identifiers**: For each test record, note the resource ID
   used in API paths (UUIDs, numeric IDs, slugs). These are needed for
   authorization boundary testing.

4. **Verify account isolation**: Confirm that User A cannot normally see User B's
   data through the application's intended interface before testing the API.

5. **Multi-tenant accounts**: If the application is multi-tenant, provision
   accounts in at least two tenants with separate test data in each.

#### 1.4.3 Account Matrix

Build a matrix before testing:

```
Account         | Role        | Tenant | Resources Owned    | Token Type
----------------|-------------|--------|--------------------|------------
sectest-usera   | customer    | T1     | order-001, prof-a  | JWT / session
sectest-userb   | customer    | T1     | order-002, prof-b  | JWT / session
sectest-admin   | admin       | T1     | (all T1)           | JWT / session
sectest-t2user  | customer    | T2     | order-003, prof-c  | JWT / session
(unauthenticated)| none       | none   | none               | none
```

### 1.5 API Documentation Review

#### 1.5.1 Documentation Sources to Collect

Before active testing, gather all available documentation:

- **OpenAPI/Swagger specifications**: Check for `/swagger.json`,
  `/openapi.json`, `/api-docs`, `/v2/api-docs`, `/swagger/v1/swagger.json`
- **Postman collections**: Client may share exported collections
- **API developer portals**: Public-facing documentation sites
- **Internal documentation**: Architecture diagrams, data flow diagrams
- **Change logs**: Recent changes may highlight new endpoints
- **GraphQL schema**: Introspection query results or SDL files
- **WSDL/WADL**: For SOAP or REST services with formal descriptions
- **gRPC proto files**: For gRPC-based APIs

#### 1.5.2 Documentation Analysis Checklist

For each documented endpoint, note:

- [ ] HTTP method and path
- [ ] Authentication requirement (documented)
- [ ] Authorization requirement (documented roles/permissions)
- [ ] Request parameters (path, query, header, body)
- [ ] Request body schema
- [ ] Response codes and schemas
- [ ] Rate limiting documentation
- [ ] Pagination parameters
- [ ] Filtering/sorting parameters
- [ ] Deprecated status
- [ ] Version availability

#### 1.5.3 Undocumented Endpoint Discovery

Documented APIs frequently have undocumented endpoints. Discovery methods
(all passive or low-impact):

1. **Client-side code analysis**: JavaScript bundles, mobile app binaries
   often reference endpoints not in public documentation.

2. **API specification differencing**: Compare Swagger/OpenAPI specs across
   versions. Endpoints removed from documentation may still be active.

3. **Wordlist-based discovery**: Using the API's naming conventions, construct
   likely endpoint paths. For example, if `/api/v2/users` exists, check
   `/api/v2/users/export`, `/api/v2/users/bulk`, `/api/v2/users/search`.

4. **HTTP method probing**: For each known endpoint, test all standard HTTP
   methods. A GET-only endpoint may accept PUT or DELETE.

5. **Version probing**: If `/api/v2/resource` exists, check `/api/v1/resource`
   and `/api/v3/resource`.

6. **Path pattern extrapolation**: If the API follows RESTful conventions and
   has `/orders` and `/products`, check for `/invoices`, `/payments`,
   `/shipments`, and other domain-appropriate resources.

### 1.6 Testing Tool Configuration

#### 1.6.1 Proxy Configuration

All API testing traffic should flow through an intercepting proxy for logging
and analysis. Configuration essentials:

- **TLS interception**: Install the proxy CA certificate in all testing tools.
  Verify the target API's real certificate chain separately.
- **Scope filtering**: Configure the proxy to capture only in-scope traffic.
  Exclude your own services, update servers, and unrelated domains.
- **Logging**: Enable full request/response logging for the engagement. This
  is your audit trail.
- **Session management**: Configure the proxy to handle the API's
  authentication mechanism (auto-refresh tokens, cookie handling).

#### 1.6.2 Tool-Specific Setup

For each testing tool in your workflow:

1. **Configure rate limiting**: Set per-tool rate limits below the engagement's
   maximum. Leave headroom for concurrent tools.

2. **Configure user-agent**: Use a distinctive user-agent string agreed with the
   client so their monitoring team can identify your traffic:
   `SecurityAssessment/[EngagementID] ([Assessor])`

3. **Disable auto-scan features**: Turn off any automatic vulnerability scanning
   that might exceed scope or rate limits.

4. **Configure authentication**: Set up token refresh, cookie jars, or API key
   headers as needed for each test account.

5. **Verify connectivity**: Send a single benign request to each in-scope
   endpoint to confirm connectivity and authentication before beginning testing.

#### 1.6.3 Automation Safety Checks

When writing or using automated test scripts:

- Include a scope check: the script should refuse to send requests to domains
  not in the allow-list.
- Include a rate limiter: hard-coded maximum requests per second.
- Include a kill switch: a mechanism to stop all requests immediately.
- Include dry-run mode: show what requests would be sent without sending them.
- Log every request and response for audit purposes.
- Include error handling that stops testing on unexpected 5xx responses (may
  indicate the target is destabilized).

### 1.7 Baseline Traffic Capture

#### 1.7.1 Purpose

Before testing for vulnerabilities, capture baseline behavior for every in-scope
endpoint. This serves three purposes:

1. **Normal behavior reference**: Know what a normal response looks like before
   looking for abnormal ones.
2. **Evidence**: Prove that the endpoint was functional before and after testing.
3. **Test design**: Baseline responses reveal parameter handling, data formats,
   and error behavior that inform test case design.

#### 1.7.2 Baseline Capture Procedure

For each in-scope endpoint:

1. **Send a valid request as each test account**: Record the complete request and
   response, including headers and timing.

2. **Send a request with missing authentication**: Record the response code and
   body. This is the unauthenticated baseline.

3. **Send a request with invalid authentication**: Record the response. Compare
   with the unauthenticated response (differences may leak information).

4. **Send a request with valid authentication but for a non-existent resource**:
   Record the 404 response. Compare with the unauthorized response (differences
   enable resource enumeration).

5. **Note response characteristics**:
   - Response time (average of 3 requests)
   - Response headers (security headers, caching, CORS)
   - Response body structure
   - Error message format
   - Content-type header

#### 1.7.3 Baseline Documentation Format

```
ENDPOINT BASELINE
Endpoint: [method] [path]
Date captured: [date]
Environment: [prod/staging/dev]

AUTHENTICATED (User A):
  Request: [full request]
  Response Code: [code]
  Response Time: [ms]
  Response Headers: [relevant headers]
  Response Body: [structure, not full data]
  Notes: [any observations]

AUTHENTICATED (User B):
  [same structure]

UNAUTHENTICATED:
  Response Code: [code]
  Response Body: [structure]
  Notes: [compare with authenticated]

INVALID AUTH:
  Response Code: [code]
  Response Body: [structure]
  Notes: [compare with unauthenticated]

NON-EXISTENT RESOURCE:
  Response Code: [code]
  Response Body: [structure]
  Notes: [compare with unauthorized]
```

---

