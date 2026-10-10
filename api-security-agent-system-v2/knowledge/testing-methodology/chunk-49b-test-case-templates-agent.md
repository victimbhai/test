# API Security Test Case Templates — Agent Chunk 49b
> Source: 10-authorized-testing-hypotheses.md
> Purpose: Use standardized test case templates for consistent API security testing including hypothesis statement, test steps, expected results, evidence collection, and batch testing for matrix-style testing
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use the standard test case template for each security test: Hypothesis ID, Title, OWASP Category, CWE Reference, Preconditions, Test Steps (detailed numbered steps), Expected Result, Actual Result, Evidence (screenshots, request/response pairs, status codes), Severity Assessment, Remediation Recommendation. For matrix testing (e.g., BOLA across all endpoints), use the batch template that tests multiple endpoints/parameters systematically in a table format.

---

## 4. Test Case Templates

### 4.1 Standard Test Case Template

```
TEST CASE
=========================================================
Test ID:            [Category]-[Sequence] (e.g., AUTH-01)
Category:           [Authentication | Authorization | Input Validation |
                     Business Logic | Configuration]
Hypothesis:         [What we believe may be true]
Risk Level:         [None | Low | Medium | High | Critical]
Test Risk:          [Impact of the test itself: None | Low | Medium | High]
Environment:        [Any | Staging Only | Dev Only]

PREREQUISITES:
- [ ] [Prerequisite 1]
- [ ] [Prerequisite 2]
- [ ] [Prerequisite 3]

TEST STEPS:
1. [First step]
   Expected intermediate result: [what should happen]
2. [Second step]
   Expected intermediate result: [what should happen]
3. [Third step]
   Expected intermediate result: [what should happen]

EXPECTED RESULT (PASS):
[Description of what a secure system does]
Response code: [expected code]
Response body: [expected content or structure]

EXPECTED RESULT (FAIL):
[Description of what a vulnerable system does]
Response code: [actual code indicating vulnerability]
Response body: [content indicating vulnerability]

EVIDENCE REQUIRED:
- [ ] Request/response pair (baseline)
- [ ] Request/response pair (test)
- [ ] Screenshot or log excerpt
- [ ] Timestamp

RISK ASSESSMENT:
Likelihood:    [Low | Medium | High]
Impact:        [Low | Medium | High | Critical]
Overall Risk:  [Low | Medium | High | Critical]
CVSS Score:    [if applicable]

REMEDIATION REFERENCE:
- [OWASP reference]
- [CWE reference]
- [Specific remediation guidance]

NOTES:
[Additional context, caveats, or observations]
=========================================================
```

### 4.2 Filled Template Examples

#### Example: BOLA Test Case

```
TEST CASE
=========================================================
Test ID:            AUTHZ-001
Category:           Authorization
Hypothesis:         GET /api/orders/{id} does not verify that the
                    authenticated user owns the requested order.
Risk Level:         High
Test Risk:          Low (read-only access to test data)
Environment:        Any

PREREQUISITES:
- [x] User A authenticated with valid token
- [x] User B's order ID known: SECTEST-UserB-Order-002
- [x] Baseline captured: User A accessing own order returns 200

TEST STEPS:
1. Authenticate as User A. Capture the session token.
   Expected: Valid token received.
2. Send GET /api/orders/SECTEST-UserB-Order-002 with User A's token.
   Expected: 403 Forbidden (order belongs to User B).
3. Compare the response with baseline (User A's own order).
   Expected: Response should differ (403 vs. 200).

EXPECTED RESULT (PASS):
The API returns 403 Forbidden. The response body does not contain
User B's order data.
Response code: 403
Response body: {"error": "Forbidden"} or similar

EXPECTED RESULT (FAIL):
The API returns 200 OK with User B's order data.
Response code: 200
Response body: {"id": "...", "user": "UserB", "items": [...]}

EVIDENCE REQUIRED:
- [x] User A's token (redacted)
- [x] Request to own order (baseline, 200)
- [x] Request to User B's order (test case)
- [x] Timestamp of test

RISK ASSESSMENT:
Likelihood:    High (common vulnerability)
Impact:        High (access to other users' orders)
Overall Risk:  High
CVSS Score:    7.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

REMEDIATION REFERENCE:
- OWASP API Security Top 10: API1:2023 Broken Object Level Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
- Fix: Implement server-side ownership verification before returning data.
  The query should include the authenticated user's ID as a filter condition.

NOTES:
Test all HTTP methods on this endpoint (GET, PUT, DELETE, PATCH).
Test with numeric ID variations if IDs are sequential.
=========================================================
```

#### Example: JWT None Algorithm Test Case

```
TEST CASE
=========================================================
Test ID:            AUTH-002
Category:           Authentication
Hypothesis:         The JWT validation library accepts the 'none' algorithm,
                    allowing unsigned tokens.
Risk Level:         Critical
Test Risk:          Low (single request with modified token)
Environment:        Any

PREREQUISITES:
- [x] Valid JWT captured from authenticated session
- [x] JWT uses RSA or ECDSA algorithm (asymmetric)
- [x] JWT decode/encode tooling available

TEST STEPS:
1. Capture a valid JWT. Decode and record the header and payload.
   Header: {"alg": "RS256", "typ": "JWT"}
   Payload: {"sub": "sectest-usera", "exp": [future], ...}
2. Modify the header: {"alg": "none", "typ": "JWT"}
3. Re-encode as: base64url(header).base64url(payload).
   (empty signature, with trailing period)
4. Send GET /api/profile with Authorization: Bearer [modified-token]
5. Also test with "None", "NONE", "nOnE" in the alg field.
6. Also test without the trailing period.

EXPECTED RESULT (PASS):
The API returns 401 Unauthorized. The modified token is rejected.
Response code: 401
Response body: {"error": "Invalid token"} or similar

EXPECTED RESULT (FAIL):
The API returns 200 OK with the user's profile, as if the token
were properly signed.
Response code: 200
Response body: {"id": "sectest-usera", "name": "..."}

EVIDENCE REQUIRED:
- [x] Original JWT (redacted payload)
- [x] Modified JWT with 'none' algorithm
- [x] Response to modified token
- [x] Response to original token (baseline)

RISK ASSESSMENT:
Likelihood:    Medium (requires known vulnerability in JWT library)
Impact:        Critical (complete authentication bypass)
Overall Risk:  Critical
CVSS Score:    9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

REMEDIATION REFERENCE:
- CVE-2015-9235 (original 'none' algorithm vulnerability)
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- Fix: Configure the JWT library with an explicit algorithm allow-list.
  Never accept the algorithm from the token header without validation.

NOTES:
If this succeeds, also test H-AUTH-03 (weak HMAC) and algorithm
confusion attacks (RS256 to HS256).
=========================================================
```

### 4.3 Batch Test Case Template (for Matrix Testing)

For authorization matrix testing, a more compact format is efficient:

```
BATCH TEST: Authorization Matrix -- /api/orders
============================================================
Endpoint: /api/orders/{id}
Resource IDs: UserA=order-001, UserB=order-002

| # | Method | Auth    | Resource  | Expected | Actual | Status |
|---|--------|---------|-----------|----------|--------|--------|
| 1 | GET    | None    | order-001 | 401      |        |        |
| 2 | GET    | UserA   | order-001 | 200      |        |        |
| 3 | GET    | UserA   | order-002 | 403      |        |        |
| 4 | GET    | UserB   | order-001 | 403      |        |        |
| 5 | GET    | Admin   | order-001 | 200      |        |        |
| 6 | PUT    | None    | order-001 | 401      |        |        |
| 7 | PUT    | UserA   | order-001 | 200      |        |        |
| 8 | PUT    | UserA   | order-002 | 403      |        |        |
| 9 | PUT    | UserB   | order-001 | 403      |        |        |
|10 | PUT    | Admin   | order-001 | 200      |        |        |
|11 | DELETE | None    | order-001 | 401      |        |        |
|12 | DELETE | UserA   | order-001 | 200/403  |        |        |
|13 | DELETE | UserA   | order-002 | 403      |        |        |
|14 | DELETE | Admin   | order-001 | 200      |        |        |

Findings: [list any mismatches]
============================================================
```

---

