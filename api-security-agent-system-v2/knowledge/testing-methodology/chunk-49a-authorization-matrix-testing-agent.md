# Authorization Matrix Testing Methodology — Agent Chunk 49a
> Source: 10-authorized-testing-hypotheses.md
> Purpose: Build and execute a complete authorization matrix covering all role/endpoint/method combinations with automated testing tools and comparison logic
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Build the authorization matrix: 1) List all API endpoints. 2) List all user roles. 3) For each role x endpoint x method combination, define expected behavior (allow/deny). 4) Execute automated testing using Autorize or custom scripts that replay requests with different role tokens. 5) Compare actual vs expected results. 6) Flag any case where a lower-privilege role can access a higher-privilege endpoint. Handle dynamic data (changing IDs, timestamps) in response comparison. Document all findings with evidence.

---

## 3. Authorization Matrix Testing

### 3.1 Building the Complete Authorization Matrix

An authorization matrix maps every combination of role, endpoint, HTTP method,
and expected outcome. It is the most systematic way to verify authorization
enforcement.

#### 3.1.1 Matrix Structure

```
Endpoint          | Method | Unauth | User A | User B | Admin | Description
------------------|--------|--------|--------|--------|-------|------------
/api/users        | GET    | 401    | 200*   | 200*   | 200   | List users
/api/users/{id}   | GET    | 401    | 200(A) | 200(B) | 200   | Get user
/api/users/{id}   | PUT    | 401    | 200(A) | 403    | 200   | Update user
/api/users/{id}   | DELETE | 401    | 403    | 403    | 200   | Delete user
/api/admin/config | GET    | 401    | 403    | 403    | 200   | Get config
/api/orders       | POST   | 401    | 200    | 200    | 200   | Create order
/api/orders/{id}  | GET    | 401    | 200(A) | 200(B) | 200   | Get order
```

Legend:
- `200` = access granted
- `200*` = access granted, but response may be filtered
- `200(A)` = access granted only to own resources
- `401` = authentication required
- `403` = access denied (authenticated but unauthorized)

#### 3.1.2 Building the Matrix

Step 1: **Enumerate all endpoints** from documentation, specification files,
and endpoint discovery.

Step 2: **Enumerate all HTTP methods** for each endpoint (from OPTIONS response
and documentation).

Step 3: **Enumerate all roles** (from documentation, account provisioning,
and application analysis).

Step 4: **Document expected behavior** for each cell. This requires input from
the application owner -- assumptions about intended behavior lead to false
positives and false negatives.

Step 5: **Add resource ownership variants**. For each endpoint that handles
specific resources, add rows for "own resource" and "other user's resource."

#### 3.1.3 Matrix Size Considerations

For a typical API with:
- 50 endpoints
- 4 HTTP methods each (GET, POST, PUT, DELETE)
- 4 roles (unauthenticated, user, moderator, admin)
- 2 ownership states (own, other's) for applicable endpoints

The matrix may have 50 x 4 x 4 x 2 = 1,600 test cases. This is why
automation is essential.

### 3.2 Automated Authorization Matrix Testing

#### 3.2.1 Automation Strategy

The automation flow:

1. **Token collection**: Authenticate as each role and store the token/session.

2. **Baseline capture**: For each endpoint+method combination, send a request
   with the highest-privilege account. Record the expected "authorized"
   response pattern (status code, response structure).

3. **Matrix execution**: For each cell in the matrix, send the request with the
   corresponding role's authentication. Record the actual response.

4. **Comparison**: Compare each actual response against the expected outcome
   from the matrix. Flag discrepancies.

#### 3.2.2 Automated Comparison Logic

For each test case:

```
IF expected == "401" AND actual_status != 401:
    FINDING: "Endpoint accessible without authentication"
    
IF expected == "403" AND actual_status == 200:
    FINDING: "Authorization bypass -- role has unauthorized access"
    
IF expected == "200(own)" AND actual_status == 200 AND resource_owner != authenticated_user:
    FINDING: "BOLA -- access to another user's resource"
    
IF expected == "200" AND actual_status == 403:
    NOTE: "Possible over-restriction -- may be intentional"
```

#### 3.2.3 Handling Dynamic Data

Automated matrix testing must handle:

- **Resource IDs**: Template resource IDs in test cases and replace with
  actual IDs for each test account at runtime.
- **CSRF tokens**: Fetch new CSRF tokens for each session.
- **Token expiration**: Refresh tokens during long test runs.
- **Rate limiting**: Respect rate limits; add delays between requests.
- **State dependencies**: Some endpoints require prior state (an order must
  exist before it can be fetched). Arrange test data before matrix execution.

### 3.3 Role/Endpoint/Method Combinations

#### 3.3.1 Priority Matrix

Not all cells have equal priority. Focus first on:

**Critical priority**:
- Admin endpoints accessible to non-admin roles
- Any endpoint accessible to unauthenticated users that shouldn't be
- Write operations (POST/PUT/DELETE) on other users' resources
- Endpoints that handle sensitive data (PII, financial, health)

**High priority**:
- Read access to other users' resources
- Endpoints with different behavior per API version
- Bulk operation endpoints
- Export/download endpoints

**Medium priority**:
- Non-sensitive read endpoints with overly broad access
- Endpoints with filtered but not blocked access
- Search endpoints that return unauthorized data in results

**Lower priority**:
- OPTIONS/HEAD method responses
- Non-sensitive configuration endpoints
- Public documentation endpoints

#### 3.3.2 Systematic Verification

For each combination, verify:

1. **Status code is correct**: 401/403 for unauthorized, 200 for authorized.
2. **Response body is appropriate**: Unauthorized responses should not contain
   the protected data, even partially.
3. **Response headers are consistent**: No data leakage through headers
   (e.g., `X-Total-Count` revealing record count to unauthorized users).
4. **Timing is consistent**: Response time for authorized vs. unauthorized
   should not reveal whether the resource exists (timing oracle).

### 3.4 Tool-Assisted Testing

#### 3.4.1 Using Burp Suite AuthMatrix Extension

AuthMatrix automates authorization matrix testing within Burp Suite:

1. **Configure roles**: Create entries for each test role with their
   authentication tokens.
2. **Capture requests**: Browse the application through Burp and send requests
   to AuthMatrix.
3. **Define expected outcomes**: Mark each role+endpoint combination as
   expected success or failure.
4. **Run**: AuthMatrix replays each request with each role's token.
5. **Review**: Green cells match expected outcomes; red cells are potential
   findings.

#### 3.4.2 Using Burp Suite Autorize Extension

Autorize is a passive authorization testing tool:

1. **Configure**: Set the low-privilege user's authentication header/cookie.
2. **Browse**: Navigate the application as the high-privilege user.
3. **Observe**: Autorize automatically replays each request with the
   low-privilege token and compares responses.
4. **Review**: Responses marked as "bypassed" indicate authorization failures.

#### 3.4.3 Custom Scripts

For APIs without a browser-based UI, custom scripts are often necessary.

Script requirements:
- Accept the authorization matrix as input (CSV or JSON)
- Authenticate as each role and manage token lifecycle
- Execute each test case with the appropriate authentication
- Compare actual responses with expected outcomes
- Generate a report of discrepancies
- Include rate limiting and error handling
- Support dry-run mode

---

