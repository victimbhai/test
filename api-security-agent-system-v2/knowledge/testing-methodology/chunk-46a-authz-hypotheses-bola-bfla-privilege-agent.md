# Testing Hypotheses: Authorization Part 1 — Agent Chunk 46a
> Source: 10-authorized-testing-hypotheses.md
> Purpose: Execute structured authorization test hypotheses: BOLA/IDOR, BFLA, horizontal/vertical privilege escalation, GraphQL field authorization, nested resource authorization, and bulk endpoint authorization
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Execute each hypothesis: H-AUTHZ-01 (BOLA/IDOR — substitute object IDs across users for every endpoint), H-AUTHZ-02 (BFLA — access admin endpoints with regular user tokens), H-AUTHZ-03 (horizontal privilege escalation — tamper user_id/account_id parameters), H-AUTHZ-04 (vertical escalation — add role/isAdmin to request bodies), H-AUTHZ-05 (GraphQL field-level auth — request admin-only fields as regular user), H-AUTHZ-06 (nested resource auth — access /users/{otherUserId}/orders), H-AUTHZ-07 (bulk endpoint auth — mix owned/unowned IDs in batch requests).

---

### 2.2 Authorization Testing Hypotheses

Authorization testing verifies that authenticated users can only access
resources and functions appropriate to their role and identity.

---

#### H-AUTHZ-01: BOLA/IDOR -- Object-Level Authorization Missing

**Hypothesis**: Object-level authorization may be missing, allowing
authenticated users to access resources belonging to other users by
manipulating resource identifiers.

**Risk level of test**: LOW -- accesses test data owned by test accounts.

**Prerequisites**:
- Two test accounts (User A, User B) at the same privilege level
- Known resource IDs for resources owned by each account
- Baseline responses for each account accessing their own resources

**Test procedure**:

1. Authenticate as User A. Record User A's session token.

2. Identify all endpoints that access specific resources by ID:
   - `GET /api/users/{id}`
   - `GET /api/orders/{id}`
   - `GET /api/documents/{id}`
   - `PUT /api/profiles/{id}`
   - `DELETE /api/items/{id}`

3. For each endpoint, submit a request using User A's authentication but
   User B's resource ID.

4. Record the response:
   - **200 OK with User B's data**: BOLA confirmed
   - **403 Forbidden**: Authorization check present
   - **404 Not Found**: May indicate authorization (returns same response
     as non-existent resource) -- compare with response for truly
     non-existent resource IDs to distinguish
   - **200 OK with empty data**: Partial authorization (knows resource
     exists but withholds data) -- still potentially informative

5. Test across all HTTP methods for each endpoint. Authorization may be
   present on GET but missing on PUT or DELETE.

6. Test with different ID formats:
   - If UUIDs are used, test with User B's UUID
   - If numeric IDs are used, test with User B's numeric ID
   - If slugs are used, test with User B's slug

**Expected results**:
- **Vulnerable**: User A can read, modify, or delete User B's resources.
- **Not vulnerable**: All cross-account access returns 403 or an
  indistinguishable 404.

**Evidence collection**:
- Request with User A's token and User B's resource ID
- Response showing User B's data (redact sensitive test data)
- Baseline comparison (User A accessing their own resource vs. User B's)
- Each affected endpoint and HTTP method

---

#### H-AUTHZ-02: BFLA -- Function-Level Authorization Missing

**Hypothesis**: Function-level authorization may be missing, allowing
low-privilege users to access administrative or elevated functions.

**Risk level of test**: LOW-MEDIUM -- attempts to access admin functions
with non-admin credentials. May trigger admin operations if vulnerable.

**Prerequisites**:
- Non-admin test account
- Admin test account (for baseline comparison)
- List of administrative endpoints (from documentation, admin panel
  analysis, or endpoint discovery)

**Test procedure**:

1. Authenticate as the admin account and identify all administrative
   endpoints. Common patterns:
   - `/api/admin/*`
   - `/api/users` (list all users)
   - `/api/config`, `/api/settings`
   - `/api/logs`, `/api/audit`
   - `/api/users/{id}/role` (change user roles)
   - Endpoints that return different data for admin vs. user
   - Bulk operation endpoints
   - Export/import endpoints

2. Record baseline responses for each admin endpoint using the admin token.

3. Authenticate as the non-admin user. Submit requests to each admin endpoint
   using the non-admin token.

4. Compare responses:
   - Same data as admin: BFLA confirmed
   - 403/401: Authorization check present
   - Different data (filtered): Partial authorization, may still be a finding
   - 404: May mask the endpoint's existence from non-admin users

5. Also test:
   - Non-admin user sending POST/PUT/DELETE to admin endpoints
   - Non-admin user accessing admin-only query parameters on shared endpoints
     (e.g., `GET /api/orders?include_all_users=true`)

**Expected results**:
- **Vulnerable**: Non-admin user can access admin functionality or data.
- **Not vulnerable**: All admin endpoints return 403 for non-admin users.

**Evidence collection**:
- Each admin endpoint tested
- Admin response vs. non-admin response
- Specific admin functions accessible to non-admin users
- Impact assessment for each accessible function

---

#### H-AUTHZ-03: Horizontal Privilege Escalation via Parameter Tampering

**Hypothesis**: Users may be able to escalate privileges horizontally by
modifying user-related parameters in requests.

**Risk level of test**: LOW -- modifies requests for test accounts only.

**Prerequisites**:
- Two test accounts at the same level
- Understanding of how user identity is conveyed in requests

**Test procedure**:

1. Identify requests where user identity is included as a parameter
   (separate from the authentication token):
   - `user_id` in request body
   - `owner` field in creation requests
   - `email` in profile update requests
   - `account_id` in query parameters

2. For each such parameter, authenticate as User A and change the user
   identity parameter to User B's identifier while keeping User A's
   authentication token.

3. Check if the operation is performed as User B or rejected.

**Expected results**:
- **Vulnerable**: Operations performed on User B's account using User A's
  authentication combined with User B's identity parameter.
- **Not vulnerable**: Server-side logic uses the authenticated identity, not
  the client-supplied parameter, or validates they match.

---

#### H-AUTHZ-04: Vertical Privilege Escalation via Role Manipulation

**Hypothesis**: Users may be able to escalate their own privilege level by
modifying role or permission fields in profile or registration requests.

**Risk level of test**: MEDIUM -- may change the test account's actual role.
Ensure you can revert.

**Prerequisites**:
- Test account with standard privileges
- Knowledge of role/permission field names and values (from documentation
  or API responses)
- Ability to revert role changes

**Test procedure**:

1. Capture a profile update request or user registration request.

2. Add role/permission fields to the request body that are not normally
   user-editable:
   ```json
   {
     "name": "Test User",
     "email": "test@example.com",
     "role": "admin",
     "is_admin": true,
     "permissions": ["admin", "superuser"],
     "group": "administrators"
   }
   ```

3. Submit the modified request and check:
   - Whether the role/permission fields are accepted (check the updated
     profile response)
   - Whether the account's actual permissions changed (try accessing admin
     endpoints)

4. This overlaps with mass assignment testing (H-AUTHZ-08) but is focused
   specifically on privilege escalation.

**Expected results**:
- **Vulnerable**: Adding role/permission fields to the request body changes
  the account's actual privileges.
- **Not vulnerable**: Role/permission fields in the request body are ignored
  or rejected with an error.

**Evidence collection**:
- Modified request body with added fields
- Response showing whether fields were accepted
- Proof of privilege change (accessing admin endpoints post-modification)
- Reversion confirmation

---

#### H-AUTHZ-05: GraphQL Field-Level Authorization Missing

**Hypothesis**: GraphQL resolvers may lack field-level authorization, exposing
sensitive fields to unauthorized users.

**Risk level of test**: LOW -- queries fields on test data.

**Prerequisites**:
- GraphQL endpoint in scope
- Two test accounts with different privilege levels
- Knowledge of the GraphQL schema (from introspection or documentation)

**Test procedure**:

1. Identify fields that should have restricted access:
   - `User.email`, `User.phone`, `User.address` (PII)
   - `User.role`, `User.permissions` (security-sensitive)
   - `Order.internalNotes` (staff-only)
   - `Product.costPrice` vs `Product.retailPrice`
   - Any field documented as "admin only" or "internal"

2. As a low-privilege user, query for restricted fields on objects the user
   can access:
   ```graphql
   query {
     user(id: "my-id") {
       id
       name
       email
       role
       permissions
       internalNotes
     }
   }
   ```

3. Compare the response with what the admin user receives for the same query.

4. Check for sensitive fields on related objects:
   ```graphql
   query {
     order(id: "my-order") {
       id
       customer {
         id
         email
         paymentMethods {
           cardNumber
           expiry
         }
       }
     }
   }
   ```

**Expected results**:
- **Vulnerable**: Sensitive fields returned to unauthorized users. Fields
  that should be admin-only are visible to regular users.
- **Not vulnerable**: Sensitive fields are null, omitted, or produce an
  authorization error when queried by unauthorized users.

---

#### H-AUTHZ-06: Nested Resource Authorization Bypass

**Hypothesis**: Authorization may be checked on a parent resource but not on
nested child resources, allowing access through relationship traversal.

**Risk level of test**: LOW -- accesses test data through relationship paths.

**Prerequisites**:
- API with nested resources (e.g., `/organizations/{id}/users/{id}`)
- Test accounts in different organizations/scopes

**Test procedure**:

1. Identify nested resource patterns:
   - `/organizations/{orgId}/users/{userId}`
   - `/projects/{projId}/files/{fileId}`
   - `/teams/{teamId}/members/{memberId}`

2. Test accessing a nested resource by:
   - Using authorized `orgId` but unauthorized `userId`
   - Using unauthorized `orgId` but direct `userId`
   - Accessing the child resource directly if an alternative path exists
     (e.g., `/users/{userId}` vs `/organizations/{orgId}/users/{userId}`)

3. For GraphQL, test nested queries that traverse authorization boundaries:
   ```graphql
   query {
     myOrganization {
       users {
         otherOrganizations {
           confidentialData
         }
       }
     }
   }
   ```

**Expected results**:
- **Vulnerable**: Access to child resources bypasses parent authorization,
  or child resources accessible through alternative paths without authorization.
- **Not vulnerable**: Authorization checked at every level of resource nesting.

---

#### H-AUTHZ-07: Bulk Endpoint Authorization Bypass

**Hypothesis**: Bulk operation endpoints may not enforce per-item authorization,
allowing manipulation of resources not owned by the authenticated user.

**Risk level of test**: MEDIUM -- may modify test data in bulk.

**Prerequisites**:
- Endpoints that accept multiple resource IDs (bulk get, bulk update, bulk delete)
- Test resources owned by different accounts

**Test procedure**:

1. Identify bulk endpoints:
   - `POST /api/items/bulk-get` with `{"ids": ["id1", "id2", "id3"]}`
   - `PUT /api/items/bulk-update` with array of items
   - `DELETE /api/items/bulk-delete` with `{"ids": [...]}`
   - `POST /api/export` with filter criteria

2. As User A, include User B's resource IDs in bulk requests alongside
   User A's own resources.

3. Check whether User B's resources are included in the response or
   affected by the operation.

4. Test with only User B's resources (no User A resources included).

**Expected results**:
- **Vulnerable**: Bulk operations process resources across authorization
  boundaries. User B's resources returned or modified through User A's request.
- **Not vulnerable**: Each item in a bulk request is individually authorized.
  Unauthorized items are excluded or cause the entire request to fail.

---

