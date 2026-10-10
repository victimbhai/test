# Testing Hypotheses: Authorization Part 2 — Agent Chunk 46b
> Source: 10-authorized-testing-hypotheses.md
> Purpose: Execute structured authorization test hypotheses: mass assignment, tenant isolation bypass, API version authorization inconsistency, webhook/file authorization, GraphQL mutation authorization, HTTP method override, and subscription-level authorization
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Execute each hypothesis: H-AUTHZ-08 (mass assignment — add role/permissions fields to POST/PUT bodies), H-AUTHZ-09 (tenant isolation — access resources from other tenants via ID manipulation), H-AUTHZ-10 (version inconsistency — test same endpoint across API versions for auth gaps), H-AUTHZ-11 (webhook auth bypass — modify/delete other users' webhooks), H-AUTHZ-12 (file access auth — download files belonging to other users), H-AUTHZ-13 (GraphQL mutation auth — execute mutations without proper roles), H-AUTHZ-14 (method override — use X-HTTP-Method-Override to access blocked methods), H-AUTHZ-15 (plan-level auth — access premium features with free account).

---

#### H-AUTHZ-08: Mass Assignment

**Hypothesis**: API endpoints may accept and process fields that the user should
not be able to set, allowing unauthorized modification of object properties.

**Risk level of test**: LOW-MEDIUM -- may modify test account properties.

**Prerequisites**:
- API documentation or schema showing all object fields
- Identification of fields that should be server-controlled

**Test procedure**:

1. Identify fields that should not be client-settable:
   - `id`, `created_at`, `updated_at` (system fields)
   - `is_verified`, `is_active`, `is_admin` (status fields)
   - `role`, `permissions`, `group` (authorization fields)
   - `balance`, `credits`, `subscription_tier` (business fields)
   - `owner_id`, `organization_id` (relationship fields)
   - `price`, `discount` (financial fields on orders/products)

2. Send update requests (PUT/PATCH) with these fields added:
   ```json
   PUT /api/profile
   {
     "name": "Test User",
     "is_verified": true,
     "balance": 999999,
     "role": "admin"
   }
   ```

3. Check the response and a subsequent GET to see if the fields were accepted.

4. Also test during resource creation (POST):
   ```json
   POST /api/orders
   {
     "product_id": "abc",
     "quantity": 1,
     "price": 0,
     "discount": 100,
     "status": "completed"
   }
   ```

**Expected results**:
- **Vulnerable**: Server-controlled fields are modified by client request.
  Account balance, role, or status changed.
- **Not vulnerable**: Server-controlled fields are ignored in the request, or
  the request is rejected with a validation error listing disallowed fields.

---

#### H-AUTHZ-09: Tenant Isolation Bypass

**Hypothesis**: Multi-tenant API may allow cross-tenant data access or
operations.

**Risk level of test**: LOW -- tests cross-tenant access with test accounts.

**Prerequisites**:
- Test accounts in at least two different tenants
- Known resource IDs in each tenant

**Test procedure**:

1. Authenticate as a user in Tenant A.

2. Attempt to access resources belonging to Tenant B:
   - Direct resource access by ID
   - Search/filter endpoints with Tenant B's identifiers
   - API calls with Tenant B's tenant identifier in headers, path, or body
   - GraphQL queries traversing tenant boundaries

3. Attempt to create resources in Tenant B's context:
   - Modify tenant-identifying fields in creation requests
   - Use Tenant B's identifiers in relationship fields

4. Test tenant identifier manipulation:
   - If tenant is in a header (`X-Tenant-ID`), change it
   - If tenant is in the path (`/api/tenants/{id}/...`), change it
   - If tenant is in the JWT claims, this overlaps with token tampering

**Expected results**:
- **Vulnerable**: Cross-tenant data access or resource creation succeeds.
- **Not vulnerable**: All cross-tenant operations rejected. Tenant boundary
  is enforced at the data layer, not just the request parsing layer.

---

#### H-AUTHZ-10: API Version Authorization Inconsistency

**Hypothesis**: Different API versions may have inconsistent authorization
checks, with older versions potentially lacking security controls added in
newer versions.

**Risk level of test**: LOW -- tests same operations across API versions.

**Prerequisites**:
- Multiple API versions accessible (v1, v2, v3)
- Same test accounts valid across versions

**Test procedure**:

1. Identify all available API versions:
   - Path-based: `/api/v1/`, `/api/v2/`
   - Header-based: `Accept: application/vnd.api.v1+json`
   - Query-based: `?version=1`

2. For each authorization finding already identified (or suspected) in the
   current API version, test the same endpoint in all other versions.

3. Even without known findings, test basic BOLA and BFLA checks across all
   versions.

4. Pay special attention to:
   - Deprecated but still active versions
   - Beta or preview versions
   - Undocumented older versions

**Expected results**:
- **Vulnerable**: Authorization checks present in v2 are absent in v1. Or
  newer undocumented v3 endpoints have weaker authorization.
- **Not vulnerable**: Authorization is consistent across all accessible
  API versions.

---

#### H-AUTHZ-11: Webhook Authorization Bypass

**Hypothesis**: Webhook configuration endpoints may lack proper authorization,
or webhook payloads may be delivered without proper authentication.

**Risk level of test**: LOW-MEDIUM -- may configure webhooks that generate
outbound traffic.

**Prerequisites**:
- Webhook functionality in scope
- Test endpoint to receive webhook payloads
- Authorization to configure webhooks

**Test procedure**:

1. **Webhook registration authorization**:
   - Attempt to register webhooks as a low-privilege user
   - Attempt to register webhooks pointing to internal/private URLs (SSRF)
   - Attempt to register webhooks for events the user should not have access to
   - Attempt to modify or delete other users' webhook registrations

2. **Webhook payload security**:
   - Register a webhook and examine the delivered payload
   - Check for HMAC signature on webhook payloads
   - Verify the signature validation process
   - Check for sensitive data in webhook payloads that exceeds the user's
     permission level

3. **Webhook delivery security**:
   - Check if webhook URLs must be HTTPS
   - Check if webhook delivery follows redirects (potential SSRF)
   - Check if webhook retry logic can be abused

**Expected results**:
- **Vulnerable**: Unauthorized webhook registration, payloads without integrity
  verification, or SSRF through webhook URL registration.
- **Not vulnerable**: Webhook operations properly authorized, payloads signed,
  URLs validated against an allow-list.

---

#### H-AUTHZ-12: File Access Authorization

**Hypothesis**: File upload and download endpoints may not enforce authorization,
allowing access to other users' uploaded files.

**Risk level of test**: LOW -- accesses test files.

**Prerequisites**:
- File upload/download functionality in scope
- Test files uploaded by different test accounts
- Known file identifiers for each account's files

**Test procedure**:

1. Upload files from User A and User B. Record the returned file identifiers
   (URLs, IDs, paths).

2. As User A, attempt to access User B's files:
   - Direct URL access
   - API endpoint with User B's file ID
   - Modify the file path/name in the download URL

3. Check for predictable file URLs:
   - Sequential file IDs
   - Timestamp-based paths
   - Username-based paths (`/uploads/userB/file.pdf`)

4. Check signed URL behavior:
   - If signed URLs are used, how long are they valid?
   - Can a signed URL for one file be modified to access another?
   - Can unsigned URLs access files?

5. Check directory listing:
   - Can the upload directory be listed?
   - Does the file storage expose a directory index?

**Expected results**:
- **Vulnerable**: User A can access User B's files through ID manipulation,
  predictable URLs, or directory listing.
- **Not vulnerable**: All file access is authorized. File URLs are
  unpredictable or properly signed with per-user authorization.

---

#### H-AUTHZ-13: GraphQL Mutation Authorization

**Hypothesis**: GraphQL mutations may have weaker authorization than queries,
allowing unauthorized data modification.

**Risk level of test**: MEDIUM -- may modify test data.

**Prerequisites**:
- GraphQL endpoint in scope
- Knowledge of available mutations
- Test data that can be safely modified

**Test procedure**:

1. List all available mutations (from introspection or documentation).

2. Categorize mutations by expected authorization level:
   - User-level: update own profile, create own resources
   - Admin-level: delete users, change configurations
   - System-level: migrations, schema changes

3. As a standard user, attempt each admin-level and system-level mutation:
   ```graphql
   mutation {
     deleteUser(id: "test-user-b-id") {
       success
     }
   }
   ```

4. As a standard user, attempt mutations on other users' resources:
   ```graphql
   mutation {
     updateOrder(id: "user-b-order-id", input: { status: "cancelled" }) {
       id
       status
     }
   }
   ```

5. Check for mutations that change authorization:
   ```graphql
   mutation {
     setUserRole(userId: "my-id", role: ADMIN) {
       id
       role
     }
   }
   ```

**Expected results**:
- **Vulnerable**: Unauthorized mutations succeed. Standard users can perform
  admin mutations or modify other users' data.
- **Not vulnerable**: All unauthorized mutations return authorization errors.

---

#### H-AUTHZ-14: HTTP Method Override Authorization

**Hypothesis**: HTTP method override headers may bypass authorization checks
that are method-specific.

**Risk level of test**: LOW -- tests header-based method override.

**Prerequisites**:
- Knowledge of which HTTP methods are authorized for each endpoint
- Understanding of the web framework in use

**Test procedure**:

1. Identify method override mechanisms supported by the framework:
   - `X-HTTP-Method-Override: DELETE`
   - `X-HTTP-Method: PUT`
   - `X-Method-Override: PATCH`
   - `_method=DELETE` query parameter
   - `_method=DELETE` in request body

2. For an endpoint where DELETE is not authorized for the test user, send a
   POST request with a method override header set to DELETE:
   ```
   POST /api/resources/user-b-id
   X-HTTP-Method-Override: DELETE
   ```

3. Check if the server:
   - Processes the request as a DELETE (authorization bypassed)
   - Processes the request as a POST (override ignored)
   - Rejects the override header

4. Test all override mechanisms for all restricted methods.

**Expected results**:
- **Vulnerable**: Method override headers bypass method-specific authorization.
  A user unauthorized for DELETE can delete resources via POST with override.
- **Not vulnerable**: Authorization is applied after method override resolution,
  or method override is disabled.

---

#### H-AUTHZ-15: Subscription/Plan-Level Authorization

**Hypothesis**: API features restricted to certain subscription plans may be
accessible to users on lower-tier plans.

**Risk level of test**: LOW -- tests feature access with test accounts.

**Prerequisites**:
- Test accounts on different subscription tiers
- Documentation of feature restrictions per tier

**Test procedure**:

1. Identify features documented as restricted to specific plans:
   - Higher API rate limits
   - Premium endpoints (analytics, export, bulk operations)
   - Advanced features (custom fields, integrations, webhooks)
   - Higher storage or usage limits

2. As a lower-tier user, attempt to access premium features:
   - Call premium endpoints directly
   - Exceed lower-tier limits
   - Access advanced configuration options

3. Check for plan enforcement at the API level vs. only in the UI:
   - Features hidden in the UI may be accessible via direct API calls

**Expected results**:
- **Vulnerable**: Lower-tier users can access premium features through
  direct API calls.
- **Not vulnerable**: Plan restrictions enforced at the API layer, not just UI.

---

