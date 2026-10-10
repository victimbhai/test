# API Security Schemes, Documentation Gaps & Inventory Templates — Agent Chunk 09b
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Understand OpenAPI security scheme types and their attack implications, identify documentation-vs-implementation inconsistencies, analyze API changelogs, and build structured endpoint inventories
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Review the security schemes defined in the API spec (apiKey, http/bearer, OAuth2, openIdConnect, mutualTLS) and understand the specific attack vectors for each type. Check for common documentation inconsistencies: undocumented parameters, missing auth enforcement, extra HTTP methods, response schema differences. Analyze changelogs for security-relevant changes (deprecated, removed, authentication, permission keywords). Build a comprehensive endpoint inventory with the provided template format, documenting auth requirements, parameters, rate limits, error handling, and security notes for each endpoint.

---


### 4.2 Security Schemes in OpenAPI

OpenAPI supports the following security scheme types:

**1. apiKey:**
```yaml
securitySchemes:
  ApiKeyAuth:
    type: apiKey
    in: header        # header, query, or cookie
    name: X-API-Key   # name of the header/query/cookie parameter

# Security implications:
# - header: Most secure option for API keys
# - query: Key appears in URL, logged everywhere
# - cookie: Subject to CSRF unless additional protection exists
```

**2. http (Bearer, Basic, Digest):**
```yaml
securitySchemes:
  BearerAuth:
    type: http
    scheme: bearer
    bearerFormat: JWT

  BasicAuth:
    type: http
    scheme: basic

# Security implications:
# - bearer: Standard for token-based auth, check token validation
# - basic: Credentials in every request, must have TLS
# - digest: Rarely used in APIs, may have implementation issues
```

**3. oauth2:**
```yaml
securitySchemes:
  OAuth2:
    type: oauth2
    flows:
      authorizationCode:
        authorizationUrl: https://auth.target.com/authorize
        tokenUrl: https://auth.target.com/token
        refreshUrl: https://auth.target.com/refresh
        scopes:
          read:users: Read user data
          write:users: Modify user data
          admin: Administrative access

# Security implications:
# - Test authorization code flow for CSRF, redirect URI validation
# - Test scope enforcement per endpoint
# - Check token lifetimes and refresh token handling
# - Verify PKCE for public clients
```

**4. openIdConnect:**
```yaml
securitySchemes:
  OpenIdConnect:
    type: openIdConnect
    openIdConnectUrl: https://auth.target.com/.well-known/openid-configuration

# Security implications:
# - Fetch and analyze the OpenID Connect configuration
# - Check for supported grant types, signing algorithms
# - Verify token validation implementation
```

**5. mutualTLS (OpenAPI 3.1+):**
```yaml
securitySchemes:
  mTLS:
    type: mutualTLS

# Security implications:
# - Check certificate validation implementation
# - Test with self-signed certificates
# - Verify revocation checking (CRL, OCSP)
```

### 4.3 Documentation vs. Implementation Inconsistencies

Common inconsistencies between API documentation and actual implementation:

1. **Additional undocumented parameters:** Endpoints accept parameters not listed in docs
2. **Missing authentication on documented endpoints:** Docs say auth required but it is not enforced
3. **Extra HTTP methods supported:** Documentation lists GET but POST/DELETE also work
4. **Response schema differences:** Actual responses contain fields not in documentation
5. **Missing rate limits:** Documentation claims rate limiting but none is enforced
6. **Version discrepancies:** v2 documentation but v1 is still accessible with different behavior
7. **Deprecated fields still active:** Fields marked deprecated in docs still functional and accepted
8. **Error response information disclosure:** Actual error responses more verbose than documented

### 4.4 API Changelog Analysis for Security-Relevant Changes

```bash
# Monitor API changelog for security-relevant changes
# Look for patterns like:
# - "deprecated" - may indicate zombie API opportunities
# - "removed" - check if actually removed
# - "authentication" - auth changes may introduce gaps
# - "permission" - authorization changes
# - "rate limit" - rate limit changes
# - "breaking change" - may affect security controls

# Example: Parsing a structured changelog
curl -s https://developer.target.com/changelog.json | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
security_keywords = [
    'auth', 'secur', 'token', 'password', 'permission',
    'deprecat', 'remov', 'rate', 'limit', 'cors', 'csrf',
    'encrypt', 'tls', 'ssl', 'vulnerab', 'fix', 'patch',
    'scope', 'role', 'access', 'key', 'secret'
]
for entry in data:
    text = json.dumps(entry).lower()
    if any(kw in text for kw in security_keywords):
        print(json.dumps(entry, indent=2))
"
```

---

## 5. API Inventory and Cataloging

### 5.1 Building the API Endpoint Inventory

A comprehensive API inventory is the foundation of effective security testing. Each
endpoint should be documented with the following attributes:

**Endpoint Inventory Template:**

```
Endpoint ID: API-001
URL Path: /api/v2/users/{userId}
HTTP Methods: GET, PUT, PATCH, DELETE
Base URL: https://api.target.com

Authentication:
  Required: Yes
  Type: Bearer Token (JWT)
  Token Location: Authorization header
  Additional: None

Authorization:
  GET: User (own profile), Admin (any profile)
  PUT: User (own profile), Admin (any profile)
  PATCH: User (own profile), Admin (any profile)
  DELETE: Admin only

Parameters:
  Path:
    - userId (string, required): UUID of the user
  Query (GET):
    - fields (string, optional): Comma-separated field names to return
    - include (string, optional): Related resources to include
  Body (PUT/PATCH):
    - name (string, optional): User's display name
    - email (string, optional): User's email address
    - role (string, optional): User's role (user, admin) - SENSITIVE
    - status (string, optional): Account status (active, suspended) - SENSITIVE
  Headers:
    - X-Request-ID (string, optional): Request correlation ID
    - If-Match (string, optional for PUT): ETag for optimistic concurrency

Request Content Types: application/json
Response Content Types: application/json

Rate Limiting:
  GET: 100 requests/minute
  PUT/PATCH: 30 requests/minute
  DELETE: 10 requests/minute

Error Handling:
  400: Returns field-level validation errors (JSON)
  401: Returns "Unauthorized" with WWW-Authenticate header
  403: Returns "Forbidden" with reason
  404: Returns "Not Found" (no information disclosure)
  429: Returns "Too Many Requests" with Retry-After header
  500: Returns generic "Internal Server Error" (no stack trace)

Security Notes:
  - PUT allows role change - test for privilege escalation
  - PATCH partial update - test for mass assignment
  - DELETE requires admin - test with user token
  - userId in path - test IDOR with other user IDs
  - fields parameter - test for SQL injection
  - include parameter - test for resource inclusion bypass
```

### 5.2 Inventory Data Model

```json
{
  "api_inventory": {
    "target": "target.com",
    "scan_date": "2025-01-15",
    "endpoints": [
      {
        "id": "API-001",
        "path": "/api/v2/users/{userId}",
        "methods": {
          "GET": {
            "auth_required": true,
            "auth_type": "bearer",
            "authorization_levels": ["user_self", "admin"],
            "parameters": {
              "path": [
                {"name": "userId", "type": "string", "format": "uuid", "required": true}
              ],
              "query": [
                {"name": "fields", "type": "string", "required": false},
                {"name": "include", "type": "string", "required": false}
              ]
            },
            "response_codes": [200, 400, 401, 403, 404],
            "rate_limit": {"requests": 100, "window": "1m"},
            "data_classification": "PII",
            "test_priority": "HIGH"
          },
          "PUT": {
            "auth_required": true,
            "auth_type": "bearer",
            "authorization_levels": ["user_self", "admin"],
            "parameters": {
              "path": [
                {"name": "userId", "type": "string", "format": "uuid", "required": true}
              ],
              "body": {
                "content_type": "application/json",
                "fields": [
                  {"name": "name", "type": "string", "sensitive": false},
                  {"name": "email", "type": "string", "sensitive": true},
                  {"name": "role", "type": "string", "sensitive": true, "note": "privilege_escalation_vector"},
                  {"name": "status", "type": "string", "sensitive": true}
                ]
              }
            },
            "response_codes": [200, 400, 401, 403, 404, 422],
            "rate_limit": {"requests": 30, "window": "1m"},
            "data_classification": "PII",
            "test_priority": "CRITICAL"
          }
        },
        "tags": ["users", "pii", "idor_candidate"],
        "discovered_via": ["openapi_spec", "traffic_analysis"],
        "notes": "User management endpoint - high priority for BOLA/IDOR testing"
      }
    ]
  }
}
```
