# GraphQL-Specific Testing Methodology — Agent Chunk 50b
> Source: 10-authorized-testing-hypotheses.md
> Purpose: Execute structured GraphQL security testing: introspection exploitation, query complexity testing, batching abuse, field-level authorization, mutation authorization, subscription security, and federation testing
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Execute GraphQL testing methodology: 1) Introspection — attempt full schema dump, test alternatives if disabled. 2) Query complexity — send nested queries measuring response time, find depth/complexity limits. 3) Batching — send array of queries, verify per-query rate limiting. 4) Field-level auth — request sensitive fields (ssn, password_hash, internal_notes) as each user role. 5) Mutation auth — test admin mutations (deleteUser, updateConfig) with regular tokens. 6) Subscription auth — subscribe to other users' events. 7) Federation — test cross-subgraph authorization boundaries.

---

## 6. GraphQL-Specific Testing Methodology

GraphQL APIs have unique security characteristics that require specialized
testing methodology.

### 6.1 Introspection Testing

**Hypothesis**: GraphQL introspection may be enabled in production, exposing
the complete API schema.

**Test procedure**:

1. Send the standard introspection query:
   ```graphql
   query {
     __schema {
       types {
         name
         fields {
           name
           type {
             name
             kind
           }
           args {
             name
             type {
               name
               kind
             }
           }
         }
       }
       queryType { name }
       mutationType { name }
       subscriptionType { name }
     }
   }
   ```

2. If introspection is disabled, try partial introspection:
   ```graphql
   query {
     __type(name: "User") {
       name
       fields {
         name
       }
     }
   }
   ```

3. Try introspection via GET request (some implementations only block POST).

4. Try introspection with different Content-Type headers.

5. If schema is obtained, analyze for:
   - Sensitive types and fields (financial, PII, internal)
   - Mutation types indicating write operations
   - Deprecated fields that may still be functional
   - Input types revealing validation rules
   - Custom directives indicating security controls

**Expected results**:
- **Vulnerable**: Full schema returned in production environment.
- **Not vulnerable**: Introspection disabled. Partial introspection also
  blocked. Schema not discoverable.

### 6.2 Query Complexity Testing

**Hypothesis**: GraphQL may accept deeply nested or complex queries that consume
excessive server resources.

**Risk level of test**: MEDIUM -- may cause high resource usage. Test carefully.

**Test procedure**:

1. **Depth testing**: Send queries with increasing nesting depth:
   ```graphql
   query {
     users {
       orders {
         items {
           product {
             reviews {
               author {
                 orders {
                   items { ... }
                 }
               }
             }
           }
         }
       }
     }
   }
   ```
   Start at depth 3 and increase by 1 until rejected or depth 10.

2. **Width testing**: Request many fields at each level:
   ```graphql
   query {
     user1: user(id: "1") { id name email }
     user2: user(id: "2") { id name email }
     ...
     user100: user(id: "100") { id name email }
   }
   ```
   Start at 10 aliases and increase until rejected or 100.

3. **Complexity analysis**: If the schema allows circular references
   (User -> Orders -> User -> Orders), test whether the server limits
   the total number of resolved fields.

4. Measure response time and resource consumption at each level.

**Expected results**:
- **Vulnerable**: Server accepts and processes arbitrarily deep/wide queries.
  Response time increases linearly or exponentially with depth/width.
- **Not vulnerable**: Server enforces maximum query depth, maximum query
  complexity score, and/or query cost limits. Queries exceeding limits are
  rejected before execution.

### 6.3 Batching Abuse Testing

**Hypothesis**: GraphQL query batching may be abusable to bypass rate limiting
or perform brute-force attacks in a single request.

**Test procedure**:

1. Test whether batching is supported:
   ```json
   [
     {"query": "{ user(id: \"1\") { id } }"},
     {"query": "{ user(id: \"2\") { id } }"},
     {"query": "{ user(id: \"3\") { id } }"}
   ]
   ```

2. If batching is supported, test limits:
   - How many queries can be batched? Test 10, 100, 1000.
   - Is rate limiting per-request or per-query within a batch?
   - Can login mutations be batched (brute-force in one request)?

3. Test batching for authorization bypass:
   - Batch an authorized query with unauthorized queries
   - Check if authorization is applied per-query or per-batch

**Expected results**:
- **Vulnerable**: Unlimited batching allows brute-force in a single request,
  or rate limiting is per-HTTP-request rather than per-GraphQL-query.
- **Not vulnerable**: Batching is limited or disabled. Rate limiting counts
  individual queries within a batch.

### 6.4 Field-Level Authorization Testing

See H-AUTHZ-05 for the detailed procedure. Additional GraphQL-specific
considerations:

1. **Fragment-based access**: Test if fragments can access fields that direct
   queries cannot.
   
2. **Inline fragment type confusion**: Test accessing fields through union types
   or interfaces.

3. **Directive-based bypass**: Test if custom directives can override
   authorization.

### 6.5 Mutation Authorization Testing

See H-AUTHZ-13 for the detailed procedure. Additional considerations:

1. **Input validation on mutations**: Test whether mutation inputs are validated
   with the same rigor as query arguments.

2. **Mutation side effects**: Document all side effects of mutations (emails
   sent, webhooks triggered, state changes).

3. **Mutation idempotency**: Test whether mutations are idempotent (can be
   safely retried) or if replay can cause duplicate operations.

### 6.6 Subscription Security Testing

**Hypothesis**: GraphQL subscriptions may allow unauthorized access to real-time
data streams.

**Test procedure**:

1. List available subscriptions from the schema.

2. As a low-privilege user, subscribe to events that should be restricted:
   ```graphql
   subscription {
     orderUpdated {
       id
       user { id email }
       status
       total
     }
   }
   ```

3. Check if:
   - Subscription establishment requires authorization
   - Events are filtered by the subscriber's permissions
   - Subscribing to other users' events is possible

4. Test subscription handshake security:
   - Is the WebSocket upgrade authenticated?
   - Are authentication tokens validated for each message?
   - Can an authenticated subscription continue after token revocation?

### 6.7 Federation Testing

For GraphQL Federation (multiple services behind one gateway):

1. **Service boundary testing**: Test if queries can traverse service boundaries
   in ways that bypass per-service authorization.

2. **Key field manipulation**: Test if entity key fields can be manipulated to
   access cross-service data.

3. **Gateway vs. service authorization**: Test if authorization is enforced at
   the gateway, the services, or both. A common finding is authorization at the
   gateway only, which can be bypassed by directly calling service endpoints.

4. **Schema composition leaks**: Check if the federated schema exposes internal
   service names or architecture through type names or directives.

---

