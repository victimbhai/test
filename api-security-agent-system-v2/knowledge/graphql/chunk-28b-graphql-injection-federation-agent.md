# GraphQL Advanced: Injection, Federation & Directive Attacks — Agent Chunk 28b
> Source: 07-advanced-api-vulnerability-classes.md
> Purpose: Test GraphQL APIs for injection vulnerabilities, subscription abuse, federation security issues, persisted query bypass, and directive abuse
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Test GraphQL injection by injecting SQL/NoSQL payloads in query arguments, manipulating custom directives, and testing filter/search arguments for injection. Test subscriptions for unauthorized data access (subscribe to events of other users). In federated GraphQL (Apollo Federation), test cross-service authorization gaps by querying entities from different subgraphs. Test persisted query bypass by sending arbitrary queries when only persisted queries should be allowed. Test directive abuse: @skip, @include with variable manipulation, custom directives for privilege escalation.

---

### 8.5 GraphQL Injection

When GraphQL queries are constructed via string concatenation (rather than parameterized variables), injection is possible:

**Vulnerable server-side code:**

```python
# Server constructs a GraphQL query from user input
def search_users(search_term):
    query = f'''
    {{
      users(search: "{search_term}") {{
        id
        name
        email
      }}
    }}
    '''
    return execute_graphql(query)
```

**Attack:**

```
search_term = ") { id name email } admin: users(search: "
```

Resulting query:

```graphql
{
  users(search: "") { id name email } admin: users(search: "") {
    id
    name
    email
  }
}
```

The attacker has injected a second query that returns all users by searching for an empty string.

### 8.6 Subscription Abuse

GraphQL subscriptions use WebSockets for real-time data. Security issues include:

**Authentication checked only at connection time:**

```javascript
// Server checks auth only when WebSocket connects
const server = new ApolloServer({
  subscriptions: {
    onConnect: (connectionParams) => {
      const token = connectionParams.authToken;
      if (!verifyToken(token)) throw new Error('Unauthorized');
      return { user: decodeToken(token) };
    }
  }
});
```

If the user's permissions change or their token is revoked after the WebSocket connection is established, they continue receiving subscription data.

**Data exfiltration via subscriptions:**

```graphql
subscription {
  userUpdated {
    id
    name
    email
    ssn  # Sensitive field that might not have subscription-level auth
    creditCard
  }
}
```

Subscriptions often have weaker field-level authorization than queries because they are implemented separately.

### 8.7 Federation Vulnerabilities

GraphQL Federation (Apollo Federation) allows multiple GraphQL services to be composed into a single supergraph. The `_entities` query is a federated-only query used to resolve entity references across services.

**_entities query abuse:**

```graphql
{
  _entities(representations: [
    { __typename: "User", id: "admin-user-id" }
  ]) {
    ... on User {
      email
      role
      internalNotes
    }
  }
}
```

If the `_entities` resolver does not apply the same authorization checks as regular query resolvers, an attacker can directly fetch any entity by its type and ID.

**__typename information disclosure:**

```graphql
{
  __typename  # Reveals the root query type name
  
  user(id: 1) {
    __typename  # "User"
    profile {
      __typename  # "UserProfile" - reveals internal type names
    }
  }
}
```

Type names can reveal internal service architecture and implementation details.

### 8.8 Persisted Query Bypass

Persisted queries are a security measure where the server only executes pre-registered queries identified by hashes. Bypass techniques:

```
# Attempt to register a new persisted query
POST /graphql HTTP/1.1
Content-Type: application/json

{
  "extensions": {
    "persistedQuery": {
      "version": 1,
      "sha256Hash": "attacker-computed-hash"
    }
  },
  "query": "{ malicious query }"
}
```

If the server is configured for Automatic Persisted Queries (APQ), it will register any new query on first submission and serve it by hash thereafter. The attacker registers an introspection query or a data exfiltration query as a persisted query.

### 8.9 Directive Abuse

**@deprecated information disclosure:**

```graphql
{
  __type(name: "User") {
    fields(includeDeprecated: true) {
      name
      isDeprecated
      deprecationReason
    }
  }
}
```

Deprecation reasons may reveal upcoming changes, internal field names, or migration plans.

**Custom directive exploitation:**

```graphql
# If the server has a custom @auth directive
# The attacker may be able to override it
{
  user(id: 1) @skip(if: true) {
    secretField
  }
}
```

### 8.10 Real-World CVEs

**CVE-2023-33142 — Hasura GraphQL Engine:**
Unauthorized access to metadata that allowed schema introspection and database enumeration even when introspection was disabled. The `pg_dump` metadata endpoint was accessible without admin authentication in certain configurations.

**CVE-2023-26478 — XWiki GraphQL Plugin:**
The GraphQL plugin for XWiki allowed unauthorized users to access sensitive data through the GraphQL API, including user credentials and configuration details. No authentication was required to access the GraphQL endpoint.

**CVE-2021-41248 — GraphQL Playground:**
Cross-site scripting via malicious GraphQL schema descriptions that were rendered without sanitization in the Playground UI.

**CVE-2022-37616 — graphql-js (prototype pollution):**
The `graphql-js` library was vulnerable to prototype pollution through specially crafted GraphQL documents, which could lead to denial of service or potentially remote code execution.

### 8.11 Detection and Remediation

**Detection:**
- Test introspection access (both `__schema` and `__type`)
- Send deeply nested queries and measure response time/resource consumption
- Test batching with arrays of queries
- Check field-level authorization through different query paths (direct vs. relationship)
- Test for persisted query registration
- Use tools: graphql-cop, InQL Scanner (Burp extension), graphmap

**Remediation:**
- Disable introspection in production (`introspection: false` in Apollo Server)
- Implement query complexity analysis with depth limits and cost limits
- Limit query depth (max 7-10 levels is typical)
- Limit batch sizes (max 5-10 queries per request)
- Implement field-level authorization consistently across all access paths
- Use persisted queries in locked-down mode (do not accept new registrations)
- Apply rate limiting at the operation level, not just the request level
- Validate and limit subscription connections per user
- Audit federation `_entities` resolver authorization

```javascript
// Apollo Server with security configuration
const server = new ApolloServer({
  schema,
  introspection: false,
  plugins: [
    ApolloServerPluginLandingPageDisabled(),
  ],
  validationRules: [
    depthLimit(10),
    costAnalysis({
      maximumCost: 1000,
      defaultCost: 1,
    }),
    queryComplexity({
      maximumComplexity: 2000,
    }),
  ],
});
```
