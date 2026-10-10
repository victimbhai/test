# GraphQL Protocol Security: Discovery & Introspection — Agent Chunk 32a
> Source: 08-protocol-specific-research.md
> Purpose: Understand GraphQL security fundamentals, discover GraphQL endpoints, and exploit introspection to map the full schema including types, queries, mutations, and subscriptions
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Discover GraphQL endpoints at common paths (/graphql, /gql, /api/graphql, /graphiql, /playground). Send introspection query (__schema) to enumerate all types, queries, mutations, and subscriptions. If introspection is disabled, use field suggestion attacks and tools like Clairvoyance for schema recovery. Extract security-relevant info: input types for mutations, authentication-related fields, admin-only types. Use GraphiQL/Playground for interactive exploration if available.

---

## 2. GraphQL API Security

### 2.1 GraphQL Fundamentals Relevant to Security

GraphQL is a query language for APIs that gives clients the power to ask for exactly the data they need. This flexibility is also its greatest security challenge — clients can craft queries that the server developer never anticipated.

#### Key Security-Relevant Concepts

**Schema**: Defines the types, queries, mutations, and subscriptions. The schema IS the API surface area. Unlike REST where endpoints are separate, a GraphQL schema exposes the entire data model as a graph.

**Types and Fields**: Each type has fields, and each field has a resolver function. Authorization must be enforced at the resolver level because a single query can traverse many resolvers.

```graphql
# A typical schema showing the security-relevant interconnections
type Query {
  user(id: ID!): User
  users(filter: UserFilter): [User!]!
  me: User
  admin: AdminPanel
}

type Mutation {
  updateUser(id: ID!, input: UserInput!): User
  deleteUser(id: ID!): Boolean
  createApiKey: ApiKey
  resetPassword(email: String!): Boolean
}

type Subscription {
  messageReceived(roomId: ID!): Message
  orderStatusChanged(orderId: ID!): Order
}

type User {
  id: ID!
  username: String!
  email: String!         # Should regular users see other users' emails?
  password: String       # Should this field EVER be exposed?
  ssn: String            # Extremely sensitive
  role: Role!
  posts: [Post!]!
  privateMessages: [Message!]!  # Per-user authorization needed
  apiKeys: [ApiKey!]!    # Sensitive — only visible to the owner
  organization: Organization!
}

type Organization {
  id: ID!
  name: String!
  billingInfo: BillingInfo!  # Sensitive
  members: [User!]!          # Could leak all users
  internalNotes: String      # Internal-only field
}
```

**Resolvers and the N+1 Problem**: Resolvers execute for each field. A query asking for 100 users, each with 50 posts, each with 10 comments triggers 100 + 5000 + 50000 resolver calls. This is a DoS vector even without malicious intent.

**DataLoader Pattern**: Batches and caches resolver calls to mitigate N+1. Security implication: the cache can serve stale authorization decisions if user permissions change during a request.

### 2.2 GraphQL Endpoint Discovery

```bash
# Standard GraphQL paths
PATHS=(
  "/graphql"
  "/gql"
  "/api/graphql"
  "/api/gql"
  "/graphql/console"
  "/graphql/api"
  "/graphql/v1"
  "/v1/graphql"
  "/v1/gql"
  "/v2/graphql"
  "/graphql/explorer"
  "/playground"
  "/graphql/playground"
  "/graphiql"
  "/graphql/graphiql"
  "/api/graphiql"
  "/altair"
  "/graphql/altair"
  "/subscriptions"
  "/graphql/subscriptions"
  "/graphql/ws"
  "/graphql/stream"
  "/query"
  "/api/query"
)

for path in "${PATHS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com$path" --max-time 5)
  if [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ]; then
    echo "[$STATUS] https://target.com$path"
  fi
done

# POST method detection (most GraphQL uses POST)
for path in "${PATHS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com$path" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}' --max-time 5)
  if [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ]; then
    echo "[POST $STATUS] https://target.com$path"
  fi
done

# Detect GraphiQL or GraphQL Playground by response content
curl -s "https://target.com/graphql" | grep -i "graphiql\|playground\|voyager\|altair"

# WebSocket endpoint for subscriptions
# Try upgrading to WebSocket
curl -s -o /dev/null -w "%{http_code}" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  "https://target.com/graphql"
```

### 2.3 Introspection Attacks

Introspection is a core GraphQL feature that allows clients to query the schema itself. Many production deployments leave it enabled.

```graphql
# Full schema introspection query
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}
```

```bash
# Send introspection query via curl
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name,args{name,type{name,kind,ofType{name}}}}}}}"}'

# Minimal introspection — get query type fields
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{fields{name}}}}"}'

# Get mutation fields
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{mutationType{fields{name,args{name,type{name}}}}}}"}'

# Get subscription fields
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{subscriptionType{fields{name}}}}"}'

# When introspection is disabled, use field suggestion errors
# Many GraphQL implementations suggest valid field names in error messages
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}'

curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{user}"}'
# Error: "Cannot query field \"user\" on type \"Query\".
#         Did you mean \"users\" or \"currentUser\"?"

curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{passwor}"}'
# Error might suggest: "Did you mean \"password\" or \"passwordReset\"?"
```

**Tool: Clairvoyance** — Reconstructs GraphQL schemas even when introspection is disabled:

```bash
# Clairvoyance uses field suggestion errors to brute-force the schema
python3 -m clairvoyance \
  -u https://target.com/graphql \
  -w wordlist.txt \
  -o schema.json

# Use with a targeted wordlist
python3 -m clairvoyance \
  -u https://target.com/graphql \
  -w /path/to/graphql-wordlist.txt \
  -H "Authorization: Bearer $TOKEN" \
  -o schema.json
```

