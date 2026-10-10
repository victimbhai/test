# GraphQL Discovery & Traffic Proxy Configuration — Agent Chunk 08b
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Detect GraphQL endpoints, extract schemas via introspection, recover schemas when introspection is disabled, and set up proxy interception for API traffic analysis
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Probe all common GraphQL endpoint paths with both POST and GET methods. When a GraphQL endpoint is found, run the full introspection query to extract all queries, mutations, subscriptions, types, and arguments. If introspection is disabled, use field suggestion attacks with common field names to enumerate the schema. Use graphw00f to fingerprint the GraphQL engine, InQL for query generation, and Clairvoyance for schema recovery. Set up Burp Suite, mitmproxy, or Caido to intercept API traffic and use the provided mitmproxy addon script to automatically catalog discovered endpoints.

---


### 3.3 GraphQL Discovery

GraphQL APIs present a unique attack surface because a single endpoint handles all
operations, and the schema itself describes all available queries, mutations, and types.

#### 3.3.1 Endpoint Detection

```bash
# Common GraphQL endpoint paths
GRAPHQL_PATHS=(
  "/graphql"
  "/graphql/v1"
  "/graphql/v2"
  "/api/graphql"
  "/api/v1/graphql"
  "/v1/graphql"
  "/v2/graphql"
  "/query"
  "/gql"
  "/graphiql"
  "/playground"
  "/console"
  "/explorer"
  "/altair"
  "/graph"
  "/api/graph"
  "/_graphql"
  "/graphql/console"
  "/graphql/explorer"
  "/graphql/schema"
)

for path in "${GRAPHQL_PATHS[@]}"; do
  # Test with a simple GraphQL query
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com${path}" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }"}' --max-time 5)
  if [ "$response" != "404" ] && [ "$response" != "000" ]; then
    echo "[${response}] https://target.com${path}"
  fi

  # Also test GET method
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com${path}?query={__typename}" --max-time 5)
  if [ "$response" != "404" ] && [ "$response" != "000" ]; then
    echo "[${response}] GET: https://target.com${path}"
  fi
done
```

#### 3.3.2 Introspection Queries

When GraphQL introspection is enabled, the entire schema can be extracted with a single
query. This reveals all queries, mutations, subscriptions, types, and their arguments.

```bash
# Full introspection query
curl -s -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name description fields(includeDeprecated: true) { name description args { name description type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } defaultValue } type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } isDeprecated deprecationReason } inputFields { name description type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } defaultValue } interfaces { kind name ofType { kind name } } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { kind name } } directives { name description locations args { name description type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } defaultValue } } } }"
  }' | python3 -m json.tool > graphql_schema.json

# Shortened introspection - just types and queries
curl -s -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name kind fields { name type { name kind } } } } }"}' | \
  python3 -m json.tool

# List all queries
curl -s -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name description args { name type { name } } } } } }"}' | \
  python3 -m json.tool

# List all mutations
curl -s -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { mutationType { fields { name description args { name type { name } } } } } }"}' | \
  python3 -m json.tool
```

#### 3.3.3 Field Suggestion Attacks (When Introspection Is Disabled)

When introspection is disabled, field suggestions can be used to enumerate the schema.
Many GraphQL implementations return helpful error messages that suggest valid field names
when an invalid field is queried.

```bash
# Test if suggestions are enabled
curl -s -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typ }"}' | python3 -m json.tool

# Expected response with suggestions:
# "Cannot query field '__typ' on type 'Query'. Did you mean '__type' or '__typename'?"

# Enumerate root query fields using common names
COMMON_FIELDS=(
  "user" "users" "me" "currentUser" "viewer"
  "account" "accounts" "profile" "profiles"
  "admin" "admins" "administrator"
  "post" "posts" "article" "articles"
  "comment" "comments" "message" "messages"
  "order" "orders" "payment" "payments"
  "product" "products" "item" "items"
  "search" "find" "get" "list" "all"
  "config" "configuration" "settings" "setting"
  "flag" "flags" "feature" "features"
  "log" "logs" "audit" "event" "events"
  "notification" "notifications"
  "file" "files" "upload" "uploads"
  "role" "roles" "permission" "permissions"
  "token" "tokens" "session" "sessions"
  "webhook" "webhooks" "callback" "callbacks"
  "internal" "debug" "test" "health"
)

for field in "${COMMON_FIELDS[@]}"; do
  response=$(curl -s -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{ ${field} }\"}")
  # Check if the field exists or get suggestions
  if echo "$response" | grep -q "Did you mean"; then
    echo "SUGGESTION for '${field}': $(echo "$response" | \
      grep -oP "Did you mean [^?]+")"
  elif ! echo "$response" | grep -q "Cannot query field"; then
    echo "VALID FIELD: ${field}"
  fi
done
```

#### 3.3.4 GraphQL-Specific Tools

**graphw00f (GraphQL Fingerprinting):**
```bash
# Installation
pip3 install graphw00f

# Fingerprint the GraphQL engine
python3 -m graphw00f -t https://target.com/graphql

# This identifies the backend (Apollo, Hasura, graphql-java, etc.)
# which determines available features and known vulnerabilities
```

**InQL (Burp Extension and CLI):**
```bash
# CLI installation
pip3 install inql

# Analyze a GraphQL endpoint
inql -t https://target.com/graphql

# Analyze with authentication
inql -t https://target.com/graphql -H "Authorization: Bearer <token>"

# Generate queries from introspection
inql -t https://target.com/graphql --generate-queries

# Output in various formats
inql -t https://target.com/graphql --generate-html -o report.html
```

**Clairvoyance (Schema Recovery Without Introspection):**
```bash
# Installation
pip3 install clairvoyance

# Recover schema when introspection is disabled
clairvoyance https://target.com/graphql -o recovered_schema.json

# With a custom wordlist
clairvoyance https://target.com/graphql -w custom_wordlist.txt -o schema.json

# With authentication
clairvoyance https://target.com/graphql \
  -H "Authorization: Bearer <token>" -o schema.json
```

### 3.4 Traffic Analysis

#### 3.4.1 Proxy Configuration for API Traffic Capture

**Burp Suite Setup:**
```
1. Start Burp Suite and configure proxy listener (default: 127.0.0.1:8080)
2. Install Burp CA certificate in browser/system trust store
3. Configure browser proxy settings
4. For mobile devices:
   a. Set device proxy to your machine's IP:8080
   b. Install Burp CA certificate on the device
5. For CLI tools:
   export http_proxy=http://127.0.0.1:8080
   export https_proxy=http://127.0.0.1:8080
```

**mitmproxy Setup:**
```bash
# Installation
pip3 install mitmproxy

# Start mitmproxy with web interface
mitmweb --listen-port 8080

# Start mitmproxy with console interface
mitmproxy --listen-port 8080

# Start in transparent mode (requires iptables configuration)
mitmproxy --mode transparent --listen-port 8080

# Dump all API traffic to a file
mitmdump --listen-port 8080 -w api_traffic.flow

# Filter and save only API requests
mitmdump --listen-port 8080 \
  --set "flow_detail=3" \
  -s "filter_script.py" \
  -w api_only_traffic.flow
```

**mitmproxy API Filter Script:**
```python
# filter_script.py - Custom mitmproxy script to extract API endpoints
import json
from mitmproxy import ctx

class APIExtractor:
    def __init__(self):
        self.endpoints = set()
        self.output_file = "discovered_api_endpoints.txt"

    def request(self, flow):
        url = flow.request.pretty_url
        method = flow.request.method

        # Filter for API-like requests
        api_indicators = [
            '/api/', '/v1/', '/v2/', '/v3/', '/graphql',
            '/rest/', '/service/', '/services/'
        ]

        is_api = any(indicator in url for indicator in api_indicators)
        is_json = 'application/json' in flow.request.headers.get(
            'content-type', ''
        )
        is_json_response = 'application/json' in flow.request.headers.get(
            'accept', ''
        )

        if is_api or is_json or is_json_response:
            endpoint = f"[{method}] {url}"
            if endpoint not in self.endpoints:
                self.endpoints.add(endpoint)
                ctx.log.info(f"New API endpoint: {endpoint}")
                with open(self.output_file, 'a') as f:
                    f.write(endpoint + '\n')

                # Log request details
                headers = dict(flow.request.headers)
                if 'authorization' in {k.lower() for k in headers}:
                    ctx.log.info(f"  Auth header present")
                if flow.request.content:
                    ctx.log.info(f"  Body size: {len(flow.request.content)} bytes")

    def response(self, flow):
        # Analyze response for additional API discovery
        content_type = flow.response.headers.get('content-type', '')
        if 'application/json' in content_type and flow.response.content:
            try:
                data = json.loads(flow.response.content)
                # Look for URLs in response data
                self._extract_urls(data)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

    def _extract_urls(self, data, depth=0):
        if depth > 5:
            return
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str) and (
                    value.startswith('/api/') or
                    value.startswith('http') and '/api/' in value
                ):
                    endpoint = f"[RESPONSE_URL] {value}"
                    if endpoint not in self.endpoints:
                        self.endpoints.add(endpoint)
                        ctx.log.info(f"URL in response: {value}")
                self._extract_urls(value, depth + 1)
        elif isinstance(data, list):
            for item in data:
                self._extract_urls(item, depth + 1)

addons = [APIExtractor()]
```

**Caido Setup:**
```
1. Download Caido from https://caido.io
2. Start Caido (default listener on 127.0.0.1:8080)
3. Install CA certificate
4. Configure proxy in browser
5. Use the HTTPQL query language to filter API traffic:
   - req.path.cont:"/api/"
   - req.header.cont:"application/json"
   - resp.header.cont:"application/json"
```

