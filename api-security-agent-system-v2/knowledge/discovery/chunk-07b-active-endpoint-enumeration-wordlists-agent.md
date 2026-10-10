# Active Endpoint Enumeration: Wordlists, HTTP Methods & OpenAPI Locations — Agent Chunk 07b
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Use specialized API wordlists for brute-forcing, enumerate supported HTTP methods per endpoint, fuzz content types for parser differentials, and scan all common OpenAPI/Swagger specification file locations
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use feroxbuster and gobuster alongside ffuf with Assetnote and SecLists API wordlists. Generate custom wordlists from the target's own vocabulary. For each discovered endpoint, test all HTTP methods (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, TRACE) since different methods may have different security controls. Fuzz Content-Type headers to find XML/YAML parsing that enables XXE or injection. Scan all ~50 common OpenAPI/Swagger specification paths on both the main domain and api subdomain.

---


**Using feroxbuster:**

```bash
# Installation
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash

# Basic API directory brute-force
feroxbuster -u https://api.target.com \
  -w /path/to/api-wordlist.txt \
  --status-codes 200 201 202 204 301 302 307 401 403 405 \
  --json -o ferox_results.json

# With recursion and rate limiting
feroxbuster -u https://api.target.com/api/v1 \
  -w /path/to/api-wordlist.txt \
  --depth 3 \
  --rate-limit 50 \
  --status-codes 200 201 202 204 301 302 307 401 403 405

# With authentication headers
feroxbuster -u https://api.target.com/api/v1 \
  -w /path/to/api-wordlist.txt \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json"

# Multiple extensions
feroxbuster -u https://api.target.com \
  -w /path/to/api-wordlist.txt \
  -x json xml yaml
```

**Using gobuster:**

```bash
# Installation
go install github.com/OJ/gobuster/v3@latest

# API endpoint discovery
gobuster dir -u https://api.target.com \
  -w /path/to/api-wordlist.txt \
  -s "200,201,202,204,301,302,307,401,403,405" \
  -b "" \
  -o gobuster_results.txt

# With custom headers
gobuster dir -u https://api.target.com \
  -w /path/to/api-wordlist.txt \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json"

# VHOST discovery for API subdomains
gobuster vhost -u https://target.com \
  -w /path/to/api-subdomains.txt \
  --append-domain
```

#### 3.1.2 API-Specific Wordlists

**Assetnote Wordlists:**
```bash
# Download Assetnote API wordlists
# https://wordlists.assetnote.io/

# Common API paths wordlist
wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2024_11_28.txt

# Specific technology wordlists
wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_aspx_asp_cfm_svc_ashx_asmx_2024_11_28.txt
wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_jsp_jspa_do_action_2024_11_28.txt
wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_php_2024_11_28.txt
```

**SecLists API Paths:**
```bash
# From SecLists repository
# https://github.com/danielmiessler/SecLists/

# API-specific wordlists in SecLists
# Discovery/Web-Content/api/
# Discovery/Web-Content/api-endpoints.txt
# Discovery/Web-Content/swagger.txt
# Discovery/Web-Content/graphql.txt
# Discovery/Web-Content/common-api-endpoints-mazen160.txt

git clone --depth 1 https://github.com/danielmiessler/SecLists.git
ls SecLists/Discovery/Web-Content/api/
```

**Custom API Wordlist Generation:**

```bash
# Generate a custom wordlist from the target application's vocabulary
# Extract words from the target's website
curl -s https://target.com | \
  grep -oP '[a-zA-Z]+' | \
  tr '[:upper:]' '[:lower:]' | \
  sort -u > target_words.txt

# Generate API-style paths from extracted words
while read -r word; do
  echo "$word"
  echo "${word}s"                    # plural
  echo "get-${word}"
  echo "get-${word}s"
  echo "create-${word}"
  echo "update-${word}"
  echo "delete-${word}"
  echo "list-${word}s"
  echo "search-${word}s"
  echo "${word}/list"
  echo "${word}/search"
  echo "${word}/create"
  echo "${word}/export"
  echo "${word}/import"
  echo "${word}/bulk"
  echo "${word}/{id}"
  echo "${word}/me"
  echo "${word}/current"
  echo "admin/${word}"
  echo "admin/${word}s"
  echo "internal/${word}"
  echo "manage/${word}s"
done < target_words.txt > custom_api_wordlist.txt
```

#### 3.1.3 HTTP Method Enumeration

For each discovered endpoint, enumerate which HTTP methods are accepted. Different
methods may have different security controls, and some methods may expose functionality
not accessible through the default method.

```bash
# Test all common HTTP methods against an endpoint
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X "$method" https://api.target.com/api/v1/users)
  echo "$method: $response"
done

# Automated method enumeration across multiple endpoints
while read -r endpoint; do
  echo "=== $endpoint ==="
  for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
    response=$(curl -s -o /dev/null -w "%{http_code}" \
      -X "$method" "https://api.target.com${endpoint}" --max-time 5)
    if [ "$response" != "404" ] && [ "$response" != "000" ]; then
      echo "  $method: $response"
    fi
  done
done < discovered_endpoints.txt

# Check OPTIONS for CORS and allowed methods
curl -s -I -X OPTIONS https://api.target.com/api/v1/users | \
  grep -i "allow\|access-control"
```

#### 3.1.4 Content-Type Fuzzing

APIs may behave differently depending on the Content-Type header. Testing different
content types can reveal additional attack vectors or bypass input validation.

```bash
# Test different content types
for ct in "application/json" "application/xml" "application/x-www-form-urlencoded" \
  "multipart/form-data" "text/xml" "application/yaml" "text/yaml" \
  "application/x-yaml" "application/soap+xml" "text/plain" \
  "application/msgpack" "application/x-protobuf" "application/cbor"; do

  echo "=== Content-Type: $ct ==="
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://api.target.com/api/v1/users" \
    -H "Content-Type: $ct" \
    -d '{"test":"value"}'
  echo ""
done

# XML content type with JSON endpoint (XXE testing vector)
curl -X POST "https://api.target.com/api/v1/users" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><user><name>test</name></user>'

# YAML injection attempt
curl -X POST "https://api.target.com/api/v1/users" \
  -H "Content-Type: application/yaml" \
  -d 'name: test'
```

### 3.2 OpenAPI/Swagger Discovery

#### 3.2.1 Common Specification Locations

```bash
# Check all common OpenAPI/Swagger spec locations
SPEC_PATHS=(
  "/swagger.json"
  "/swagger.yaml"
  "/swagger/v1/swagger.json"
  "/swagger/v2/swagger.json"
  "/api-docs"
  "/api-docs.json"
  "/api/api-docs"
  "/v1/api-docs"
  "/v2/api-docs"
  "/v3/api-docs"
  "/api/v1/api-docs"
  "/api/v2/api-docs"
  "/api/v3/api-docs"
  "/openapi.json"
  "/openapi.yaml"
  "/openapi/v1"
  "/openapi/v2"
  "/openapi/v3"
  "/.well-known/openapi.json"
  "/.well-known/openapi.yaml"
  "/api/swagger.json"
  "/api/swagger.yaml"
  "/api/openapi.json"
  "/api/openapi.yaml"
  "/docs"
  "/docs/api"
  "/api/docs"
  "/redoc"
  "/api/redoc"
  "/swagger-ui"
  "/swagger-ui.html"
  "/swagger-ui/index.html"
  "/api/swagger-ui"
  "/api/swagger-ui.html"
  "/swagger-resources"
  "/swagger-resources/configuration/ui"
  "/swagger-resources/configuration/security"
  "/api/swagger-resources"
  "/api.json"
  "/api.yaml"
  "/api.html"
  "/api/spec"
  "/api/specification"
  "/api/schema"
  "/_api/docs"
  "/_api/swagger"
  "/internal/api-docs"
  "/internal/swagger"
  "/debug/api"
  "/graphql/schema"
  "/graphql/documentation"
)

for path in "${SPEC_PATHS[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com${path}" --max-time 5)
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "[${code}] https://target.com${path}"
  fi
done

# Also check on API subdomain
for path in "${SPEC_PATHS[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://api.target.com${path}" --max-time 5)
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "[${code}] https://api.target.com${path}"
  fi
done
```
