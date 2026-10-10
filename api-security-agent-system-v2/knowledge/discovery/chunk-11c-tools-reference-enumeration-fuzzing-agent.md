# Tools Reference: ffuf, feroxbuster, Nuclei, Arjun/x8, GraphQL Tools & Caido — Agent Chunk 11c
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Master the usage of specialized API enumeration, fuzzing, vulnerability scanning, parameter discovery, and GraphQL security tools
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use ffuf for API endpoint discovery (standard paths, version enumeration, JSON body parameter fuzzing, IDOR testing, host header fuzzing for virtual hosts). Use feroxbuster for recursive API discovery with automatic link extraction. Run Nuclei with API-specific templates (api, graphql, jwt, oauth, token, cors, ssrf tags) and create custom templates for target-specific checks. Use Arjun for GET/POST parameter discovery and x8 for JSON body and header parameter detection. Deploy graphw00f for GraphQL engine fingerprinting, InQL CLI for query generation, Clairvoyance for schema recovery, and BatchQL for batching attack tests. Use Caido's HTTPQL query language for efficient API traffic filtering.

---

### 8.4 ffuf (Fuzz Faster U Fool)

**Purpose:** Fast web fuzzer primarily used for API endpoint and parameter discovery.

**Installation:**
```bash
go install github.com/ffuf/ffuf/v2@latest
```

**API-Specific Usage Patterns:**

```bash
# Standard API endpoint discovery
ffuf -u https://api.target.com/api/v1/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,307,401,403,405 \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -rate 50 \
  -o ffuf_api_results.json -of json

# Parameter value fuzzing (IDOR testing)
ffuf -u https://api.target.com/api/v1/users/FUZZ \
  -w /opt/SecLists/Fuzzing/id-integers.txt \
  -H "Authorization: Bearer <user_token>" \
  -mc 200 \
  -fs 0

# JSON body parameter fuzzing
ffuf -u https://api.target.com/api/v1/users \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"username":"test","FUZZ":"value"}' \
  -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200,201,400,422 \
  -fw 1

# API version enumeration
ffuf -u https://api.target.com/api/FUZZ/users \
  -w <(echo -e "v1\nv2\nv3\nv4\nv5\nbeta\nalpha\nstaging\ndev\ninternal\nlegacy") \
  -mc 200,201,301,302,401,403

# Host header fuzzing for API virtual hosts
ffuf -u https://TARGET_IP/ \
  -H "Host: FUZZ.target.com" \
  -w api_subdomains.txt \
  -mc 200,301,302,401,403 \
  -fs 0
```

### 8.5 feroxbuster

**Purpose:** Fast, recursive content discovery tool with features tailored for
modern web applications and APIs.

**Installation:**
```bash
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash
```

**API-Specific Usage:**

```bash
# Recursive API discovery with depth control
feroxbuster -u https://api.target.com \
  -w /opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  --depth 3 \
  --status-codes 200 201 204 301 302 307 401 403 405 \
  --headers "Authorization: Bearer <token>" \
  --headers "Content-Type: application/json" \
  --rate-limit 100 \
  --json -o ferox_results.json

# With automatic extraction of new paths from responses
feroxbuster -u https://api.target.com/api/v1 \
  -w /opt/api-wordlist.txt \
  --extract-links \
  --collect-words \
  --depth 2

# Filter by response characteristics
feroxbuster -u https://api.target.com/api \
  -w /opt/api-wordlist.txt \
  --filter-size 0 \
  --filter-words 1 \
  --filter-lines 1
```

### 8.6 Nuclei

**Purpose:** Template-based vulnerability scanner with a large library of community
templates, including many specific to API security.

**Installation:**
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update templates
nuclei -update-templates
```

**API-Specific Usage:**

```bash
# Scan with API-specific templates
nuclei -u https://api.target.com -tags api -o nuclei_api_results.txt

# Scan for exposed API documentation
nuclei -u https://target.com -tags exposure,swagger,openapi

# Scan for misconfigured API services
nuclei -u https://target.com -tags misconfig -severity critical,high

# Scan for known CVEs in API frameworks
nuclei -u https://api.target.com -tags cve -severity critical,high

# Scan with specific template categories
nuclei -u https://api.target.com \
  -tags "api,graphql,jwt,oauth,token,cors,ssrf" \
  -severity critical,high,medium \
  -o nuclei_results.txt

# Scan from a list of discovered endpoints
nuclei -l discovered_api_urls.txt \
  -tags api \
  -rate-limit 50 \
  -bulk-size 25 \
  -o nuclei_bulk_results.txt

# Custom template for API testing
# Example: Check for exposed Spring Boot Actuator
# Save as custom-templates/spring-actuator.yaml
cat << 'TEMPLATE'
id: spring-boot-actuator-env
info:
  name: Spring Boot Actuator - Env Endpoint
  severity: high
  tags: api,misconfig,spring

http:
  - method: GET
    path:
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/env"
      - "{{BaseURL}}/actuator"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "activeProfiles"
          - "propertySources"
        condition: or

      - type: status
        status:
          - 200
TEMPLATE

nuclei -u https://target.com -t custom-templates/
```

### 8.7 Arjun and x8 (Parameter Discovery)

**Arjun:**
```bash
# Installation
pip3 install arjun

# GET parameter discovery
arjun -u https://api.target.com/api/v1/search \
  --headers "Authorization: Bearer <token>"

# POST JSON body parameter discovery
arjun -u https://api.target.com/api/v1/users \
  -m POST \
  --headers "Content-Type: application/json" \
  --headers "Authorization: Bearer <token>"

# Batch URL scanning
arjun -i api_endpoints.txt \
  --headers "Authorization: Bearer <token>" \
  -oJ arjun_results.json

# With custom wordlist
arjun -u https://api.target.com/api/v1/users \
  -w custom_params.txt \
  --stable

# Tip: Arjun identifies parameters by detecting response differences
# when parameters are added. Use --stable for APIs with variable responses.
```

**x8:**
```bash
# Installation
cargo install x8

# Parameter discovery with comparison
x8 -u "https://api.target.com/api/v1/search" \
  -w params.txt \
  -H "Authorization: Bearer <token>"

# JSON body parameter discovery
x8 -u "https://api.target.com/api/v1/users" \
  -w params.txt \
  -m POST \
  -b '{}' \
  --json \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json"

# Header parameter discovery
x8 -u "https://api.target.com/api/v1/users" \
  -w header_params.txt \
  --headers

# Tip: x8 uses multiple techniques to detect parameters including
# response time, body size, and status code changes.
```

### 8.8 GraphQL-Specific Tools

**graphw00f (Fingerprinting):**
```bash
pip3 install graphw00f
python3 -m graphw00f -t https://target.com/graphql
# Identifies: Apollo, Hasura, graphql-java, Ariadne, Strawberry,
# graphql-ruby, Juniper, Sangria, graphql-go, and more
```

**InQL CLI:**
```bash
pip3 install inql
inql -t https://target.com/graphql --generate-queries -o ./inql_output
```

**Clairvoyance (Schema Recovery):**
```bash
pip3 install clairvoyance
clairvoyance https://target.com/graphql -o recovered_schema.json
# Works when introspection is disabled by using field suggestion attacks
```

**graphql-voyager:**
```
# Web-based GraphQL schema visualization
# Use the introspection result from InQL or direct query
# Paste the schema JSON into https://graphql-kit.com/graphql-voyager/
# Visualize relationships between types to understand data model
```

**BatchQL:**
```bash
# Test for GraphQL batching attacks
git clone https://github.com/assetnote/batchql
cd batchql
python3 batch.py -e https://target.com/graphql -q '{ __typename }'
# Tests whether the endpoint accepts batched queries that could bypass
# rate limiting or perform enumeration attacks
```

### 8.9 Caido

**Purpose:** Modern, lightweight web security testing proxy designed as a
faster alternative to Burp Suite with native API testing capabilities.

**Installation:**
```bash
# Download from https://caido.io/download
# Linux:
chmod +x caido-cli
./caido-cli
```

**API-Specific Features:**

```
1. HTTPQL Query Language:
   - req.path.cont:"/api/" AND req.method.eq:"POST"
   - resp.header.cont:"application/json"
   - req.body.cont:"admin"
   - resp.code.gte:500

2. Workflows:
   - Create automated testing workflows for API endpoints
   - Chain requests for multi-step API testing
   - Conditional logic based on response analysis

3. Replay:
   - Fast request replaying with parameter modification
   - Tab-based testing for multiple endpoints simultaneously
   - Built-in diff comparison between responses

4. Automate:
   - Parameter fuzzing with custom wordlists
   - Response matching and filtering
   - Export results in JSON format

5. API-Specific Tips:
   - Use HTTPQL to quickly filter API traffic from general web traffic
   - Leverage the Workflow feature for authorization testing chains
   - Use the built-in JWT decoder for token analysis
   - Configure upstream proxies for mobile traffic interception
```

