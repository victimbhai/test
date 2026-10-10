# Passive API Discovery: Mobile Secrets, Web Archives & DNS Reconnaissance — Agent Chunk 06d
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Extract hardcoded secrets from mobile apps, discover historical API endpoints via web archives, use Google dorks for API discovery, and enumerate API-related subdomains via DNS tools
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Search decompiled mobile apps for hardcoded API keys, OAuth secrets, and Firebase configs. Query the Wayback Machine CDX API and waymore for historical API URLs. Use Google dorks to find exposed API documentation, specification files, and error pages. Enumerate API-specific subdomains (api.target.com, api-dev.target.com, etc.) using subfinder, amass, dnsx, and httpx.

---


#### 2.2.4 Hardcoded Secrets in Mobile Applications

```bash
# After decompilation, search for hardcoded secrets
# API Keys
grep -rn "api[_-]?key\s*[:=]" output_dir/ --include="*.java" --include="*.kt" \
  --include="*.swift" --include="*.m" | grep -v "test\|example\|sample"

# OAuth Client IDs and Secrets
grep -rn "client[_-]?(id|secret)\s*[:=]" output_dir/ \
  --include="*.java" --include="*.kt"

# Firebase configuration
find output_dir -name "google-services.json" -exec cat {} \;
find output_dir -name "GoogleService-Info.plist" -exec cat {} \;

# AWS configuration
grep -rn "AKIA[0-9A-Z]{16}" output_dir/
grep -rn "aws[_-]?(access|secret|session)" output_dir/

# Generic secret patterns
grep -rn "password\s*[:=]\s*[\"'][^\"']+[\"']" output_dir/ \
  --include="*.java" --include="*.kt" --include="*.swift"
grep -rn "secret\s*[:=]\s*[\"'][^\"']+[\"']" output_dir/ \
  --include="*.java" --include="*.kt" --include="*.swift"
```

#### 2.2.5 API Base URL Extraction

```bash
# Comprehensive API base URL extraction from decompiled Android app
grep -rn "https\?://[a-zA-Z0-9.-]*api[a-zA-Z0-9.-]*\.[a-zA-Z]\{2,\}" \
  output_dir/ --include="*.java" --include="*.kt" --include="*.xml" | sort -u

# Extract from build configuration (BuildConfig)
find output_dir -name "BuildConfig.java" -exec grep -n "URL\|HOST\|API\|ENDPOINT" {} \;

# Extract from Gradle files (if present)
find output_dir -name "*.gradle" -exec grep -n "api\|url\|host\|endpoint" {} \;

# Extract from assets directory
find output_dir -path "*/assets/*" -name "*.json" -exec \
  grep -l "api\|url\|endpoint" {} \;
find output_dir -path "*/assets/*" -name "*.json" -exec \
  python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
    print(json.dumps(data, indent=2))
" {} \;
```

### 2.3 Web Archive and Historical Analysis

Historical data sources can reveal API endpoints that are no longer documented or
have been moved but remain accessible, as well as older versions of API specifications
and documentation.

#### 2.3.1 Wayback Machine API Endpoint Discovery

```bash
# Query the Wayback Machine CDX API for all URLs from the target
curl -s "https://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text\
&fl=original&collapse=urlkey" | sort -u > wayback_urls.txt

# Filter for API-related URLs
grep -iP "(api|graphql|rest|v[0-9]+|swagger|openapi|docs)" wayback_urls.txt \
  > api_urls.txt

# Filter for JSON/XML API responses
grep -iP "\.(json|xml|yaml|yml)$" wayback_urls.txt > data_files.txt

# Filter for documentation pages
grep -iP "(swagger|openapi|api-docs|developer|documentation)" wayback_urls.txt \
  > doc_urls.txt

# Check if discovered endpoints are still alive
while read -r url; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$url" --max-time 5)
  echo "$code $url"
done < api_urls.txt | grep -v "^000\|^404" > live_api_endpoints.txt

# Use waymore for comprehensive Wayback Machine search
pip3 install waymore

waymore -i target.com -mode U -oU wayback_urls.txt
grep -iP "api" wayback_urls.txt | sort -u
```

**Wayback Machine for Historical API Specifications:**

```bash
# Search for historical Swagger/OpenAPI specs
for path in "swagger.json" "api-docs" "openapi.json" "openapi.yaml" \
  "swagger/v1/swagger.json" "v2/api-docs" "v3/api-docs"; do

  echo "=== Checking: $path ==="
  curl -s "https://web.archive.org/cdx/search/cdx?\
url=target.com/${path}&output=json&fl=timestamp,original,statuscode" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
for entry in data[1:]:
    if entry[2] == '200':
        print(f'  Timestamp: {entry[0]}, URL: {entry[1]}')
" 2>/dev/null
done

# Retrieve a historical version of a spec
TIMESTAMP="20230615120000"
curl -s "https://web.archive.org/web/${TIMESTAMP}/https://target.com/swagger.json" \
  -o historical_swagger.json
```

#### 2.3.2 Google Dorks for API Discovery

```
# Basic API endpoint discovery
site:target.com inurl:api
site:target.com inurl:api/v1
site:target.com inurl:api/v2
site:target.com inurl:api/v3
site:target.com inurl:rest
site:target.com inurl:graphql
site:target.com inurl:grpc

# API documentation discovery
site:target.com inurl:swagger
site:target.com inurl:swagger-ui
site:target.com inurl:api-docs
site:target.com inurl:openapi
site:target.com inurl:redoc
site:target.com intitle:"API Documentation"
site:target.com intitle:"API Reference"
site:target.com inurl:developer
site:target.com inurl:developers

# API specification files
site:target.com filetype:json "openapi"
site:target.com filetype:yaml "openapi"
site:target.com filetype:json "swagger"
site:target.com filetype:yaml "swagger"
site:target.com filetype:json "paths"
site:target.com filetype:json "basePath"

# API key and credential leaks
site:target.com filetype:env
site:target.com filetype:yml "api_key"
site:target.com filetype:json "api_key"
site:target.com inurl:config filetype:json
site:target.com inurl:settings filetype:json

# Error pages revealing API information
site:target.com "internal server error" "api"
site:target.com "stack trace" "api"
site:target.com "404" "endpoint"

# GraphQL-specific
site:target.com inurl:graphql
site:target.com inurl:graphiql
site:target.com inurl:playground
site:target.com inurl:explorer

# Postman-related
site:postman.com "target.com"
site:documenter.getpostman.com "target.com"

# Developer forum and support
site:stackoverflow.com "target.com" "api"
site:github.com "target.com" "api"
```

### 2.4 DNS and Subdomain Enumeration

API services are frequently deployed on dedicated subdomains. Comprehensive subdomain
enumeration can reveal API infrastructure that is not linked from the main application.

#### 2.4.1 API-Specific Subdomains

Common API subdomain patterns to check:
```
api.target.com
api-v1.target.com
api-v2.target.com
api-v3.target.com
api-dev.target.com
api-staging.target.com
api-test.target.com
api-qa.target.com
api-uat.target.com
api-sandbox.target.com
api-beta.target.com
api-alpha.target.com
api-internal.target.com
api-admin.target.com
api-gateway.target.com
api-proxy.target.com
developer.target.com
developers.target.com
dev-api.target.com
dev.target.com
staging.target.com
staging-api.target.com
gateway.target.com
gw.target.com
graphql.target.com
gql.target.com
rest.target.com
ws.target.com
websocket.target.com
socket.target.com
realtime.target.com
partner.target.com
partner-api.target.com
partners.target.com
b2b.target.com
b2b-api.target.com
integration.target.com
integrations.target.com
webhook.target.com
webhooks.target.com
callback.target.com
internal.target.com
admin.target.com
admin-api.target.com
manage.target.com
management.target.com
console.target.com
portal.target.com
docs.target.com
docs-api.target.com
status.target.com
health.target.com
monitor.target.com
metrics.target.com
```

#### 2.4.2 Subdomain Enumeration Tools

**subfinder:**
```bash
# Installation
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Basic enumeration
subfinder -d target.com -o subdomains.txt

# With all sources enabled (requires API keys in config)
subfinder -d target.com -all -o subdomains.txt

# Filter for API-related subdomains
subfinder -d target.com -all | grep -iP "api|dev|staging|gateway|graphql|rest|internal" \
  > api_subdomains.txt
```

**amass:**
```bash
# Installation
go install -v github.com/owasp-amass/amass/v4/...@master

# Passive enumeration only
amass enum -passive -d target.com -o amass_subdomains.txt

# Active enumeration with DNS resolution
amass enum -active -d target.com -o amass_subdomains.txt

# With brute-forcing
amass enum -active -brute -d target.com -o amass_subdomains.txt

# Filter results
grep -iP "api|dev|staging|gateway|rest|internal" amass_subdomains.txt
```

**dnsx (DNS resolution and filtering):**
```bash
# Installation
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Resolve discovered subdomains
cat subdomains.txt | dnsx -a -resp -o resolved_subdomains.txt

# Check for specific record types
cat subdomains.txt | dnsx -a -aaaa -cname -mx -txt -resp

# Filter for live hosts
cat subdomains.txt | dnsx -a -resp-only | sort -u > live_ips.txt
```

**httpx (HTTP probing):**
```bash
# Installation
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Probe discovered subdomains for HTTP services
cat subdomains.txt | httpx -ports 80,443,8080,8443,3000,5000,8000,9090 \
  -title -tech-detect -status-code -o httpx_results.txt

# Filter for API-related responses
cat subdomains.txt | httpx -ports 80,443,8080,8443 \
  -match-string "api\|json\|swagger\|graphql" -o api_hosts.txt

# Extract technologies for API framework identification
cat subdomains.txt | httpx -tech-detect -json -o tech_results.json
```
