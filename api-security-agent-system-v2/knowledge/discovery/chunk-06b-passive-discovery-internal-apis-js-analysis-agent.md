# Passive API Discovery: Internal API Exposure & JavaScript Analysis — Agent Chunk 06b
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Detect accidentally exposed internal microservices and extract API endpoints from JavaScript bundles
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
When testing a target, first scan for accidentally exposed internal services (Kubernetes, Docker, service mesh admin ports). Then download and analyze all JavaScript files to extract hardcoded API paths, base URLs, and authentication patterns. Use LinkFinder, JSParser, and manual regex extraction to find endpoints the application communicates with.

---

### 1.6 Internal Microservice APIs Accidentally Exposed

The shift to microservices architecture has dramatically expanded the internal API surface,
and misconfigurations frequently expose these services to the internet.

**Common Exposure Vectors:**

1. **Cloud Security Group Misconfiguration:**
   - AWS security groups allowing 0.0.0.0/0 inbound on service ports
   - Azure NSG rules with overly permissive source addresses
   - GCP firewall rules not restricted to internal VPC ranges

2. **Kubernetes Ingress Misconfiguration:**
   - Ingress controllers routing to internal services without authentication
   - NodePort services exposed on all cluster nodes
   - LoadBalancer services with public IPs for internal services
   - Missing network policies allowing cross-namespace access

   ```yaml
   # Dangerous: Ingress exposing internal service without auth
   apiVersion: networking.k8s.io/v1
   kind: Ingress
   metadata:
     name: internal-service-ingress
   spec:
     rules:
     - host: "*.target.com"
       http:
         paths:
         - path: /internal-api
           pathType: Prefix
           backend:
             service:
               name: internal-user-service
               port:
                 number: 8080
   ```

3. **API Gateway Route Leakage:**
   - Wildcard routes forwarding to internal microservices
   - Missing route-level authentication configuration
   - Path traversal through gateway routing (e.g., `/public/../internal/admin`)
   - Header-based routing that can be manipulated by external clients

4. **Docker and Container Exposure:**
   - Docker daemon exposed on port 2375/2376 without TLS
   - Container management APIs (Portainer, Rancher) on public interfaces
   - Debug ports published in docker-compose.yml
   - Container health check endpoints on routable addresses

5. **Service Mesh Bypass:**
   - Accessing services directly on pod IP addresses, bypassing the service mesh
   - Envoy admin interface exposed (`/admin`, port 15000)
   - Istio pilot debug endpoints
   - Linkerd admin dashboard without authentication

**Detection Approach:**

```bash
# Scan for common internal service ports on discovered hosts
nmap -sV -p 8080,8443,9090,9443,3000,5000,8000,8888,4000,6379,27017,9200,5672,15672 \
  target.com

# Check for Kubernetes-related exposure
curl -s https://target.com/api/v1/namespaces
curl -s https://target.com/apis
curl -s https://target.com/healthz
curl -s https://target.com/version

# Check for Envoy/Istio admin exposure
curl -s https://target.com:15000/help
curl -s https://target.com:15000/clusters
curl -s https://target.com:15000/config_dump

# Check for common management interfaces
curl -s -o /dev/null -w "%{http_code}" https://target.com:9090/metrics  # Prometheus
curl -s -o /dev/null -w "%{http_code}" https://target.com:3000/api/org  # Grafana
curl -s -o /dev/null -w "%{http_code}" https://target.com:5601/api/status  # Kibana
curl -s -o /dev/null -w "%{http_code}" https://target.com:8500/v1/agent/self  # Consul
curl -s -o /dev/null -w "%{http_code}" https://target.com:8200/v1/sys/health  # Vault
```

---

## 2. Passive Discovery Techniques

Passive discovery techniques gather information about the API attack surface without
sending any requests to the target. These techniques are essential for the initial
reconnaissance phase and for identifying targets that may be missed by active scanning.

### 2.1 JavaScript Source Analysis

Modern web applications are predominantly single-page applications (SPAs) that contain
their entire API client logic in JavaScript bundles. These bundles are a goldmine for
API endpoint discovery because they contain hardcoded API paths, base URLs, authentication
logic, and often internal comments and debug code.

#### 2.1.1 Extracting API Endpoints from JavaScript Bundles

**Manual Analysis Approach:**

1. Identify all JavaScript files loaded by the application:
   ```bash
   # Download the main page and extract script sources
   curl -s https://target.com | grep -oP 'src="([^"]*\.js[^"]*)"' | \
     sed 's/src="//;s/"//'

   # Alternative: extract from full HTML including dynamically loaded scripts
   curl -s https://target.com | grep -oEi '(src|href)="[^"]*\.(js|mjs|cjs)[^"]*"' | \
     grep -oP '"[^"]*"' | tr -d '"'
   ```

2. Download and concatenate all JavaScript files:
   ```bash
   # Create a working directory
   mkdir -p /tmp/js_analysis
   cd /tmp/js_analysis

   # Download all JS files
   curl -s https://target.com | grep -oP 'src="([^"]*\.js[^"]*)"' | \
     sed 's/src="//;s/"//' | while read -r url; do
       # Handle relative URLs
       if [[ "$url" == /* ]]; then
         url="https://target.com${url}"
       elif [[ "$url" != http* ]]; then
         url="https://target.com/${url}"
       fi
       filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
       curl -s "$url" -o "$filename"
       echo "Downloaded: $url -> $filename"
     done
   ```

3. Extract API endpoints using regex patterns:
   ```bash
   # General API path patterns
   grep -ohrP '["'"'"'](/api/[a-zA-Z0-9_/\-\.:{}]+)["'"'"']' *.js | sort -u

   # RESTful path patterns
   grep -ohrP '["'"'"'](/v[0-9]+/[a-zA-Z0-9_/\-\.:{}]+)["'"'"']' *.js | sort -u

   # Full URL patterns including protocol
   grep -ohrP 'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/[a-zA-Z0-9_/\-\.:{}?&=]+)' \
     *.js | sort -u

   # Fetch API calls
   grep -ohrP 'fetch\s*\(\s*["'"'"'`]([^"'"'"'`]+)["'"'"'`]' *.js | sort -u

   # Axios calls
   grep -ohrP 'axios\.(get|post|put|patch|delete|head|options)\s*\(\s*["'"'"'`]([^"'"'"'`]+)' \
     *.js | sort -u

   # XMLHttpRequest
   grep -ohrP '\.open\s*\(\s*["'"'"'](?:GET|POST|PUT|PATCH|DELETE)["'"'"']\s*,\s*["'"'"'`]([^"'"'"'`]+)' \
     *.js | sort -u

   # Template literals with API paths
   grep -ohrP '`[^`]*(/api/[^`]+)[^`]*`' *.js | sort -u

   # GraphQL endpoint references
   grep -ohrP '["'"'"'](/graphql[a-zA-Z0-9_/\-]*)["'"'"']' *.js | sort -u

   # WebSocket endpoints
   grep -ohrP 'wss?://[a-zA-Z0-9\-\.]+[a-zA-Z0-9_/\-\.]*' *.js | sort -u
   ```

**Comprehensive Regex Patterns for Endpoint Extraction:**

```
# API endpoint patterns in JavaScript

# RESTful API paths
/api/v[0-9]+/[a-zA-Z0-9_/\-]+
/rest/[a-zA-Z0-9_/\-]+
/service/[a-zA-Z0-9_/\-]+
/services/[a-zA-Z0-9_/\-]+
/endpoint/[a-zA-Z0-9_/\-]+

# Fetch API usage
fetch\(['"]([^'"]+)['"]\)
fetch\(`([^`]+)`\)

# Axios usage
axios\.(get|post|put|delete|patch|head|options)\(['"]([^'"]+)['"]\)
axios\(['"]([^'"]+)['"]\)
axios\(\{[^}]*url:\s*['"]([^'"]+)['"]

# jQuery AJAX
\$\.(ajax|get|post|put|delete)\(\s*['"]([^'"]+)['"]
\$\.ajax\(\s*\{[^}]*url:\s*['"]([^'"]+)['"]

# Angular HttpClient
this\.http\.(get|post|put|delete|patch)\s*[<(]\s*['"`]([^'"`]+)['"`]
this\.httpClient\.(get|post|put|delete|patch)\s*[<(]\s*['"`]([^'"`]+)['"`]

# React/Next.js API routes
/api/[a-zA-Z0-9_/\[\]\-]+
/pages/api/[a-zA-Z0-9_/\[\]\-]+

# URL construction patterns
baseUrl\s*\+\s*['"]([^'"]+)['"]
apiUrl\s*\+\s*['"]([^'"]+)['"]
BASE_URL\s*\+\s*['"]([^'"]+)['"]
API_BASE\s*\+\s*['"]([^'"]+)['"]
endpoint\s*[:=]\s*['"]([^'"]+)['"]
```

#### 2.1.2 Tools for JavaScript Analysis

**LinkFinder:**
LinkFinder is a Python tool designed to discover endpoints and their parameters in
JavaScript files.

```bash
# Installation
pip3 install linkfinder

# Basic usage - analyze a single JavaScript file
python3 linkfinder.py -i https://target.com/static/js/main.js -o cli

# Analyze a URL and automatically extract JS files
python3 linkfinder.py -i https://target.com -o cli

# Output to HTML for visual analysis
python3 linkfinder.py -i https://target.com -o results.html

# Analyze all JS files from a domain (using stdin)
cat js_urls.txt | while read -r url; do
  python3 linkfinder.py -i "$url" -o cli
done | sort -u > all_endpoints.txt

# Using with Burp Suite output
# Export all JS URLs from Burp sitemap, then:
cat burp_js_urls.txt | python3 linkfinder.py -i - -o cli
```

**JSParser:**
```bash
# Installation
git clone https://github.com/nicelhc13/JSParser.git
cd JSParser
pip3 install -r requirements.txt
python3 setup.py install

# Usage
python3 handler.py -u https://target.com/static/js/app.js
```

**relative-url-extractor:**
```bash
# Installation
git clone https://github.com/jobertabma/relative-url-extractor.git
cd relative-url-extractor

# Extract relative URLs from a JavaScript file
ruby extract.rb https://target.com/static/js/main.js

# Process multiple files
cat js_urls.txt | while read -r url; do
  ruby extract.rb "$url"
done | sort -u
```

**GAP (Burp Extension):**
The GAP (Get All Parameters) Burp Suite extension automatically extracts API endpoints,
parameters, and other interesting information from all requests/responses flowing through
the proxy.

Installation:
1. Open Burp Suite
2. Go to Extender > BApp Store
3. Search for "GAP" or "Get All Parameters"
4. Install

Usage:
- Browse the target application with the proxy active
- GAP automatically extracts endpoints and parameters
- Review results in the GAP tab
- Export discovered endpoints for further analysis

#### 2.1.3 Webpack/Source Map Analysis

Webpack source maps (`.map` files) can reveal the original source code structure,
including API route definitions, before minification and bundling.

**Checking for Source Maps:**

```bash
# Check if source maps are publicly accessible
# Source maps are typically at the same URL with .map appended
curl -s -o /dev/null -w "%{http_code}" https://target.com/static/js/main.js.map
curl -s -o /dev/null -w "%{http_code}" https://target.com/static/js/app.bundle.js.map
curl -s -o /dev/null -w "%{http_code}" https://target.com/static/js/vendor.js.map

# Check for sourceMappingURL in JS files
grep -r "sourceMappingURL" *.js

# Typical source map filename patterns
# main.chunk.js -> main.chunk.js.map
# app-abc123.js -> app-abc123.js.map
# bundle.min.js -> bundle.min.js.map
```

**Extracting Source from Source Maps:**

```bash
# Install source map explorer tools
npm install -g source-map-explorer
npm install -g sourcemapper

# Using sourcemapper to extract original source
sourcemapper -url https://target.com/static/js/main.js.map -output ./extracted_source

# The extracted source will maintain the original directory structure
# Look for API route definitions
find ./extracted_source -name "*.js" -o -name "*.ts" -o -name "*.tsx" | \
  xargs grep -l "api\|endpoint\|fetch\|axios\|baseUrl\|apiUrl"

# Extract all API-related code from reconstructed source
find ./extracted_source -type f \( -name "*.js" -o -name "*.ts" -o -name "*.tsx" \) | \
  xargs grep -n "api/\|/graphql\|fetch(\|axios\.\|httpClient\.\|baseUrl\|API_URL" | \
  sort -u
```

**Source Map Exploitation Tool - unwebpack-sourcemap:**
```bash
# Install
pip3 install unwebpack-sourcemap

# Extract source from a webpack source map
unwebpack-sourcemap https://target.com/static/js/main.js.map ./output_dir

# Or from a local file
unwebpack-sourcemap ./main.js.map ./output_dir

# The tool recovers the original webpack module tree
```
