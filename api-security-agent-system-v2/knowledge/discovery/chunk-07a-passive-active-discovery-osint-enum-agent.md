# OSINT Source Code Analysis & Active Endpoint Enumeration — Agent Chunk 07a
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Use certificate transparency logs and ASN enumeration for infrastructure discovery, search public code repos for leaked API configs and Postman collections, and begin active endpoint brute-forcing with ffuf
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Query crt.sh and certspotter for subdomains from certificate transparency logs. Enumerate ASN ranges to find all IP blocks owned by the target. Search GitHub for leaked API keys, OpenAPI specs, Postman collections, and .env files using org-specific dorks. Scan discovered Postman collections for complete endpoint inventories with auth details. Begin active directory brute-forcing with ffuf using API-specific wordlists and proper authentication headers.

---


#### 2.4.3 Certificate Transparency Logs

Certificate Transparency (CT) logs provide a public record of all TLS certificates
issued by participating Certificate Authorities. Querying these logs reveals
subdomains that have had certificates issued, including internal and API subdomains.

```bash
# Using crt.sh
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
names = set()
for entry in data:
    for name in entry.get('name_value', '').split('\n'):
        name = name.strip().lower()
        if name and '*' not in name:
            names.add(name)
for name in sorted(names):
    print(name)
" > ct_subdomains.txt

# Filter for API-related subdomains from CT logs
grep -iP "api|dev|staging|gateway|graphql|rest|internal" ct_subdomains.txt

# Using certspotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
names = set()
for entry in data:
    for name in entry.get('dns_names', []):
        name = name.strip().lower()
        if '*' not in name:
            names.add(name)
for name in sorted(names):
    print(name)
"
```

#### 2.4.4 ASN Enumeration

```bash
# Find the organization's ASN
whois -h whois.radb.net -- "-i origin $(whois target.com | grep -i origin | \
  awk '{print $NF}')" | grep "route:" | awk '{print $2}'

# Using amass for ASN enumeration
amass intel -org "Target Organization"

# Using bgp.he.net for ASN lookup (manual)
# https://bgp.he.net/search?search%5Bsearch%5D=target.com

# Enumerate all IPs in the ASN range and scan for API services
whois -h whois.radb.net -- "-i origin AS12345" | grep "route:" | \
  awk '{print $2}' > asn_ranges.txt

# Scan ASN ranges for HTTP services
cat asn_ranges.txt | nmap -sV -p 80,443,8080,8443,3000,5000,8000 -iL - \
  -oG api_scan_results.txt
```

### 2.5 Public Source Code Analysis

Public code repositories are a treasure trove for API discovery. Developers
inadvertently push API configurations, credentials, internal documentation, and
complete API specifications to public repositories.

#### 2.5.1 GitHub Search for API Information

```
# Search for API documentation and configs
"target.com" api_key
"target.com" api_secret
"target.com" apikey
"target.com" apisecret
"target.com" filename:swagger.json
"target.com" filename:swagger.yaml
"target.com" filename:openapi.json
"target.com" filename:openapi.yaml
"target.com" filename:.env
"target.com" filename:config.json
"target.com" filename:config.yaml
"target.com" filename:config.yml
"target.com" filename:settings.py
"target.com" filename:application.properties
"target.com" filename:application.yml
"target.com" filename:appsettings.json
"target.com" filename:docker-compose.yml

# Organization-specific searches
org:target filename:.env
org:target filename:swagger.json
org:target filename:openapi.json
org:target "api_key"
org:target "secret_key"
org:target "access_token"
org:target "database_url"
org:target "AWS_ACCESS_KEY"
org:target path:postman

# Search for Postman collections
org:target filename:postman_collection.json
org:target filename:postman_environment.json
"target.com" filename:postman_collection.json

# Search for API client libraries
org:target "Authorization: Bearer"
org:target "x-api-key"
org:target "api/v"

# Search for CI/CD configurations that reference APIs
org:target filename:.github/workflows
org:target filename:.gitlab-ci.yml
org:target filename:Jenkinsfile
org:target filename:Dockerfile "API_URL"
```

**Using GitHub CLI for Automated Searches:**

```bash
# Search for code containing API references
gh search code "target.com api" --limit 100

# Search for repositories with API documentation
gh search repos "target.com api documentation" --limit 50

# Search for specific file types
gh search code "target.com" --filename swagger.json --limit 50
gh search code "target.com" --filename openapi.yaml --limit 50
```

#### 2.5.2 Postman Collection Discovery

Postman public workspaces and shared collections frequently contain complete API
inventories with authentication details, example requests, and test data.

```bash
# Search Postman public workspaces
# Via Postman Explore: https://www.postman.com/explore

# Search the Postman public API network
curl -s "https://www.postman.com/search?q=target.com&type=all" | \
  python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin), indent=2))"

# Google dork for Postman collections
# site:documenter.getpostman.com "target.com"
# site:postman.com "target.com"

# Download and analyze Postman collections from GitHub
gh search code "target.com" --filename postman_collection.json --limit 50 --json path,repository
```

**Analyzing Postman Collections:**

```python
#!/usr/bin/env python3
"""Extract API endpoints from Postman collections."""
import json
import sys

def extract_requests(item, base_url=""):
    """Recursively extract requests from Postman collection items."""
    endpoints = []

    if 'item' in item:
        # This is a folder
        for sub_item in item['item']:
            endpoints.extend(extract_requests(sub_item, base_url))
    elif 'request' in item:
        request = item['request']
        method = request.get('method', 'GET')
        url = request.get('url', {})

        if isinstance(url, str):
            path = url
        elif isinstance(url, dict):
            raw = url.get('raw', '')
            path = raw
            # Also extract from path array
            if 'path' in url:
                path = '/' + '/'.join(url['path'])
            if 'host' in url:
                host = '.'.join(url['host']) if isinstance(url['host'], list) else url['host']
                base_url = host

        # Extract headers
        headers = {}
        if isinstance(request.get('header'), list):
            for h in request['header']:
                headers[h.get('key', '')] = h.get('value', '')

        # Extract auth
        auth = request.get('auth', {})

        endpoints.append({
            'name': item.get('name', 'Unknown'),
            'method': method,
            'url': path,
            'base_url': base_url,
            'headers': headers,
            'auth_type': auth.get('type', 'none') if isinstance(auth, dict) else 'none',
        })

    return endpoints

if __name__ == '__main__':
    with open(sys.argv[1]) as f:
        collection = json.load(f)

    endpoints = []
    for item in collection.get('item', []):
        endpoints.extend(extract_requests(item))

    print(f"\n{'='*80}")
    print(f"Collection: {collection.get('info', {}).get('name', 'Unknown')}")
    print(f"Total endpoints found: {len(endpoints)}")
    print(f"{'='*80}\n")

    for ep in endpoints:
        print(f"  [{ep['method']}] {ep['url']}")
        if ep['headers']:
            for k, v in ep['headers'].items():
                if k.lower() in ('authorization', 'x-api-key', 'api-key'):
                    print(f"    Auth Header: {k}: {v[:20]}...")
        if ep['auth_type'] != 'none':
            print(f"    Auth Type: {ep['auth_type']}")
```

#### 2.5.3 GitLab, Bitbucket, and Other Repositories

```bash
# GitLab search (for public GitLab instances)
# https://gitlab.com/search?search=target.com+api

# Bitbucket search
# https://bitbucket.org/search?q=target.com+api

# Using truffleHog for secret scanning in repositories
pip3 install trufflehog
trufflehog github --org target --only-verified

# Using gitleaks for secret detection
gitleaks detect --source /path/to/cloned/repo --report-format json \
  --report-path gitleaks_report.json

# Search for API-relevant files
gitleaks detect --source /path/to/repo --config-path custom_config.toml
```

---

## 3. Active Discovery Techniques

Active discovery involves directly interacting with the target to identify API endpoints,
parameters, and behaviors. These techniques generate traffic to the target and may be
detected by security monitoring systems.

### 3.1 Endpoint Enumeration

#### 3.1.1 Directory Brute-Forcing with API-Specific Wordlists

**Using ffuf (Fuzz Faster U Fool):**

```bash
# Installation
go install github.com/ffuf/ffuf/v2@latest

# Basic API endpoint discovery
ffuf -u https://api.target.com/FUZZ -w /path/to/api-wordlist.txt \
  -mc 200,201,202,204,301,302,307,401,403,405 \
  -o ffuf_results.json -of json

# Discovery with common API prefixes
ffuf -u https://target.com/api/FUZZ -w /path/to/api-wordlist.txt \
  -mc 200,201,202,204,301,302,307,401,403,405

# Discovery with version prefix
ffuf -u https://target.com/api/v1/FUZZ -w /path/to/api-wordlist.txt \
  -mc 200,201,202,204,301,302,307,401,403,405

# Recursive discovery
ffuf -u https://api.target.com/FUZZ -w /path/to/api-wordlist.txt \
  -mc 200,201,202,204,301,302,307,401,403,405 \
  -recursion -recursion-depth 3

# Multiple wordlist positions (path + extension)
ffuf -u https://api.target.com/FUZZ1.FUZZ2 \
  -w /path/to/api-wordlist.txt:FUZZ1 \
  -w extensions.txt:FUZZ2 \
  -mc 200,201,202,204,301,302,307,401,403

# With authentication
ffuf -u https://api.target.com/api/v1/FUZZ \
  -w /path/to/api-wordlist.txt \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -mc 200,201,202,204,301,302,307,403,405

# Filter out common false positives by response size
ffuf -u https://api.target.com/FUZZ -w /path/to/api-wordlist.txt \
  -mc all -fs 0 -fw 1

# POST endpoint discovery
ffuf -u https://api.target.com/api/v1/FUZZ \
  -w /path/to/api-wordlist.txt \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{}' \
  -mc 200,201,202,204,400,401,403,405,422
```
