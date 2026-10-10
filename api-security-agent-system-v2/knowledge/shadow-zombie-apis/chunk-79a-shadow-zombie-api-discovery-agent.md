# Shadow & Zombie API Discovery — Agent Chunk 79a
> Source: OWASP API9:2023, Salt Security State of API Security 2024, LinkFinder, SecLists, Wayback Machine
> Purpose: Teaches the agent to discover undocumented (shadow) and deprecated (zombie) API endpoints that bypass modern security controls
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this chunk when performing API inventory assessment or when looking for undocumented endpoints. Shadow APIs are undocumented but active; zombie APIs are deprecated but still reachable. Both often lack current security controls. Start with passive discovery (JS analysis, Wayback), then move to active fuzzing.

---

## 1. OWASP API9:2023 — Improper Inventory Management

### Definition
APIs that are not properly inventoried, documented, or retired create attack surface that security teams do not monitor. This includes:
- **Shadow APIs**: Endpoints deployed by developers without going through the API gateway or documentation process
- **Zombie APIs**: Old API versions that were supposed to be retired but remain accessible
- **Rogue APIs**: APIs deployed by third parties or partners without authorization

### Salt Security 2024 Report Key Findings
- 37% of organizations discovered shadow APIs they did not know existed
- 54% of organizations had zombie APIs still accessible in production
- Average time to discover a shadow API: 172 days
- 68% of shadow APIs lacked any authentication
- API attacks increased 400% in the six months before the report

---

## 2. Shadow API Discovery Techniques

### Step 1: JavaScript Analysis with LinkFinder

```bash
# Install LinkFinder
git clone https://github.com/GerbenJav);ado/LinkFinder.git
cd LinkFinder && pip install -r requirements.txt

# Extract endpoints from JavaScript files
python3 linkfinder.py -i https://target.com -d -o results.html

# Extract from a specific JS file
python3 linkfinder.py -i https://target.com/static/app.bundle.js -o cli
```

**Manual JS Analysis Patterns:**
```bash
# Download all JS files
curl -s https://target.com | grep -oP 'src="[^"]*\.js"' | \
  sed 's/src="//;s/"//' | while read js; do
    curl -s "https://target.com$js" >> all_js.txt
  done

# Search for API endpoints
grep -oP '["'"'"']/api/[a-zA-Z0-9/_-]+' all_js.txt | sort -u

# Search for fetch/axios calls
grep -oP '(fetch|axios)\s*\(\s*['"'"'"`][^'"'"'"`]+' all_js.txt

# Search for hidden parameters
grep -oP '[?&][a-zA-Z_]+=' all_js.txt | sort -u
```

### Step 2: ChkApi — API Endpoint Validation
```bash
# Validate discovered endpoints
# ChkApi checks if discovered paths respond
chkapi -u https://target.com -w discovered_endpoints.txt -o valid_endpoints.txt
```

### Step 3: Wordlist Fuzzing with ffuf

```bash
# General API endpoint fuzzing
ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,307,401,403,405 -o results.json

# Version-based fuzzing
ffuf -u https://target.com/api/vFUZZ/users -w <(seq 1 20) \
  -mc 200,201,204,301,302,307,401,403

# Common shadow API paths
ffuf -u https://target.com/FUZZ -w - << 'EOF'
/internal/api
/debug/api
/api/internal
/api/private
/api/hidden
/api/dev
/api/test
/api/staging
/api/beta
/api/admin
/swagger.json
/openapi.json
/api-docs
/graphql
/graphiql
/_api
/rest
/v1/internal
/actuator
/health
/metrics
/env
EOF
```

### Step 4: Traffic Analysis (Passive Discovery)
```bash
# Using mitmproxy to capture API traffic
mitmproxy -w traffic_dump.flow

# Extract unique API endpoints from captured traffic
mitmdump -r traffic_dump.flow --set flow_detail=1 | \
  grep -oP '(GET|POST|PUT|DELETE|PATCH)\s+https?://[^\s]+' | sort -u
```

### Step 5: Wayback Machine Enumeration
```bash
# Query Wayback Machine for historical API endpoints
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/api/*&output=text&fl=original&collapse=urlkey" | \
  sort -u > wayback_apis.txt

# Also check for old swagger/openapi docs
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/swagger*&output=text&fl=original&collapse=urlkey"
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/openapi*&output=text&fl=original&collapse=urlkey"

# Use gau (Get All URLs)
gau target.com | grep -iE '/api/|/v[0-9]+/' | sort -u
```

### Step 6: APK Decompilation (Mobile API Discovery)
```bash
# Decompile Android APK
apktool d target_app.apk -o decompiled/

# Search for API endpoints in smali and resources
grep -rP 'https?://[a-zA-Z0-9.-]+/api' decompiled/ | sort -u

# Use JADX for Java source recovery
jadx target_app.apk -d jadx_output/
grep -rP '(BASE_URL|API_URL|endpoint|apiUrl)' jadx_output/ | sort -u
```

---

## 3. Zombie API Exploitation

### Version Downgrade Attack
```bash
# Current API (v3) requires OAuth2 + MFA
curl -H "Authorization: Bearer <token>" https://target.com/api/v3/users/me
# Response: requires MFA challenge

# Old API (v1) may still accept API key only
curl -H "X-API-Key: leaked_key" https://target.com/api/v1/users/me
# Response: full user profile with PII (no MFA required)
```

### Unredacted Data in Old Versions
```bash
# v3 response (current, properly redacted)
{
  "id": 1234,
  "email": "u***@example.com",
  "phone": "***-***-5678",
  "ssn": null
}

# v1 response (zombie, unredacted)
{
  "id": 1234,
  "email": "user@example.com",
  "phone": "555-123-5678",
  "ssn": "123-45-6789",
  "internal_notes": "VIP customer - bypass verification"
}
```

### Common Zombie API Patterns
```
# Version enumeration
/api/v1/  -> Often lacks RBAC, returns raw data
/api/v2/  -> May have partial security
/api/v3/  -> Current, fully secured

# Legacy path patterns
/api/legacy/
/api/old/
/api/deprecated/
/api-v1/
/services/v1/
/ws/v1/        # SOAP-era web services
```

---

## 4. Comprehensive Discovery Workflow

```
Phase 1 - Passive Recon (no target interaction)
  1. Wayback Machine enumeration
  2. Certificate transparency logs (crt.sh)
  3. DNS enumeration (subdomain discovery)
  4. GitHub/GitLab code search for API paths
  5. Google dorking: site:target.com inurl:api

Phase 2 - Semi-Passive (normal browsing)
  6. JavaScript file analysis (LinkFinder)
  7. Browser DevTools network tab monitoring
  8. Mobile app decompilation

Phase 3 - Active Discovery
  9. Wordlist fuzzing (ffuf/gobuster)
  10. Version enumeration
  11. Content-type variation testing
  12. HTTP method enumeration per endpoint

Phase 4 - Validation
  13. Compare discovered endpoints against API documentation
  14. Test authentication requirements on each endpoint
  15. Compare response schemas across API versions
  16. Flag endpoints missing from API gateway logs
```

---

## 5. Detection & Mitigation
- Maintain a real-time API inventory with automated discovery tools
- Route all API traffic through an API gateway with logging
- Implement automated decommissioning: if an API version is deprecated, remove the route
- Monitor for API calls to undocumented endpoints (anomaly detection)
- Require all APIs to register with a central catalog before deployment
- Use API schema validation to reject requests to unregistered endpoints
