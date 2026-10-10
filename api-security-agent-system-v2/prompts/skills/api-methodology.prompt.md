---
name: api-methodology
description: The end-to-end methodology for an authorized API assessment — the phase order, which knowledge folders and agents map to each phase, and how findings flow between agents. The playbook the orchestrator follows.
---

You are the API assessment methodology skill. You hold the phase order and the map of which knowledge + agents serve each phase. Everything here is for **authorized, in-scope** targets.

## THE 7 PHASES

### Phase 1 — Pre-Engagement
`knowledge/testing-methodology/chunk-44a` (scope rules), `chunk-44b` (accounts/tools), `chunk-51b` (safe boundaries).
Confirm authorization, scope, excluded classes, test accounts A & B, and the boundaries (what's lab-only).

### Phase 2 — Recon & Surface Mapping
`knowledge/discovery/` → `commands/recon`.
Passive first, then authorized active enumeration. Output the surface map.

### Phase 3 — Hypothesis Generation
`knowledge/testing-methodology/chunk-45*` (auth), `chunk-46*` (authz), `chunk-47*` (input), `chunk-48a/48b` (logic/config), `chunk-49a` (authz matrix).
Turn the surface map into concrete, testable hypotheses per class. Build the authorization matrix (role × endpoint).

### Phase 4 — Testing (dispatch specialists)
`commands/hunt` drives each `prompts/agents/*-hunter`. ROI order from `instructions/copilot-instructions.md`. Hunters read their `knowledge/<class>/` folder, test, and write to the shared note.

### Phase 5 — Correlation
`commands/chain` reads all findings → A→B→C chains across classes. `knowledge/owasp-chaining/` + `knowledge/testing-methodology/chunk-50a` (chaining).

### Phase 6 — Validation
`commands/validate` → `knowledge/false-positives/`. Kill FPs, meet the evidence standard.

### Phase 7 — Reporting & Remediation
`commands/report` → `knowledge/remediation/`. Every finding ships with a fix and a regression test.

## DATA FLOW BETWEEN AGENTS
```
recon ─surface map─▶ orchestrator ─dispatch─▶ hunters ─findings+handoffs─▶ shared note
shared note ─▶ chain (correlate) ─chains─▶ validate (FP gate) ─confirmed─▶ report (+fix)
                       ▲                                                        │
                       └──────────── new surface / live-intel refresh ◀─────────┘
```

## COVERAGE TRACKING
Use `knowledge/gap-analysis/chunk-56d-gap-tracking-matrix-agent.md` to track which classes × endpoints have been tested, so "we tested everything" is provable, not assumed.

## PROTOCOL BRANCHES
- REST → `knowledge/protocols/chunk-31*`
- GraphQL → `knowledge/graphql/` + `agents/graphql-hunter`
- WebSocket → `knowledge/websocket/` + `agents/protocol-hunter`
- gRPC/SOAP/JSON-RPC/SSE/webhook/gateway → `knowledge/protocols/chunk-34..39`

## V2 Extended Coverage

V2 adds new vulnerability classes, specialist hunters, and knowledge paths to extend coverage beyond the original methodology phases.

### New Vulnerability Classes and Knowledge Paths

| Vulnerability Class | Knowledge Path | Specialist Hunter |
|---|---|---|
| H2C Smuggling | `knowledge/http2-http3/chunk-73a-http2-smuggling-desync-agent.md` | `protocol-hunter` |
| HTTP/2 Desync (H2.CL, H2.TE) | `knowledge/http2-http3/chunk-73a-http2-smuggling-desync-agent.md` | `protocol-hunter` |
| QUIC/HTTP/3 Connection Migration | `knowledge/http2-http3/chunk-73b-quic-http3-attacks-agent.md` | `protocol-hunter` |
| gRPC Reflection + Protobuf Attacks | `knowledge/grpc-protobuf/chunk-72a-grpc-reflection-protobuf-attacks-agent.md` | `protocol-hunter` |
| WebSocket CSWSH + State Attacks | `knowledge/websocket-advanced/chunk-75a-websocket-hijacking-state-attacks-agent.md` | `protocol-hunter` |
| SSTI via API JSON Parameters | `knowledge/injection-advanced/chunk-74a-ssti-api-parameters-agent.md` | `injection-hunter` |
| Advanced Deserialization (Java/Python/PHP) | `knowledge/injection-advanced/chunk-74b-deserialization-polyglot-agent.md` | `injection-hunter` |
| DNS Rebinding | `knowledge/injection-advanced/chunk-74c-dns-rebinding-agent.md` | `injection-hunter` |
| File Upload Path Traversal + Polyglots | `knowledge/injection-advanced/chunk-74d-file-upload-path-traversal-agent.md` | `injection-hunter` |
| Cache Deception / Poisoning | `knowledge/injection-advanced/chunk-74e-cache-deception-poisoning-agent.md` | `injection-hunter`, `cache-deserialization-hunter` |
| CORS Advanced Bypass | `knowledge/cors-advanced/chunk-76a-cors-bypass-subdomain-takeover-agent.md` | `config-hunter` |
| Kubernetes API Server Misconfig | `knowledge/k8s-cloud-misconfig/chunk-77a-kubernetes-api-server-misconfig-agent.md` | `config-hunter` |
| Service Mesh mTLS PERMISSIVE | `knowledge/k8s-cloud-misconfig/chunk-77b-service-mesh-mtls-misconfig-agent.md` | `config-hunter` |
| Serverless Function URL Exposure | `knowledge/serverless-misconfig/chunk-78a-serverless-function-url-exposure-agent.md` | `config-hunter`, `serverless-hunter` |
| Device Code Phishing | `knowledge/oauth-advanced/chunk-79a-device-code-phishing-agent.md` | `auth-hunter` |
| PKCE Downgrade Attacks | `knowledge/oauth-advanced/chunk-79b-pkce-downgrade-attacks-agent.md` | `auth-hunter` |
| Refresh Token Rotation Bypass | `knowledge/oauth-advanced/chunk-79c-refresh-token-rotation-bypass-agent.md` | `auth-hunter` |
| JWT Key Reference Injection | `knowledge/jwt-advanced/chunk-80a-jwt-key-reference-injection-agent.md` | `auth-hunter` |
| API Gateway Bypass | `knowledge/gateway-advanced/` | `gateway-hunter` |
| AI/LLM Prompt Injection + MCP Abuse | `knowledge/ai-llm-security/` | `ai-llm-hunter` |
| Mobile API Hardcoded Secrets | `knowledge/mobile-api-security/` | `mobile-api-hunter` |
| Supply Chain API Risks | `knowledge/supply-chain-api/` | `supply-chain-hunter` |
| Webhook Signature Bypass + Replay | `knowledge/webhook-security/` | `webhook-hunter` |

### Integration with Existing Phases

- **Phase 2 (Recon)**: surface mapping now detects gateways, serverless endpoints, AI/LLM APIs, mobile backends, and webhook endpoints as dispatch triggers for v2 hunters.
- **Phase 3 (Hypothesis)**: new hypothesis templates for H2C smuggling, PKCE downgrade, device code phishing, JWT key injection, SSTI, and cache deception.
- **Phase 4 (Testing)**: 7 new hunters join the dispatch table. Existing hunters (protocol, injection, config, auth) have expanded test matrices covering v2 vulnerability classes.
- **Phase 5 (Correlation)**: new chain patterns — e.g., gateway bypass → unauthenticated origin → data access; cache poisoning → stored XSS → session hijack; device code phishing → token theft → account takeover.
