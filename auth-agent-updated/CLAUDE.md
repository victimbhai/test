# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

This is the **foundational** security testing agent - it must be executed first as other agents (IDOR, Privilege Escalation, API Security, Business Logic) depend on its knowledge base for session context, token handling, and authorization understanding.

The final output is a production-ready autonomous agent prompt (`agent/AUTH_AGENT_PROMPT.md`) that can detect and exploit authentication and authorization vulnerabilities.

## Architecture

```
auth-agent/
├── knowledge-base/     # 24 research files organized by topic
│   ├── 01-02           # Auth mechanisms, session management
│   ├── 03-05           # Credential attacks, auth bypass, session attacks
│   ├── 06-09           # Token attacks (JWT, OAuth, SAML, API)
│   ├── 10-11           # MFA bypass, WebAuthn attacks
│   ├── 12-13           # Access control, permission attacks
│   ├── 14-15           # Password reset, account recovery
│   ├── 16-17           # Registration attacks, enumeration
│   ├── 18-20           # Framework, cloud, mobile auth attacks
│   ├── 21              # Tools documentation
│   └── 22-24           # Case studies, CVEs, breach analysis
├── agent/
│   ├── AUTH_AGENT_PROMPT.md    # Production-ready agent system prompt
│   ├── methodology.md          # 12-phase testing methodology
│   └── auth-agent-logic.md     # Decision trees, attack selection, false positive filtering
├── tools/
│   ├── auth-tester.py          # Multi-protocol auth testing framework
│   ├── jwt-attacks.sh          # JWT attack automation (alg:none, key confusion, etc.)
│   ├── session-analyzer.py     # Session token entropy and security analysis
│   └── enum-users.py           # User enumeration via timing/response analysis
├── payloads/
│   ├── default-credentials.txt     # Common default creds by platform
│   ├── auth-bypass-payloads.txt    # SQL/NoSQL/LDAP injection, type juggling
│   ├── jwt-secrets.txt             # Weak JWT signing keys
│   ├── mfa-bypass-payloads.txt     # OTP bypass, response manipulation
│   └── oauth-redirect-payloads.txt # Redirect URI manipulation patterns
└── reports/
```

## Research Phases

The project follows 11 phases defined in `RESEARCH_PROMPT.md`:

| Phase | Focus | Knowledge Base Files |
|-------|-------|---------------------|
| 1 | Auth Mechanisms | 01-auth-mechanisms.md, 02-session-management.md |
| 2 | Auth Vulnerabilities | 03-credential-attacks.md, 04-auth-bypass.md, 05-session-attacks.md |
| 3 | Token Attacks | 06-jwt-attacks.md, 07-oauth-attacks.md, 08-saml-attacks.md, 09-api-auth-attacks.md |
| 4 | MFA Bypass | 10-mfa-bypass.md, 11-webauthn-attacks.md |
| 5 | Authorization | 12-access-control.md, 13-permission-attacks.md |
| 6 | Password Reset | 14-password-reset.md, 15-account-recovery.md |
| 7 | Registration | 16-registration-attacks.md, 17-enumeration.md |
| 8 | Tech-Specific | 18-framework-auth.md, 19-cloud-auth.md, 20-mobile-auth.md |
| 9 | Tooling | 21-tools.md |
| 10 | Real-World | 22-case-studies.md, 23-cve-analysis.md, 24-breach-analysis.md |
| 11 | Agent Creation | agent/methodology.md, agent/auth-agent-logic.md, agent/AUTH_AGENT_PROMPT.md |

## Commands

```bash
# Run authentication testing tools
python tools/auth-tester.py bruteforce -u https://target.com/login -U users.txt -P passwords.txt
python tools/auth-tester.py jwt -t <token>
python tools/session-analyzer.py -u https://target.com/login --cookies "session=abc123"
python tools/enum-users.py -u https://target.com/login -w usernames.txt

# JWT attack automation
bash tools/jwt-attacks.sh <jwt_token>

# Execute research phases
"Execute RESEARCH_PROMPT.md - launch parallel agents for all phases"
"Research JWT attacks and add to knowledge-base/06-jwt-attacks.md"

# Compile final agent
"Compile knowledge-base into final AUTH agent prompt"
```

## Dependent Agents

This auth-agent provides context to:
- **IDOR Agent** (`../idor-agent/`) - Session tokens for cross-account testing
- **Privilege Escalation Agent** - Role and permission understanding
- **API Security Agent** - Token authentication patterns
- **Business Logic Agent** - Multi-user session scenarios

---

# Extended Architecture (v3.0 - 2026-10)
# Original content above is UNCHANGED.

## Extended Architecture

```
auth-agent/
├── knowledge-base/     # 46 research files (32 original + 14 new)
│   ├── 01-24           # Original core knowledge base
│   ├── 25-32           # Original advanced knowledge base
│   ├── 33              # Framework middleware bypass (Next.js, Spring, etc.)
│   ├── 34              # AitM phishing & MFA bypass attacks
│   ├── 35              # HTTP/2-3 auth smuggling & token exchange
│   ├── 36              # CI/CD OIDC token abuse & SCIM attacks
│   ├── 37              # Kubernetes & service mesh auth bypass
│   ├── 38              # GraphQL, gRPC, WebSocket auth bypass
│   ├── 39              # Deserialization & SSTI in auth flows
│   ├── 40              # Race conditions & session puzzling
│   ├── 41              # Subdomain takeover, CORS, timing attacks
│   ├── 42              # AI/LLM agent auth exploitation
│   ├── 43              # NTLM, Kerberos, LDAP, RADIUS attacks
│   ├── 44              # Cloud IAM privilege escalation (AWS/Azure/GCP)
│   ├── 45              # Passkey sync & browser extension attacks
│   └── 46              # SCIM, Token Exchange, DPoP advanced attacks
├── agent/
│   ├── AUTH_AGENT_PROMPT.md    # v3.0 - Extended with KB 33-46 references
│   ├── methodology.md          # v3.0 - Extended with phases 13-20
│   └── auth-agent-logic.md     # v3.0 - Extended with 7 new decision trees
├── tools/
│   ├── auth-tester.py               # Original - Multi-protocol auth testing
│   ├── jwt-attacks.sh               # Original - JWT attack automation
│   ├── session-analyzer.py          # Original - Session token analysis
│   ├── enum-users.py                # Original - User enumeration
│   ├── framework-bypass-tester.py   # NEW - Framework middleware bypass
│   ├── graphql-auth-tester.py       # NEW - GraphQL auth testing
│   ├── race-condition-tester.py     # NEW - Single-packet race testing
│   └── cloud-iam-tester.py          # NEW - AWS/Azure/GCP IAM testing
├── payloads/
│   ├── default-credentials.txt      # Original
│   ├── auth-bypass-payloads.txt     # Original
│   ├── jwt-secrets.txt              # Original
│   ├── mfa-bypass-payloads.txt      # Original
│   ├── oauth-redirect-payloads.txt  # Original
│   ├── framework-bypass-payloads.txt    # NEW - Framework bypass payloads
│   ├── cicd-oidc-payloads.txt           # NEW - CI/CD OIDC payloads
│   ├── graphql-grpc-ws-payloads.txt     # NEW - GraphQL/gRPC/WebSocket
│   ├── race-condition-payloads.txt      # NEW - Race condition payloads
│   └── cloud-iam-payloads.txt           # NEW - Cloud IAM & network auth
└── reports/
```

## Extended Research Phases

| Phase | Focus | Knowledge Base Files |
|-------|-------|---------------------|
| 12 | Framework Middleware Bypass | 33-framework-middleware-bypass.md |
| 13 | AitM & MFA Advanced Bypass | 34-aitm-phishing-attacks.md |
| 14 | HTTP Smuggling & Token Abuse | 35-http-smuggling-auth.md |
| 15 | CI/CD OIDC & SCIM | 36-cicd-oidc-attacks.md |
| 16 | K8s & Service Mesh | 37-kubernetes-service-mesh-auth.md |
| 17 | GraphQL/gRPC/WebSocket | 38-graphql-grpc-websocket-auth.md |
| 18 | Deserialization & SSTI | 39-deserialization-ssti-auth.md |
| 19 | Race Conditions & Session | 40-race-conditions-advanced.md |
| 20 | Subdomain/CORS/Timing | 41-subdomain-cors-timing.md |
| 21 | AI/LLM Auth Exploitation | 42-ai-llm-auth-exploitation.md |
| 22 | Network & Legacy Auth | 43-network-legacy-modern-auth.md |
| 23 | Cloud IAM Escalation | 44-cloud-iam-advanced.md |
| 24 | Passkey & Browser Extensions | 45-passkey-browser-extension-attacks.md |
| 25 | SCIM/Token Exchange/DPoP | 46-scim-token-exchange-dpop.md |

## Extended Commands

```bash
# Framework middleware bypass testing
python tools/framework-bypass-tester.py https://target.com

# GraphQL auth testing
python tools/graphql-auth-tester.py https://target.com/graphql

# Race condition testing
python tools/race-condition-tester.py https://target.com

# Cloud IAM escalation testing
python tools/cloud-iam-tester.py aws
python tools/cloud-iam-tester.py azure
python tools/cloud-iam-tester.py gcp
python tools/cloud-iam-tester.py all
```

---

# Extended Architecture (v4.0 - Deep Research - 2026-10)
# Original content above is UNCHANGED.

## v4.0 Extended Architecture

```
auth-agent/
├── knowledge-base/     # 52 research files (32 original + 14 v3.0 + 6 v4.0)
│   ├── 01-24           # Original core knowledge base
│   ├── 25-32           # Original advanced knowledge base
│   ├── 33-46           # v3.0 extension (framework bypass, AitM, K8s, etc.)
│   ├── 47              # JWT/OAuth advanced attacks (JKU/X5U, issuer array, alg confusion)
│   ├── 48              # API gateway path normalization (trailing slash, double encoding)
│   ├── 49              # HTTP smuggling & WebSocket auth bypass (CL.TE, CSWSH)
│   ├── 50              # SSRF → cloud metadata chains, XSS→OAuth, IDOR→ATO
│   ├── 51              # Emerging auth threats (AitM, supply chain, token leakage)
│   └── 52              # Detection & prevention matrix (WAF rules, CVE index)
├── agent/
│   ├── AUTH_AGENT_PROMPT.md    # v4.0 - Extended with KB 47-52 references
│   ├── methodology.md          # v4.0 - Extended with phases 21-25
│   └── auth-agent-logic.md     # v4.0 - Extended with 5 new decision trees
├── tools/                      # 8 custom testing scripts
├── payloads/
│   ├── [9 original + 5 v3.0 payload files]
│   ├── path-normalization-payloads.txt     # NEW v4.0 - Gateway bypass payloads
│   └── advanced-chaining-payloads.txt      # NEW v4.0 - Multi-vector chaining
└── reports/
```

## v4.0 Research Phases

| Phase | Focus | Knowledge Base Files |
|-------|-------|---------------------|
| 21 | JWT Advanced & Token Forgery | 47-jwt-oauth-advanced-2025.md |
| 22 | API Gateway Path Normalization | 48-api-gateway-path-normalization.md |
| 23 | HTTP Smuggling & WebSocket | 49-http-smuggling-websocket-advanced.md |
| 24 | SSRF Chaining & Multi-Vector ATO | 50-ssrf-cloud-metadata-chains.md |
| 25 | Emerging Threats & Token Leakage | 51-emerging-auth-threats-2025.md, 52-detection-prevention-matrix.md |

## v4.0 CVE Coverage (30+ new CVEs)

Critical: CVE-2024-54150, CVE-2025-54576, CVE-2026-23760, CVE-2025-55315, CVE-2024-55591, CVE-2024-21893, CVE-2025-61882
High: CVE-2025-30144, CVE-2025-53864, CVE-2024-2419, CVE-2025-66202, CVE-2025-71399, CVE-2025-52882, CVE-2026-69192, CVE-2025-27152
