# API Security Agent System

A multi-agent workspace for **authorized Web API security assessment**, built in three separated layers so a small model can load exactly what it needs, when it needs it. Arrangement mirrors the `claude-bugbounty-vscode` reference workspace.

> **Authorized use only.** Every agent gates on scope and authorization before testing. Test only APIs you own or are explicitly permitted to test (a bug bounty program's scope or a signed engagement). See `instructions/copilot-instructions.md`.

---

## The Three Layers

```
api-security-agent-system/
│
├── instructions/                 ← ALWAYS-ON RULES (load first, every session)
│   └── copilot-instructions.md      scope gate, ROI priority, A→B chain table,
│                                     the knowledge-base map, interaction model
│
├── knowledge/                    ← KNOWLEDGE LAYER — reference only, never executed
│   ├── 00-intel/                    real-world data from 299 classified reports
│   ├── <vuln-class>/ … (49 folders) payloads, techniques, CVEs, detection, remediation
│   └── …                            ~220 chunk files, each sized for a small context window
│
└── prompts/                      ← PROMPT LAYER — the agents that DO the work
    ├── agents/   (19)               the orchestrator + 18 specialist "hunters"
    ├── commands/ (5)                workflow verbs: recon · hunt · chain · validate · report
    └── skills/   (5)                methodology · intel · live-internet-sources · triage · reporting
```

**Why separate?** A *knowledge* file states *what is true* about a vuln class. A *prompt* file states *what to do*. A hunter loads only its one knowledge folder (small context), tests, then hands off. Knowledge is read, never run.

---

## How To Use It

1. **Load the rules:** start every session with `instructions/copilot-instructions.md`.
2. **Start the orchestrator:** `prompts/agents/api-autopilot-hunter.prompt.md` — give it an in-scope target.
3. It runs **`recon`** → builds the surface map → **dispatches specialist hunters** by ROI → **`chain`** correlates their findings → **`validate`** kills false positives → **`report`** writes it up with fixes.

You can also invoke any piece directly — one command (e.g. `recon`), one hunter (e.g. `bola-idor-hunter`), or one skill (e.g. `hackerone-api-intel`).

---

## How The Agents Interact (the upgrade in this version)

The agents are no longer a flat list — they cooperate through three mechanisms:

**1. A shared session note** (format in `commands/hunt.prompt.md`). Every hunter reads and appends to the same note: Confirmed findings, Candidates, **Handoff Signals**, Dead Ends, New Surface.

**2. Handoff signals** — each hunter has a `CROSS-AGENT HANDOFF` section listing what it receives from and sends to other hunters. The orchestrator drains this queue and dispatches the named hunter. Examples:

```
ssrf-hunter  ──got cloud-metadata credential──▶  config-hunter   (scope the credential)
auth-hunter  ──forged a token for another sub──▶  bola-idor-hunter (re-test cross-object as that identity)
config-hunter──leaked API key──────────────────▶  bola-idor + bfla (map what it unlocks)
graphql-hunter──node() ids + types────────────▶  bola-idor-hunter (object-level authz per type)
mass-assignment──set role:admin────────────────▶  bfla-hunter     (confirm the privileged function opens)
```

**3. The `chain` command** reads the *whole* note and correlates A→B→C across classes — this is where a leaked key + a BOLA + an SSRF become one critical chain that no single hunter saw alone.

```
recon ─map─▶ orchestrator ─dispatch─▶ hunters ─findings+handoffs─▶ shared note
                  ▲                                                    │
   new surface ───┘        shared note ─▶ chain ─▶ validate ─▶ report (+fix)
```

---

## Reading From Live Internet Sources

`prompts/skills/live-intel-sources.prompt.md` is the registry agents use to stay current — CVE/NVD records, vendor advisories, OWASP text, specs, and freshly disclosed reports — with exact query patterns per class. Rule: pull **reference knowledge** only; never fetch-and-run exploit code against a target. When a live source teaches a new technique, the agent writes it back into the matching `knowledge/<class>/` folder so the snapshot improves over time.

---

## The Specialist Hunters (prompts/agents)

| Hunter | OWASP | Knowledge folder |
|---|---|---|
| `api-autopilot-hunter` | — (orchestrator) | dispatches all below |
| `config-hunter` | API8 + API9 | misconfiguration, inventory-management, framework-matrices |
| `bola-idor-hunter` | API1 | bola-idor |
| `auth-hunter` | API2 | broken-auth, foundations |
| `mass-assignment-hunter` | API3 | bopla-mass-assignment |
| `resource-consumption-hunter` | API4 | resource-consumption |
| `bfla-hunter` | API5 | bfla |
| `race-logic-hunter` | API6 | business-logic, race-conditions |
| `ssrf-hunter` | API7 | ssrf |
| `injection-hunter` | beyond/API10 | injection, prototype-pollution |
| `graphql-hunter` | cross | graphql |
| `protocol-hunter` | cross | websocket, protocols |
| `gateway-hunter` | cross | gateway-advanced |
| `serverless-hunter` | cross | serverless-misconfig |
| `ai-llm-hunter` | cross | ai-llm-security |
| `mobile-api-hunter` | cross | mobile-api-security |
| `supply-chain-hunter` | cross | supply-chain-api |
| `cache-deserialization-hunter` | cross | cache-deser-advanced |
| `webhook-hunter` | cross | webhook-security |

---

## Stats
- **3 layers**, **49 knowledge folders**, **~220 knowledge chunks** (each ~8–12K tokens)
- **19 agents** + **5 commands** + **5 skills** = 29 prompt files
- Covers the OWASP API Top 10, 15+ advanced classes, 7 protocols, 14 frameworks, 9 gateways, 60+ CVEs, 55+ hypothesis tests, and patterns from 299 real disclosed reports.

---

## V2 Additions

V2 expands the system from 12 to 19 agents (7 new specialist hunters) and from 27 to 49 knowledge folders (~220 chunks total). The additions focus on areas frequently seen in modern API assessments that v1 covered only at a surface level:

### 7 New Specialist Hunters
| Hunter | Focus |
|---|---|
| `gateway-hunter` | API gateway bypass, path normalization, header trust, rate-limit evasion across Kong/Envoy/Traefik/NGINX |
| `serverless-hunter` | Lambda/Cloud Function URL exposure (AUTH_TYPE=NONE), event injection, cold-start timing, env-var leakage |
| `ai-llm-hunter` | Prompt injection, MCP tool abuse, model endpoint auth, training-data extraction, LLM-to-API chains |
| `mobile-api-hunter` | Certificate pinning bypass, device attestation spoofing, hardcoded secrets in APK/IPA, API-key scope abuse |
| `supply-chain-hunter` | Third-party API integration risks, OAuth token reuse, dependency confusion, API-key leakage to vendors |
| `cache-deserialization-hunter` | Web cache deception/poisoning, CDN misconfig, Java/Python/PHP deserialization chains |
| `webhook-hunter` | Webhook signature bypass, SSRF via callback URLs, replay attacks, event subscription hijacking |

### Enhanced Existing Hunters (v2 additions appended)
- **protocol-hunter**: H2C smuggling, HTTP/2 desync (H2.CL/H2.TE), QUIC/HTTP/3 attacks, gRPC reflection exploitation, protobuf schema poisoning, WebSocket CSWSH, GraphQL subscription auth bypass
- **injection-hunter**: SSTI via JSON params (5 engines), advanced deserialization (Java/Python/PHP + CVE-2025-32444), DNS rebinding, file upload polyglots, cache deception/poisoning
- **config-hunter**: CORS null origin/subdomain takeover chaining/regex bypass (3 CVEs), Kubernetes API server misconfig, service mesh mTLS PERMISSIVE mode, serverless function URL exposure
- **auth-hunter**: Device code phishing, PKCE downgrade (CVE-2025-4144, CVE-2023-48228), JWT key reference injection (kid/jku/x5u/jwk), refresh token rotation race bypass

### New Knowledge Folders (22 added)
Covering: gRPC/protobuf attacks, HTTP/2 smuggling, QUIC/HTTP/3, advanced WebSocket hijacking, CORS bypass techniques, Kubernetes/cloud misconfig, service mesh security, serverless misconfig, OAuth advanced attacks, JWT key injection, SSTI, advanced deserialization, DNS rebinding, file upload attacks, cache deception, gateway security, AI/LLM security, mobile API security, supply-chain API risks, and webhook security.
