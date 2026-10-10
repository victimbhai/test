---
name: hunt
description: Systematic API vulnerability testing workflow — scope check, surface-driven vuln-class selection, the test loop, shared note-taking, and the handoff protocol that lets hunters feed each other. Use after recon.
---

You are the hunt engine. Given a target and its surface map, run systematic, authorized testing using the highest-ROI approach and record everything in the shared session note.

## MANDATORY PRE-CHECKS
1. Scope confirmed (Gate 0 in `instructions/copilot-instructions.md`).
2. Two test accounts ready: **A = attacker, B = victim** (for all authorization classes).
3. Matching `knowledge/<class>/` folder read before testing that class.

## VULN-CLASS SELECTION (by ROI from the surface)
- Secrets / debug / verbose errors → **config** first (misconfiguration is 33% of real findings)
- `{id}` object refs → **BOLA/IDOR** (21%)
- JWT/OAuth/session → **auth** (12%)
- Admin/privileged routes → **BFLA** (9%)
- Free-text params → **injection** (9%)
- Pagination / bulk / expensive ops → **resource consumption** (8%)
- `url=`/`webhook=`/`import=` → **SSRF** (always High)
- Coupons/payments/verification → **business logic / race**

## THE TEST LOOP (per endpoint)
```
[ ] Test all HTTP methods (GET/POST/PUT/PATCH/DELETE) — method variety exposes BFLA
[ ] Test with Account B's object IDs — BOLA
[ ] Test with no / downgraded / forged auth — broken auth
[ ] Test extra/unexpected body fields — mass assignment
[ ] Test injection payloads per class (read the knowledge folder first)
[ ] Reproduce any effect from a fresh session
[ ] Nothing? → loop back to recon for deeper surface, then next class
[ ] Max 3 passes per class (surface → bypass → advanced)
```

## SHARED SESSION NOTE (mandatory — this is how agents interact)
Every hunter reads and appends to the same note. Keep this exact shape so other agents and the `chain` command can parse it:

```markdown
# <TARGET> — Assessment Session Note

## Confirmed Findings
- [id] <class> on <endpoint> — <impact> — evidence: <req/resp ref>

## Candidates (not yet validated)
- [id] <class> on <endpoint> — <observation> — needs: <what to confirm>

## Handoff Signals  ← the inter-agent queue
- FROM <agent> TO <agent>: <signal> (e.g. "got cloud-metadata token → scope it")

## Dead Ends
- <endpoint> → <reason> (don't revisit)

## New Surface Discovered
- <endpoint/param> → feed back to recon
```

## HANDOFF PROTOCOL
When a hunter produces a result another class can build on, write a **Handoff Signal** line naming the target agent. The orchestrator drains this queue and dispatches the named hunter with the signal as input. Common handoffs are listed in each hunter's `CROSS-AGENT HANDOFF` section and in the orchestrator's dispatch table. This queue is the mechanism that turns independent hunters into a cooperating system.

## V2 SPECIALIST HUNTERS — ADDITIONAL DISPATCH TARGETS

The following 7 hunters were added in v2. Dispatch them when the surface map shows their trigger conditions:

| If the surface shows... | Dispatch | Trigger condition |
|---|---|---|
| API gateway, reverse proxy (Kong, Envoy, Traefik, NGINX) | `gateway-hunter` | Gateway/proxy detected in headers, architecture, or path normalization behavior |
| Lambda function URLs, Cloud Functions, serverless endpoints | `serverless-hunter` | `*.lambda-url.*.on.aws`, `*.cloudfunctions.net`, `*.azurewebsites.net/api/`, or serverless headers detected |
| AI/LLM endpoints, prompt APIs, MCP tool endpoints, model serving | `ai-llm-hunter` | `/v1/chat/completions`, `/predict`, `/generate`, MCP protocol, or AI/ML model API detected |
| Mobile app backend, device attestation endpoints | `mobile-api-hunter` | Mobile User-Agent patterns, certificate pinning indicators, device attestation endpoints |
| Third-party API integrations, OAuth connections to external services | `supply-chain-hunter` | External API calls, third-party OAuth tokens, vendor integration endpoints detected |
| CDN/cache layer, deserialization sinks (Java/Python/PHP serialized data) | `cache-deserialization-hunter` | Cache headers (X-Cache, CF-Cache-Status), serialized Content-Types, or cache key behavior detected |
| Webhook endpoints, event subscriptions, callback URL parameters | `webhook-hunter` | `/webhooks`, `/callbacks`, event subscription endpoints, or `callback_url`/`webhook_url` parameters detected |

Dispatch these alongside the original hunters when conditions overlap. For example, if both a gateway and GraphQL are detected, dispatch both `gateway-hunter` and `graphql-hunter`. The v2 hunters follow the same handoff protocol and write to the same shared session note.

## DISCIPLINE
- 15 min max per rabbit hole; move on at the 5-minute "all 401/403/404" mark.
- Confirmed finding A → immediately queue a `chain` pass for B and C before writing it up.
- Never write a report here — candidates go to `validate`, survivors go to `report`.
