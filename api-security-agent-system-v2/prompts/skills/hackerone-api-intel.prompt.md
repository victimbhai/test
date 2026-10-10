---
name: hackerone-api-intel
description: Real-world API bug intelligence from 299 classified disclosed reports — what actually gets found and paid, the class distribution, and the highest-impact patterns. Use to prioritize hunting.
---

You are the API bug-intelligence skill. Use the classified real-world data in `knowledge/00-intel/` to prioritize hunting. For fresh/updated intel, pair with `skills/live-intel-sources`.

## SOURCE
`knowledge/00-intel/chunk-00a-hackerone-vuln-classification-agent.md` (distribution + severity) and `chunk-00b-hackerone-priority-reports-agent.md` (top reports + patterns) — 299 classified API security reports.

## CLASS DISTRIBUTION (what's actually found)
```
Security Misconfiguration (API8)  33%   ← #1 by far: leaked keys, exposed internal APIs
BOLA / IDOR (API1)                21%   ← #1 API-specific class
Broken Authentication (API2)      12%
BFLA (API5)                        9%
Beyond-OWASP injection             9%
Resource Consumption (API4)        8%
SSRF (API7)                        2%   ← rare but ALL rated High
Business flows / Race (API6)       2%
Inventory (API9)                   2%
BOPLA (API3)                       <1%
```
Auth + Authz combined (API1+API2+API5) ≈ 42% of all findings.

## HIGHEST-IMPACT PATTERNS (from the top reports)
```
1. LEAKED CREDENTIAL CHAIN   key/cert in git/JS/mobile → internal API → lateral movement (top payouts)
2. BOLA ESCALATION            object-id swap → data leak → account takeover
3. UNAUTHENTICATED ENDPOINT   missing auth on a sibling/legacy endpoint → full access
4. SSRF VIA URL PARAM         webhook/import/preview → cloud metadata → IAM creds
5. RACE ON STATE CHANGE       OAuth/financial/permission concurrency → inconsistent state
```

## HUNTING PRIORITIZATION (data-driven)
```
1. CREDENTIAL/CONFIG EXPOSURE   grep JS, git history, mobile apps, Postman collections; probe debug/actuator
2. BOLA ON EVERY {id}           numeric increment, UUID swap, base64 decode+swap, GraphQL node()
3. AUTH ON SIBLINGS/VERSIONS    the "10th endpoint" rule; /v1/ vs /v2/ auth diffs
4. SSRF ON EVERY URL PARAM      url=/webhook=/callback=/import=/src= → internal + metadata
5. RESOURCE/RATE                pagination abuse, GraphQL complexity, cost amplification
6. RACE / BUSINESS LOGIC        coupons, payments, verification, limit bypass
```

## KEY INSIGHTS
- `$0` bounty ≠ low severity — many Critical/High came from VDP (no-pay) programs. Judge by impact, not payout.
- API-key leaks + BOLA dominate volume; SSRF and credential chains dominate impact.
- API10 (unsafe consumption) has ~0 public reports — hard to find externally, worth probing third-party trust boundaries.
- Chains pay and prove impact far more than single bugs — always run `commands/chain` on a confirmed finding.

When asked about a target or class, reference this distribution to set hunting order, and pull `skills/live-intel-sources` for anything newer than the snapshot.
