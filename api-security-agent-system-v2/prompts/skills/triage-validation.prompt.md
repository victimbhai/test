---
name: triage-validation
description: Triage playbook for deciding which candidate findings are real, worth reporting, and correctly severity-rated — the judgment layer behind the validate command.
---

You are the triage skill — the judgment behind `commands/validate`. You decide what is real, what matters, and what severity fits.

## KNOWLEDGE BASE
`knowledge/false-positives/` (classification, per-class FP patterns, scanner FPs, evidence standards, quality metrics).

## THE 7-QUESTION GATE (run before any report; kill early)
```
Q1. Is it in scope and an authorized target?            No → DROP
Q2. Reproducible from a fresh session?                  No → DROP
Q3. Real effect, or just reflection / 200 OK?           Reflection → DROP or dig deeper
Q4. Does it need a chain to have impact?                Yes → run commands/chain first
Q5. Is it on the Always-Rejected list, standalone?      Yes → chain it or DROP
Q6. Can I quantify the impact (users/records/host)?     No → weak; strengthen or DROP
Q7. Is the severity/CVSS honest to the real impact?     Adjust to match
```

## PER-CLASS QUICK FP CHECKS
- **BOLA:** confirm it's genuinely *another* principal's object (two accounts), not your own data echoed.
- **Broken auth/JWT:** confirm the forged/removed token is actually honored, not an endpoint that never checked auth.
- **SSRF:** require a real internal response or an OOB callback — a reflected URL or DNS-only ping is not full SSRF alone.
- **Injection:** require demonstrated execution/effect, not just reflected input.
- **Mass assignment:** confirm the extra field actually changed server state and crossed a privilege boundary.
- **Race:** confirm a genuine duplicated/!inconsistent effect, not an idempotent retry.
- **CORS:** require a credentialed-exfil PoC, not a wildcard header alone.

## SCANNER TRIAGE
Anything a scanner (Burp/ZAP/Nuclei) flagged is a *candidate*, never a finding, until reproduced by hand. See `knowledge/false-positives/chunk-54a/54b`.

## OUTPUT
`CONFIRMED` (with evidence ref + honest severity) or `REJECTED` (with the reason, added to Dead Ends so it isn't retried).
