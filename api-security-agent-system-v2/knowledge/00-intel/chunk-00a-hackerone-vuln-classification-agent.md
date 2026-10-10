# HackerOne Vulnerability Classification & Statistics — Agent Chunk 00a
> Source: 02-public-report-manifest.md
> Purpose: Understand real-world API vulnerability distribution patterns from 299 HackerOne reports to prioritize testing efforts
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this data to understand which vulnerability categories are most common in real bug bounty programs. Prioritize your testing based on these real-world frequency distributions. When you find a vulnerability, classify it using the OWASP mapping and severity schema below.

---

## Classification Schema

Each of the 299 public HackerOne API security reports is classified across five dimensions.

### OWASP API Security Top 10 (2023) Mapping

| Code | OWASP Category | Description | Typical Indicators |
|------|---------------|-------------|---------------------|
| API1 | Broken Object Level Authorization (BOLA) | IDOR, unauthorized data access to other users' objects | "IDOR", "leak user info", "disclose email", "private data", "unauthorized access to user" |
| API2 | Broken Authentication | Auth bypass, credential leaks, session issues | "account takeover", "auth bypass", "leaked certificate", "OTP leak", "banned user access" |
| API3 | Broken Object Property Level Authorization (BOPLA) | Mass assignment, excessive data exposure at property level | "mass assignment", "enable API access for free" |
| API4 | Unrestricted Resource Consumption | Rate limiting, DoS, resource exhaustion | "DoS", "rate limit", "brute force", "infinite loop", "email bomb" |
| API5 | Broken Function Level Authorization (BFLA) | Privilege escalation, admin function access by regular users | "privilege escalation", "admin endpoint", "create admin", "restricted user can" |
| API6 | Unrestricted Access to Sensitive Business Flows | Race conditions, business logic abuse | "race condition", "business logic" |
| API7 | Server Side Request Forgery (SSRF) | SSRF through API endpoints | "SSRF", "XSPA" |
| API8 | Security Misconfiguration | API key leaks, exposed endpoints, misconfigurations | "API key leaked", "exposed API", "misconfiguration", "hardcoded key" |
| API9 | Improper Inventory Management | Shadow APIs, undocumented endpoints, zombie APIs | "undocumented API", "shadow", "internal API", "beta api" |
| API10 | Unsafe Consumption of APIs | Trusting third-party API responses without validation | "third-party", "external API trust" |
| Beyond-OWASP | Outside OWASP API Top 10 | XSS, CSRF, SQLi, RCE, injection via API surfaces | "XSS", "CSRF", "SQLi", "injection", "RCE" |

### Vulnerability Type Taxonomy

- **IDOR** — Insecure Direct Object Reference
- **Auth Bypass** — Authentication mechanism bypass
- **API Key Leak** — Exposed API keys, tokens, or secrets
- **Credential Leak** — Exposed passwords, certificates, or secrets (non-API-key)
- **Info Disclosure** — Sensitive information exposure through API responses
- **Privilege Escalation** — Unauthorized access to higher-privilege functions
- **SSRF** — Server-Side Request Forgery
- **CSRF** — Cross-Site Request Forgery via API
- **XSS** — Cross-Site Scripting via API surfaces
- **SQLi** — SQL Injection via API parameters
- **NoSQLi** — NoSQL Injection via API parameters
- **DoS** — Denial of Service / Resource Exhaustion
- **Rate Limiting** — Missing or bypassable rate limits
- **Race Condition** — Time-of-check to time-of-use flaws
- **Mass Assignment** — Unintended property modification
- **RCE** — Remote Code Execution via API
- **Injection** — Generic injection (command, flag, CRLF, HTML)
- **Misconfiguration** — Server/endpoint misconfiguration
- **Shadow API** — Undocumented or deprecated API exposure
- **Cache Poisoning** — Cache-based attacks on API responses
- **Path Traversal** — Directory traversal via API

### Severity Estimation Guidelines

| Severity | Criteria |
|----------|----------|
| Critical | RCE, full account takeover, complete data breach, bounty >= $10000 |
| High | Significant data leak, privilege escalation, auth bypass, SSRF to internal, bounty $1000-$9999 |
| Medium | Limited data exposure, single-user impact, configuration issues, bounty $100-$999 |
| Low | Informational disclosure, limited impact, no direct exploitation path |
| Informational | No security impact, usability issues, documentation problems |

---

## Statistical Distribution (from 299 Reports)

### Distribution by OWASP Category

| OWASP Category | Code | Count | Percentage |
|---------------|------|-------|------------|
| Security Misconfiguration | API8 | 100 | 33.4% |
| Broken Object Level Authorization | API1 | 62 | 20.7% |
| Broken Authentication | API2 | 35 | 11.7% |
| Broken Function Level Authorization | API5 | 27 | 9.0% |
| Beyond OWASP API Top 10 | Beyond-OWASP | 27 | 9.0% |
| Unrestricted Resource Consumption | API4 | 23 | 7.7% |
| Server Side Request Forgery | API7 | 7 | 2.3% |
| Unrestricted Access to Sensitive Business Flows | API6 | 5 | 1.7% |
| Improper Inventory Management | API9 | 5 | 1.7% |
| Broken Object Property Level Authorization | API3 | 1 | 0.3% |
| Unsafe Consumption of APIs | API10 | 0 | 0.0% |

### Distribution by Vulnerability Type

| Vulnerability Type | Count | Percentage |
|-------------------|-------|------------|
| API Key Leak | 72 | 24.1% |
| Info Disclosure | 58 | 19.4% |
| Auth Bypass | 30 | 10.0% |
| Misconfiguration | 29 | 9.7% |
| IDOR | 22 | 7.4% |
| XSS | 16 | 5.4% |
| Privilege Escalation | 14 | 4.7% |
| Rate Limiting | 13 | 4.3% |
| CSRF | 11 | 3.7% |
| DoS | 10 | 3.3% |
| SSRF | 7 | 2.3% |
| Race Condition | 5 | 1.7% |
| Credential Leak | 5 | 1.7% |
| Shadow API | 4 | 1.3% |
| Injection | 3 | 1.0% |
| RCE | 2 | 0.7% |
| SQLi | 2 | 0.7% |
| BFLA | 2 | 0.7% |
| Mass Assignment | 1 | 0.3% |
| Path Traversal | 1 | 0.3% |
| NoSQLi/RCE | 1 | 0.3% |
| Others (Cache Poisoning, CRLF, HTML Injection, etc.) | 6 | 2.0% |

### Distribution by Severity

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 18 | 6.0% |
| High | 111 | 37.1% |
| Medium | 143 | 47.8% |
| Low | 22 | 7.4% |
| Informational | 1 | 0.3% |

### Cross-Reference: OWASP Category by Severity

| OWASP Cat | Critical | High | Medium | Low | Info | Total |
|-----------|----------|------|--------|-----|------|-------|
| API1 | 2 | 22 | 34 | 3 | 0 | 62 |
| API2 | 3 | 19 | 11 | 0 | 0 | 35 |
| API3 | 0 | 0 | 1 | 0 | 0 | 1 |
| API4 | 0 | 5 | 13 | 5 | 0 | 23 |
| API5 | 3 | 13 | 10 | 0 | 0 | 27 |
| API6 | 0 | 4 | 1 | 0 | 0 | 5 |
| API7 | 0 | 6 | 1 | 0 | 0 | 7 |
| API8 | 3 | 21 | 56 | 11 | 1 | 100 |
| API9 | 0 | 0 | 4 | 0 | 0 | 5 |
| Beyond-OWASP | 5 | 8 | 14 | 1 | 0 | 27 |

---

## Key Insights for Agent Testing Prioritization

1. **API Key Leaks Dominate (24.1%)** — Check JS files, GitHub repos, mobile APKs, public Postman collections for exposed keys
2. **BOLA/IDOR Is Highest-Impact API-Specific Vuln (20.7%)** — Always test object-level authorization by swapping IDs
3. **Auth + Authz = 41.5% of all reports** — API1 + API2 + API5 combined; authentication and authorization testing should be primary focus
4. **SSRF Is Consistently High-Impact** — All 7 SSRF reports rated High severity; always test URL/webhook parameters
5. **Race Conditions Are Under-Explored (1.7%)** — Only 5 reports but sophisticated patterns; high untapped potential
6. **GraphQL Appears in Multiple High-Impact Reports** — Test introspection, query complexity, mutation authorization
7. **API10 (Unsafe Consumption) Has Zero Reports** — Hard to find externally but exists; test third-party API trust boundaries
8. **$0 Bounties Don't Mean Low Severity** — Many Critical/High findings received $0 from VDP programs

---

## Top 20 Programs by Report Count

| Program | Reports | Total Bounty |
|---------|---------|-------------|
| AWS VDP | 18 | $0 |
| Mail.ru | 14 | $600 |
| HackerOne | 10 | $3,500 |
| Shopify | 9 | $9,800 |
| New Relic | 8 | $5,750 |
| Starbucks | 7 | $0 |
| GitHub | 6 | $4,000 |
| TikTok | 6 | $1,000 |
| X / xAI | 6 | $280 |
| Mozilla | 6 | $1,000 |

---

*Source: 299 classified HackerOne API security reports from TOPAPI.md*
