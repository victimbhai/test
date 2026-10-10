# OWASP Cross-Category Attack Chaining + Priority Matrix — Agent Chunk 21
> Source: 06-owasp-api-top-10-research.md (lines 0-31, 3183-3481)
> Purpose: Guide an agent to chain vulnerabilities across OWASP categories for maximum impact, prioritize testing by likelihood/impact, and apply context-dependent prioritization for specific API types
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
After testing individual OWASP categories, look for opportunities to chain findings together. A low-severity misconfiguration (API8) can become critical when chained with SSRF (API7) or auth bypass (API2). Use the priority matrix to determine testing order based on the target API's domain (financial, healthcare, e-commerce, cloud/SaaS, IoT). Apply the bug bounty statistics to estimate finding likelihood and expected severity.

---

## Context: OWASP API Security Top 10 (2023 Edition)

The 2023 edition reflects significant shifts from the 2019 version:
- API3:2019 (Excessive Data Exposure) and API6:2019 (Mass Assignment) were merged into API3:2023 (Broken Object Property Level Authorization)
- New categories emerged: API6:2023 (Unrestricted Access to Sensitive Business Flows) and API10:2023 (Unsafe Consumption of APIs)
- Server-Side Request Forgery was elevated from a sub-category to its own entry at API7:2023
- These changes reflect the evolving threat landscape where APIs are increasingly the primary attack surface

### CVE References Cited Across All Categories
- CVE-2015-9235: JWT alg:none vulnerability in multiple libraries
- CVE-2016-10555: Node.js jsonwebtoken algorithm confusion
- CVE-2023-44487: HTTP/2 Rapid Reset denial-of-service
- CVE-2024-24762: python-multipart ReDoS affecting FastAPI/Starlette

### Tools Referenced Across All Categories
- Burp Suite with Autorize extension for BOLA testing
- OWASP ZAP for automated API security testing
- ffuf for API endpoint discovery and fuzzing
- jwt_tool for JWT analysis and exploitation testing
- hashcat for JWT secret brute-forcing
- TruffleHog and GitLeaks for secret detection in repositories
- subfinder for subdomain enumeration

---

## Cross-Category Vulnerability Chaining

Real-world API attacks rarely exploit a single vulnerability in isolation. The most impactful attacks chain multiple vulnerabilities across categories.

### Chain 1: API9 + API1 — Discovery + Unauthorized Access

**Scenario**: An attacker discovers a deprecated API version (API9: Improper Inventory Management) that lacks the authorization checks implemented in the current version (API1: BOLA).

```
1. Attacker discovers /api/v1/ is still accessible (API9)
2. Current /api/v3/users/{id}/data enforces authorization
3. Deprecated /api/v1/users/{id}/data does NOT enforce authorization (API1)
4. Attacker accesses other users' data through the deprecated endpoint
```

### Chain 2: API2 + API5 — Auth Bypass + Privilege Escalation

**Scenario**: An attacker exploits a JWT vulnerability to forge a valid token (API2: Broken Authentication), then uses that token to access administrative functions (API5: BFLA).

```
1. Attacker discovers JWT uses HS256 with a weak secret (API2)
2. Attacker cracks the JWT secret: "your-256-bit-secret"
3. Attacker forges JWT with {"role": "admin"} in the payload
4. Attacker accesses /api/v1/admin/users with the forged admin token (API5)
5. Full administrative access achieved
```

### Chain 3: API1 + API3 — BOLA + Property Exposure

**Scenario**: An attacker exploits BOLA to access another user's profile (API1), which exposes excessive data (API3) including internal IDs and API keys that enable further attacks.

```
1. Attacker changes user_id to access another user's profile (API1: BOLA)
2. Response includes internal API keys, password reset tokens (API3: excessive exposure)
3. Attacker uses the leaked API key for further access
4. Attacker uses the password reset token to take over the account (API2 impact)
```

### Chain 4: API7 + API2 — SSRF + Credential Theft

**Scenario**: An attacker exploits SSRF (API7) to access cloud metadata (169.254.169.254), obtains IAM credentials, and uses those credentials to access other cloud resources.

```
1. Attacker finds SSRF in webhook URL validation (API7)
2. SSRF target: http://169.254.169.254/latest/meta-data/iam/security-credentials/
3. Obtains temporary AWS credentials (AccessKeyId, SecretAccessKey, Token)
4. Uses credentials to access S3 buckets, databases, other AWS services
5. Data exfiltration of the entire cloud environment
```

### Chain 5: API3 + API5 — Mass Assignment + Privilege Escalation

**Scenario**: An attacker uses mass assignment (API3) to elevate their own role, then accesses administrative functions (API5).

```
1. Attacker sends PUT /api/v1/users/me with {"role": "admin"} (API3: mass assignment)
2. Server binds the role field to the user model without filtering
3. Attacker now has admin role in the system
4. Attacker accesses /api/v1/admin/* endpoints (API5: now authorized due to elevated role)
```

### Chain 6: API8 + API7 — Misconfiguration + SSRF

**Scenario**: Exposed API documentation (API8) reveals an internal webhook endpoint, which the attacker exploits for SSRF (API7).

```
1. Attacker finds /swagger.json exposed without authentication (API8)
2. Documentation reveals POST /api/v1/integrations/webhook with a url parameter
3. Attacker registers webhook pointing to internal services (API7: SSRF)
4. Internal service responses are logged and accessible to the attacker
```

### Chain 7: API4 + API6 — Resource Consumption + Business Logic Abuse

**Scenario**: An attacker combines the lack of rate limiting (API4) with automated business flow abuse (API6) to drain a company's SMS budget and denial-of-service legitimate users.

```
1. No rate limiting on the "send OTP" endpoint (API4)
2. Attacker automates OTP requests to thousands of phone numbers (API6)
3. Company incurs massive SMS costs ($0.05 * 1,000,000 = $50,000)
4. SMS service provider rate limits the company's account
5. Legitimate users cannot receive OTP codes -- authentication denied
```

---

## Statistical Analysis: Bug Bounty Distribution

Based on analysis of publicly disclosed reports across major bug bounty platforms (HackerOne, Bugcrowd, Intigriti) and historical data through 2025:

### Frequency Distribution by Category

| Category | Estimated % of Valid API Bug Reports | Median Bounty |
|----------|--------------------------------------|---------------|
| API1: BOLA/IDOR | 35-40% | $2,000-$5,000 |
| API2: Broken Authentication | 15-20% | $3,000-$8,000 |
| API3: BOPLA | 12-15% | $1,500-$4,000 |
| API5: BFLA | 8-10% | $2,500-$6,000 |
| API7: SSRF | 5-8% | $3,000-$10,000 |
| API8: Security Misconfiguration | 5-7% | $500-$2,000 |
| API4: Resource Consumption | 3-5% | $500-$1,500 |
| API9: Improper Inventory | 3-5% | $500-$2,500 |
| API6: Business Flow Abuse | 2-4% | $1,000-$3,000 |
| API10: Unsafe Consumption | 1-2% | $2,000-$5,000 |

### Key Observations

1. **BOLA dominates**: It accounts for the plurality of all API vulnerability reports. Every API endpoint that accepts an identifier is a potential BOLA target, the attack is simple (change one parameter), and the impact is immediately demonstrable.

2. **Authentication flaws command higher bounties**: While less frequent than BOLA, authentication vulnerabilities often lead to account takeover, which is consistently rated as critical severity.

3. **SSRF has the highest ceiling**: Individual SSRF reports, especially those leading to cloud credential exposure, have received some of the largest bounties in bug bounty history. The Capital One incident demonstrated the catastrophic potential.

4. **Business logic (API6) is underreported**: Not because business logic flaws are rare, but because they require deep understanding of the application's business model and are harder to demonstrate in a bug report.

5. **Unsafe consumption (API10) is rarely reported**: This category requires the researcher to understand the backend's integration with third-party services, which is rarely visible from the outside. More commonly discovered in code reviews and internal security audits.

---

## Priority Matrix for Testing

### When to Test What First

| Category | Likelihood (1-5) | Impact (1-5) | Priority Score | Testing Order |
|----------|-------------------|--------------|----------------|---------------|
| API1: BOLA | 5 | 4 | 20 | 1st |
| API2: Broken Auth | 4 | 5 | 20 | 1st (tied) |
| API3: BOPLA | 4 | 4 | 16 | 3rd |
| API5: BFLA | 3 | 5 | 15 | 4th |
| API7: SSRF | 3 | 5 | 15 | 4th (tied) |
| API8: Misconfiguration | 4 | 3 | 12 | 6th |
| API4: Resource Consumption | 3 | 3 | 9 | 7th |
| API9: Improper Inventory | 3 | 3 | 9 | 7th (tied) |
| API6: Business Flows | 2 | 4 | 8 | 9th |
| API10: Unsafe Consumption | 2 | 4 | 8 | 9th (tied) |

### Recommended Testing Workflow

**Phase 1 — Immediate (First Day of Engagement):**
1. **API1: BOLA** — Test every endpoint that accepts object identifiers. Swap IDs between two user accounts. This is the highest-ROI test because it is fast, easy to execute, and commonly yields findings.
2. **API2: Broken Authentication** — Analyze JWT tokens (algorithm, expiration, signing strength). Test for password brute-force protection. Check OAuth implementation. Test API key exposure.

**Phase 2 — Core Testing (Days 2-3):**
3. **API3: BOPLA** — Test mass assignment by adding extra fields to every input endpoint. Inspect every API response for excessive data exposure.
4. **API5: BFLA** — Attempt to access admin/internal endpoints with regular user credentials. Test HTTP method switching.
5. **API7: SSRF** — Test every endpoint that accepts URLs (webhooks, imports, image URLs, PDF generation). Target cloud metadata endpoints.

**Phase 3 — Configuration and Inventory (Days 4-5):**
6. **API8: Misconfiguration** — Check security headers, CORS, TLS, error handling, debug endpoints, exposed documentation.
7. **API9: Improper Inventory** — Discover shadow APIs, zombie APIs, undocumented endpoints. Test deprecated API versions.

**Phase 4 — Advanced Testing (Days 5+):**
8. **API4: Resource Consumption** — Test rate limiting, pagination abuse, GraphQL complexity, file upload limits.
9. **API6: Business Flows** — Test automated abuse scenarios specific to the application's business logic.
10. **API10: Unsafe Consumption** — If code access is available, review third-party API integrations for input validation.

### Context-Dependent Prioritization

The default priority matrix should be adjusted based on the specific application context:

**Financial APIs (banking, payments, crypto):**
- Elevate API2 (authentication) and API5 (BFLA) to top priority
- API6 (business flows) becomes critical (automated trading, fund transfers)
- API1 (BOLA) remains high (accessing other users' financial data)

**Healthcare APIs:**
- Elevate API1 (BOLA) to absolute top priority (patient data access)
- API3 (BOPLA) is critical (exposure of medical records in responses)
- Regulatory impact (HIPAA) increases the severity of every finding

**E-commerce APIs:**
- Elevate API6 (business flows) — scalping, coupon abuse, inventory manipulation
- API3 mass assignment is high priority (price manipulation, discount injection)
- API1 (BOLA) for order data, payment methods, shipping addresses

**Cloud/SaaS APIs:**
- Elevate API7 (SSRF) — cloud metadata access has catastrophic impact
- API9 (inventory management) is critical (multi-tenant boundary violations through shadow APIs)
- API5 (BFLA) — tenant admin vs. platform admin privilege confusion

**IoT/Device APIs:**
- Elevate API2 (authentication) — device authentication is often weak
- API4 (resource consumption) — resource-constrained devices are easily overwhelmed
- API8 (misconfiguration) — firmware often ships with debug endpoints and default credentials

---

## References

### OWASP Resources
- OWASP API Security Top 10 — 2023 Edition: https://owasp.org/API-Security/editions/2023/en/0x00-header/
- OWASP API Security Project: https://owasp.org/www-project-api-security/
- OWASP Testing Guide — API Testing: https://owasp.org/www-project-web-security-testing-guide/
