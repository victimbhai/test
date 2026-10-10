# Safe Testing Boundaries & Hypothesis Index — Agent Chunk 51b
> Source: 10-authorized-testing-hypotheses.md
> Purpose: Establish safe testing boundaries (what NOT to test without authorization), avoid disrupting production systems, rate limit your own testing, handle test data properly, and perform cleanup after testing
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Before testing, establish boundaries: 1) Never test — DoS attacks, social engineering, physical access, attacks on shared infrastructure without explicit scope. 2) Avoid disruption — test during low-traffic hours, implement delays between requests, avoid bulk data modification in production. 3) Rate limit yourself — max 10 requests/second default, reduce for destructive operations. 4) Data handling — never store real PII, anonymize test data, use minimum necessary data. 5) Cleanup — delete test accounts/data, remove test webhooks, restore modified configurations. Reference the hypothesis index (H-AUTH, H-AUTHZ, H-INPUT, H-BIZ, H-CONFIG) for test coverage tracking.

---

## 8. Safe Testing Boundaries

### 8.1 What NOT to Test Without Explicit Authorization

Even with a general API security testing authorization, the following
activities require specific, explicit, written approval:

#### 8.1.1 Never Without Specific Authorization

- **Denial of service testing**: Load testing, resource exhaustion, or any
  test designed to overwhelm the system.
- **Data exfiltration**: Extracting real user data, even to demonstrate a
  vulnerability. Capture the minimum evidence.
- **Account takeover of non-test accounts**: Never test with real user
  accounts, even if you discover their credentials.
- **Production database writes**: Never modify production data.
- **Third-party API testing**: Never test APIs belonging to a third party
  through the client's integration.
- **Social engineering**: Never attempt to deceive employees, even to
  test API-related processes.
- **Physical access**: Never attempt physical access to systems.
- **Malware deployment**: Never deploy any persistent code on the target.
- **Cryptocurrency mining**: Never use target resources for mining.
- **Lateral movement**: If you compromise one system, do not attempt to
  access other systems without explicit scope expansion.

#### 8.1.2 Requires Specific Case-by-Case Approval

- **Injection testing in production**: SQL, command, template injection
  testing should be in staging. If production testing is unavoidable,
  get specific approval for each endpoint.
- **Race condition testing**: High request volume may destabilize systems.
- **File upload testing**: Uploading files that bypass restrictions may
  create persistent issues.
- **Webhook testing**: May trigger external integrations.
- **Payment flow testing**: May create real financial transactions.
- **Email/SMS triggering**: May send notifications to real users.

### 8.2 How to Avoid Disrupting Production Systems

#### 8.2.1 Rate Management

- **Set conservative rate limits**: Start at 1 request per second and increase
  only as needed.
- **Monitor response times**: If response times increase by more than 100% from
  baseline, reduce your rate.
- **Avoid parallel testing of the same endpoint**: Sequential testing prevents
  compounding load.
- **Respect 429 responses**: When rate limited, wait for the `Retry-After`
  period. Do not retry immediately.

#### 8.2.2 Payload Safety

- **Use detection payloads, not exploitation payloads**: A single quote to
  detect SQL injection is safer than `UNION SELECT` to extract data.
- **Avoid destructive payloads**: No `DROP TABLE`, no `rm -rf`, no
  `format C:`, even in strings that shouldn't be executed.
- **Use time-based detection sparingly**: `SLEEP(5)` ties up a database
  connection. Use `SLEEP(1)` if time-based detection is necessary.
- **Test file uploads with inert files**: Use genuinely harmless files, not
  executable content.

#### 8.2.3 State Management

- **Don't delete resources you can't recreate**: If a test deletes a resource,
  ensure you can recreate it or that it is test data.
- **Don't modify state that affects other users**: Changing a global
  configuration setting affects all users.
- **Track your changes**: Maintain a log of every write operation (POST, PUT,
  DELETE) so you can reverse them.
- **Use idempotent operations when possible**: GET and HEAD are inherently safe.
  PUT is idempotent. POST and DELETE are not.

### 8.3 Rate Limiting Your Own Testing

#### 8.3.1 Request Budget

Calculate a request budget for the engagement:

```
Testing duration: 5 days
Maximum rate: 5 requests/second (agreed with client)
Effective testing hours: 8 hours/day
Buffer: 50% (for baseline captures, retries, analysis)

Budget = 5 * 8 * 3600 * 5 * 0.5 = 360,000 requests

Per-endpoint average: 360,000 / number_of_endpoints
```

#### 8.3.2 Rate Limiting Implementation

In all testing scripts:

```
Configuration:
  MAX_REQUESTS_PER_SECOND: 5
  MAX_REQUESTS_PER_MINUTE: 200
  DELAY_BETWEEN_SEQUENCES: 2 seconds
  BACKOFF_ON_429: exponential, starting at 30 seconds
  STOP_ON_5XX: after 3 consecutive 5xx responses
  ALERT_ON_RESPONSE_TIME: if >2x baseline
```

### 8.4 Data Handling During Testing

#### 8.4.1 Data Minimization

- Capture only the evidence needed for the report.
- If a vulnerability exposes 1,000 records, capture 1 record as evidence.
  Redact PII in the report; store the unredacted version encrypted.
- Never download bulk data "for analysis."
- Screenshots should be cropped to show the relevant portion.

#### 8.4.2 Data Classification

During testing, you will encounter data that must be handled according to its
sensitivity:

| Data Type | Handling |
|-----------|----------|
| Test data (SECTEST- prefixed) | Can be stored in testing notes |
| API keys/tokens (test accounts) | Encrypt; include only in encrypted appendix |
| Real user PII | Do not capture. If accidentally captured, notify client, delete |
| Real credentials | Do not capture. Notify client immediately |
| Financial data | Do not capture beyond minimum evidence |
| Health data | Do not capture beyond minimum evidence. Extra compliance requirements |
| Infrastructure secrets | Notify client immediately. Do not store |

#### 8.4.3 Secure Storage During Assessment

- All testing data encrypted at rest (full-disk encryption minimum)
- Testing notes in encrypted container
- Network capture files encrypted
- Evidence screenshots in encrypted container
- No testing data in cloud storage without client approval
- No testing data on personal devices (use dedicated testing workstation)

### 8.5 Cleanup Procedures After Testing

#### 8.5.1 Pre-Cleanup Checklist

Before cleanup, verify:

- [ ] All test cases are complete
- [ ] All evidence is captured and encrypted
- [ ] All findings are documented
- [ ] Report draft is complete (so you do not need to re-test)

#### 8.5.2 System Cleanup

1. **Revert configuration changes**: If any test modified system configuration
   (e.g., mass assignment changed a role), revert it.

2. **Remove test data**: Delete all SECTEST- prefixed data created during
   testing.

3. **Invalidate test tokens**: Log out all test sessions. If tokens were
   captured and could be reused, notify the client to rotate secrets.

4. **Remove webhooks**: Delete any webhook registrations created during testing.

5. **Remove uploaded files**: Delete any files uploaded during testing.

6. **Verify system state**: Confirm the system is in the same state as before
   testing began. Check:
   - Test account balances (if applicable)
   - Test account permissions
   - System configuration
   - Webhook registrations
   - Scheduled tasks or jobs created during testing

#### 8.5.3 Assessor Cleanup

1. **Delete local test data**: Remove all unencrypted testing data from the
   testing workstation.

2. **Secure the report**: Encrypt the final report and evidence package.

3. **Transfer to client**: Deliver the encrypted report through an agreed
   secure channel.

4. **Delete proxy logs**: After the report is delivered and accepted, delete
   all proxy logs, network captures, and raw evidence.

5. **Confirm deletion**: Provide the client with a data destruction
   confirmation.

#### 8.5.4 Post-Engagement Data Retention

Define in the engagement agreement:

- How long the assessor retains the report: typically 90 days for follow-up
  questions.
- How long the assessor retains raw evidence: typically destroyed after
  report acceptance.
- How the data is destroyed: secure deletion (overwrite, not just file delete).
- Whether the client receives all raw evidence or only the report.

---

## Appendix A: Quick Reference -- Hypothesis Index

| ID | Hypothesis | Section |
|----|-----------|---------|
| H-AUTH-01 | Default credentials on management interfaces | 2.1 |
| H-AUTH-02 | JWT 'none' algorithm acceptance | 2.1 |
| H-AUTH-03 | JWT weak HMAC secret | 2.1 |
| H-AUTH-04 | Predictable password reset tokens | 2.1 |
| H-AUTH-05 | API keys in client-side code | 2.1 |
| H-AUTH-06 | Missing rate limiting on login | 2.1 |
| H-AUTH-07 | Account lockout bypass | 2.1 |
| H-AUTH-08 | MFA bypass | 2.1 |
| H-AUTH-09 | Insufficient session token entropy | 2.1 |
| H-AUTH-10 | Token revocation ineffectiveness | 2.1 |
| H-AUTH-11 | OAuth redirect_uri validation bypass | 2.1 |
| H-AUTH-12 | PKCE enforcement absence | 2.1 |
| H-AUTH-13 | Refresh token rotation absence | 2.1 |
| H-AUTH-14 | Cookie security attribute deficiency | 2.1 |
| H-AUTH-15 | API key scope over-privilege | 2.1 |
| H-AUTHZ-01 | BOLA/IDOR | 2.2 |
| H-AUTHZ-02 | BFLA | 2.2 |
| H-AUTHZ-03 | Horizontal privilege escalation | 2.2 |
| H-AUTHZ-04 | Vertical privilege escalation via role manipulation | 2.2 |
| H-AUTHZ-05 | GraphQL field-level authorization | 2.2 |
| H-AUTHZ-06 | Nested resource authorization bypass | 2.2 |
| H-AUTHZ-07 | Bulk endpoint authorization bypass | 2.2 |
| H-AUTHZ-08 | Mass assignment | 2.2 |
| H-AUTHZ-09 | Tenant isolation bypass | 2.2 |
| H-AUTHZ-10 | API version authorization inconsistency | 2.2 |
| H-AUTHZ-11 | Webhook authorization bypass | 2.2 |
| H-AUTHZ-12 | File access authorization | 2.2 |
| H-AUTHZ-13 | GraphQL mutation authorization | 2.2 |
| H-AUTHZ-14 | HTTP method override authorization | 2.2 |
| H-AUTHZ-15 | Subscription/plan-level authorization | 2.2 |
| H-INPUT-01 | SQL injection | 2.3 |
| H-INPUT-02 | NoSQL injection | 2.3 |
| H-INPUT-03 | Server-side template injection | 2.3 |
| H-INPUT-04 | OS command injection | 2.3 |
| H-INPUT-05 | SSRF | 2.3 |
| H-INPUT-06 | Path traversal | 2.3 |
| H-INPUT-07 | JSON injection | 2.3 |
| H-INPUT-08 | XML injection / XXE | 2.3 |
| H-INPUT-09 | GraphQL-specific injection | 2.3 |
| H-INPUT-10 | ReDoS | 2.3 |
| H-INPUT-11 | HTTP header injection | 2.3 |
| H-INPUT-12 | LDAP injection | 2.3 |
| H-INPUT-13 | XPath injection | 2.3 |
| H-INPUT-14 | ORM injection | 2.3 |
| H-INPUT-15 | Unicode normalization bypass | 2.3 |
| H-LOGIC-01 | Race conditions in financial transactions | 2.4 |
| H-LOGIC-02 | Workflow step bypass | 2.4 |
| H-LOGIC-03 | Price manipulation | 2.4 |
| H-LOGIC-04 | Quantity manipulation | 2.4 |
| H-LOGIC-05 | Coupon/discount abuse | 2.4 |
| H-LOGIC-06 | Referral system abuse | 2.4 |
| H-LOGIC-07 | Rate limiting bypass | 2.4 |
| H-LOGIC-08 | File upload restriction bypass | 2.4 |
| H-LOGIC-09 | Pagination abuse | 2.4 |
| H-LOGIC-10 | Business rule violations | 2.4 |
| H-CONFIG-01 | CORS misconfiguration | 2.5 |
| H-CONFIG-02 | Verbose error messages | 2.5 |
| H-CONFIG-03 | Debug endpoints in production | 2.5 |
| H-CONFIG-04 | Missing security headers | 2.5 |
| H-CONFIG-05 | TLS configuration issues | 2.5 |
| H-CONFIG-06 | API documentation exposure | 2.5 |
| H-CONFIG-07 | HTTP method allowance | 2.5 |
| H-CONFIG-08 | Content-type enforcement | 2.5 |
| H-CONFIG-09 | Rate limiting existence | 2.5 |
| H-CONFIG-10 | Cache control | 2.5 |

## Appendix B: Testing Risk Classification

| Risk Level | Description | Environment | Approval Needed |
|------------|-------------|-------------|-----------------|
| NONE | Passive analysis, no requests sent | Any | General engagement |
| LOW | Single benign requests, read-only | Any | General engagement |
| LOW-MEDIUM | Multiple requests, minor side effects | Any | General engagement |
| MEDIUM | May modify test data, moderate request volume | Staging preferred | General engagement |
| MEDIUM-HIGH | May modify system state, injection payloads | Staging/Dev only | Specific approval |
| HIGH | May impact availability, destructive potential | Dev only | Specific + written approval |

## Appendix C: OWASP and CWE Cross-Reference

| Hypothesis | OWASP API Top 10 | CWE |
|-----------|-----------------|-----|
| H-AUTH-01 | API2:2023 | CWE-798 |
| H-AUTH-02 | API2:2023 | CWE-327 |
| H-AUTH-03 | API2:2023 | CWE-326 |
| H-AUTH-04 | API2:2023 | CWE-330 |
| H-AUTH-05 | API2:2023 | CWE-312 |
| H-AUTH-06 | API2:2023 | CWE-307 |
| H-AUTHZ-01 | API1:2023 | CWE-639 |
| H-AUTHZ-02 | API5:2023 | CWE-285 |
| H-AUTHZ-08 | API3:2023 | CWE-915 |
| H-INPUT-01 | API8:2023 | CWE-89 |
| H-INPUT-05 | API7:2023 | CWE-918 |
| H-LOGIC-01 | API6:2023 | CWE-362 |
| H-CONFIG-01 | API8:2023 | CWE-942 |
| H-CONFIG-04 | API8:2023 | CWE-693 |

---

*End of Chapter 10: Authorized Testing Hypotheses and Methodology*
