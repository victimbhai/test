# References: Methodology, Compliance & Glossary — Agent Chunk 66e
> Source: 14-references.md
> Purpose: Reference testing methodology standards, regulatory/compliance references (PCI DSS, GDPR, HIPAA), wordlists/payloads, checklists, CWE references for API vulnerabilities, and glossary of API security terms
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Methodology references: OWASP Testing Guide, PTES, NIST SP 800-115 for structuring assessments. Compliance: PCI DSS API requirements, GDPR data exposure via APIs, HIPAA API security controls. Wordlists: SecLists API paths, Assetnote wordlists, custom API wordlists. CWE references: map vulnerabilities to CWE IDs in reports (CWE-284 authorization, CWE-89 SQLi, CWE-918 SSRF). Glossary: standardized terminology for consistent reporting.

---

- Legal authorization (penetration testing agreement, scope letter)

### 12.2 Testing Phase Quick References

- **Reconnaissance**: API specification review, endpoint discovery, technology fingerprinting
- **Authentication testing**: Token analysis, credential testing, session management
- **Authorization testing**: BOLA, BFLA, privilege escalation, role-based access
- **Input validation**: Injection testing, fuzzing, boundary value analysis
- **Business logic**: Race conditions, flow manipulation, abuse scenarios
- **Configuration**: CORS, security headers, error handling, verbose responses

### 12.3 Reporting Phase Checklists

- Finding deduplication and false positive elimination
- Severity scoring with CVSS justification
- Reproduction step verification (clean-state reproduction)
- Evidence collection completeness
- Remediation recommendation specificity
- Executive summary and business impact assessment
- Peer review before delivery

---

## 13. CWE References for API Vulnerabilities

A mapping of common API vulnerability classes to their CWE identifiers.

### 13.1 Authentication and Authorization

| CWE ID   | Name                                                  | API Vulnerability Class             |
|----------|-------------------------------------------------------|--------------------------------------|
| CWE-284  | Improper Access Control                               | Generic authorization failure        |
| CWE-285  | Improper Authorization                                | BFLA                                 |
| CWE-287  | Improper Authentication                               | Authentication bypass                |
| CWE-306  | Missing Authentication for Critical Function          | Unauthenticated API access           |
| CWE-307  | Improper Restriction of Excessive Authentication Attempts | Missing rate limiting on auth   |
| CWE-308  | Use of Single-factor Authentication                   | Weak API authentication              |
| CWE-639  | Authorization Bypass Through User-Controlled Key      | BOLA/IDOR                            |
| CWE-863  | Incorrect Authorization                               | Privilege escalation                 |
| CWE-862  | Missing Authorization                                 | No authorization check on endpoint   |

### 13.2 Injection

| CWE ID   | Name                                                  | API Vulnerability Class             |
|----------|-------------------------------------------------------|--------------------------------------|
| CWE-89   | SQL Injection                                         | SQL injection via API parameters     |
| CWE-78   | OS Command Injection                                  | Command injection via API            |
| CWE-91   | XML Injection (Blind XPath Injection)                 | XPath injection in XML APIs          |
| CWE-94   | Improper Control of Generation of Code                | Code injection                       |
| CWE-917  | Improper Neutralization of Special Elements (Expression Language) | EL/OGNL injection        |
| CWE-943  | Improper Neutralization of Special Elements in Data Query Logic | NoSQL injection              |

### 13.3 Data Handling

| CWE ID   | Name                                                  | API Vulnerability Class             |
|----------|-------------------------------------------------------|--------------------------------------|
| CWE-200  | Exposure of Sensitive Information                     | Excessive data exposure              |
| CWE-209  | Information Exposure Through Error Message            | Verbose API error responses          |
| CWE-213  | Exposure of Sensitive Information Due to Incompatible Policies | Inconsistent data filtering |
| CWE-312  | Cleartext Storage of Sensitive Information            | Unencrypted sensitive data           |
| CWE-319  | Cleartext Transmission of Sensitive Information       | HTTP instead of HTTPS                |
| CWE-532  | Insertion of Sensitive Information into Log Files     | API logging sensitive data           |
| CWE-915  | Improperly Controlled Modification of Dynamically-Determined Object Attributes | Mass assignment |

### 13.4 Network and Protocol

| CWE ID   | Name                                                  | API Vulnerability Class             |
|----------|-------------------------------------------------------|--------------------------------------|
| CWE-918  | Server-Side Request Forgery (SSRF)                    | SSRF via API parameters              |
| CWE-352  | Cross-Site Request Forgery (CSRF)                     | CSRF on state-changing API endpoints |
| CWE-942  | Permissive Cross-domain Policy with Untrusted Domains | CORS misconfiguration                |
| CWE-444  | Inconsistent Interpretation of HTTP Requests          | HTTP request smuggling               |

### 13.5 Concurrency and Logic

| CWE ID   | Name                                                  | API Vulnerability Class             |
|----------|-------------------------------------------------------|--------------------------------------|
| CWE-362  | Concurrent Execution Using Shared Resource with Improper Synchronization | Race conditions |
| CWE-367  | Time-of-check Time-of-use (TOCTOU) Race Condition     | TOCTOU in API operations             |
| CWE-770  | Allocation of Resources Without Limits or Throttling  | Missing rate limiting, resource exhaustion |
| CWE-799  | Improper Control of Interaction Frequency             | Insufficient rate limiting           |
| CWE-841  | Improper Enforcement of Behavioral Workflow           | Business logic bypass                |

---

## 14. Version History and Errata

### 14.1 Knowledge Base Version History

| Version | Date       | Changes                                                      |
|---------|------------|---------------------------------------------------------------|
| 1.0     | 2024-01    | Initial release covering OWASP API Top 10 2023               |
| 1.1     | 2024-03    | Added GraphQL and WebSocket testing chapters                  |
| 1.2     | 2024-06    | Added race condition methodology (Smashing the State Machine) |
| 1.3     | 2024-09    | Added false positive guide and evidence standards             |
| 1.4     | 2025-01    | Updated OAuth references for RFC 9700                        |
| 1.5     | 2025-06    | Added NIST SP 800-228 references, updated tool list          |

### 14.2 Contributing

This knowledge base is a living document. Contributions are welcome for:
- New vulnerability classes and testing techniques
- Updated tool versions and capabilities
- Additional CVE entries and bug bounty report references
- Corrections and clarifications
- Additional framework-specific guidance

---

## 15. Glossary of Terms

| Term            | Definition                                                                    |
|-----------------|-------------------------------------------------------------------------------|
| ABAC            | Attribute-Based Access Control                                                |
| API             | Application Programming Interface                                             |
| ASVS            | Application Security Verification Standard                                    |
| BFLA            | Broken Function Level Authorization                                           |
| BOLA            | Broken Object Level Authorization                                             |
| CORS            | Cross-Origin Resource Sharing                                                 |
| CSRF            | Cross-Site Request Forgery                                                    |
| CVE             | Common Vulnerabilities and Exposures                                          |
| CVSS            | Common Vulnerability Scoring System                                           |
| CWE             | Common Weakness Enumeration                                                   |
| DoS             | Denial of Service                                                             |
| gRPC            | Google Remote Procedure Call                                                  |
| HPACK           | HTTP/2 Header Compression                                                     |
| IDOR            | Insecure Direct Object Reference                                              |
| IMDSv2          | Instance Metadata Service Version 2 (AWS)                                     |
| JWE             | JSON Web Encryption                                                           |
| JWK             | JSON Web Key                                                                  |
| JWS             | JSON Web Signature                                                            |
| JWT             | JSON Web Token                                                                |
| NoSQL           | Non-relational databases (MongoDB, Couchbase, etc.)                           |
| OAS             | OpenAPI Specification                                                         |
| OIDC            | OpenID Connect                                                                |
| OOB             | Out-of-Band                                                                   |
| OWASP           | Open Worldwide Application Security Project                                   |
| PKCE            | Proof Key for Code Exchange                                                   |
| PoC             | Proof of Concept                                                              |
| RBAC            | Role-Based Access Control                                                     |
| RCE             | Remote Code Execution                                                         |
| REST            | Representational State Transfer                                               |
| SAML            | Security Assertion Markup Language                                            |
| SPA             | Single-Page Application                                                       |
| SSTI            | Server-Side Template Injection                                                |
| SSRF            | Server-Side Request Forgery                                                   |
| TLS             | Transport Layer Security                                                      |
| TOCTOU          | Time-of-Check to Time-of-Use                                                  |
| WAF             | Web Application Firewall                                                      |
| XSS             | Cross-Site Scripting                                                          |

---

## 16. How to Use This Reference

### For Security Testers

1. **Before an engagement**: Review the relevant OWASP categories, framework documentation,
   and tool references for the target technology stack.
2. **During testing**: Reference CVE databases and bug bounty reports for known vulnerability
   patterns in the target technologies.
3. **During reporting**: Use CWE references, CVSS scoring guides, and evidence standards from
   Chapter 11 to produce high-quality findings.

### For Developers

1. **During design**: Reference OWASP ASVS, NIST guidelines, and framework security
   documentation to build secure APIs.
2. **During implementation**: Use framework-specific security documentation and cheat sheets
   for secure coding patterns.
3. **After an assessment**: Reference the remediation guidance linked from findings and the
   framework documentation for implementing fixes.

### For Security Managers

1. **Program design**: Use OWASP methodology references and compliance standards to design
   API security programs.
2. **Vendor evaluation**: Reference tool comparisons and methodology standards to evaluate
   security testing vendors.
3. **Metrics and reporting**: Use CVSS and EPSS references for vulnerability management
   prioritization.

---

*This reference chapter is maintained as part of the API Security Research Knowledge Base.
All URLs were verified at the time of publication. Broken links should be reported for
correction. Resources behind paywalls or registration walls are noted where known.*
