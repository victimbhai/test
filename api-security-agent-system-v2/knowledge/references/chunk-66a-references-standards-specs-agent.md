# References: Standards & Specifications — Agent Chunk 66a
> Source: 14-references.md
> Purpose: Reference API security standards and specifications (OAuth RFCs, JWT, HTTP semantics, OpenAPI, TLS) for verifying implementations and citing in reports
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use these references when verifying API implementations against standards. Key standards: RFC 6749/6750 (OAuth 2.0), RFC 7519 (JWT), RFC 7231/7235 (HTTP semantics/auth), RFC 8446 (TLS 1.3), OpenAPI 3.1 specification, RFC 6455 (WebSocket), RFC 7540 (HTTP/2).

---

## Introduction

This chapter consolidates every standard, specification, research paper, CVE, tool, report,
and resource referenced throughout the API Security Research Knowledge Base. It serves as
both a bibliography and a curated reading list for practitioners seeking to deepen their
expertise in API security testing.

Resources are organized by category, with annotations describing their relevance to API
security testing. URLs are provided where publicly available.

---

## 1. Standards and Specifications

### 1.1 OWASP Standards

#### OWASP API Security Top 10 (2023)

The primary reference framework for API-specific security risks. The 2023 edition
reorganized several categories and added new ones based on industry trends.

| ID         | Title                                              | Relevance                                   |
|------------|-----------------------------------------------------|----------------------------------------------|
| API1:2023  | Broken Object Level Authorization                  | Most common API vulnerability class          |
| API2:2023  | Broken Authentication                              | Token, session, and credential attacks       |
| API3:2023  | Broken Object Property Level Authorization         | Mass assignment and excessive data exposure  |
| API4:2023  | Unrestricted Resource Consumption                  | Rate limiting and DoS                        |
| API5:2023  | Broken Function Level Authorization                | Privilege escalation, admin function access  |
| API6:2023  | Unrestricted Access to Sensitive Business Flows    | Business logic abuse                         |
| API7:2023  | Server Side Request Forgery                        | SSRF attacks via API parameters              |
| API8:2023  | Security Misconfiguration                          | CORS, headers, debug modes                   |
| API9:2023  | Improper Inventory Management                      | Shadow APIs, version management              |
| API10:2023 | Unsafe Consumption of APIs                         | Third-party API integration risks            |

- **URL**: https://owasp.org/API-Security/
- **License**: Creative Commons Attribution-ShareAlike 4.0

#### OWASP Testing Guide v4.2

Comprehensive methodology for web application security testing, with sections applicable
to API testing.

- **URL**: https://owasp.org/www-project-web-security-testing-guide/
- **Key sections for API testing**:
  - Chapter 4.5: Authentication Testing
  - Chapter 4.6: Authorization Testing
  - Chapter 4.7: Session Management Testing
  - Chapter 4.8: Input Validation Testing
  - Chapter 4.10: Business Logic Testing

#### OWASP Application Security Verification Standard (ASVS) v4.0.3

A framework of security requirements and controls for designing, developing, and testing
web applications and APIs.

- **URL**: https://owasp.org/www-project-application-security-verification-standard/
- **Key sections for API testing**:
  - V2: Authentication
  - V3: Session Management
  - V4: Access Control
  - V5: Validation, Sanitization, and Encoding
  - V8: Data Protection
  - V12: Files and Resources
  - V13: API and Web Service (dedicated API chapter)
  - V14: Configuration

#### OWASP Cheat Sheet Series

Concise, actionable guidance on specific security topics.

| Cheat Sheet                                  | Relevance                                |
|----------------------------------------------|-------------------------------------------|
| REST Security Cheat Sheet                    | Foundational REST API security guidance   |
| JSON Web Token Cheat Sheet for Java          | JWT implementation best practices         |
| GraphQL Cheat Sheet                          | GraphQL-specific security guidance        |
| Authentication Cheat Sheet                   | Authentication mechanism design           |
| Authorization Cheat Sheet                    | Authorization pattern implementation      |
| Input Validation Cheat Sheet                 | Input handling for APIs                   |
| Cross-Site Request Forgery Prevention        | CSRF in API contexts                      |
| Mass Assignment Cheat Sheet                  | Preventing mass assignment in APIs        |
| Server Side Request Forgery Prevention       | SSRF defense strategies                   |
| Microservices Security Cheat Sheet           | Securing microservice APIs                |

- **URL**: https://cheatsheetseries.owasp.org/

#### OWASP Mobile Application Security Verification Standard (MASVS)

Covers mobile API security considerations including certificate pinning, local data storage,
and mobile-specific authentication flows.

- **URL**: https://mas.owasp.org/MASVS/

### 1.2 OAuth and Authentication RFCs

#### RFC 6749 -- The OAuth 2.0 Authorization Framework

Defines the core OAuth 2.0 protocol including authorization code, implicit, resource owner
password credentials, and client credentials grant types.

- **URL**: https://www.rfc-editor.org/rfc/rfc6749
- **Published**: October 2012
- **Authors**: D. Hardt (Ed.)
- **Relevance**: Foundation for API authorization testing; understanding grant type flows,
  token handling, and protocol weaknesses
- **Key testing areas**: Redirect URI validation, state parameter usage, scope enforcement,
  token leakage, authorization code interception

#### RFC 6750 -- The OAuth 2.0 Bearer Token Usage

Defines how to use bearer tokens in HTTP requests to access OAuth 2.0 protected resources.

- **URL**: https://www.rfc-editor.org/rfc/rfc6750
- **Published**: October 2012
- **Authors**: M. Jones, D. Hardt
- **Relevance**: Bearer token transmission, error handling, and the security considerations
  of bearer tokens (they are credentials -- treat them as such)
- **Key testing areas**: Token transmission methods (header, body, query), token leakage in
  logs, referer headers, and URLs

#### RFC 7519 -- JSON Web Token (JWT)

Defines the JWT format for claims-based security tokens used in API authentication
and authorization.

- **URL**: https://www.rfc-editor.org/rfc/rfc7519
- **Published**: May 2015
- **Authors**: M. Jones, J. Bradley, N. Sakimura
- **Relevance**: JWT structure, claims, validation requirements, and the security model
- **Key testing areas**: Algorithm selection, signature verification, claim validation,
  token expiration, audience restriction
- **Related RFCs**:
  - RFC 7515 (JSON Web Signature -- JWS)
  - RFC 7516 (JSON Web Encryption -- JWE)
  - RFC 7517 (JSON Web Key -- JWK)
  - RFC 7518 (JSON Web Algorithms -- JWA)

#### RFC 7636 -- Proof Key for Code Exchange (PKCE)

Extends the OAuth 2.0 authorization code grant with a cryptographic challenge to prevent
authorization code interception attacks.

- **URL**: https://www.rfc-editor.org/rfc/rfc7636
- **Published**: September 2015
- **Authors**: N. Sakimura, J. Bradley, N. Agarwal
- **Relevance**: Critical for mobile and SPA OAuth implementations; prevents authorization
  code theft even without client secrets
- **Key testing areas**: Code verifier entropy, code challenge method (S256 vs plain),
  missing PKCE enforcement

#### RFC 9700 -- OAuth 2.0 Security Best Current Practice

Consolidates security recommendations for OAuth 2.0 deployments based on years of
real-world experience and attack research. Supersedes earlier draft security BCPs.

- **URL**: https://www.rfc-editor.org/rfc/rfc9700
- **Published**: January 2025
- **Authors**: T. Lodderstedt, J. Bradley, A. Labunets, D. Fett
- **Relevance**: The authoritative source for current OAuth 2.0 security guidance; covers
  attacks discovered since RFC 6749 was published, including mix-up attacks, PKCE
  requirements, redirect URI restrictions, and token binding
- **Key recommendations**:
  - Implicit grant SHOULD NOT be used
  - PKCE MUST be used for all authorization code grants
  - Exact redirect URI matching (no wildcards or pattern matching)
  - Authorization code is one-time use
  - Sender-constrained tokens where feasible
  - Resource indicators for multi-tenant scenarios

#### RFC 9207 -- OAuth 2.0 Authorization Server Issuer Identification

Defines a mechanism for the authorization server to include its issuer identifier in
authorization responses, preventing mix-up attacks.

- **URL**: https://www.rfc-editor.org/rfc/rfc9207
- **Published**: March 2022
- **Authors**: K. Meyer zu Selhausen, D. Fett
- **Relevance**: Prevents OAuth mix-up attacks where a malicious authorization server
  tricks the client into sending tokens to the wrong endpoint
- **Key testing areas**: Issuer validation in authorization responses, mix-up attack
  resistance

#### OAuth 2.1 (Draft Specification)

A consolidation of OAuth 2.0 (RFC 6749), PKCE (RFC 7636), Bearer Token Usage (RFC 6750),
and Security BCP into a single, updated specification.

- **URL**: https://oauth.net/2.1/
- **Status**: Internet-Draft (work in progress as of 2025)
- **Key changes from OAuth 2.0**:
  - Removes implicit grant entirely
  - Removes resource owner password credentials grant
  - Requires PKCE for all authorization code grants
  - Restricts redirect URIs to exact match
  - Requires use of refresh token rotation

#### RFC 8414 -- OAuth 2.0 Authorization Server Metadata

Defines a well-known endpoint for authorization servers to publish their OAuth 2.0
