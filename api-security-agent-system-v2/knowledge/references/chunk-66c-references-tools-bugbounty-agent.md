# References: Tools & Bug Bounty Reports — Agent Chunk 66c
> Source: 14-references.md
> Purpose: Reference API security testing tools and real-world bug bounty reports for technique validation and methodology improvement
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Tool references: use for tool selection per testing phase (discovery: subfinder/amass, scanning: Nuclei/ffuf, proxying: Burp/mitmproxy, exploitation: sqlmap/ysoserial). Bug bounty reports: study real-world API vulnerabilities, understand what makes a good submission, learn from disclosed techniques. Cross-reference your findings against similar bug bounty reports for validation and impact assessment.

---

## 4. Tool References

### 4.1 Discovery and Reconnaissance Tools

| Tool                  | Purpose                                                   | URL                                          | License       |
|-----------------------|-----------------------------------------------------------|----------------------------------------------|---------------|
| Amass                 | Network mapping, subdomain discovery, ASN enumeration     | https://github.com/owasp-amass/amass         | Apache 2.0    |
| Subfinder             | Fast passive subdomain enumeration                        | https://github.com/projectdiscovery/subfinder| MIT           |
| httpx                 | HTTP toolkit for probing and technology detection         | https://github.com/projectdiscovery/httpx    | MIT           |
| katana                | Web crawler for endpoint and parameter discovery          | https://github.com/projectdiscovery/katana   | MIT           |
| GAU (GetAllURLs)      | Fetch known URLs from AlienVault OTX, Wayback, Common Crawl | https://github.com/lc/gau                  | MIT           |
| Waybackurls           | Fetch URLs from the Wayback Machine                       | https://github.com/tomnomnom/waybackurls     | MIT           |
| kiterunner            | API endpoint brute-force discovery                        | https://github.com/assetnote/kiterunner      | AGPL-3.0      |
| ffuf                  | Fast web fuzzer for endpoint and parameter discovery      | https://github.com/ffuf/ffuf                 | MIT           |
| Arjun                 | Hidden HTTP parameter discovery                           | https://github.com/s0md3v/Arjun              | GPL-3.0       |
| ParamSpider           | Parameter extraction from web archives                    | https://github.com/devanshbatham/ParamSpider | MIT           |
| swagger-ui            | Swagger/OpenAPI specification rendering                   | https://github.com/swagger-api/swagger-ui    | Apache 2.0    |

### 4.2 Scanning and Testing Tools

| Tool                  | Purpose                                                   | URL                                          | License       |
|-----------------------|-----------------------------------------------------------|----------------------------------------------|---------------|
| Burp Suite Pro        | Comprehensive web/API security testing platform           | https://portswigger.net/burp                 | Commercial    |
| OWASP ZAP             | Open-source web application security scanner              | https://www.zaproxy.org/                     | Apache 2.0    |
| Nuclei                | Template-based vulnerability scanner                      | https://github.com/projectdiscovery/nuclei   | MIT           |
| Nikto                 | Web server vulnerability scanner                          | https://github.com/sullo/nikto               | GPL-2.0       |
| SQLMap                | Automated SQL injection detection and exploitation        | https://github.com/sqlmapproject/sqlmap       | GPL-2.0       |
| Postman               | API development and testing platform                      | https://www.postman.com/                     | Freemium      |
| Insomnia              | API client for REST, GraphQL, gRPC                        | https://insomnia.rest/                       | MIT           |
| SoapUI                | SOAP and REST API testing tool                            | https://www.soapui.org/                      | EUPL          |
| dredd                 | API description validation tool                           | https://github.com/apiaryio/dredd            | MIT           |
| Schemathesis          | Property-based API testing from OpenAPI specs             | https://github.com/schemathesis/schemathesis | MIT           |

### 4.3 Authentication and Token Testing Tools

| Tool                  | Purpose                                                   | URL                                          | License       |
|-----------------------|-----------------------------------------------------------|----------------------------------------------|---------------|
| jwt_tool              | JWT analysis, testing, and exploitation                   | https://github.com/ticarpi/jwt_tool          | GPL-3.0       |
| jwt.io                | Online JWT decoder and verifier                           | https://jwt.io/                              | Free          |
| jwt-cracker           | JWT secret brute-force tool                               | https://github.com/lmammino/jwt-cracker      | MIT           |
| hashcat               | Password/hash/JWT secret cracking                         | https://hashcat.net/hashcat/                 | MIT           |
| John the Ripper       | Password/hash cracking with JWT support                   | https://www.openwall.com/john/               | GPL-2.0       |
| oauth-tester          | OAuth 2.0 flow testing                                    | Various implementations                      | Various       |
| Authz0                | Authorization testing automation                          | https://github.com/AresS31/authz0            | MIT           |

### 4.4 SSRF and Network Testing Tools

| Tool                  | Purpose                                                   | URL                                          | License       |
|-----------------------|-----------------------------------------------------------|----------------------------------------------|---------------|
| Collaborator (Burp)   | Out-of-band interaction detection                         | Part of Burp Suite                           | Commercial    |
| interactsh            | OOB interaction server                                    | https://github.com/projectdiscovery/interactsh| MIT          |
| SSRFmap               | Automated SSRF detection and exploitation                 | https://github.com/swisskyrepo/SSRFmap       | MIT           |
| Gopherus              | SSRF payload generator for gopher protocol                | https://github.com/tarunkant/Gopherus        | MIT           |

### 4.5 Race Condition and Concurrency Tools

| Tool                  | Purpose                                                   | URL                                          | License       |
|-----------------------|-----------------------------------------------------------|----------------------------------------------|---------------|
| Turbo Intruder        | High-speed HTTP request engine for Burp Suite             | https://github.com/PortSwigger/turbo-intruder| MIT          |
| race-the-web          | Race condition testing framework                          | https://github.com/TheHackerDev/race-the-web | MIT           |
| racepwn               | Race condition exploitation tool                          | https://github.com/racepwn/racepwn           | MIT           |

### 4.6 GraphQL Testing Tools

| Tool                  | Purpose                                                   | URL                                          | License       |
|-----------------------|-----------------------------------------------------------|----------------------------------------------|---------------|
| InQL                  | Burp Suite extension for GraphQL testing                  | https://github.com/doyensec/inql             | Apache 2.0    |
| graphql-voyager       | GraphQL schema visualization                              | https://github.com/graphql-kit/graphql-voyager| MIT          |
| GraphQL Raider        | Burp extension for GraphQL manipulation                   | https://github.com/nickreed/graphql-raider   | MIT           |
| BatchQL               | GraphQL batching attack tool                              | https://github.com/assetnote/batchql         | MIT           |
| clairvoyance          | GraphQL schema extraction without introspection           | https://github.com/nikitastupin/clairvoyance | MIT           |
| graphw00f              | GraphQL server fingerprinting                             | https://github.com/dolevf/graphw00f          | BSD-3         |

### 4.7 Fuzzing Tools

| Tool                  | Purpose                                                   | URL                                          | License       |
|-----------------------|-----------------------------------------------------------|----------------------------------------------|---------------|
| RESTler               | Stateful REST API fuzzer from Microsoft Research          | https://github.com/microsoft/restler-fuzzer  | MIT           |
| APIFuzzer             | API fuzzing based on OpenAPI specifications               | https://github.com/KissPeter/APIFuzzer       | GPL-3.0       |
| Atheris               | Python coverage-guided fuzzer                             | https://github.com/google/atheris            | Apache 2.0    |
| Boofuzz               | Network protocol fuzzing framework                        | https://github.com/jtpereyda/boofuzz         | GPL-2.0       |

### 4.8 Proxy and Interception Tools

| Tool                  | Purpose                                                   | URL                                          | License       |
|-----------------------|-----------------------------------------------------------|----------------------------------------------|---------------|
| mitmproxy             | Interactive TLS-capable intercepting proxy                | https://mitmproxy.org/                       | MIT           |
| Fiddler               | Web debugging proxy                                       | https://www.telerik.com/fiddler              | Freemium      |
| Charles Proxy         | HTTP proxy and monitor                                    | https://www.charlesproxy.com/                | Commercial    |

### 4.9 Reporting and Documentation Tools

| Tool                  | Purpose                                                   | URL                                          | License       |
|-----------------------|-----------------------------------------------------------|----------------------------------------------|---------------|
| Dradis                | Security assessment collaboration platform                | https://dradis.com/                          | GPL-2.0/Comm. |
| Ghostwriter           | Reporting tool for penetration tests                      | https://github.com/GhostManager/Ghostwriter  | BSD-3         |
| pwndoc                | Penetration test report generator                         | https://github.com/pwndoc/pwndoc             | MIT           |
| Serpico               | Report generation for penetration testing                 | https://github.com/SerpicoProject/Serpico    | MIT           |

---

## 5. Bug Bounty Report References

### 5.1 BOLA/IDOR Reports

| Title                                         | Platform   | Bounty     | Key Technique                               |
|-----------------------------------------------|-----------|------------|----------------------------------------------|
| IDOR to view private Shopify store revenue    | HackerOne | $20,000    | Sequential ID enumeration on admin endpoint  |
| Access to any user's email via IDOR           | HackerOne | $10,000    | User ID parameter manipulation in API        |
| IDOR allows deletion of any user's account    | Bugcrowd  | $5,000     | Object reference manipulation in DELETE      |
| View any organization's invoices              | HackerOne | $15,000    | Org ID swapping in invoice API               |
| Access other users' payment methods           | HackerOne | $7,500     | IDOR in payment method listing endpoint      |

**Common techniques observed**:
- Horizontal privilege escalation via ID manipulation
- Using predictable/sequential identifiers
- Modifying object references in PUT/PATCH/DELETE requests
- Exploiting API endpoints not covered by frontend authorization

### 5.2 Authentication Bypass Reports

| Title                                         | Platform   | Bounty     | Key Technique                               |
|-----------------------------------------------|-----------|------------|----------------------------------------------|
| JWT alg:none allows admin access              | HackerOne | $25,000    | Algorithm none attack on JWT                 |
| OAuth redirect_uri bypass via path traversal  | HackerOne | $10,000    | ../  in redirect_uri parameter               |
| Password reset token reuse                    | Bugcrowd  | $8,000     | Token not invalidated after use              |
| API key leaked in JavaScript source           | HackerOne | $5,000     | Hardcoded API key in client-side bundle      |
| Authentication bypass via HTTP verb tampering | HackerOne | $12,000    | Changing POST to GET bypasses auth check     |

### 5.3 Injection Reports

| Title                                         | Platform   | Bounty     | Key Technique                               |
|-----------------------------------------------|-----------|------------|----------------------------------------------|
| Blind SQLi in search API                      | HackerOne | $15,000    | Time-based blind SQL injection via API       |
| NoSQL injection in MongoDB-backed API         | Bugcrowd  | $6,000     | JSON operator injection ($gt, $regex)        |
| GraphQL injection via nested mutations        | HackerOne | $8,500     | Mutation parameter injection                 |
| SSTI via API template rendering               | HackerOne | $20,000    | Server-side template injection in API output |
| Command injection via filename parameter      | HackerOne | $30,000    | OS command injection in file processing API  |

### 5.4 SSRF Reports

| Title                                         | Platform   | Bounty     | Key Technique                               |
|-----------------------------------------------|-----------|------------|----------------------------------------------|
| SSRF via webhook URL leads to AWS creds       | HackerOne | $25,000    | Internal metadata endpoint access via webhook|
| SSRF via image URL parameter                  | HackerOne | $10,000    | URL parameter in image processing endpoint   |
| Blind SSRF via PDF export feature             | Bugcrowd  | $7,500     | Internal URL rendering in PDF generator      |
| SSRF via SVG file upload                      | HackerOne | $15,000    | XXE/SSRF via SVG with external entities      |
| DNS rebinding SSRF bypass                     | HackerOne | $12,000    | Bypassing URL validation via DNS rebinding   |

### 5.5 Rate Limiting and Business Logic Reports

| Title                                         | Platform   | Bounty     | Key Technique                               |
|-----------------------------------------------|-----------|------------|----------------------------------------------|
| Race condition in coupon redemption           | HackerOne | $10,000    | Concurrent requests apply coupon multiple times|
| Unlimited referral bonus via race condition   | Bugcrowd  | $8,000     | Parallel referral creation before dedup      |
| Brute-force OTP due to missing rate limit     | HackerOne | $5,000     | 4-digit OTP brute-forced in minutes          |
| Price manipulation via parallel requests      | HackerOne | $15,000    | TOCTOU race between price check and charge   |
| Account takeover via password reset brute-force| HackerOne | $20,000   | Reset token enumeration (6-digit numeric)    |

### 5.6 CORS and Misconfiguration Reports

| Title                                         | Platform   | Bounty     | Key Technique                               |
|-----------------------------------------------|-----------|------------|----------------------------------------------|
| CORS misconfiguration allows data theft       | HackerOne | $6,000     | Origin reflection with credentials           |
| Exposed admin API with default credentials    | Bugcrowd  | $10,000    | Unauthenticated admin API endpoint           |
| Debug endpoint exposes environment variables  | HackerOne | $8,000     | Actuator/debug endpoint information leak     |
| Sensitive data in GraphQL error messages      | HackerOne | $3,000     | Detailed error messages leak DB schema       |
| API version rollback to vulnerable endpoint   | HackerOne | $7,500     | Accessing deprecated v1 API without auth     |

---

## 6. Framework Security Documentation

### 6.1 Backend Frameworks

| Framework        | Security Documentation URL                                    | Key Topics                                    |
|-----------------|----------------------------------------------------------------|------------------------------------------------|
| Django REST      | https://www.django-rest-framework.org/api-guide/authentication/| Authentication, permissions, throttling        |
| Flask            | https://flask.palletsprojects.com/en/latest/security/          | Security headers, CSRF, input validation       |
| FastAPI          | https://fastapi.tiangolo.com/tutorial/security/                | OAuth2, JWT, dependency injection for auth     |
| Express.js       | https://expressjs.com/en/advanced/best-practice-security.html  | Helmet, rate limiting, input validation        |
| Spring Security  | https://spring.io/projects/spring-security                     | Full auth framework, OAuth2, SAML, LDAP       |
| ASP.NET Core     | https://learn.microsoft.com/en-us/aspnet/core/security/        | Identity, auth, data protection, CORS          |
| Ruby on Rails    | https://guides.rubyonrails.org/security.html                   | CSRF, SQLi prevention, mass assignment         |
| Laravel          | https://laravel.com/docs/security                              | Authentication, authorization, encryption      |
| Go (net/http)    | https://pkg.go.dev/net/http                                    | TLS config, handler security, middleware       |
| Gin (Go)         | https://gin-gonic.com/docs/                                    | Middleware, validation, security headers       |

### 6.2 API Gateway Security

| Gateway           | Security Documentation URL                                  | Key Features                                  |
|-------------------|--------------------------------------------------------------|------------------------------------------------|
| Kong              | https://docs.konghq.com/gateway/latest/                      | Auth plugins, rate limiting, CORS, ACLs        |
| AWS API Gateway   | https://docs.aws.amazon.com/apigateway/                      | IAM auth, Lambda authorizers, throttling       |
| Azure API Mgmt    | https://learn.microsoft.com/en-us/azure/api-management/      | OAuth, certificates, IP filtering, policies    |
| Google Cloud API GW| https://cloud.google.com/api-gateway/docs                   | IAM, JWT validation, service accounts          |
| Nginx             | https://docs.nginx.com/nginx/admin-guide/security-controls/  | Rate limiting, access control, SSL/TLS         |
| HAProxy           | https://www.haproxy.com/documentation/                       | ACLs, rate limiting, SSL termination           |
| Traefik           | https://doc.traefik.io/traefik/                              | Middleware, rate limiting, TLS                 |
| Envoy             | https://www.envoyproxy.io/docs/envoy/latest/                 | Ext authz, rate limiting, RBAC                 |

### 6.3 GraphQL Implementations

| Implementation     | Security Documentation URL                                  | Key Security Features                         |
|--------------------|--------------------------------------------------------------|------------------------------------------------|
| Apollo Server      | https://www.apollographql.com/docs/apollo-server/security/   | Introspection control, query depth limits      |
| graphql-java       | https://www.graphql-java.com/documentation/instrumentation   | Max depth, max complexity, timeout             |
| Hasura             | https://hasura.io/docs/latest/security/                      | Role-based access, allow lists, rate limiting  |
| PostGraphile       | https://www.graphile.org/postgraphile/security/              | Row-level security, JWT claims                 |
| Dgraph             | https://dgraph.io/docs/graphql/                              | ACLs, encryption, namespaces                   |

### 6.4 Identity Providers

| Provider          | Security Documentation URL                                   | API Security Features                         |
|-------------------|---------------------------------------------------------------|------------------------------------------------|
| Auth0             | https://auth0.com/docs/secure/                                | OAuth, RBAC, attack protection, brute-force    |
| Okta              | https://developer.okta.com/docs/concepts/security/            | OAuth, SAML, API access management             |
| Keycloak          | https://www.keycloak.org/documentation                        | OIDC, SAML, fine-grained authorization         |
| AWS Cognito       | https://docs.aws.amazon.com/cognito/                          | User pools, identity pools, MFA                |
| Firebase Auth     | https://firebase.google.com/docs/auth                         | OAuth providers, custom tokens, security rules |
| Azure AD / Entra  | https://learn.microsoft.com/en-us/azure/active-directory/     | OAuth, SAML, conditional access, RBAC          |

---

