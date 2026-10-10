# References: Research Papers & CVE Database — Agent Chunk 66b
> Source: 14-references.md
> Purpose: Reference security research papers/presentations and CVE database entries relevant to API security testing
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use research references for: understanding novel attack techniques (single-packet race conditions, prototype pollution chains, GraphQL exploitation), staying current on API attack trends, referencing in technical reports. CVE database: cross-reference detected framework/library versions against known CVEs, use CVE details in vulnerability reports for credibility, track CVE timelines for version-specific testing.

---

## 2. Research Papers and Presentations

### 2.1 Conference Presentations

#### James Kettle -- "Smashing the State Machine" (Black Hat USA 2023)

Groundbreaking research on race condition vulnerabilities in web applications and APIs,
introducing the single-packet attack technique for reliable race condition exploitation.

- **Conference**: Black Hat USA 2023
- **Presenter**: James Kettle (PortSwigger)
- **URL**: https://portswigger.net/research/smashing-the-state-machine
- **Key contributions**:
  - Single-packet attack technique for eliminating network jitter
  - Classification of race condition vulnerability types (limit overrun, time-of-check to
    time-of-use, session-based)
  - Practical exploitation methodology for multi-step race conditions
- **Relevance**: Chapters on race condition testing methodology

#### James Kettle -- "HTTP Desync Attacks" (Black Hat USA 2019)

Research on HTTP request smuggling in modern environments, demonstrating how discrepancies
between front-end and back-end HTTP parsers create exploitable conditions.

- **Conference**: Black Hat USA 2019
- **Presenter**: James Kettle (PortSwigger)
- **URL**: https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
- **Key contributions**:
  - Revived and modernized request smuggling techniques
  - CL.TE, TE.CL, and TE.TE desync patterns
  - Impact on API gateways and reverse proxies
- **Relevance**: API gateway and proxy security testing

#### James Kettle -- "HTTP/2: The Sequel is Always Worse" (Black Hat USA 2021)

Research on HTTP/2 specific vulnerabilities including H2.CL desync, request tunneling,
and HTTP/2 exclusive desync attacks.

- **Conference**: Black Hat USA 2021
- **Presenter**: James Kettle (PortSwigger)
- **URL**: https://portswigger.net/research/http2
- **Relevance**: HTTP/2 API security testing

#### Egor Homakov -- OAuth Security Research

Extensive research on OAuth 2.0 security vulnerabilities including state fixation,
redirect URI bypass techniques, and token leakage vectors.

- **Key publications**: Multiple blog posts and conference talks on OAuth security
- **URL**: http://homakov.blogspot.com/
- **Relevance**: OAuth implementation testing methodology

#### Philippe De Ryck -- "OAuth and OpenID Connect Security Best Practices"

Comprehensive guidance on securing OAuth and OpenID Connect implementations in modern
applications.

- **URL**: https://pragmaticwebsecurity.com/
- **Relevance**: Practical OAuth/OIDC security testing guidance

### 2.2 Research Papers

#### Bishop Fox -- "An Exploration of JSON Interoperability Vulnerabilities"

Research examining how different JSON parsers handle edge cases differently, leading to
security vulnerabilities when multiple parsers process the same JSON data.

- **Organization**: Bishop Fox
- **URL**: https://bishopfox.com/blog/json-interoperability-vulnerabilities
- **Key findings**:
  - Duplicate key handling differences across parsers
  - Comment handling inconsistencies
  - Number precision differences
  - String encoding edge cases
  - Truncation and overflow behaviors
- **Relevance**: JSON parsing attacks in API security testing

#### "How Many Days Has It Been Since a JWT alg=none Vulnerability?" (Various)

Ongoing research tracking JWT implementation vulnerabilities, particularly the recurrence
of algorithm confusion and alg:none acceptance in production systems.

- **Relevance**: JWT security testing methodology and common implementation mistakes

#### Snyky / Snyk Security Research -- API Security Reports

Annual reports on the state of API security, vulnerability trends, and attack patterns
observed across the software supply chain.

- **URL**: https://snyk.io/reports/
- **Relevance**: Industry trends and statistical context for API vulnerability prevalence

#### Salt Security -- State of API Security Report

Quarterly reports analyzing API attack traffic, trends in API vulnerability exploitation,
and emerging API threat vectors.

- **URL**: https://salt.security/api-security-trends
- **Relevance**: Real-world API attack data, trending vulnerability classes, industry
  benchmarks for API security posture

### 2.3 PortSwigger Research Publications

PortSwigger Research produces consistently high-quality research relevant to API security.

| Title                                             | Year  | Topic                            |
|--------------------------------------------------|-------|-----------------------------------|
| Smashing the State Machine                       | 2023  | Race conditions                   |
| Browser-Powered Desync Attacks                   | 2022  | Client-side desync                |
| HTTP/2: The Sequel is Always Worse               | 2021  | HTTP/2 vulnerabilities            |
| HTTP Request Smuggling                           | 2019  | Request smuggling                 |
| Practical Web Cache Poisoning                    | 2018  | Cache poisoning via headers       |
| Server-Side Template Injection                   | 2015  | SSTI fundamentals                 |
| Turbo Intruder: Embracing the 10M Attack Surface | 2019  | High-concurrency testing          |

- **URL**: https://portswigger.net/research

### 2.4 Academic Papers

#### "A Systematic Review of API Security Testing Techniques"

Academic surveys on automated and manual API security testing techniques, comparing
effectiveness of different approaches.

- **Relevance**: Understanding the theoretical foundations and limitations of API security
  testing methodologies

#### "RESTful API Security: A Systematic Mapping Study"

Systematic literature review of security concerns specific to RESTful API architectures.

- **Relevance**: Taxonomy of REST API vulnerabilities and defense mechanisms

#### "An Empirical Study of GraphQL Security"

Analysis of common security anti-patterns in real-world GraphQL deployments.

- **Relevance**: Evidence-based GraphQL security testing priorities

---

## 3. CVE Database

### 3.1 Authentication and Authorization CVEs

| CVE ID            | Technology     | Severity | Description                                                    | Year |
|-------------------|---------------|----------|----------------------------------------------------------------|------|
| CVE-2018-0114    | Cisco node-jose| Critical | JWT signature bypass via embedded JWK                          | 2018 |
| CVE-2022-23529   | jsonwebtoken   | Critical | Remote code execution via JWT secret poisoning                 | 2022 |
| CVE-2022-23539   | jsonwebtoken   | Medium   | Insecure default key handling in jwt.verify()                  | 2022 |
| CVE-2022-23540   | jsonwebtoken   | Medium   | Algorithm confusion in jwt.verify() without algorithms option  | 2022 |
| CVE-2022-23541   | jsonwebtoken   | Medium   | Key type mismatch allows bypass                                | 2022 |
| CVE-2019-20933   | InfluxDB       | Critical | Empty shared secret allows authentication bypass               | 2019 |
| CVE-2020-28042   | jwt-go         | Medium   | None algorithm bypass                                          | 2020 |
| CVE-2021-29442   | Nacos          | High     | Authentication bypass in Nacos API                             | 2021 |
| CVE-2023-22602   | Apache Shiro   | Critical | Authentication bypass via path manipulation                    | 2023 |
| CVE-2024-21683   | Atlassian Conf.| High     | RCE via authenticated API endpoint                             | 2024 |
| CVE-2023-32784   | KeePass        | Medium   | Master password recovery from process memory                   | 2023 |

### 3.2 Injection CVEs

| CVE ID            | Technology     | Severity | Description                                                    | Year |
|-------------------|---------------|----------|----------------------------------------------------------------|------|
| CVE-2017-5638    | Apache Struts  | Critical | RCE via Content-Type header injection                          | 2017 |
| CVE-2019-0232    | Apache Tomcat  | Critical | RCE via CGI parameter injection on Windows                     | 2019 |
| CVE-2021-44228   | Apache Log4j   | Critical | RCE via JNDI injection (Log4Shell)                             | 2021 |
| CVE-2021-45046   | Apache Log4j   | Critical | Incomplete fix for Log4Shell                                   | 2021 |
| CVE-2022-22963   | Spring Cloud   | Critical | RCE via Spring Cloud Function SpEL injection                   | 2022 |
| CVE-2022-22965   | Spring Framework| Critical | RCE via class loader manipulation (Spring4Shell)               | 2022 |
| CVE-2023-34362   | MOVEit Transfer| Critical | SQL injection leading to RCE                                   | 2023 |
| CVE-2023-46604   | Apache ActiveMQ| Critical | RCE via deserialization                                        | 2023 |
| CVE-2024-3094    | xz-utils       | Critical | Supply chain compromise with backdoor in SSH                   | 2024 |

### 3.3 SSRF CVEs

| CVE ID            | Technology     | Severity | Description                                                    | Year |
|-------------------|---------------|----------|----------------------------------------------------------------|------|
| CVE-2019-17571   | Apache Log4j   | Critical | Deserialization RCE via SocketServer                           | 2019 |
| CVE-2021-26855   | MS Exchange    | Critical | SSRF leading to RCE (ProxyLogon)                               | 2021 |
| CVE-2021-26858   | MS Exchange    | High     | Post-auth arbitrary file write (ProxyLogon chain)              | 2021 |
| CVE-2021-27065   | MS Exchange    | High     | Post-auth arbitrary file write (ProxyLogon chain)              | 2021 |
| CVE-2021-40438   | Apache httpd   | Critical | SSRF via mod_proxy                                             | 2021 |
| CVE-2023-42793   | JetBrains TC   | Critical | Authentication bypass leading to RCE via SSRF chain            | 2023 |

### 3.4 HTTP Protocol CVEs

| CVE ID            | Technology     | Severity | Description                                                    | Year |
|-------------------|---------------|----------|----------------------------------------------------------------|------|
| CVE-2023-44487   | HTTP/2         | High     | HTTP/2 Rapid Reset denial of service                           | 2023 |
| CVE-2023-25690   | Apache httpd   | Critical | HTTP request smuggling via mod_proxy                           | 2023 |
| CVE-2022-1388    | F5 BIG-IP      | Critical | Authentication bypass via request smuggling                    | 2022 |
| CVE-2021-22986   | F5 BIG-IP      | Critical | RCE via iControl REST API                                      | 2021 |
| CVE-2020-11724   | Jetty          | Medium   | HTTP request smuggling due to CL/TE handling                   | 2020 |

### 3.5 API Framework CVEs

| CVE ID            | Technology     | Severity | Description                                                    | Year |
|-------------------|---------------|----------|----------------------------------------------------------------|------|
| CVE-2023-25136   | OpenSSH        | Medium   | Pre-auth double-free vulnerability                             | 2023 |
| CVE-2023-44487   | Various HTTP/2 | High     | Rapid Reset attack affecting all HTTP/2 implementations        | 2023 |
| CVE-2022-41741   | NGINX          | High     | Memory corruption in ngx_http_mp4_module                       | 2022 |
| CVE-2023-27997   | Fortinet       | Critical | Heap buffer overflow in FortiOS SSL VPN                        | 2023 |
| CVE-2023-3519    | Citrix NetScaler| Critical | RCE via unauthenticated buffer overflow                       | 2023 |
| CVE-2024-1709    | ConnectWise    | Critical | Authentication bypass in ScreenConnect                         | 2024 |

### 3.6 GraphQL-Related CVEs

| CVE ID            | Technology     | Severity | Description                                                    | Year |
|-------------------|---------------|----------|----------------------------------------------------------------|------|
| CVE-2022-37315   | graphql-java   | High     | Denial of service via deeply nested queries                    | 2022 |
| CVE-2023-26144   | graphql-armor  | Medium   | Bypass of query complexity limits                              | 2023 |
| CVE-2022-40302   | Hasura GraphQL | High     | Authorization bypass in certain query patterns                 | 2022 |

### 3.7 Deserialization CVEs

| CVE ID            | Technology     | Severity | Description                                                    | Year |
|-------------------|---------------|----------|----------------------------------------------------------------|------|
| CVE-2015-5254    | Apache ActiveMQ| High     | RCE via Java deserialization in JMS ObjectMessage               | 2015 |
| CVE-2017-9805    | Apache Struts  | High     | RCE via XML deserialization in REST plugin                      | 2017 |
| CVE-2019-12384   | Jackson        | High     | RCE via polymorphic deserialization                             | 2019 |
| CVE-2020-36518   | Jackson        | High     | Denial of service via deeply nested JSON                       | 2020 |
| CVE-2023-36665   | Protobuf.js    | High     | Prototype pollution via protobuf parsing                       | 2023 |

---

