# References: Framework Documentation & Training — Agent Chunk 66d
> Source: 14-references.md
> Purpose: Reference framework security documentation, books, training resources, and community resources for API security learning and methodology development
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Framework security docs: consult per framework when testing — Express.js security best practices, Django security docs, Spring Security reference, Rails security guide. Books/training: recommended for skill development and team onboarding. Community resources: OWASP API Security project, PortSwigger Web Security Academy, API security conferences, Discord/Slack communities. Use for staying current on emerging threats and techniques.

---

## 7. Books and Training Resources

### 7.1 Books

#### API Security

| Title                                                     | Author(s)                    | Publisher    | Year | Focus                                    |
|-----------------------------------------------------------|------------------------------|-------------|------|-------------------------------------------|
| Hacking APIs                                              | Corey J. Ball                | No Starch   | 2022 | Hands-on API pentesting methodology       |
| API Security in Action                                    | Neil Madden                  | Manning     | 2020 | Designing secure APIs from the ground up  |
| Black Hat GraphQL                                         | Nick Aleks, Dolev Farhi      | No Starch   | 2023 | GraphQL security testing                  |
| Web API Security                                          | Justin Richer, Antonio Sanso | Manning     | 2024 | OAuth, OIDC, and API auth patterns        |

#### Web Application Security (API-Relevant)

| Title                                                     | Author(s)                    | Publisher    | Year | Focus                                    |
|-----------------------------------------------------------|------------------------------|-------------|------|-------------------------------------------|
| The Web Application Hacker's Handbook (2nd ed)            | Dafydd Stuttard, Marcus Pinto| Wiley       | 2011 | Comprehensive web app security testing    |
| Real-World Bug Hunting                                    | Peter Yaworski               | No Starch   | 2019 | Bug bounty methodology and case studies   |
| Bug Bounty Bootcamp                                       | Vickie Li                    | No Starch   | 2021 | Bug bounty techniques and methodology     |
| The Tangled Web                                           | Michal Zalewski              | No Starch   | 2011 | Browser security model fundamentals       |
| Web Security for Developers                               | Malcolm McDonald             | No Starch   | 2020 | Practical web security for developers     |

#### OAuth and Authentication

| Title                                                     | Author(s)                    | Publisher    | Year | Focus                                    |
|-----------------------------------------------------------|------------------------------|-------------|------|-------------------------------------------|
| OAuth 2 in Action                                         | Justin Richer, Antonio Sanso | Manning     | 2017 | Deep dive into OAuth 2.0 implementation   |
| OpenID Connect in Action                                  | Prabath Siriwardena          | Manning     | 2023 | OIDC patterns and security                |
| Identity Attack Vectors                                   | Morey J. Haber, Darran Rolls | Apress      | 2020 | Identity and access management attacks    |

### 7.2 Online Training Platforms

| Platform                        | URL                                          | API Security Content                        |
|---------------------------------|----------------------------------------------|----------------------------------------------|
| PortSwigger Web Security Academy| https://portswigger.net/web-security          | Free labs on API security, JWT, OAuth, SSRF  |
| PentesterLab                    | https://pentesterlab.com/                     | Hands-on exercises for API vulnerabilities   |
| HackTheBox                      | https://www.hackthebox.com/                   | CTF-style API security challenges            |
| TryHackMe                       | https://tryhackme.com/                        | Guided API security learning paths           |
| APIsec University               | https://www.apisec.ai/apisec-university       | Dedicated API security courses               |
| SANS SEC522                     | https://www.sans.org/                         | Application Security: Securing Web Apps      |
| Practical API Hacking (TCM)     | https://academy.tcm-sec.com/                  | Practical API penetration testing course     |

### 7.3 Vulnerable Labs and Practice Environments

| Lab                             | URL                                          | Purpose                                      |
|---------------------------------|----------------------------------------------|----------------------------------------------|
| OWASP crAPI                     | https://github.com/OWASP/crAPI               | Deliberately vulnerable API for practice     |
| OWASP Juice Shop                | https://owasp.org/www-project-juice-shop/     | Vulnerable web app with API components       |
| VAmPI                           | https://github.com/erev0s/VAmPI              | Vulnerable REST API based on OWASP Top 10    |
| DVGA (Damn Vulnerable GraphQL)  | https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application | GraphQL-specific vulnerable lab |
| Pixi                            | https://github.com/DevSlop/Pixi              | Intentionally vulnerable API application     |
| Generic University              | https://github.com/InsiderPhD/Generic-University | API testing practice with guided challenges|
| Websheep                        | https://github.com/nickvdyck/websheep        | Vulnerable API for security testing practice |
| rest-api-goat                   | https://github.com/optiv/rest-api-goat       | OWASP API Top 10 vulnerable API              |

---

## 8. Community Resources

### 8.1 Blogs and Newsletters

| Resource                          | URL                                          | Focus                                        |
|-----------------------------------|----------------------------------------------|----------------------------------------------|
| PortSwigger Daily Swig            | https://portswigger.net/daily-swig           | Web/API security news and research           |
| Trail of Bits Blog                | https://blog.trailofbits.com/                | Security research, tooling, audits           |
| Detectify Labs                    | https://labs.detectify.com/                   | Web security research and bug bounty insights|
| The Hacker News                   | https://thehackernews.com/                   | Security news including API vulnerabilities  |
| Dana Epp's Blog                   | https://danaepp.com/                          | API security focused content                 |
| APIsecurity.io Newsletter         | https://apisecurity.io/                       | Weekly API security news and vulnerabilities |
| tl;dr sec Newsletter              | https://tldrsec.com/                          | Weekly security digest with API coverage     |
| Inon Shkedy's Blog                | https://inonshkedy.com/                       | OWASP API Security project contributor       |
| Alissa Knight                     | https://alissaknight.com/                     | API security research, automotive/fintech    |
| Katie Paxton-Fear                 | https://insiderphd.dev/                       | Bug bounty and API security education        |

### 8.2 Security Research Labs

| Organization                      | URL                                          | API Security Focus                           |
|-----------------------------------|----------------------------------------------|----------------------------------------------|
| PortSwigger Research              | https://portswigger.net/research             | Web/API vulnerability research               |
| Bishop Fox                        | https://bishopfox.com/                        | API security assessments and research        |
| Doyensec                          | https://www.doyensec.com/                     | Application security research, GraphQL       |
| NCC Group                         | https://research.nccgroup.com/                | Security research including API testing      |
| Trail of Bits                     | https://www.trailofbits.com/                  | Security audits and tooling                  |
| Project Discovery                 | https://projectdiscovery.io/                  | Open-source security tooling (Nuclei, httpx) |
| Assetnote                         | https://www.assetnote.io/                     | Attack surface management, API discovery     |
| Salt Security                     | https://salt.security/                        | API security platform and research           |
| Wallarm                           | https://www.wallarm.com/                      | API security platform and research           |
| 42Crunch                          | https://42crunch.com/                         | API security audit platform                  |

### 8.3 Conferences with API Security Content

| Conference                        | URL                                          | Frequency  | API Content                                  |
|-----------------------------------|----------------------------------------------|------------|----------------------------------------------|
| Black Hat (USA, EU, Asia)         | https://www.blackhat.com/                    | Annual     | Cutting-edge API/web research                |
| DEF CON                           | https://defcon.org/                           | Annual     | API security village, talks, CTFs            |
| OWASP Global AppSec               | https://owasp.org/events/                    | Biannual   | Dedicated API security tracks                |
| BSides (various cities)           | https://www.securitybsides.com/              | Ongoing    | Community security talks including APIs      |
| RESTfest                          | https://www.restfest.org/                    | Annual     | REST API design and security                 |
| API World                         | https://apiworld.co/                          | Annual     | API ecosystem including security tracks      |
| APIDays                           | https://www.apidays.global/                  | Multiple   | API-focused events globally                  |
| NorthSec                          | https://nsec.io/                              | Annual     | Security research and CTFs                   |
| Hack In The Box                   | https://conference.hitb.org/                  | Biannual   | Advanced security research                   |

### 8.4 Community Forums and Discussion

| Platform                          | URL / Location                               | Focus                                        |
|-----------------------------------|----------------------------------------------|----------------------------------------------|
| OWASP Slack                       | https://owasp.org/slack/invite               | OWASP community channels including API sec   |
| HackerOne Hacktivity              | https://hackerone.com/hacktivity              | Public bug bounty reports and discussion     |
| Bugcrowd Forum                    | https://forum.bugcrowd.com/                  | Bug bounty community discussion              |
| Reddit r/netsec                   | https://reddit.com/r/netsec                  | Network/application security discussion      |
| Reddit r/websecurity              | https://reddit.com/r/websecurity             | Web security focused discussion              |
| Reddit r/bugbounty                | https://reddit.com/r/bugbounty               | Bug bounty tips and discussion               |
| InfoSec Twitter/X                 | Various security researchers                 | Real-time security research sharing          |

### 8.5 Vulnerability Databases and Advisories

| Database                          | URL                                          | Use Case                                     |
|-----------------------------------|----------------------------------------------|----------------------------------------------|
| NIST NVD                          | https://nvd.nist.gov/                        | Authoritative CVE database with CVSS scores  |
| MITRE CVE                         | https://cve.mitre.org/                       | CVE numbering authority and database         |
| GitHub Advisory Database          | https://github.com/advisories                | OSS vulnerability advisories                 |
| Snyk Vulnerability Database       | https://security.snyk.io/                    | Package-level vulnerability tracking         |
| CISA Known Exploited Vulnerabilities | https://www.cisa.gov/known-exploited-vulnerabilities | Actively exploited vulnerabilities     |
| Exploit-DB                        | https://www.exploit-db.com/                  | Public exploits and PoCs                     |
| VulnDB                            | https://vulndb.cyberriskanalytics.com/       | Commercial vulnerability intelligence        |

---

## 9. Methodology and Process References

### 9.1 Testing Methodologies

| Methodology                        | URL                                         | Scope                                        |
|------------------------------------|----------------------------------------------|----------------------------------------------|
| OWASP Testing Guide               | https://owasp.org/www-project-web-security-testing-guide/ | Comprehensive web app testing methodology |
| PTES (Penetration Testing Standard)| http://www.pentest-standard.org/             | Full penetration testing methodology         |
| OSSTMM                            | https://www.isecom.org/OSSTMM.3.pdf         | Open Source Security Testing Methodology     |
| NIST SP 800-115                    | https://csrc.nist.gov/publications/detail/sp/800-115/final | Technical Guide to Information Security Testing |

### 9.2 Threat Modeling Frameworks

| Framework                          | URL                                         | Best For                                     |
|------------------------------------|----------------------------------------------|----------------------------------------------|
| STRIDE                             | Microsoft SDL resources                      | Systematic threat categorization             |
| PASTA                              | https://owasp.org/www-pdf-archive/AppSecEU2012_PASTA.pdf | Risk-centric threat modeling        |
| LINDDUN                           | https://linddun.org/                          | Privacy threat modeling                      |
| OWASP Threat Dragon               | https://owasp.org/www-project-threat-dragon/ | Open-source threat modeling tool             |
| Attack Trees                       | Various academic sources                     | Structured attack path analysis              |

### 9.3 Scoring and Classification Systems

| System                             | URL                                         | Purpose                                      |
|------------------------------------|----------------------------------------------|----------------------------------------------|
| CVSS v3.1                          | https://www.first.org/cvss/v3.1/specification-document | Vulnerability severity scoring    |
| CVSS v4.0                          | https://www.first.org/cvss/v4-0/             | Updated vulnerability scoring with improvements |
| CWE (Common Weakness Enumeration)  | https://cwe.mitre.org/                       | Software weakness classification             |
| CAPEC (Common Attack Patterns)     | https://capec.mitre.org/                     | Attack pattern enumeration                   |
| EPSS                               | https://www.first.org/epss/                  | Exploit prediction scoring                   |
| DREAD                              | Microsoft historical resources               | Risk rating model (retired but referenced)   |

---

## 10. Regulatory and Compliance References

### 10.1 Data Protection Regulations

| Regulation                        | Jurisdiction  | URL                                          | API Relevance                                |
|-----------------------------------|--------------|----------------------------------------------|----------------------------------------------|
| GDPR                              | EU/EEA       | https://gdpr.eu/                              | Data access APIs, consent management, DSAR   |
| CCPA/CPRA                         | California   | https://oag.ca.gov/privacy/ccpa              | Consumer data APIs, opt-out mechanisms       |
| PIPEDA                            | Canada       | https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/ | Data handling APIs |
| LGPD                              | Brazil       | https://www.gov.br/cidadania/pt-br/acesso-a-informacao/lgpd | Data processing APIs           |
| POPIA                             | South Africa | https://popia.co.za/                          | Data processing requirements                 |

### 10.2 Industry-Specific Regulations

| Regulation                        | Industry      | URL                                          | API Relevance                                |
|-----------------------------------|--------------|----------------------------------------------|----------------------------------------------|
| PCI DSS v4.0                      | Payment      | https://www.pcisecuritystandards.org/         | Payment processing APIs                      |
| HIPAA                             | Healthcare   | https://www.hhs.gov/hipaa/                   | Health data APIs, ePHI transmission          |
| SOX                               | Financial    | https://www.sec.gov/                          | Financial reporting system APIs              |
| FedRAMP                           | US Government| https://www.fedramp.gov/                      | Cloud service APIs for government use        |
| FISMA                             | US Government| https://csrc.nist.gov/topics/laws-and-regulations/laws/fisma | Federal information system APIs    |

---

## 11. Wordlists and Payloads

### 11.1 General Security Wordlists

| Wordlist                          | URL                                          | Purpose                                      |
|-----------------------------------|----------------------------------------------|----------------------------------------------|
| SecLists                          | https://github.com/danielmiessler/SecLists   | Comprehensive security testing wordlists     |
| FuzzDB                            | https://github.com/fuzzdb-project/fuzzdb     | Attack patterns and discovery primitives     |
| PayloadsAllTheThings              | https://github.com/swisskyrepo/PayloadsAllTheThings | Payload lists for various attacks      |
| Assetnote Wordlists               | https://wordlists.assetnote.io/              | API-focused wordlists for discovery          |
| CommonSpeak2                      | https://github.com/assetnote/commonspeak2    | Wordlists derived from real-world data       |

### 11.2 API-Specific Wordlists

| Wordlist                          | Location (within SecLists or standalone)     | Purpose                                      |
|-----------------------------------|----------------------------------------------|----------------------------------------------|
| API endpoints                     | SecLists/Discovery/Web-Content/api/          | Common API endpoint paths                    |
| API parameters                    | SecLists/Discovery/Web-Content/api/          | Common API parameter names                   |
| GraphQL operations                | Various community-maintained                 | Common GraphQL query and mutation names      |
| JWT secrets                       | SecLists/Passwords/                           | Common JWT signing secrets for brute-force   |
| HTTP headers                      | SecLists/Discovery/Web-Content/              | Common and security-relevant headers         |

---

## 12. Checklists and Quick References

### 12.1 Pre-Engagement Checklists

- Scope definition (endpoints, methods, authentication levels)
- Rules of engagement (rate limits, destructive testing, data handling)
- Environment details (staging vs production, load balancer configuration)
- Account provisioning (test accounts with different roles)
- Communication channels (escalation procedures, findings reporting)
