# HackerOne Priority Reports & Attack Patterns — Agent Chunk 00b
> Source: 02-public-report-manifest.md
> Purpose: Study the highest-impact real-world API vulnerability reports to learn attack patterns and testing strategies
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
These are the top 50 most impactful API security bug bounty reports ranked by bounty, upvotes, severity, and teaching value. Study these patterns to understand what real exploitable API vulnerabilities look like. Use the URLs to read full report details when available. Apply these patterns when testing target APIs.

---

## Tier 1: Must Study (Top 20 Priority Reports)

These combine high bounty, high upvotes, high relevance, and strong teaching value.

| # | Report Title | Program | Bounty | Upvotes | OWASP | Vuln Type | Key Pattern |
|---|-------------|---------|--------|---------|-------|-----------|-------------|
| 4 | API access to Phabricator from leaked certificate in git repo | Uber | $39,999 | 425 | API2 | Credential Leak | Leaked cert → internal API access chain |
| 1 | Exposed Kubernetes API - RCE/Exposed Creds | Snapchat | $25,000 | 1179 | API8 | Misconfig/RCE | K8s API exposed → full RCE |
| 6 | Blind SSRF to internal services in matrix preview_link API | Reddit | $6,000 | 331 | API7 | SSRF | URL preview feature → internal SSRF |
| 3 | Flickr Account Takeover using AWS Cognito API | Flickr | $0 | 436 | API2 | Auth Bypass | Cognito API misconfigured → ATO |
| 7 | Blind SQLi leading to RCE from Unauthenticated API | Starbucks | $0 | 233 | Beyond | SQLi/RCE | Unauthed test API → SQLi → RCE |
| 5 | DoS to WP-JSON API by cache poisoning CORS header | Automattic | $0 | 403 | API4 | DoS/Cache | CORS header cache poisoning on API |
| 9 | Github Apps Scoped Tokens get Full Access via GraphQL | GitHub | $0 | 195 | API5 | Priv Esc | OAuth scope gap via GraphQL API |
| 19 | Apache Flink RCE via GET jar/plan API Endpoint | Aiven | $6,000 | 127 | API8 | RCE | Direct RCE through API endpoint |
| 11 | Unauthorized Access to TikTok Private Videos via API | TikTok | $0 | 161 | API1 | IDOR | Object ID manipulation → private content |
| 18 | Git flag injection - Search API with scope 'blobs' | GitLab | $7,000 | 128 | Beyond | Injection | Parameter injection in API search |
| 10 | IDOR - API endpoint leaking sensitive user info | Razer | $375 | 172 | API1 | IDOR | Classic IDOR on user data endpoint |
| 38 | Docker Registry HTTP API v2 exposed without auth | Semmle | $0 | 80 | API2 | Auth Bypass | Infrastructure API no auth → image poisoning |
| 33 | Privilege Escalation via REST API to Admin → RCE | WordPress | $0 | 90 | API5 | Priv Esc | REST API role escalation to admin RCE |
| 26 | Multiple IDORs in family pairing API | TikTok | $0 | 104 | API1 | IDOR | Multiple IDOR patterns in one API |
| 30 | Exposed Cortex API at shopifycloud.com | Shopify | $6,300 | 94 | API8 | Misconfig | Internal API exposed to internet |
| 35 | Create admin accounts via API on BCRM instances | LY Corp | $0 | 86 | API5 | Priv Esc | API allows admin account creation |
| 70 | Race Conditions in OAuth 2 API implementations | IBB | $0 | 48 | API6 | Race Cond | Foundational OAuth2 race research |
| 72 | RC Between GitHub Repo Transfer REST + GraphQL Mutation | GitHub | $0 | 48 | API6 | Race Cond | REST-to-GraphQL race → admin retention |
| 61 | IDOR in API applications → account takeover | Automattic | $0 | 53 | API1 | IDOR | IDOR escalating to full ATO |
| 60 | DoS via markdown API from unauthenticated user | GitHub | $4,000 | 53 | API4 | DoS | Unauthed API → resource exhaustion |

### Key Attack Patterns from Tier 1

**Pattern 1: Leaked Credentials Chain**
- Find leaked API keys/certs in: Git repos, JS files, mobile APKs, Postman collections
- Chain: Leaked key → API access → internal data → lateral movement

**Pattern 2: IDOR/BOLA Escalation**
- Swap user IDs, object IDs, UUIDs in API endpoints
- Test: GET /api/users/{id}, GET /api/orders/{id}, GET /api/files/{id}
- Chain: IDOR → data leak → account takeover

**Pattern 3: Unauthed API Endpoint**
- Find API endpoints missing authentication checks
- Test: Remove auth headers, try different HTTP methods
- Chain: No auth → full API access → data extraction

**Pattern 4: SSRF via URL Parameters**
- Test any parameter accepting URLs: webhooks, callbacks, previews, imports
- Payloads: internal IPs (169.254.169.254, 127.0.0.1), internal hostnames
- Chain: SSRF → cloud metadata → credentials → infrastructure access

**Pattern 5: Race Condition on State Changes**
- Send concurrent requests to state-changing endpoints
- Target: OAuth flows, financial operations, permission changes
- Chain: Race → inconsistent state → unauthorized access

---

## Tier 2: Should Study (Reports 21-50)

| # | Report Title | Program | Bounty | OWASP | Key Pattern |
|---|-------------|---------|--------|-------|-------------|
| 2 | JumpCloud API Key leaked via Github | Starbucks | $0 | API8 | Canonical API key leak in public repo |
| 25 | CSRF on API endpoint → account takeover | Khan Academy | $0 | Beyond | API CSRF leading to full ATO |
| 12 | Undocumented fileCopy GraphQL API | Shopify | $2,000 | API9 | Shadow API discovery in GraphQL |
| 73 | RC Between GitHub Repo Update REST + GraphQL | GitHub | $0 | API6 | Persistent admin via race condition |
| 66 | SSRF via hijacked aggregated API server | Kubernetes | $1,000 | API7 | K8s SSRF through aggregated API |
| 17 | OTP code Leaked in API Response | MTN Group | $0 | API2 | OTP in response body |
| 199 | Post-Auth Blind NoSQLi in users.list API → RCE | Rocket.Chat | $0 | Beyond | NoSQL injection via API to RCE |
| 198 | /api/as/v1/credentials/ allows privilege escalation | Elastic | $0 | API5 | Direct credential API access |
| 105 | SSRF in Portainer → Internal Docker API | Uber | $500 | API7 | SSRF chain to Docker API |
| 109 | Zero click ATO due to API misconfiguration | UPchieve | $0 | API2 | Zero-click account takeover |
| 99 | Bypass Rate Limits via X-Forwarded-For | Snapchat | $0 | API4 | Header-based rate limit bypass |
| 75 | Missing auth on buddy group API | LY Corp | $3,000 | API2 | Endpoint missing auth check |
| 113 | Enable API access for free via mass assignment | New Relic | $0 | API3 | Mass assignment → premium bypass |
| 115 | API signature can be reused with other params | Gatecoin | $0 | API2 | Signature replay attack |
| 77 | PATCH manipulation to escalate API Key settings | Frontegg | $0 | API5 | HTTP method → privilege escalation |
| 64 | Account deletion API without 2FA verification | Mozilla | $1,000 | API2 | 2FA bypass on destructive action |
| 79 | Unauthed API exposes premium content + financial data | XVIDEOS | $0 | API2 | Missing auth on financial API |
| 215 | Shopify API ruby SDK SSRF + client secret leak | Shopify | $0 | API7 | SDK-level SSRF; supply chain |
| 69 | Unrestricted access to quiesce in REST API | PlayStation | $1,000 | API5 | Critical function exposed via API |
| 88 | Race Condition on Create API Function | Enjin | $0 | API6 | Race on creation endpoint |
| 102 | StoreFront API allows brute force on login | Shopify | $0 | API4 | Missing rate limit on auth |
| 148 | Weak brute-force protection on login API | Palo Alto | $0 | API4 | Brute force → ATO |
| 74 | Expired password still grants API/Git access | GitLab | $950 | API2 | Password policy not enforced on API |
| 142 | Unbounded decompression in Node.js Fetch API | Node.js | $0 | API4 | Decompression bomb DoS |
| 92 | Delete any LinkedIn comment via learning API | LinkedIn | $0 | API5 | BFLA → delete other users' content |
| 187 | Boolean-based SQLi in API endpoint | Razer | $0 | Beyond | SQLi through API parameter |
| 286 | REST API executes query parameter directly | Rocket.Chat | $0 | Beyond | Direct query injection |
| 121 | Internal ML API path traversal | HackerOne | $0 | Beyond | Path traversal on ML API |
| 267 | Timing Attack on API Token Verification | joola.io | $0 | API2 | Timing side-channel on auth |
| 197 | Public→private group doesn't remove from search API | GitLab | $0 | API9 | Zombie API data persistence |

---

## Highest Bounty Reports (Top 10)

| Report | Program | Bounty | OWASP | Attack Chain |
|--------|---------|--------|-------|-------------|
| API access to Phabricator from leaked cert | Uber | $39,999 | API2 | Git repo → leaked cert → internal API |
| Exposed Kubernetes API | Snapchat | $25,000 | API8 | K8s API exposed → RCE + creds |
| Git flag injection in Search API | GitLab | $7,000 | Beyond | Flag injection in API search params |
| Exposed Cortex API | Shopify | $6,300 | API8 | Internal API accessible externally |
| Blind SSRF in preview_link API | Reddit | $6,000 | API7 | URL preview → blind SSRF |
| Apache Flink RCE via API | Aiven | $6,000 | API8 | Direct API endpoint → RCE |
| DoS via markdown API | GitHub | $4,000 | API4 | Unauthed API → resource exhaustion |
| Leak info via API request | Grab | $3,000 | API1 | Real-time data leakage via API |
| Missing auth on buddy group API | LY Corp | $3,000 | API2 | Auth check missing on endpoint |
| Stored XSS on PyPi simple API | GitLab | $3,000 | Beyond | XSS through API response |

---

## Report URL Pattern

All reports accessible at: `https://hackerone.com/reports/{report_id}`

Key report IDs for deep study:
- #455645 (K8s API RCE), #591813 (Uber Phabricator), #1960765 (Reddit SSRF)
- #1342088 (Flickr ATO), #592400 (Starbucks SQLi/RCE), #591302 (WP-JSON DoS)
- #1711938 (GitHub GraphQL), #1418891 (Flink RCE), #2868084 (TikTok IDOR)
- #682442 (GitLab injection), #347296 (Docker Registry), #1107282 (WP REST priv esc)
- #55140 (OAuth2 race), #2216036 (GitHub race), #1130874 (Rocket.Chat NoSQLi)

---

*Source: Priority analysis of 299 classified HackerOne API security reports*
