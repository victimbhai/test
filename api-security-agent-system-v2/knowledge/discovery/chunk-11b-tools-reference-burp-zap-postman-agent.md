# Tools Reference: Burp Suite, OWASP ZAP & Postman/Insomnia — Agent Chunk 11b
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Configure and use Burp Suite Professional (with API security extensions), OWASP ZAP, and Postman/Insomnia for comprehensive API security testing
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Set up Burp Suite with API-specific configuration: disable automatic form submissions, configure JSON/XML handling, set up match-and-replace rules for auth tokens. Install essential extensions: AuthMatrix (authorization testing across roles), Autorize (automatic authorization enforcement testing), InQL (GraphQL security), Param Miner (hidden parameter discovery), JWT Editor (token manipulation). Use ZAP for automated API scanning by importing OpenAPI specs and running active scans. Configure Postman with multiple auth environments and use test scripts to verify authorization, data exposure, and IDOR protections. Use Newman CLI for CI/CD integration.

---

## 8. Tools Reference

### 8.1 Burp Suite Professional

**Purpose:** Comprehensive web application and API security testing platform that serves
as the central tool for intercepting, modifying, and replaying API requests.

**Installation:**
```bash
# Download from https://portswigger.net/burp/pro
# Requires Java Runtime Environment (JRE) 17+
# Linux installation:
chmod +x burpsuite_pro_linux_v2024_x.sh
./burpsuite_pro_linux_v2024_x.sh
```

**API-Security-Specific Configuration:**

```
1. Project Settings:
   - Disable automatic form submissions
   - Configure JSON/XML content type handling
   - Set up custom match-and-replace rules for auth tokens

2. Proxy Configuration:
   - Configure invisible proxying for mobile apps
   - Set up upstream proxy for chaining
   - Configure TLS pass-through for certificate-pinned domains

3. Scanner Configuration:
   - Enable API-specific scan checks
   - Configure insertion points for JSON/XML bodies
   - Set scan speed appropriate for API rate limits

4. Scope Configuration:
   - Include only target API domains
   - Exclude third-party authentication providers from active scanning
```

**Essential Burp Extensions for API Security:**

**AuthMatrix:**
```
Purpose: Automated authorization testing across multiple roles
Installation: BApp Store > AuthMatrix

Usage:
1. Map the application through normal browsing
2. Configure user roles and their authentication tokens
3. Define the authorization matrix (which role should access which endpoint)
4. Run the test - AuthMatrix replays each request with each role's token
5. Review the results matrix for authorization failures

API-specific tip: Configure JSON body extraction rules to identify
IDOR-related fields (user IDs, resource IDs) that should change
between users.
```

**Autorize:**
```
Purpose: Automatic authorization enforcement testing
Installation: BApp Store > Autorize

Usage:
1. Configure a low-privilege user's session cookies/tokens
2. Browse the application as a high-privilege user
3. Autorize automatically replays each request with the low-privilege
   credentials and without any credentials
4. Color-coded results show authorization enforcement status

API-specific tip: Set up custom header replacement for Bearer tokens
rather than cookie-based session replacement.
```

**InQL (Introspection Query Language):**
```
Purpose: GraphQL security testing
Installation: BApp Store > InQL

Usage:
1. Point InQL at the GraphQL endpoint
2. It performs introspection and generates:
   - All available queries and mutations
   - Input type structures
   - Field suggestions
3. Generate example queries for each operation
4. Test for injection in GraphQL arguments

API-specific tip: Use InQL's batch query generator to test for
DoS via query batching, and the complexity analyzer to identify
expensive queries.
```

**Param Miner:**
```
Purpose: Hidden parameter and header discovery
Installation: BApp Store > Param Miner

Usage:
1. Right-click a request > Extensions > Param Miner > Guess Parameters
2. Select parameter locations to test (URL, body, headers, cookies)
3. Configure detection method (response length diff, reflection, error-based)
4. Review discovered parameters

API-specific tip: Use Param Miner with JSON body fuzzing to discover
hidden fields in API request bodies. Focus on POST/PUT endpoints
where mass assignment is a risk.
```

**JWT Editor:**
```
Purpose: JWT token manipulation and attack
Installation: BApp Store > JWT Editor

Usage:
1. JWT tokens in requests are automatically detected and highlighted
2. Click to decode and edit the token
3. Test attacks:
   - Algorithm confusion (RS256 to HS256)
   - Signature removal (alg: none)
   - Key injection (jwk header injection)
   - Claim manipulation (role, sub, exp)
4. Sign modified tokens with discovered or generated keys

API-specific tip: Extract the public key from the JWKS endpoint and
use it as the HMAC secret for algorithm confusion attacks.
```

### 8.2 OWASP ZAP (Zed Attack Proxy)

**Purpose:** Open-source alternative to Burp Suite for API security testing, with
strong automation capabilities and API scanning features.

**Installation:**
```bash
# Via package manager
sudo apt install zaproxy

# Via Docker
docker pull ghcr.io/zaproxy/zaproxy:stable
docker run -u zap -p 8080:8080 -p 8090:8090 \
  ghcr.io/zaproxy/zaproxy:stable zap-webswing.sh

# Via snap
sudo snap install zaproxy --classic
```

**API Scanning with ZAP:**

```bash
# Import OpenAPI specification and scan
zap-cli --zap-url http://localhost:8080 openapi-import \
  https://api.target.com/openapi.json

# Run active scan against imported API
zap-cli --zap-url http://localhost:8080 active-scan \
  https://api.target.com/

# Automated API scan using Docker
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \
  -t https://api.target.com/openapi.json \
  -f openapi \
  -r api_scan_report.html

# GraphQL scanning
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \
  -t https://api.target.com/graphql \
  -f graphql \
  -r graphql_scan_report.html
```

**API-Security-Specific Tips:**
- Use the OpenAPI import add-on to automatically create a site tree from specs
- Configure authentication contexts for Bearer token-based APIs
- Use the Fuzzer with API-specific payloads for JSON parameter testing
- Enable the GraphQL add-on for schema-aware GraphQL testing
- Configure scan policies to focus on API-relevant vulnerabilities

### 8.3 Postman and Insomnia

**Purpose:** API development and manual testing tools that provide structured request
building, collection organization, and test automation.

**Postman for Security Testing:**

```
Security Testing Workflow:
1. Import the API specification (OpenAPI, cURL, Swagger)
2. Configure environments for different auth levels:
   - admin_token, user_token, partner_token, no_token
3. Create test scripts for each request:

   // Authorization test
   pm.test("Admin endpoint rejects user token", function() {
       pm.response.to.have.status(403);
   });

   // Data exposure test
   pm.test("Response does not contain internal fields", function() {
       var body = pm.response.json();
       pm.expect(body).to.not.have.property('internal_id');
       pm.expect(body).to.not.have.property('password_hash');
       pm.expect(body).to.not.have.property('ssn');
   });

   // IDOR test
   pm.test("Cannot access other user resources", function() {
       pm.response.to.have.status(403);
   });

4. Use Collection Runner to execute all tests across environments
5. Use Newman (CLI) for CI/CD integration:
   newman run collection.json -e admin_env.json --reporters cli,html
```

**Insomnia for API Testing:**

```
Key Features for Security Testing:
1. Environment switching for different auth contexts
2. Plugin system for custom authentication flows
3. Request chaining for multi-step tests
4. Response validation with JSONPath
5. Git sync for version-controlled test collections
6. gRPC support for testing gRPC services
```

