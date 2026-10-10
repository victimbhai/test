# Testing Hypotheses: Input Validation Part 1 — Agent Chunk 47a
> Source: 10-authorized-testing-hypotheses.md
> Purpose: Execute structured input validation test hypotheses: SQL injection, NoSQL injection, SSTI, OS command injection, and SSRF through API parameters
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Execute each hypothesis: H-INPUT-01 (SQL injection — test sort/filter/search params with SQLi payloads, time-based blind, UNION-based), H-INPUT-02 (NoSQL injection — inject MongoDB operators $ne/$gt/$regex in JSON params), H-INPUT-03 (SSTI — inject template syntax {{7*7}} in string params, test for Jinja2/Handlebars/EJS), H-INPUT-04 (OS command injection — inject command separators ;|`$() in params that interact with system), H-INPUT-05 (SSRF — provide internal URLs/cloud metadata URLs in URL params). Document all test payloads and responses.

---

### 2.3 Input Validation Testing Hypotheses

Input validation testing verifies that the API properly validates, sanitizes,
and handles all user-supplied input. These tests carry higher risk to the
target system and should be performed in staging environments when possible.

---

#### H-INPUT-01: SQL Injection Through API Parameters

**Hypothesis**: SQL injection may be possible through API parameters that are
used in database queries.

**Risk level of test**: MEDIUM-HIGH -- malformed queries may cause errors or
data exposure. Test in staging when possible.

**Prerequisites**:
- Endpoints that query a database (search, filter, sort, lookup)
- Staging environment preferred
- Authorization for injection testing

**Test procedure**:

1. Identify potentially injectable parameters:
   - Search/filter parameters: `?search=`, `?filter=`, `?q=`
   - Sort parameters: `?sort=`, `?order_by=`
   - ID parameters in path and query
   - JSON body fields used in database queries

2. For each parameter, test with SQL metacharacters (detection, not exploitation):
   - Single quote: `'` -- look for SQL error messages
   - Double quote: `"` -- different SQL dialects
   - Comment sequence: `-- `, `#`, `/**/`
   - Boolean test: `' OR '1'='1` vs `' OR '1'='2`
   - Time-based: `'; SELECT SLEEP(5)--` (use with extreme caution in
     production, only in staging)

3. Compare responses:
   - **Error-based detection**: Does the response include SQL error messages,
     stack traces, or database-specific errors?
   - **Boolean-based detection**: Does the response differ between the TRUE
     and FALSE conditions?
   - **Response-time detection**: Does a time-delay payload cause a
     measurable delay? (staging only)

4. For JSON-based APIs, test injection through JSON values:
   ```json
   {"search": "test' OR '1'='1"}
   {"filter": {"field": "name", "value": "test' OR '1'='1"}}
   ```

5. For GraphQL, test injection through argument values:
   ```graphql
   query {
     users(filter: "test' OR '1'='1") {
       id
     }
   }
   ```

**Expected results**:
- **Vulnerable**: SQL error messages in response, different behavior for
  TRUE vs FALSE conditions, or measurable time delays.
- **Not vulnerable**: Consistent error handling, parameterized queries
  preventing injection, no SQL-specific error messages.

**Evidence collection**:
- The injected parameter and value
- The response showing SQL error or boolean difference
- Baseline comparison (same request without injection)
- The specific SQL dialect indicated by errors (MySQL, PostgreSQL, MSSQL, etc.)

**Important**: Do not attempt data extraction. The purpose is to detect the
vulnerability, not exploit it. A single confirmed boolean difference or error
message is sufficient evidence.

---

#### H-INPUT-02: NoSQL Injection

**Hypothesis**: NoSQL injection may be possible through API parameters used in
NoSQL database queries (MongoDB, CouchDB, etc.).

**Risk level of test**: MEDIUM -- may alter query logic.

**Prerequisites**:
- Evidence or suspicion of NoSQL backend
- Staging environment preferred

**Test procedure**:

1. Test for MongoDB operator injection through JSON parameters:
   ```json
   {"username": {"$gt": ""}, "password": {"$gt": ""}}
   {"username": {"$ne": "nonexistent"}}
   {"username": {"$regex": ".*"}}
   ```

2. Test for JavaScript injection in MongoDB `$where` clauses:
   ```json
   {"$where": "1==1"}
   {"$where": "sleep(5000)"}  // staging only
   ```

3. Test through query parameters:
   ```
   ?username[$ne]=&password[$ne]=
   ?username[$gt]=&password[$gt]=
   ?username[$regex]=.*
   ```

4. Compare responses to identify changed query behavior.

**Expected results**:
- **Vulnerable**: Query operator injection changes result set, or JavaScript
  injection causes a time delay.
- **Not vulnerable**: Operators in input are treated as literal strings, not
  query operators.

---

#### H-INPUT-03: Server-Side Template Injection (SSTI)

**Hypothesis**: User input may be embedded in server-side templates without
sanitization, allowing template expression evaluation.

**Risk level of test**: HIGH in production (template evaluation may execute
code). Test in staging/dev only.

**Prerequisites**:
- Staging or development environment
- Endpoints that reflect user input in rendered responses

**Test procedure**:

1. Identify endpoints where user input appears in the response (error pages,
   email templates, PDF generation, report generation).

2. Test with template expressions for common template engines:
   - Jinja2/Twig: `{{7*7}}`
   - Freemarker: `${7*7}`
   - Velocity: `#set($x=7*7)${x}`
   - ERB: `<%= 7*7 %>`
   - Pebble: `{{7*7}}`
   - Smarty: `{7*7}`

3. If `49` appears in the response where you submitted `{{7*7}}`, the input
   is being evaluated as a template expression.

4. Do NOT proceed to code execution payloads. The arithmetic test is
   sufficient evidence.

**Expected results**:
- **Vulnerable**: Template expression is evaluated (49 appears in response).
- **Not vulnerable**: Template syntax is rendered as literal text.

---

#### H-INPUT-04: OS Command Injection

**Hypothesis**: API parameters may be incorporated into operating system
commands without proper sanitization.

**Risk level of test**: HIGH in production. Test in staging/dev only.

**Prerequisites**:
- Staging or development environment
- Endpoints that may interact with the OS (file operations, network lookups,
  PDF generation, image processing)

**Test procedure**:

1. Identify endpoints likely to execute OS commands:
   - File conversion endpoints
   - Network diagnostic endpoints (ping, traceroute, DNS lookup)
   - Document/report generation
   - Image processing
   - Archive handling

2. Test with time-delay command injection (detection only):
   - `; sleep 5` (Unix)
   - `& timeout 5` (Windows)
   - `| sleep 5`
   - `` `sleep 5` ``
   - `$(sleep 5)`

3. Measure response time. A 5-second delay compared to baseline indicates
   command execution.

4. If time-delay confirms injection, a single out-of-band test (DNS lookup
   to a controlled domain) can further confirm. Do NOT execute destructive
   commands or attempt to establish remote access.

**Expected results**:
- **Vulnerable**: Measurable delay matching the sleep duration.
- **Not vulnerable**: No delay difference between normal and injected requests.

---

#### H-INPUT-05: SSRF Through URL Parameters

**Hypothesis**: API parameters that accept URLs may be vulnerable to
server-side request forgery, allowing the attacker to make the server
send requests to internal resources.

**Risk level of test**: MEDIUM -- may cause the server to make unintended
requests.

**Prerequisites**:
- Endpoints that accept URL parameters (webhooks, imports, previews, avatars,
  link previews, file downloads)
- A controlled external server to detect SSRF callbacks

**Test procedure**:

1. Identify URL-accepting parameters:
   - Webhook URLs
   - Import/fetch URLs
   - Avatar/image URLs
   - Link preview URLs
   - OAuth callback URLs
   - File download URLs
   - PDF rendering URLs

2. Test with controlled external URLs first to confirm the server makes
   outbound requests. Use a request-logging service or controlled domain.

3. If outbound requests are confirmed, test for internal network access:
   - `http://127.0.0.1/`
   - `http://localhost/`
   - `http://169.254.169.254/` (cloud metadata -- document but do not extract)
   - `http://[::1]/` (IPv6 localhost)
   - `http://internal-service.local/`

4. Test bypass techniques:
   - URL encoding: `http://127.0.0.%31/`
   - Decimal IP: `http://2130706433/` (127.0.0.1 as decimal)
   - IPv6 mapping: `http://[::ffff:127.0.0.1]/`
   - DNS rebinding: Use a controlled domain that resolves to an internal IP
   - Redirect chain: External URL that redirects to internal URL

5. Test protocol handling:
   - `file:///etc/hostname` (file protocol)
   - `dict://127.0.0.1:6379/INFO` (Redis)
   - `gopher://127.0.0.1:25/` (SMTP)

**Expected results**:
- **Vulnerable**: Server makes requests to internal IPs or non-HTTP protocols.
  Cloud metadata endpoint accessible.
- **Not vulnerable**: URL validation rejects internal IPs, non-HTTP protocols,
  and redirect chains to internal resources.

**Important**: If the cloud metadata endpoint (169.254.169.254) is reachable,
document it as critical but do NOT extract credentials or secrets. The finding
is the reachability, not the metadata content.

---

