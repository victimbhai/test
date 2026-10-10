# Testing Hypotheses: Authentication Part 1 — Agent Chunk 45a
> Source: 10-authorized-testing-hypotheses.md
> Purpose: Execute structured authentication test hypotheses: default credentials, JWT none/weak HMAC attacks, predictable reset tokens, exposed API keys, missing rate limiting on login, and account lockout bypass
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Execute each hypothesis as a structured test: H-AUTH-01 (default credentials on admin interfaces — test admin:admin, root:root on /admin, /management), H-AUTH-02 (JWT none algorithm — set alg:none, remove signature), H-AUTH-03 (JWT weak HMAC — brute-force with hashcat/jwt_tool wordlists), H-AUTH-04 (predictable reset tokens — request multiple, analyze entropy/pattern), H-AUTH-05 (API keys in client code — search JS bundles, mobile apps), H-AUTH-06 (no rate limit on login — send 100+ rapid login attempts), H-AUTH-07 (lockout bypass — test with different headers, IP rotation).

---

### 2.1 Authentication Testing Hypotheses

Authentication testing verifies that the API correctly identifies who is making
a request and that authentication mechanisms cannot be bypassed or subverted.

---

#### H-AUTH-01: Default Credentials on API Management Interfaces

**Hypothesis**: Default credentials may be present on API management interfaces,
allowing unauthorized administrative access.

**Risk level of test**: LOW -- only attempts known defaults against admin panels.

**Prerequisites**:
- Identification of API gateway/management interfaces in scope
- List of known default credentials for the identified technology
- Authorization to test administrative interfaces

**Test procedure**:

1. Identify the API gateway or management technology in use. Check:
   - Response headers (`X-Powered-By`, `Server`, vendor-specific headers)
   - Error page formatting (framework-specific error templates)
   - Known default admin paths for common API gateways:
     - Kong: `:8001/` or `:8444/`
     - Tyk: `/tyk/keys`
     - AWS API Gateway: via AWS console (out of scope for API testing)
     - Apigee: management API
     - MuleSoft: Anypoint Platform
   - Application framework admin panels:
     - Django REST: `/admin/`
     - Spring Boot Actuator: `/actuator/`, `/manage/`
     - Laravel: `/telescope`, `/horizon`
     - Express: custom admin routes

2. For each identified admin interface, consult the vendor documentation for
   default credentials.

3. Attempt login with each set of default credentials. Limit attempts to
   documented defaults only -- this is not a brute-force test.

4. If a default credential works, document the access gained and stop. Do not
   explore further without explicit additional authorization.

**Expected results**:
- **Vulnerable**: Login succeeds with default credentials. Response includes
  admin session token, admin dashboard content, or management API data.
- **Not vulnerable**: Login fails. Response is a 401 or 403 with no data leak.

**Evidence collection**:
- Screenshot or response body showing successful admin access
- The specific default credential pair that worked (document in encrypted report)
- Scope of access available through the admin interface
- Timestamp and request/response pair

---

#### H-AUTH-02: JWT 'none' Algorithm Acceptance

**Hypothesis**: JWT tokens may accept the 'none' algorithm, allowing signature
bypass and token forgery.

**Risk level of test**: LOW -- sends a modified token; the API either accepts or
rejects it.

**Prerequisites**:
- A valid JWT token obtained through normal authentication
- Understanding of the JWT structure in use (header, payload, signature)
- A tool or script to decode, modify, and re-encode JWTs

**Test procedure**:

1. Capture a valid JWT from an authenticated session. Decode it to examine
   the header and payload:
   ```
   Header: {"alg": "RS256", "typ": "JWT"}
   Payload: {"sub": "user123", "role": "user", "exp": 1700000000}
   ```

2. Modify the header to use the 'none' algorithm:
   ```
   Header: {"alg": "none", "typ": "JWT"}
   ```

3. Re-encode the header and payload as Base64URL. Construct the token as:
   ```
   [base64url(header)].[base64url(payload)].
   ```
   Note the trailing period with no signature, and also test without the
   trailing period.

4. Also test case variations: `"alg": "None"`, `"alg": "NONE"`,
   `"alg": "nOnE"`.

5. Submit the modified token in the same position as the original (Authorization
   header, cookie, etc.) and send a request to a protected endpoint.

6. Compare the response with the baseline authenticated response.

**Expected results**:
- **Vulnerable**: The API returns a 200 OK with the same data as a properly
  signed token. The signature was not verified.
- **Not vulnerable**: The API returns 401 Unauthorized. The token is rejected
  because the algorithm is not in the server's allow-list.

**Evidence collection**:
- The original valid JWT (redacted if it contains sensitive claims)
- The modified JWT with 'none' algorithm
- Both the original and modified response (status code, headers, body)
- Timestamp of the test

**Remediation reference**: The server must maintain an explicit allow-list of
accepted algorithms and reject any token whose `alg` header is not on the list.
Libraries that accept `alg` from the token header without server-side validation
are vulnerable.

---

#### H-AUTH-03: JWT Weak HMAC Secret

**Hypothesis**: JWT tokens signed with HS256/HS384/HS512 may use a weak secret
that can be recovered through offline brute-force.

**Risk level of test**: NONE to the target system -- this is entirely offline
analysis of a captured token.

**Prerequisites**:
- A valid JWT signed with an HMAC algorithm (HS256, HS384, HS512)
- A system with sufficient compute for offline hash cracking
- A wordlist of common secrets and passwords

**Test procedure**:

1. Capture a valid JWT and confirm the algorithm is HMAC-based by decoding
   the header: `{"alg": "HS256", ...}`

2. Using an offline tool, attempt to recover the signing secret by testing
   candidate secrets against the token's signature. The verification is:
   ```
   HMAC-SHA256(base64url(header) + "." + base64url(payload), candidate_secret)
   == signature_from_token
   ```

3. Test with progressively larger candidate sets:
   - Common JWT secrets: `secret`, `password`, `key`, `jwt_secret`, the
     application name, default framework secrets
   - Common password lists (top 1000, top 10000)
   - If time permits, larger dictionaries

4. If the secret is recovered, verify by signing a new token with the recovered
   secret and submitting it to the API. This step confirms the finding and must
   be included in the report.

**Expected results**:
- **Vulnerable**: The secret is recovered. A token signed with the recovered
  secret is accepted by the API.
- **Not vulnerable**: The secret is not recovered within a reasonable time. This
  does not prove the secret is strong -- it only means it was not in the tested
  candidate set. Note the scope of testing in the report.

**Evidence collection**:
- The captured JWT (with payload redacted if it contains sensitive data)
- The recovered secret (in the encrypted report only)
- The tool and wordlist used, with the number of candidates tested
- A forged token and the API's response to it (proving the secret works)
- Time taken for recovery

**Note**: This test is entirely offline. No requests are sent to the target
during the cracking phase. Only the final verification request touches the API.

---

#### H-AUTH-04: Predictable Password Reset Tokens

**Hypothesis**: Password reset tokens may be predictable, allowing an attacker
to generate valid reset tokens for arbitrary accounts.

**Risk level of test**: LOW-MEDIUM -- generates multiple reset tokens for test
accounts. May trigger email notifications.

**Prerequisites**:
- At least two test accounts with accessible email addresses
- Authorization to test the password reset flow
- Confirmation that reset emails go to test mailboxes (not real users)

**Test procedure**:

1. Request password reset tokens for test Account A, collecting at least 10
   tokens over a short time period. Record the exact timestamp of each request.

2. Repeat for test Account B, collecting 10 tokens.

3. Analyze the tokens for patterns:
   - **Length**: Are all tokens the same length?
   - **Character set**: What characters appear? Is it hex, alphanumeric, base64?
   - **Entropy**: Calculate the actual entropy of the token space.
   - **Sequentiality**: Do tokens increment? Convert to numeric and check
     for sequential patterns.
   - **Timestamp correlation**: Do tokens encode or correlate with the request
     timestamp?
   - **Account correlation**: Do tokens for different accounts share a pattern?
   - **Predictability**: Given tokens T1 through T9, can you predict T10?

4. If a pattern is identified, generate a candidate token and attempt to use
   it through the reset flow. Use only test accounts for this step.

**Expected results**:
- **Vulnerable**: Tokens show predictable patterns. A generated token is
  accepted by the reset endpoint.
- **Not vulnerable**: Tokens are high-entropy, randomly generated, and show no
  correlation with timestamps, account IDs, or sequence numbers. Minimum 128
  bits of entropy is expected.

**Evidence collection**:
- All captured tokens (redacted in report, full set in encrypted appendix)
- Statistical analysis of token entropy and patterns
- If predictable: the pattern identified and a demonstration of prediction
- Timestamp of each token request

---

#### H-AUTH-05: API Keys Exposed in Client-Side Code

**Hypothesis**: API keys or secrets may be exposed in client-side code
(JavaScript bundles, mobile application binaries, configuration files).

**Risk level of test**: NONE to the target system -- this is static analysis of
publicly available code.

**Prerequisites**:
- Access to the client-side application (web app URL, mobile app binary)
- Tools for JavaScript deobfuscation and mobile app decompilation

**Test procedure**:

1. **Web application analysis**:
   - Download all JavaScript bundles loaded by the application
   - Search for patterns indicating API keys:
     - `api_key`, `apiKey`, `API_KEY`
     - `secret`, `token`, `auth`
     - `Bearer `, `Basic `
     - Long hexadecimal or base64 strings
     - Environment variable references: `process.env.`, `import.meta.env.`
   - Check for source maps (`.js.map` files) that reveal original source
   - Review `config.js`, `environment.ts`, and similar configuration files
   - Check HTML source for meta tags or data attributes containing keys
   - Review network requests in browser developer tools for hardcoded keys

2. **Mobile application analysis** (if in scope):
   - Decompile the application binary
   - Search for the same patterns as above
   - Check `strings` output for key-like values
   - Review configuration files (plist, xml, json) within the app bundle
   - Check for keys in native code vs. JavaScript/webview code

3. For each discovered key:
   - Determine what API it belongs to
   - Determine its permission scope (read-only? write? admin?)
   - Verify it is a real, active key (single benign API call)
   - Determine if it should be client-side (some keys are meant for clients)

**Expected results**:
- **Vulnerable**: Active API keys with server-side permissions found in
  client-side code. Particularly concerning: admin keys, payment processor
  keys, cloud provider keys, or keys with write permissions.
- **Not vulnerable**: Only publishable client-side keys found (e.g., Stripe
  publishable keys, Google Maps browser keys with proper restrictions).

**Evidence collection**:
- File and line number where each key was found
- The key itself (redacted in report body, full key in encrypted appendix)
- Verified permission scope of each key
- Whether the key should legitimately be client-side

---

#### H-AUTH-06: Missing Rate Limiting on Login Endpoints

**Hypothesis**: Login endpoints may lack rate limiting, allowing brute-force
password guessing attacks.

**Risk level of test**: LOW-MEDIUM -- sends multiple failed login attempts to
test accounts only. May trigger account lockout.

**Prerequisites**:
- Test account with known credentials
- Authorization to test rate limiting
- Understanding of the lockout policy (if any)

**Test procedure**:

1. Record the current time. Send 10 login requests with incorrect passwords
   to the test account, spacing them 1 second apart. Use obviously wrong
   passwords to avoid accidental success.

2. Record the response code and body for each attempt. Note any changes:
   - Does the response change after N failures?
   - Does the response time increase (tarpit/progressive delay)?
   - Is a CAPTCHA introduced?
   - Is the account locked?
   - Are additional headers introduced (Retry-After)?

3. If no rate limiting is observed after 10 attempts, send 10 more (total 20).
   Stop at 20 regardless -- the finding is established.

4. After testing, verify the test account is still accessible with correct
   credentials. If locked, follow the unlock procedure.

5. Test the same from different source IPs if possible (the rate limiting
   may be per-IP rather than per-account).

6. Also check for rate limiting on:
   - The token endpoint (`/oauth/token`)
   - API key authentication endpoints
   - MFA verification endpoints

**Expected results**:
- **Vulnerable**: 20 rapid-fire login failures accepted without any rate
  limiting, lockout, CAPTCHA, or delay.
- **Not vulnerable**: Rate limiting engages (429 response, progressive delay,
  CAPTCHA challenge, or account lockout) within 5-10 failed attempts.

**Evidence collection**:
- All request/response pairs with timestamps
- Calculation of the effective rate limit (or its absence)
- Whether rate limiting is per-account, per-IP, or both
- Behavior after rate limit is hit (lockout duration, reset mechanism)

---

