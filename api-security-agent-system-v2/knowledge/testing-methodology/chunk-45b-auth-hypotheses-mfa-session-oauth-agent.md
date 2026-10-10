# Testing Hypotheses: Authentication Part 2 — Agent Chunk 45b
> Source: 10-authorized-testing-hypotheses.md
> Purpose: Execute structured authentication test hypotheses: MFA bypass, session token entropy, token revocation, and OAuth redirect_uri validation bypass
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Execute each hypothesis: H-AUTH-08 (MFA bypass — test null OTP, response manipulation, race conditions, backup code brute-force), H-AUTH-09 (session token entropy — collect 100+ tokens, analyze randomness), H-AUTH-10 (token revocation — change password/logout then reuse old tokens), H-AUTH-11 (OAuth redirect_uri bypass — test path traversal, subdomain variations, open redirects, parameter pollution in redirect_uri). Document expected vs actual behavior for each test.

---

#### H-AUTH-07: Account Lockout Bypass

**Hypothesis**: Account lockout mechanisms may be byppassable through request
manipulation.

**Risk level of test**: LOW -- tests lockout mechanism behavior.

**Prerequisites**:
- Confirmed account lockout exists (from H-AUTH-06)
- Test account credentials
- Multiple test accounts

**Test procedure**:

1. Trigger account lockout on the test account through repeated failed logins.

2. Attempt to bypass the lockout through:
   - **IP rotation**: If lockout is IP-based, test from a different IP.
   - **Header manipulation**: Add or modify `X-Forwarded-For`,
     `X-Real-IP`, `X-Originating-IP` headers.
   - **Username variation**: Test with different casings of the username
     (`user@example.com` vs `User@Example.com`).
   - **Endpoint variation**: If `/login` locks out, try `/api/v2/login`
     or `/auth/token`.
   - **Method variation**: If POST locks out, try PUT.
   - **Parameter location**: If JSON body locks out, try query parameters
     or form-encoded body.

3. After each bypass attempt, check if login is possible with correct
   credentials.

4. Reset the lockout state between bypass techniques (wait for timeout or
   use an unlock mechanism).

**Expected results**:
- **Vulnerable**: Lockout bypassed through one of the manipulation techniques.
  Login succeeds despite lockout state.
- **Not vulnerable**: Lockout persists regardless of IP, headers, username
  casing, endpoint, method, or parameter location.

**Evidence collection**:
- The bypass technique that worked
- Request/response showing lockout and subsequent bypass
- Timestamp sequence

---

#### H-AUTH-08: Multi-Factor Authentication Bypass

**Hypothesis**: Multi-factor authentication may be bypassable by skipping the
MFA verification step or manipulating the flow.

**Risk level of test**: LOW -- tests the MFA flow on test accounts.

**Prerequisites**:
- Test account with MFA enabled and access to the second factor
- Understanding of the MFA flow

**Test procedure**:

1. Complete the first authentication factor (password) and capture the
   response. Note any intermediate tokens or session states.

2. Instead of completing the MFA step, attempt to access protected resources
   directly using whatever token/session was established after step 1.

3. Test additional bypass vectors:
   - **Skip to post-MFA endpoint**: After password auth, directly call an
     endpoint that should only be accessible after MFA.
   - **Reuse MFA codes**: Submit a previously used MFA code.
   - **Empty MFA code**: Submit an empty or null MFA code.
   - **MFA code brute-force**: If the code is numeric (e.g., 6 digits), check
     for rate limiting on the MFA verification endpoint specifically.
   - **Backup code misuse**: If backup codes exist, check if they bypass
     rather than replace MFA.
   - **MFA disable without MFA**: Check if the MFA disable endpoint requires
     current MFA verification.

4. For TOTP-based MFA, test time window tolerance:
   - Submit codes from adjacent time windows (past and future).
   - Note how many windows are accepted.

**Expected results**:
- **Vulnerable**: Protected resources accessible without completing MFA, or
  MFA verification can be bypassed through manipulation.
- **Not vulnerable**: All protected resources require completed MFA. MFA codes
  are validated, rate-limited, and single-use.

**Evidence collection**:
- The specific bypass technique that worked
- Request/response showing access without MFA completion
- MFA code validation behavior (rate limiting, replay protection)

---

#### H-AUTH-09: Insufficient Session Token Entropy

**Hypothesis**: Session tokens may have insufficient entropy, making them
guessable or predictable.

**Risk level of test**: NONE to the target -- offline statistical analysis.

**Prerequisites**:
- Ability to generate multiple session tokens (at least 20)
- Statistical analysis tools

**Test procedure**:

1. Generate 20+ session tokens by authenticating the test account repeatedly.
   For each token, record:
   - The exact token value
   - The timestamp of generation
   - Any other varying request parameters

2. Analyze the tokens:
   - **Length**: Minimum 128 bits (approximately 22 base64 characters or
     32 hex characters).
   - **Character distribution**: Should be uniform across the character set.
     Chi-squared test for uniformity.
   - **Sequential correlation**: No linear or polynomial relationship between
     successive tokens.
   - **Time correlation**: No correlation between token value and generation
     timestamp.
   - **Bit-level analysis**: Convert to binary and check for fixed bit
     positions.
   - **Compression ratio**: Truly random data does not compress. A token set
     with a good compression ratio suggests patterns.

3. If JWTs are used as session tokens, this test applies to the `jti` claim
   if present, not the entire JWT (which is deterministic by design).

**Expected results**:
- **Vulnerable**: Tokens show patterns, insufficient length (below 128 bits),
  non-uniform character distribution, or predictable sequences.
- **Not vulnerable**: Tokens pass all statistical randomness tests, are at
  least 128 bits, and show no correlation with time or sequence.

**Evidence collection**:
- Sample token set (redacted in report, full set in encrypted appendix)
- Statistical analysis results (chi-squared, serial correlation, compression)
- Token length and character set analysis

---

#### H-AUTH-10: Token Revocation Ineffectiveness

**Hypothesis**: Token revocation (logout, password change, permission change)
may not invalidate previously issued tokens.

**Risk level of test**: LOW -- tests logout and token lifecycle on test accounts.

**Prerequisites**:
- Test accounts with valid authentication
- Understanding of the token type (JWT, opaque, session cookie)

**Test procedure**:

1. **Logout revocation**:
   - Authenticate and capture the token.
   - Verify the token works (request a protected resource).
   - Log out through the API's logout endpoint.
   - Immediately attempt to use the captured token again.
   - If the token still works, check again after 1 minute, 5 minutes, and
     15 minutes.

2. **Password change revocation**:
   - Authenticate with Account A and capture the token.
   - Change Account A's password.
   - Attempt to use the pre-change token.

3. **Permission change revocation**:
   - Authenticate and capture the token.
   - Have the client change the account's permissions (add or remove a role).
   - Attempt to use the pre-change token.
   - Verify the token reflects the old or new permissions.

4. **Token refresh revocation**:
   - If refresh tokens are used, capture both access and refresh tokens.
   - Use the refresh token to get a new access token.
   - Attempt to use the old access token.
   - Attempt to use the old refresh token again.

**Expected results**:
- **Vulnerable**: Tokens remain valid after logout, password change, or
  permission change. Old tokens continue to work.
- **Not vulnerable**: Tokens are immediately invalidated on logout and
  password change. Permission changes are reflected in real-time or within
  a documented, acceptable window.

**Evidence collection**:
- Token used, logout/change action taken, and post-action response
- Time window during which old tokens remain valid (if any)
- Whether the vulnerability applies to access tokens, refresh tokens, or both

**Note**: For stateless JWTs, immediate revocation is architecturally difficult.
Document the token expiration time and whether a token blacklist exists. A JWT
with a 24-hour expiration and no blacklist is a finding, even though it is a
known trade-off.

---

#### H-AUTH-11: OAuth redirect_uri Validation Bypass

**Hypothesis**: The OAuth authorization endpoint may not strictly validate the
`redirect_uri` parameter, allowing authorization code or token theft.

**Risk level of test**: LOW -- tests redirect behavior on test accounts only.

**Prerequisites**:
- OAuth authorization endpoint in scope
- Test account that can initiate OAuth flows
- Knowledge of legitimate redirect URIs

**Test procedure**:

1. Capture a legitimate OAuth authorization request and note the
   `redirect_uri` parameter.

2. Test variations of the redirect URI:
   - **Subdomain substitution**: `https://evil.legitimate-domain.com/callback`
   - **Path traversal**: `https://legitimate-domain.com/callback/../evil`
   - **Parameter addition**: `https://legitimate-domain.com/callback?next=evil`
   - **Fragment addition**: `https://legitimate-domain.com/callback#evil`
   - **Port variation**: `https://legitimate-domain.com:8443/callback`
   - **Protocol downgrade**: `http://legitimate-domain.com/callback`
   - **Partial match**: `https://legitimate-domain.com.evil.com/callback`
   - **URL encoding**: Double-encode parts of the URI
   - **Open redirect chain**: If a legitimate redirect URI has an open
     redirect, chain it: `https://legitimate-domain.com/redirect?url=evil`
   - **Removal**: Omit the `redirect_uri` entirely and check where the
     code/token is sent

3. For each variation, initiate the OAuth flow and check whether the
   authorization server redirects the code/token to the modified URI.

4. If the `response_type` is `token` (implicit flow), the access token
   appears in the fragment. If `code`, the authorization code appears as
   a query parameter.

**Expected results**:
- **Vulnerable**: Authorization code or token redirected to a URI outside the
  registered set.
- **Not vulnerable**: Strict redirect URI validation rejects all modifications.
  Only exact-match registered URIs are accepted.

**Evidence collection**:
- The legitimate redirect URI and each tested variation
- The authorization server's response to each variation
- Whether codes/tokens were issued to unauthorized URIs

---

