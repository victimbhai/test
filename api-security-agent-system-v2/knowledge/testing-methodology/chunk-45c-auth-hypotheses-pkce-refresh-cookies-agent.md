# Testing Hypotheses: Authentication Part 3 — Agent Chunk 45c
> Source: 10-authorized-testing-hypotheses.md
> Purpose: Execute structured authentication test hypotheses: PKCE enforcement absence, refresh token rotation, cookie security attributes, and API key scope over-privilege
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Execute each hypothesis: H-AUTH-12 (PKCE not enforced — complete OAuth flow without code_verifier, test if code_challenge is optional), H-AUTH-13 (refresh token rotation absent — reuse refresh tokens after rotation, test if old refresh tokens still work), H-AUTH-14 (cookie security attributes — check Secure, HttpOnly, SameSite, Domain, Path, __Host-/__Secure- prefix), H-AUTH-15 (API key scope over-privilege — test if keys have broader access than documented, try admin endpoints with regular API keys).

---

#### H-AUTH-12: PKCE Enforcement Absence

**Hypothesis**: The OAuth token endpoint may not enforce PKCE (Proof Key for
Code Exchange), making the authorization code flow vulnerable to interception.

**Risk level of test**: LOW -- tests token endpoint behavior.

**Prerequisites**:
- OAuth authorization and token endpoints in scope
- Understanding of the OAuth flow in use

**Test procedure**:

1. Initiate a normal OAuth authorization flow WITH PKCE:
   - Generate `code_verifier` and `code_challenge`
   - Include `code_challenge` and `code_challenge_method` in the auth request
   - Complete authentication and capture the authorization code

2. Exchange the code at the token endpoint WITHOUT the `code_verifier`:
   - Send the token request with the authorization code but omit
     `code_verifier`
   - If the token is issued, PKCE is not enforced

3. Also test:
   - Authorization request without `code_challenge` -- does the server
     require it?
   - Token exchange with an incorrect `code_verifier`
   - Token exchange with `code_verifier` for a different `code_challenge`

**Expected results**:
- **Vulnerable**: Token issued without `code_verifier`, or authorization
  granted without `code_challenge`.
- **Not vulnerable**: Token endpoint rejects requests missing or with
  incorrect `code_verifier`. Authorization endpoint requires `code_challenge`.

**Evidence collection**:
- Request/response pairs for each test variation
- Whether PKCE is required or optional
- Whether `code_challenge_method` S256 is enforced (plain should be rejected)

---

#### H-AUTH-13: Refresh Token Rotation Absence

**Hypothesis**: Refresh tokens may not be rotated on use, allowing indefinite
reuse of a stolen refresh token.

**Risk level of test**: LOW -- tests token refresh behavior on test accounts.

**Prerequisites**:
- Test account with OAuth refresh token
- Understanding of the refresh flow

**Test procedure**:

1. Authenticate and capture the refresh token (RT1).

2. Use RT1 to request a new access token. Capture the response, including
   any new refresh token (RT2).

3. Attempt to use RT1 again:
   - If it works, refresh tokens are not being rotated.
   - If it fails, rotation is in place.

4. If rotation is in place, verify detection:
   - Use RT2 to get RT3.
   - Attempt to use RT1 or RT2 again.
   - Check if the entire token family is revoked (the preferred behavior
     when a rotated token is reused, indicating theft).

**Expected results**:
- **Vulnerable**: Refresh tokens are reusable indefinitely. No rotation occurs.
- **Partially vulnerable**: Rotation occurs but old tokens are not revoked,
  or reuse of old tokens does not trigger family revocation.
- **Not vulnerable**: Refresh tokens are single-use, rotated on each refresh,
  and reuse of an old token revokes the entire family.

**Evidence collection**:
- Token exchange sequence showing rotation (or lack thereof)
- Behavior when an old refresh token is reused
- Whether token family revocation is triggered

---

#### H-AUTH-14: Cookie Security Attribute Deficiency

**Hypothesis**: Session cookies may lack essential security attributes (Secure,
HttpOnly, SameSite), weakening session security.

**Risk level of test**: NONE -- passive analysis of response headers.

**Prerequisites**:
- Endpoint that sets session cookies

**Test procedure**:

1. Authenticate with a test account and capture the `Set-Cookie` response
   headers.

2. For each session-related cookie, check for:
   - **Secure flag**: Must be present. Without it, the cookie is sent over
     unencrypted HTTP.
   - **HttpOnly flag**: Must be present for session tokens. Without it,
     JavaScript can read the cookie (XSS risk).
   - **SameSite attribute**: Should be `Strict` or `Lax`. `None` requires
     `Secure` and enables cross-site sending.
   - **Domain scope**: Should be as narrow as possible. A cookie scoped to
     `.example.com` is sent to all subdomains.
   - **Path scope**: Should be as narrow as possible.
   - **Expires/Max-Age**: Session cookies should not have excessively long
     lifetimes. Check for cookies that persist for months or years.

3. If the `Secure` flag is missing, verify by making an HTTP (non-HTTPS)
   request to the same endpoint and checking if the cookie is sent.

**Expected results**:
- **Vulnerable**: Session cookies missing `Secure`, `HttpOnly`, or have
  `SameSite=None` without justification, or excessively broad domain scope.
- **Not vulnerable**: All session cookies have `Secure`, `HttpOnly`, and
  appropriate `SameSite` setting with narrow scope.

**Evidence collection**:
- Full `Set-Cookie` header for each session cookie
- Analysis of each security attribute
- Cookie lifetime (expires/max-age value)

---

#### H-AUTH-15: API Key Scope Over-Privilege

**Hypothesis**: API keys may have broader permissions than necessary for their
intended use, violating the principle of least privilege.

**Risk level of test**: LOW -- tests API key capabilities with authorized keys.

**Prerequisites**:
- API keys provisioned for specific purposes (e.g., read-only, specific service)
- Documentation of intended key permissions

**Test procedure**:

1. For each provisioned API key, document its intended purpose and expected
   permission scope.

2. Systematically test the key against endpoints outside its intended scope:
   - A "read-only" key should not be able to POST/PUT/DELETE.
   - A key scoped to "users" should not access "billing" endpoints.
   - A key intended for a specific environment should not work in other
     environments.

3. Record which endpoints accept the key and what operations succeed.

4. Compare actual permissions with documented/intended permissions.

**Expected results**:
- **Vulnerable**: API key has permissions beyond its intended scope. A
  read-only key can write, or a service-specific key accesses other services.
- **Not vulnerable**: API key permissions exactly match documented scope.
  All out-of-scope operations are rejected with 403.

**Evidence collection**:
- Key's intended scope (from documentation or client)
- Table of endpoints tested and whether access was granted
- Specific out-of-scope operations that succeeded

---

