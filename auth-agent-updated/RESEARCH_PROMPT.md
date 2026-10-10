# Authentication & Authorization Vulnerability Deep Research Directive

## Mission
You are a security research agent tasked with building a comprehensive knowledge base on Authentication and Authorization vulnerabilities. This intelligence will power an automated security testing agent that understands ALL authentication mechanisms, their weaknesses, bypass techniques, and exploitation methods.

## Why This Agent is Foundational
Authentication testing is prerequisite for:
- IDOR testing (requires authenticated sessions)
- Privilege escalation (requires understanding roles/permissions)
- Session attacks (requires understanding session management)
- API security (requires understanding token-based auth)
- Business logic testing (requires multi-user context)

## Research Execution Mode
- Execute research systematically, section by section
- Save all findings to the `/knowledge-base` directory
- Use web search extensively for real-world data
- Cross-reference multiple sources for accuracy
- Include source URLs for all claims

---

# PHASE 1: AUTHENTICATION MECHANISMS TAXONOMY

## Task 1.1: Authentication Methods Overview
Research and document in `knowledge-base/01-auth-mechanisms.md`:

### Traditional Authentication
- Username/Password authentication
- Form-based authentication
- HTTP Basic Authentication
- HTTP Digest Authentication
- NTLM Authentication
- Kerberos Authentication

### Token-Based Authentication
- Session tokens (cookies)
- JWT (JSON Web Tokens)
- API Keys
- Bearer tokens
- Refresh tokens
- Access tokens

### Modern Authentication Protocols
- OAuth 2.0 (all grant types)
  - Authorization Code
  - Implicit
  - Client Credentials
  - Resource Owner Password
  - Device Code
  - PKCE extension
- OpenID Connect (OIDC)
- SAML 2.0
- WS-Federation

### Single Sign-On (SSO)
- Enterprise SSO mechanisms
- Social login (Google, Facebook, Apple, Microsoft)
- Federated identity
- Identity providers (IdP)
- Service providers (SP)

### Multi-Factor Authentication (MFA)
- SMS/Voice OTP
- TOTP (Time-based One-Time Password)
- HOTP (HMAC-based One-Time Password)
- Push notifications
- Hardware tokens (YubiKey, RSA)
- Biometrics
- Email-based verification
- Magic links
- Passkeys/WebAuthn/FIDO2

### Passwordless Authentication
- Magic links
- Biometric authentication
- Hardware security keys
- Certificate-based authentication
- Smart cards

### API Authentication
- API Keys (header, query, body)
- HMAC signatures
- Mutual TLS (mTLS)
- OAuth 2.0 for APIs
- JWT Bearer tokens

## Task 1.2: Session Management Mechanisms
Document in `knowledge-base/02-session-management.md`:

### Session Types
- Server-side sessions
- Client-side sessions (stateless)
- Hybrid approaches
- Distributed session stores

### Session Storage
- Cookie-based sessions
- LocalStorage/SessionStorage
- IndexedDB
- Memory-based tokens

### Session Attributes
- Session ID generation
- Session timeout (idle/absolute)
- Session renewal/rotation
- Secure cookie attributes (HttpOnly, Secure, SameSite)
- Domain and path scoping

### Session Lifecycle
- Session creation
- Session validation
- Session refresh
- Session termination
- Concurrent session handling

---

# PHASE 2: AUTHENTICATION VULNERABILITIES

## Task 2.1: Credential-Based Attacks
Document in `knowledge-base/03-credential-attacks.md`:

### Brute Force Attacks
- Online brute force
- Offline brute force
- Distributed brute force
- Credential stuffing
- Password spraying
- Reverse brute force (fixed password, multiple users)
- Rate limiting bypass techniques

### Password Vulnerabilities
- Weak password policies
- Default credentials
- Hardcoded credentials
- Password in URL/logs
- Password autocomplete issues
- Password reset poisoning

### Username Enumeration
- Login error message differences
- Registration endpoint enumeration
- Password reset enumeration
- Timing-based enumeration
- Response size differences
- API endpoint enumeration

### Credential Storage Issues
- Plaintext password storage
- Weak hashing algorithms (MD5, SHA1)
- Missing salt
- Insufficient iterations
- Reversible encryption

## Task 2.2: Authentication Bypass Techniques
Document in `knowledge-base/04-auth-bypass.md`:

### Direct Bypass Methods
- SQL injection in login
- NoSQL injection in login
- LDAP injection
- XML injection (XXE in SAML)
- Type juggling (PHP loose comparison)
- Mass assignment in registration
- Parameter manipulation

### Logic-Based Bypasses
- Forced browsing
- Direct object access
- Response manipulation
- Status code manipulation
- Multi-step authentication bypass
- Race conditions in auth
- Null/empty value injection

### Token-Based Bypasses
- Token prediction
- Token fixation
- Token leakage
- Token replay
- Insufficient token entropy
- Token in URL exposure

### Protocol-Level Bypasses
- HTTP verb tampering
- Host header manipulation
- Referer header bypass
- X-Forwarded-For manipulation
- HTTP request smuggling

## Task 2.3: Session Attacks
Document in `knowledge-base/05-session-attacks.md`:

### Session Hijacking
- Session token theft (XSS)
- Session sniffing (MITM)
- Session prediction
- Session brute forcing
- Cookie theft vectors

### Session Fixation
- Pre-authentication fixation
- Cookie injection
- Session adoption
- Meta tag injection
- Link-based fixation

### Session Management Flaws
- Missing session invalidation on logout
- Missing session invalidation on password change
- Concurrent session issues
- Session timeout issues
- Cross-site session usage
- Insecure session transmission

### Cookie Attacks
- Cookie manipulation
- Cookie injection
- Cookie overflow
- Subdomain cookie leakage
- Cookie tossing

---

# PHASE 3: TOKEN-BASED AUTHENTICATION ATTACKS

## Task 3.1: JWT Vulnerabilities
Document in `knowledge-base/06-jwt-attacks.md`:

### Signature Attacks
- Algorithm confusion (RS256 to HS256)
- Algorithm none attack
- Key confusion attacks
- Weak signing keys
- Key injection via JKU/X5U
- Kid parameter injection

### Claim Manipulation
- Expiration bypass (exp claim)
- Not-before bypass (nbf claim)
- Issuer manipulation (iss claim)
- Audience manipulation (aud claim)
- Subject manipulation (sub claim)
- Role/privilege claim tampering

### Implementation Flaws
- Missing signature verification
- Signature stripping
- Token replay
- Insufficient token entropy
- Sensitive data in payload
- Token stored insecurely

### Advanced JWT Attacks
- CVE-2022-21449 (Java ECDSA)
- JWK Set injection
- Cross-service JWT relay
- Embedded JWK attacks

## Task 3.2: OAuth 2.0 Vulnerabilities
Document in `knowledge-base/07-oauth-attacks.md`:

### Authorization Code Flow Attacks
- Authorization code injection
- Code replay attacks
- CSRF in OAuth flow
- Open redirect via redirect_uri
- Redirect URI validation bypass
- State parameter manipulation

### Implicit Flow Attacks
- Token leakage via referrer
- Token in browser history
- Access token theft
- Fragment handling issues

### Client Credential Attacks
- Client secret exposure
- Client impersonation
- Confidential client bypass

### Token Attacks
- Access token leakage
- Refresh token theft
- Token scope manipulation
- Token substitution
- Cross-site token usage

### PKCE Bypass
- Missing PKCE enforcement
- Code verifier prediction
- Downgrade attacks

## Task 3.3: SAML Vulnerabilities
Document in `knowledge-base/08-saml-attacks.md`:

### Signature Attacks
- XML Signature Wrapping (XSW)
- Missing signature validation
- Signature exclusion
- Certificate spoofing
- Signature algorithm downgrade

### Assertion Attacks
- Assertion replay
- Assertion manipulation
- Recipient manipulation
- Audience manipulation
- NotBefore/NotOnOrAfter bypass

### XML-Based Attacks
- XXE in SAML
- XSLT injection
- XPath injection
- Entity expansion (Billion Laughs)

### Protocol Attacks
- IdP confusion
- SP confusion
- Relay state manipulation
- Assertion consumer service bypass

## Task 3.4: API Key & Token Vulnerabilities
Document in `knowledge-base/09-api-auth-attacks.md`:

### API Key Issues
- Key exposure in client-side code
- Key in URL/logs
- Key in version control
- Insufficient key rotation
- Overly permissive key scope
- Missing key validation

### Bearer Token Attacks
- Token leakage
- Insufficient token entropy
- Missing token expiration
- Token scope confusion
- Cross-API token usage

### HMAC Signature Attacks
- Timing attacks
- Key recovery
- Replay attacks
- Signature bypass

---

# PHASE 4: MULTI-FACTOR AUTHENTICATION BYPASSES

## Task 4.1: MFA Bypass Techniques
Document in `knowledge-base/10-mfa-bypass.md`:

### Direct Bypass Methods
- Direct request to authenticated endpoint
- Step skipping in MFA flow
- Response manipulation
- Forced browsing past MFA

### OTP Attacks
- OTP brute force
- OTP rate limiting bypass
- OTP reuse
- OTP leakage in response
- OTP timing attacks
- OTP generation weakness

### SMS-Based MFA Attacks
- SIM swapping
- SS7 attacks
- SMS interception
- Voicemail exploitation
- Phone number manipulation

### Recovery/Fallback Attacks
- Backup code brute force
- Recovery email takeover
- Security question bypass
- Support-based social engineering
- Fallback method exploitation

### Token/Device Attacks
- Session cookie reuse post-MFA
- Remember device token manipulation
- Device fingerprint bypass
- Trusted device exploitation

### Protocol-Level Bypasses
- OAuth state manipulation
- SAML assertion injection
- Session fixation post-MFA
- Race conditions

## Task 4.2: Passkey/WebAuthn Attacks
Document in `knowledge-base/11-webauthn-attacks.md`:

### Implementation Flaws
- Challenge prediction
- Origin validation bypass
- RP ID manipulation
- Counter validation issues
- Attestation bypass

### Credential Attacks
- Credential ID enumeration
- Cross-origin credential usage
- Authenticator cloning

### Fallback Exploitation
- Password fallback after WebAuthn
- Recovery mechanism weaknesses
- Downgrade to weaker method

---

# PHASE 5: AUTHORIZATION VULNERABILITIES

## Task 5.1: Access Control Flaws
Document in `knowledge-base/12-access-control.md`:

### Horizontal Privilege Escalation
- IDOR (cross-reference IDOR agent)
- Parameter manipulation
- Cookie/session manipulation
- API access control bypass

### Vertical Privilege Escalation
- Role manipulation
- Admin function access
- Privilege parameter injection
- Missing function-level access control

### Context-Based Access Control
- Time-based access bypass
- Location-based access bypass
- IP-based access bypass
- Device-based access bypass

### Access Control Models
- RBAC (Role-Based) flaws
- ABAC (Attribute-Based) flaws
- DAC (Discretionary) issues
- MAC (Mandatory) bypass

## Task 5.2: Permission & Role Vulnerabilities
Document in `knowledge-base/13-permission-attacks.md`:

### Role Manipulation
- Role parameter tampering
- Hidden role discovery
- Role hierarchy bypass
- Default role exploitation

### Permission Bypass
- Missing permission checks
- Client-side permission enforcement
- Permission caching issues
- Inherited permission issues

### Multi-Tenancy Issues
- Tenant isolation bypass
- Cross-tenant data access
- Shared resource exploitation
- Tenant ID manipulation

---

# PHASE 6: PASSWORD RESET & ACCOUNT RECOVERY

## Task 6.1: Password Reset Vulnerabilities
Document in `knowledge-base/14-password-reset.md`:

### Token-Based Attacks
- Reset token prediction
- Token brute force
- Token leakage (referrer, logs)
- Token reuse
- Expired token acceptance
- Token in URL issues

### Flow-Based Attacks
- Host header poisoning
- Email parameter manipulation
- Username/email manipulation
- Response manipulation
- Race conditions

### Verification Bypass
- OTP bypass in reset
- Security question bypass
- Email verification bypass
- Phone verification bypass

## Task 6.2: Account Recovery Attacks
Document in `knowledge-base/15-account-recovery.md`:

### Recovery Mechanism Flaws
- Security question weaknesses
- Recovery email takeover
- Phone-based recovery bypass
- Identity verification bypass
- Support channel exploitation

### Account Takeover Chains
- Combining vulnerabilities
- Social engineering + technical
- Third-party compromise
- Credential recovery enumeration

---

# PHASE 7: REGISTRATION & ACCOUNT CREATION

## Task 7.1: Registration Vulnerabilities
Document in `knowledge-base/16-registration-attacks.md`:

### Input Manipulation
- Duplicate account creation
- Email manipulation (case, dots, plus)
- Username squatting
- Mass assignment in registration
- Hidden parameter injection

### Verification Bypass
- Email verification bypass
- Phone verification bypass
- CAPTCHA bypass
- Rate limiting bypass

### Logic Flaws
- Referral system abuse
- Invitation token manipulation
- Pre-registration account claim
- Orphaned account takeover

## Task 7.2: Account Enumeration
Document in `knowledge-base/17-enumeration.md`:

### Enumeration Vectors
- Login endpoint
- Registration endpoint
- Password reset endpoint
- API endpoints
- Error message analysis
- Timing analysis
- Response size analysis

### Prevention Bypass
- Rate limit bypass
- CAPTCHA bypass
- Distributed enumeration
- Timing attack refinement

---

# PHASE 8: TECHNOLOGY-SPECIFIC AUTH ATTACKS

## Task 8.1: Framework-Specific Vulnerabilities
Document in `knowledge-base/18-framework-auth.md`:

### PHP Frameworks
- Laravel auth bypass
- Symfony security issues
- CodeIgniter session flaws
- PHP type juggling in auth

### Python Frameworks
- Django auth vulnerabilities
- Flask-Login issues
- FastAPI auth patterns

### Java Frameworks
- Spring Security bypass
- Java JWT library flaws
- Struts authentication issues

### JavaScript Frameworks
- Express session issues
- Passport.js vulnerabilities
- NextAuth.js flaws

### .NET Framework
- ASP.NET Identity issues
- Windows Authentication bypass
- Forms Authentication flaws

## Task 8.2: Cloud Platform Auth
Document in `knowledge-base/19-cloud-auth.md`:

### AWS Authentication
- IAM credential exposure
- Cognito misconfiguration
- STS token issues
- Cross-account access

### Azure Authentication
- Azure AD misconfiguration
- Managed identity abuse
- Service principal issues
- Conditional Access bypass

### GCP Authentication
- Service account exposure
- Workload identity issues
- OAuth consent screen abuse

### Firebase Authentication
- Firebase auth bypass
- Custom token issues
- Anonymous auth escalation

## Task 8.3: Mobile Authentication
Document in `knowledge-base/20-mobile-auth.md`:

### Mobile-Specific Issues
- Insecure token storage
- Certificate pinning bypass
- Biometric bypass
- Deep link hijacking
- Intent manipulation (Android)
- URL scheme hijacking (iOS)

### Mobile API Auth
- API key extraction
- Token extraction from apps
- Traffic interception
- Frida/Objection techniques

---

# PHASE 9: TOOLING INTELLIGENCE

## Task 9.1: Authentication Testing Tools
Document in `knowledge-base/21-tools.md`:

### Brute Force Tools
- Hydra configuration and usage
- Medusa commands
- Burp Intruder patterns
- Custom Python scripts

### Token Analysis Tools
- jwt_tool commands
- JWT Editor (Burp)
- SAML Raider (Burp)
- OAuth testing tools

### Session Analysis
- Cookie Manager
- Session handling in Burp
- Autorize for auth testing
- AuthMatrix configuration

### Automated Scanners
- Nuclei auth templates
- OWASP ZAP auth context
- Burp active scan config
- Custom auth testing scripts

## Task 9.2: Automation Scripts
Create in `tools/` directory:
- `auth-tester.py` - Python authentication testing framework
- `jwt-attacks.sh` - JWT attack automation
- `session-analyzer.py` - Session security analyzer
- `enum-users.py` - User enumeration script

## Task 9.3: Wordlists & Payloads
Create in `payloads/` directory:
- `default-credentials.txt` - Common default creds
- `auth-bypass-payloads.txt` - Authentication bypass payloads
- `jwt-secrets.txt` - Common JWT signing keys
- `mfa-bypass-payloads.txt` - MFA bypass payloads
- `oauth-redirect-payloads.txt` - OAuth redirect manipulation

---

# PHASE 10: REAL-WORLD INTELLIGENCE

## Task 10.1: Bug Bounty Case Studies
Document in `knowledge-base/22-case-studies.md`:

Search and document:
- HackerOne authentication bypasses
- Bugcrowd auth vulnerabilities
- High-impact auth bugs ($10k+)
- OAuth/SAML bypass writeups
- JWT attack case studies
- MFA bypass real cases

## Task 10.2: CVE Analysis
Document in `knowledge-base/23-cve-analysis.md`:

Research notable CVEs:
- Authentication bypass CVEs
- JWT library CVEs
- OAuth implementation CVEs
- Session management CVEs
- SSO vulnerabilities

## Task 10.3: Data Breach Analysis
Document in `knowledge-base/24-breach-analysis.md`:

- Credential-related breaches
- Session hijacking incidents
- OAuth token leaks
- API key exposures
- Regulatory implications

---

# PHASE 11: AGENT CREATION

## Task 11.1: Testing Methodology
Create in `agent/methodology.md`:

Comprehensive methodology:
1. Reconnaissance & fingerprinting
2. Authentication mechanism identification
3. Session management analysis
4. Token analysis (JWT/OAuth/SAML)
5. MFA assessment
6. Authorization testing
7. Password reset evaluation
8. Registration security
9. Account enumeration
10. Exploitation & chaining
11. Impact assessment
12. Reporting

## Task 11.2: Agent Decision Logic
Create in `agent/auth-agent-logic.md`:

Decision trees for:
- Auth mechanism identification
- Attack selection based on mechanism
- Bypass technique prioritization
- Token attack workflow
- MFA bypass decision tree
- Escalation paths

## Task 11.3: Final Agent Prompt
Create in `agent/AUTH_AGENT_PROMPT.md`:

Production-ready agent prompt synthesizing:
- All knowledge base content
- Decision logic
- Payload libraries
- Tool integration
- Reporting templates

---

# OUTPUT FORMAT REQUIREMENTS

For each knowledge base file:

```markdown
# [Topic Title]

## Overview
[Brief description]

## Technical Details
[Precise, actionable information]

## Attack Vectors
[Specific attack techniques]

## Code Examples
[Vulnerable code and exploit code]

## Tool Commands
[Exact commands with parameters]

## Testing Steps
[Step-by-step procedures]

## Payloads
[Ready-to-use test payloads]

## Detection Signatures
[Patterns for identification]

## References
- [Source 1 URL]
- [Source 2 URL]
```

---

# EXECUTION COMMANDS

```bash
# Start Phase 1
"Begin PHASE 1: Research authentication mechanisms taxonomy"

# Continue to next phase
"Proceed to PHASE 2: Authentication vulnerabilities"

# Generate specific section
"Research and document Task 3.1: JWT Vulnerabilities"

# Compile final agent
"Using all knowledge-base files, create the final AUTH testing agent prompt"
```

---

# INTEGRATION WITH OTHER AGENTS

This Authentication Agent provides foundational knowledge for:

| Agent | Integration Point |
|-------|-------------------|
| IDOR Agent | Session tokens, user context |
| Privilege Escalation Agent | Authorization knowledge |
| API Security Agent | Token authentication |
| Business Logic Agent | Multi-user scenarios |
| Session Attacks Agent | Session management |

The AUTH agent should be executed FIRST and referenced by other vulnerability agents.
