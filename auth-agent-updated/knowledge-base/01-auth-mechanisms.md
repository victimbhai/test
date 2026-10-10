# Authentication Mechanisms Taxonomy

## Overview

Authentication is the process of verifying the identity of a user, system, or entity attempting to access a resource. This document provides a comprehensive taxonomy of authentication mechanisms used in modern applications, covering traditional methods, token-based systems, modern protocols, single sign-on solutions, multi-factor authentication, passwordless approaches, and API authentication.

Understanding these mechanisms is critical for security professionals conducting authentication bypass testing, vulnerability assessments, and penetration testing engagements.

---

## 1. Traditional Authentication Methods

### 1.1 Username/Password Authentication

**Description:** The most common and oldest form of authentication where users provide a unique identifier (username) and a secret (password).

**Technical Details:**
- Credentials are typically submitted via HTML forms over HTTPS
- Server validates credentials against stored hashes in a database
- Password hashing algorithms: bcrypt, Argon2, scrypt, PBKDF2

**Security Considerations:**
- Vulnerable to brute force attacks without rate limiting
- Credential stuffing from breached databases
- Phishing attacks for credential harvesting
- Password spraying attacks
- Rainbow table attacks if weak hashing is used

**Code Example (Password Hashing with bcrypt):**
```python
import bcrypt

# Hashing a password
password = b"user_password"
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password, salt)

# Verifying a password
if bcrypt.checkpw(password, hashed):
    print("Password matches")
```

**References:**
- OWASP Authentication Cheat Sheet
- NIST SP 800-63B Digital Identity Guidelines

---

### 1.2 Form-Based Authentication

**Description:** Authentication mechanism where credentials are submitted through HTML forms, processed server-side, and a session is established upon successful validation.

**Technical Details:**
- POST request with credentials in the request body
- CSRF tokens should be included to prevent cross-site request forgery
- Response typically sets a session cookie

**HTTP Request Example:**
```http
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=user&password=pass123&csrf_token=abc123
```

**Security Considerations:**
- Must use HTTPS to prevent credential interception
- Implement CSRF protection
- Rate limiting to prevent brute force
- Account lockout policies
- Secure password reset mechanisms

---

### 1.3 HTTP Basic Authentication

**Description:** A simple authentication scheme built into the HTTP protocol where credentials are sent as a Base64-encoded string in the Authorization header.

**Technical Details:**
- Credentials format: `username:password` encoded in Base64
- Server responds with `WWW-Authenticate: Basic realm="..."` on 401
- Credentials sent with every request

**HTTP Header Example:**
```http
GET /protected HTTP/1.1
Host: example.com
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
```

**Security Considerations:**
- Base64 is encoding, NOT encryption - easily decoded
- MUST use HTTPS to prevent credential exposure
- No built-in session management
- Credentials cached by browsers
- No logout mechanism (credentials cached until browser closed)

**References:**
- RFC 7617 - The 'Basic' HTTP Authentication Scheme

---

### 1.4 HTTP Digest Authentication

**Description:** An improvement over Basic authentication that uses MD5 hashing and nonce values to avoid sending plaintext passwords.

**Technical Details:**
- Server sends a nonce with the 401 challenge
- Client computes: `MD5(MD5(username:realm:password):nonce:MD5(method:uri))`
- Provides replay protection through nonce

**HTTP Challenge/Response:**
```http
# Server Challenge
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest realm="example.com", nonce="abc123", qop="auth"

# Client Response
Authorization: Digest username="user", realm="example.com",
    nonce="abc123", uri="/protected", response="computed_hash", qop=auth
```

**Security Considerations:**
- Vulnerable to man-in-the-middle attacks without HTTPS
- MD5 is cryptographically weak
- Does not protect password on the server (stored as MD5 hash)
- Largely deprecated in favor of modern alternatives

**References:**
- RFC 7616 - HTTP Digest Access Authentication

---

### 1.5 NTLM Authentication

**Description:** NT LAN Manager is a Microsoft proprietary authentication protocol used primarily in Windows environments for SSO within corporate networks.

**Technical Details:**
- Challenge-response mechanism
- Three-message handshake: Type 1 (Negotiate), Type 2 (Challenge), Type 3 (Authenticate)
- Uses DES/MD4/MD5 based hashing

**Authentication Flow:**
```
1. Client -> Server: NTLMSSP_NEGOTIATE
2. Server -> Client: NTLMSSP_CHALLENGE (with server nonce)
3. Client -> Server: NTLMSSP_AUTH (with encrypted response)
```

**Security Considerations:**
- Vulnerable to pass-the-hash attacks
- Relay attacks (NTLM relay)
- Offline cracking of captured hashes
- Should be disabled in favor of Kerberos where possible
- NTLMv1 is severely broken; NTLMv2 is marginally better

**References:**
- Microsoft NTLM Documentation
- OWASP Testing for NTLM Authentication

---

### 1.6 Kerberos Authentication

**Description:** A network authentication protocol that uses tickets to allow nodes to prove their identity in a secure manner over non-secure networks.

**Technical Details:**
- Three parties: Client, Server, Key Distribution Center (KDC)
- KDC components: Authentication Server (AS) and Ticket Granting Server (TGS)
- Uses symmetric key cryptography (AES)
- Time-sensitive tickets (requires synchronized clocks)

**Authentication Flow:**
```
1. Client -> AS: Request TGT (Ticket Granting Ticket)
2. AS -> Client: TGT (encrypted with client's password hash)
3. Client -> TGS: TGT + Service Request
4. TGS -> Client: Service Ticket
5. Client -> Server: Service Ticket
6. Server -> Client: (Optional) Mutual authentication
```

**Security Considerations:**
- Kerberoasting: Requesting service tickets and cracking offline
- Golden Ticket attacks: Forged TGTs using krbtgt hash
- Silver Ticket attacks: Forged service tickets
- Pass-the-Ticket attacks
- Clock skew attacks
- AS-REP Roasting for accounts without pre-authentication

**References:**
- RFC 4120 - The Kerberos Network Authentication Service (V5)
- Microsoft Kerberos Documentation

---

## 2. Token-Based Authentication

### 2.1 Session Cookies

**Description:** Server-side session management where the server maintains session state and provides the client with a session identifier stored in a cookie.

**Technical Details:**
- Session ID generated server-side upon successful authentication
- Stored in HTTP cookie with security attributes
- Session data stored server-side (memory, database, Redis, etc.)

**Cookie Example:**
```http
Set-Cookie: SESSIONID=abc123xyz789;
    Secure;
    HttpOnly;
    SameSite=Strict;
    Path=/;
    Max-Age=3600
```

**Security Considerations:**
- Session fixation attacks
- Session hijacking through XSS (mitigated by HttpOnly)
- CSRF attacks (mitigated by SameSite)
- Session prediction (weak ID generation)
- Insufficient session expiration

**References:**
- OWASP Session Management Cheat Sheet
- RFC 6265 - HTTP State Management Mechanism

---

### 2.2 JSON Web Tokens (JWT)

**Description:** A compact, URL-safe means of representing claims to be transferred between two parties, commonly used for stateless authentication.

**Technical Details:**
- Three parts: Header, Payload, Signature (Base64URL encoded)
- Format: `xxxxx.yyyyy.zzzzz`
- Algorithms: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, PS256, EdDSA

**JWT Structure:**
```json
// Header
{
  "alg": "RS256",
  "typ": "JWT"
}

// Payload
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "exp": 1516242622,
  "roles": ["user", "admin"]
}

// Signature
RSASHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), privateKey)
```

**Security Considerations:**
- Algorithm confusion attacks (alg: none, RS256 -> HS256)
- Weak secret keys (brute forceable)
- Missing signature verification
- Token not expiring (no exp claim)
- Sensitive data in payload (tokens are only encoded, not encrypted)
- JWK injection attacks
- Kid parameter injection
- Token sidejacking (stolen tokens via XSS)

**Code Example (Verification):**
```python
import jwt

try:
    decoded = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],  # Explicitly specify allowed algorithms
        options={"require": ["exp", "iat", "sub"]}
    )
except jwt.ExpiredSignatureError:
    print("Token has expired")
except jwt.InvalidTokenError:
    print("Invalid token")
```

**References:**
- RFC 7519 - JSON Web Token (JWT)
- RFC 7515 - JSON Web Signature (JWS)
- OWASP JWT Cheat Sheet

---

### 2.3 API Keys

**Description:** A unique identifier used to authenticate a client application to an API service, typically a long random string.

**Technical Details:**
- Usually passed in headers, query parameters, or request body
- Often associated with rate limits and permissions
- May be scoped to specific API endpoints or operations

**Usage Examples:**
```http
# Header-based
GET /api/data HTTP/1.1
X-API-Key: sk_live_abc123xyz789

# Query parameter (less secure)
GET /api/data?api_key=sk_live_abc123xyz789

# Authorization header
Authorization: Api-Key sk_live_abc123xyz789
```

**Security Considerations:**
- Exposure in logs if passed in URL/query parameters
- Lack of expiration (long-lived credentials)
- Difficult to rotate without breaking integrations
- No user context (identifies application, not user)
- Susceptible to leakage in client-side code

**References:**
- OWASP API Security Top 10

---

### 2.4 Bearer Tokens

**Description:** A type of access token that grants access to a protected resource. The bearer (holder) of the token is granted access without further verification.

**Technical Details:**
- Specified in OAuth 2.0 RFC 6750
- Transmitted in Authorization header
- Token format can be opaque or structured (JWT)

**HTTP Header Example:**
```http
GET /api/protected HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Security Considerations:**
- Must use HTTPS (token is bearer credential)
- Token theft leads to account compromise
- No built-in mechanism to verify token holder
- Should implement token binding where possible

**References:**
- RFC 6750 - The OAuth 2.0 Authorization Framework: Bearer Token Usage

---

### 2.5 Refresh Tokens

**Description:** Long-lived tokens used to obtain new access tokens without requiring re-authentication, enabling better security through short-lived access tokens.

**Technical Details:**
- Longer expiration than access tokens (days to months)
- Stored securely (server-side or secure storage)
- Used to request new access tokens from token endpoint
- Often rotated on each use (refresh token rotation)

**Token Refresh Flow:**
```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=def502003a8b...
&client_id=client123
&client_secret=secret456
```

**Security Considerations:**
- Refresh token theft enables persistent access
- Should be bound to client (detect token reuse)
- Implement refresh token rotation
- Store securely (not in localStorage for SPAs)
- Implement refresh token families for reuse detection

**References:**
- RFC 6749 - OAuth 2.0 (Section 6)
- OAuth 2.0 Security Best Current Practice

---

## 3. Modern Authentication Protocols

### 3.1 OAuth 2.0

**Description:** An authorization framework that enables applications to obtain limited access to user accounts on third-party services without exposing credentials.

**Technical Details:**
OAuth 2.0 defines four roles:
- Resource Owner (User)
- Client (Application)
- Authorization Server
- Resource Server

**Grant Types:**

#### 3.1.1 Authorization Code Grant
Most secure grant for server-side applications.
```
1. User -> Client: Initiate login
2. Client -> Auth Server: Authorization request with redirect_uri
3. Auth Server -> User: Login prompt
4. User -> Auth Server: Credentials
5. Auth Server -> Client: Authorization code (via redirect)
6. Client -> Auth Server: Exchange code for tokens (with client_secret)
7. Auth Server -> Client: Access token + Refresh token
```

#### 3.1.2 Authorization Code Grant with PKCE (Proof Key for Code Exchange)
Required for public clients (SPAs, mobile apps).
```python
import hashlib
import base64
import secrets

# Generate code_verifier (43-128 characters)
code_verifier = secrets.token_urlsafe(32)

# Generate code_challenge
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).decode().rstrip('=')

# Authorization request includes code_challenge
# Token request includes code_verifier
```

#### 3.1.3 Client Credentials Grant
Machine-to-machine authentication.
```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=client123
&client_secret=secret456
&scope=read:data
```

#### 3.1.4 Resource Owner Password Credentials (ROPC)
Legacy grant, should be avoided.
```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=password
&username=user@example.com
&password=userpassword
&client_id=client123
```

#### 3.1.5 Device Authorization Grant (Device Code Flow)
For devices with limited input capabilities.
```
1. Device -> Auth Server: Request device code
2. Auth Server -> Device: device_code, user_code, verification_uri
3. User -> Auth Server: Enter user_code at verification_uri
4. Device -> Auth Server: Poll with device_code
5. Auth Server -> Device: Access token (when user approves)
```

#### 3.1.6 Implicit Grant (Deprecated)
Previously used for SPAs, now deprecated in favor of PKCE.

**Security Considerations:**
- Open redirect vulnerabilities in redirect_uri validation
- Authorization code injection
- CSRF on authorization endpoint
- Token leakage in browser history/referer headers
- Scope escalation
- Client impersonation

**References:**
- RFC 6749 - OAuth 2.0 Authorization Framework
- RFC 7636 - PKCE
- RFC 8628 - Device Authorization Grant
- OAuth 2.0 Security Best Current Practice (RFC 9700)

---

### 3.2 OpenID Connect (OIDC)

**Description:** An identity layer built on top of OAuth 2.0 that provides authentication (who the user is) in addition to authorization (what they can access).

**Technical Details:**
- Adds ID Token (JWT) containing user identity claims
- Defines standard scopes: openid, profile, email, address, phone
- Introduces UserInfo endpoint for additional claims
- Supports multiple flows: Authorization Code, Implicit, Hybrid

**ID Token Example:**
```json
{
  "iss": "https://auth.example.com",
  "sub": "user123",
  "aud": "client_id",
  "exp": 1516242622,
  "iat": 1516239022,
  "nonce": "abc123",
  "at_hash": "hash_of_access_token",
  "email": "user@example.com",
  "email_verified": true
}
```

**Discovery and Configuration:**
```http
GET /.well-known/openid-configuration HTTP/1.1
Host: auth.example.com
```

**Security Considerations:**
- ID token validation (signature, claims, nonce)
- Token substitution attacks
- Confused deputy attacks
- Insufficient redirect_uri validation
- Missing state parameter for CSRF protection

**References:**
- OpenID Connect Core 1.0
- OpenID Connect Discovery 1.0

---

### 3.3 SAML 2.0 (Security Assertion Markup Language)

**Description:** An XML-based framework for exchanging authentication and authorization data between an Identity Provider (IdP) and a Service Provider (SP).

**Technical Details:**
- XML-based protocol
- Three main components: Assertions, Protocols, Bindings
- Primary flow: SP-initiated SSO with HTTP POST binding

**SAML Assertion Structure:**
```xml
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <ds:Signature>...</ds:Signature>
  <saml:Subject>
    <saml:NameID>user@example.com</saml:NameID>
  </saml:Subject>
  <saml:Conditions NotBefore="..." NotOnOrAfter="...">
    <saml:AudienceRestriction>
      <saml:Audience>https://sp.example.com</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="...">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>
        urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
      </saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>
    <saml:Attribute Name="email">
      <saml:AttributeValue>user@example.com</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

**Security Considerations:**
- XML Signature Wrapping (XSW) attacks
- XML External Entity (XXE) injection
- Comment injection in NameID
- Missing signature validation
- Certificate validation bypass
- Replay attacks (assertion reuse)
- Signature exclusion attacks

**References:**
- OASIS SAML 2.0 Specifications
- OWASP SAML Security Cheat Sheet

---

### 3.4 WS-Federation

**Description:** A web services security specification that defines mechanisms for federating identity, authentication, and authorization across different security realms.

**Technical Details:**
- Part of the WS-* web services specifications
- Uses Security Token Service (STS)
- Commonly used with ADFS (Active Directory Federation Services)
- Supports SAML tokens and custom token formats

**Authentication Flow:**
```
1. User -> SP: Access resource
2. SP -> User: Redirect to IdP with wtrealm, wreply parameters
3. User -> IdP: Authenticate
4. IdP -> User: Security token (POST to wreply)
5. User -> SP: Submit token
6. SP: Validate token, create session
```

**Security Considerations:**
- Similar to SAML: signature validation, replay attacks
- Token theft and replay
- Realm validation bypass
- Cross-realm escalation

**References:**
- WS-Federation Specification
- Microsoft ADFS Documentation

---

## 4. Single Sign-On (SSO)

### 4.1 Enterprise SSO

**Description:** Centralized authentication service allowing users to access multiple enterprise applications with a single set of credentials.

**Technical Details:**
- Typically implemented with SAML, OIDC, or Kerberos
- Central Identity Provider manages authentication
- Service Providers delegate authentication to IdP
- Session maintained across applications

**Components:**
- Identity Provider (IdP): Okta, Azure AD, Ping Identity, OneLogin
- Service Providers (SP): Enterprise applications
- Directory Services: LDAP, Active Directory

**Security Considerations:**
- IdP compromise affects all connected applications
- Session management across applications
- Single point of failure
- Token propagation security
- Logout propagation (single logout)

---

### 4.2 Social Login

**Description:** Authentication using credentials from social identity providers (Google, Facebook, Apple, etc.).

**Technical Details:**
- Implemented using OAuth 2.0 / OpenID Connect
- Provider-specific SDKs available
- Scope requests vary by provider

**Provider Implementations:**

**Google Sign-In:**
```javascript
// Using Google Identity Services
google.accounts.id.initialize({
  client_id: 'CLIENT_ID.apps.googleusercontent.com',
  callback: handleCredentialResponse
});
```

**Apple Sign-In:**
- Requires supporting email relay for privacy
- Provides unique user ID per app
- Sign in with Apple requirements for App Store apps

**Facebook Login:**
```javascript
FB.login(function(response) {
  if (response.authResponse) {
    // User is logged in
  }
}, {scope: 'email,public_profile'});
```

**Security Considerations:**
- Account takeover via email address changes
- Inconsistent user identifier handling
- Scope creep (requesting unnecessary permissions)
- Token validation requirements
- Account linking vulnerabilities

---

### 4.3 Federated Identity

**Description:** A system where multiple organizations share identity information, allowing users from one domain to access resources in another.

**Technical Details:**
- Trust relationships between identity domains
- Attribute mapping between organizations
- Just-in-time provisioning of users
- SCIM (System for Cross-domain Identity Management) for provisioning

**Components:**
- Identity Provider (IdP): Organization that authenticates users
- Service Provider (SP): Organization providing resources
- Trust Framework: Agreements and technical standards

**Security Considerations:**
- Attribute assertion trust
- Cross-domain privilege escalation
- Orphaned accounts
- Attribute mapping inconsistencies

---

### 4.4 Identity Provider (IdP) and Service Provider (SP)

**Description:** The two main actors in federated identity systems.

**Identity Provider (IdP):**
- Authenticates users
- Issues identity assertions/tokens
- Maintains user credentials and attributes
- Examples: Azure AD, Okta, Auth0, Keycloak

**Service Provider (SP):**
- Relies on IdP for authentication
- Consumes identity assertions/tokens
- Provides access to protected resources
- Implements authorization based on identity claims

**Security Considerations:**
- IdP spoofing
- Assertion/token manipulation
- Man-in-the-middle attacks
- Confused deputy problems
- Insufficient claim validation

---

## 5. Multi-Factor Authentication (MFA)

### 5.1 SMS/Voice OTP

**Description:** One-time passwords delivered via SMS text message or voice call to a registered phone number.

**Technical Details:**
- Typically 4-8 digit codes
- Time-limited validity (30 seconds to 10 minutes)
- Delivered via SMS gateway or voice call
- Fallback option for other MFA methods

**Security Considerations:**
- SIM swapping attacks
- SS7 protocol vulnerabilities
- Social engineering of mobile carriers
- SMS interception
- Phone number recycling
- Considered weakest form of MFA by NIST

**References:**
- NIST SP 800-63B (deprecates SMS for high-assurance scenarios)

---

### 5.2 TOTP (Time-based One-Time Password)

**Description:** Algorithm that generates time-based one-time passwords using a shared secret and current time.

**Technical Details:**
- Based on HMAC-SHA1 (or SHA256/SHA512)
- 30-second time windows (configurable)
- 6-8 digit codes
- Shared secret provisioned via QR code or manual entry

**Algorithm:**
```python
import hmac
import hashlib
import struct
import time

def generate_totp(secret, time_step=30, digits=6):
    # Get current time counter
    counter = int(time.time() // time_step)

    # Generate HMAC
    counter_bytes = struct.pack('>Q', counter)
    hmac_hash = hmac.new(secret, counter_bytes, hashlib.sha1).digest()

    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    code = struct.unpack('>I', hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF

    return str(code % (10 ** digits)).zfill(digits)
```

**Security Considerations:**
- Secret key theft from authenticator app backups
- Time synchronization requirements
- Phishing attacks can capture codes in real-time
- No resistance to real-time MitM attacks

**References:**
- RFC 6238 - TOTP: Time-Based One-Time Password Algorithm

---

### 5.3 HOTP (HMAC-based One-Time Password)

**Description:** Counter-based one-time password algorithm that generates codes based on a shared secret and incrementing counter.

**Technical Details:**
- Based on HMAC-SHA1
- Counter increments with each use
- Requires counter synchronization between client and server
- Used in hardware tokens like RSA SecurID

**Security Considerations:**
- Counter desynchronization
- Look-ahead window requirements
- Counter prediction attacks
- Same phishing vulnerabilities as TOTP

**References:**
- RFC 4226 - HOTP: An HMAC-Based One-Time Password Algorithm

---

### 5.4 Push Notifications

**Description:** Authentication method where a push notification is sent to a registered device, requiring user approval.

**Technical Details:**
- Requires registered mobile application
- Server sends push notification via APNS/FCM
- User approves or denies in app
- May include additional context (location, device, time)

**Security Considerations:**
- Push fatigue/bombing attacks (repeated notifications until user approves)
- Device compromise
- Man-in-the-middle attacks
- Notification spoofing
- Account takeover via device registration

**Mitigation (Number Matching):**
- Display a number on login screen
- User must enter matching number in app
- Prevents blind approval attacks

---

### 5.5 Hardware Tokens

**Description:** Physical devices that generate or store authentication credentials.

**Types:**
- Disconnected tokens: Generate OTP codes (RSA SecurID)
- Connected tokens: USB devices (YubiKey)
- Contactless tokens: NFC-enabled devices
- Smart cards: PKI-based authentication

**Security Considerations:**
- Physical theft
- Supply chain attacks
- Battery life (for OTP generators)
- Cost of deployment and replacement
- User experience friction

---

### 5.6 Biometrics

**Description:** Authentication using unique biological characteristics.

**Types:**
- Fingerprint recognition
- Facial recognition
- Iris/retina scanning
- Voice recognition
- Behavioral biometrics (typing patterns, gait)

**Technical Details:**
- Template stored locally or in secure enclave
- Match-on-device vs. match-on-server
- Liveness detection to prevent spoofing
- False Acceptance Rate (FAR) vs. False Rejection Rate (FRR)

**Security Considerations:**
- Biometrics cannot be changed if compromised
- Spoofing attacks (fake fingerprints, photos, voice recordings)
- Privacy concerns with biometric data storage
- Environmental factors affecting recognition
- Should be used with other factors, not standalone

---

### 5.7 Magic Links

**Description:** Passwordless authentication where a time-limited link is sent to the user's email address.

**Technical Details:**
- Server generates unique, high-entropy token
- Token embedded in URL sent via email
- Link typically valid for 5-30 minutes
- Single-use (invalidated after use)

**Example:**
```
https://example.com/auth/verify?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Security Considerations:**
- Email account compromise
- Link interception
- Token prediction (weak randomness)
- Token reuse if not invalidated
- Phishing attacks with similar domains

---

### 5.8 Passkeys / WebAuthn / FIDO2

**Description:** Modern passwordless authentication standard using public-key cryptography, resistant to phishing and credential theft.

**Technical Details:**

**Architecture:**
- Relying Party (RP): The website/application
- Authenticator: Device that creates/stores credentials (platform or roaming)
- WebAuthn API: Browser JavaScript API
- CTAP2: Protocol for external authenticators

**Registration Flow:**
```javascript
// Create credential (registration)
const credential = await navigator.credentials.create({
  publicKey: {
    challenge: new Uint8Array([/* server challenge */]),
    rp: { name: "Example Corp", id: "example.com" },
    user: {
      id: new Uint8Array([/* user id */]),
      name: "user@example.com",
      displayName: "John Doe"
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },   // ES256
      { type: "public-key", alg: -257 }  // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: "platform",  // or "cross-platform"
      residentKey: "required",  // for discoverable credentials
      userVerification: "required"
    },
    timeout: 60000
  }
});
```

**Authentication Flow:**
```javascript
// Get credential (authentication)
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge: new Uint8Array([/* server challenge */]),
    rpId: "example.com",
    allowCredentials: [{
      type: "public-key",
      id: credentialId,
      transports: ["internal", "usb", "ble", "nfc"]
    }],
    userVerification: "required",
    timeout: 60000
  }
});
```

**Security Advantages:**
- Phishing-resistant (origin bound)
- No shared secrets transmitted
- Replay attack resistant (challenge-response)
- Credentials bound to specific origin
- Supports attestation for device verification

**Security Considerations:**
- Authenticator loss/theft
- Account recovery mechanisms may be weaker
- Platform authenticator tied to device
- Cross-device/account portability challenges
- Attestation privacy concerns

**References:**
- W3C Web Authentication (WebAuthn) Level 2
- FIDO2 Specifications (FIDO Alliance)

---

## 6. Passwordless Authentication

### 6.1 Magic Links (Email-based)

See section 5.7 above for detailed coverage.

**Additional Considerations:**
- User experience dependent on email delivery speed
- Works across devices (opens on any device)
- Requires email account security

---

### 6.2 Biometric Authentication

See section 5.6 above for detailed coverage.

**Additional Passwordless Context:**
- Often combined with device binding
- Platform implementations: Face ID, Touch ID, Windows Hello
- FIDO2/WebAuthn provides standardized framework

---

### 6.3 Hardware Security Keys

**Description:** Physical devices (USB, NFC) that provide cryptographic authentication without passwords.

**Types:**
- FIDO U2F (legacy, second-factor only)
- FIDO2/WebAuthn (passwordless capable)
- PIV/Smart Card

**Popular Devices:**
- YubiKey (Yubico)
- Titan Security Key (Google)
- Feitian keys
- SoloKeys (open source)

**Security Considerations:**
- Physical key management
- Backup key registration
- Organization key policies
- Attestation and supply chain verification

---

### 6.4 Certificate-Based Authentication

**Description:** Authentication using X.509 digital certificates, typically stored on smart cards or in device keystores.

**Technical Details:**
- Public Key Infrastructure (PKI)
- Certificate issued by trusted CA
- Private key stored securely (smart card, TPM, HSM)
- Mutual TLS (mTLS) for authentication

**Certificate Structure:**
```
Certificate:
    Subject: CN=John Doe, O=Example Corp
    Issuer: CN=Example Corp CA
    Validity: Not Before: Jan 1, Not After: Dec 31
    Public Key: RSA 2048-bit
    Extensions:
        Key Usage: Digital Signature, Key Encipherment
        Extended Key Usage: Client Authentication
        Subject Alternative Name: email:john@example.com
```

**Security Considerations:**
- Certificate revocation checking (CRL, OCSP)
- Private key protection
- CA compromise
- Certificate lifecycle management
- Smart card PIN brute force

---

### 6.5 Smart Cards

**Description:** Physical cards containing embedded chips that store cryptographic keys and certificates.

**Technical Details:**
- ISO 7816 standard interface
- PIV (Personal Identity Verification) common in government
- CAC (Common Access Card) for US DoD
- Requires card reader for contact cards
- Contactless variants use NFC (ISO 14443)

**Authentication Flow:**
```
1. Insert smart card into reader
2. Application requests certificate from card
3. Server sends challenge
4. Card signs challenge with private key (requires PIN)
5. Server verifies signature with certificate
```

**Security Considerations:**
- PIN brute force protection
- Card cloning (physical attacks)
- Reader tampering
- Certificate management
- Lost card procedures

---

## 7. API Authentication

### 7.1 API Keys

See section 2.3 for detailed coverage.

**Additional API Context:**
- Often used for rate limiting and usage tracking
- May provide different permission levels (read-only, write)
- Should be rotated regularly
- Environment-specific keys (development, staging, production)

---

### 7.2 HMAC Signatures

**Description:** Request signing using HMAC (Hash-based Message Authentication Code) to ensure request integrity and authenticity.

**Technical Details:**
- Shared secret between client and server
- Signature computed over request components
- Timestamp included to prevent replay attacks
- Common algorithms: HMAC-SHA256, HMAC-SHA512

**Example Implementation (AWS Signature V4 style):**
```python
import hmac
import hashlib
from datetime import datetime

def sign_request(method, path, headers, body, secret_key):
    timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

    # Create canonical request
    canonical_request = f"{method}\n{path}\n{headers}\n{hashlib.sha256(body).hexdigest()}"

    # Create string to sign
    string_to_sign = f"HMAC-SHA256\n{timestamp}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"

    # Calculate signature
    signature = hmac.new(
        secret_key.encode(),
        string_to_sign.encode(),
        hashlib.sha256
    ).hexdigest()

    return signature, timestamp
```

**HTTP Header Example:**
```http
POST /api/resource HTTP/1.1
Host: api.example.com
X-Timestamp: 20250130T120000Z
Authorization: HMAC-SHA256 Credential=key_id, Signature=abc123...
```

**Security Considerations:**
- Clock skew tolerance (typically 5-15 minutes)
- Replay attacks within time window
- Secret key management
- Signature scope (what's included in signature)
- Canonicalization issues

**References:**
- AWS Signature Version 4

---

### 7.3 Mutual TLS (mTLS)

**Description:** Two-way TLS authentication where both client and server present certificates to verify each other's identity.

**Technical Details:**
- Server presents certificate (standard TLS)
- Client also presents certificate
- Both parties verify certificate chain
- Common in zero-trust and service mesh architectures

**Configuration (nginx example):**
```nginx
server {
    listen 443 ssl;

    ssl_certificate /etc/ssl/server.crt;
    ssl_certificate_key /etc/ssl/server.key;

    ssl_client_certificate /etc/ssl/ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;

    location / {
        proxy_set_header X-Client-Cert $ssl_client_s_dn;
        proxy_pass http://backend;
    }
}
```

**Security Considerations:**
- Certificate management complexity
- Certificate revocation checking
- Certificate pinning considerations
- Performance overhead
- Debugging/troubleshooting complexity

**Use Cases:**
- Service-to-service authentication (microservices)
- API gateway authentication
- Zero-trust network architecture
- Financial services / high-security environments

---

### 7.4 OAuth 2.0 for APIs

**Description:** Using OAuth 2.0 access tokens for API authentication, typically with the Client Credentials grant or as a delegated authorization mechanism.

**Technical Details:**

**Client Credentials Flow (Machine-to-Machine):**
```http
POST /oauth/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=service_account
&client_secret=secret
&scope=api:read api:write
```

**Token Introspection (RFC 7662):**
```http
POST /oauth/introspect HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response:**
```json
{
  "active": true,
  "scope": "api:read api:write",
  "client_id": "service_account",
  "exp": 1516242622,
  "iat": 1516239022
}
```

**Security Considerations:**
- Token storage and transmission
- Scope management and enforcement
- Token lifetime and rotation
- Audience validation
- Token binding

**References:**
- RFC 6749 - OAuth 2.0
- RFC 7662 - OAuth 2.0 Token Introspection
- RFC 8693 - OAuth 2.0 Token Exchange

---

## Security Testing Checklist

### Authentication Testing Points:
1. **Credential Handling**
   - Password complexity enforcement
   - Secure password storage (hashing)
   - Credential transmission security

2. **Session Management**
   - Session ID entropy
   - Session fixation
   - Session timeout

3. **Token Security**
   - Algorithm validation (JWT)
   - Signature verification
   - Token expiration

4. **MFA Implementation**
   - Bypass possibilities
   - Rate limiting on OTP
   - Backup codes security

5. **Protocol Implementation**
   - OAuth redirect_uri validation
   - SAML signature verification
   - OIDC claim validation

6. **Account Security**
   - Account enumeration
   - Password reset flow
   - Account lockout

---

## References

### Standards and Specifications
- RFC 6749 - OAuth 2.0 Authorization Framework
- RFC 7519 - JSON Web Token (JWT)
- RFC 7617 - HTTP Basic Authentication
- RFC 7616 - HTTP Digest Authentication
- RFC 4120 - Kerberos V5
- RFC 6238 - TOTP
- RFC 4226 - HOTP
- RFC 7636 - PKCE
- W3C WebAuthn Level 2
- FIDO2 Specifications
- OASIS SAML 2.0
- OpenID Connect Core 1.0

### Security Guidelines
- OWASP Authentication Cheat Sheet
- OWASP Session Management Cheat Sheet
- OWASP Testing Guide - Authentication
- NIST SP 800-63B Digital Identity Guidelines
- CIS Controls for Authentication

### Security Research
- PortSwigger Web Security Academy - Authentication
- OWASP API Security Top 10
- OAuth 2.0 Security Best Current Practice (RFC 9700)
