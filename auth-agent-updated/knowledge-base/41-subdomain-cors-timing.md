# KB-41: Subdomain Takeover, CORS & Timing Side-Channel Auth Attacks

## Overview

Subdomain takeover for auth token theft, CORS misconfiguration for credential exfiltration, and timing side-channel attacks on auth tokens.

---

## 1. Subdomain Takeover for Auth Token Theft

### 1.1 Finding Dangling Subdomains

```bash
# Enumerate subdomains and check for dangling CNAME records
# Claimable services: Heroku, Azure, CloudFront, S3, GitHub Pages, Netlify, Vercel

# If cookie scope is .target.com, taken-over subdomain steals all cookies
# Enables: session theft, CSRF, OAuth redirect abuse
```

### 1.2 Cookie Scope Exploitation

After claiming a dangling subdomain:
- Cookies scoped to `.target.com` are sent to the subdomain automatically
- Session cookies, CSRF tokens, auth tokens become accessible
- Can also SET cookies for the parent domain (session fixation)
- If subdomain is in CORS allowlist, credential theft via XHR

---

## 2. CORS Misconfiguration for Auth Credential Theft

### 2.1 Test Matrix

| Origin Tested | Vulnerable If Reflected |
|---------------|------------------------|
| `https://evil.com` | Origin reflection without allowlist |
| `https://evil.target.com` | Suffix matching only |
| `https://target.com.evil.com` | Prefix matching only |
| `null` | Null origin trusted |
| Subdomain of target | Subdomain trust too broad |

### 2.2 Testing Approach

```
For each API endpoint that returns sensitive data:
1. Send request with Origin: https://evil.com
2. Check if Access-Control-Allow-Origin reflects it
3. Check if Access-Control-Allow-Credentials: true
4. If both: CRITICAL - credentials sent cross-origin
```

---

## 3. Timing Side-Channel Auth Attacks

### 3.1 Username Enumeration via Timing

Valid users trigger password hash comparison (slow bcrypt/scrypt).
Invalid users return immediately. Measure response time difference.

### 3.2 Token Comparison Timing

If token comparison is not constant-time, correct bytes take longer.
Byte-by-byte recovery of reset tokens, API keys, session IDs.

### 3.3 MFA Code Timing

Some implementations compare MFA codes character-by-character.
Timing differences reveal correct digits progressively.

---

## 4. mTLS Bypass Techniques

### 4.1 Common Bypass Vectors

| Technique | Description |
|-----------|-------------|
| No enforcement | Server doesn't require client cert |
| Self-signed accepted | No CA validation |
| CN-based authz | Authorization based on CN field alone |
| Proxy termination | mTLS terminated at proxy, backend trusts headers |
| Cert expiry not checked | Expired certs still accepted |

## References

- Subdomain Takeover (can-i-take-over-xyz project)
- CORS Misconfiguration (PortSwigger research)
- Timing Side-Channel Attacks on Web Applications
- mTLS Security Best Practices
