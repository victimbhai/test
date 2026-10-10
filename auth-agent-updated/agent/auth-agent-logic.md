# Authentication Agent Decision Logic

## Overview

This document defines the comprehensive decision-making logic for the Authentication & Authorization Security Testing Agent. It provides systematic workflows for identifying authentication mechanisms, selecting appropriate attacks, prioritizing bypass techniques, and filtering false positives.

---

## Table of Contents

1. [Authentication Mechanism Identification](#1-authentication-mechanism-identification)
2. [Attack Selection Decision Trees](#2-attack-selection-decision-trees)
3. [Bypass Technique Prioritization](#3-bypass-technique-prioritization)
4. [Token Attack Workflow](#4-token-attack-workflow)
5. [MFA Bypass Decision Tree](#5-mfa-bypass-decision-tree)
6. [Escalation Paths](#6-escalation-paths)
7. [False Positive Filtering](#7-false-positive-filtering)
8. [Priority Scoring System](#8-priority-scoring-system)
9. [Python Detection Logic](#9-python-detection-logic)
10. [Response Analysis Rules](#10-response-analysis-rules)

---

## 1. Authentication Mechanism Identification

### 1.1 Detection Flowchart

```
                                    +------------------+
                                    |   Start Request  |
                                    +--------+---------+
                                             |
                                             v
                        +--------------------+--------------------+
                        |        Analyze Request Headers          |
                        +--------------------+--------------------+
                                             |
                   +-------------------------+-------------------------+
                   |                         |                         |
                   v                         v                         v
         +--------+--------+       +--------+--------+       +--------+--------+
         | Authorization   |       |    Cookie       |       |   X-API-Key     |
         |    Header?      |       |    Present?     |       |    Header?      |
         +--------+--------+       +--------+--------+       +--------+--------+
                  |                         |                         |
         +--------+--------+                |                +--------+--------+
         |                 |                |                |                 |
         v                 v                v                v                 v
    +---------+      +---------+      +---------+      +---------+      +---------+
    | Bearer  |      | Basic   |      | Session |      | API Key |      | Custom  |
    | Token   |      | Auth    |      | Based   |      | Auth    |      | Auth    |
    +---------+      +---------+      +---------+      +---------+      +---------+
         |                                  |
         v                                  v
    +---------+                       +---------+
    | JWT/    |                       | Check   |
    | OAuth/  |                       | Cookie  |
    | SAML?   |                       | Format  |
    +---------+                       +---------+
```

### 1.2 Token Type Detection Logic

```
+------------------+
|  Examine Token   |
+--------+---------+
         |
         v
+--------+---------+
| Contains 2 dots? |
| (xxx.yyy.zzz)    |
+--------+---------+
    |         |
   Yes        No
    |         |
    v         v
+-------+   +-------+
|  JWT  |   | Check |
|       |   | Other |
+-------+   +-------+
              |
    +---------+---------+
    |         |         |
    v         v         v
+-------+ +-------+ +-------+
| OAuth | | SAML  | | API   |
| Token | | Token | | Key   |
+-------+ +-------+ +-------+
```

### 1.3 Authentication Type Indicators

| Indicator | Mechanism Type | Confidence |
|-----------|---------------|------------|
| `Authorization: Bearer eyJ...` (3 parts, dots) | JWT | High |
| `Authorization: Bearer [random-string]` | OAuth Opaque Token | High |
| `Authorization: Basic [base64]` | Basic Auth | High |
| `Cookie: JSESSIONID=...` | Session (Java) | High |
| `Cookie: PHPSESSID=...` | Session (PHP) | High |
| `Cookie: ASP.NET_SessionId=...` | Session (.NET) | High |
| `X-API-Key: ...` | API Key | High |
| `X-Auth-Token: ...` | Custom Token | Medium |
| `SAMLResponse=...` in body | SAML | High |
| `id_token` in response | OpenID Connect | High |
| Login form with username/password | Form-Based | High |
| `WWW-Authenticate: Negotiate` | Kerberos/NTLM | High |
| `client_id` + `client_secret` in request | OAuth Client Credentials | High |
| `code` + `redirect_uri` in request | OAuth Auth Code | High |

### 1.4 Detection Priority Order

1. **Headers First**: Check `Authorization`, `X-API-Key`, custom auth headers
2. **Cookies Second**: Analyze session cookies and their formats
3. **Body Parameters**: Check for OAuth/SAML tokens in request body
4. **URL Parameters**: Look for tokens in query strings (insecure but common)
5. **Response Analysis**: Check Set-Cookie, WWW-Authenticate headers

---

## 2. Attack Selection Decision Trees

### 2.1 Master Attack Selection Flowchart

```
                           +----------------------+
                           | Auth Type Identified |
                           +-----------+----------+
                                       |
       +---------------+---------------+---------------+---------------+
       |               |               |               |               |
       v               v               v               v               v
  +----+----+    +----+----+    +----+----+    +----+----+    +----+----+
  |   JWT   |    |  OAuth  |    |  SAML   |    | Session |    | API Key |
  +---------+    +---------+    +---------+    +---------+    +---------+
       |               |               |               |               |
       v               v               v               v               v
  +----+----+    +----+----+    +----+----+    +----+----+    +----+----+
  | JWT     |    | OAuth   |    | SAML    |    | Session |    | API Key |
  | Attack  |    | Attack  |    | Attack  |    | Attack  |    | Attack  |
  | Tree    |    | Tree    |    | Tree    |    | Tree    |    | Tree    |
  +---------+    +---------+    +---------+    +---------+    +---------+
```

### 2.2 JWT Attack Decision Tree

```
                           +------------------+
                           |   JWT Detected   |
                           +--------+---------+
                                    |
                                    v
                           +--------+---------+
                           | Decode Header &  |
                           | Payload (no sig) |
                           +--------+---------+
                                    |
            +-----------------------+-----------------------+
            |                       |                       |
            v                       v                       v
    +-------+-------+       +-------+-------+       +-------+-------+
    | Check 'alg'   |       | Identify      |       | Check Claims  |
    | Algorithm     |       | Key Source    |       | for Tampering |
    +-------+-------+       +-------+-------+       +-------+-------+
            |                       |                       |
    +-------+-------+               |               +-------+-------+
    |               |               |               |       |       |
    v               v               v               v       v       v
+---+---+     +----+----+   +------+------+    +---+---+ +--+--+ +-+-+
| RS256 |     | HS256   |   | jku/x5u/kid|    | role  | | sub | |exp|
| ES256 |     | HS384   |   | headers?   |    | claim | |claim| |nbf|
+---+---+     +----+----+   +------+------+    +-------+ +-----+ +---+
    |              |               |
    v              v               v
+---+--------+ +---+--------+ +---+--------+
| Algorithm  | | Secret     | | Header     |
| Confusion  | | Cracking   | | Injection  |
| Attack     | | Attack     | | Attack     |
+------------+ +------------+ +------------+
```

### 2.3 OAuth Attack Decision Tree

```
                           +------------------+
                           |  OAuth Detected  |
                           +--------+---------+
                                    |
                                    v
                           +--------+---------+
                           | Identify OAuth   |
                           | Flow Type        |
                           +--------+---------+
                                    |
            +-----------------------+-----------------------+
            |                       |                       |
            v                       v                       v
    +-------+-------+       +-------+-------+       +-------+-------+
    | Authorization |       | Implicit      |       | Client        |
    | Code Flow     |       | Flow          |       | Credentials   |
    +-------+-------+       +-------+-------+       +-------+-------+
            |                       |                       |
            v                       v                       v
    +-------+-------+       +-------+-------+       +-------+-------+
    |State Bypass   |       |Token Leakage  |       |Secret Exposure|
    |Redirect Abuse |       |Referrer Leak  |       |Token Theft    |
    |Code Replay    |       |Fragment Abuse |       |Scope Escalate |
    |PKCE Bypass    |       |History Leak   |       +---------------+
    +---------------+       +---------------+
```

### 2.4 Session Attack Decision Tree

```
                           +------------------+
                           | Session Detected |
                           +--------+---------+
                                    |
                                    v
                           +--------+---------+
                           | Analyze Cookie   |
                           | Properties       |
                           +--------+---------+
                                    |
            +-----------------------+-----------------------+
            |                       |                       |
            v                       v                       v
    +-------+-------+       +-------+-------+       +-------+-------+
    | Cookie Flags  |       | Session ID    |       | Session       |
    | Analysis      |       | Entropy       |       | Binding       |
    +-------+-------+       +-------+-------+       +-------+-------+
            |                       |                       |
            v                       v                       v
    +-------+-------+       +-------+-------+       +-------+-------+
    |Missing Secure |       |Predictable?   |       |IP/Device      |
    |Missing HttpOnly       |Sequential?    |       |Binding Check  |
    |SameSite Absent|       |Weak Random?   |       +---------------+
    +---------------+       +---------------+
            |                       |
            v                       v
    +-------+-------+       +-------+-------+
    |Cookie Theft   |       |Session        |
    |XSS Vector     |       |Prediction     |
    +---------------+       +---------------+
```

---

## 3. Bypass Technique Prioritization

### 3.1 Priority Matrix by Auth Type

#### JWT Priority Order (Highest to Lowest Impact)

| Priority | Technique | Success Rate | Detection Risk |
|----------|-----------|--------------|----------------|
| 1 | None Algorithm Attack | High | Low |
| 2 | Algorithm Confusion (RS256->HS256) | High | Low |
| 3 | Embedded JWK Attack | Medium | Low |
| 4 | JKU/X5U Header Injection | Medium | Medium |
| 5 | Kid Header Injection (Path Traversal) | Medium | Medium |
| 6 | Weak Secret Cracking | Variable | Low |
| 7 | Claim Manipulation (unsigned) | High (if vuln) | Low |
| 8 | Expiration Bypass | Low | Low |
| 9 | CVE-specific (Psychic Signatures) | Context-dependent | Low |

#### OAuth Priority Order

| Priority | Technique | Success Rate | Detection Risk |
|----------|-----------|--------------|----------------|
| 1 | State Parameter Missing/Bypass | High | Low |
| 2 | Open Redirect via redirect_uri | High | Medium |
| 3 | Authorization Code Replay | Medium | Low |
| 4 | PKCE Bypass (Missing Enforcement) | Medium | Low |
| 5 | Scope Escalation | Medium | Low |
| 6 | Client Secret Exposure | Variable | Low |
| 7 | Token Leakage (Referrer/History) | Medium | Low |
| 8 | Cross-Service Token Relay | Low | Low |

#### Session Priority Order

| Priority | Technique | Success Rate | Detection Risk |
|----------|-----------|--------------|----------------|
| 1 | Session Fixation | Medium | Low |
| 2 | Cookie Flag Exploitation | Medium | Low |
| 3 | Session ID Prediction | Low | Medium |
| 4 | Session Replay (post-logout) | Medium | Low |
| 5 | Concurrent Session Abuse | Low | Low |
| 6 | Session Timeout Bypass | Low | Low |

### 3.2 Attack Selection Algorithm

```
FUNCTION select_attacks(auth_type, context):
    attacks = []

    IF auth_type == "JWT":
        # Always test none algorithm first (quick win)
        attacks.append(("none_algorithm", priority=1))

        IF has_public_key_available():
            attacks.append(("algorithm_confusion", priority=2))

        IF jku_or_x5u_present():
            attacks.append(("header_injection", priority=3))

        attacks.append(("weak_secret_crack", priority=4))
        attacks.append(("claim_manipulation", priority=5))

    ELIF auth_type == "OAuth":
        attacks.append(("state_bypass", priority=1))
        attacks.append(("redirect_uri_abuse", priority=2))

        IF is_public_client():
            attacks.append(("pkce_bypass", priority=3))

        attacks.append(("scope_escalation", priority=4))
        attacks.append(("code_replay", priority=5))

    ELIF auth_type == "Session":
        attacks.append(("session_fixation", priority=1))
        attacks.append(("cookie_flags", priority=2))
        attacks.append(("session_replay", priority=3))

    ELIF auth_type == "API_Key":
        attacks.append(("key_exposure_scan", priority=1))
        attacks.append(("key_reuse_check", priority=2))
        attacks.append(("rate_limit_bypass", priority=3))

    RETURN sort_by_priority(attacks)
```

### 3.3 Dynamic Prioritization Factors

```
priority_score = base_priority

# Adjust based on context
IF target_is_high_value:
    priority_score += 2

IF technique_has_low_detection_risk:
    priority_score += 1

IF previous_similar_technique_succeeded:
    priority_score += 3

IF time_constraint_tight:
    # Prioritize quick wins
    IF technique_is_fast:
        priority_score += 2

IF stealth_required:
    IF technique_is_noisy:
        priority_score -= 3

RETURN priority_score
```

---

## 4. Token Attack Workflow

### 4.1 JWT Comprehensive Attack Flow

```
+------------------------------------------------------------------+
|                    JWT ATTACK WORKFLOW                            |
+------------------------------------------------------------------+
                                |
                                v
                    +---------------------+
                    | 1. Token Extraction |
                    | - Headers           |
                    | - Cookies           |
                    | - Local Storage     |
                    +----------+----------+
                               |
                               v
                    +---------------------+
                    | 2. Token Decoding   |
                    | - Decode header     |
                    | - Decode payload    |
                    | - Note algorithm    |
                    +----------+----------+
                               |
                               v
                    +---------------------+
                    | 3. Reconnaissance   |
                    | - Find JWKS/pubkey  |
                    | - Check endpoints   |
                    | - Identify claims   |
                    +----------+----------+
                               |
            +------------------+------------------+
            |                  |                  |
            v                  v                  v
   +--------+--------+ +-------+--------+ +------+---------+
   | SIGNATURE       | | CLAIM          | | IMPLEMENTATION |
   | ATTACKS         | | MANIPULATION   | | FLAWS          |
   +-----------------+ +----------------+ +----------------+
            |                  |                  |
            v                  v                  v
   +--------+--------+ +-------+--------+ +------+---------+
   | 4a. None Alg    | | 4b. Role/Admin | | 4c. Missing    |
   |     Attack      | |     Escalation | |     Sig Verify |
   +--------+--------+ +-------+--------+ +------+---------+
            |                  |                  |
            v                  v                  v
   +--------+--------+ +-------+--------+ +------+---------+
   | 5a. Algorithm   | | 5b. Subject    | | 5c. Signature  |
   |     Confusion   | |     Swap       | |     Stripping  |
   +--------+--------+ +-------+--------+ +------+---------+
            |                  |                  |
            v                  v                  v
   +--------+--------+ +-------+--------+ +------+---------+
   | 6a. JKU/X5U     | | 6b. Audience   | | 6c. Token      |
   |     Injection   | |     Tampering  | |     Replay     |
   +--------+--------+ +-------+--------+ +------+---------+
            |                  |                  |
            v                  v                  v
   +--------+--------+ +-------+--------+ +------+---------+
   | 7a. Kid         | | 7b. Expiration | | 7c. Cross-svc  |
   |     Injection   | |     Bypass     | |     Relay      |
   +--------+--------+ +-------+--------+ +------+---------+
            |                  |                  |
            v                  v                  v
   +--------+--------+ +-------+--------+ +------+---------+
   | 8a. Embedded    | | 8b. Issuer     | | 8c. Token      |
   |     JWK Attack  | |     Spoofing   | |     Confusion  |
   +--------+--------+ +-------+--------+ +------+---------+
            |                  |                  |
            v                  v                  v
   +--------+--------+ +-------+--------+
   | 9a. Weak Key    | | 9b. Custom     |
   |     Cracking    | |     Claim Add  |
   +-----------------+ +----------------+
                               |
                               v
                    +---------------------+
                    | 10. Validate Results|
                    | - Check access      |
                    | - Verify escalation |
                    | - Document finding  |
                    +---------------------+
```

### 4.2 JWT Attack Decision Points

```python
# JWT Attack Decision Logic
def jwt_attack_decision(token, context):
    """
    Determines optimal JWT attack sequence based on token analysis
    """
    header = decode_jwt_header(token)
    payload = decode_jwt_payload(token)

    attacks_to_try = []

    # PHASE 1: Quick Wins
    if header.get('alg') in ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']:
        # Asymmetric algorithm - try confusion
        attacks_to_try.append({
            'attack': 'none_algorithm',
            'priority': 1,
            'reason': 'Quick test - no dependencies'
        })
        attacks_to_try.append({
            'attack': 'algorithm_confusion',
            'priority': 2,
            'reason': 'Asymmetric key detected - confusion possible'
        })

    if header.get('alg') in ['HS256', 'HS384', 'HS512']:
        # Symmetric algorithm - try cracking
        attacks_to_try.append({
            'attack': 'none_algorithm',
            'priority': 1,
            'reason': 'Quick test - no dependencies'
        })
        attacks_to_try.append({
            'attack': 'weak_secret_crack',
            'priority': 3,
            'reason': 'Symmetric key - may be weak'
        })

    # PHASE 2: Header Injection
    if 'jku' in header:
        attacks_to_try.append({
            'attack': 'jku_injection',
            'priority': 2,
            'reason': 'JKU header present - injection possible'
        })

    if 'x5u' in header:
        attacks_to_try.append({
            'attack': 'x5u_injection',
            'priority': 2,
            'reason': 'X5U header present - injection possible'
        })

    if 'kid' in header:
        attacks_to_try.append({
            'attack': 'kid_injection',
            'priority': 3,
            'reason': 'Kid header present - path traversal/SQLi possible'
        })

    # PHASE 3: Claim Manipulation
    privilege_claims = ['role', 'admin', 'is_admin', 'permissions', 'scope', 'groups']
    for claim in privilege_claims:
        if claim in payload:
            attacks_to_try.append({
                'attack': 'claim_escalation',
                'target_claim': claim,
                'priority': 4,
                'reason': f'Privilege claim {claim} found'
            })

    # PHASE 4: Implementation Flaws
    attacks_to_try.append({
        'attack': 'missing_signature_verification',
        'priority': 5,
        'reason': 'Always test for missing verification'
    })

    attacks_to_try.append({
        'attack': 'signature_stripping',
        'priority': 5,
        'reason': 'Always test for signature acceptance without signature'
    })

    return sorted(attacks_to_try, key=lambda x: x['priority'])
```

### 4.3 OAuth Attack Flow

```
+------------------------------------------------------------------+
|                    OAUTH ATTACK WORKFLOW                          |
+------------------------------------------------------------------+
                                |
                                v
                    +---------------------+
                    | 1. Flow Detection   |
                    | - Auth Code         |
                    | - Implicit          |
                    | - Client Creds      |
                    | - PKCE Usage        |
                    +----------+----------+
                               |
            +------------------+------------------+
            |                                     |
            v                                     v
   +--------+--------+                   +--------+--------+
   | AUTH CODE FLOW  |                   | IMPLICIT FLOW   |
   +-----------------+                   +-----------------+
            |                                     |
            v                                     v
   +--------+--------+                   +--------+--------+
   | 2a. Test State  |                   | 2b. Token       |
   |     Parameter   |                   |     Leakage     |
   +--------+--------+                   +--------+--------+
            |                                     |
            v                                     v
   +--------+--------+                   +--------+--------+
   | 3a. Redirect URI|                   | 3b. Referrer    |
   |     Validation  |                   |     Header Leak |
   +--------+--------+                   +--------+--------+
            |                                     |
            v                                     v
   +--------+--------+                   +--------+--------+
   | 4a. Code Replay |                   | 4b. History     |
   |     Attack      |                   |     Leak        |
   +--------+--------+                   +--------+--------+
            |                                     |
            v                                     v
   +--------+--------+                   +--------+--------+
   | 5a. PKCE Bypass |                   | 5b. Fragment    |
   |     Testing     |                   |     Handling    |
   +--------+--------+                   +--------+--------+
            |                                     |
            v                                     v
   +--------+--------+
   | 6. Scope        |
   |    Escalation   |
   +-----------------+
            |
            v
   +--------+--------+
   | 7. Token        |
   |    Substitution |
   +-----------------+
```

---

## 5. MFA Bypass Decision Tree

### 5.1 MFA Bypass Master Flow

```
                           +------------------+
                           |  MFA Detected    |
                           +--------+---------+
                                    |
                                    v
                           +--------+---------+
                           | Identify MFA     |
                           | Type             |
                           +--------+---------+
                                    |
         +--------------------------+---------------------------+
         |              |              |              |          |
         v              v              v              v          v
    +----+----+   +----+----+   +----+----+   +----+----+  +----+----+
    |  TOTP   |   |   SMS   |   |  Email  |   | Push    |  |Hardware |
    | (App)   |   |  OTP    |   |  OTP    |   | Notif   |  | Token   |
    +---------+   +---------+   +---------+   +---------+  +---------+
         |              |              |              |          |
         v              v              v              v          v
    +----+----+   +----+----+   +----+----+   +----+----+  +----+----+
    |Time Sync|   |SIM Swap |   |Email    |   |Notif    |  |Physical |
    |Bypass   |   |SS7 Atk  |   |Takeover |   |Fatigue  |  |Access   |
    +---------+   |VoIP Int |   +---------+   +---------+  +---------+
                  +---------+
```

### 5.2 Detailed MFA Bypass Techniques

```
+------------------------------------------------------------------+
|                    MFA BYPASS DECISION TREE                       |
+------------------------------------------------------------------+
                                |
                                v
                    +---------------------+
                    | 1. Direct Bypass    |
                    | Attempts            |
                    +----------+----------+
                               |
         +---------------------+---------------------+
         |                     |                     |
         v                     v                     v
+--------+--------+   +--------+--------+   +--------+--------+
| Response        |   | Parameter       |   | Step Skipping   |
| Manipulation    |   | Manipulation    |   |                 |
+-----------------+   +-----------------+   +-----------------+
| - Change        |   | - Remove MFA    |   | - Jump directly |
|   success=true  |   |   parameter     |   |   to post-MFA   |
| - Modify status |   | - Empty value   |   |   endpoint      |
|   codes         |   | - Different     |   | - Access        |
| - Intercept &   |   |   encoding      |   |   authenticated |
|   modify        |   |                 |   |   pages         |
+-----------------+   +-----------------+   +-----------------+
                               |
                               v
                    +---------------------+
                    | 2. Code Attacks     |
                    +----------+----------+
                               |
         +---------------------+---------------------+
         |                     |                     |
         v                     v                     v
+--------+--------+   +--------+--------+   +--------+--------+
| Brute Force     |   | Code Reuse      |   | Race Condition  |
+-----------------+   +-----------------+   +-----------------+
| - 4-6 digit     |   | - Same code     |   | - Submit        |
|   enumeration   |   |   multiple      |   |   multiple      |
| - No rate limit |   |   times         |   |   codes         |
| - Predictable   |   | - Expired code  |   |   simultaneously|
|   codes         |   |   still valid   |   | - Timing attacks|
+-----------------+   +-----------------+   +-----------------+
                               |
                               v
                    +---------------------+
                    | 3. Backup Method    |
                    | Exploitation        |
                    +----------+----------+
                               |
         +---------------------+---------------------+
         |                     |                     |
         v                     v                     v
+--------+--------+   +--------+--------+   +--------+--------+
| Recovery Codes  |   | Backup Phone    |   | Security        |
+-----------------+   +-----------------+   | Questions       |
| - Predictable   |   | - Less secure   |   +-----------------+
|   generation    |   |   channel       |   | - Weak          |
| - Brute force   |   | - Social eng    |   |   questions     |
| - Reuse         |   | - Carrier       |   | - OSINT answers |
|                 |   |   vulnerabilities   |                 |
+-----------------+   +-----------------+   +-----------------+
                               |
                               v
                    +---------------------+
                    | 4. Session/Token    |
                    | Attacks             |
                    +----------+----------+
                               |
         +---------------------+---------------------+
         |                     |                     |
         v                     v                     v
+--------+--------+   +--------+--------+   +--------+--------+
| Pre-Auth Token  |   | Remember Device |   | Session         |
| Reuse           |   | Bypass          |   | Fixation        |
+-----------------+   +-----------------+   +-----------------+
| - Capture pre-  |   | - Forge device  |   | - Fix session   |
|   MFA token     |   |   cookie        |   |   before MFA    |
| - Replay after  |   | - Copy device   |   | - Inherit       |
|   MFA elsewhere |   |   fingerprint   |   |   authenticated |
|                 |   | - Token theft   |   |   state         |
+-----------------+   +-----------------+   +-----------------+
```

### 5.3 MFA Bypass Priority Matrix

| Priority | Technique | MFA Type | Success Rate | Risk Level |
|----------|-----------|----------|--------------|------------|
| 1 | Response Manipulation | All | High if vuln | Low |
| 2 | Step Skipping | All | Medium | Low |
| 3 | Code Brute Force | TOTP/SMS | Variable | Medium |
| 4 | Recovery Code Abuse | All | Medium | Low |
| 5 | Remember Device Bypass | All | Medium | Low |
| 6 | Race Conditions | All | Low | Medium |
| 7 | Backup Method Downgrade | Multi-method | Medium | Low |
| 8 | Session Token Reuse | All | Low | Low |

---

## 6. Escalation Paths

### 6.1 Horizontal to Vertical Escalation Flow

```
+------------------------------------------------------------------+
|                    ESCALATION PATH WORKFLOW                       |
+------------------------------------------------------------------+
                                |
                                v
                    +---------------------+
                    | Start: Compromised  |
                    | Low-Privilege User  |
                    +----------+----------+
                               |
            +------------------+------------------+
            |                                     |
            v                                     v
   +--------+--------+                   +--------+--------+
   | HORIZONTAL      |                   | VERTICAL        |
   | ESCALATION      |                   | ESCALATION      |
   +-----------------+                   +-----------------+
            |                                     |
            v                                     v
   +--------+--------+                   +--------+--------+
   | Access Other    |                   | Gain Higher     |
   | Users' Data     |                   | Privileges      |
   +--------+--------+                   +--------+--------+
            |                                     |
   +--------+--------+                   +--------+--------+
   | - IDOR on       |                   | - Admin Panel   |
   |   user_id       |                   |   Access        |
   | - Cookie swap   |                   | - Role Injection|
   | - Session theft |                   | - Function      |
   | - Parameter     |                   |   Bypass        |
   |   tampering     |                   | - Mass Assign   |
   +--------+--------+                   +--------+--------+
            |                                     |
            v                                     v
   +--------+--------+                   +--------+--------+
   | Find Admin      |   +-------------->| Admin Access    |
   | Account Access  |   |               | Achieved        |
   +--------+--------+   |               +--------+--------+
            |            |                        |
            +------------+                        v
                                         +--------+--------+
                                         | System Level    |
                                         | Access          |
                                         +-----------------+
                                         | - Config access |
                                         | - Data export   |
                                         | - User creation |
                                         | - Code execution|
                                         +-----------------+
```

### 6.2 Escalation Decision Points

```python
def determine_escalation_path(current_access, findings):
    """
    Determines optimal escalation path based on current access and findings
    """
    paths = []

    # Check for horizontal escalation opportunities
    if 'idor_vulnerable' in findings:
        paths.append({
            'type': 'horizontal',
            'technique': 'IDOR Enumeration',
            'target': 'Other user accounts',
            'priority': 1
        })

    if 'predictable_session' in findings:
        paths.append({
            'type': 'horizontal',
            'technique': 'Session Prediction',
            'target': 'Other active sessions',
            'priority': 2
        })

    # Check for vertical escalation opportunities
    if 'admin_endpoint_accessible' in findings:
        paths.append({
            'type': 'vertical',
            'technique': 'Direct Admin Access',
            'target': 'Admin functionality',
            'priority': 1
        })

    if 'role_parameter_injectable' in findings:
        paths.append({
            'type': 'vertical',
            'technique': 'Role Injection',
            'target': 'Admin role',
            'priority': 2
        })

    if 'jwt_claim_modifiable' in findings:
        paths.append({
            'type': 'vertical',
            'technique': 'JWT Claim Modification',
            'target': 'Elevated privileges',
            'priority': 2
        })

    if 'mass_assignment_vulnerable' in findings:
        paths.append({
            'type': 'vertical',
            'technique': 'Mass Assignment',
            'target': 'Admin/elevated attributes',
            'priority': 3
        })

    # Horizontal-to-Vertical bridge
    if current_access['type'] == 'horizontal':
        paths.append({
            'type': 'bridge',
            'technique': 'Find Admin Account via Enumeration',
            'target': 'Admin user credentials/session',
            'priority': 2
        })

    return sorted(paths, key=lambda x: x['priority'])
```

### 6.3 Access Control Bypass Escalation

```
                    +---------------------+
                    | Identify Access     |
                    | Control Model       |
                    +----------+----------+
                               |
         +---------------------+---------------------+
         |                     |                     |
         v                     v                     v
    +----+----+           +----+----+           +----+----+
    |  RBAC   |           |  ABAC   |           |   DAC   |
    +---------+           +---------+           +---------+
         |                     |                     |
         v                     v                     v
    +----+----+           +----+----+           +----+----+
    | Role    |           | Attribute|          | Ownership|
    | Manip   |           | Injection|          | Transfer |
    +---------+           +---------+           +---------+
    | - Header|           | - Inject |          | - Modify |
    |   inject|           |   attrs  |          |   owner  |
    | - Token |           | - Type   |          | - Claim  |
    |   modify|           |   confusion|        |   resource|
    | - Param |           | - Policy |          | - ACL    |
    |   inject|           |   bypass |          |   abuse  |
    +---------+           +---------+           +---------+
```

---

## 7. False Positive Filtering

### 7.1 False Positive Detection Rules

```python
class FalsePositiveFilter:
    """
    Filters false positives from authentication testing results
    """

    def __init__(self):
        self.fp_patterns = {
            'jwt_none_algorithm': self._check_jwt_none_fp,
            'oauth_redirect': self._check_oauth_redirect_fp,
            'session_fixation': self._check_session_fixation_fp,
            'access_control': self._check_access_control_fp,
            'mfa_bypass': self._check_mfa_bypass_fp
        }

    def _check_jwt_none_fp(self, finding):
        """
        JWT None Algorithm False Positive Checks
        """
        fp_indicators = []

        # FP: Token accepted but no privileged action allowed
        if finding.get('response_code') == 200:
            if not self._contains_privileged_data(finding.get('response_body')):
                fp_indicators.append('Response lacks privileged data')

        # FP: Error message indicates rejection despite 200 status
        error_keywords = ['invalid', 'unauthorized', 'denied', 'rejected', 'expired']
        if any(kw in finding.get('response_body', '').lower() for kw in error_keywords):
            fp_indicators.append('Error keywords in response body')

        # FP: Same response as invalid token
        if finding.get('response_body') == finding.get('baseline_invalid_response'):
            fp_indicators.append('Response matches invalid token baseline')

        return {
            'is_false_positive': len(fp_indicators) > 0,
            'indicators': fp_indicators,
            'confidence': 1.0 - (len(fp_indicators) * 0.3)
        }

    def _check_oauth_redirect_fp(self, finding):
        """
        OAuth Redirect URI False Positive Checks
        """
        fp_indicators = []

        # FP: Redirect happens but no code/token passed
        if 'code=' not in finding.get('redirect_location', ''):
            if 'access_token=' not in finding.get('redirect_location', ''):
                fp_indicators.append('No code or token in redirect')

        # FP: Error parameter in redirect
        if 'error=' in finding.get('redirect_location', ''):
            fp_indicators.append('Error parameter present in redirect')

        # FP: Redirect to error page
        error_paths = ['/error', '/invalid', '/unauthorized', '/denied']
        if any(path in finding.get('redirect_location', '') for path in error_paths):
            fp_indicators.append('Redirect to error page')

        return {
            'is_false_positive': len(fp_indicators) > 0,
            'indicators': fp_indicators,
            'confidence': 1.0 - (len(fp_indicators) * 0.4)
        }

    def _check_session_fixation_fp(self, finding):
        """
        Session Fixation False Positive Checks
        """
        fp_indicators = []

        # FP: Session ID changed after authentication
        if finding.get('pre_auth_session') != finding.get('post_auth_session'):
            fp_indicators.append('Session regenerated on authentication')

        # FP: Session tied to IP/User-Agent
        if finding.get('session_bound'):
            fp_indicators.append('Session has additional binding')

        return {
            'is_false_positive': len(fp_indicators) > 0,
            'indicators': fp_indicators,
            'confidence': 1.0 - (len(fp_indicators) * 0.5)
        }

    def _check_access_control_fp(self, finding):
        """
        Access Control Bypass False Positive Checks
        """
        fp_indicators = []

        # FP: 200 response but empty/error body
        if finding.get('response_code') == 200:
            body = finding.get('response_body', '')
            if len(body) < 50:
                fp_indicators.append('Response body too short')
            if 'error' in body.lower() or 'denied' in body.lower():
                fp_indicators.append('Error message in successful response')

        # FP: Response matches unauthenticated baseline
        if finding.get('response_body') == finding.get('unauth_baseline'):
            fp_indicators.append('Response matches unauthenticated baseline')

        # FP: Redirect to login
        if finding.get('response_code') in [301, 302, 303, 307, 308]:
            if '/login' in finding.get('redirect_location', '').lower():
                fp_indicators.append('Redirect to login page')

        return {
            'is_false_positive': len(fp_indicators) > 0,
            'indicators': fp_indicators,
            'confidence': 1.0 - (len(fp_indicators) * 0.35)
        }

    def _check_mfa_bypass_fp(self, finding):
        """
        MFA Bypass False Positive Checks
        """
        fp_indicators = []

        # FP: MFA prompt still shown
        mfa_keywords = ['verification', 'confirm', 'two-factor', '2fa', 'otp', 'code']
        if any(kw in finding.get('response_body', '').lower() for kw in mfa_keywords):
            fp_indicators.append('MFA prompt still present in response')

        # FP: Limited access granted (read-only, partial)
        if 'read-only' in finding.get('response_body', '').lower():
            fp_indicators.append('Only read-only access granted')

        return {
            'is_false_positive': len(fp_indicators) > 0,
            'indicators': fp_indicators,
            'confidence': 1.0 - (len(fp_indicators) * 0.4)
        }

    def filter_findings(self, findings):
        """
        Process all findings and return filtered results
        """
        filtered = []

        for finding in findings:
            finding_type = finding.get('type')
            if finding_type in self.fp_patterns:
                fp_check = self.fp_patterns[finding_type](finding)
                finding['false_positive_analysis'] = fp_check

                if not fp_check['is_false_positive']:
                    filtered.append(finding)
                elif fp_check['confidence'] > 0.7:
                    # Include low-confidence FPs for manual review
                    finding['needs_manual_review'] = True
                    filtered.append(finding)

        return filtered
```

### 7.2 Response Analysis for FP Detection

```
+------------------------------------------------------------------+
|                FALSE POSITIVE DETECTION FLOW                      |
+------------------------------------------------------------------+
                                |
                                v
                    +---------------------+
                    | Analyze Response    |
                    +----------+----------+
                               |
         +---------------------+---------------------+
         |                     |                     |
         v                     v                     v
+--------+--------+   +--------+--------+   +--------+--------+
| Status Code     |   | Response Body   |   | Response        |
| Analysis        |   | Analysis        |   | Headers         |
+-----------------+   +-----------------+   +-----------------+
         |                     |                     |
         v                     v                     v
+--------+--------+   +--------+--------+   +--------+--------+
| 200 but error   |   | Error keywords  |   | Set-Cookie      |
| in body = FP    |   | present = FP    |   | changes = FP?   |
+-----------------+   +-----------------+   +-----------------+
| 403/401 always  |   | Empty response  |   | WWW-Authenticate|
| = FP            |   | = likely FP     |   | header = FP     |
+-----------------+   +-----------------+   +-----------------+
                               |
                               v
                    +---------------------+
                    | Compare to         |
                    | Baselines          |
                    +----------+----------+
                               |
         +---------------------+---------------------+
         |                     |                     |
         v                     v                     v
+--------+--------+   +--------+--------+   +--------+--------+
| Valid Session   |   | Invalid Token   |   | Unauth Access   |
| Baseline        |   | Baseline        |   | Baseline        |
+-----------------+   +-----------------+   +-----------------+
         |                     |                     |
         v                     v                     v
+--------+--------+   +--------+--------+   +--------+--------+
| Match = valid   |   | Match = FP      |   | Match = FP      |
| finding         |   |                 |   |                 |
+-----------------+   +-----------------+   +-----------------+
```

### 7.3 Confidence Scoring for Findings

| Indicator | Confidence Adjustment |
|-----------|----------------------|
| Response matches valid baseline | +0.3 |
| Privileged data in response | +0.4 |
| No error keywords | +0.1 |
| Response differs from invalid baseline | +0.2 |
| Error keywords present | -0.3 |
| Empty or minimal response | -0.2 |
| Redirect to login/error | -0.4 |
| Response matches invalid baseline | -0.5 |

---

## 8. Priority Scoring System

### 8.1 Vulnerability Severity Scoring

```python
class VulnerabilityScoringSystem:
    """
    Calculates priority scores for authentication vulnerabilities
    """

    # Base scores by vulnerability type
    BASE_SCORES = {
        # Critical (9.0-10.0)
        'jwt_none_algorithm': 9.5,
        'jwt_algorithm_confusion': 9.0,
        'authentication_bypass': 9.5,
        'mfa_complete_bypass': 9.5,
        'admin_access_without_auth': 10.0,

        # High (7.0-8.9)
        'jwt_weak_secret': 8.0,
        'oauth_redirect_uri_bypass': 8.5,
        'session_fixation': 7.5,
        'vertical_privilege_escalation': 8.5,
        'jwt_claim_tampering': 8.0,

        # Medium (4.0-6.9)
        'horizontal_privilege_escalation': 6.5,
        'oauth_state_bypass': 6.0,
        'session_timeout_bypass': 5.0,
        'oauth_scope_escalation': 6.5,
        'mfa_rate_limit_bypass': 5.5,

        # Low (1.0-3.9)
        'session_cookie_missing_flags': 3.5,
        'sensitive_data_in_jwt': 3.0,
        'oauth_code_replay': 4.0,
        'user_enumeration': 3.5,
    }

    # Impact multipliers
    IMPACT_MULTIPLIERS = {
        'data_exposure': {
            'pii': 1.3,
            'financial': 1.4,
            'health': 1.4,
            'credentials': 1.5,
            'none': 1.0
        },
        'scope': {
            'single_user': 1.0,
            'multiple_users': 1.2,
            'all_users': 1.4,
            'admin': 1.5,
            'system': 1.6
        },
        'exploitability': {
            'trivial': 1.3,
            'easy': 1.2,
            'moderate': 1.0,
            'difficult': 0.8,
            'very_difficult': 0.6
        }
    }

    def calculate_score(self, finding):
        """
        Calculate priority score for a finding
        """
        vuln_type = finding.get('type')
        base_score = self.BASE_SCORES.get(vuln_type, 5.0)

        # Apply impact multipliers
        data_type = finding.get('data_exposure_type', 'none')
        scope = finding.get('scope', 'single_user')
        exploitability = finding.get('exploitability', 'moderate')

        multiplier = (
            self.IMPACT_MULTIPLIERS['data_exposure'].get(data_type, 1.0) *
            self.IMPACT_MULTIPLIERS['scope'].get(scope, 1.0) *
            self.IMPACT_MULTIPLIERS['exploitability'].get(exploitability, 1.0)
        )

        final_score = min(base_score * multiplier, 10.0)

        return {
            'base_score': base_score,
            'multiplier': multiplier,
            'final_score': round(final_score, 1),
            'severity': self._score_to_severity(final_score)
        }

    def _score_to_severity(self, score):
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'

    def prioritize_findings(self, findings):
        """
        Sort findings by priority score
        """
        scored_findings = []
        for finding in findings:
            score_data = self.calculate_score(finding)
            finding['priority_score'] = score_data
            scored_findings.append(finding)

        return sorted(
            scored_findings,
            key=lambda x: x['priority_score']['final_score'],
            reverse=True
        )
```

### 8.2 Priority Matrix

```
                    EXPLOITABILITY
                    Easy    Moderate    Difficult
                +--------------------------------+
    Critical   |   P1   |    P1     |    P2     |  IMPACT
    High       |   P1   |    P2     |    P2     |
    Medium     |   P2   |    P3     |    P3     |
    Low        |   P3   |    P4     |    P4     |
                +--------------------------------+

P1 = Immediate (0-24 hours)
P2 = Urgent (1-3 days)
P3 = Normal (1-2 weeks)
P4 = Low (1 month)
```

### 8.3 Contextual Priority Adjustments

| Factor | Adjustment |
|--------|------------|
| Internet-facing application | +1.0 |
| Internal application only | -1.0 |
| Handles sensitive data | +0.5 |
| Financial/healthcare sector | +1.0 |
| Proof of concept achieved | +0.5 |
| Requires user interaction | -0.5 |
| Rate limiting in place | -0.3 |
| WAF/security controls detected | -0.2 |

---

## 9. Python Detection Logic

### 9.1 Complete Authentication Detection Module

```python
"""
Authentication Mechanism Detection Module
For Security Testing Agent
"""

import re
import base64
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class AuthType(Enum):
    JWT = "jwt"
    OAUTH = "oauth"
    SAML = "saml"
    SESSION = "session"
    BASIC = "basic"
    API_KEY = "api_key"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


@dataclass
class AuthenticationSignature:
    """Represents detected authentication mechanism"""
    auth_type: AuthType
    confidence: float
    indicators: List[str]
    token_value: Optional[str]
    additional_info: Dict


class AuthenticationDetector:
    """
    Detects and classifies authentication mechanisms from HTTP requests/responses
    """

    # JWT patterns
    JWT_PATTERN = re.compile(
        r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    )

    # Session cookie patterns by framework
    SESSION_PATTERNS = {
        'php': re.compile(r'PHPSESSID=([a-zA-Z0-9,-]+)'),
        'java': re.compile(r'JSESSIONID=([A-F0-9]+)'),
        'asp_net': re.compile(r'ASP\.NET_SessionId=([a-zA-Z0-9]+)'),
        'django': re.compile(r'sessionid=([a-z0-9]+)'),
        'rails': re.compile(r'_session_id=([a-f0-9]+)'),
        'express': re.compile(r'connect\.sid=s%3A([^;]+)'),
        'flask': re.compile(r'session=([A-Za-z0-9._-]+)'),
    }

    # OAuth indicators
    OAUTH_INDICATORS = [
        'access_token', 'refresh_token', 'token_type', 'bearer',
        'expires_in', 'scope', 'client_id', 'client_secret',
        'grant_type', 'authorization_code', 'redirect_uri'
    ]

    # SAML indicators
    SAML_INDICATORS = [
        'SAMLRequest', 'SAMLResponse', 'SAMLart',
        'RelayState', 'urn:oasis:names:tc:SAML'
    ]

    def detect_from_request(
        self,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        body: str,
        url: str
    ) -> AuthenticationSignature:
        """
        Analyze HTTP request components to detect authentication mechanism
        """
        detections = []

        # Check Authorization header
        auth_header = headers.get('Authorization', '') or headers.get('authorization', '')
        if auth_header:
            detections.append(self._analyze_auth_header(auth_header))

        # Check for API key headers
        api_key_result = self._detect_api_key(headers)
        if api_key_result:
            detections.append(api_key_result)

        # Check cookies
        cookie_result = self._analyze_cookies(cookies)
        if cookie_result:
            detections.append(cookie_result)

        # Check request body
        body_result = self._analyze_body(body)
        if body_result:
            detections.append(body_result)

        # Check URL parameters
        url_result = self._analyze_url(url)
        if url_result:
            detections.append(url_result)

        # Return highest confidence detection
        if detections:
            return max(detections, key=lambda x: x.confidence)

        return AuthenticationSignature(
            auth_type=AuthType.UNKNOWN,
            confidence=0.0,
            indicators=[],
            token_value=None,
            additional_info={}
        )

    def _analyze_auth_header(self, header_value: str) -> AuthenticationSignature:
        """Analyze Authorization header"""
        indicators = []

        # Bearer token (JWT or OAuth)
        if header_value.lower().startswith('bearer '):
            token = header_value[7:].strip()

            # Check if JWT
            if self.JWT_PATTERN.match(token):
                jwt_info = self._decode_jwt(token)
                indicators.append('Bearer token with JWT format')
                indicators.append(f"Algorithm: {jwt_info.get('algorithm', 'unknown')}")

                return AuthenticationSignature(
                    auth_type=AuthType.JWT,
                    confidence=0.95,
                    indicators=indicators,
                    token_value=token,
                    additional_info=jwt_info
                )
            else:
                # Opaque OAuth token
                indicators.append('Bearer token (opaque)')
                return AuthenticationSignature(
                    auth_type=AuthType.OAUTH,
                    confidence=0.75,
                    indicators=indicators,
                    token_value=token,
                    additional_info={'token_type': 'opaque'}
                )

        # Basic auth
        elif header_value.lower().startswith('basic '):
            indicators.append('Basic authentication header')
            try:
                decoded = base64.b64decode(header_value[6:]).decode('utf-8')
                if ':' in decoded:
                    indicators.append('Valid base64 credentials format')
            except:
                pass

            return AuthenticationSignature(
                auth_type=AuthType.BASIC,
                confidence=0.95,
                indicators=indicators,
                token_value=header_value[6:],
                additional_info={'type': 'basic'}
            )

        # Digest auth
        elif header_value.lower().startswith('digest '):
            indicators.append('Digest authentication header')
            return AuthenticationSignature(
                auth_type=AuthType.CUSTOM,
                confidence=0.90,
                indicators=indicators,
                token_value=header_value,
                additional_info={'type': 'digest'}
            )

        return AuthenticationSignature(
            auth_type=AuthType.CUSTOM,
            confidence=0.5,
            indicators=['Unknown authorization header format'],
            token_value=header_value,
            additional_info={}
        )

    def _detect_api_key(self, headers: Dict[str, str]) -> Optional[AuthenticationSignature]:
        """Detect API key authentication"""
        api_key_headers = [
            'X-API-Key', 'X-Api-Key', 'x-api-key',
            'API-Key', 'api-key', 'apikey',
            'X-Auth-Token', 'X-Access-Token',
            'X-Secret-Key', 'Authorization-Token'
        ]

        for header in api_key_headers:
            if header.lower() in [h.lower() for h in headers.keys()]:
                key_value = headers.get(header) or headers.get(header.lower())
                return AuthenticationSignature(
                    auth_type=AuthType.API_KEY,
                    confidence=0.90,
                    indicators=[f'API key header found: {header}'],
                    token_value=key_value,
                    additional_info={'header_name': header}
                )

        return None

    def _analyze_cookies(self, cookies: Dict[str, str]) -> Optional[AuthenticationSignature]:
        """Analyze cookies for session identification"""
        indicators = []
        detected_framework = None
        session_value = None

        for framework, pattern in self.SESSION_PATTERNS.items():
            for cookie_name, cookie_value in cookies.items():
                if pattern.search(f"{cookie_name}={cookie_value}"):
                    indicators.append(f'{framework.upper()} session cookie detected')
                    detected_framework = framework
                    session_value = cookie_value
                    break

        # Check for JWT in cookies
        for cookie_name, cookie_value in cookies.items():
            if self.JWT_PATTERN.match(cookie_value):
                jwt_info = self._decode_jwt(cookie_value)
                return AuthenticationSignature(
                    auth_type=AuthType.JWT,
                    confidence=0.90,
                    indicators=[f'JWT found in cookie: {cookie_name}'],
                    token_value=cookie_value,
                    additional_info={**jwt_info, 'cookie_name': cookie_name}
                )

        if detected_framework:
            return AuthenticationSignature(
                auth_type=AuthType.SESSION,
                confidence=0.85,
                indicators=indicators,
                token_value=session_value,
                additional_info={'framework': detected_framework}
            )

        return None

    def _analyze_body(self, body: str) -> Optional[AuthenticationSignature]:
        """Analyze request/response body for auth tokens"""
        if not body:
            return None

        indicators = []

        # Check for SAML
        for indicator in self.SAML_INDICATORS:
            if indicator in body:
                indicators.append(f'SAML indicator found: {indicator}')

        if indicators:
            return AuthenticationSignature(
                auth_type=AuthType.SAML,
                confidence=0.90,
                indicators=indicators,
                token_value=self._extract_saml_token(body),
                additional_info={'saml_indicators': indicators}
            )

        # Check for OAuth parameters
        oauth_count = sum(1 for ind in self.OAUTH_INDICATORS if ind in body.lower())
        if oauth_count >= 2:
            return AuthenticationSignature(
                auth_type=AuthType.OAUTH,
                confidence=min(0.5 + (oauth_count * 0.1), 0.90),
                indicators=[f'OAuth parameters found ({oauth_count})'],
                token_value=self._extract_oauth_token(body),
                additional_info={'oauth_indicator_count': oauth_count}
            )

        # Check for JWT in body
        jwt_match = self.JWT_PATTERN.search(body)
        if jwt_match:
            token = jwt_match.group()
            jwt_info = self._decode_jwt(token)
            return AuthenticationSignature(
                auth_type=AuthType.JWT,
                confidence=0.85,
                indicators=['JWT found in request/response body'],
                token_value=token,
                additional_info=jwt_info
            )

        return None

    def _analyze_url(self, url: str) -> Optional[AuthenticationSignature]:
        """Analyze URL for auth tokens (insecure but common)"""
        # JWT in URL
        jwt_match = self.JWT_PATTERN.search(url)
        if jwt_match:
            token = jwt_match.group()
            return AuthenticationSignature(
                auth_type=AuthType.JWT,
                confidence=0.80,
                indicators=['JWT found in URL (insecure)'],
                token_value=token,
                additional_info={
                    **self._decode_jwt(token),
                    'security_issue': 'Token in URL'
                }
            )

        # Access token in URL (OAuth)
        if 'access_token=' in url or 'token=' in url:
            return AuthenticationSignature(
                auth_type=AuthType.OAUTH,
                confidence=0.75,
                indicators=['Access token in URL (insecure)'],
                token_value=self._extract_url_param(url, 'access_token'),
                additional_info={'security_issue': 'Token in URL'}
            )

        # API key in URL
        if 'api_key=' in url.lower() or 'apikey=' in url.lower():
            return AuthenticationSignature(
                auth_type=AuthType.API_KEY,
                confidence=0.80,
                indicators=['API key in URL (insecure)'],
                token_value=self._extract_url_param(url, 'api_key'),
                additional_info={'security_issue': 'API key in URL'}
            )

        return None

    def _decode_jwt(self, token: str) -> Dict:
        """Decode JWT without verification"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {'error': 'Invalid JWT format'}

            # Decode header
            header_padding = '=' * (4 - len(parts[0]) % 4)
            header = json.loads(
                base64.urlsafe_b64decode(parts[0] + header_padding)
            )

            # Decode payload
            payload_padding = '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(
                base64.urlsafe_b64decode(parts[1] + payload_padding)
            )

            return {
                'algorithm': header.get('alg', 'unknown'),
                'type': header.get('typ', 'JWT'),
                'header': header,
                'payload': payload,
                'claims': list(payload.keys()),
                'has_jku': 'jku' in header,
                'has_x5u': 'x5u' in header,
                'has_kid': 'kid' in header,
            }
        except Exception as e:
            return {'error': str(e)}

    def _extract_saml_token(self, body: str) -> Optional[str]:
        """Extract SAML token from body"""
        import re
        patterns = [
            r'SAMLResponse=([A-Za-z0-9+/=]+)',
            r'SAMLRequest=([A-Za-z0-9+/=]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, body)
            if match:
                return match.group(1)
        return None

    def _extract_oauth_token(self, body: str) -> Optional[str]:
        """Extract OAuth token from body"""
        import re
        patterns = [
            r'"access_token"\s*:\s*"([^"]+)"',
            r'access_token=([^&\s]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, body)
            if match:
                return match.group(1)
        return None

    def _extract_url_param(self, url: str, param: str) -> Optional[str]:
        """Extract parameter value from URL"""
        import re
        pattern = rf'{param}=([^&\s]+)'
        match = re.search(pattern, url, re.IGNORECASE)
        return match.group(1) if match else None


class AttackVectorSelector:
    """
    Selects appropriate attack vectors based on detected authentication
    """

    ATTACK_VECTORS = {
        AuthType.JWT: [
            {'name': 'none_algorithm', 'priority': 1, 'tool': 'jwt_tool -X a'},
            {'name': 'algorithm_confusion', 'priority': 2, 'tool': 'jwt_tool -X k'},
            {'name': 'weak_secret', 'priority': 3, 'tool': 'jwt_tool -C -d wordlist'},
            {'name': 'jku_injection', 'priority': 4, 'tool': 'jwt_tool -X s -ju URL'},
            {'name': 'kid_injection', 'priority': 5, 'tool': 'jwt_tool -X i'},
            {'name': 'claim_manipulation', 'priority': 6, 'tool': 'jwt_tool -I -pc claim'},
            {'name': 'embedded_jwk', 'priority': 7, 'tool': 'jwt_tool -X e'},
        ],
        AuthType.OAUTH: [
            {'name': 'state_bypass', 'priority': 1, 'tool': 'manual'},
            {'name': 'redirect_uri_manipulation', 'priority': 2, 'tool': 'burp_intruder'},
            {'name': 'code_replay', 'priority': 3, 'tool': 'manual'},
            {'name': 'pkce_bypass', 'priority': 4, 'tool': 'manual'},
            {'name': 'scope_escalation', 'priority': 5, 'tool': 'manual'},
            {'name': 'token_leakage', 'priority': 6, 'tool': 'referrer_check'},
        ],
        AuthType.SESSION: [
            {'name': 'session_fixation', 'priority': 1, 'tool': 'manual'},
            {'name': 'cookie_flag_check', 'priority': 2, 'tool': 'browser_devtools'},
            {'name': 'session_prediction', 'priority': 3, 'tool': 'burp_sequencer'},
            {'name': 'session_replay', 'priority': 4, 'tool': 'manual'},
            {'name': 'concurrent_session', 'priority': 5, 'tool': 'manual'},
        ],
        AuthType.BASIC: [
            {'name': 'credential_brute_force', 'priority': 1, 'tool': 'hydra'},
            {'name': 'default_credentials', 'priority': 2, 'tool': 'manual'},
            {'name': 'credential_stuffing', 'priority': 3, 'tool': 'custom_script'},
        ],
        AuthType.API_KEY: [
            {'name': 'key_exposure_search', 'priority': 1, 'tool': 'trufflehog'},
            {'name': 'rate_limit_bypass', 'priority': 2, 'tool': 'manual'},
            {'name': 'key_reuse_check', 'priority': 3, 'tool': 'manual'},
        ],
        AuthType.SAML: [
            {'name': 'signature_bypass', 'priority': 1, 'tool': 'saml_raider'},
            {'name': 'assertion_manipulation', 'priority': 2, 'tool': 'saml_raider'},
            {'name': 'xxe_injection', 'priority': 3, 'tool': 'burp'},
            {'name': 'replay_attack', 'priority': 4, 'tool': 'manual'},
        ],
    }

    def select_attacks(
        self,
        auth_signature: AuthenticationSignature,
        context: Dict = None
    ) -> List[Dict]:
        """
        Select and prioritize attack vectors for detected auth mechanism
        """
        base_attacks = self.ATTACK_VECTORS.get(
            auth_signature.auth_type,
            []
        ).copy()

        # Adjust priorities based on additional info
        if auth_signature.auth_type == AuthType.JWT:
            jwt_info = auth_signature.additional_info

            # Boost algorithm confusion if asymmetric
            if jwt_info.get('algorithm', '').startswith('RS'):
                self._adjust_priority(base_attacks, 'algorithm_confusion', -1)

            # Boost header injection if jku/x5u present
            if jwt_info.get('has_jku'):
                self._adjust_priority(base_attacks, 'jku_injection', -2)

            if jwt_info.get('has_kid'):
                self._adjust_priority(base_attacks, 'kid_injection', -1)

        # Apply context-based adjustments
        if context:
            if context.get('time_limited'):
                # Prioritize quick attacks
                for attack in base_attacks:
                    if attack['name'] in ['none_algorithm', 'state_bypass']:
                        attack['priority'] -= 1

            if context.get('stealth_required'):
                # Deprioritize noisy attacks
                for attack in base_attacks:
                    if attack['name'] in ['credential_brute_force', 'weak_secret']:
                        attack['priority'] += 2

        return sorted(base_attacks, key=lambda x: x['priority'])

    def _adjust_priority(self, attacks: List[Dict], attack_name: str, adjustment: int):
        """Adjust priority for specific attack"""
        for attack in attacks:
            if attack['name'] == attack_name:
                attack['priority'] = max(1, attack['priority'] + adjustment)
                break
```

---

## 10. Response Analysis Rules

### 10.1 Response Pattern Matching

```python
class ResponseAnalyzer:
    """
    Analyzes HTTP responses to determine authentication test results
    """

    # Success indicators
    SUCCESS_PATTERNS = {
        'privileged_access': [
            r'admin', r'administrator', r'superuser',
            r'dashboard', r'management', r'control.panel',
            r'"role"\s*:\s*"admin"', r'"isAdmin"\s*:\s*true',
            r'<title>.*admin.*</title>',
        ],
        'data_access': [
            r'"email"\s*:', r'"phone"\s*:', r'"address"\s*:',
            r'"ssn"\s*:', r'"credit.card"\s*:', r'"password"\s*:',
            r'"users"\s*:\s*\[', r'"accounts"\s*:\s*\[',
        ],
        'authenticated': [
            r'welcome', r'logged.in', r'authenticated',
            r'"status"\s*:\s*"success"', r'"authenticated"\s*:\s*true',
            r'logout', r'sign.out', r'profile',
        ]
    }

    # Failure indicators
    FAILURE_PATTERNS = {
        'authentication_required': [
            r'login', r'sign.in', r'authenticate',
            r'unauthorized', r'not.authenticated',
            r'"authenticated"\s*:\s*false',
            r'401', r'403',
        ],
        'invalid_token': [
            r'invalid.token', r'token.expired', r'malformed',
            r'signature.verification.failed', r'jwt.invalid',
            r'"valid"\s*:\s*false',
        ],
        'access_denied': [
            r'access.denied', r'forbidden', r'not.allowed',
            r'permission.denied', r'insufficient.privileges',
        ]
    }

    # Ambiguous patterns (require further analysis)
    AMBIGUOUS_PATTERNS = [
        r'error', r'failed', r'invalid',
        r'try.again', r'incorrect',
    ]

    def analyze_response(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
        baseline: Dict = None
    ) -> Dict:
        """
        Comprehensive response analysis
        """
        result = {
            'status_code': status_code,
            'likely_successful': False,
            'confidence': 0.0,
            'indicators': [],
            'data_exposed': [],
            'requires_review': False
        }

        # Status code analysis
        if status_code == 200:
            result['indicators'].append('HTTP 200 OK')
            result['confidence'] += 0.3
        elif status_code in [301, 302, 303, 307, 308]:
            location = headers.get('Location', '')
            if not any(p in location.lower() for p in ['login', 'auth', 'error']):
                result['indicators'].append('Redirect (not to login)')
                result['confidence'] += 0.2
            else:
                result['indicators'].append('Redirect to login/error')
                result['confidence'] -= 0.3
        elif status_code in [401, 403]:
            result['indicators'].append(f'HTTP {status_code} - Access denied')
            result['confidence'] -= 0.5

        # Body pattern analysis
        body_lower = body.lower()

        # Check success patterns
        for category, patterns in self.SUCCESS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    result['indicators'].append(f'Success pattern ({category}): {pattern}')
                    result['confidence'] += 0.15
                    if category == 'data_access':
                        result['data_exposed'].append(pattern)

        # Check failure patterns
        for category, patterns in self.FAILURE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    result['indicators'].append(f'Failure pattern ({category}): {pattern}')
                    result['confidence'] -= 0.2

        # Check ambiguous patterns
        for pattern in self.AMBIGUOUS_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                result['requires_review'] = True
                result['indicators'].append(f'Ambiguous pattern: {pattern}')

        # Compare to baseline if available
        if baseline:
            similarity = self._calculate_similarity(body, baseline.get('body', ''))
            if similarity > 0.9:
                result['indicators'].append('Response very similar to baseline')
                if baseline.get('type') == 'authenticated':
                    result['confidence'] += 0.3
                elif baseline.get('type') == 'unauthenticated':
                    result['confidence'] -= 0.3

        # Final determination
        result['confidence'] = max(min(result['confidence'], 1.0), 0.0)
        result['likely_successful'] = result['confidence'] > 0.5

        return result

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate text similarity using simple ratio"""
        if not text1 or not text2:
            return 0.0

        # Simple length-normalized matching
        shorter = min(len(text1), len(text2))
        longer = max(len(text1), len(text2))

        if longer == 0:
            return 1.0

        # Count matching characters
        matches = sum(1 for a, b in zip(text1, text2) if a == b)
        return matches / longer

    def extract_sensitive_data(self, body: str) -> List[Dict]:
        """
        Extract potentially sensitive data from response
        """
        findings = []

        # Email patterns
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)
        if emails:
            findings.append({'type': 'email', 'values': emails, 'count': len(emails)})

        # Phone patterns
        phones = re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', body)
        if phones:
            findings.append({'type': 'phone', 'values': phones, 'count': len(phones)})

        # Credit card patterns
        cards = re.findall(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', body)
        if cards:
            findings.append({'type': 'credit_card', 'values': ['[REDACTED]'] * len(cards), 'count': len(cards)})

        # SSN patterns
        ssns = re.findall(r'\b\d{3}[-]?\d{2}[-]?\d{4}\b', body)
        if ssns:
            findings.append({'type': 'ssn', 'values': ['[REDACTED]'] * len(ssns), 'count': len(ssns)})

        # API keys/tokens
        tokens = re.findall(r'["\']?(api_key|apikey|api-key|token|secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?', body, re.IGNORECASE)
        if tokens:
            findings.append({'type': 'api_key', 'values': ['[REDACTED]'] * len(tokens), 'count': len(tokens)})

        return findings


class TestResultProcessor:
    """
    Processes and categorizes test results
    """

    def __init__(self):
        self.response_analyzer = ResponseAnalyzer()
        self.fp_filter = FalsePositiveFilter()

    def process_test_result(
        self,
        test_type: str,
        request: Dict,
        response: Dict,
        baseline: Dict = None
    ) -> Dict:
        """
        Process a single test result
        """
        # Analyze response
        analysis = self.response_analyzer.analyze_response(
            status_code=response.get('status_code'),
            headers=response.get('headers', {}),
            body=response.get('body', ''),
            baseline=baseline
        )

        # Build finding
        finding = {
            'type': test_type,
            'request': request,
            'response_code': response.get('status_code'),
            'response_body': response.get('body', ''),
            'analysis': analysis,
            'sensitive_data': self.response_analyzer.extract_sensitive_data(
                response.get('body', '')
            )
        }

        # Check for false positive
        if analysis['likely_successful']:
            fp_check = self.fp_filter.filter_findings([finding])
            if fp_check and not fp_check[0].get('false_positive_analysis', {}).get('is_false_positive'):
                finding['verified'] = True
            else:
                finding['verified'] = False
                finding['fp_indicators'] = fp_check[0].get('false_positive_analysis', {}).get('indicators', [])
        else:
            finding['verified'] = False

        return finding
```

### 10.2 Result Classification Matrix

```
+------------------------------------------------------------------+
|              RESPONSE CLASSIFICATION MATRIX                       |
+------------------------------------------------------------------+

Status Code + Body Content = Classification

200 + Privileged Content    = CONFIRMED VULNERABILITY (High Confidence)
200 + User Data Exposed     = CONFIRMED VULNERABILITY (High Confidence)
200 + Error Message         = FALSE POSITIVE (Medium Confidence)
200 + Login Prompt          = FALSE POSITIVE (High Confidence)
200 + Empty/Minimal         = NEEDS REVIEW (Low Confidence)

302 + Redirect to Dashboard = LIKELY VULNERABLE (Medium Confidence)
302 + Redirect to Login     = FALSE POSITIVE (High Confidence)
302 + Redirect to Error     = FALSE POSITIVE (High Confidence)

401 + Any Content           = FALSE POSITIVE (High Confidence)
403 + Any Content           = FALSE POSITIVE (High Confidence)

500 + Any Content           = NEEDS REVIEW (Application Error)
```

### 10.3 Decision Logic Summary

```
FUNCTION classify_result(response):
    IF response.status == 200:
        IF contains_privileged_data(response.body):
            RETURN "CONFIRMED_VULNERABILITY"
        ELIF contains_error_keywords(response.body):
            RETURN "FALSE_POSITIVE"
        ELIF response.body == baseline_unauthenticated:
            RETURN "FALSE_POSITIVE"
        ELIF response.body == baseline_authenticated:
            RETURN "CONFIRMED_VULNERABILITY"
        ELSE:
            RETURN "NEEDS_REVIEW"

    ELIF response.status in [301, 302, 303, 307, 308]:
        redirect_target = response.headers['Location']
        IF is_login_page(redirect_target):
            RETURN "FALSE_POSITIVE"
        ELIF is_error_page(redirect_target):
            RETURN "FALSE_POSITIVE"
        ELSE:
            RETURN "LIKELY_VULNERABLE"

    ELIF response.status in [401, 403]:
        RETURN "FALSE_POSITIVE"

    ELIF response.status >= 500:
        RETURN "NEEDS_REVIEW"

    ELSE:
        RETURN "UNKNOWN"
```

---

## Appendix A: Quick Reference Cards

### A.1 JWT Attack Quick Reference

| Attack | Condition | Tool Command |
|--------|-----------|--------------|
| None Algorithm | Always try first | `jwt_tool TOKEN -X a` |
| Algorithm Confusion | RS* algorithm | `jwt_tool TOKEN -X k -pk pubkey.pem` |
| Weak Secret | HS* algorithm | `jwt_tool TOKEN -C -d wordlist.txt` |
| JKU Injection | jku in header | `jwt_tool TOKEN -X s -ju https://attacker.com/jwks` |
| Kid Injection | kid in header | `jwt_tool TOKEN -I -hc kid -hv "../../dev/null"` |
| Embedded JWK | Always try | `jwt_tool TOKEN -X e` |
| Claim Tampering | Privilege claims | `jwt_tool TOKEN -I -pc role -pv admin` |

### A.2 OAuth Attack Quick Reference

| Attack | Test Method | Expected Result |
|--------|-------------|-----------------|
| State Bypass | Remove/modify state | Code granted without state validation |
| Redirect Manipulation | Modify redirect_uri | Code/token sent to attacker URL |
| Code Replay | Reuse auth code | Token issued multiple times |
| PKCE Bypass | Omit code_challenge | Request accepted without PKCE |
| Scope Escalation | Add elevated scopes | Higher privileges granted |

### A.3 MFA Bypass Quick Reference

| Technique | Implementation | Success Indicator |
|-----------|----------------|-------------------|
| Response Manipulation | Change success=false to true | Full access granted |
| Step Skip | Access post-MFA URL directly | Dashboard access |
| Code Brute Force | Enumerate 4-6 digit codes | Valid code found |
| Backup Code Abuse | Use recovery codes | MFA bypassed |
| Device Remember Bypass | Forge device cookie | MFA not prompted |

---

## Appendix B: Flowchart Symbols Legend

```
+-------------+     Decision/Process box
|             |
+-------------+

+------+------+     Diamond - Decision point
|      |      |
|      v      |
+-------------+

       |            Arrow - Flow direction
       v

+------+------+     Multiple outputs from decision
       |
  +----+----+
  |         |
  v         v
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024-01-30 | Initial comprehensive document |

---

## References

- OWASP Testing Guide v4.2 - Authentication Testing
- OWASP Top 10 2021 - A07 Identification and Authentication Failures
- RFC 7519 - JSON Web Token (JWT)
- RFC 6749 - OAuth 2.0 Authorization Framework
- RFC 7636 - PKCE for OAuth
- PortSwigger Web Security Academy - Authentication
- jwt_tool Documentation
- Burp Suite Professional Documentation

---

# ═══════════════════════════════════════════════════════════════
# ADVANCED DECISION TREES EXTENSION v3.0 (2026-10)
# New attack selection logic for extended KB (33-46)
# Original content above is UNCHANGED.
# ═══════════════════════════════════════════════════════════════

## Section 11: Framework Middleware Bypass Decision Tree

```
[Target Identified]
        |
        v
[Detect Web Framework]
   |         |         |         |         |
   v         v         v         v         v
Next.js   Nuxt.js  SvelteKit  Spring   Express
   |         |         |         |         |
   v         v         v         v         v
Test        Test      Test      Test     Test
x-mid-     _payload  __data    path     proto-
subreq     .json     .json     trav     type
header                         +        pollu-
(CVE-2025-                     actuator tion
29927)
   |         |         |         |         |
   v         v         v         v         v
[Protected route accessed without auth?]
   |YES                |NO
   v                   v
[CRITICAL]         [Test HTTP Method Override]
                       |
                       v
              [Test path normalization]
                       |
                       v
              [Test ISR/SSG data routes]
```

### Framework Detection Logic
```python
def detect_framework(response):
    headers = response.headers
    body = response.text
    if 'next.js' in headers.get('x-powered-by', '').lower():
        return 'nextjs'
    if '/_next/' in body or '__next' in body:
        return 'nextjs'
    if '__nuxt' in body:
        return 'nuxtjs'
    if '__data.json' in body:
        return 'sveltekit'
    if 'jsessionid' in str(response.cookies).lower():
        return 'spring'
    if 'csrfmiddlewaretoken' in body:
        return 'django'
    if 'express' in headers.get('x-powered-by', '').lower():
        return 'express'
    return 'unknown'
```

## Section 12: AitM & Advanced MFA Bypass Decision Tree

```
[MFA Enabled Target]
        |
        v
[Identify MFA Type]
   |         |         |         |
   v         v         v         v
TOTP      Push      SMS      FIDO2/
           Notif              Passkey
   |         |         |         |
   v         v         v         v
Race       Push      SIM     ACSB/caBLE
Condition  Fatigue   Swap    attack
Attack     (100+     Social
           prompts)  Eng
   |         |         |         |
   v         v         v         v
[AitM Phishing (EvilGinx3)]
        |
        v
[Session Token Captured?]
   |YES        |NO
   v            v
Import     [Device Code Phishing]
cookie          |
into            v
browser    [Try BitM via noVNC]
```

### MFA Bypass Priority Matrix
```
Priority 1: Race condition on MFA verification endpoint
Priority 2: AitM proxy (EvilGinx3) to capture post-MFA session
Priority 3: Push fatigue (if push notification MFA)
Priority 4: Device code phishing (OAuth device flow targets)
Priority 5: Number matching social engineering
Priority 6: Response manipulation (change 403 to 200)
Priority 7: Direct TOTP brute force (rate limit dependent)
```

## Section 13: GraphQL/gRPC/WebSocket Auth Decision Tree

```
[API Endpoint Discovered]
        |
        v
[Identify API Type]
   |              |           |
   v              v           v
GraphQL         gRPC      WebSocket
   |              |           |
   v              v           v
Test            Test        Test
introspect      reflect-    upgrade
enabled?        ion on?     without
   |              |         auth?
   v              v           |
Schema         Service        v
analysis       enum       [CSWSH test]
   |              |           |
   v              v           v
Test batch     Test meta-  Test post-
+ alias        data inject auth msg
rate limit     (auth hdr   injection
bypass         spoofing)
   |              |           |
   v              v           v
Test            Test        Test
unprotected     plaintext   admin
mutations       channel     commands
```

### GraphQL Attack Chain
```python
GRAPHQL_ATTACK_ORDER = [
    'introspection_query',      # Schema enumeration
    'batch_query_array',        # Rate limit bypass
    'alias_multiplication',     # Operation multiplication
    'nested_query_auth',        # Nested field auth check
    'mutation_without_auth',    # Unprotected mutations
    'depth_limit_test',         # DoS via deep nesting
    'directive_overloading',    # Custom directive abuse
]
```

## Section 14: CI/CD & Cloud Auth Attack Decision Tree

```
[Target Uses CI/CD or Cloud]
        |
        v
[Identify Platform]
   |           |           |           |
   v           v           v           v
GitHub      GitLab      AWS         Azure/GCP
Actions     CI          IAM
   |           |           |           |
   v           v           v           v
Extract     Extract     Check       Check
OIDC        CI_JOB_     trust       managed
token       JWT         policy      identity
   |           |           |           |
   v           v           v           v
Assume      Assume      Confused    Token from
AWS role    cloud       deputy?     metadata
(weak       role        (no         endpoint
trust?)                 ExternalId)
   |           |           |           |
   v           v           v           v
[Enumerate permissions and escalation paths]
        |
        v
[Check for cross-account/cross-tenant access]
```

### AWS IAM Escalation Paths
```
Path 1: iam:CreateUser + iam:AttachUserPolicy → Create admin user
Path 2: iam:PassRole + lambda:CreateFunction → Execute as privileged role
Path 3: iam:PassRole + ec2:RunInstances → Launch instance with role
Path 4: sts:AssumeRole → Cross-account pivot (weak trust policy)
Path 5: iam:CreateAccessKey → Backdoor existing user
Path 6: iam:UpdateLoginProfile → Change user password
Path 7: lambda:UpdateFunctionCode → Inject into existing Lambda
```

## Section 15: Race Condition & Session Puzzling Decision Tree

```
[Auth Flow Identified]
        |
        v
[Identify Race-Prone Operations]
   |           |           |           |
   v           v           v           v
MFA         Register    Password   Coupon/
Verify      Account     Reset      Promo
   |           |           |           |
   v           v           v           v
Single-     Same email  Same token  Same code
packet      10x in      10x in      10x in
race        parallel    parallel    parallel
(H2 mux)
   |           |           |           |
   v           v           v           v
[Multiple successes = VULNERABLE]
        |
        v
[Test Session Puzzling]
   |
   v
Start reset flow → Visit admin (session var reuse?)
   |
   v
[Test SPA State Confusion]
   |
   v
Manipulate localStorage/sessionStorage auth state
   |
   v
[Test Account Pre-Hijacking]
   |
   v
Pre-register with victim email → Wait for SSO merge
```

## Section 16: Network & Legacy Auth Decision Tree

```
[Internal Network / AD Environment]
        |
        v
[Identify Auth Protocol]
   |           |           |           |
   v           v           v           v
NTLM       Kerberos    LDAP       RADIUS
   |           |           |           |
   v           v           v           v
Coercion    AS-REP      Injection   Blast-
(Petit-     Roast +     in auth     RADIUS
Potam,      Kerber-     params      (CVE-2024-
PrinterBug) oast                    3596)
   |           |           |           |
   v           v           v           v
Relay to    Crack       Bypass      MD5
LDAP/       hashes      login       collision
HTTP/SMB                filter      attack
   |           |           |           |
   v           v           v           v
[Escalate to Domain Admin / Full Access]
```

## Section 17: Kubernetes & Service Mesh Auth Decision Tree

```
[K8s / Service Mesh Target]
        |
        v
[Check Access Level]
   |              |
   v              v
Pod Access    External
   |              |
   v              v
Check SA      Test Ingress
token perms   CVE-2025-1974
   |              |
   v              v
List secrets  Bypass Istio
Create pods   AuthPolicy
Mount tokens  (path case,
              source IP)
   |              |
   v              v
[Escalate K8s RBAC]
        |
        v
[Test admission controller bypass]
        |
        v
[Pivot to cloud provider IAM]
```

## Extended Priority Scoring

### New Attack Category Weights
```python
EXTENDED_WEIGHTS = {
    'framework_middleware_bypass': 95,  # CVE-based, high success rate
    'graphql_introspection':      80,  # Common misconfiguration
    'graphql_batching_bypass':    70,  # Rate limit circumvention
    'race_condition_mfa':         85,  # MFA bypass, high impact
    'race_condition_registration': 60, # Duplicate account creation
    'aitm_phishing':              90,  # Post-MFA session theft
    'cicd_oidc_abuse':            85,  # Cloud privilege escalation
    'k8s_sa_token_abuse':         80,  # Container breakout
    'cloud_iam_escalation':       90,  # Full cloud account takeover
    'ntlm_relay':                 85,  # Domain admin path
    'deserialization_auth':       75,  # RCE via auth flow
    'ssti_auth':                  80,  # RCE via template injection
    'session_puzzling':           65,  # Auth state confusion
    'account_pre_hijack':         70,  # Pre-registration takeover
    'websocket_cswsh':            60,  # Cross-site WebSocket hijack
    'subdomain_takeover':         75,  # Token theft via DNS
    'cors_misconfiguration':      70,  # Credential theft
    'timing_side_channel':        55,  # Information disclosure
    'passkey_sync_attack':        65,  # Passkey theft
    'browser_extension_theft':    60,  # Token extraction
    'scim_provisioning_race':     55,  # Identity provisioning abuse
}
```

## Extended Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024-01-30 | Initial comprehensive document |
| 3.0 | 2026-10-10 | Added decision trees for framework bypass, AitM/MFA, GraphQL/gRPC/WebSocket, CI/CD/Cloud, race conditions, network auth, K8s/service mesh. Extended priority scoring with 21 new attack categories. |

## Extended References

- CVE-2025-29927 - Next.js Middleware Bypass
- CVE-2025-1974 - Kubernetes IngressNightmare
- CVE-2024-3596 - Blast-RADIUS
- CVE-2024-27316 / CVE-2024-24549 - HTTP/2 CONTINUATION
- RFC 8693 - Token Exchange
- RFC 9449 - DPoP
- OAuth 2.1 Draft Specification
- GNAP (Grant Negotiation and Authorization Protocol)
- Kubernetes RBAC Documentation
- Istio Security Best Practices
- AWS IAM Best Practices
- Azure AD Security Documentation
- GCP IAM Documentation

---

# v4.0 Extension — Deep Research Decision Trees (2026-10)
# Original content above is UNCHANGED.

## Section 18: JWT Advanced Attack Decision Tree

```
START → Check JWT headers for jku/x5u fields
  ├── jku/x5u present → Test with attacker-controlled JWKS URL
  │   ├── Server fetches attacker JWKS → CRITICAL: JKU/X5U Injection
  │   │   └── Chain: Forge token → Privilege escalation → ATO
  │   └── URL filtered → Try bypass techniques
  │       ├── Open redirect on trusted domain → Chain redirect to attacker JWKS
  │       ├── URL parser confusion (@, #, %23) → CVE-2024-2419 style
  │       └── DNS rebinding → Alternate resolution bypass
  ├── Check algorithm field
  │   ├── RS256 endpoint → Test HS256 confusion (CVE-2024-54150)
  │   │   └── Sign with public key as HMAC secret
  │   ├── alg:none → Test signature stripping
  │   └── Multiple algorithms accepted → Test each for weakness
  ├── Check iss claim type
  │   ├── String → Normal
  │   └── Test array injection → iss:["evil.com","legit.com"] (CVE-2025-30144)
  │       └── If accepted → Token forgery with key redirect
  ├── Check kid parameter
  │   ├── Test SQL injection → kid: "key1' UNION SELECT 'secret' --"
  │   ├── Test path traversal → kid: "../../dev/null"
  │   └── Test SSRF → kid pointing to external URL
  └── Check nested JSON handling
      └── Deep nesting test → 10000-level nested objects (CVE-2025-53864)
          └── Stack overflow → DoS confirmed
```

**Reference:** `knowledge-base/47-jwt-oauth-advanced-2025.md`

## Section 19: API Gateway Path Normalization Decision Tree

```
START → Identify gateway/proxy technology
  ├── Test trailing slash bypass
  │   ├── /path returns 401 but /path/ returns 200 → CRITICAL: Auth bypass
  │   └── Both same → Not vulnerable to trailing slash
  ├── Test double encoding
  │   ├── /%2561dmin resolves to /admin → CRITICAL: Double encoding bypass
  │   ├── /%61dmin resolves to /admin → HIGH: Single encoding bypass
  │   └── Both blocked → Test triple encoding /%252561dmin
  ├── Test double slash
  │   ├── //path bypasses rate limit or auth → HIGH: Double slash bypass (CVE-2025-71399)
  │   └── Normalized before check → Not vulnerable
  ├── Test dot segment traversal
  │   ├── /allowed/../restricted/ accessible → CRITICAL: Dot segment bypass
  │   ├── Encoded dots /%2e%2e/ work → CRITICAL: Encoded traversal
  │   └── All normalized → Not vulnerable
  ├── Test version downgrade
  │   ├── /api/v1/ vs /api/v2/ → Different auth requirements?
  │   │   ├── v1 unauthenticated → CRITICAL: Version downgrade (CVE-2026-23760)
  │   │   └── Same auth → Test /api/beta/, /api/internal/, /api/legacy/
  │   └── Single version → Not applicable
  ├── Test semicolon path params (Java/Tomcat)
  │   └── /admin;jsessionid=fake accessible → HIGH: Path param bypass
  ├── Test case manipulation
  │   └── /Admin vs /admin → Different auth? → MEDIUM: Case sensitivity
  └── Test mass assignment on write endpoints
      ├── Add role/is_admin/permissions to PUT/PATCH body
      │   ├── Fields accepted → CRITICAL: Mass assignment (API3:2023)
      │   └── Rejected → Test nested objects, param pollution
      └── Check GraphQL for APQ bypass
          ├── Register arbitrary query via APQ → HIGH: APQ bypass (CVE-2025-32032)
          └── APQ disabled or hash-verified → Not vulnerable
```

**Reference:** `knowledge-base/48-api-gateway-path-normalization.md`

## Section 20: HTTP Smuggling & WebSocket Decision Tree

```
START → Identify proxy/backend technology stack
  ├── HTTP Smuggling Tests
  │   ├── CL.TE probe → Send CL:6 + TE:chunked with trailing G
  │   │   ├── Timeout/error → Potential CL.TE desync
  │   │   └── Normal → Try TE.CL
  │   ├── TE.CL probe → Send TE:chunked + CL:3 with smuggled chunk
  │   │   ├── Second request affected → CRITICAL: TE.CL smuggling
  │   │   └── Normal → Try TE.TE
  │   ├── TE.TE obfuscation
  │   │   ├── Transfer-Encoding: xchunked → Test
  │   │   ├── Transfer-Encoding: chunked (trailing space) → Test
  │   │   ├── Transfer-Encoding:[tab]chunked → Test
  │   │   └── CVE-2025-55315 chunk extension → Test Kestrel
  │   └── Header normalization (CVE-2025-64484)
  │       └── X_Forwarded_Email (underscore) → Becomes X-Forwarded-Email?
  │           ├── Yes → HIGH: Header normalization smuggling
  │           └── No → Not vulnerable
  ├── WebSocket Tests
  │   ├── Test Origin validation
  │   │   ├── Connect with Origin: https://evil.com
  │   │   │   ├── Accepted → HIGH: Missing Origin validation
  │   │   │   └── Rejected → Origin check present
  │   │   └── Test CSWSH from attacker page
  │   │       └── Can read WebSocket messages → HIGH: CSWSH
  │   ├── Test post-handshake auth
  │   │   ├── Auth only at upgrade → Send privileged messages after
  │   │   │   ├── Executed → CRITICAL: No per-message auth
  │   │   │   └── Rejected → Per-message auth present
  │   │   └── Test with expired/invalid tokens post-handshake
  │   └── Test local WebSocket servers (IDE extensions)
  │       ├── Port scan localhost 3000-4000
  │       │   ├── WebSocket responds → Test for MCP/JSON-RPC
  │       │   │   └── Commands execute → HIGH: Local WS hijack (CVE-2025-52882)
  │       │   └── No WebSocket → Not vulnerable
  │       └── Check for authentication on localhost WS
  └── Test FortiOS WebSocket (CVE-2024-55591)
      └── Connect to :8443/jsconsole with crafted token
```

**Reference:** `knowledge-base/49-http-smuggling-websocket-advanced.md`

## Section 21: SSRF & Vulnerability Chaining Decision Tree

```
START → Identify SSRF-capable endpoints
  ├── SSRF to Cloud Metadata
  │   ├── Direct: http://169.254.169.254/latest/meta-data/ → Works?
  │   │   ├── Yes → CRITICAL: Direct SSRF to metadata
  │   │   │   └── Fetch IAM credentials → AWS/Azure/GCP escalation
  │   │   └── Blocked → Try IP encoding bypasses
  │   │       ├── Decimal: 2852039166
  │   │       ├── Octal: 0251.0376.0251.0376
  │   │       ├── Hex: 0xa9fea9fe
  │   │       ├── IPv6: [::ffff:169.254.169.254]
  │   │       ├── IPv6 hex: [::ffff:a9fe:a9fe] (CVE-2026-44589)
  │   │       ├── Leading zeros: 012.0.0.1 (CVE-2026-69192)
  │   │       ├── DNS rebinding via rbndr.us
  │   │       └── Redirect chain: 302 to metadata
  │   └── IMDSv2? → Need token via PUT with hop limit
  │       └── Header injection possible? → Set X-aws-ec2-metadata-token
  ├── XSS → OAuth Token Theft Chain
  │   ├── Find XSS injection point
  │   │   ├── Check localStorage for access_token/refresh_token
  │   │   │   └── Present → Exfiltrate via fetch to attacker server
  │   │   ├── Check sessionStorage
  │   │   ├── Check IndexedDB
  │   │   └── Initiate OAuth popup for silent token capture
  │   └── Self-XSS + Login CSRF combo
  ├── IDOR → Email Change → Password Reset → ATO
  │   ├── Find user management endpoints with sequential IDs
  │   │   ├── PUT /api/users/{id} accepts cross-user email change?
  │   │   │   ├── Yes → Change victim email to attacker-controlled
  │   │   │   │   └── Trigger password reset → ATO (CVE-2026-32103)
  │   │   │   └── No → Test UUID-based IDOR, param pollution
  │   │   └── Check if reset token leaked in response body
  │   └── Test with different auth tokens (cross-account)
  ├── Host Header Injection → Password Reset Poisoning
  │   ├── Test Host: evil.com on /forgot-password
  │   │   ├── Reset link uses injected host → HIGH: Host injection ATO
  │   │   └── Host header filtered → Try alternatives
  │   │       ├── X-Forwarded-Host: evil.com
  │   │       ├── X-Host: evil.com
  │   │       ├── Forwarded: host=evil.com
  │   │       ├── Host: legit.com:80@evil.com
  │   │       └── Host with CRLF injection
  │   └── CVE-2025-43930 / CVE-2026-27812 patterns
  └── CSRF + SameSite Bypass → ATO
      ├── CSRF token present? → Try removing it entirely
      │   ├── Still works → CSRF protection broken
      │   └── Fails → Try method override
      │       ├── GET with _method=POST (SameSite Lax bypass)
      │       │   ├── Works → HIGH: SameSite bypass (CVE-2024-28143)
      │       │   └── Fails → Try other frameworks
      │       └── Test Content-Type: text/plain (avoid CORS preflight)
      └── Target: password change, email change, MFA disable endpoints
```

**Reference:** `knowledge-base/50-ssrf-cloud-metadata-chains.md`

## Section 22: Emerging Threats Decision Tree

```
START → Assess authentication infrastructure
  ├── AitM Phishing Assessment
  │   ├── MFA type deployed?
  │   │   ├── SMS/TOTP → Vulnerable to EvilGinx interception
  │   │   ├── Push notification → Vulnerable to real-time relay
  │   │   ├── FIDO2/WebAuthn → Resistant (domain-bound)
  │   │   └── None → Credential theft without MFA bypass needed
  │   ├── OAuth Device Code flow enabled?
  │   │   ├── Yes → Test EvilTokens device code phishing
  │   │   │   └── Bypasses proxy entirely
  │   │   └── No / Restricted by Conditional Access → Lower risk
  │   └── Token Protection / Device binding enabled?
  │       ├── Yes → Stolen tokens unusable on different device
  │       └── No → Tokens freely portable
  ├── Supply Chain OAuth Audit
  │   ├── List third-party OAuth application consents
  │   │   ├── Over-scoped permissions → HIGH: Supply chain risk
  │   │   ├── Monitor for consent from unknown apps
  │   │   └── Check token usage from unexpected IPs
  │   └── Salesloft/Drift pattern: 700+ orgs affected
  ├── Bearer Token Leakage Tests
  │   ├── Token in URL parameter? (CVE-2026-44883)
  │   │   └── Yes → Leaks via Referer, logs, history
  │   ├── Token follows cross-origin redirect? (CVE-2025-27152 Axios)
  │   │   └── Yes → Authorization header sent to attacker
  │   └── Token in error messages or debug output?
  ├── CORS Misconfiguration
  │   ├── Test reflected Origin with credentials
  │   │   ├── Reflected + Allow-Credentials: true → CRITICAL
  │   │   ├── null origin accepted → HIGH
  │   │   └── Strict allowlist → Not vulnerable
  │   └── Test regex bypass (e.g., evil-trusted.com)
  └── X-Forwarded-For Trust Bypass
      ├── Test XFF: 127.0.0.1 to bypass IP restrictions
      │   ├── Access granted → CRITICAL: XFF trust (CVE-2024-47070)
      │   └── Blocked → Test other headers
      │       ├── X-Real-IP, True-Client-IP, CF-Connecting-IP
      │       └── Multiple XFF headers (first vs last wins)
      └── Check if rate limiting uses XFF
```

**Reference:** `knowledge-base/51-emerging-auth-threats-2025.md`, `knowledge-base/52-detection-prevention-matrix.md`

## v4.0 Extended Priority Scoring

```python
PRIORITY_SCORES_V4 = {
    'jku_x5u_injection':          95,  # Complete token forgery
    'jwt_algorithm_confusion':    90,  # Sign with public key
    'jwt_issuer_array_injection': 75,  # Type confusion bypass
    'oauth2_proxy_bypass':        95,  # Complete auth bypass
    'api_version_downgrade':      90,  # Unprotected legacy endpoints
    'path_normalization_bypass':  95,  # Gateway auth bypass
    'double_encoding_bypass':     85,  # Middleware bypass
    'http_request_smuggling':     90,  # Proxy-level auth bypass
    'websocket_auth_bypass':      85,  # Post-handshake bypass
    'cswsh_attack':               70,  # Cross-site WS hijack
    'ssrf_cloud_metadata':        95,  # IAM credential theft
    'ip_encoding_bypass':         80,  # SSRF filter evasion
    'dns_rebinding':              75,  # SSRF validation bypass
    'xss_oauth_token_theft':      85,  # Token exfiltration
    'idor_email_change_ato':      90,  # Full account takeover
    'host_header_injection':      75,  # Password reset poisoning
    'csrf_samesite_bypass':       70,  # Method override bypass
    'oauth_redirect_chaining':    80,  # Authorization code theft
    'mass_assignment':            85,  # Privilege escalation
    'graphql_apq_bypass':         75,  # Allowlist bypass
    'graphql_alias_batching':     70,  # Rate limit bypass
    'aitm_phishing':              90,  # Post-MFA session theft
    'supply_chain_oauth':         85,  # Third-party token theft
    'bearer_token_leakage':       65,  # Information disclosure
    'cors_credential_theft':      75,  # Cross-origin token theft
    'xff_trust_bypass':           80,  # IP restriction bypass
    'local_websocket_hijack':     70,  # IDE extension attack
}
```

## v4.0 Version History

| Version | Date | Changes |
|---------|------|---------|
| 4.0 | 2026-10-10 | Added decision trees for JWT advanced (JKU/X5U, issuer array, algorithm confusion), API gateway path normalization, HTTP smuggling/WebSocket, SSRF chaining, and emerging threats. Extended priority scoring with 27 new attack categories from internet-sourced deep research with 24 adversarially-verified findings. |

## v4.0 CVE References

- CVE-2024-54150 - cjwt Algorithm Confusion (RS256→HS256)
- CVE-2018-0114 - node-jose Embedded JWK Injection
- CVE-2025-30144 - fast-jwt Issuer Array Injection
- CVE-2025-53864 - Nimbus JOSE+JWT Nested JSON DoS
- CVE-2025-54576 - OAuth2-Proxy Query Parameter Auth Bypass
- CVE-2024-2419 - Keycloak URL Parser Redirect Bypass
- CVE-2025-66202 - Astro Double Encoding Path Bypass
- CVE-2025-71399 - Better Auth Double Slash Bypass
- CVE-2026-23760 - SmarterMail Version Downgrade
- CVE-2025-15602 - Snipe-IT Mass Assignment
- CVE-2025-55315 - ASP.NET Kestrel Chunk Extension Smuggling
- CVE-2025-32094 - Akamai Obs-fold Smuggling
- CVE-2024-53008 - HAProxy Message Framing
- CVE-2024-33452 - Kong/OpenResty HEAD Smuggling
- CVE-2025-64484 - OAuth2-Proxy Header Normalization
- CVE-2024-55591 - FortiOS WebSocket Auth Bypass
- CVE-2025-52882 - Claude Code MCP Local WebSocket Hijack
- CVE-2024-21893 - Ivanti Connect Secure SSRF via SAML
- CVE-2025-4427/4428 - Ivanti EPMM Auth Bypass + EL Injection
- CVE-2025-61882 - Oracle EBS SSRF + XSLT RCE
- CVE-2026-69192 - Leading-Zero Octet IP Confusion
- CVE-2026-44589 - IPv6 Denylist Bypass
- CVE-2025-43930 - Host Header Injection Password Reset
- CVE-2026-32103 - IDOR Account Takeover
- CVE-2025-27152 - Axios Credential Leakage via Redirect
- CVE-2026-44883 - Portainer Token in URL
- CVE-2024-41659 - Memos CORS Misconfiguration
- CVE-2024-47070 - authentik XFF Exception Bypass
- CVE-2024-51504 - ZooKeeper XFF IP Spoofing
- CVE-2025-32032 - Apollo Router APQ Bypass
- CVE-2026-35413 - Directus SDL Schema Leak
- CVE-2026-14916 - Kong JWT Algorithm Confusion
