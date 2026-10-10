# KB-46: SCIM Provisioning, Token Exchange & DPoP Advanced Attacks

## Overview

Deep dives into SCIM provisioning race conditions, OAuth Token Exchange (RFC 8693) delegation chain attacks, and DPoP (RFC 9449) proof-of-possession bypass techniques.

---

## 1. SCIM Provisioning Attacks

### 1.1 Unauthorized SCIM Endpoint Access

```
SCIM endpoints are often exposed without proper auth:
GET /scim/v2/Users          -> Enumerate all users
GET /scim/v2/Groups         -> Enumerate groups/roles
POST /scim/v2/Users         -> Create users
PATCH /scim/v2/Users/{id}   -> Modify user attributes
DELETE /scim/v2/Users/{id}  -> Delete users

Testing:
1. Find SCIM endpoint (common paths: /scim, /scim/v2, /api/scim)
2. Test without auth or with low-privilege token
3. Attempt user creation with admin role
4. Attempt attribute modification (role escalation)
```

### 1.2 Race Condition in Provisioning

```
During user provisioning (IdP -> SP sync):
1. User created with default role
2. Group membership applied (may set admin role)
3. Race: access between step 1 and 2 = default role
   Or: modify role during provisioning window

Single-packet technique: send role-change and login simultaneously
```

### 1.3 Attribute Injection

```
SCIM user creation with injected attributes:
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "attacker@target.com",
  "roles": [{"value": "admin"}],
  "entitlements": [{"value": "full-access"}],
  "urn:custom:schema": {"isAdmin": true}
}
```

---

## 2. Token Exchange (RFC 8693) Deep Dive

### 2.1 Delegation Chain Attacks

```
Token Exchange allows service A to get a token for service B
on behalf of the original user.

Attack: Exchange low-privilege token for high-privilege one

POST /oauth/token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<LOW_PRIV_TOKEN>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
audience=admin-service
scope=admin full-access
```

### 2.2 Cross-Tenant Exchange

```
Exchange token from tenant A for token valid in tenant B:

POST /oauth/token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<TENANT_A_TOKEN>
audience=https://api.tenant-b.com

If server doesn't validate tenant boundaries: cross-tenant access
```

### 2.3 Actor Token Impersonation

```
RFC 8693 supports actor tokens for delegation:
- subject_token: WHO to act as (target user)
- actor_token: WHO is acting (the requester)

Attack: Use own token as actor, admin token as subject
Result: Token that acts as admin on behalf of attacker
```

---

## 3. DPoP (RFC 9449) Advanced Bypass

### 3.1 Bearer Fallback

```
Test if resource server accepts Bearer when token was issued with DPoP:
Authorization: Bearer <dpop_bound_token>
(Without DPoP proof header)

If accepted: DPoP binding is not enforced, stolen tokens are usable
```

### 3.2 Proof Replay

```
DPoP proofs should be unique (jti claim checked):
1. Capture valid DPoP proof
2. Replay same proof with same token
3. If accepted: replay attack possible

Also test: proofs with future/past iat (time window)
```

### 3.3 Key Binding Bypass

```
DPoP binds token to a specific key (jkt claim in access token):
1. Create DPoP proof with DIFFERENT key pair
2. Use with the original access token
3. If accepted: key binding not validated

Also test:
- Algorithm confusion in DPoP proof (change ES256 to HS256)
- Missing required fields (htm, htu) in proof
- Nonce reuse when server provides DPoP-Nonce
```

### 3.4 Token Endpoint Bypass

```
Some servers bind DPoP at issuance but not at resource access:
1. Request token with DPoP proof
2. Use token at resource server WITHOUT DPoP
3. If resource server doesn't require DPoP proof: binding ineffective
```

---

## 4. Testing Checklist

| Test | Target | Severity if Found |
|------|--------|-------------------|
| SCIM endpoint without auth | /scim/v2/Users | Critical |
| SCIM user creation with admin role | POST /scim/v2/Users | Critical |
| Token exchange scope escalation | /oauth/token | Critical |
| Token exchange cross-tenant | /oauth/token | Critical |
| DPoP Bearer fallback | Resource server | High |
| DPoP proof replay | Resource server | High |
| DPoP key mismatch accepted | Resource server | Critical |

## References

- SCIM RFC 7644: Protocol specification
- RFC 8693: OAuth 2.0 Token Exchange
- RFC 9449: OAuth 2.0 DPoP
- DPoP implementation guide
