# Attack Surface Prioritization, STRIDE Threat Modeling & Change Detection — Agent Chunk 10b
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Prioritize testing by endpoint category (auth, state-changing, file upload, webhooks, admin), apply STRIDE threat modeling to APIs, create data flow diagrams, and detect API specification changes
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Prioritize testing in this order: (1) Authentication/authorization endpoints — login, token, password reset, MFA. (2) State-changing endpoints (POST/PUT/PATCH/DELETE) — test for CSRF, authorization, input validation, race conditions. (3) File upload/download endpoints — test for path traversal, type bypass, SSRF, IDOR. (4) Webhook/callback endpoints — test for SSRF, replay attacks, signature validation. (5) Admin/management endpoints — test for privilege escalation, missing auth. Apply STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege) to identify threats at each API layer. Use oasdiff to monitor OpenAPI spec changes and the provided monitoring script to detect security-relevant modifications.

---


#### 6.1.2 Authentication/Authorization Endpoints

These endpoints are critical because compromise here grants access to everything:

**Highest Priority:**
- Login: `/api/auth/login`, `/api/auth/signin`
- Token generation: `/api/oauth/token`, `/api/auth/token`
- Password reset: `/api/auth/password-reset`, `/api/auth/forgot-password`
- Token refresh: `/api/auth/refresh`
- Registration: `/api/auth/register`, `/api/auth/signup`
- MFA management: `/api/auth/mfa/setup`, `/api/auth/mfa/verify`
- Session management: `/api/auth/sessions`, `/api/auth/logout`
- API key management: `/api/keys`, `/api/api-keys`
- OAuth authorization: `/api/oauth/authorize`
- SAML endpoints: `/api/saml/login`, `/api/saml/acs`

#### 6.1.3 State-Changing Endpoints

POST, PUT, PATCH, and DELETE endpoints can modify data and should be tested for:
- CSRF protection
- Authorization enforcement
- Input validation
- Idempotency
- Race conditions

#### 6.1.4 File Upload/Download Endpoints

```
High priority endpoints:
- /api/upload, /api/files/upload
- /api/users/{id}/avatar
- /api/documents/upload
- /api/attachments
- /api/import (CSV, Excel imports)
- /api/export (data export)
- /api/files/{id}/download

Test for:
- Unrestricted file upload (path traversal, malicious content types)
- File type validation bypass
- Server-side request forgery via file URL parameters
- Information disclosure in exported files
- Access control on file downloads (IDOR)
- Denial of service via large file uploads
```

#### 6.1.5 Webhook and Callback Endpoints

```
Webhook endpoints:
- /api/webhooks (registration)
- /api/webhooks/{id} (management)
- /api/callbacks (callback URL registration)
- /api/integrations/{id}/webhook

Test for:
- SSRF via webhook URL (internal network scanning)
- Webhook signature validation
- Replay attacks on webhook deliveries
- Denial of service via recursive webhooks
- Information disclosure in webhook payloads
- Unauthorized webhook registration
```

#### 6.1.6 Admin/Management Endpoints

```
Admin endpoints:
- /api/admin/*
- /api/manage/*
- /api/internal/*
- /api/settings
- /api/config
- /api/system/*
- /api/debug/*

Test for:
- Horizontal privilege escalation (user accessing admin)
- Vertical privilege escalation (lower admin to higher admin)
- Missing authentication
- Information disclosure (config details, user lists)
- Dangerous operations (delete all, reset, import)
```

### 6.2 STRIDE Threat Modeling for APIs

STRIDE is a threat modeling framework that categorizes threats into six categories.
When applied to APIs, each category maps to specific attack patterns.

```
S - Spoofing (Authentication)
    API Threats:
    - Authentication bypass
    - Token forgery (JWT algorithm confusion, key confusion)
    - Session hijacking
    - API key theft
    - OAuth flow manipulation
    - Certificate spoofing in mTLS

T - Tampering (Integrity)
    API Threats:
    - Parameter tampering (price, quantity, role)
    - Request body manipulation
    - SQL/NoSQL injection
    - Mass assignment (setting admin fields via API)
    - IDOR (modifying other users' data)
    - XML/JSON injection

R - Repudiation (Non-repudiation)
    API Threats:
    - Missing audit logging
    - Log injection
    - Unsigned API calls
    - Missing request correlation IDs
    - Insufficient transaction logging

I - Information Disclosure
    API Threats:
    - Excessive data exposure in responses
    - Verbose error messages (stack traces, SQL errors)
    - API specification exposure
    - Directory listing
    - Debug endpoint exposure
    - Response header information leakage
    - Timing-based information disclosure

D - Denial of Service
    API Threats:
    - Missing or weak rate limiting
    - Resource-intensive queries (GraphQL complexity)
    - Large payload attacks
    - Regex denial of service (ReDoS)
    - Zip bombs / decompression attacks
    - Slowloris-style attacks on WebSocket connections

E - Elevation of Privilege
    API Threats:
    - Broken object-level authorization (BOLA/IDOR)
    - Broken function-level authorization
    - Mass assignment leading to role elevation
    - JWT claim manipulation
    - OAuth scope escalation
    - Admin API access from user context
```

### 6.3 Data Flow Diagrams for API Threat Modeling

Creating data flow diagrams (DFDs) specific to API interactions helps identify threat
boundaries and data exposure points.

**Level 0 DFD (Context):**
```
[Client App] --HTTPS--> [API Gateway] --Internal--> [Backend Services]
                              |                           |
                              v                           v
                        [Auth Service]              [Database]
                              |                           |
                              v                           v
                        [Identity Provider]        [Object Storage]
```

**Level 1 DFD (Detailed API Flow):**
```
1. Client -> API Gateway:
   - TLS termination
   - Rate limiting check
   - API key / JWT validation
   - Request logging
   - WAF rules applied

2. API Gateway -> Auth Service:
   - Token validation
   - Permission lookup
   - Session validation

3. API Gateway -> Backend Service:
   - Authorized request forwarded
   - Internal headers added (user ID, permissions)
   - Request signed

4. Backend Service -> Database:
   - Parameterized queries
   - Connection pooling
   - Read/write splitting

5. Backend Service -> External API:
   - Outbound request with stored credentials
   - Response validation
   - Error handling

6. Backend Service -> Client (via Gateway):
   - Response filtering (remove internal fields)
   - Response signing
   - Cache headers
```

---

## 7. Continuous Attack Surface Monitoring

### 7.1 API Change Detection

APIs evolve continuously. New endpoints are added, existing ones are modified, and
deprecated endpoints may or may not be removed. Continuous monitoring detects these
changes before they introduce security gaps.

**OpenAPI Spec Diff Monitoring:**

```bash
# Using oasdiff for OpenAPI specification comparison
# Installation
go install github.com/tufin/oasdiff@latest

# Compare two versions of a spec
oasdiff diff spec_v1.json spec_v2.json

# Check for breaking changes
oasdiff breaking spec_v1.json spec_v2.json

# Generate changelog
oasdiff changelog spec_v1.json spec_v2.json

# Output in JSON for automated processing
oasdiff diff spec_v1.json spec_v2.json --format json > api_changes.json
```

**Automated API Spec Monitoring Script:**

```bash
#!/bin/bash
# api_monitor.sh - Monitor API specification for changes

API_SPEC_URL="https://api.target.com/openapi.json"
STORAGE_DIR="/opt/api-monitor/specs"
ALERT_SCRIPT="/opt/api-monitor/alert.sh"

mkdir -p "$STORAGE_DIR"

DATE=$(date +%Y%m%d_%H%M%S)
NEW_SPEC="${STORAGE_DIR}/spec_${DATE}.json"
LATEST_LINK="${STORAGE_DIR}/spec_latest.json"

# Download current spec
curl -s "$API_SPEC_URL" -o "$NEW_SPEC"

if [ ! -f "$LATEST_LINK" ]; then
    # First run
    ln -sf "$NEW_SPEC" "$LATEST_LINK"
    echo "Initial spec captured: $NEW_SPEC"
    exit 0
fi

# Compare with previous spec
PREVIOUS_SPEC=$(readlink -f "$LATEST_LINK")

if ! diff -q "$PREVIOUS_SPEC" "$NEW_SPEC" > /dev/null 2>&1; then
    echo "API specification changed!"

    # Generate diff report
    DIFF_REPORT="${STORAGE_DIR}/diff_${DATE}.txt"
    diff "$PREVIOUS_SPEC" "$NEW_SPEC" > "$DIFF_REPORT"

    # Check for security-relevant changes
    SECURITY_CHANGES=$(python3 - "$PREVIOUS_SPEC" "$NEW_SPEC" << 'PYTHON'
import json, sys

with open(sys.argv[1]) as f:
    old = json.load(f)
with open(sys.argv[2]) as f:
    new = json.load(f)

old_paths = set(old.get('paths', {}).keys())
new_paths = set(new.get('paths', {}).keys())

added = new_paths - old_paths
removed = old_paths - new_paths

changes = []
if added:
    changes.append(f"NEW ENDPOINTS: {', '.join(sorted(added))}")
if removed:
    changes.append(f"REMOVED ENDPOINTS: {', '.join(sorted(removed))}")

# Check for security scheme changes
old_security = old.get('components', {}).get('securitySchemes', {})
new_security = new.get('components', {}).get('securitySchemes', {})
if old_security != new_security:
    changes.append("SECURITY SCHEMES CHANGED")

# Check for endpoints that lost authentication
for path in (old_paths & new_paths):
    old_methods = old['paths'].get(path, {})
    new_methods = new['paths'].get(path, {})
    for method in set(list(old_methods.keys()) + list(new_methods.keys())):
        if method in ('parameters', 'summary', 'description'):
            continue
        old_sec = old_methods.get(method, {}).get('security')
        new_sec = new_methods.get(method, {}).get('security')
        if old_sec and not new_sec:
            changes.append(f"AUTH REMOVED: {method.upper()} {path}")
        elif old_sec is not None and new_sec == []:
            changes.append(f"AUTH EXPLICITLY DISABLED: {method.upper()} {path}")

print('\n'.join(changes) if changes else '')
PYTHON
)

    if [ -n "$SECURITY_CHANGES" ]; then
        echo "SECURITY-RELEVANT CHANGES DETECTED:"
        echo "$SECURITY_CHANGES"
        # Send alert
        if [ -x "$ALERT_SCRIPT" ]; then
            "$ALERT_SCRIPT" "API Security Change Alert" "$SECURITY_CHANGES"
        fi
    fi

    # Update latest link
    ln -sf "$NEW_SPEC" "$LATEST_LINK"
else
    echo "No changes detected"
    rm "$NEW_SPEC"
fi
```
