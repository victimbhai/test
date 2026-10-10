# Authorization Matrix Testing, Data Flows & Risk-Based Prioritization — Agent Chunk 10a
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Build and test authorization matrices across roles, map API data flows to identify sensitive data paths, define trust boundaries, and calculate risk scores for endpoint prioritization
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Create an authorization matrix mapping every endpoint-method combination against every role (unauthenticated, user, manager, admin, partner). Use the provided Python script to automate testing — it replays each request with each role's token and flags CRITICAL findings where access is granted when it should be denied. Map data flows through the API architecture (client -> gateway -> service -> database -> external APIs) to identify where sensitive data crosses trust boundaries. Use the Priority Score formula (Data_Sensitivity x Access_Width x Attack_Complexity_Inverse) to rank endpoints for testing.

---


### 5.3 Creating the Authorization Matrix

The authorization matrix maps every endpoint-method combination against every role or
permission level to define expected access and identify gaps.

```
Endpoint                     | Method | Unauth | User | Manager | Admin | Partner |
-----------------------------|--------|--------|------|---------|-------|---------|
/api/v2/users                | GET    | 403    | 200* | 200     | 200   | 403     |
/api/v2/users                | POST   | 401    | 403  | 403     | 201   | 403     |
/api/v2/users/{id}           | GET    | 401    | 200* | 200     | 200   | 403     |
/api/v2/users/{id}           | PUT    | 401    | 200* | 200*    | 200   | 403     |
/api/v2/users/{id}           | DELETE | 401    | 403  | 403     | 200   | 403     |
/api/v2/orders               | GET    | 401    | 200* | 200     | 200   | 200*    |
/api/v2/orders               | POST   | 401    | 201  | 201     | 201   | 201     |
/api/v2/orders/{id}          | GET    | 401    | 200* | 200*    | 200   | 200*    |
/api/v2/orders/{id}          | PUT    | 401    | 200* | 200*    | 200   | 403     |
/api/v2/orders/{id}          | DELETE | 401    | 403  | 200*    | 200   | 403     |
/api/v2/admin/settings       | GET    | 401    | 403  | 403     | 200   | 403     |
/api/v2/admin/settings       | PUT    | 401    | 403  | 403     | 200   | 403     |
/api/v2/reports              | GET    | 401    | 200* | 200     | 200   | 200*    |
/api/v2/reports/export       | POST   | 401    | 403  | 201     | 201   | 403     |
/api/v2/webhooks             | GET    | 401    | 200* | 200*    | 200   | 200*    |
/api/v2/webhooks             | POST   | 401    | 201  | 201     | 201   | 201     |
/api/v2/internal/debug       | GET    | 401    | 403  | 403     | 200   | 403     |

* = filtered to own resources only (BOLA/IDOR test required)
```

**Automated Authorization Matrix Testing Script:**

```python
#!/usr/bin/env python3
"""Generate and test authorization matrix for API endpoints."""
import requests
import json
import sys
from dataclasses import dataclass

@dataclass
class TestResult:
    endpoint: str
    method: str
    role: str
    expected: int
    actual: int
    passed: bool
    response_size: int
    notes: str = ""

def test_authorization_matrix(base_url, matrix, tokens):
    """
    Test authorization matrix.

    Args:
        base_url: API base URL
        matrix: Dict of {endpoint: {method: {role: expected_status}}}
        tokens: Dict of {role: bearer_token}
    """
    results = []

    for endpoint, methods in matrix.items():
        for method, roles in methods.items():
            for role, expected_status in roles.items():
                headers = {"Content-Type": "application/json"}
                if role != "unauthenticated":
                    headers["Authorization"] = f"Bearer {tokens.get(role, '')}"

                url = f"{base_url}{endpoint}"
                try:
                    response = requests.request(
                        method=method,
                        url=url,
                        headers=headers,
                        json={} if method in ('POST', 'PUT', 'PATCH') else None,
                        timeout=10,
                        allow_redirects=False,
                    )
                    actual_status = response.status_code
                    passed = actual_status == expected_status
                    notes = ""

                    if not passed:
                        if actual_status < expected_status:
                            notes = "MORE PERMISSIVE THAN EXPECTED"
                        else:
                            notes = "More restrictive than expected"

                        # Check for particularly dangerous failures
                        if expected_status in (401, 403) and actual_status == 200:
                            notes = "CRITICAL: Access granted when should be denied"

                    results.append(TestResult(
                        endpoint=endpoint,
                        method=method,
                        role=role,
                        expected=expected_status,
                        actual=actual_status,
                        passed=passed,
                        response_size=len(response.content),
                        notes=notes,
                    ))

                except requests.RequestException as e:
                    results.append(TestResult(
                        endpoint=endpoint,
                        method=method,
                        role=role,
                        expected=expected_status,
                        actual=0,
                        passed=False,
                        response_size=0,
                        notes=f"Request failed: {e}",
                    ))

    return results

def print_results(results):
    print(f"\n{'='*90}")
    print("AUTHORIZATION MATRIX TEST RESULTS")
    print(f"{'='*90}")

    # Print failures first
    failures = [r for r in results if not r.passed]
    if failures:
        print(f"\nFAILURES ({len(failures)}):")
        print(f"{'-'*90}")
        for r in failures:
            status = "!!!" if "CRITICAL" in r.notes else "!"
            print(f"  {status} [{r.method}] {r.endpoint}")
            print(f"    Role: {r.role}")
            print(f"    Expected: {r.expected}, Got: {r.actual}")
            print(f"    Note: {r.notes}")
            print()

    # Summary
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    critical = sum(1 for r in results if "CRITICAL" in r.notes)

    print(f"\nSUMMARY:")
    print(f"  Total tests: {total}")
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")
    print(f"  Critical: {critical}")
```

### 5.4 Mapping Data Flows

Understanding data flows helps identify where sensitive data enters, traverses, and exits
the API ecosystem.

```
Data Flow Diagram Elements for APIs:

1. External Entity -> API Gateway
   - Client sends request with credentials
   - Gateway validates API key / JWT / OAuth token

2. API Gateway -> Backend Service
   - Gateway forwards request with internal auth (mTLS, internal token)
   - Gateway may strip or add headers
   - Gateway may transform request format

3. Backend Service -> Database
   - Service queries database with user-provided parameters
   - Risk: SQL injection, NoSQL injection, parameter tampering

4. Backend Service -> External API
   - Service calls third-party APIs with stored credentials
   - Risk: SSRF, credential exposure, data leakage

5. Backend Service -> Message Queue
   - Service publishes events with user data
   - Risk: Sensitive data in message payloads, unauthorized consumption

6. Backend Service -> Cache (Redis, Memcached)
   - Service caches user data for performance
   - Risk: Cache poisoning, sensitive data in cache without TTL

7. Backend Service -> Object Storage (S3, GCS)
   - Service stores uploaded files or generated reports
   - Risk: Insecure direct object references, missing access controls
```

### 5.5 Identifying Trust Boundaries

Trust boundaries represent points where the level of trust changes. Each trust boundary
crossing in an API architecture requires security controls.

```
Trust Boundaries in API Architecture:

1. Internet <-> API Gateway
   Controls: TLS, authentication, rate limiting, WAF, input validation

2. API Gateway <-> DMZ Services
   Controls: Internal authentication, authorization, request signing

3. DMZ Services <-> Internal Services
   Controls: mTLS, service mesh policies, network segmentation

4. Services <-> Databases
   Controls: Database authentication, prepared statements, connection encryption

5. Services <-> External APIs
   Controls: Outbound firewall rules, credential management, response validation

6. Admin Interface <-> Internal Network
   Controls: VPN, MFA, IP allowlisting, audit logging

7. Partner API <-> Partner Network
   Controls: mTLS, API key management, data minimization

Key Questions at Each Boundary:
- Who/what is trusted on each side?
- What validation occurs at the crossing?
- What happens if trust is violated?
- Is the crossing logged and monitored?
- Can the boundary be bypassed?
```

---

## 6. Attack Surface Prioritization

### 6.1 Risk-Based Prioritization

Not all API endpoints carry equal risk. Prioritization ensures that the most critical
endpoints receive testing attention first.

#### 6.1.1 Endpoints Handling Sensitive Data

**PII (Personally Identifiable Information):**
- User profile endpoints: `/api/users/{id}`, `/api/users/me`
- Address endpoints: `/api/users/{id}/addresses`
- Payment information: `/api/users/{id}/payment-methods`
- Communication: `/api/users/{id}/emails`, `/api/users/{id}/phone-numbers`
- Identity documents: `/api/users/{id}/documents`
- Search endpoints that return PII: `/api/users/search`

**Financial Data:**
- Transaction endpoints: `/api/transactions`, `/api/payments`
- Account balance: `/api/accounts/{id}/balance`
- Billing endpoints: `/api/billing`, `/api/invoices`
- Refund endpoints: `/api/refunds`
- Financial reports: `/api/reports/financial`

**Medical/Health Data:**
- Patient records: `/api/patients/{id}/records`
- Prescription data: `/api/prescriptions`
- Lab results: `/api/lab-results`
- Health metrics: `/api/health-data`

**Priority Score Calculation:**

```
Priority = Data_Sensitivity * Access_Width * Attack_Complexity_Inverse

Where:
  Data_Sensitivity:
    Critical (financial, medical, credentials) = 5
    High (PII, personal data) = 4
    Medium (business data, internal info) = 3
    Low (public data, metadata) = 2
    Minimal (non-sensitive operational data) = 1

  Access_Width:
    Public (no auth) = 5
    Any authenticated user = 4
    Specific role required = 3
    Admin only = 2
    Internal only = 1

  Attack_Complexity_Inverse:
    Trivial to exploit = 5
    Low complexity = 4
    Moderate complexity = 3
    High complexity = 2
    Very complex = 1
```
