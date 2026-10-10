# Tools Reference: Async Python API Testing & Discovery Checklists — Agent Chunk 11e
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Use high-performance async Python (httpx) for concurrent API endpoint scanning, and follow comprehensive checklists for API attack surface discovery and security testing methodology
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use the httpx-based async scanning script to test hundreds of endpoints concurrently with configurable concurrency limits. The script handles timeouts, follows redirects optionally, and filters out 404s automatically. Follow the API Attack Surface Discovery Checklist (Appendix A) as a step-by-step guide through the entire discovery process: passive recon (JS, mobile, archives, DNS, source code, Google dorks), active recon (endpoint enum, OpenAPI, GraphQL, traffic), inventory/cataloging, prioritization, and continuous monitoring. Use the Quick Reference (Appendix B) to understand the 9-phase API security testing methodology.

---



# Example usage
if __name__ == '__main__':
    tester = APISecurityTester(
        base_url='https://api.target.com',
        auth_token='your-jwt-token-here',
        proxy='http://127.0.0.1:8080',  # Through Burp
        rate_limit=10,  # 10 requests/second max
    )

    # Test IDOR on user profiles
    print("Testing IDOR on /api/v1/users/{id}")
    tester.test_idor('/api/v1/users/{id}', range(1, 20))

    # Test method enumeration
    print("\nTesting methods on /api/v1/users")
    methods = tester.test_method_enumeration('/api/v1/users')
    for method, result in methods.items():
        print(f"  {method}: {result['status']}")

    # Test auth bypass
    print("\nTesting auth bypass on /api/v1/admin/settings")
    tester.test_auth_bypass('/api/v1/admin/settings')

    # Test mass assignment
    print("\nTesting mass assignment on /api/v1/users")
    tester.test_mass_assignment(
        '/api/v1/users',
        known_fields={'name': 'Test User', 'email': 'test@example.com'},
        hidden_fields={
            'role': 'admin',
            'is_admin': True,
            'permissions': ['admin'],
            'verified': True,
            'credit_balance': 99999,
        }
    )
```

**Async API Testing with httpx:**

```python
#!/usr/bin/env python3
"""High-performance async API testing using httpx."""
import httpx
import asyncio
import json
from typing import List, Dict

async def scan_endpoints(
    base_url: str,
    paths: List[str],
    headers: Dict[str, str] = None,
    concurrency: int = 20,
) -> List[Dict]:
    """Scan multiple endpoints concurrently."""
    results = []
    semaphore = asyncio.Semaphore(concurrency)

    async def check_endpoint(client, path):
        async with semaphore:
            url = f"{base_url}{path}"
            try:
                response = await client.get(url, timeout=10)
                return {
                    'path': path,
                    'status': response.status_code,
                    'content_type': response.headers.get('content-type', ''),
                    'content_length': len(response.content),
                    'server': response.headers.get('server', ''),
                }
            except httpx.RequestError as e:
                return {
                    'path': path,
                    'error': str(e),
                }

    async with httpx.AsyncClient(
        headers=headers or {},
        verify=False,
        follow_redirects=False,
    ) as client:
        tasks = [check_endpoint(client, path) for path in paths]
        results = await asyncio.gather(*tasks)

    return [r for r in results if r.get('status') and r['status'] != 404]

async def main():
    base_url = "https://api.target.com"
    headers = {"Authorization": "Bearer <token>"}

    # Load wordlist
    with open('/opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt') as f:
        paths = [f"/api/v1/{line.strip()}" for line in f if line.strip()]

    print(f"Scanning {len(paths)} endpoints...")
    results = await scan_endpoints(base_url, paths, headers)

    print(f"\nFound {len(results)} live endpoints:")
    for r in sorted(results, key=lambda x: x.get('status', 999)):
        print(f"  [{r['status']}] {r['path']} "
              f"({r.get('content_type', 'unknown')})")

if __name__ == '__main__':
    asyncio.run(main())
```

---

## Appendix A: API Attack Surface Discovery Checklist

```
[ ] 1. PASSIVE RECONNAISSANCE
    [ ] JavaScript bundle analysis
        [ ] Download all JS files from the target
        [ ] Extract API endpoints using regex patterns
        [ ] Analyze source maps if available
        [ ] Extract environment variables and secrets
        [ ] Identify framework-specific route configurations
    [ ] Mobile application analysis
        [ ] Decompile APK/IPA
        [ ] Extract API base URLs and endpoints
        [ ] Identify hardcoded secrets and API keys
        [ ] Analyze certificate pinning configuration
    [ ] Web archive analysis
        [ ] Query Wayback Machine for historical URLs
        [ ] Search for archived API documentation
        [ ] Identify deprecated endpoint paths
    [ ] DNS and subdomain enumeration
        [ ] Enumerate API-specific subdomains
        [ ] Check certificate transparency logs
        [ ] Perform ASN enumeration
        [ ] Probe discovered subdomains with httpx
    [ ] Public source code analysis
        [ ] Search GitHub/GitLab for API configurations
        [ ] Look for leaked OpenAPI specifications
        [ ] Search for Postman collections
        [ ] Check for hardcoded credentials
    [ ] Google dorking
        [ ] Search for API documentation pages
        [ ] Search for exposed specification files
        [ ] Search for error pages revealing API information

[ ] 2. ACTIVE RECONNAISSANCE
    [ ] Endpoint enumeration
        [ ] Run ffuf/feroxbuster with API-specific wordlists
        [ ] Enumerate API versions (v1, v2, v3, etc.)
        [ ] Test all HTTP methods per endpoint
        [ ] Fuzz content types
    [ ] OpenAPI/Swagger discovery
        [ ] Check all common spec locations
        [ ] Parse discovered specifications
        [ ] Compare spec with discovered endpoints
    [ ] GraphQL discovery
        [ ] Detect GraphQL endpoints
        [ ] Run introspection queries
        [ ] Attempt field suggestion attacks
        [ ] Fingerprint the GraphQL engine
    [ ] Traffic analysis
        [ ] Proxy all application traffic
        [ ] Catalog discovered endpoints
        [ ] Discover hidden parameters
        [ ] Analyze authentication tokens

[ ] 3. INVENTORY AND CATALOGING
    [ ] Build endpoint inventory with all attributes
    [ ] Create authorization matrix
    [ ] Map data flows and trust boundaries
    [ ] Identify sensitive data endpoints
    [ ] Document authentication mechanisms

[ ] 4. PRIORITIZATION
    [ ] Score endpoints by risk (data sensitivity x access width)
    [ ] Prioritize auth/authz endpoints
    [ ] Prioritize state-changing endpoints
    [ ] Prioritize file handling endpoints
    [ ] Prioritize webhook/callback endpoints
    [ ] Prioritize admin/management endpoints

[ ] 5. CONTINUOUS MONITORING
    [ ] Set up OpenAPI spec change detection
    [ ] Configure new endpoint alerting
    [ ] Monitor deprecated endpoints
    [ ] Automate inventory updates
```

## Appendix B: API Security Testing Methodology Quick Reference

```
Phase 1: Discovery        -> Find all endpoints, parameters, and data types
Phase 2: Authentication   -> Test login, token handling, session management
Phase 3: Authorization    -> Test BOLA/IDOR, function-level access, role bypass
Phase 4: Input Validation -> Test injection (SQL, NoSQL, command, SSRF, XSS)
Phase 5: Data Exposure    -> Test for excessive data in responses
Phase 6: Rate Limiting    -> Test DoS resilience, brute-force protection
Phase 7: Business Logic   -> Test workflows, race conditions, state manipulation
Phase 8: Configuration    -> Test CORS, headers, error handling, TLS
Phase 9: Reporting        -> Document findings with impact and remediation
```

---

*Chapter 05 of the Web API Security Research Knowledge Base*
*API Attack Surface Discovery and Inventory Methodology*
