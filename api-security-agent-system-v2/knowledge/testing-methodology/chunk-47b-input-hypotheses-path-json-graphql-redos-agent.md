# Testing Hypotheses: Input Validation Part 2 — Agent Chunk 47b
> Source: 10-authorized-testing-hypotheses.md
> Purpose: Execute structured input validation test hypotheses: path traversal, JSON injection, XXE, GraphQL injection, ReDoS, header injection, LDAP injection, XPath injection, ORM injection, and Unicode normalization bypass
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Execute each hypothesis: H-INPUT-06 (path traversal — inject ../../etc/passwd in file path params), H-INPUT-07 (JSON injection — nested objects, prototype pollution keys), H-INPUT-08 (XXE — switch Content-Type to XML, inject entities), H-INPUT-09 (GraphQL injection — test filter/search arguments for injection), H-INPUT-10 (ReDoS — send strings that trigger catastrophic backtracking), H-INPUT-11 (header injection — inject \r\n in header values), H-INPUT-12 (LDAP injection — inject )(| in search params), H-INPUT-14 (ORM injection — Django __gte/__contains, Rails where), H-INPUT-15 (Unicode normalization — bypass filters with Unicode equivalents).

---

#### H-INPUT-06: Path Traversal

**Hypothesis**: File-related API parameters may be vulnerable to path traversal,
allowing access to files outside the intended directory.

**Risk level of test**: MEDIUM -- may access sensitive system files.

**Prerequisites**:
- Endpoints that handle file paths or filenames
- Staging environment preferred for unrestricted testing

**Test procedure**:

1. Identify file-related parameters:
   - File download: `?file=report.pdf`
   - Template selection: `?template=invoice`
   - Language/locale: `?lang=en`
   - Include/import: `?config=default`

2. Test path traversal sequences:
   - `../../../etc/passwd`
   - `..%2f..%2f..%2fetc%2fpasswd`
   - `....//....//....//etc/passwd`
   - `..%252f..%252f..%252fetc%252fpasswd` (double encoding)
   - `..\..\..\windows\win.ini` (Windows)

3. Check for:
   - File contents in the response
   - Different error messages for existing vs. non-existing files
     (directory existence oracle)
   - Error messages revealing the file system path

**Expected results**:
- **Vulnerable**: File contents from outside the intended directory appear
  in the response, or error messages reveal file system structure.
- **Not vulnerable**: Traversal sequences are rejected or neutralized.
  Error messages do not reveal file system paths.

---

#### H-INPUT-07: JSON Injection

**Hypothesis**: API endpoints may be vulnerable to JSON injection where
user input is concatenated into JSON structures rather than properly serialized.

**Risk level of test**: LOW-MEDIUM.

**Test procedure**:

1. Identify endpoints where user input is incorporated into JSON responses
   or stored as JSON.

2. Submit values containing JSON metacharacters:
   ```json
   {"name": "test\",\"role\":\"admin\",\"x\":\""}
   ```

3. Check if the injection modifies the JSON structure in stored data or
   subsequent API responses.

4. Test for JSON-based injection in:
   - Search parameters that are embedded in JSON queries
   - Fields that are stored and reflected in JSON format
   - Configuration values stored as JSON

---

#### H-INPUT-08: XML Injection / XXE

**Hypothesis**: API endpoints that process XML may be vulnerable to XML
External Entity (XXE) injection.

**Risk level of test**: HIGH in production (may access local files or internal
network). Test in staging/dev only.

**Prerequisites**:
- Endpoints that accept XML input
- Staging environment

**Test procedure**:

1. Identify XML-accepting endpoints:
   - SOAP endpoints
   - Endpoints with `Content-Type: application/xml`
   - Endpoints that accept file uploads (XLSX, DOCX, SVG are XML-based)
   - Endpoints that accept `Content-Type: text/xml`

2. Send a request with an external entity definition:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [
     <!ENTITY xxe SYSTEM "file:///etc/hostname">
   ]>
   <root>
     <data>&xxe;</data>
   </root>
   ```

3. Check if the entity is resolved in the response (file contents appear).

4. If no direct reflection, test blind XXE with an out-of-band channel:
   - External DTD loading: entity pointing to a controlled server
   - Check the controlled server for incoming requests

5. Test through XML-based file formats:
   - Upload an XLSX file with XXE in the internal XML files
   - Upload an SVG file with XXE
   - Upload a DOCX file with XXE

**Expected results**:
- **Vulnerable**: External entity resolved, file contents in response, or
  out-of-band request received.
- **Not vulnerable**: External entities disabled. XML parser configured to
  reject DTDs or external entities.

---

#### H-INPUT-09: GraphQL-Specific Injection

**Hypothesis**: GraphQL queries may be vulnerable to injection through
argument values or directive manipulation.

**Risk level of test**: LOW-MEDIUM.

**Test procedure**:

1. Test injection through string arguments:
   ```graphql
   query {
     user(name: "test\" OR 1=1) --") { id }
   }
   ```

2. Test directive injection:
   ```graphql
   query {
     user(id: "1") @skip(if: true) {
       id
     }
     __type(name: "User") {
       fields { name }
     }
   }
   ```

3. Test batch query injection:
   ```json
   [
     {"query": "query { user(id: \"1\") { id } }"},
     {"query": "query { __schema { types { name } } }"}
   ]
   ```

4. Test variable injection through JSON:
   ```json
   {
     "query": "query($id: ID!) { user(id: $id) { id } }",
     "variables": {"id": {"$gt": ""}}
   }
   ```

---

#### H-INPUT-10: Regular Expression DoS (ReDoS)

**Hypothesis**: User input may be used in regular expressions that are
vulnerable to catastrophic backtracking.

**Risk level of test**: MEDIUM -- may cause CPU consumption. Use carefully
and monitor.

**Prerequisites**:
- Endpoints that validate input with regular expressions (email, URL, phone)
- Staging environment preferred

**Test procedure**:

1. Identify endpoints with regex-based validation:
   - Email validation fields
   - URL validation fields
   - Pattern-match search fields
   - Custom format validators

2. Send input designed to trigger backtracking in common vulnerable patterns:
   - For email regex: `aaaaaaaaaaaaaaaaaaaaaaaaaaa!` (25+ repeated chars
     followed by invalid char)
   - For URL regex: Similar pattern of repeated valid chars + invalid ending

3. Measure response time. Compare with baseline:
   - Normal input: ~100ms
   - ReDoS input: >5s indicates vulnerability

4. Start with shorter strings and increase gradually. Do NOT send extremely
   long strings that could crash the service. Maximum test string: 50
   characters.

**Expected results**:
- **Vulnerable**: Response time increases exponentially with input length.
- **Not vulnerable**: Response time remains constant regardless of input length.

---

#### H-INPUT-11: HTTP Header Injection

**Hypothesis**: User input reflected in HTTP response headers may allow
header injection, enabling response splitting or cookie setting.

**Risk level of test**: LOW.

**Test procedure**:

1. Identify parameters that are reflected in response headers:
   - Redirect URLs (Location header)
   - Content-Disposition filenames
   - Custom response headers
   - CORS headers reflecting Origin

2. Test with CRLF sequences:
   - `%0d%0aInjected-Header: value`
   - `%0d%0a%0d%0a<html>` (response splitting)
   - `\r\nSet-Cookie: evil=value`

3. Check if the injected header appears in the response.

**Expected results**:
- **Vulnerable**: Injected headers appear in the HTTP response.
- **Not vulnerable**: CRLF sequences are stripped or encoded.

---

#### H-INPUT-12: LDAP Injection

**Hypothesis**: API endpoints interfacing with LDAP directories may be
vulnerable to LDAP injection.

**Risk level of test**: MEDIUM -- may alter LDAP queries.

**Test procedure**:

1. Identify endpoints that may query LDAP:
   - User search/lookup
   - Authentication endpoints
   - Directory browsing

2. Test with LDAP metacharacters:
   - `*` (wildcard)
   - `)(objectClass=*)` (filter injection)
   - `*)(uid=*))(|(uid=*`

3. Compare responses to determine if the LDAP filter was modified.

---

#### H-INPUT-13: XPath Injection

**Hypothesis**: API endpoints that query XML datastores using XPath may be
vulnerable to XPath injection.

**Risk level of test**: MEDIUM.

**Test procedure**:

1. Identify endpoints querying XML data (less common in modern APIs but
   present in legacy systems and XML-based configurations).

2. Test with XPath operators:
   - `' or '1'='1`
   - `' or ''='`
   - `1 and count(/*)>0`

3. Compare responses to identify modified query behavior.

---

#### H-INPUT-14: ORM Injection

**Hypothesis**: API endpoints using ORM frameworks may be vulnerable to
ORM-specific injection through query parameter manipulation.

**Risk level of test**: MEDIUM.

**Test procedure**:

1. Identify ORM usage from error messages, framework detection, or known
   technology stack.

2. Test ORM-specific injection vectors:
   - **Sequelize**: `?where[id][$gt]=0`
   - **Hibernate**: HQL injection through string parameters
   - **Django ORM**: `?field__contains=value`, `?field__gt=0`
   - **ActiveRecord**: `?filter[id]=1 OR 1=1`

3. Test for parameter manipulation that bypasses ORM query building:
   ```json
   {"filter": {"id": {"$gt": 0}}}
   ```

---

#### H-INPUT-15: Unicode Normalization Bypass

**Hypothesis**: Unicode normalization differences between validation and
processing layers may allow input filter bypasses.

**Risk level of test**: LOW.

**Test procedure**:

1. Test with Unicode characters that normalize to ASCII equivalents:
   - `%EF%BC%9C` (fullwidth less-than) for `<`
   - `%EF%BC%9E` (fullwidth greater-than) for `>`
   - `%E2%80%8B` (zero-width space) within filtered words
   - Homoglyph characters for filtered strings

2. Check if validation rejects the input but the processing layer normalizes
   and uses it.

3. Test Unicode in:
   - File path parameters (traversal with Unicode path separators)
   - SQL injection bypass (Unicode quotes and operators)
   - XSS payload bypass through Unicode normalization

---

