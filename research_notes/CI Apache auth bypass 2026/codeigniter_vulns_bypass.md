# CodeIgniter Vulnerabilities, Bypass Techniques, and Exploitation Methods (2024-2026)

## Latest CodeIgniter CVEs (2024-2026)

### Takeaway
CodeIgniter 4 has had multiple critical CVEs from 2024-2026 affecting SQL queries, file uploads, path traversal, request validation, and ImageMagick handling. The most critical cluster (three CVEs) was fixed in version 4.7.4 in 2026. Applications running any CI4 version below 4.7.4 should be considered potentially vulnerable.

### Cited Findings

**CodeIgniter 4 Framework (2026):**
- **CVE-2026-63221** (CVSS 9.4, Critical): SQL injection in Query Builder `deleteBatch()` when used with `where()` conditions. The method substitutes bound values from `where()` conditions into generated SQL while ignoring their escape flags. Affects 4.3.0 through 4.7.3. Regular `delete()` is NOT affected. Fixed in 4.7.4. — [Averlon Research](https://research.averlon.ai/vulnerability-intelligence/cve/CVE-2026-63221); [Basefortify](https://basefortify.eu/cve_reports/2026/07/cve-2026-63221.html)
- **CVE-2026-63223** (CVSS 9.8, Critical): Uploaded file extension validation bypass in `is_image` and `mime_in` validation rules. These rules do not independently check the file extension, allowing upload of executable content when the app preserves client filenames and stores in web-accessible directories. Fixed in 4.7.4. — [Averlon Research](https://research.averlon.ai/vulnerability-intelligence/cve/CVE-2026-63223); [CVE.imfht](https://cve.imfht.com/detail/CVE-2026-63223?lang=en)
- **CVE-2026-63222** (CVSS 7.5, High): Path traversal in `UploadedFile::move()` when called without a second argument. Uses unsanitized client filename. Fixed in 4.7.4. — [Rapid7](https://www.rapid7.com/db/vulnerabilities/cve-2026-63222/)
- **CVE-2026-48062** (CVSS 9.8, Critical): The `ext_in` validation rule checked the extension guessed from file content (MIME) rather than the client filename. An attacker could upload `shell.php` containing GIF magic bytes, and `ext_in[avatar,gif]` would pass. Fixed in 4.7.3. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-48062/); [Wiz](https://www.wiz.io/vulnerability-database/cve/cve-2026-48062)
- **CVE-2026-63220**: `IncomingRequest::isSecure()` trusted `X-Forwarded-Proto` and `Front-End-Https` headers from any incoming request, allowing HTTPS spoofing. Most exploitable when backend is reachable directly over HTTP. — [ReleaseAlert](https://releasealert.dev/cve/CVE-2026-63220)

**CodeIgniter 4 Framework (2025):**
- **CVE-2025-54418** (Critical): ImageMagick command injection. Fixed in 4.6.2. — [Packagist Advisories](https://packagist.org/packages/codeigniter4/framework/advisories)
- **CVE-2025-24013** (High): Header name/value validation gap. Fixed version not confirmed from search results alone. — [Packagist Advisories](https://packagist.org/packages/codeigniter4/framework/advisories)

**CodeIgniter 4 Framework (2024):**
- **CVE-2024-29904** (High): Denial of Service vulnerability. Fixed in 4.4.7. — [Packagist Advisories](https://packagist.org/packages/codeigniter4/framework/advisories)

**CodeIgniter 4 Framework (2023, still relevant):**
- **CVE-2023-32692** (CVSS 9.8, Critical): Remote Code Execution via Validation Placeholders. Affects the Validation library and extends to controller and in-model validation. Network-based, no privileges or user interaction required. CWE-94 (Code Injection). PoC available. Fixed in 4.3.5. — [Averlon Research](https://research.averlon.ai/vulnerability-intelligence/cve/CVE-2023-32692); [Vulert](https://vulert.com/vuln-db/CVE-2023-32692); [OpenCVE](https://www.opencve.io/cve/CVE-2023-32692)

**CI4MS (CodeIgniter 4 CMS, separate project):**
- **CVE-2026-25510** (Critical RCE): Authenticated users with file editor permissions can execute arbitrary PHP. Versions before 0.28.5.0. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-25510/)
- **CVE-2026-34567** (Stored XSS): Blog category content not sanitized. Versions before 0.31.0.0. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-34567/)
- **CVE-2026-35035** (CVSS 7.2, High): Company information settings rendered without output encoding on public pages. Versions before 0.31.2.0. — [TheHackerWire](https://www.thehackerwire.com/vulnerability/CVE-2026-35035/)

### Inferences
- The 4.7.4 release is a critical security milestone for CI4; any target running < 4.7.4 should be tested for all three 2026 CVEs.
- CVE-2023-32692 (validation placeholder RCE) remains relevant since many applications may not have upgraded past 4.3.5, and a PoC is publicly available.
- The upload validation bypasses (CVE-2026-48062 and CVE-2026-63223) are particularly dangerous for applications that allow user uploads with preserved filenames in web-accessible directories.

### Gaps
- No CVEs were found specifically for CodeIgniter 3 in the 2024-2026 timeframe. CI3 may still be affected by older unpatched issues since it reached end of life.
- Full details for CVE-2025-54418 (ImageMagick command injection) were not retrieved; the GitHub advisory GHSA-9952-gv64-x94c should be consulted directly.


## CSRF Protection Bypass Techniques

### Takeaway
CodeIgniter's CSRF protection has had two framework-level bypasses (CVE-2022-24712 and CVE-2022-35943), and the non-rotating token design (same token for entire session) creates additional attack surface for token leakage and fixation. The most practical current attacks target the interaction between CSRF and auto-routing.

### Cited Findings
- **CVE-2022-24712**: Versions prior to 4.1.9 allowed CSRF protection bypass. With auto-routing enabled, controllers that did not explicitly check the request method could be exploited. The fix was to upgrade to 4.1.9 and ensure controllers validate the HTTP method before processing. — [GitHub Advisory GHSA-4v37-24gm-h554](https://github.com/codeigniter4/CodeIgniter4/security/advisories/GHSA-4v37-24gm-h554)
- **CVE-2022-35943 (CodeIgniter Shield)**: SameSite attackers can bypass CSRF protection when they control a subdomain. Works with both `cookie` and `session` CSRF protection modes. Fixed in CI4 4.2.3 and Shield 1.0.0-beta.2. — [GitHub Advisory GHSA-5hm8-vh6r-2cjq](https://github.com/codeigniter4/shield/security/advisories/GHSA-5hm8-vh6r-2cjq)
- CodeIgniter's CSRF tokens in CI3 are non-rotating by default (same token valid for entire session). This is configurable via `$config['csrf_regenerate']` but many applications leave it as `FALSE`. — Based on CodeIgniter 3 documentation and default configuration.

**General CSRF bypass techniques applicable to CI deployments:**
- Method switching (POST to GET): If the endpoint accepts GET requests but only validates CSRF on POST. — [LinkedIn Article](https://www.linkedin.com/pulse/find-valid-impactful-csrf-vulnerabilities-bug-bounty-bypass-mon-saji)
- Token removal or blank value: Some implementations fail open when the token parameter is absent entirely.
- Setting the token value to `undefined` or null.
- Token leakage via Referer header when the CSRF token is embedded in URLs.

### Inferences
- The non-rotating token design in CI3 (and CI4 when `$csrfRegenerate` is false) means a leaked token remains valid for the entire session duration, making Referer-based leakage more impactful.
- The SameSite bypass (CVE-2022-35943) is particularly relevant for targets with subdomains, such as `api.example.com` or `staging.example.com`.
- Testing should focus on whether CSRF validation is applied uniformly across all state-changing endpoints, especially those accessible via auto-routing.

### Gaps
- No public technique was found for CSRF token prediction in CodeIgniter specifically.
- No bug bounty writeup was found demonstrating CSRF bypass on a hardened CodeIgniter target.


## Session Handling Vulnerabilities

### Takeaway
CodeIgniter has two notable session-related CVEs: a session fixation flaw in CI3 (CVE-2018-12071) and a cross-cookie session access issue in CI4 (CVE-2022-46170). Both are fixed in relatively old versions, but applications that have not upgraded remain vulnerable.

### Cited Findings
- **CVE-2018-12071** (Session Fixation, CI3): Mishandling of `session.use_strict_mode` in versions prior to 3.1.9. Allows an attacker to fix or set the session ID. One source rates it CVSS 9.8; another assigns no score. No known public exploits reported in the wild. Fixed by upgrading to 3.1.9+. — [Vulert](https://vulert.com/vuln-db/CVE-2018-12071)
- **CVE-2022-46170** (CI4, Cross-Cookie Access): When an application uses multiple session cookies (e.g., user and admin) with database/Memcached/Redis session handlers, possession of one cookie grants access to pages requiring the other. Fixed in 4.2.11. Workaround: use only one session cookie. — [OSV](https://osv.dev/vulnerability/CVE-2022-46170); [Averlon Research](https://research.averlon.ai/vulnerability-intelligence/cve/CVE-2022-46170)

### Inferences
- CI3 applications running below 3.1.9 are vulnerable to session fixation, which could be chained with other flaws for full account takeover.
- The cross-cookie issue (CVE-2022-46170) is most relevant in applications with separate admin/user session cookies, a common pattern in enterprise CI4 deployments.
- Cookie-based session storage in CI3 (the default in older versions) is fundamentally weaker than server-side storage, as the session data can be decoded client-side (it is base64-encoded, optionally encrypted).

### Gaps
- No session prediction techniques specific to CodeIgniter were found in the research.
- No public exploitation of CI3's cookie-based session serialization was found in 2024-2026 writeups.


## Input Filtering Bypass Techniques

### Takeaway
CodeIgniter's `xss_clean()` is a blacklist-based filter with a long history of bypasses (CVE-2012-1915, CVE-2013-4891, and multiple GitHub issues). It should never be relied upon as a primary XSS defense. The differences between `$this->input->post()` and raw `$_POST` also create bypass opportunities.

### Cited Findings
- **CVE-2013-4891** (CI <= 2.1.3): `xss_clean()` only stripped attributes from properly closed HTML tags. Browsers parse unclosed tags leniently, so attributes like `onerror` survived filtering. Fixed in 2.1.4. — [Neal Poole Blog](https://nealpoole.com/blog/2013/07/codeigniter-21-xss-clean-filter-bypass/); [Acunetix](https://www.acunetix.com/vulnerabilities/web/codeigniter-2-1-3-xss_clean-filter-bypass/)
- **CVE-2012-1915** (CI <= 2.1.1): Krzysztof Kotowicz demonstrated bypass via different attribute separators and invalid regexp detecting tag closure too early. The researcher recommended avoiding `xss_clean()` entirely, calling it a blacklist filter that "will therefore unavoidably be bypassable in the future." — [Exploit-DB](https://www.exploit-db.com/exploits/37521); [Kotowicz Blog](http://blog.kotowicz.net/2012/07/codeigniter-210-xssclean-cross-site.html)
- **Keyword filtering bypass** (GitHub #6058): The filter replaces `document.cookie` with `[removed]`. Building the same identifier at runtime from string fragments bypasses this check. — [GitHub Issue #6058](https://github.com/bcit-ci/CodeIgniter/issues/6058)
- **Image map bypass** (GitHub #4877): `<img usemap>` with `<area>` pointing to a `data:` URL produces XSS on click. Reported for CI 3.1.2. — [GitHub Issue #4877](https://github.com/bcit-ci/CodeIgniter/issues/4877)
- Versions before 3.0.3 allowed certain XSS vectors to bypass the Security library's protections. — [GitLab Advisory Database](https://advisories.gitlab.com/pkg/composer/codeigniter/framework)

**`$this->input->post()` vs `$_POST`:**
- `$this->input->post()` applies optional XSS filtering when the second parameter is TRUE. Using `$_POST` directly bypasses all CI input processing.
- In CI4, `$this->request->getPost()` replaces the CI3 input class. The XSS filtering is no longer built into the input class in CI4.

### Inferences
- Any CI3 application relying on `xss_clean()` as its primary XSS defense is likely bypassable with sufficient effort. The function is blacklist-based and has been bypassed repeatedly over more than a decade.
- HTMLPurifier or context-aware output escaping (CI4's `esc()` function) are the recommended replacements.
- Testing should focus on finding endpoints where raw `$_POST` or `$_GET` is used instead of the framework's input methods, as this bypasses all CI filtering.

### Gaps
- No comprehensive, current (2024-2026) bypass payload list for CI3's latest `xss_clean()` implementation was found.
- The exact differences in input handling between CI3 and CI4 for edge cases (e.g., array inputs, nested parameters) were not fully documented in search results.


## Routing and Controller Access Vulnerabilities

### Takeaway
CodeIgniter's Auto Routing (Legacy) feature is the single largest source of routing-related security issues, enabling CSRF bypass, filter bypass, and unintended controller method access. The official documentation explicitly warns against using it.

### Cited Findings
- **Auto Routing (Legacy) dangers**: The official CI4 documentation warns that Auto Routing (Legacy) sends a request using any HTTP method to a controller method, and advises against using it because it is "easy to create vulnerable apps where controller filters or CSRF protection are bypassed." — [CI4 Security Docs](https://codeigniter4.github.io/userguide/concepts/security.html)
- **Filter bypass via alternate URLs**: A filter set on a specific route can be skipped when a controller is accessible via a different URL than the configured route (possible with auto-routing). Method-restricted filters can be sidestepped by calling the controller with an unexpected HTTP method. — [CI4 Security Docs](https://codeigniter4.github.io/userguide/concepts/security.html)
- **CLI routes over HTTP** (pre-4.1.9): An improper input validation vulnerability allowed attackers to execute CLI routes via HTTP requests. Fixed in 4.1.9. — [GitHub Advisory GHSA-4v37-24gm-h554](https://github.com/codeigniter4/CodeIgniter4/security/advisories/GHSA-4v37-24gm-h554)
- **CSRF bypass via auto-routing** (CVE-2022-24712): With auto-routing enabled, controllers that did not check request method before processing were vulnerable to CSRF bypass. Fixed in 4.1.9. — [GitLab Advisory](https://advisories.gitlab.com/pkg/composer/codeigniter4/framework/CVE-2022-24712/)
- **`_remap()` method**: CI3 and CI4 support a `_remap()` method in controllers that overrides normal method routing. If improperly implemented, it can expose methods that were intended to be private. — [CI4 Controllers Docs](https://codeigniter4.github.io/userguide/incoming/controllers.html)

### Inferences
- Any CI4 application still using Auto Routing (Legacy) should be tested for filter bypass by accessing controllers via alternate URL patterns.
- The CLI-over-HTTP issue (pre-4.1.9) is particularly dangerous as CLI commands may perform administrative operations without authentication checks.
- Testing `_remap()` implementations for access control issues is worthwhile, as custom routing logic is often less well-audited than framework routing.

### Gaps
- No specific route parameter injection technique for CodeIgniter was found in search results.
- No public writeup demonstrating `_remap()` abuse for access control bypass was found.


## Hidden Endpoints and Debug Features

### Takeaway
CodeIgniter's Profiler is the primary debug feature that can leak sensitive information if left enabled in production. No hidden or undocumented endpoints were found in the framework itself, but third-party debug bars and migration controllers are common in development setups that get deployed to production.

### Cited Findings
- **CI Profiler**: Displays benchmark results, database queries, `$_POST` data, HTTP headers, config variables, and session data at the bottom of pages when enabled. Loaded automatically by the Output Class when profiling is enabled via `$this->output->enable_profiler(TRUE)`. — [TutorialsPoint](https://www.tutorialspoint.com/codeigniter/codeigniter_application_profiling.htm)
- **CI4 Debug Toolbar**: In CI4, the debug toolbar is controlled by `CI_DEBUG` and `app.baseURL` configuration. It is enabled by default in development environments. It exposes routes, database queries, request/response data, and environment variables.
- **Third-party debug bars**: A community debug bar exists for CI3 (`codeigniter-debugbar`), which uses PHP Debug Bar. — [Ecosyste.ms](https://awesome.ecosyste.ms/projects/github.com%2FTan5en5%2Fcodeigniter-debugbar)

### Inferences
- Testing for the profiler involves checking if `$this->output->enable_profiler(TRUE)` is conditionally enabled based on an IP whitelist or environment variable that could be manipulated.
- In CI4, check if `CI_DEBUG` is set to true in production by looking for the debug toolbar HTML at the bottom of responses.
- Migration controllers (e.g., `/migrate`, `/migration/index`) are not part of the framework but are commonly created by developers and may be left accessible in production.
- Common discovery paths to test: `/index.php/migrate`, `/index.php/test`, `/index.php/debug`, and any CI3 default controller at `/index.php/welcome`.

### Gaps
- No CVE or advisory related to debug feature exposure in CodeIgniter was found.
- No documented hidden endpoint or backdoor in the CodeIgniter framework itself was found.


## File Upload Vulnerabilities

### Takeaway
CodeIgniter 4 has had three critical file upload validation bypasses in 2026 alone (CVE-2026-48062, CVE-2026-63222, CVE-2026-63223), making file upload the most actively exploited attack surface in the framework. The core issue is that validation rules checked MIME-derived extensions instead of client filenames.

### Cited Findings
- **CVE-2026-48062** (CVSS 9.8): The `ext_in` rule used `$file->guessExtension()` (MIME-based) instead of `$file->getClientExtension()` (filename-based). Craft a file named `shell.php` with GIF magic bytes; MIME detector sees `image/gif`, `ext_in[avatar,gif]` passes. Fixed in 4.7.3. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-48062/); [Wiz](https://www.wiz.io/vulnerability-database/cve/cve-2026-48062)
- **CVE-2026-63223** (CVSS 9.8): `is_image` and `mime_in` rules do not independently enforce safe client filename extensions. Remote attacker can upload executable content when the app preserves client filenames and stores in web-accessible directories where PHP can run. Fixed in 4.7.4. — [Averlon Research](https://research.averlon.ai/vulnerability-intelligence/cve/CVE-2026-63223); [GitLab Advisory](https://advisories.gitlab.com/composer/codeigniter4/framework/CVE-2026-63223/)
- **CVE-2026-63222** (CVSS 7.5): `UploadedFile::move()` without a second argument uses unsanitized client filename, enabling path traversal. Fixed in 4.7.4. — [Rapid7](https://www.rapid7.com/db/vulnerabilities/cve-2026-63222/)

**Exploitation conditions (common to all three):**
1. Application preserves client filename (does not use `$file->getRandomName()`)
2. Files stored in web-accessible directory
3. PHP execution enabled in upload directory

**Recommended mitigations from advisories:**
- Upgrade to 4.7.4+
- Save uploads outside web root (e.g., `writable/uploads`)
- Use `$file->store()` or `$file->move($path, $file->getRandomName())`
- Disable script execution in upload directories via `.htaccess` or server config

### Inferences
- File upload is the highest-value target on CI4 applications < 4.7.4. The combination of MIME bypass + path traversal can achieve RCE in a single chain.
- For CI3, the older techniques (double extension like `shell.php.jpg`, null byte `shell.php%00.jpg`) may still work depending on PHP version and server configuration.
- Even on patched versions, test whether the application properly randomizes filenames and restricts the upload directory.

### Gaps
- No specific null byte bypass for CI3 file uploads was confirmed in search results, though this is a general PHP technique pre-PHP 5.3.4.


## Database Query Builder Injection Techniques

### Takeaway
The Query Builder is generally safe when used correctly (values passed as separate arguments are auto-escaped), but two specific bypass patterns exist: the `deleteBatch()` escape flag bug (CVE-2026-63221) and passing user-controlled array keys/structures into `where()` methods.

### Cited Findings
- **CVE-2026-63221** (CVSS 9.4): `deleteBatch()` substitutes bound values from `where()` conditions into SQL while ignoring escape flags. Only `deleteBatch()` is affected; regular `delete()` works correctly. Affects 4.3.0 through 4.7.3, fixed in 4.7.4. — [Averlon Research](https://research.averlon.ai/vulnerability-intelligence/cve/CVE-2026-63221); [OpenCVE](https://app.opencve.io/cve/CVE-2026-63221)
- **CVE-2022-40832**: CI3 up to 3.1.13, injection in `having()` method. Disputed by multiple third parties as not a valid vulnerability. — [Vulert](https://vulert.com/vuln-db/CVE-2022-40832)
- **User-controlled array keys in `getWhere()`**: A CTF writeup (HTB "Insomnia") demonstrated that passing user-controlled JSON keys directly into `getWhere()` allows SQL injection by manipulating the key portion of the where clause. — [CSIRT MUNI Writeup](https://writeups.csirt.muni.cz/content/htb/Challenges/web-insomnia/)
- **Raw SQL in `where()` calls**: CodeIgniter forum threads confirm that placing user input directly into raw SQL strings within `where()` bypasses escaping. The auto-escape only applies to values passed as separate arguments. — [CI Forum](https://forum.codeigniter.com/showthread.php?tid=41827)
- The official documentation states: "values are escaped automatically by the system" -- but this applies to values passed as arguments, not to raw SQL fragments. — [CI4 Query Builder Docs](https://codeigniter.com/user_guide/database/query_builder.html)

### Inferences
- The safest pattern is `$builder->where('field', $value)` (two arguments). Using `$builder->where("field = '$value'")` (one argument with inline value) bypasses escaping entirely.
- Passing user-controlled arrays directly into `where()`, `getWhere()`, or similar methods is dangerous because the array keys become column names and are not escaped.
- `deleteBatch()` with `where()` is the only currently known code path where the Query Builder itself fails to escape properly (as opposed to developer misuse).

### Gaps
- No bypass of the Query Builder's auto-escaping for properly used two-argument `where()` calls was found, suggesting the escaping mechanism itself is sound when used correctly.
- The disputed CVE-2022-40832 for `having()` could not be confirmed or denied from available sources.


## Techniques for Exploiting Hardened CodeIgniter Applications

### Takeaway
When basic vulnerabilities are patched (CSRF everywhere, server-side captcha, no SQL errors, strong headers), exploitation shifts to business logic flaws, race conditions, framework-specific edge cases, and chaining low-severity issues. No single comprehensive guide to hardened CI exploitation was found, but several techniques emerge from the CVEs and advisories.

### Cited Findings
- **Validation Placeholder RCE** (CVE-2023-32692): Even well-secured applications using CI4's built-in validation may be vulnerable to code execution if they use validation placeholders and run CI4 < 4.3.5. This bypasses all application-level security measures. PoC available. — [Averlon Research](https://research.averlon.ai/vulnerability-intelligence/cve/CVE-2023-32692)
- **Upload validation bypass chain**: Combine CVE-2026-48062 (MIME bypass) + CVE-2026-63222 (path traversal) for RCE even on applications with upload restrictions. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-48062/); [Rapid7](https://www.rapid7.com/db/vulnerabilities/cve-2026-63222/)
- **HTTPS spoofing via `isSecure()`** (CVE-2026-63220): On applications that check `isSecure()` for access control decisions (e.g., admin panels only on HTTPS), spoofing via `X-Forwarded-Proto` header can bypass this check. — [ReleaseAlert](https://releasealert.dev/cve/CVE-2026-63220)
- **Auto-routing filter bypass**: Even with filters configured, auto-routing can expose controllers via alternate URL patterns that bypass route-specific filters. — [CI4 Security Docs](https://codeigniter4.github.io/userguide/concepts/security.html)

**Advanced testing approaches for hardened CI targets:**
1. **Version fingerprinting**: Check `system/CodeIgniter.php` for version constants, or identify version from response headers, error page styling, or behavior differences between CI3/CI4.
2. **Configuration leak hunting**: Look for `.env` files, `application/config/database.php` (CI3), or `app/Config/Database.php` (CI4) exposed via misconfigured web servers.
3. **Serialization attacks**: CI3's cookie-based sessions (when not encrypted) contain serialized PHP data. If the encryption key is weak or leaked, session data can be manipulated.
4. **Race conditions**: Test file upload + access sequences, session creation, and multi-step operations for TOCTOU vulnerabilities.
5. **Host header injection**: Test if the application uses `base_url()` or `site_url()` with a spoofable host header for password reset links or redirects.

### Inferences
- The most productive approach on hardened CI targets is to first identify the exact CI version (via error pages, header patterns, or file fingerprinting) and then check against the CVE list above.
- Business logic testing (IDOR, privilege escalation, parameter tampering) remains effective regardless of framework-level hardening.
- CI3 applications are generally more vulnerable than CI4 due to the older codebase, weaker defaults (cookie sessions, `xss_clean()` dependency), and end-of-life status.

### Gaps
- No comprehensive bug bounty writeup for a hardened CodeIgniter target was found in search results. The CodeIgniter bug bounty program on BugBountyHunter shows only 4 total disclosed issues with $0 total paid publicly. — [BugBountyHunter](https://www.bugbountyhunter.com/program?id=codeigniter)
- No PortSwigger Research or Synack Red Team blog posts specifically about CodeIgniter exploitation were found.
- Race condition exploitation techniques specific to CodeIgniter's session or file handling were not documented in any source found.


## Bug Bounty Writeups and Practical Exploitation

### Takeaway
Public bug bounty writeups specifically targeting CodeIgniter are extremely scarce. The most relevant practical exploitation material comes from CTF writeups and the framework's own security advisories rather than traditional bug bounty disclosures.

### Cited Findings
- **HTB "Insomnia" CTF challenge**: Demonstrates SQL injection through `getWhere()` by passing user-controlled JSON keys directly to the query builder, bypassing password checks. — [CSIRT MUNI Writeup](https://writeups.csirt.muni.cz/content/htb/Challenges/web-insomnia/)
- **CodeIgniter Bug Bounty Program**: Shows 4 total issues disclosed with $0 total paid publicly. — [BugBountyHunter](https://www.bugbountyhunter.com/program?id=codeigniter)
- **CSRF-to-Account-Takeover writeup**: A generic CSRF bypass writeup (not CI-specific) demonstrates the technique of method switching and token removal applicable to CI targets. — [Medium - ShellReaper](https://medium.com/@shellreaper/how-i-hunted-my-first-bug-bounty-csrf-to-account-takeover-384ec1607a09)
- **CVE-2023-32692 PoC**: A PoC for the validation placeholder RCE is listed as available on exploit-intel.com. — [Exploit-Intel](https://exploit-intel.com/author/ip-qi)

### Inferences
- The scarcity of public CI-specific bug bounty writeups suggests either: (a) CI targets are uncommon in major bounty programs, (b) findings are not publicly disclosed, or (c) researchers focus on the application layer rather than the framework.
- The CTF writeup (HTB Insomnia) provides the most practical exploitation example for testing query builder misuse in real applications.
- For bug bounty hunters targeting CI applications, the framework-level CVEs (especially upload bypass and validation RCE) are the highest-value initial checks before moving to application-specific testing.

### Gaps
- No HackerOne or Bugcrowd disclosure specifically mentioning CodeIgniter was found in 2024-2026 search results.
- No Synack Red Team or PortSwigger Research content on CodeIgniter was found.
- No comprehensive methodology guide for CI-specific bug bounty hunting was found.
