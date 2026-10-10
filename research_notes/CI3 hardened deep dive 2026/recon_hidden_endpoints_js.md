# Advanced Reconnaissance and Hidden Endpoint Discovery for Hardened CodeIgniter 3 Applications

## JavaScript Source Code Analysis Techniques for Hidden API Endpoints

### Takeaway
JavaScript files are one of the richest sources of hidden API endpoints because frontend code necessarily references backend routes, even those behind authentication or administrative gates; regex-based tools like LinkFinder and AST-based tools like jsluice can extract these efficiently at scale.

### Cited Findings
- LinkFinder (github.com/GerbenJavado/LinkFinder) is a Python script that uses jsbeautifier combined with a large regex pattern set covering full URLs, absolute/dotted paths, relative paths with slashes, and bare filenames to extract endpoints from JavaScript files -- [LinkFinder on GitHub](https://github.com/GerbenJavado/LinkFinder); [Starlog overview](https://starlog.is/articles/developer-tools/gerbenjavado-linkfinder)
- LinkFinder usage: `-i <url_or_file>` for a single JS file, `-d <domain>` to enumerate and analyze every JS file on a domain, `-r <regex>` to filter output (e.g. `^/api/`), `-c <cookies>` for authenticated targets, and `-b` to read a Burp "Save selected" file -- [Starlog overview](https://starlog.is/articles/developer-tools/gerbenjavado-linkfinder)
- GoLinkFinder is a Go rewrite that adds extraction of AWS/GCP URLs, JWTs, and API keys with customizable regex filters -- [GoLinkFinder on pkg.go.dev](https://pkg.go.dev/github.com/lcalzada-xor/GoLinkfinderEVO)
- AST-based tools like JSParser or Esprima can parse JavaScript's structure, understanding context and semantics, while regex-based approaches like LinkFinder always produce false positives -- [GoLinuxCloud hidden endpoints guide](https://www.golinuxcloud.com/find-hidden-endpoints-examples/)
- jsluice uses tree-sitter parsing and adds secret extraction alongside endpoint discovery, recommended when deeper analysis is needed beyond LinkFinder's regex sweep -- [GoLinuxCloud hidden endpoints guide](https://www.golinuxcloud.com/find-hidden-endpoints-examples/)
- getJS is typically run first to collect JS URLs from a target, then mass-linkfinder runs LinkFinder over the collected list in batch -- [Trickest mass-linkfinder](https://trickest.com/tools/mass-linkfinder)
- JSFinder2 is another alternative, using regex originally derived from LinkFinder -- [JSFinder2 on PyPI](https://pypi.org/project/jsfinder2/)
- Frontend code can expose URLs for supposedly protected features, including internal configurations, secrets, and hidden endpoints -- [Strike.sh pentester guide](https://strike.sh/blog/i-know-the-path-to-your-heart-a-pentesters-guide-to-exposing-hidden-endpoints)

### Inferences
- For a CI3 application, manual regex patterns should target CI3 AJAX conventions: patterns like `/index.php/controller/method`, `/admin/ajax_*`, `/api/v[0-9]/`, and jQuery `$.ajax({url:` or `$.post(` or `$.get(` calls in the JS source
- The recommended workflow is: (1) getJS to harvest all JS URLs, (2) LinkFinder in batch mode for a fast regex sweep, (3) jsluice for AST-based deeper analysis on high-value scripts, (4) manual grep with CI3-specific regex patterns
- Custom regex patterns for CI3 AJAX: `grep -oP '(\/index\.php\/[a-zA-Z_\/]+|\/admin\/[a-zA-Z_\/]+|\/api\/[a-zA-Z_\/]+|url:\s*["\x27][^"]+["\x27])' *.js`

### Gaps
- No detailed documentation found for the original JSParser tool (github.com/nicedude/JSParser) to confirm its current status or exact capabilities
- relative-url-extractor was not found in search results; it may be archived or renamed


## Source Map and Webpack Disclosure Techniques

### Takeaway
Exposed source map files (.js.map) can reverse minified JavaScript back to readable original source code, revealing comments, variable names, API routes, and application logic; even when not explicitly linked from bundles, heuristic discovery of .map files is a viable technique.

### Cited Findings
- When source maps are publicly accessible on production systems, they expose the original, unobfuscated source code including comments, variable names, and application logic that were intended to remain private -- [Invicti scanner documentation](https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/javascript-source-map-detected)
- Source maps don't introduce new secrets since anything in the bundle was already there, but they make the code far easier to read and audit -- [Vibe-eval patterns guide](https://vibe-eval.com/patterns/source-maps-and-git-exposed/)
- Testers check whether `.js.map` files are reachable and whether the bundle references them through `//# sourceMappingURL=` directives -- [Escape vulnerability docs](https://docs.escape.tech/documentation/platform/vulnerabilities/exposed_sourcemap)
- A Claude Code recon skill workflow includes checking for `sourcesContent` fields in maps and running secret scans on the reconstructed source tree -- [Tessl skill registry](https://tessl.io/registry/skills/github/elementalsouls/Claude-BugHunter/hunt-source-leak)
- Fluidattacks rates exposed source maps as Medium severity (CVSS 3.1 base 5.3); Invicti classifies them as Informational -- [Fluidattacks](https://db.fluidattacks.com/wek/236); [Invicti](https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/javascript-source-map-detected)
- Workshop material describes recovering maps even when they are not linked from the bundle, using heuristic naming (appending `.map` to known JS filenames) -- [Eventbrite workshop listing](https://www.eventbrite.com.mx/e/unpacking-the-bundle-weaponizing-webpack-source-maps-for-critical-info-tickets-1983560792727)

### Inferences
- Discovery approach for CI3: (1) View page source and identify all loaded JS files, (2) For each JS file, check the last line for `//# sourceMappingURL=`, (3) Attempt to fetch `<filename>.js.map` for every JS file even without the directive, (4) If maps are found, use `source-map-cli` or browser DevTools to reconstruct the source tree, (5) Search reconstructed source for API endpoints, credentials, and internal routes
- CI3 asset pipeline analysis: CI3 typically serves assets from `/assets/`, `/static/`, or `/public/` directories; check these paths for `.map` files alongside the JS bundles
- Tool command: `curl -sI https://target.com/assets/js/app.min.js.map` to check for existence; `npx source-map-explorer app.min.js app.min.js.map` to analyze

### Gaps
- No CI3-specific guidance found on asset pipeline configurations that might expose source maps differently from generic webpack setups


## Wayback Machine and Archive-Based Historical Endpoint Discovery

### Takeaway
Web archive tools like gau, waybackurls, and waymore can surface deprecated endpoints, old admin panels, and debug pages that were accessible before hardening; these URLs may still resolve or reveal naming patterns for active but hidden functionality.

### Cited Findings
- gau is a passive tool that queries Wayback Machine, Common Crawl, AlienVault OTX, and urlscan for paths, parameters, and endpoints already recorded in public archives -- [Trickest gau tool page](https://trickest.com/tools/gau)
- gau results include historical dead URLs, so results need to be probed for liveness before they can be trusted -- [Trickest gau tool page](https://trickest.com/tools/gau)
- waymore harvests a domain's historical URLs from Wayback Machine, Common Crawl, URLScan, AlienVault OTX, VirusTotal, and Intelligence X, making it broader than gau -- [Trickest waymore tool page](https://trickest.com/tools/waymore)
- Use gau for a lighter URL-only pass and waymore when you need more sources -- [Trickest waymore tool page](https://trickest.com/tools/waymore)
- Archive recon can surface deprecated endpoints: URLs or APIs disabled in production but still accessible, along with old admin panels and debug pages -- [YesWeHack recon series](https://www.yeswehack.com/learn-bug-bounty/recon-wayback-machine-web-archive)
- TheTimeMachine is a Python tool that weaponizes WaybackURLs for recon, vulnerability detection, and sensitive endpoint discovery -- [XEye Academy blog](https://payhip.com/XEyeAcademy/blog/posts/thetimemachine-for-bug-bounties-osint)

### Inferences
- Recommended workflow for CI3 target: (1) `gau target.com | sort -u > gau_urls.txt`, (2) `cat gau_urls.txt | grep -i 'index.php\|/admin\|/api\|/ajax\|/cron\|/migrate\|/debug\|/test'` to filter CI3-relevant paths, (3) `httpx -l filtered_urls.txt -sc -title` to check which historical URLs still respond, (4) `waymore -i target.com -mode U` for broader archive coverage
- Historical robots.txt from Wayback can reveal paths that were once disallowed but have since been removed from the current robots.txt: `curl "https://web.archive.org/web/*/target.com/robots.txt"`
- CommonCrawl can be queried directly via its API: `curl "https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=target.com/*&output=json"` to find indexed URLs
- CI3 applications often expose `index.php/controller/method` URL patterns in archives even when mod_rewrite later hides the `index.php` prefix

### Gaps
- waybackurls (tomnomnom/waybackurls) was not directly documented in search results; its exact feature set versus gau could not be confirmed from primary sources


## Google Dorking for CI3-Specific Endpoints

### Takeaway
Google dorking combines site-scoped searches with CI3 framework indicators (readme.rst, composer.json, index.php patterns) to passively discover exposed functionality, configuration files, and deployment artifacts that survive hardening.

### Cited Findings
- `inurl:readme.rst intext:"CodeIgniter"` (GHDB-4585): CodeIgniter comes with a default offline readme.rst which most installed applications don't remove and gets indexed -- [Exploit-DB GHDB-4585](https://exploit-db.com/ghdb/4585)
- `inurl:composer.json codeigniter -site:github.com` (GHDB-4839): Helps find production sites built on CI3 by targeting their dependency manifest -- [Exploit-DB GHDB-4839](https://www.exploit-db.com/ghdb/4839)
- `inurl:tests/mocks intext:autoloader` (GHDB-4916): Identifies CodeIgniter installations via their test infrastructure -- [Exploit-DB GHDB-4916](https://www.exploit-db.com/ghdb/4916)
- Google dorking is a passive reconnaissance technique that doesn't directly interact with target systems; operators like `site:` limit queries to a specific domain and `inurl:` searches within URLs -- [freeCodeCamp Google dorking tutorial](https://www.freecodecamp.org/news/google-dorking-for-pentesters-a-practical-tutorial/)
- Always obtain explicit permission before testing a website or network; use dorks only against systems you are authorized to assess -- [freeCodeCamp Google dorking tutorial](https://www.freecodecamp.org/news/google-dorking-for-pentesters-a-practical-tutorial/)

### Inferences
- CI3-specific dork set for a target (replace `target.com`):
  - `site:target.com inurl:index.php` -- find all CI3 routed pages
  - `site:target.com filetype:pdf` -- find uploaded/generated documents that may reveal internal paths
  - `site:target.com intitle:"index of"` -- find directory listings
  - `site:target.com inurl:index.php/admin` -- find admin controllers
  - `site:target.com inurl:index.php/api` -- find API controllers
  - `site:target.com ext:sql | ext:env | ext:log | ext:bak` -- find leaked configuration/database files
  - `site:target.com inurl:index.php/user OR inurl:index.php/auth OR inurl:index.php/login` -- find authentication endpoints
  - `site:target.com "CodeIgniter" OR "CI_Controller" OR "Powered by CodeIgniter"` -- find framework disclosure
  - `site:target.com inurl:system/` -- find exposed framework directories
  - `site:target.com filetype:php inurl:application/` -- find exposed application source

### Gaps
- No CI3-specific comprehensive dork list was found in search results; the dork suggestions above are inferred from general CI3 knowledge combined with GHDB entries


## Subdomain and Virtual Host Enumeration

### Takeaway
Certificate Transparency logs, passive DNS, and active brute-forcing together reveal staging environments, API subdomains, and admin-specific hosts that may run less hardened versions of the application or expose additional attack surface.

### Cited Findings
- CT logs are public and list hostnames that have had TLS certificates issued, including forgotten dev and staging hosts that wordlist brute-forcing alone would miss -- [AppSecSanta subdomain finder](https://appsecsanta.com/tools/subdomain-finder)
- CT-based enumeration is passive and sends no traffic to the target, making it a standard first step in authorized testing and bug bounty programs -- [Medium subdomain enumeration guide](https://medium.com/@thexnumb/the-ultimate-guide-to-subdomain-enumeration-for-bug-bounty-hunters-73b60fca62bc)
- CT only covers hosts that had publicly trusted certificates; passive DNS sources can catch HTTP-only hosts and services behind wildcard certs -- [Medium subdomain enumeration guide](https://medium.com/@thexnumb/the-ultimate-guide-to-subdomain-enumeration-for-bug-bounty-hunters-73b60fca62bc)
- A 404 from crt.sh means the service is refusing traffic, not that no certificates exist; a 200 with an empty list is the real "no results" case -- [Medium subdomain enumeration guide](https://medium.com/@thexnumb/the-ultimate-guide-to-subdomain-enumeration-for-bug-bounty-hunters-73b60fca62bc)
- Certspotter is a fallback when crt.sh is rate-limited or slow -- [Medium subdomain enumeration guide](https://medium.com/@thexnumb/the-ultimate-guide-to-subdomain-enumeration-for-bug-bounty-hunters-73b60fca62bc)
- subfinder queries CT logs alongside other passive sources for subdomain enumeration -- [Medium subdomain enumeration guide](https://medium.com/@thexnumb/the-ultimate-guide-to-subdomain-enumeration-for-bug-bounty-hunters-73b60fca62bc)

### Inferences
- Recommended tool chain: (1) `subfinder -d target.com -all -o subdomains.txt` for passive enumeration across CT, DNS, and search engines, (2) `curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u` for direct CT log query, (3) `httpx -l subdomains.txt -sc -title -tech-detect` to probe discovered hosts, (4) Virtual host brute-force with `ffuf -w vhosts.txt -u http://target.com -H "Host: FUZZ.target.com" -fs <default_size>`
- CI3-relevant subdomains to look for: `api.`, `admin.`, `staging.`, `dev.`, `test.`, `internal.`, `cms.`, `portal.`, `backend.`, `legacy.`, `v2.`, `old.`, `beta.`
- Virtual host enumeration is especially important when multiple CI3 apps share a single Apache server; different vhosts may have different hardening levels

### Gaps
- No specific data found on how CI3 applications are commonly deployed across subdomains versus path-based routing


## CI3-Specific Controller and Method Discovery Patterns

### Takeaway
CodeIgniter 3's routing maps URL segments directly to controller classes and methods, making the controller/method naming convention a strong basis for targeted wordlist construction; underscore-prefixed methods have special framework meaning and cannot be called via URL.

### Cited Findings
- CodeIgniter 3 controllers have a special `_output()` method that the output class calls instead of echoing data directly; underscore-prefixed methods have special meaning in CI3 -- [CodeIgniter user guide](https://codeigniter.com/user_guide/incoming/controllers.html)
- A CodeIgniter forum thread discusses how to hide public-facing methods while keeping them reachable by URL, indicating confusion between method visibility and URL routability that a tester might exploit -- [CodeIgniter forum thread](https://forum.codeigniter.com/showthread.php?tid=43762)
- CI3 advisories include XSS filter bypasses and an ODBC driver SQL injection fixed in 3.1.0, useful for version fingerprinting -- [GitLab advisories for CI framework](https://advisories.gitlab.com/pkg/composer/codeigniter/framework)
- CVE-2023-32692 code injection applies to CodeIgniter 4 (fixed in 4.3.5), not CI3 -- [INCIBE-CERT](https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2023-32692)

### Inferences
- CI3 default URL structure: `http://target.com/index.php/controller/method/param1/param2` or with mod_rewrite: `http://target.com/controller/method/param1/param2`
- Common CI3 controller names to enumerate: `welcome`, `home`, `dashboard`, `admin`, `user`, `users`, `auth`, `login`, `api`, `ajax`, `cron`, `migrate`, `test`, `debug`, `reports`, `export`, `import`, `upload`, `download`, `settings`, `config`, `profile`, `search`, `notification`, `notifications`, `email`, `payment`, `payments`, `order`, `orders`, `product`, `products`, `category`, `page`, `pages`, `blog`, `post`, `news`, `contact`, `support`, `ticket`, `tickets`, `help`, `faq`, `about`, `terms`, `privacy`, `sitemap`, `feed`, `rss`, `webhook`, `callback`, `install`, `setup`, `update`, `maintenance`, `tools`, `utility`, `utilities`, `file`, `files`, `media`, `image`, `images`, `gallery`, `document`, `documents`, `log`, `logs`, `error`, `errors`, `monitor`, `health`, `status`, `version`, `info`
- Common CI3 method names to enumerate per controller: `index`, `create`, `store`, `update`, `edit`, `delete`, `destroy`, `show`, `view`, `list`, `all`, `get`, `post`, `save`, `remove`, `search`, `filter`, `export`, `import`, `download`, `upload`, `process`, `callback`, `ajax_list`, `ajax_get`, `ajax_save`, `ajax_delete`, `ajax_search`, `ajax_update`, `get_data`, `get_list`, `get_detail`, `get_by_id`, `check`, `validate`, `verify`, `confirm`, `approve`, `reject`, `activate`, `deactivate`, `enable`, `disable`, `login`, `logout`, `register`, `forgot_password`, `reset_password`, `change_password`, `bulk_action`, `batch`, `test`, `debug`, `info`
- CI3 AJAX endpoint patterns: `/admin/ajax/controller_name`, `/admin/api/resource`, `/admin/controller/ajax_method`, `/controller/get_data`, `/controller/process`
- Methods prefixed with underscore (`_remap`, `_output`) are CI3 framework internals and are NOT directly callable via URL -- testers should not waste attempts on these
- CI3 `_remap()` method can redirect all requests to a single method, making controller-level enumeration less useful if `_remap` is in use; try method-level fuzzing instead

### Gaps
- No comprehensive CI3-specific pentesting guide or wordlist was found in search results
- The behavior of CI3 routing with `.htaccess` rewrite rules (hiding `index.php`) and how this affects enumeration was not documented in the results


## Burp Suite Passive Discovery Techniques

### Takeaway
Burp Suite Professional's content discovery tool uses wordlists and naming pattern derivation to find hidden resources, while extensions like Param Miner and BurpMax add parameter guessing and passive secret extraction from proxied traffic.

### Cited Findings
- Burp Suite Professional has an automated content discovery tool that uses lists of common file and directory names to guess hidden functionality, and also derives a naming scheme from already-identified resources to search for similarly named items -- [PortSwigger documentation](https://portswigger.net:443/burp/documentation/desktop/testing-workflow/mapping/hidden-content/automated-discovery)
- Content discovery is started from Target > Site map by right-clicking the domain root and choosing Engagement tools > Discover content; the site map must be populated first -- [PortSwigger documentation](https://portswigger.net:443/burp/documentation/desktop/testing-workflow/mapping/hidden-content/automated-discovery)
- Burp Intruder can alternatively be used to discover hidden directories, files, and other endpoints -- [PortSwigger documentation](https://portswigger.net:443/burp/documentation/desktop/testing-workflow/mapping/hidden-content/automated-discovery)
- Param Miner extension discovers hidden/unlinked parameters via right-click > Guess Hidden Parameters; custom wordlists tend to perform better than generic ones, and a combination of both is usually recommended -- [Intigriti hidden parameters guide](https://www.intigriti.com/researchers/blog/hacking-tools/finding-hidden-input-parameters)
- BurpMax extension runs passive checks on every proxied response, covering secrets, API keys, and HTML comment leaks -- [GitHub BurpMax](https://github.com/ommirkute/BurpMax)
- RedHunt Labs Asset Discover extension passively parses HTTP responses of in-scope URLs and identifies domains, subdomains, IPs, and S3 buckets -- [GitHub Asset Discover](https://github.com/redhuntlabs/burpsuite-asset_discover)
- JavaScript files processed through Burp may reference specific API endpoints that a regular user would be unable to access through conventional means -- [YesWeHack recon series](https://www.yeswehack.com/learn-bug-bounty/discover-map-hidden-endpoints-parameters)

### Inferences
- Optimal Burp workflow for CI3: (1) Browse the application thoroughly with Burp proxy enabled to populate the site map, (2) Run Content Discovery from the site map root, (3) Run Param Miner on key endpoints like login and admin pages, (4) Review Burp's passive scan results for comments, hidden form fields, and JS references, (5) Use Intruder with CI3-specific wordlist against `index.php/FUZZ` and `index.php/admin/FUZZ`
- Burp's "Backslash Powered Scanner" extension can identify parser differentials in routing -- it sends unusual characters to discover how the backend interprets paths differently than expected

### Gaps
- No specific documentation found on how Burp's content discovery interacts with CI3's routing (e.g., whether it handles `index.php/controller/method` URL structure natively)


## HTTP Response Header Analysis

### Takeaway
Response headers from a CI3 application can leak the server version, PHP version, framework identity, and caching behavior; different endpoints may return different header sets, revealing inconsistencies that point to hidden functionality.

### Cited Findings
- No specific search was conducted for this topic, but cross-references from other searches provide relevant context.
- Strike.sh's pentester guide notes that frontend code can expose information about internal configurations -- [Strike.sh blog](https://strike.sh/blog/i-know-the-path-to-your-heart-a-pentesters-guide-to-exposing-hidden-endpoints)

### Inferences
- Key headers to inspect on a CI3 application:
  - `Server:` -- reveals Apache version (e.g., `Apache/2.4.x`)
  - `X-Powered-By:` -- reveals PHP version (e.g., `PHP/7.4.x`); CI3 does not suppress this by default
  - `Set-Cookie:` -- CI3 default session cookie name is `ci_session`; custom names may reveal application identity
  - `X-CI-*` or custom headers -- some CI3 apps add framework-specific headers
  - `Content-Security-Policy:` -- missing or misconfigured CSP may indicate less-hardened endpoints
  - `X-Frame-Options:`, `X-Content-Type-Options:`, `Strict-Transport-Security:` -- missing security headers on specific paths suggest those paths were added later or have different configurations
- Technique: Compare headers across known endpoints versus discovered endpoints; inconsistencies in security header presence can indicate different controller configurations or middleware stacks
- Command: `curl -sI https://target.com/index.php/path | grep -iE 'server|x-powered|set-cookie|x-frame|content-security|x-content-type'`
- CI3 error pages may return different headers than normal responses, potentially revealing the CI3 version through specific error signatures

### Gaps
- No search was specifically conducted for CI3 header analysis best practices; findings are inferred from general web application testing knowledge


## robots.txt, sitemap.xml, crossdomain.xml, security.txt Analysis

### Takeaway
These well-known files serve as low-hanging fruit for reconnaissance; robots.txt Disallow entries explicitly name paths the site owner wants hidden from crawlers (but not from attackers), while historical versions from web archives can reveal paths that were later removed.

### Cited Findings
- One methodology guide advises checking for a security.txt file before deeper testing: "Before going deeper, check if the target publishes a security.txt file"; this often reveals scope boundaries and points of contact -- [Bug bounty recon methodology](https://bug-bounties.as93.net/learn/bug-bounty-recon-methodology)
- A pentest cheatsheet lists fetching robots.txt as a basic directory discovery step using `curl -s $url/robots.txt` -- [N4C cheatsheet](https://n4c.hadi.icu/cheatsheets/web/discovery)
- One recon tool lists robots.txt and sitemap discovery as built-in features alongside OpenAPI/Swagger and GraphQL endpoint discovery -- [Huggingface authorized-recon](https://huggingface.co/Maiks71/authorized-recon)
- The scope definition shapes the entire recon approach; well-known files help identify what is and isn't in scope -- [Bug bounty recon methodology](https://bug-bounties.as93.net/learn/bug-bounty-recon-methodology)

### Inferences
- Full checklist of well-known files to probe on CI3 targets:
  - `/robots.txt` -- Disallow entries name hidden paths
  - `/sitemap.xml` or `/sitemap_index.xml` -- enumerates public pages and may include admin or API sections accidentally
  - `/.well-known/security.txt` or `/security.txt` -- security contact and scope info
  - `/crossdomain.xml` -- Flash cross-domain policy; lists domains allowed to interact, revealing related services and APIs
  - `/clientaccesspolicy.xml` -- Silverlight equivalent; may list internal domain names
  - `/.well-known/openid-configuration` -- if the CI3 app is an OAuth provider
  - `/swagger.json` or `/openapi.json` or `/api-docs` -- API documentation that may be accidentally exposed
  - `/phpinfo.php` or `/info.php` -- PHP info page left from development
- Historical robots.txt from Wayback: `curl "https://web.archive.org/web/2020*/https://target.com/robots.txt"` to find paths that were disallowed in previous versions but removed from current robots.txt
- CI3 applications sometimes list `/system/`, `/application/`, `/user_guide/` in robots.txt, confirming the framework and revealing directory structure

### Gaps
- crossdomain.xml analysis was not covered in any search result; its relevance has diminished with Flash's end-of-life, but the file may still exist on older applications
- clientaccesspolicy.xml was similarly absent from results


## Parameter Discovery for Hidden Parameters

### Takeaway
Tools like Arjun, Param Miner, and x8 can discover undocumented parameters on known endpoints, potentially unlocking hidden functionality, debug modes, or access control bypasses on a hardened CI3 application.

### Cited Findings
- Arjun (github.com/s0md3v/Arjun) is a Python tool for finding hidden HTTP parameters; it uses a default wordlist (which users can modify), is multi-threaded, handles rate limiting, accepts custom headers, and supports GET, POST, XML, and JSON methods -- [Intigriti Arjun guide](https://www.intigriti.com/researchers/blog/hacking-tools/hacker-tools-arjun-the-parameter-discovery-tool)
- Param Miner is a Burp Suite extension that discovers hidden/unlinked parameters and is specifically useful for finding Web Cache Poisoning related vulnerabilities -- [Intigriti hidden parameters guide](https://www.intigriti.com/researchers/blog/hacking-tools/finding-hidden-input-parameters)
- x8 is a blazing-fast, Rust-powered hidden parameter discovery suite -- [Intigriti hidden parameters guide](https://www.intigriti.com/researchers/blog/hacking-tools/finding-hidden-input-parameters)
- ParamSpider can find parameters from web archives, subdomains, and other sources -- [Intigriti hidden parameters guide](https://www.intigriti.com/researchers/blog/hacking-tools/finding-hidden-input-parameters)
- Custom wordlists tend to do better than generic ones for parameter discovery, and a combination of both is usually recommended -- [Intigriti hidden parameters guide](https://www.intigriti.com/researchers/blog/hacking-tools/finding-hidden-input-parameters)

### Inferences
- Arjun usage for CI3: `arjun -u https://target.com/index.php/controller/method -m GET` for GET parameters; `arjun -u https://target.com/index.php/controller/method -m POST` for POST; `arjun -u https://target.com/index.php/controller/method -m JSON` for JSON API endpoints
- CI3-specific parameters to test: `debug`, `test`, `verbose`, `format`, `callback`, `jsonp`, `token`, `api_key`, `key`, `secret`, `admin`, `role`, `is_admin`, `bypass`, `mode`, `env`, `config`, `lang`, `language`, `page`, `limit`, `offset`, `sort`, `order`, `fields`, `include`, `expand`, `embed`, `filter`, `q`, `search`, `export`, `download`, `action`, `type`, `status`, `raw`, `preview`, `draft`, `version`
- ParamSpider for archive-based parameter discovery: `paramspider -d target.com` collects parameters from archived URLs
- Combine with: `gau target.com | grep '?' | unfurl keys | sort -u` to extract historical parameter names

### Gaps
- x8 tool documentation and specific command syntax were not found in search results


## CI3 Error Page Information Disclosure

### Takeaway
CI3 error pages can leak controller names, PHP versions, file paths, and framework version information depending on the environment configuration and custom error handling.

### Cited Findings
- CI3 advisories include known XSS filter bypasses and SQL injection issues that are version-specific, making error signatures useful for fingerprinting the exact CI3 version -- [GitLab CI3 advisories](https://advisories.gitlab.com/pkg/composer/codeigniter/framework)

### Inferences
- CI3 environment-dependent error behavior:
  - `ENVIRONMENT = 'development'`: Full PHP error reporting, stack traces with file paths, CI3 error templates showing controller/method names
  - `ENVIRONMENT = 'production'`: Suppressed errors, but custom 404 pages may still leak controller names in the URL or error message
- Probing techniques:
  - Request non-existent controller: `GET /index.php/nonexistent_controller_xyz` -- CI3 may show "404 Page Not Found" with specific styling that differs from Apache's 404
  - Request non-existent method on known controller: `GET /index.php/known_controller/nonexistent_method` -- may produce a different error than a non-existent controller, confirming the controller exists
  - Request with wrong HTTP method: `POST /index.php/controller/method` when GET is expected -- may produce a method-specific error
  - Request with excessive path segments: `GET /index.php/controller/method/a/b/c/d/e/f/g` -- may trigger parameter count errors
  - Request with special characters: `GET /index.php/controller/method/%00` -- null byte may trigger framework-specific error handling
- The difference between "controller not found" (Apache/CI3 404) versus "method not found" (CI3 error) versus "method exists but access denied" (CI3 403 or redirect) can be used as an oracle for controller/method enumeration

### Gaps
- No specific CI3 error signature database was found in search results
- The exact error messages produced by different CI3 versions were not documented in the search results


## Certificate Transparency Log Analysis

### Takeaway
CT logs provide a passive, no-traffic method to discover subdomains, staging environments, and internal hostnames that have received TLS certificates, potentially revealing less-hardened instances of the CI3 application.

### Cited Findings
- CT logs are public and list hostnames that have had TLS certificates issued, including forgotten dev and staging hosts -- [AppSecSanta](https://appsecsanta.com/tools/subdomain-finder)
- CT-based enumeration sends no traffic to the target -- [Medium subdomain guide](https://medium.com/@thexnumb/the-ultimate-guide-to-subdomain-enumeration-for-bug-bounty-hunters-73b60fca62bc)
- CT only covers hosts that had publicly trusted certificates; passive DNS catches HTTP-only hosts -- [Medium subdomain guide](https://medium.com/@thexnumb/the-ultimate-guide-to-subdomain-enumeration-for-bug-bounty-hunters-73b60fca62bc)

### Inferences
- Primary CT query: `curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u`
- Alternative tools: `subfinder -d target.com -sources crtsh,certspotter`, or `amass enum -passive -d target.com`
- Look for patterns like: `staging-app.target.com`, `dev.target.com`, `api-internal.target.com`, `admin.target.com`, `ci.target.com`, `jenkins.target.com`, `git.target.com`
- Wildcard certificates (`*.target.com`) in CT logs confirm subdomain usage even without revealing specific names
- Historical CT data may show certificates for hosts that no longer resolve but hint at naming conventions

### Gaps
- No CI3-specific CT analysis guidance exists; the technique is framework-agnostic


## DNS Record Analysis (TXT, MX, SPF, DKIM, SRV)

### Takeaway
DNS records passively reveal the target's email provider, SaaS integrations, internal service names, and infrastructure layout; TXT verification records are particularly useful for identifying third-party services and cloud providers.

### Cited Findings
- MX records expose the email provider and can reveal unexpected mail servers or abandoned services; pentesters treat them as likely phishing or exploitation targets -- [CompTIA PenTest+ material via TrustedInstitute](https://trustedinstitute.com/concept/comptia-pentest-plus/reconnaissance-enumeration/dns-reconnaissance/)
- TXT records often reveal SaaS vendors through verification tokens; DMARC and domain verification entries appear among the most useful TXT records for investigators -- [ForensicOSINT DNS guide](https://www.forensicosint.com/guides/dns-lookup-for-osint-investigations)
- SPF evaluation is capped at a limit of 10 DNS lookups; multiple SPF records, excessive lookups, invalid mechanisms, and weak enforcement policies are all checkable -- [DuoCircle DNS scanning techniques](https://www.duocircle.com/blog/12-dns-scanning-techniques-for-domain-intelligence-and-email-security/)
- SRV records can pinpoint specific services like Active Directory or SIP -- [CompTIA PenTest+ material via TrustedInstitute](https://trustedinstitute.com/concept/comptia-pentest-plus/reconnaissance-enumeration/dns-reconnaissance/)
- A CDN can mean an IP address from a lookup may belong to the CDN rather than the organization -- [ForensicOSINT DNS guide](https://www.forensicosint.com/guides/dns-lookup-for-osint-investigations)
- Historical DNS records can show past infrastructure that no longer resolves; pairing with passive DNS data recovers records that reveal past infrastructure -- [ForensicOSINT DNS guide](https://www.forensicosint.com/guides/dns-lookup-for-osint-investigations)
- Misconfigured zone transfer (AXFR) can hand over the full zone, which is a high-severity finding -- [LinuxHandbook dnsrecon guide](https://linuxhandbook.com/enumerate-dns-records-dnsrecon/)

### Inferences
- DNS enumeration commands:
  - `dig target.com ANY +noall +answer` -- all record types
  - `dig target.com TXT +short` -- SaaS verification tokens (e.g., `google-site-verification=`, `MS=`, `v=spf1`, `_dmarc`)
  - `dig target.com MX +short` -- email infrastructure
  - `dig _sip._tcp.target.com SRV +short` -- SIP services
  - `dig _ldap._tcp.target.com SRV +short` -- Active Directory
  - `dnsrecon -d target.com -t std,brt,axfr` -- comprehensive DNS enumeration including zone transfer attempt
  - `dig @ns1.target.com target.com AXFR` -- direct zone transfer attempt
- TXT records revealing infrastructure: SPF `include:` mechanisms list email senders (e.g., `include:_spf.google.com` reveals Google Workspace; `include:amazonses.com` reveals AWS SES)
- SaaS verification tokens in TXT records reveal which services the target uses, potentially identifying additional attack surface (e.g., Salesforce, HubSpot, Atlassian)
- Reverse DNS on discovered IPs can reveal hosting provider and internal naming conventions

### Gaps
- DKIM selector enumeration techniques were not covered in search results; selectors must be guessed or discovered through email headers


## CI3 AJAX Endpoint Patterns

### Takeaway
CI3 applications commonly follow predictable naming conventions for AJAX endpoints, combining controller names with `ajax_` prefixed methods or dedicated AJAX controllers; these patterns form the basis of targeted wordlists.

### Cited Findings
- No specific search was conducted for CI3 AJAX patterns, but findings from the CI3 controller discovery section and JavaScript analysis section apply directly.

### Inferences
- Common CI3 AJAX URL patterns:
  - `/index.php/admin/ajax/get_data`
  - `/index.php/admin/ajax/save_record`
  - `/index.php/admin/api/resource/list`
  - `/index.php/controller/ajax_method_name`
  - `/index.php/controller/get_json`
  - `/index.php/controller/load_more`
  - `/index.php/controller/autocomplete`
  - `/index.php/controller/check_username`
  - `/index.php/controller/validate_form`
  - `/index.php/controller/process_upload`
- CI3 AJAX detection via response headers: AJAX endpoints typically return `Content-Type: application/json` and check for `X-Requested-With: XMLHttpRequest` header; sending requests with and without this header may produce different behaviors
- ffuf command for CI3 AJAX enumeration: `ffuf -w ci3_methods.txt -u https://target.com/index.php/admin/FUZZ -H "X-Requested-With: XMLHttpRequest" -mc 200,302,403 -fc 404`
- CI3 `$this->input->is_ajax_request()` check can be bypassed by adding the `X-Requested-With: XMLHttpRequest` header to direct requests

### Gaps
- No authoritative source was found documenting common CI3 AJAX naming conventions; patterns are inferred from CI3 framework conventions and common development practices


## Priority-Ranked Technique Summary

### Takeaway
Techniques are ranked by their likelihood of revealing genuinely new attack surface on a hardened CI3 application where standard enumeration has been exhausted.

### Cited Findings
- This section synthesizes findings from all sections above.

### Inferences
1. **JavaScript source analysis** (HIGH priority) -- Most likely to reveal hidden endpoints because JS must reference backend routes; use LinkFinder + jsluice + manual CI3 regex patterns
2. **Source map discovery** (HIGH priority) -- If .map files exist, they provide complete source code reconstruction with minimal effort
3. **Archive-based historical endpoint discovery** (HIGH priority) -- Surfaces endpoints that existed before hardening; completely passive and likely to reveal paths not in current wordlists
4. **CI3 controller/method fuzzing with framework-specific wordlist** (HIGH priority) -- CI3's predictable routing makes a well-constructed wordlist highly effective; differentiate controller-not-found vs method-not-found responses
5. **Parameter discovery on known endpoints** (MEDIUM-HIGH priority) -- May unlock hidden functionality (debug modes, export features) on endpoints that are already accessible
6. **Subdomain and vhost enumeration** (MEDIUM priority) -- Staging/dev instances may be less hardened; CT logs and DNS provide passive discovery
7. **Google dorking with CI3-specific queries** (MEDIUM priority) -- May surface indexed pages, configuration files, or deployment artifacts
8. **DNS record analysis** (MEDIUM priority) -- Reveals infrastructure and third-party services passively
9. **Burp Suite passive analysis** (MEDIUM priority) -- Depends on traffic volume captured; best combined with active browsing
10. **Well-known file analysis** (LOW-MEDIUM priority) -- Quick to check but often already covered; historical robots.txt from archives adds value
11. **HTTP header analysis** (LOW priority) -- Useful for fingerprinting but rarely reveals new endpoints directly
12. **CI3 error page analysis** (LOW priority) -- Useful as an oracle during enumeration but not a discovery technique on its own
13. **Certificate transparency** (LOW priority) -- Likely already covered by subdomain enumeration tools; primary value is confirming CT-only hosts
