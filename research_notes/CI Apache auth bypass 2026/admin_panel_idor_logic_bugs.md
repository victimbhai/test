# Advanced Techniques for Finding IDOR, Business Logic, and Access Control Vulnerabilities in Hardened Admin Panels

## IDOR Techniques for Admin Panels (2024-2026)

### Takeaway
IDORs remain prevalent in admin panels because they cannot be detected by automated scanners and require manual, creative testing. Even UUIDs do not eliminate IDORs if those UUIDs leak through other endpoints; the key techniques are authorization testing with Autorize, historical endpoint discovery via Wayback Machine, and enumerating leaked references in application responses.

### Cited Findings
- IDORs cannot be detected by automated tools alone and require creativity and manual security testing. UUIDs do not fix the problem since if a UUID leaks through another endpoint, the IDOR vulnerability persists. -- [Instatunnel Substack: The $1 Billion Authorization Bug](https://instatunnel.substack.com/p/insecure-direct-object-references)
- The Burp Suite extension Autorize automates authorization checks: you give it a low-privileged user's cookies while browsing as a high-privileged user, and it replays every request with the low-privileged session to detect authorization failures. -- [Instatunnel Substack](https://instatunnel.substack.com/p/insecure-direct-object-references)
- Using archived URLs (Wayback Machine, Waymore) to find old endpoints, then filtering for keywords like "admin" or "manager" reveals likely high-value paths that may still be accessible. -- [BrutSecurity Telegram](https://t.me/s/brutsecurity?after=596)
- Account management endpoints are high-payout targets because of their potential for user addition, deletion, and privilege escalation. -- [Claude BugHunter Skill (aggregated from 26 public reports)](https://claudskills.com/skills/hunt-idor/SKILL.md)
- An admin panel located at an unpredictable URL was disclosed somewhere in the application's source code, leading to full access. -- [DEV Community: Broken Access Control IDOR](https://dev.to/sainsec/broken-access-control-idor-c7n)
- Joseph Thacker argues that IDORs with unpredictable IDs are still valid and should be fixed, and that read/write IDORs on user objects for other organizations would be rated Critical on most programs. -- [Joseph Thacker: Unpredictable IDORs](https://josephthacker.com/hacking/cybersecurity/2022/08/18/unpredictable-idors.html)
- UUIDv4 makes enumeration harder but does not replace authorization checks; UUIDs might appear in public places like profile pages, comments, forum posts, or shared links. A UUID might also be derived from a predictable value such as an MD5 of an email or username. -- [InfoSec Writeups: Why IDORs Are Everywhere](https://infosecwriteups.com/why-idors-are-everywhere-and-how-to-find-them-3ba45128e0f3)
- Common document-related parameter names to test for IDOR include `doc=`, `file=`, `document_id=`, `report=`, `invoice=`, `id=`. -- [IDOR Cheat Sheet (Notion)](https://jasper-join-7e5.notion.site/IDOR-Cheat-Sheet-9f7c9e3285bf4c7cae5ea38243cd0391)

### Inferences
- For the specific /document endpoint context: test sequential numeric IDs, attempt accessing other users' documents by changing the ID parameter, check if UUIDs are derived from predictable values (e.g., MD5 of filename or user ID), and look for document ID leaks in other API responses.
- Horizontal privilege escalation (user A accessing user B's documents) is testable by creating two accounts and swapping document IDs between them.
- Vertical privilege escalation (regular user accessing admin documents) requires obtaining any admin document ID -- check error messages, API responses, or application source for leaks.

### Gaps
- No specific HackerOne/Bugcrowd disclosed report from 2024-2026 was found that details an admin panel IDOR with bounty amounts.
- No specific writeup found for CodeIgniter-based admin panel IDOR exploitation.


## Business Logic Vulnerabilities in Admin Panels

### Takeaway
Business logic vulnerabilities in admin panels center on missing server-side enforcement of UI restrictions, race conditions in state-changing operations (especially invitation/role workflows), and failure to re-validate authorization at every step of multi-step processes. Race conditions using single-packet attacks via Turbo Intruder are a particularly effective modern technique.

### Cited Findings
- A $1,500 bounty was paid for a business logic flaw where the UI hid the management section from lower-privileged users but the API still accepted their requests. The backend never enforced the same restrictions the UI did. -- [InfoSec Writeups: $1,500 Bounty Business Logic Flaw](https://infosecwriteups.com/1-500-bounty-business-logic-flaw-in-project-secrets-management-4b985175071e)
- Race conditions often lead to severe impacts such as bypassing business logic, escalating privileges, or stealing funds, and are readily overlooked by code reviews and automated scans. -- [YesWeHack: Ultimate Guide to Race Condition Vulnerabilities](https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities)
- A single-endpoint race condition let an attacker claim a reserved email invitation and gain admin access via an email update. -- [InfoSec Writeups: Single Endpoint Race Conditions](https://infosecwriteups.com/single-endpoint-race-conditions-7a3879c09e79)
- A race condition combined with broken access control let blocked accounts onboard. A separate finding showed the resend-invite action generated a fresh token but never re-validated the staff limit. -- [InfoSec Writeups: $10,800 Business Impact Bug](https://infosecwriteups.com/how-i-found-a-10-800-business-impact-bug-race-condition-broken-access-control-de40c9897e91)
- Applications that check permissions when an invite is created but not when it is accepted are vulnerable: code performs authorization checks at invitation creation but fails to repeat them at acceptance. -- [Intigriti: Exploiting Business Logic Error Vulnerabilities](https://intigriti.com/researchers/blog/hacking-tools/exploiting-business-logic-error-vulnerabilities)
- Testing should include checking role parameters during registration, whether privileges persist after a downgrade, and whether invitations can grant more access than the inviter holds. -- [AppSecure Security: Business Logic Flaws](https://www.appsecure.security/blog/business-logic-flaws-unseen-risk-modern-applications)
- Not all undocumented behavior is a security bug. Check whether a logic flaw actually affects confidentiality, integrity, or availability before reporting. -- [Intigriti](https://intigriti.com/researchers/blog/hacking-tools/exploiting-business-logic-error-vulnerabilities)

### Inferences
- For the CodeIgniter admin panel context: test whether changing a user's role via the admin panel API endpoint works when called by a non-admin session. Test race conditions on document status changes, user role modifications, and any multi-step approval workflows.
- Race condition testing methodology: use Burp Suite's Turbo Intruder with single-packet attack (sending multiple requests in one TCP packet to achieve simultaneous server-side processing). Target state-changing endpoints like role assignment, document approval, and account activation.
- Price/quantity manipulation: intercept admin panel requests that modify billing, quotas, or resource limits and attempt to set values outside expected ranges.

### Gaps
- No specific race condition bounty writeup was found for CodeIgniter or PHP-based admin panels specifically.


## Mass Assignment Techniques for Privilege Escalation in PHP Frameworks

### Takeaway
Mass assignment in PHP frameworks occurs when controllers bind HTTP request parameters directly to model properties without restricting which fields can be modified. In CodeIgniter specifically, the `$allowedFields` model property is the primary defense, and its absence or misconfiguration allows privilege escalation by adding parameters like `role=admin` or `is_admin=1` to POST requests.

### Cited Findings
- OWASP describes mass assignment as automatic binding of HTTP request parameters to internal objects, where permission-related properties such as `is_admin`, `role`, or `approved` should only be set by privileged users. Testing involves comparing requests from different user levels and trying administrative parameters as a low-privileged user. -- [OWASP WSTG: Testing for Mass Assignment](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment)
- A PHP User class whose constructor loops over `$_POST` and sets each key as a property allows the `$role` property to be set by any user, even though it should be controlled internally. -- [Medium: Top 10 PHP Vulnerabilities](https://nagvekar.medium.com/top-10-php-vulnerabilities-you-need-to-know-beyond-sql-injection-xss-and-csrf-2dbe8a145b6f)
- In Laravel, passing `$request->all()` directly into `update()` allows a request containing `"is_admin": 1` to grant admin rights. The fix is to use `$fillable` whitelists. -- [LRQA: Explaining Mass Assignment Vulnerabilities](https://lrqa.com/en/cyber-labs/explaining-mass-assignment-vulnerabilities)
- Testing techniques include adding a hidden form field named `role` to the request, or intercepting the request with a proxy and appending the field name and value. -- [LRQA](https://lrqa.com/en/cyber-labs/explaining-mass-assignment-vulnerabilities)
- CVE-2020-10793 reports a privilege escalation in CodeIgniter up to 4.0.0, though it was attributed to a custom module or plugin built on top of CodeIgniter rather than the framework itself. -- [Vulert: CVE-2020-10793](https://vulert.com/vuln-db/CVE-2020-10793)
- DeepStrike lists specific testing techniques: add common admin parameters (`role`, `is_admin`, `admin`, `user_type`, `privilege`, `group_id`, `permissions`) to profile update, registration, and settings endpoints. -- [DeepStrike: Mass Assignment Techniques](https://deepstrike.io/blog/mass-assignment-techniques)

### Inferences
- For CodeIgniter admin panels: check whether the model's `$allowedFields` array is properly configured to exclude sensitive fields. Test by adding `role=admin`, `is_admin=1`, `user_type=administrator`, `group_id=1` to any form submission endpoint (user creation, profile update, settings change).
- Step-by-step testing: (1) Identify all POST/PUT endpoints in the admin panel; (2) Capture a legitimate request with Burp Suite; (3) Add one extra parameter at a time from the list above; (4) Check the response and database state for changes; (5) Pay special attention to user creation and profile update endpoints.
- In CodeIgniter 3.x (which uses the older Active Record pattern), mass assignment is less framework-managed and more likely to be handled ad-hoc by developers, increasing the risk.

### Gaps
- No CodeIgniter 3-specific mass assignment advisory or writeup was found. The CVE-2020-10793 is for CI 4.x and was attributed to a custom module.
- No confirmed bounty amount found for mass assignment in PHP applications specifically.


## Discovering Hidden Admin Functionality

### Takeaway
JavaScript source analysis is the most effective technique for finding hidden admin endpoints and unauthenticated functionality. Tools like LinkFinder extract API endpoints from JavaScript files, and these endpoints frequently lack proper authorization checks because developers assume they are not discoverable.

### Cited Findings
- An admin panel was found by inspecting a JavaScript snippet in the application's source that referenced an unusual endpoint path. Visiting that path gave direct access to the administrator panel without requiring authentication. -- [InfoSec Writeups: Unprotected Admin Functionality with Unpredictable URL](https://infosecwriteups.com/access-control-vulnerabilities-unprotected-admin-functionality-with-unpredictable-url-1a3436277906)
- LinkFinder extracts endpoints from JavaScript files. The workflow is: fetch JavaScript files, run LinkFinder, then fuzz discovered paths with ffuf. -- [YesWeHack: Discover and Map Hidden Endpoints](https://www.yeswehack.com/learn-bug-bounty/discover-map-hidden-endpoints-parameters)
- An endpoint referenced in JavaScript returned 401 Unauthorized, but access was gained after adding an Authorization header from a normal user's request, making it a high-severity finding. -- [The Hackers Log: Hidden API Endpoints](https://thehackerslog.substack.com/p/hidden-api-endpoints-the-hackers)
- JavaScript files commonly contain references to admin-only AJAX endpoints, API keys, internal URLs, debug endpoints, and commented-out features. Common search terms include `/admin`, `/debug`, `/beta`, `/internal`, `/api/v1`. -- [Spectatorguy Newsletter: Hunting Hidden Endpoints](https://spectatorguy.beehiiv.com/p/hunting-hidden-endpoints-advanced-techniques-for-bug-bounty); [Medium: $500 Secrets via JS Analysis](https://hackersatty.medium.com/500-secrets-uncovering-critical-vulnerabilities-with-advanced-javascript-analysis-ab9a970dc8e8)

### Inferences
- For the CodeIgniter admin panel: (1) Download all JavaScript files referenced in the HTML source; (2) Run LinkFinder or manually search for path strings containing `/admin`, `/api`, `/document`, `/user`, `/config`; (3) Look for AJAX endpoint definitions in jQuery or vanilla JS code; (4) Check for commented-out features in HTML/JS source; (5) Test each discovered endpoint with both authenticated and unauthenticated requests.
- CodeIgniter applications typically have controllers mapped to URL segments (e.g., `/controller/method`). Enumerate controller names by reviewing JS source for XMLHttpRequest or fetch calls.
- Incremental ID enumeration: once any document or resource ID is found, attempt sequential values (ID-1, ID+1, etc.) to access adjacent resources.

### Gaps
- No specific bounty amounts were confirmed for hidden endpoint discovery in admin panels.


## Authentication Bypass via Session Puzzling (with OTP + CSRF in Place)

### Takeaway
Session puzzling (session variable overloading) is a server-side vulnerability where the same session variable serves multiple purposes across different application flows, allowing attackers to bypass authentication, OTP, and multi-step verification by populating session state through an unprotected flow and then accessing a protected one.

### Cited Findings
- OWASP describes session puzzling as occurring when an application uses the same session variable for more than one purpose. Outcomes include bypassing authentication enforcement, impersonating users, elevating privileges, and skipping phases of multi-step processes. -- [OWASP WSTG v4.1: Testing for Session Puzzling (WSTG-SESS-08)](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/08-Testing_for_Session_Puzzling.html)
- Shay Chen's 2013 DeepSec talk demonstrated cases where crawling a site populated an attacker's session with values later used for admin authentication enforcement, allowing bypass. -- [DeepSec 2013: The Boomerang Effect](https://blog.deepsec.net/deepsec-2013-talk-the-boomerang-effect-using-session-puzzling-to-attack-apps-from-the-backend)
- Session puzzling can bypass two-factor authentication when the session state set during one flow (e.g., password reset) satisfies the checks of another flow (e.g., login with OTP). -- [Invicti: Two Interesting Session Related Vulnerabilities](https://www.invicti.com/blog/web-security/two-interesting-session-related-vulnerabilities)
- Multiple mechanisms rely on one underlying session variable but interpret it differently in different contexts. For example, a "verified" flag set by email verification might be reused by the OTP verification check. -- [AppCheck-NG: Session Puzzling Attacks](https://appcheck-ng.com/session-puzzling-attacks-a-k-a-session-variable-overloading/)

### Inferences
- For the CodeIgniter admin panel with OTP login: (1) Map all flows that set session variables (login, password reset, registration, profile update, OTP verification); (2) Identify session variables that are shared across flows; (3) Attempt to reach the post-OTP-verified state by completing a different flow first (e.g., complete a password reset flow, then navigate to the admin dashboard without completing OTP); (4) Test whether the OTP verification flag is tied to the specific login attempt or is a generic "verified" flag.
- PHP's native session handling (used by CodeIgniter) stores session data in a single `$_SESSION` superglobal, making session variable overloading more likely when developers use generic key names like `verified`, `authenticated`, `user_role`.
- Parallel session attack: open two browser sessions simultaneously -- complete OTP in one, then check if the other session also gains access (tests whether OTP verification is session-specific or IP/account-wide).

### Gaps
- No specific bug bounty writeup was found demonstrating session puzzling bypassing OTP in a real-world program with confirmed payout.


## Exploiting Non-Rotating CSRF Tokens

### Takeaway
Non-rotating CSRF tokens (tokens that remain static per session) are vulnerable to reuse attacks, cross-user token reuse, and token fixation. While rotating tokens per-request is recommended, many applications use per-session tokens, and several attack techniques exist to exploit this design choice.

### Cited Findings
- CSRF tokens that are not invalidated after use can be replayed. Reuse makes the attack harder to detect because the token remains valid indefinitely during the session. The recommended fix is to invalidate or regenerate the token after each use. -- [Ruby on Rails Security Discussion](https://discuss.rubyonrails.org/t/security-says-csrf-token-should-be-a-nonce/89189)
- CVE-2023-45128 (Go Fiber CSRF middleware): the CSRF token was validated against tokens in storage but not associated with a session, nor by using a Double Submit Cookie Method, allowing token reuse across different users. -- [Vulert: CVE-2023-45128](https://vulert.com/vuln-db/go-github-com-gofiber-fiber-v2-92013)
- A common implementation flaw is generating one token at login and reusing it for the entire session. The token stays the same across page loads, making it vulnerable to extraction via XSS or MITM. -- [PentesterLab: CSRF Token Glossary](https://pentesterlab.com/glossary/csrf-token)
- Phabricator explicitly uses non-rotating "session core" secrets hashed into CSRF tokens, acknowledging that this design choice "won't appreciably improve security but will make the system look more secure." -- [Phabricator T5510](https://secure.phabricator.com/T5510)
- Testing for non-rotating tokens: replay previously issued tokens after logout, after rotation events, or after workflow completion. Check whether state-changing requests still accept them. -- [Escape.tech: CSRF Token Invalidation](https://docs.escape.tech/documentation/reference/vulnerabilities/csrf_token_invalidation/)

### Inferences
- For the CodeIgniter admin panel: (1) Capture a valid CSRF token; (2) Log out and log back in -- check if the same token still works; (3) Test if a token from user A works for user B's session (cross-user reuse); (4) Check if the token is derived from the session ID (making it predictable if the session ID is known); (5) Test CSRF token fixation: set a known token via a login CSRF attack, then use that same token for subsequent CSRF attacks.
- Login CSRF + token fixation chain: force the victim to log in to the attacker's account (login CSRF), the application sets the attacker's CSRF token in the victim's browser, then the attacker can craft CSRF attacks using their known token.
- CodeIgniter's CSRF protection (csrf_protection in config) uses per-session tokens by default in CI3 and has an option for per-request regeneration in CI4 (`csrf_regenerate`). If `csrf_regenerate` is set to FALSE (or not set in CI3), tokens persist for the session duration.

### Gaps
- No specific bug bounty payout found for non-rotating CSRF token exploitation.
- No confirmed research on predicting CodeIgniter CSRF tokens from session IDs.


## Stale/Legacy Endpoint Exploitation

### Takeaway
Legacy endpoints that predate newer security controls (captcha, WAF rules, rate limiting) are a significant attack surface. Techniques include path variant bypass (semicolons, double encoding, case variations), discovering old endpoints through archived URLs, and exploiting the gap between the endpoint's original security posture and the application's current standards.

### Cited Findings
- A security fix was bypassed by adding a semicolon to the endpoint path. The edge proxy rejected the canonical path, but the variant passed through to the backend application. The researcher received a $175 bounty on Bugcrowd. -- [Exploit-DB: Paper 48084](https://www.exploit-db.com/docs/48084)
- CVE-2025-42601 describes an authentication bypass in Meon KYC solutions caused by insufficient server-side Captcha validation. A remote attacker could intercept a request, strip the Captcha parameter, and submit the request without solving the challenge. -- [SentinelOne: CVE-2025-42601](https://www.sentinelone.com/vulnerability-database/cve-2025-42601/)
- Dev/staging subdomains often lack WAF protection. Historical DNS records can expose origin servers through stale A records. -- [The Hackers Log: Bypassing WAFs](https://thehackerslog.substack.com/p/bypassing-wafs-like-a-hacker-tricks)
- Some WAFs only inspect HTTP/1.1 traffic, so HTTP/2 requests can bypass WAF inspection entirely. -- [The Hackers Log](https://thehackerslog.substack.com/p/bypassing-wafs-like-a-hacker-tricks)
- A WAF that did not decode base64 parameters before inspection allowed encoded payloads to bypass filtering. The vendor paid a bounty. -- [Exploit-DB](https://www.exploit-db.com/docs/48084)

### Inferences
- For the CodeIgniter admin panel context (building on the previously reported /admin/. finding): (1) Enumerate path variants: `/admin/./endpoint`, `/admin/;/endpoint`, `/admin/%2e/endpoint`, `/Admin/endpoint` (case variation); (2) Check if legacy endpoints (older controller methods) lack captcha protection that newer ones have; (3) Test if the `/document` endpoint has older, unprotected methods alongside newer protected ones; (4) Use Wayback Machine to find historical endpoints the application once exposed.
- Apache-specific: Apache's `mod_rewrite` and path normalization may handle path variants differently than CodeIgniter's router, creating bypass opportunities. Test trailing slashes, double slashes (`//admin`), URL-encoded paths, and path parameter injection (`;param=value`).
- The `/admin/.` finding suggests Apache path handling inconsistencies -- this pattern should be extended to test all admin sub-paths with similar traversal/normalization tricks.

### Gaps
- No specific writeup found combining stale endpoint + captcha bypass in a CodeIgniter application.


## Document/File-Serving IDOR Exploitation

### Takeaway
File-serving endpoints are high-value IDOR targets because they often expose sensitive documents. The key techniques are sequential ID enumeration, UUID derivation analysis, path traversal in download parameters, and checking for authorization gaps between viewing and downloading.

### Cited Findings
- Predictable IDs (sequential or derived from guessable values like usernames) are the primary weak point in document-serving endpoints. -- [InfoSec Writeups: Why IDORs Are Everywhere](https://infosecwriteups.com/why-idors-are-everywhere-and-how-to-find-them-3ba45128e0f3)
- UUIDs might be derived from predictable values such as an MD5 hash of an email or username, making them calculable rather than random. -- [InfoSec Writeups](https://infosecwriteups.com/why-idors-are-everywhere-and-how-to-find-them-3ba45128e0f3)
- Parameter names commonly used for document retrieval that should be tested: `doc=`, `file=`, `document_id=`, `report=`, `invoice=`, `attachment=`, `download=`, `path=`, `filename=`. -- [IDOR Cheat Sheet (Notion)](https://jasper-join-7e5.notion.site/IDOR-Cheat-Sheet-9f7c9e3285bf4c7cae5ea38243cd0391)
- Read/write IDORs on user objects for other organizations are rated Critical on most programs. -- [Joseph Thacker](https://josephthacker.com/hacking/cybersecurity/2022/08/18/unpredictable-idors.html)

### Inferences
- For the CodeIgniter /document endpoint (previously reported IDOR): (1) If the previous IDOR was fixed with authorization checks, test if the check is comprehensive -- does it verify the user owns the document, or just that the user is authenticated?; (2) Test different HTTP methods (GET vs POST vs PUT) on the same endpoint; (3) Check if the document listing endpoint leaks IDs that can be used in the download endpoint; (4) Test path traversal: `/document/../../../etc/passwd`, `/document/..%2f..%2f`; (5) Check if signed URLs or time-limited tokens are used, and if so, test token reuse and expiration.
- Authorization gap testing: the view/preview function may have authorization checks while the raw download/export function does not (or vice versa).
- Metadata leakage: even if document content is protected, metadata endpoints (file size, upload date, uploader name) may lack authorization checks.

### Gaps
- No specific bug bounty writeup found for document-serving IDOR in CodeIgniter applications.
- No confirmed bounty amounts for file-serving IDOR specifically.


## SMS/OTP Bombing as Reportable Bug Bounty Finding

### Takeaway
Captcha-less OTP endpoints are reportable as SMS flooding vectors in bug bounties when the impact can be demonstrated (financial cost to the target, denial of service, MFA fatigue). The finding is strengthened by demonstrating the absence of rate limiting and captcha on the OTP request endpoint, combined with the per-SMS cost to the organization.

### Cited Findings
- Cyble identified approximately 843 vulnerable API endpoints from e-commerce, financial, government, and telecom organizations, each lacking adequate rate limiting or CAPTCHA protection on OTP endpoints. -- [Cyble via The Cyber Express](https://thecyberexpress.com/tag/captcha/amp/)
- CloudSEK describes the impact of OTP bombing as increased API costs, legal exposure, reputational damage, and the potential for MFA fatigue/exhaustion attacks in account takeover scenarios. The flood can also mask illegitimate login attempts. -- [CloudSEK: Rogue Scripts Exploiting OTP APIs](https://cloudsek.com/threatintelligence/rogue-scripts-are-exploiting-otp-verification-apis-to-send-heaps-of-otp-smses-hold-the-potential-of-triggering-service-disruptions)
- 44 Indian APIs were found exposed to OTP bombing, confirming the scale of the problem in production environments. -- [IANS Live](https://ianslive.in/hackers-using-otp-apis-for-large-scale-sms-bombing-44-indian-apis-exposed--20230828143305)
- Authgear recommends treating the OTP request endpoint like a payment endpoint: require CAPTCHA, per-entity rate limits, and risk scoring before sending any OTP. -- [Authgear: How OTP Bots Bypass SMS 2FA](https://www.authgear.com/post/otp-bots-bypass-sms-2fa/)

### Inferences
- For the CodeIgniter admin panel with OTP login: (1) Test if the OTP request endpoint has captcha protection -- if not, it is a reportable finding; (2) Test rate limiting by sending multiple OTP requests rapidly; (3) Calculate the financial impact: typical SMS cost is $0.01-0.05 per message, so 10,000 requests = $100-500 in SMS costs; (4) Demonstrate that OTP bombing can be used for MFA fatigue attacks (flooding the admin with OTPs until they approve one without verifying); (5) Report the finding with cost impact assessment and proof of concept showing the absence of rate limiting.
- The combination of legacy endpoint (lacking captcha) + OTP request = SMS bombing is a valid chain that elevates the severity of the legacy endpoint finding.
- Programs may consider this out of scope for "denial of service" but in scope for "abuse/fraud prevention" -- check the program's policy.

### Gaps
- No specific bug bounty program policy was found that explicitly addresses SMS OTP bombing as in-scope or out-of-scope.
- No confirmed bounty amount for SMS bombing specifically.


## Information Disclosure Findings Valuable in Bug Bounties

### Takeaway
Information disclosure findings are most valuable when they enable follow-on attacks. Version disclosure leads to CVE lookup and targeted exploitation, internal IP disclosure enables SSRF targeting, stack traces reveal framework details, and user enumeration via different error messages enables credential stuffing. Standalone, these are typically Low severity but become Medium-High when chained.

### Cited Findings
- A malformed input producing a verbose Java stack trace revealed an Apache Struts version, which was then used for CVE lookup. This can be scaled across many subdomains by testing for stack trace disclosure on each. -- [InfoSec Writeups: Exposure Protocol Part 1](https://infosecwriteups.com/exposure-protocol-information-disclosure-in-the-wild-part-1-588de47882b1)
- Internal paths, frameworks, database credentials, API keys, and internal service URLs are commonly found in exposed configuration files and debug endpoints. These facilitate lateral movement and SSRF attacks. -- [VibeAppScanner: Information Disclosure](https://vibeappscanner.com/vulnerability/information-disclosure)
- User enumeration through differing responses (e.g., "invalid password" vs "user not found") is a classic information disclosure that enables targeted credential stuffing. -- [VibeAppScanner](https://vibeappscanner.com/vulnerability/information-disclosure)

### Inferences
- For the CodeIgniter/Apache admin panel: (1) Check server response headers for Apache version, PHP version, CodeIgniter version; (2) Trigger errors by sending malformed requests and check for stack traces revealing internal paths; (3) Test the login endpoint for user enumeration -- different responses for valid vs invalid mobile numbers; (4) Check for phpinfo() pages, debug endpoints, or .env files; (5) Look for internal IP addresses in response headers (X-Forwarded-For, X-Real-IP), HTML comments, or JavaScript source.
- Apache-specific: check for `Server` header version disclosure, `X-Powered-By` header, `.htaccess` misconfigurations that expose directory listings.
- CodeIgniter-specific: check for the default error page that reveals the CI version, test for `application/logs/` directory access, check for `system/` directory exposure.

### Gaps
- No specific bounty amounts found for information disclosure findings in admin panels.
- Programs' valuation of standalone information disclosure varies significantly.


## Chaining Low-Severity Findings into Higher-Severity Reports

### Takeaway
Chaining individually low-severity vulnerabilities into a demonstrated attack path consistently results in higher bounty payouts, with documented examples showing payouts increasing from $500 to $5,000 when chains are demonstrated. The key chains for hardened admin panels are: legacy endpoint + missing captcha = SMS bombing; IDOR + session manipulation = account takeover; information disclosure + brute force = credential stuffing.

### Cited Findings
- Severity scores rate each bug on its own, but attackers measure reachability: what does this finding let me do next, and what does that unlock after it. Multiple individually lower-rated findings combine into working attack paths. -- [Cycode: Attack Chaining](https://cycode.com/blog/attack-chaining/)
- A profile-page leak exposing how reset tokens are built, combined with a missing CSRF check and a missing rate limit on a reset endpoint, enabled full account takeover. -- [ZeroThreat: Low-Risk Vulnerabilities to Critical Attack Chains](https://zerothreat.ai/blog/low-risk-vulnerabilities-to-critical-attack-chains)
- An IDOR plus XSS chain resulted in payout increasing from $500 to $5,000 when the full chain was demonstrated. The vendor initially classified the IDOR alone as medium-severity ($500). -- [InfoSec Writeups: From $500 to $5,000 Chaining IDOR and XSS](https://infosecwriteups.com/from-500-to-5-000-how-chaining-idor-and-xss-led-to-mass-account-takeovers-ethical-hacking-a55de6e59a71)
- A Bugcrowd-focused guide advises writing chains as combined findings, since per the program's "one fix = one bounty" rule they should be evaluated as separate findings whose chain raises the joint severity. -- [Claude BugHunter: Bugcrowd Reporting](https://claudskills.com/skills/bug-chain-builder/SKILL.md)

### Inferences
- Specific chain opportunities for the CodeIgniter admin panel:
  1. **Legacy endpoint + missing captcha = SMS bombing**: If the `/admin/.` legacy endpoint lacks captcha but the main endpoint has it, the legacy endpoint becomes an SMS flooding vector. Severity: Medium (financial impact + DoS).
  2. **IDOR + session puzzling = account takeover**: Combine document IDOR (accessing other users' documents) with session variable overloading to escalate from data access to full account control. Severity: Critical.
  3. **Information disclosure + brute force = credential stuffing**: User enumeration via different error messages for valid/invalid mobile numbers + rate limiting bypass on OTP = targeted account compromise. Severity: High.
  4. **Non-rotating CSRF + login CSRF = session fixation chain**: Force victim to log into attacker's account, then use the known CSRF token for state-changing attacks. Severity: Medium-High.
  5. **Hidden endpoint + missing authorization = privilege escalation**: Discover admin-only endpoints via JavaScript analysis, find they lack per-request authorization. Severity: High-Critical.
- Report framing matters: demonstrate the full chain step-by-step, show the impact clearly, and suggest a severity rating based on the chain rather than individual components.
- Even when individual findings are rated Low or Informational, a working chain that demonstrates account takeover, data exfiltration, or financial loss should be reported as a combined High/Critical finding.

### Gaps
- Not all programs accept chained reports -- some evaluate each finding independently.
- No confirmed bounty amounts for chains specific to CodeIgniter admin panels.


## Step-by-Step Testing Methodology for Hardened Admin Panels

### Takeaway
A systematic approach to testing hardened admin panels combines reconnaissance (JavaScript analysis, endpoint discovery, Wayback Machine), authorization testing (Autorize, role parameter tampering, IDOR on all resource endpoints), business logic testing (race conditions, workflow bypass, session puzzling), and chain building (combining individually low findings into high-impact attack paths).

### Cited Findings
This section synthesizes the methodologies from all sources cited above into a practical testing workflow.

### Inferences
**Phase 1: Reconnaissance**
1. Download and analyze all JavaScript files for hidden endpoints, API paths, and admin-only functionality
2. Use Wayback Machine and Waymore to find historical/legacy endpoints
3. Check server headers for version information (Apache, PHP, CodeIgniter)
4. Map all controller methods by analyzing URL patterns and JS AJAX calls
5. Identify all session-management flows (login, OTP, password reset, registration)

**Phase 2: Authorization Testing**
1. Set up Autorize in Burp Suite with low-privileged user cookies
2. Browse all admin functionality as an admin while Autorize replays with low-priv session
3. Test IDOR on every resource endpoint (documents, users, settings, reports) by swapping IDs
4. Test mass assignment by adding role/admin parameters to every POST/PUT request
5. Test vertical privilege escalation by accessing admin API endpoints with regular user session

**Phase 3: Business Logic Testing**
1. Test race conditions on state-changing operations using Turbo Intruder
2. Test workflow bypass: attempt to skip steps in multi-step processes (e.g., skip OTP, skip approval)
3. Test session puzzling: complete one flow and check if it satisfies checks in another
4. Test price/quantity manipulation on any billing or resource-limit endpoints
5. Test invitation/role flows for re-validation gaps

**Phase 4: Authentication and Session Testing**
1. Test CSRF token reuse: capture token, logout, login, reuse
2. Test cross-user CSRF token acceptance
3. Test OTP endpoint for rate limiting and captcha enforcement
4. Test session fixation and session variable overloading
5. Test parallel session behavior (two simultaneous sessions)

**Phase 5: Chain Building**
1. Document all individual findings, even Low/Informational
2. Map relationships between findings (which finding enables which attack)
3. Build and demonstrate complete attack chains
4. Calculate impact for each chain (data exposure scope, financial cost, account takeover potential)
5. Report chains as combined findings with demonstrated proof of concept

### Gaps
- Testing methodology is synthesized from multiple sources; no single authoritative source covers all these techniques for hardened admin panels specifically.
