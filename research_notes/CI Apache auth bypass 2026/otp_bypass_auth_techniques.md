# OTP Bypass and Authentication Bypass Techniques for Bug Bounty Testing (2024-2026)

## OTP Brute-Force and Rate Limiting Bypass

### Takeaway
OTP brute-force remains viable in 2024-2026 when rate limits are absent, per-session rather than per-account, or bypassable via header manipulation or concurrent requests. Multiple CVEs in 2025-2026 confirm this remains a widespread issue with CVSS scores reaching 9.8.

### Cited Findings
- CVE-2026-8760 (WordPress "Login with OTP" plugin): A misplaced rate limit on the validation endpoint left 6-digit OTPs guessable, with CVSS 9.8. Described as a follow-on to an earlier incomplete fix. -- [ZeroPath Blog](https://researcher.branch.zeropath.com/blog/cve-2026-8760-wordpress-login-otp-authentication-bypass)
- CVE-2026-85237 (MISP email OTP): The email OTP verification endpoint had no brute-force protection, and several concurrent sessions could hit the same valid OTP. A patch added failed-attempt counting, a lockout threshold, and invalidation of the OTP after too many failures. CVSS 8.6. -- [OpenCVE](https://app.opencve.io/cve/CVE-2026-85237); [Lutra Security](https://fieldguide.lutrasecurity.com/CVE-2026-85237/)
- CVE-2026-33640 (Outline): Codes were not invalidated after repeated bad submissions and depended entirely on the rate limiter. Bypassing that limiter allowed unlimited guesses within the code's lifetime. Fixed in 1.6.0; CVSS 9.1, CWE-307. -- [GCVE](https://db.gcve.eu/vuln/CVE-2026-33640)
- CVE-2025-56224 (SigningHub v8.6.8): A lack of rate limiting on the OTP verification endpoint allowed bypass via brute force. -- [NVD](https://nvd.nist.gov/vuln/detail/cve-2025-56224)
- Pulse Security analysis of TOTP brute-forcing: An attacker does not need the exact current code, only any code valid in the acceptance window. With a missing limit, an attacker can get in within hours. Real-world software often lacks TOTP attempt limits. -- [Pulse Security](https://pulsesecurity.co.nz/articles/totp-bruting)
- Rate limit bypass via X-Forwarded-For header: Adding an X-Forwarded-For header to requests could toggle around a rate limit on a forgot-password endpoint. -- [System Weakness](https://systemweakness.com/brute-forcing-otp-via-bypassing-rate-limit-c5ee6b25c2a8)

### Inferences
- Rate limits keyed on IP alone can often be bypassed via X-Forwarded-For, X-Real-IP, or X-Originating-IP header rotation.
- Per-session rate limits are weaker than per-account limits because multiple sessions can be opened in parallel.
- The fix must be per-account (not per-session) attempt counters, invalidation of the OTP after a set number of failures, and rate limits on the verification endpoint that cannot be sidestepped.
- Testing approach: Use Burp Suite Intruder or Turbo Intruder to send rapid OTP guesses. Try adding X-Forwarded-For with rotating IPs. Test whether new sessions reset the counter.

### Gaps
- No single authoritative survey of rate-limit bypass techniques across major platforms was found for 2024-2026.


## OTP Response Manipulation

### Takeaway
Response manipulation -- changing server responses from failure to success in transit -- remains one of the most commonly reported OTP bypass classes in bug bounty programs. The root cause is always that the server does not re-validate OTP status on subsequent requests after sending the initial response.

### Cited Findings
- A researcher intercepted the OTP verification request with Burp Suite, set the response to be intercepted, and changed a 500 error to 200 OK before forwarding it, which created the account. -- [Noor Homaid Medium](https://noorhomaid.medium.com/bug-bounty-writeup-2f-otp-bypass-on-registeration-via-response-manipulation-2e53573ffa4c)
- Status-code tampering: A write-up describes a 2FA flow where a 400 Bad Request response was changed to 200 OK. The underlying flaw was that the back-end never properly checked the 2FA code within the session. -- [DEV Community](https://dev.to/blue_byte/2fa-bypass-via-response-manipulation-4062)
- JSON body tampering: Several sources describe servers returning a success or failure flag that the client trusts. Attackers intercept the server's response during email/phone verification and alter the outcome from "verified: false" to "verified: true." -- [Resecurity](https://www.resecurity.com/en/blog/article/methods-to-bypass-otp-in-mobile-apps-successful-vapt-scenarios)
- CVE-2026-56073 (Cap-go): An authentication bypass vulnerability in the OTP verification flow before version 12.128.2, tracked under CWE-345: Insufficient Verification of Data Authenticity. -- [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-56073/)
- Bug bounty methodology list includes: altering the status or response returned by the 2FA check to see whether the app grants access. -- [GitHub - Bug-Bounty-Methodology](https://github.com/tuhin1729/Bug-Bounty-Methodology/blob/main/2FA.md)

### Inferences
- Testing approach: (1) Submit any wrong OTP. (2) In Burp Suite, enable "Intercept Server Responses." (3) Change the HTTP status code from 4xx/5xx to 200. (4) Change JSON body fields like "success": false to "success": true, "verified": false to "verified": true, or "status": "failed" to "status": "ok". (5) Forward the modified response. (6) Check whether the application proceeds to the authenticated state.
- A comparison technique is useful: first capture the response for a valid OTP, then replay the same response structure for an invalid OTP attempt.
- The root cause is always that the server does not maintain server-side session state that tracks whether OTP was actually validated.

### Gaps
- No comprehensive study quantifying how prevalent this class of bug remains across major platforms in 2025-2026.


## OTP Race Condition Techniques

### Takeaway
Race conditions in OTP validation are a confirmed, high-severity vulnerability class in 2025-2026. The pattern is consistent: the check (reading the OTP from the store) and the consumption (deleting or marking it used) happen in separate, non-atomic steps, so parallel requests slip through.

### Cited Findings
- CVE-2026-72584 (fastschema): The account-recovery OTP attempt limit can be bypassed. The system reads the current OTP attempt counter, then, before the counter is updated, accepts additional requests that exceed the intended limit. Rated 7.4 High. Fixed in 0.15.2 where the counter update is atomic. -- [OpenCVE](https://app.opencve.io/cve/CVE-2026-72584)
- CVE-2026-85237 (MISP email OTP login): One code can produce two sessions. The OTP is read from the shared store, validated, and then deleted in separate non-atomic steps. Versions below 2.5.48 affected. -- [OpenCVE](https://app.opencve.io/cve/CVE-2026-85237)
- Parse Server MFA recovery codes: Prior to 8.6.60 and 9.6.0-alpha.54, a single recovery code could be reused through concurrent login requests. Also had a related password-reset token race fixed in 9.6.0-alpha.28 and 8.6.48. -- [OpenCVE references](https://app.opencve.io/cve/CVE-2026-107276)
- Wazuh API login: Brute-force protection on the authentication endpoint can be bypassed by sending concurrent authentication requests. Affected 4.0.0 through versions before 4.14.4. -- CWE-367 listings

### Inferences
- Testing approach: Use Burp Suite's Turbo Intruder or the single-packet attack technique (HTTP/2 multiplexing) to send 20-50 identical OTP verification requests simultaneously with the same valid OTP.
- The single-packet attack sends all requests in a single TCP packet, ensuring they arrive at the server at nearly the same time, maximizing the window for a TOCTOU race.
- Look for signs of race conditions: if the server returns success for more than one request with the same OTP, the check-and-consume is non-atomic.
- The fix must be an atomic check-and-update operation: a conditional database operation (e.g., UPDATE ... WHERE used = false, returning the number of rows affected) or a database transaction with row locking.

### Gaps
- No public tool specifically designed for OTP race condition testing was found; general race condition tools (Turbo Intruder, racepwn) are used.


## OTP Parameter Tampering

### Takeaway
Parameter tampering -- removing, emptying, or type-juggling the OTP parameter -- bypasses OTP validation when the server fails to reject requests with missing or malformed OTP fields. This includes sending empty strings, null values, arrays, and removing the parameter entirely.

### Cited Findings
- Bug bounty methodology lists the following parameter tampering techniques: send a null value in the JSON body; change an "otprequired" parameter from true to false; remove the code, or remove both the code and its parameter; send the email value as an array in JSON; submit an array of many candidate codes in one JSON request (e.g., every value from 1000 to 9999) to exploit a single-request bypass. -- [GitHub - Bug-Bounty-Methodology](https://github.com/tuhin1729/Bug-Bounty-Methodology/blob/main/2FA.md)
- Some apps accept a blank code or null code, bypassing 2FA entirely. -- [OWASP WSTG-ATHN-11](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication)
- A write-up reports that typing 000000 as the OTP allowed access to the website. -- [InfoSec Write-ups](https://infosecwriteups.com/i-typed-000000-as-the-otp-the-website-let-me-in-bc88383479d9)
- Attackers can manipulate the request by removing the OTP parameter entirely. The server fails to reject requests missing OTP. -- [Securium Solutions](https://securiumsolutions.com/otp-bypass-techniques/)
- A FLAT advisory on an OTP PHP library reports that a provisioning URI key written in bracket array form (parameters[label]=hijacked) is stored without running the label validation callback. -- [Fluid Attacks](https://db.fluidattacks.com/vul/FLAT-IP26G/)

### Inferences
- Testing techniques to try systematically:
  1. Remove the OTP parameter entirely from the request
  2. Send an empty string: "otp": ""
  3. Send null: "otp": null
  4. Send boolean: "otp": true
  5. Send zero: "otp": 0
  6. Send all-zeros matching expected length: "otp": "000000"
  7. Send array: "otp": ["1234", "5678"] or otp[]=1234&otp[]=5678
  8. Send array of all possible values: "otp": ["0000", "0001", ..., "9999"]
  9. Send negative number: "otp": -1
  10. Send null byte: "otp": "1234%00"
  11. Change "otprequired" or similar flag parameter from true to false
  12. Send very long string to test for buffer/truncation issues
  13. Send SQL injection payloads: "otp": "' OR '1'='1"
  14. Send NoSQL injection: "otp": {"$gt": ""}
- Type juggling in PHP is especially dangerous: comparison of "0" == false or null == false can cause bypass.
- The fix is strict server-side validation: require the parameter, validate its type and length, reject any request that does not match expected format.

### Gaps
- No comprehensive list of which frameworks are vulnerable to which specific type-juggling or array-injection attacks was found.


## OTP Bypass via Alternate Endpoints

### Takeaway
Applications sometimes expose multiple verification endpoints (web vs. API, mobile API, legacy endpoints, backup endpoints) with inconsistent OTP enforcement. Finding and testing these alternate paths is a reliable bug bounty technique.

### Cited Findings
- Bug bounty methodology: Go straight to a post-login dashboard URL without completing 2FA. If that fails, add a referer-style header to the 2FA page URL and then request the dashboard. -- [GitHub - Bug-Bounty-Methodology](https://github.com/tuhin1729/Bug-Bounty-Methodology/blob/main/2FA.md)
- Mobile banking app: A credential-status API could be queried with a different phone number, and the app then displayed the PIN setup screen for an account it should not have shown. The request and response were encoded with base64. -- [InfoSec Write-ups](https://infosecwriteups.com/bypassing-otp-verification-for-changing-pin-in-registered-mobile-banking-account-ed92dbcaa5c7)
- OWASP WSTG-ATHN-11 test objective: Check whether 2FA can be bypassed by accessing protected endpoints directly. -- [OWASP](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication)
- Attempt login through OAuth to skip 2FA. -- [GitHub - Bug-Bounty-Methodology](https://github.com/tuhin1729/Bug-Bounty-Methodology/blob/main/2FA.md)

### Inferences
- Testing approach:
  1. After receiving the OTP challenge, try directly navigating to the post-authentication URL (e.g., /dashboard, /admin, /home).
  2. Look for mobile API endpoints (e.g., /api/v1/mobile/verify vs. /api/v1/web/verify) that may skip OTP.
  3. Check for legacy or deprecated endpoints (e.g., /api/v1/ vs. /api/v2/) that may lack OTP enforcement.
  4. Test OAuth/SSO login flows that may bypass OTP entirely.
  5. Look for GraphQL endpoints that may have separate authentication logic.
  6. Enumerate API versions and check each for OTP enforcement.
  7. Check if setting the Referer header to the OTP page URL allows access to protected pages.
- The root cause is inconsistent authorization checks across different code paths.

### Gaps
- No systematic study comparing OTP enforcement across web vs. mobile vs. API endpoints for major platforms was found.


## Captcha-less OTP Endpoint Exploitation

### Takeaway
OTP-sending endpoints without CAPTCHA or rate limiting are exploitable for SMS flooding/bombing, cost abuse (SMS pumping), and phone number enumeration. This is both a security and financial risk for the target organization.

### Cited Findings
- CloudSEK's XVigil platform uncovered multiple GitHub repositories referencing global companies' APIs. These APIs allow unlimited OTP SMS messages to be sent to any number, lacking rate limiting or captcha protection. 44 Indian APIs were exposed. Recommended mitigations: implement a captcha-based service to limit bot-based usage and implement rate limiting at the endpoint. -- [CloudSEK](https://cloudsek.com/threatintelligence/rogue-scripts-are-exploiting-otp-verification-apis-to-send-heaps-of-otp-smses-hold-the-potential-of-triggering-service-disruptions); [CRN India](https://www.crn.in/?p=60302)
- BookMyShow rate limit bypass: A rate limit on the OTP endpoint could be defeated by appending whitespace to the phone number, which let OTP requests continue past the limit. This not only allowed an attacker to flood users' SMS inboxes but also posed a financial threat to the company by exhausting its SMS quota. Paid 1000 INR. -- [InfoSec Write-ups](https://infosecwriteups.com/how-i-bypassed-bookmyshows-otp-limit-with-just-a-space-got-1000-for-it-70eab29fb6aa)
- SMS pumping: Attackers send a flood of SMS messages to a large pool of numbers from a specific mobile network operator to receive a share of the communication revenue. -- [ClickSend](https://help.clicksend.com/article/rbjs3q1c2q-otp-attacks)
- OTP bots and MFA fatigue: Fraud kits trigger real OTPs and then socially engineer victims into reading out codes, plus SMS pumping. Recommends adaptive CAPTCHA, entity-level rate limits, and risk scoring. -- [Authgear](https://www.authgear.com/post/otp-bots-bypass-sms-2fa/)

### Inferences
- Testing approach for captcha-less endpoints:
  1. Send multiple OTP requests to the same number and check for rate limiting.
  2. Try phone number variations (with/without country code, spaces, dashes) to see if each is treated as a new request.
  3. Check if different error messages are returned for valid vs. invalid phone numbers (enumeration).
  4. Test if the endpoint is accessible without authentication.
  5. Check if IP-based rate limits can be bypassed with header rotation.
- Financial impact: Each SMS costs the company money; unlimited sending drains budget.
- Enumeration: Different error responses for "number not registered" vs. "OTP sent" reveal valid accounts.

### Gaps
- No quantitative data on the cost impact of SMS flooding attacks on specific companies was found for 2024-2026.


## Phone Number / mobile_number Parameter Manipulation

### Takeaway
Phone number format inconsistencies allow rate limit bypass, OTP redirection, and account enumeration. The core issue is that servers often fail to normalize phone numbers to a canonical form (E.164) before processing.

### Cited Findings
- BookMyShow: Appending whitespace to the phone number bypassed the rate limit because the server treated the modified string as a new request. -- [InfoSec Write-ups](https://infosecwriteups.com/how-i-bypassed-bookmyshows-otp-limit-with-just-a-space-got-1000-for-it-70eab29fb6aa)
- E.164 standard: The canonical form for international phone numbers. Any leading zeros in the national destination code or subscriber number should be removed when converting. Example: UK number becomes +447912345678. -- [Phone Check App](https://phone-check.app/blog/e164-phone-number-format-international-normalization-validation)
- Leading zeros are national trunk prefixes that get dropped for international dialing; some countries have no trunk prefix. A libphonenumber bug report describes a library storing leading zeros as a number type that cannot hold them, causing misparsing. -- [libphonenumber commit](https://git.ruhnet.net/RuhNetConsulting/libphonenumber/commit/a893c9029aeceba94454dbd3609fe620ff126173)
- Deutsche Telekom normalizer: Short numbers and variable-length numbering plans can be misread. Test cases show numbers valid with a leading zero but invalid without one. -- [GitHub - phonenumber-normalizer](https://github.com/telekom/phonenumber-normalizer)

### Inferences
- Testing techniques for phone number manipulation:
  1. With country code: +911234567890 vs. 1234567890 vs. 911234567890
  2. With leading zeros: 01234567890 vs. 1234567890
  3. With spaces: "1234567890" vs. "1234567890 " vs. " 1234567890" vs. "123 456 7890"
  4. With special characters: +91-123-456-7890 vs. (123)4567890
  5. With URL encoding: %2B911234567890
  6. With null bytes: 1234567890%00
  7. With Unicode digits: using full-width digits or other Unicode number forms
  8. Without country code when it is expected, or vice versa
  9. International format variations: 00911234567890 (double-zero prefix instead of +)
  10. Array form: mobile_number[]=1234567890
- Each format variation that the server treats as a distinct number resets rate limits and attempt counters.
- The fix is to normalize all phone numbers to E.164 before any processing (rate limiting, OTP lookup, account matching).

### Gaps
- No specific CVE or disclosed report documenting phone number format bypass for OTP in 2025-2026 was found beyond the BookMyShow case.


## CSRF Token and Session Manipulation in OTP Flows

### Takeaway
When CSRF tokens do not rotate between OTP attempts or between the OTP-request and OTP-verify steps, attackers can exploit session fixation, CSRF, or clickjacking to disable or bypass 2FA.

### Cited Findings
- Bug bounty methodology: Use CSRF or clickjacking to disable 2FA on a victim's account. Check whether enabling 2FA invalidates sessions created before it was turned on. -- [GitHub - Bug-Bounty-Methodology](https://github.com/tuhin1729/Bug-Bounty-Methodology/blob/main/2FA.md)
- Disable 2FA without a 2FA challenge. Reset the password through "forgot password" without 2FA. Perform authenticated actions (profile changes, API create/delete) without solving 2FA. -- [GitHub - Bug-Bounty-Methodology](https://github.com/tuhin1729/Bug-Bounty-Methodology/blob/main/2FA.md)

### Inferences
- Testing approach:
  1. Check if the CSRF token rotates between OTP verification attempts.
  2. Attempt to disable 2FA via a CSRF attack (craft a page that submits the disable-2FA request).
  3. Check if pre-2FA sessions remain valid after 2FA is enabled.
  4. Test session fixation: set a known session ID before OTP verification and see if it persists after.
  5. Check if password reset flow bypasses 2FA requirement.
  6. Test if the OTP verification step is tied to the session that requested it, or if any session can verify.
- Non-rotating CSRF tokens allow replay of the verification request.

### Gaps
- No specific disclosed bug bounty report documenting CSRF token prediction for OTP bypass in 2024-2026 was found.


## Hidden Form Field Manipulation in OTP Flows

### Takeaway
Hidden form fields containing email addresses, phone numbers, or flow-control parameters can be modified to redirect OTP delivery or change the authentication flow.

### Cited Findings
- Bug bounty methodology: Request tokens from two accounts and substitute one account's token into the other. -- [GitHub - Bug-Bounty-Methodology](https://github.com/tuhin1729/Bug-Bounty-Methodology/blob/main/2FA.md)
- Search responses and JavaScript files for 2FA codes or sensitive details such as partially masked phone numbers. -- [GitHub - Bug-Bounty-Methodology](https://github.com/tuhin1729/Bug-Bounty-Methodology/blob/main/2FA.md)
- Mobile banking app: A credential-status API could be queried with a different phone number, and the app then displayed the PIN setup screen for a different account. -- [InfoSec Write-ups](https://infosecwriteups.com/bypassing-otp-verification-for-changing-pin-in-registered-mobile-banking-account-ed92dbcaa5c7)

### Inferences
- Testing approach:
  1. Inspect the OTP verification form for hidden fields (email, phone, user_id, session_token).
  2. Modify hidden email/phone fields to redirect OTP delivery to attacker-controlled contact.
  3. Add extra parameters (e.g., redirect_url, next, callback) to change the post-verification flow.
  4. Cross-account token substitution: request OTP for account A, then submit account A's OTP against account B's verification endpoint.
  5. Check if the server-side ties the OTP to the specific account/phone that requested it, or if any valid OTP works for any account.
  6. Look for the OTP in the HTML source, JavaScript files, or API responses.

### Gaps
- No specific disclosed report documenting hidden field manipulation for OTP redirection in 2025-2026 was found.


## Recent CVEs and Bug Bounty Disclosures (2024-2026)

### Takeaway
Multiple high-severity OTP bypass CVEs were published in 2025-2026, demonstrating that this vulnerability class remains actively exploited and discovered. Common patterns are missing rate limits, non-atomic OTP consumption, and client-side validation trust.

### Cited Findings
- CVE-2026-8760 (WordPress Login with OTP): CVSS 9.8. Misplaced rate limit on validation endpoint. -- [ZeroPath](https://researcher.branch.zeropath.com/blog/cve-2026-8760-wordpress-login-otp-authentication-bypass)
- CVE-2026-85237 (MISP): CVSS 8.6. No brute-force protection on email OTP endpoint; race condition allowing one code to produce two sessions. -- [OpenCVE](https://app.opencve.io/cve/CVE-2026-85237)
- CVE-2026-33640 (Outline): CVSS 9.1. CWE-307. Codes not invalidated after repeated failures. -- [GCVE](https://db.gcve.eu/vuln/CVE-2026-33640)
- CVE-2025-56224 (SigningHub): Lack of rate limiting on OTP verification endpoint. -- [NVD](https://nvd.nist.gov/vuln/detail/cve-2025-56224)
- CVE-2026-56073 (Cap-go): Authentication bypass in OTP verification flow. CWE-345. -- [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-56073/)
- CVE-2026-72584 (fastschema): CVSS 7.4. Account-recovery OTP attempt limit bypass via race condition. -- [OpenCVE](https://app.opencve.io/cve/CVE-2026-72584)
- CVE-2026-107276 (Parse Server): MFA recovery code reuse through concurrent login requests. -- [OpenCVE](https://app.opencve.io/cve/CVE-2026-107276)
- Bug bounty writeup: OTP bypass on registration via response manipulation (changing 500 to 200). -- [Noor Homaid](https://noorhomaid.medium.com/bug-bounty-writeup-2f-otp-bypass-on-registeration-via-response-manipulation-2e53573ffa4c)
- Bug bounty writeup: OTP bypass in public bug bounty program via client-side validation. -- [InfoSec Write-ups](https://infosecwriteups.com/otp-bypass-bug-in-public-bug-bounty-program-5554eafc18ab)
- Bug bounty writeup: Typing 000000 as OTP granted access. -- [InfoSec Write-ups](https://infosecwriteups.com/i-typed-000000-as-the-otp-the-website-let-me-in-bc88383479d9)
- Comprehensive OTP bypass methods guide. -- [Medium - Arrhenius](https://medium.com/@arrheniuspaelongan09/otp-bypass-methods-bug-bounty-4a988573c12a)
- Rate limit brute-force bypass writeup. -- [InfoSec Write-ups](https://infosecwriteups.com/rate-limit-i-barely-know-her-how-i-brute-forced-otps-like-a-gentleman-6f1235c559cc)

### Inferences
- The most impactful findings cluster around three patterns: (1) missing or bypassable rate limits (CVSS 9.1-9.8), (2) race conditions in OTP consumption (CVSS 7.4-8.6), and (3) client-side validation trust (variable severity).
- WordPress plugins remain a rich target for OTP bypass research.
- Open-source platforms (MISP, Outline, Parse Server, fastschema) publish detailed advisories that serve as learning resources.

### Gaps
- HackerOne and Bugcrowd disclosed report databases could not be searched directly in this research; the findings above come from public blog posts, CVE databases, and vendor advisories.
- PortSwigger Research did not appear in search results for OTP-specific research in 2024-2026, though their general authentication testing methodology is well-established.
