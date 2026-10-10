# Vulnerability Chaining Strategies: Escalating Low/Informational Findings to Critical/High Severity for Bug Bounties

## What vulnerability chains turn user enumeration + password reset enumeration into account takeover?

### Takeaway
User enumeration (F1, F2) is the reconnaissance foundation that enables targeted credential stuffing, password spraying, and social engineering chains. When combined with rate-limiting gaps, OTP weaknesses, or IDOR flaws, enumeration escalates from P4/informational to P1-P2 account takeover severity.

### Cited Findings
- Facebook paid $40,000 for a chain where user ID exposure via email/phone enumeration was combined with brute-forcing phone verification codes to achieve password reset account takeover. The researcher appealed the initial payout and it was raised. -- [SecurityWeek](https://www.securityweek.com/facebook-pays-out-40000-account-takeover-exploit-chain/amp/)
- Meta paid $27,200 for brute-forcing an SMS verification PIN through a rate-limiting gap, and a separate phone-number account-recovery bug earned $163,000 (Meta's highest bounty at the time). -- [Bitdefender](https://www.bitdefender.com/en-gb/blog/hotforsecurity/meta-pays-out-bounties-for-account-takeover-and-two-factor-authentication-bypass-exploits)
- A researcher chained login API enumeration (response time + error text differences) with an insecure reset token (worked across accounts), no OTP verification, and no rate limiting to achieve full account takeover. -- [InfoSec Write-ups: Chaining Vulnerabilities Lead to Account Takeover](https://infosecwriteups.com/chaining-vulnerabilities-lead-to-account-takeover-b583f0c10591)
- OWASP classifies credential stuffing (automated injection of breached username/password pairs) as one of the most common techniques to take over user accounts. CAPEC-600 rates both Likelihood of Attack and Typical Severity as "High." -- [OWASP OAT-008](https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-008_Credential_Stuffing); [CAPEC-600](https://capec.mitre.org/data/definitions/600.html)
- User enumeration falls under OWASP A07:2021 (Identification and Authentication Failures). CWE-203 covers observable discrepancies in behavior/responses. CWE-204 covers responses that expose internal state (e.g., "User does not exist" vs generic error). -- [CWE-203](https://db.gcve.eu/cwes/CWE-203); [CWE-204](https://db.gcve.eu/cwe/CWE-204)
- Mautic (CVE-2024-47057) had user enumeration via password reset timing differences. The fix normalized response timing so reset responses take the same time regardless of user existence. -- [CWE-203 CVE Listings](https://cvepremium.circl.lu/cwe/CWE-203)

### Applicable Chains for This Target

**Chain 1: Enumeration -> Credential Stuffing -> Account Takeover**
- Step 1: Use F1 (login enumeration: "User does not exist") to build a list of valid usernames
- Step 2: Use F2 (password reset enumeration: "Email ID does not exist") to confirm email addresses for those usernames
- Step 3: Cross-reference enumerated usernames/emails against breached credential databases
- Step 4: Attempt credential stuffing against confirmed accounts
- Impact: Mass account takeover for users who reuse passwords
- CWE references: CWE-204 (Response Discrepancy), CWE-307 (Improper Restriction of Excessive Authentication Attempts), mapped to CAPEC-600
- Estimated severity: Individual enumeration = P4; Chain with credential stuffing = P2-P1

**Chain 2: Enumeration -> Password Spraying -> Account Takeover**
- Step 1: Enumerate valid usernames via F1
- Step 2: Use F3 (password policy disclosure) to craft passwords meeting exact policy requirements
- Step 3: Spray common passwords matching the disclosed policy against all enumerated accounts
- Step 4: If legacy endpoint (captcha-less) is used, no rate limiting blocks the spray
- Impact: Account compromise for users with weak passwords matching policy minimums
- Estimated severity: P2-P1 (depending on rate limiting effectiveness)

**Chain 3: Enumeration -> Social Engineering -> Account Takeover**
- Step 1: Confirm target email via F2
- Step 2: Use confirmed email to send targeted phishing (the attacker knows the email is registered)
- Step 3: Mobile number enumeration via OTP endpoint confirms phone numbers
- Step 4: Targeted vishing/smishing using confirmed contact details
- Impact: Targeted social engineering with confirmed account details
- Estimated severity: P3-P2 (social engineering chains are harder to get accepted; strongest when combined with technical exploitation)

### Inferences
- The strongest chain for this target is Enumeration + Legacy Endpoint (captcha bypass) + Credential Stuffing/Spraying, because the captcha-less legacy endpoint removes the primary automated-attack defense.
- Password policy disclosure (F3) materially assists password spraying by narrowing the search space, making it more than just informational when combined with enumeration.
- Mobile number enumeration adds a second channel for social engineering and could enable SIM-swapping attacks against high-value targets.

### Gaps
- No disclosed bug bounty report was found showing a specific payout for "user enumeration + credential stuffing" as a submitted chain. The Facebook and Meta examples involve enumeration + brute-force/rate-limit bypass, which is a close analog.
- Could not verify the exact current Bugcrowd VRT P-rating for login/password-reset user enumeration (the VRT page could not be fetched; historical versions suggest P4).

---

## What chains use "legacy endpoint without captcha" as an escalation factor?

### Takeaway
A legacy captcha-less endpoint that duplicates a protected endpoint's functionality is a captcha bypass by definition (CWE-804). It escalates brute-force, credential stuffing, and SMS bombing from theoretical to practical, and programs have paid $1,337-$5,000+ for similar findings.

### Cited Findings
- Google paid $5,000 (raised from $1,337 on appeal) for a researcher who reused botguard tokens from JavaScript-enabled sessions to bypass CAPTCHA in a no-JS flow, enabling approximately 40,000 verification attempts per second. Google retired the endpoint. -- [Rewterz Threat Advisory](https://rewterz.com/threat-advisory/google-flaw-exposed-phone-numbers-of-any-user-to-attackers)
- CVE-2026-40935 (WWBN AVideo): CAPTCHA length parameter was not clamped, allowing one-character CAPTCHAs. Failed attempts did not invalidate the session token, enabling brute-force in approximately 33 requests per session. Affects registration, password recovery, and contact forms. -- [SentinelOne Vulnerability Database](https://www.sentinelone.com/vulnerability-database/cve-2025-42601/)
- CVE-2025-42601: Removing the CAPTCHA field or token from a KYC API request was silently accepted by the server, enabling scripted enumeration. -- [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-42601/)
- CloudSEK reported that APIs allowing unlimited OTP SMS messages without rate limiting or captcha protection are actively exploited for SMS bombing. SMS flooding can serve as a veil to hide illegitimate login attempts. -- [CRN India](https://www.crn.in/?p=60302); [IBTimes India](https://www.ibtimes.co.in/rogue-scripts-hackers-use-otp-apis-sms-bombing-44-indian-apis-exposed-862026)
- CWE-804 (Guessable CAPTCHA) is the primary reference. The broader issue maps to CWE-862 (Missing Authorization) when a legacy endpoint lacks access controls that the current endpoint enforces. -- [CWE-804](https://db.gcve.eu/cwes/CWE-804)

### Applicable Chains for This Target

**Chain 4: Legacy Endpoint Captcha Bypass -> Credential Stuffing at Scale**
- Step 1: Enumerate valid usernames via F1 (through the main endpoint or the legacy one)
- Step 2: Use legacy `/admin/.` endpoint via raw HTTP (bypassing browser-enforced captcha)
- Step 3: Automate credential stuffing against all enumerated accounts at full speed (no captcha, potentially no rate limiting)
- Impact: Mass account takeover; the captcha bypass removes the only automated-attack defense
- CWE: CWE-804 (Guessable CAPTCHA), CWE-863 (Incorrect Authorization -- legacy endpoint lacking equivalent controls)
- Estimated severity: P2-P1

**Chain 5: Legacy Endpoint -> OTP Bombing / SMS Flooding**
- Step 1: Use mobile number enumeration to identify valid phone numbers
- Step 2: Send unlimited OTP requests through legacy captcha-less endpoint
- Step 3: Victim receives hundreds/thousands of SMS messages (financial cost to target organization, denial of service to victim)
- Step 4: SMS flood masks concurrent brute-force attempts on the OTP
- Impact: Financial impact (SMS costs at $0.01-0.05 per message x thousands), DoS against victim, potential OTP brute-force under cover
- CWE: CWE-799 (Improper Control of Interaction Frequency), CWE-804
- Estimated severity: P3-P2

**Chain 6: Legacy Endpoint -> OTP Brute Force -> Account Takeover**
- Step 1: Trigger password reset or login OTP for enumerated user
- Step 2: Brute-force OTP via legacy endpoint (no captcha, potentially no rate limiting)
- Step 3: If OTP is 4-6 digits (10,000-1,000,000 combinations) and no lockout, complete brute-force
- Step 4: Use valid OTP to reset password or access account
- Impact: Full account takeover
- Estimated severity: P1

### Inferences
- The "security through obscurity" argument (legacy endpoint accessible only via raw HTTP, not browsers) is itself a finding worth documenting. OWASP explicitly warns against relying on obscurity as a security control.
- The legacy endpoint's existence suggests the application was migrated/upgraded but the old endpoint was not decommissioned -- this is a common finding in CodeIgniter 3 applications that have had security hardening applied incrementally.
- Report the legacy endpoint as a captcha bypass (CWE-804) rather than just "legacy endpoint exists" -- this framing maps directly to Bugcrowd VRT categories and avoids the "informational" trap.
- The Google precedent ($5,000 for captcha bypass enabling brute-force) is the closest analog to this target's legacy endpoint finding.

### Gaps
- No disclosed report was found specifically for a "legacy endpoint without captcha that duplicates a captcha-protected endpoint" scenario. The Google case involves a different mechanism (token reuse) but the same outcome (captcha bypass enabling automation).
- Could not determine if Bugcrowd has a specific VRT entry for "stale/legacy endpoint" findings. The captcha bypass and missing rate limiting entries are the closest matches.

---

## What chains use "non-rotating CSRF tokens" for exploitation?

### Takeaway
Non-rotating CSRF tokens (same token valid for entire session) are typically P4-P3 on their own, but escalate when combined with token leakage vectors (Referer header, XSS, cached pages) or login CSRF scenarios. Jenkins CVE-2019-10353 is the most authoritative precedent.

### Cited Findings
- Jenkins CVE-2019-10353: CSRF tokens did not expire in Jenkins 2.185 and earlier. Rated severity 5 (medium) by Rapid7 with CVSS vector AV:N/AC:H/Au:N/C:P/I:P/A:P. -- [Rapid7](https://www.rapid7.com/db/vulnerabilities/jenkins-2019-07-17_cve-2019-10353); [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-10353)
- Quay CVE-2019-3864: CSRF token not refreshed per request or after logout/login. -- [Tenable](https://tenable.com/cve/CVE-2019-10353)
- Phabricator noted that researchers often reported token rotation without session binding as a vulnerability, but chose to bind tokens to sessions noting "Doing so has no real security benefit." -- [Phabricator Commit](https://projects.blender.org/archive/phabricator/commit/42cf7f6faa10a49f8ef8d604fb688d5a1f28bcaf)
- Login CSRF research describes forging a cross-site request to log a victim into the attacker's account, with severity comparable to XSS in some contexts. The Referer header is a reliable CSRF defense over HTTPS but widely blocked at the network layer. -- [CSRF Research](https://secgroup.dais.unive.it/wp-content/uploads/2020/02/csrf.pdf)
- A static CSRF token can be stolen via XSS, Referer leakage, or cached pages, and a token pool not tied to the session lets an attacker obtain a valid token from their own session and feed it to the victim. -- [HackTricks CSRF](https://www.mintlify.com/HackTricks-wiki/hacktricks/pentesting-web/csrf)

### Applicable Chains for This Target

**Chain 7: Non-Rotating CSRF Token + Referer Leakage -> CSRF Attack**
- Step 1: Identify if CSRF token appears in URL parameters or is leaked via Referer header to external resources
- Step 2: Capture token from Referer logs on attacker-controlled resource
- Step 3: Since token does not rotate, use captured token for CSRF attacks throughout the session
- Impact: Persistent CSRF capability for the session duration
- CWE: CWE-352 (Cross-Site Request Forgery)
- Estimated severity: P3-P2 (depends on what actions can be forged)

**Chain 8: Login CSRF (Force Victim into Attacker's Account)**
- Step 1: Attacker creates account on target
- Step 2: Craft CSRF payload that logs victim into attacker's account (login CSRF)
- Step 3: Victim performs sensitive actions (enters PII, links payment, uploads documents) believing they are in their own account
- Step 4: Attacker accesses their own account to harvest victim's data
- Impact: Data theft, credential capture
- CWE: CWE-352
- Estimated severity: P3-P2

**Chain 9: CSRF Token Prediction (if token is session-ID-derived)**
- Step 1: Analyze whether CSRF token is derived from or correlated with session ID
- Step 2: If predictable, generate valid tokens without authenticated access
- Step 3: Use predicted tokens for cross-site attacks
- Impact: Complete CSRF protection bypass
- Estimated severity: P2-P1 (if demonstrable)

### Inferences
- The Phabricator precedent suggests some programs may reject non-rotating CSRF tokens as not a vulnerability if tokens are session-bound. The key differentiator is whether the token is session-bound (lower severity) vs. completely static/predictable (higher severity).
- Login CSRF is the strongest angle for non-rotating CSRF tokens on this target, especially if the login form is CSRF-protected only by the non-rotating token.
- The non-rotating token finding is strongest when combined with another finding that enables token leakage (XSS, open redirect, Referer leakage).

### Gaps
- No bounty amount was found for a non-rotating CSRF token report. Jenkins CVE-2019-10353 provides severity context but not payout data.
- Could not verify whether the target's CSRF token is session-bound or completely static across sessions.

---

## What Bugcrowd/HackerOne severity ratings apply to each finding individually and when chained?

### Takeaway
Individual findings range from P5 (informational) to P4 (low). Chains that demonstrate account takeover jump to P2-P1. The Bugcrowd VRT is a baseline that can be adjusted based on demonstrated impact.

### Cited Findings
- Bugcrowd VRT states: "The recommended severity, from P1 to P5, is a baseline" and "application complexity, bounty brief restrictions, or unusual impact could result in a different rating." -- [Bugcrowd VRT](https://bugcrowd.com/vulnerability-rating-taxonomy)
- Bugcrowd severity ratings are set by application security engineers who "started with the generally-accepted industry guideline and further considered the vulnerability's average acceptance rate, average priority, and frequency on business use case specific exclusions lists." -- [Bugcrowd VRT](https://bugcrowd.com/vulnerability-rating-taxonomy)
- "Failure to Invalidate Session, On Password Reset and/or Change" is listed at P4 in VRT 1.10.1. -- [Bugcrowd VRT 1.10.1](https://bugcrowd.com/vulnerability-rating-taxonomy/1.10.1)
- "No Rate Limiting on Form -> Login" defaults to P4 as a typical baseline. -- [Bugcrowd VRT](https://bugcrowd.com/vulnerability-rating-taxonomy)
- HackerOne standards state that a known bug that is out of scope can still factor into a chain's overall impact. Programs are expected to "monitor for distinct reports that comprise a serious vulnerability chain and issue bonuses as appropriate." -- [HackerOne Platform Standards](https://docs.hackerone.com/organizations/platform-standards.html)

### Individual Severity Ratings (Estimated per Bugcrowd VRT/CVSS)

| Finding | Individual Severity | VRT Category | CWE |
|---------|-------------------|--------------|-----|
| F1: Login user enumeration | P4 (Low) | Server Security Misconfiguration > User Enumeration | CWE-204 |
| F2: Password reset enumeration | P4 (Low) | Server Security Misconfiguration > User Enumeration | CWE-204 |
| F3: Password policy disclosure | P5 (Informational) | Server Security Misconfiguration > Information Disclosure | CWE-200 |
| Legacy captcha-less endpoint | P3-P4 (Medium-Low) | Broken Authentication > CAPTCHA Bypass | CWE-804 |
| Non-rotating CSRF tokens | P4 (Low) | Broken Authentication > Session Management | CWE-352 |
| Mobile number enumeration | P4 (Low) | Server Security Misconfiguration > User Enumeration | CWE-204 |

### Chained Severity Ratings (Estimated)

| Chain | Severity | Justification |
|-------|----------|---------------|
| Enumeration + Credential Stuffing | P2 (High) | Mass account compromise via automated attack |
| Enumeration + Legacy Endpoint + Brute Force | P1-P2 (Critical-High) | Account takeover with captcha bypass |
| Legacy Endpoint + SMS Bombing | P3-P2 (Medium-High) | Financial impact + DoS + brute-force cover |
| Legacy Endpoint + OTP Brute Force | P1 (Critical) | Full account takeover |
| CSRF Token Leakage + CSRF Attack | P3-P2 (Medium-High) | Depends on forgeable actions |
| Full Chain (Enum + Legacy + OTP Brute) | P1 (Critical) | Complete authentication bypass to ATO |

### Inferences
- The gap between individual (P4-P5) and chained (P1-P2) severity is substantial, which is exactly why chaining is valuable for bounty maximization.
- Programs that follow HackerOne standards should consider chain bonuses even when individual bugs were reported separately.
- The most impactful chain combines F1 + F2 + legacy endpoint + OTP brute force = P1, because it represents a complete attack path from zero knowledge to account takeover.

### Gaps
- The exact current VRT version and its specific entries for these finding types could not be verified (VRT page fetch failed). The P-ratings above are estimated from VRT 1.10.1 and general guidance.

---

## What are the EXACT report templates and writeup formats that maximize bounty payouts?

### Takeaway
Reports that demonstrate clear impact, include working PoC scripts, reference CVSS/CWE/OWASP standards, and articulate business risk consistently earn higher payouts and faster triage.

### Cited Findings
- YesWeHack recommends reports include: "a description, the discovery process, and links to context, such as URLs for the relevant CWE definition and security advisories for existing vulnerabilities that your bug can be chained with." -- [YesWeHack](https://www.yeswehack.com/learn-bug-bounty/write-effective-bug-bounty-reports)
- Inspectiv states: "A well-documented proof of concept helps triage move faster" and "chaining multiple issues together to demonstrate a greater security risk, increasing both severity and reward potential." -- [Inspectiv Guide](https://www.inspectiv.com/articles/a-step-by-step-guide-for-security-researchers-to-maximize-payouts)
- HackerOne platform standards note that "stockpiling vulnerabilities to build exploit chains increases risk unacceptably" so chains should be reported promptly. Programs should also "monitor for distinct reports that comprise a serious vulnerability chain and issue bonuses as appropriate." -- [HackerOne Standards](https://docs.hackerone.com/organizations/platform-standards.html)
- Several programs specify: "submit one vulnerability per report, unless you need to chain vulnerabilities to provide impact." -- [HackerOne Standards](https://docs.hackerone.com/organizations/platform-standards.html)

### Recommended Report Template

```
Title: [Chain Description] Leading to [Ultimate Impact] via [Primary Mechanism]
Example: "Authentication Bypass via Legacy Captcha-less Endpoint Chaining 
         with User Enumeration Leading to Account Takeover"

## Summary
One paragraph: What the vulnerability chain is, what an attacker can achieve,
and what the blast radius is.

## Severity Assessment
- CVSS 3.1 Score: [Calculate at first.org/cvss/calculator/3.1]
- Bugcrowd VRT Category: [Closest match]
- CWE References: [All applicable]
- OWASP Category: [e.g., A07:2021 - Identification and Authentication Failures]

## Vulnerability Chain
### Link 1: [Finding Name]
- Endpoint: [URL]
- Method: [HTTP method]
- Description: [What the individual vulnerability is]
- Evidence: [Screenshot/response comparison]

### Link 2: [Finding Name]
[Same structure]

### Chain Logic
- How Link 1 enables Link 2
- Why the chain is greater than the sum of its parts
- What defense each link bypasses

## Steps to Reproduce
1. [Exact step with curl/browser instructions]
2. [Each step numbered]
3. [Include all parameters, headers, cookies]

## Proof of Concept
[Working script or detailed manual steps]
[Include expected vs actual output]

## Impact Assessment
### Technical Impact
- [What an attacker can do]
- [Number of affected accounts/users]
- [Data at risk]

### Business Impact
- [Compliance implications: GDPR, PCI DSS]
- [Financial impact: SMS costs, fraud liability]
- [Reputational risk]

### Defense-in-Depth Argument
"Although [Finding X] alone is rated [Low/P4], it reduces the attacker's 
effort for [Attack Y] by [Z]%, because [specific reasoning]. Combined with 
[Finding W], the effective security of the authentication flow is reduced 
from [N] to [M] effective bits of entropy, making automated exploitation 
practical within [timeframe]."

## Remediation Recommendations
1. [Specific fix for each link in the chain]
2. [Defense-in-depth measures]
3. [Monitoring/detection recommendations]

## References
- [CWE entries]
- [OWASP guidelines]
- [Similar disclosed reports]
- [NIST SP 800-63B for authentication]
```

### Inferences
- Reports with CVSS scores, CWE references, and business impact statements are triaged faster and rated higher than bare technical descriptions.
- The "defense in depth" argument section is where individual low-severity findings get reframed as components of a higher-severity chain.
- PoC scripts (especially automated ones showing scale) dramatically increase perceived impact and payout.

### Gaps
- No source provided a guaranteed payout multiplier for well-formatted reports vs. bare reports. The improvement is consistently described as significant but not quantified.

---

## What "defense in depth" arguments increase severity?

### Takeaway
Defense-in-depth arguments work when they quantify how a low-severity finding reduces the attacker's cost for a higher-severity attack. They fail when they are speculative or require unrealistic attack chains.

### Cited Findings
- CAPEC-600 rates credential stuffing Typical Severity as "High," establishing that the attack user enumeration enables is itself high-severity. -- [CAPEC-600](https://capec.mitre.org/data/definitions/600.html)
- The "Merchants of Vulnerabilities" paper notes that software vulnerability severity reflects "the highest failure impact that the defect could cause." -- [arXiv](https://arxiv.org/pdf/2404.17497)
- Atlassian's bug bounty program states that "the amount of payment for individual bugs will vary based not only on the CVSS severity level, but also which product the report applies to." -- [Atlassian Bug Bounty Report](https://www.atlassian.com/dam/jcr:4411ca59-a601-4a4d-86a4-554ac7b974ae/FY21_Atlassian_Bug_Bounty_Report.pdf)

### Applicable Arguments for This Target

**Argument 1: Enumeration Reduces Credential Stuffing Cost**
"Although user enumeration (F1) alone is rated P4/Low, it reduces the attacker's effort for credential stuffing by an estimated 90-99%, because the attacker no longer needs to test credentials against non-existent accounts. Against a typical application with a 1-5% username hit rate from a breached database, enumeration allows the attacker to pre-filter to only valid accounts, reducing the attack from millions of attempts to thousands of targeted attempts. This makes credential stuffing practical even against rate-limited endpoints."

**Argument 2: Password Policy Disclosure Narrows Spray Space**
"Password policy disclosure (F3) reduces the password spraying search space from effectively infinite to a constrained set matching the disclosed policy. If the policy requires 8+ characters with one uppercase and one number, the attacker can generate a targeted dictionary of common passwords matching exactly these constraints, reducing spray attempts by orders of magnitude."

**Argument 3: Legacy Endpoint Eliminates Captcha Defense**
"The legacy captcha-less OTP endpoint eliminates the primary automated-attack defense. The captcha on the production endpoint is the only control preventing automated brute-force, credential stuffing, and SMS bombing. The legacy endpoint's existence reduces the effective security of this control from 'present' to 'bypassable,' making all captcha-dependent security assumptions invalid."

**Argument 4: Non-Rotating CSRF + Enumeration = Targeted Attacks**
"Non-rotating CSRF tokens extend the exploitation window from a single request to the entire session duration. Combined with user enumeration, an attacker can conduct targeted CSRF attacks against confirmed accounts, knowing both that the account exists and that any captured token remains valid indefinitely."

**Argument 5: SMS Cost Quantification**
"The captcha-less legacy endpoint allows unlimited OTP requests. At an industry-average SMS cost of $0.01-0.05 per message, an automated script sending 100 requests/second would incur costs of $3,600-$18,000/hour to the target organization. Over a weekend, this represents $172,800-$864,000 in potential SMS costs, representing a direct financial denial-of-service."

### Inferences
- The strongest defense-in-depth arguments quantify the reduction in attacker effort (percentage, bits of entropy, time, cost).
- Arguments that reference OWASP/NIST standards carry more weight than purely technical reasoning.
- SMS cost calculations are particularly effective because they translate a technical finding into direct financial impact that non-technical decision-makers understand.
- NIST SP 800-63B (Digital Identity Guidelines) explicitly recommends against SMS-based OTP as a sole authentication factor, which strengthens any OTP-related finding.

### Gaps
- No source was found that directly confirms triagers accept defense-in-depth severity increases. General practitioner advice suggests they "tend to succeed when the researcher shows the weakness combines with another flaw" but this is not from an official platform policy.

---

## What similar chained reports earned bounties and how much?

### Takeaway
Account takeover chains involving enumeration and authentication bypass have earned $5,000-$163,000 at major programs. Smaller programs pay $25-$1,000 for individual findings in the same categories.

### Cited Findings
- Facebook: $40,000 for user ID enumeration + phone verification brute-force -> account takeover. -- [SecurityWeek](https://www.securityweek.com/facebook-pays-out-40000-account-takeover-exploit-chain/amp/)
- Meta: $27,200 for SMS verification PIN brute-force via rate-limiting gap. A separate phone-number recovery bug earned $163,000 (highest bounty). -- [Bitdefender](https://www.bitdefender.com/en-gb/blog/hotforsecurity/meta-pays-out-bounties-for-account-takeover-and-two-factor-authentication-bypass-exploits)
- Google: $5,000 (raised from $1,337 on appeal) for captcha bypass enabling ~40,000 verification attempts/second. Google retired the affected endpoint. -- [Rewterz](https://rewterz.com/threat-advisory/google-flaw-exposed-phone-numbers-of-any-user-to-attackers)
- BookMyShow: Rs. 1,000 voucher (~$12) for OTP rate-limit bypass via whitespace character in phone number. -- [InfoSec Write-ups](https://infosecwriteups.com/how-i-bypassed-bookmyshows-otp-limit-with-just-a-space-got-1000-for-it-70eab29fb6aa)
- huntr: $25 for fixing password reset enumeration in Pagekit CMS. -- [huntr via GitHub](https://git.tdem.in/pagekit/pagekit/pull/954)
- Coinbase: Researcher reported user enumeration and related issues; Coinbase said the research "may warrant consideration in the future" but "does not warrant a reward." -- [SC World](https://www.scworld.com/coinbase-responds-to-information-disclosure-user-enumeration-other-concerns/article/340815/)

### Payout Patterns

| Finding Type | Low End | High End | Key Factor |
|-------------|---------|----------|------------|
| User enumeration alone | $0-25 | $500 | Often rejected or informational |
| Captcha bypass alone | $500 | $5,000 | Depends on what it enables |
| OTP brute-force -> ATO | $5,000 | $27,200 | Depends on program size |
| Full auth bypass chain -> ATO | $10,000 | $163,000 | Scale of impact |
| SMS bombing/flooding | $100 | $1,000 | Financial impact calculation |

### Inferences
- The range is enormous ($0 to $163,000) and depends primarily on program size and demonstrated impact.
- Appeals can increase payouts significantly (Google: $1,337 -> $5,000, a 3.7x increase).
- Some programs explicitly reject user enumeration (Coinbase example), so checking the program's scope/exclusions is critical before reporting.
- The highest payouts go to chains that demonstrate account takeover at scale, not individual findings.

### Gaps
- No disclosed reports were found for CodeIgniter-specific applications or for the exact combination of findings on this target.
- Payout data from Bugcrowd-specific programs was not found in disclosed reports; the examples above are primarily from HackerOne and direct vendor programs.

---

## What chains work specifically with the OTP flow?

### Takeaway
The OTP attack chain (Enumeration -> OTP Bombing -> OTP Brute Force/Race Condition -> Account Takeover) is a well-documented path. The key enabler on this target is the legacy captcha-less endpoint that removes the automation defense.

### Cited Findings
- CloudSEK detected 44 Indian APIs exposed to SMS bombing via OTP endpoints lacking rate limiting or captcha protection. SMS flooding can serve as "a veil to hide illegitimate login attempts." -- [CRN India](https://www.crn.in/?p=60302); [IBTimes](https://www.ibtimes.co.in/rogue-scripts-hackers-use-otp-apis-sms-bombing-44-indian-apis-exposed-862026)
- A researcher bypassed OTP verification by manipulating the response body (changing "false" to "true" in the server response). -- [InfoSec Write-ups](https://infosecwriteups.com/how-i-bypassed-the-otp-verification-process-part-1-e5b333274ae9)
- CWE-799 (Improper Control of Interaction Frequency) and CWE-837 (Improper Enforcement of a Single, Unique Action) are the primary references for OTP rate-limiting failures. -- [OWASP OAT-008](https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-008_Credential_Stuffing)

### OTP Chain for This Target

**Full OTP Attack Chain:**
1. **Enumeration (F1 + F2 + Mobile):** Identify valid username, email, and phone number
2. **Trigger OTP:** Request password reset OTP for enumerated user
3. **SMS Bombing Cover (H9):** Send hundreds of OTP requests via legacy endpoint to flood victim's phone (masks the real OTP among noise, and creates attacker-cost to organization)
4. **OTP Brute Force (H3):** If OTP is 4-6 digits, brute-force via legacy captcha-less endpoint
   - 4-digit OTP: 10,000 combinations
   - 6-digit OTP: 1,000,000 combinations
   - At 100 requests/second (no captcha): 100 seconds for 4-digit, ~2.8 hours for 6-digit
5. **OTP Reuse (H4):** If OTP is not invalidated after use, reuse captured OTP
6. **OTP Race Condition (H3 variant):** Send multiple concurrent OTP verification requests to exploit race conditions in validation logic
7. **Account Takeover:** Use valid OTP to reset password and access account

**Hypothesized findings (H3-H5) are critical to test:**
- H3 (OTP brute-force): The chain's viability depends on whether rate limiting exists on OTP verification (separate from OTP generation)
- H4 (OTP reuse): If OTPs remain valid after use, a single captured OTP provides persistent access
- H5 (OTP predictability): If OTPs are generated with weak randomness, the brute-force space shrinks dramatically

### Inferences
- The legacy captcha-less endpoint is the key multiplier for OTP attacks. Without it, brute-force is impractical due to captcha. With it, the entire OTP security model collapses.
- SMS bombing is both an impact demonstration (financial cost) and an attack enabler (noise cover for brute-force).
- Race conditions in OTP verification are often present in web applications that check OTP validity in application code rather than at the database level with atomic operations.

### Gaps
- H3, H4, H5 cannot be confirmed without a registered account to test. The chain's ultimate severity depends on these hypothesized findings.

---

## What "batch reporting" vs "individual reporting" strategies maximize total payout?

### Takeaway
Report the highest-severity chain as one report, then report remaining individual findings separately. HackerOne standards support chain bonuses for related reports.

### Cited Findings
- HackerOne: "Submit one vulnerability per report, unless you need to chain vulnerabilities to provide impact." Programs should "monitor for distinct reports that comprise a serious vulnerability chain and issue bonuses as appropriate." -- [HackerOne Standards](https://docs.hackerone.com/organizations/platform-standards.html)
- Multiple programs state: "Several bugs stemming from one underlying flaw are treated as a single vulnerability (one payout)." -- [HackerOne Standards](https://docs.hackerone.com/organizations/platform-standards.html)
- HackerOne notes that "stockpiling vulnerabilities to build exploit chains increases risk unacceptably." -- [HackerOne Standards](https://docs.hackerone.com/organizations/platform-standards.html)

### Recommended Reporting Strategy for This Target

**Approach: Hybrid (Chain + Individual)**

**Report 1 (Chain - Submit First, Highest Value):**
Title: "Account Takeover via Chained Authentication Bypass: User Enumeration + Legacy Captcha-less Endpoint + OTP Brute Force"
- Includes: F1 + F2 + Legacy endpoint + H3/H4 (if confirmed)
- Target severity: P1-P2
- This is the "headline" report that demonstrates maximum impact

**Report 2 (Individual - SMS Bombing):**
Title: "SMS Flooding / Denial of Service via Legacy Captcha-less OTP Endpoint"
- Includes: Legacy endpoint + H9 + SMS cost calculation
- Target severity: P3
- Separate from Report 1 because the impact vector is different (financial DoS vs. account takeover)

**Report 3 (Individual - CSRF):**
Title: "Non-Rotating CSRF Tokens Enable Persistent Cross-Site Request Forgery"
- Includes: Non-rotating CSRF + any identified sensitive actions
- Target severity: P4-P3
- Separate because CSRF is a distinct vulnerability class

**Report 4 (Individual - Mobile Enumeration):**
Title: "Mobile Number Enumeration via Differential Error Messages on OTP Endpoint"
- Includes: Mobile number enumeration finding
- Target severity: P4
- Can reference Report 1 as context for why enumeration matters

**Report 5 (Individual - IDOR, if confirmed):**
Title: "Insecure Direct Object Reference in /document Endpoint"
- Includes: H7 (if confirmed, similar to 2023 accepted report)
- Target severity: P2-P3
- Submit independently -- IDOR is a distinct vulnerability class

**Do NOT batch:**
- F3 (Password policy disclosure) alone -- too low severity, fold it into Report 1's chain narrative
- Individual enumeration findings without chain context -- likely rejected as informational

### Inferences
- The chain report should be submitted first because it establishes the highest-severity finding and creates context for subsequent individual reports.
- Reference previous reports in later submissions ("As demonstrated in Report #X, user enumeration enables...") to build a narrative of systemic authentication weakness.
- If H7 (IDOR) is confirmed and similar to the 2023 accepted report, submit it separately with reference to the prior acceptance -- this establishes precedent.
- The total payout from this hybrid approach should exceed what a single batch report would earn, because each report addresses a distinct impact vector.

### Gaps
- No source was found quantifying the payout difference between batch and individual reporting strategies.
- Program-specific rules on duplicate/related reports will determine whether individual reports are accepted or closed as duplicates of the chain report.

---

## What OWASP/NIST/CWE references strengthen each finding's report?

### Takeaway
Mapping findings to established standards adds credibility and helps triagers assess severity. Each finding maps to multiple standards.

### Cited Findings
- CWE-203: Observable Discrepancy -- covers user enumeration via different error messages or response timing. -- [CWE-203](https://db.gcve.eu/cwes/CWE-203)
- CWE-204: Observable Response Discrepancy -- specific to responses that expose internal state (e.g., "User does not exist"). -- [CWE-204](https://db.gcve.eu/cwe/CWE-204)
- CWE-804: Guessable CAPTCHA -- covers captcha bypass mechanisms. -- [CWE-804](https://db.gcve.eu/cwes/CWE-804)
- CWE-799: Improper Control of Interaction Frequency -- covers missing rate limiting on OTP/SMS endpoints. -- [OWASP OAT-008](https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-008_Credential_Stuffing)
- CWE-352: Cross-Site Request Forgery -- covers non-rotating CSRF tokens. -- [NVD CVE-2019-10353](https://nvd.nist.gov/vuln/detail/CVE-2019-10353)
- OWASP A07:2021: Identification and Authentication Failures -- covers enumeration, weak authentication, credential stuffing. -- [OWASP](https://owasp.org/www-community/attacks/Credential_stuffing)
- CAPEC-600: Credential Stuffing -- Likelihood "High," Typical Severity "High." -- [CAPEC-600](https://capec.mitre.org/data/definitions/600.html)

### Complete Reference Map

| Finding | CWE | OWASP Top 10 | CAPEC | NIST | Additional |
|---------|-----|-------------|-------|------|------------|
| F1: Login enumeration | CWE-203, CWE-204 | A07:2021 | CAPEC-383 | SP 800-63B s5.2.2 | OAT-007 |
| F2: Reset enumeration | CWE-203, CWE-204, CWE-640 | A07:2021 | CAPEC-383 | SP 800-63B s5.1.1.2 | -- |
| F3: Policy disclosure | CWE-200, CWE-209 | A07:2021 | -- | -- | -- |
| Legacy captcha-less endpoint | CWE-804, CWE-863, CWE-1295 | A07:2021, A05:2021 | CAPEC-55 | -- | WASC-21 |
| Non-rotating CSRF | CWE-352, CWE-613 | A01:2021 | CAPEC-62 | -- | -- |
| Mobile enumeration | CWE-203, CWE-204 | A07:2021 | CAPEC-383 | SP 800-63B | -- |
| OTP brute-force (H3) | CWE-307, CWE-799 | A07:2021 | CAPEC-49 | SP 800-63B s5.1.3 | OAT-008 |
| SMS bombing (H9) | CWE-799, CWE-770 | A04:2021 | -- | -- | -- |
| IDOR (H7) | CWE-639 | A01:2021 | CAPEC-31 | -- | -- |

### Inferences
- NIST SP 800-63B is particularly powerful for authentication findings because it represents U.S. federal government security standards. Citing it implies the target's authentication does not meet government-grade requirements.
- Multiple CWE mappings per finding are legitimate and add weight. CWE-203 (broad) + CWE-204 (specific) for enumeration shows depth of analysis.
- OWASP A07:2021 covers most of these findings, which supports the narrative of systemic authentication weakness rather than isolated issues.

### Gaps
- NIST SP 800-63B section references are from general knowledge; the exact section numbers should be verified against the current document.

---

## What creative impact demonstrations increase bounty?

### Takeaway
SMS cost calculations, compliance implications, automated PoC scripts, and scale demonstrations are the most effective impact amplifiers based on disclosed reports and practitioner guidance.

### Cited Findings
- CloudSEK's research on OTP SMS bombing highlighted financial impact as a key concern for affected organizations. -- [CRN India](https://www.crn.in/?p=60302)
- Inspectiv states that "chaining multiple issues together to demonstrate a greater security risk" increases "both severity and reward potential." -- [Inspectiv](https://www.inspectiv.com/articles/a-step-by-step-guide-for-security-researchers-to-maximize-payouts)
- The Google captcha bypass researcher demonstrated ~40,000 attempts/second capability, which was the key factor in the payout increase from $1,337 to $5,000. -- [Rewterz](https://rewterz.com/threat-advisory/google-flaw-exposed-phone-numbers-of-any-user-to-attackers)

### Recommended Impact Demonstrations for This Target

**1. SMS Cost Calculator (for SMS Bombing finding)**
```
SMS Cost Impact Analysis:
- Average SMS cost (India): Rs. 0.15-0.25 per SMS ($0.002-0.003 USD)
- Average SMS cost (International): $0.01-0.05 USD per SMS
- Legacy endpoint request rate: [measured] requests/second
- Cost per hour: [rate] x 3600 x [cost per SMS]
- Cost per day: [hourly] x 24
- Weekend attack (48 hours): [daily] x 2
Example: 100 req/sec x 3600 x $0.01 = $3,600/hour = $86,400/day
```

**2. Credential Stuffing Scale Calculation**
```
Enumeration + Stuffing Scale:
- Enumeration rate via legacy endpoint: [measured] accounts/second
- Estimated user base: [estimate from application context]
- Time to enumerate all users: [user base / rate]
- Cross-reference with breached credentials: [estimated hit rate 1-5%]
- Estimated compromisable accounts: [user base x hit rate]
```

**3. Compliance Implications**
- **GDPR Article 32:** "Implement appropriate technical measures to ensure security" -- user enumeration and captcha bypass violate this
- **PCI DSS Requirement 8.1.6:** "Limit repeated access attempts by locking out the user ID after not more than six attempts" -- legacy endpoint may lack this control
- **PCI DSS Requirement 6.5.9:** "Cross-site request forgery (CSRF)" -- non-rotating tokens violate this
- **RBI Guidelines (if Indian target):** Reserve Bank of India mandates OTP security controls for financial transactions

**4. Automated PoC Script (Skeleton)**
```python
# PoC: User Enumeration via Login Endpoint
# RESPONSIBLE DISCLOSURE: Only test against authorized targets
import requests
import sys

def check_user_exists(username, base_url):
    """Returns True if user exists based on error message differential"""
    response = requests.post(f"{base_url}/login", 
                           data={"username": username, "password": "test"})
    return "User does not exist" not in response.text

# Usage: python poc_enum.py userlist.txt https://target.com
with open(sys.argv[1]) as f:
    for user in f:
        user = user.strip()
        if check_user_exists(user, sys.argv[2]):
            print(f"[VALID] {user}")
```

### Inferences
- Financial impact calculations (SMS costs) are the single most effective way to escalate an SMS bombing finding from P4 to P3-P2.
- Compliance references (GDPR, PCI DSS) add urgency for organizations that must maintain compliance certifications.
- Automated PoC scripts demonstrate that exploitation is practical, not theoretical, and remove any "this is too hard to exploit" pushback from triage.
- Scale calculations (time to enumerate all users, number of potentially compromisable accounts) help triagers understand blast radius.

### Gaps
- Specific bounty increase amounts attributable to impact demonstrations were not found. The improvement is consistently described as significant but not quantified with before/after examples.
- Compliance implications vary by jurisdiction and the target's industry; the recommendations above assume a web application handling user PII.
