#!/usr/bin/env python3
"""
Session Security Analyzer
For authorized security testing only.

Analyzes session management security including:
- Session token strength and entropy
- Cookie security attributes
- Session fixation vulnerabilities
- Session timeout behavior
- Concurrent session handling
- Session regeneration on auth
- Token predictability analysis

Usage:
    python3 session-analyzer.py -t https://target.com
    python3 session-analyzer.py -t https://target.com --login-url /login -u admin -p password
    python3 session-analyzer.py -t https://target.com --full-analysis
"""

import argparse
import requests
import json
import re
import time
import math
import hashlib
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from collections import Counter
from urllib.parse import urlparse, urljoin
import warnings

warnings.filterwarnings('ignore')

# ============================================================================
# CONFIGURATION
# ============================================================================

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
DEFAULT_TIMEOUT = 10
SAMPLE_SIZE = 10  # Number of sessions to collect for analysis

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
    def finding(severity: str, msg: str):
        colors = {
            'critical': Colors.RED + Colors.BOLD,
            'high': Colors.RED,
            'medium': Colors.YELLOW,
            'low': Colors.CYAN,
            'info': Colors.BLUE
        }
        color = colors.get(severity.lower(), Colors.WHITE)
        print(f"  {color}[{severity.upper()}]{Colors.END} {msg}")


# ============================================================================
# SESSION COLLECTOR
# ============================================================================

class SessionCollector:
    """Collect session tokens from target application"""

    def __init__(self, target: str, login_url: str = None,
                 username: str = None, password: str = None,
                 username_field: str = 'username', password_field: str = 'password'):
        self.target = target
        self.login_url = login_url
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.sessions = []

    def collect_unauthenticated(self, count: int = SAMPLE_SIZE) -> List[Dict]:
        """Collect session tokens without authentication"""
        Logger.info(f"Collecting {count} unauthenticated sessions...")

        sessions = []
        for i in range(count):
            try:
                session = requests.Session()
                session.headers.update({'User-Agent': DEFAULT_USER_AGENT})

                response = session.get(
                    self.target,
                    timeout=DEFAULT_TIMEOUT,
                    verify=False
                )

                session_data = {
                    'timestamp': time.time(),
                    'cookies': {},
                    'headers': dict(response.headers),
                    'authenticated': False
                }

                # Collect all cookies
                for cookie in session.cookies:
                    session_data['cookies'][cookie.name] = {
                        'value': cookie.value,
                        'domain': cookie.domain,
                        'path': cookie.path,
                        'secure': cookie.secure,
                        'expires': cookie.expires,
                        'httponly': cookie.has_nonstandard_attr('HttpOnly') or
                                   'httponly' in str(response.headers.get('Set-Cookie', '')).lower()
                    }

                sessions.append(session_data)
                Logger.info(f"  Collected session {i + 1}/{count}")
                time.sleep(0.5)  # Small delay between requests

            except requests.exceptions.RequestException as e:
                Logger.error(f"  Failed to collect session: {e}")

        self.sessions = sessions
        return sessions

    def collect_authenticated(self, count: int = SAMPLE_SIZE) -> List[Dict]:
        """Collect session tokens after authentication"""
        if not self.login_url or not self.username or not self.password:
            Logger.error("Login URL, username, and password required for authenticated sessions")
            return []

        Logger.info(f"Collecting {count} authenticated sessions...")

        sessions = []
        login_url = urljoin(self.target, self.login_url)

        for i in range(count):
            try:
                session = requests.Session()
                session.headers.update({'User-Agent': DEFAULT_USER_AGENT})

                # Get pre-auth session
                pre_response = session.get(self.target, timeout=DEFAULT_TIMEOUT, verify=False)
                pre_auth_cookies = {c.name: c.value for c in session.cookies}

                # Authenticate
                login_data = {
                    self.username_field: self.username,
                    self.password_field: self.password
                }

                response = session.post(
                    login_url,
                    data=login_data,
                    timeout=DEFAULT_TIMEOUT,
                    verify=False,
                    allow_redirects=True
                )

                session_data = {
                    'timestamp': time.time(),
                    'cookies': {},
                    'pre_auth_cookies': pre_auth_cookies,
                    'headers': dict(response.headers),
                    'authenticated': True,
                    'login_successful': response.status_code in [200, 302]
                }

                # Collect post-auth cookies
                for cookie in session.cookies:
                    session_data['cookies'][cookie.name] = {
                        'value': cookie.value,
                        'domain': cookie.domain,
                        'path': cookie.path,
                        'secure': cookie.secure,
                        'expires': cookie.expires
                    }

                sessions.append(session_data)
                Logger.info(f"  Collected session {i + 1}/{count}")
                time.sleep(1)  # Delay between login attempts

            except requests.exceptions.RequestException as e:
                Logger.error(f"  Failed to collect session: {e}")

        self.sessions = sessions
        return sessions


# ============================================================================
# TOKEN ANALYZER
# ============================================================================

class TokenAnalyzer:
    """Analyze session token security"""

    def __init__(self, sessions: List[Dict]):
        self.sessions = sessions
        self.findings = []

    def analyze_all(self) -> Dict[str, Any]:
        """Run all token analyses"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'session_count': len(self.sessions),
            'findings': []
        }

        if not self.sessions:
            Logger.error("No sessions to analyze")
            return results

        # Extract tokens by cookie name
        tokens_by_name = {}
        for session in self.sessions:
            for name, data in session.get('cookies', {}).items():
                if name not in tokens_by_name:
                    tokens_by_name[name] = []
                tokens_by_name[name].append({
                    'value': data['value'],
                    'timestamp': session['timestamp'],
                    'authenticated': session.get('authenticated', False)
                })

        # Analyze each cookie type
        for name, tokens in tokens_by_name.items():
            Logger.info(f"\nAnalyzing cookie: {name}")
            print("-" * 50)

            # Run analyses
            results['findings'].extend(self._analyze_entropy(name, tokens))
            results['findings'].extend(self._analyze_predictability(name, tokens))
            results['findings'].extend(self._analyze_structure(name, tokens))
            results['findings'].extend(self._analyze_length(name, tokens))

        # Analyze cookie attributes
        if self.sessions:
            results['findings'].extend(self._analyze_cookie_attributes(self.sessions[0]))

        # Analyze session regeneration
        if any(s.get('authenticated') for s in self.sessions):
            results['findings'].extend(self._analyze_session_regeneration())

        return results

    def _analyze_entropy(self, cookie_name: str, tokens: List[Dict]) -> List[Dict]:
        """Analyze token entropy"""
        findings = []
        values = [t['value'] for t in tokens]

        if not values:
            return findings

        # Calculate average entropy
        total_entropy = 0
        for value in values:
            entropy = self._calculate_entropy(value)
            total_entropy += entropy

        avg_entropy = total_entropy / len(values)
        avg_length = sum(len(v) for v in values) / len(values)

        # Minimum recommended entropy is 128 bits
        Logger.info(f"  Average length: {avg_length:.0f} characters")
        Logger.info(f"  Average entropy: {avg_entropy:.1f} bits")

        if avg_entropy < 64:
            findings.append({
                'cookie': cookie_name,
                'severity': 'critical',
                'issue': f'Very low entropy ({avg_entropy:.1f} bits)',
                'description': 'Token is highly predictable and can be brute-forced',
                'recommendation': 'Use cryptographically secure random token generation with at least 128 bits of entropy'
            })
            Logger.finding('critical', f'Very low entropy: {avg_entropy:.1f} bits (minimum 128 recommended)')
        elif avg_entropy < 128:
            findings.append({
                'cookie': cookie_name,
                'severity': 'medium',
                'issue': f'Moderate entropy ({avg_entropy:.1f} bits)',
                'description': 'Token may be vulnerable to brute-force in some scenarios',
                'recommendation': 'Increase token randomness to achieve at least 128 bits of entropy'
            })
            Logger.finding('medium', f'Moderate entropy: {avg_entropy:.1f} bits')
        else:
            Logger.finding('info', f'Good entropy: {avg_entropy:.1f} bits')

        return findings

    def _calculate_entropy(self, token: str) -> float:
        """Calculate Shannon entropy of token"""
        if not token:
            return 0

        # Calculate character frequency
        freq = Counter(token)
        length = len(token)

        # Calculate entropy
        entropy = 0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)

        # Multiply by length to get total bits
        return entropy * length

    def _analyze_predictability(self, cookie_name: str, tokens: List[Dict]) -> List[Dict]:
        """Check if tokens are predictable"""
        findings = []
        values = [t['value'] for t in tokens]

        if len(values) < 2:
            return findings

        # Check for sequential patterns
        sequential = self._check_sequential(values)
        if sequential['is_sequential']:
            findings.append({
                'cookie': cookie_name,
                'severity': 'critical',
                'issue': 'Sequential token generation detected',
                'description': f"Tokens increment by {sequential['increment']}",
                'recommendation': 'Use cryptographically secure random generation'
            })
            Logger.finding('critical', f"Sequential tokens detected (increment: {sequential['increment']})")

        # Check for timestamp patterns
        timestamp = self._check_timestamp(values)
        if timestamp['has_timestamp']:
            findings.append({
                'cookie': cookie_name,
                'severity': 'high',
                'issue': 'Timestamp pattern detected in token',
                'description': 'Token contains predictable timestamp component',
                'recommendation': 'Remove timestamp or combine with sufficient random data'
            })
            Logger.finding('high', 'Timestamp pattern detected in tokens')

        # Check for common prefixes/suffixes
        prefix_suffix = self._check_prefix_suffix(values)
        if prefix_suffix['common_prefix']:
            Logger.finding('low', f"Common prefix: {prefix_suffix['common_prefix']}")
        if prefix_suffix['common_suffix']:
            Logger.finding('low', f"Common suffix: {prefix_suffix['common_suffix']}")

        return findings

    def _check_sequential(self, values: List[str]) -> Dict[str, Any]:
        """Check if values are sequential"""
        result = {'is_sequential': False, 'increment': None}

        # Try to extract numeric portions
        numbers = []
        for v in values:
            # Try full value as number
            try:
                numbers.append(int(v))
                continue
            except ValueError:
                pass

            # Try hex
            try:
                numbers.append(int(v, 16))
                continue
            except ValueError:
                pass

            # Extract numeric suffix
            match = re.search(r'(\d+)$', v)
            if match:
                numbers.append(int(match.group(1)))

        if len(numbers) >= 2:
            # Check if sequential
            numbers.sort()
            diffs = [numbers[i+1] - numbers[i] for i in range(len(numbers)-1)]

            if len(set(diffs)) == 1 and diffs[0] > 0:
                result['is_sequential'] = True
                result['increment'] = diffs[0]

        return result

    def _check_timestamp(self, values: List[str]) -> Dict[str, Any]:
        """Check if tokens contain timestamps"""
        result = {'has_timestamp': False, 'timestamps': []}
        current_time = int(time.time())

        for value in values:
            # Check for Unix timestamp (10 digits)
            for i in range(len(value) - 9):
                try:
                    potential_ts = int(value[i:i+10])
                    # Within last week and not in future
                    if current_time - 604800 < potential_ts <= current_time + 60:
                        result['has_timestamp'] = True
                        result['timestamps'].append(potential_ts)
                        break
                except ValueError:
                    continue

            # Check for millisecond timestamp (13 digits)
            for i in range(len(value) - 12):
                try:
                    potential_ts = int(value[i:i+13]) // 1000
                    if current_time - 604800 < potential_ts <= current_time + 60:
                        result['has_timestamp'] = True
                        result['timestamps'].append(potential_ts)
                        break
                except ValueError:
                    continue

        return result

    def _check_prefix_suffix(self, values: List[str]) -> Dict[str, Any]:
        """Check for common prefixes/suffixes"""
        result = {'common_prefix': '', 'common_suffix': ''}

        if len(values) < 2:
            return result

        # Find common prefix
        prefix = values[0]
        for v in values[1:]:
            while not v.startswith(prefix) and prefix:
                prefix = prefix[:-1]

        if len(prefix) > 3:  # Only report significant prefixes
            result['common_prefix'] = prefix

        # Find common suffix
        suffix = values[0]
        for v in values[1:]:
            while not v.endswith(suffix) and suffix:
                suffix = suffix[1:]

        if len(suffix) > 3:
            result['common_suffix'] = suffix

        return result

    def _analyze_structure(self, cookie_name: str, tokens: List[Dict]) -> List[Dict]:
        """Analyze token structure"""
        findings = []
        values = [t['value'] for t in tokens]

        if not values:
            return findings

        sample = values[0]

        # Detect encoding
        encoding = self._detect_encoding(sample)
        Logger.info(f"  Detected encoding: {encoding}")

        # Check for serialized data
        if encoding == 'base64':
            try:
                import base64
                decoded = base64.b64decode(sample + '==').decode('utf-8', errors='ignore')
                if any(marker in decoded.lower() for marker in ['user', 'admin', 'role', 'session', '{']):
                    findings.append({
                        'cookie': cookie_name,
                        'severity': 'medium',
                        'issue': 'Token contains readable data',
                        'description': f'Decoded content appears to contain structured data',
                        'recommendation': 'Avoid storing sensitive data in session tokens'
                    })
                    Logger.finding('medium', 'Token contains readable/structured data')
            except:
                pass

        # Check for JSON/serialized object patterns
        if '{' in sample or '[' in sample or ':' in sample:
            findings.append({
                'cookie': cookie_name,
                'severity': 'low',
                'issue': 'Token may contain serialized data',
                'description': 'Token structure suggests serialized object',
                'recommendation': 'Review for potential deserialization vulnerabilities'
            })
            Logger.finding('low', 'Token may contain serialized data')

        return findings

    def _detect_encoding(self, value: str) -> str:
        """Detect token encoding"""
        # Check base64
        if re.match(r'^[A-Za-z0-9+/=]+$', value):
            try:
                import base64
                base64.b64decode(value + '==')
                return 'base64'
            except:
                pass

        # Check URL-safe base64
        if re.match(r'^[A-Za-z0-9_-]+$', value):
            return 'base64url'

        # Check hex
        if re.match(r'^[a-fA-F0-9]+$', value):
            return 'hex'

        # Check URL encoding
        if '%' in value:
            return 'url_encoded'

        return 'unknown'

    def _analyze_length(self, cookie_name: str, tokens: List[Dict]) -> List[Dict]:
        """Analyze token length"""
        findings = []
        values = [t['value'] for t in tokens]

        if not values:
            return findings

        lengths = [len(v) for v in values]
        avg_length = sum(lengths) / len(lengths)
        min_length = min(lengths)
        max_length = max(lengths)

        if min_length < 16:
            findings.append({
                'cookie': cookie_name,
                'severity': 'medium',
                'issue': f'Short token length ({min_length} characters)',
                'description': 'Short tokens may be easier to brute-force',
                'recommendation': 'Use tokens of at least 32 characters'
            })
            Logger.finding('medium', f'Short token length: {min_length} characters')

        if min_length != max_length:
            Logger.info(f"  Variable length: {min_length}-{max_length} characters")

        return findings

    def _analyze_cookie_attributes(self, session: Dict) -> List[Dict]:
        """Analyze cookie security attributes"""
        findings = []
        Logger.info("\nAnalyzing cookie security attributes...")
        print("-" * 50)

        for name, data in session.get('cookies', {}).items():
            # Check Secure flag
            if not data.get('secure'):
                findings.append({
                    'cookie': name,
                    'severity': 'medium',
                    'issue': 'Missing Secure flag',
                    'description': 'Cookie can be transmitted over unencrypted HTTP',
                    'recommendation': 'Set Secure flag on all session cookies'
                })
                Logger.finding('medium', f'{name}: Missing Secure flag')

            # Check HttpOnly flag
            if not data.get('httponly'):
                findings.append({
                    'cookie': name,
                    'severity': 'medium',
                    'issue': 'Missing HttpOnly flag',
                    'description': 'Cookie accessible via JavaScript (XSS risk)',
                    'recommendation': 'Set HttpOnly flag on session cookies'
                })
                Logger.finding('medium', f'{name}: Missing HttpOnly flag')

            # Check expiration
            expires = data.get('expires')
            if expires:
                # Check for very long expiration
                if expires > time.time() + 86400 * 30:  # More than 30 days
                    findings.append({
                        'cookie': name,
                        'severity': 'low',
                        'issue': 'Long cookie expiration',
                        'description': 'Cookie expires more than 30 days from now',
                        'recommendation': 'Use shorter session lifetimes for sensitive applications'
                    })
                    Logger.finding('low', f'{name}: Long expiration (>30 days)')
            else:
                Logger.finding('info', f'{name}: Session cookie (no expiration)')

        return findings

    def _analyze_session_regeneration(self) -> List[Dict]:
        """Check if session is regenerated after authentication"""
        findings = []
        Logger.info("\nAnalyzing session regeneration...")
        print("-" * 50)

        # Compare pre-auth and post-auth session tokens
        for session in self.sessions:
            if not session.get('authenticated'):
                continue

            pre_auth = session.get('pre_auth_cookies', {})
            post_auth = session.get('cookies', {})

            # Check each session-like cookie
            session_cookie_names = ['session', 'sessionid', 'sid', 'phpsessid', 'jsessionid', 'asp.net_sessionid']

            for name in session_cookie_names:
                pre_value = pre_auth.get(name)
                post_data = post_auth.get(name, {})
                post_value = post_data.get('value') if isinstance(post_data, dict) else post_data

                if pre_value and post_value and pre_value == post_value:
                    findings.append({
                        'cookie': name,
                        'severity': 'high',
                        'issue': 'Session not regenerated after authentication',
                        'description': 'Same session token used before and after login (session fixation risk)',
                        'recommendation': 'Regenerate session ID after successful authentication'
                    })
                    Logger.finding('high', f'{name}: Session NOT regenerated after authentication (FIXATION RISK)')
                elif pre_value and post_value and pre_value != post_value:
                    Logger.finding('info', f'{name}: Session properly regenerated after authentication')

        return findings


# ============================================================================
# ADDITIONAL TESTS
# ============================================================================

class SessionTests:
    """Additional session security tests"""

    def __init__(self, target: str, session_cookie: str = None):
        self.target = target
        self.session_cookie = session_cookie

    def test_session_fixation(self) -> Dict[str, Any]:
        """Test for session fixation vulnerability"""
        Logger.info("\nTesting for session fixation...")

        result = {
            'vulnerable': False,
            'details': ''
        }

        try:
            # Create session with known ID
            session = requests.Session()
            session.headers.update({'User-Agent': DEFAULT_USER_AGENT})

            # Try to set our own session ID
            fake_session_id = 'attacker_controlled_session_' + hashlib.md5(str(time.time()).encode()).hexdigest()[:16]

            session.cookies.set('session', fake_session_id)
            session.cookies.set('PHPSESSID', fake_session_id)
            session.cookies.set('JSESSIONID', fake_session_id)

            response = session.get(self.target, timeout=DEFAULT_TIMEOUT, verify=False)

            # Check if our session ID was accepted
            for cookie in session.cookies:
                if cookie.value == fake_session_id:
                    result['vulnerable'] = True
                    result['details'] = f"Server accepted attacker-controlled session ID in {cookie.name}"
                    Logger.finding('high', f'Session fixation possible via {cookie.name}')
                    break

            if not result['vulnerable']:
                Logger.finding('info', 'Server did not accept attacker-controlled session ID')

        except requests.exceptions.RequestException as e:
            Logger.error(f"Test failed: {e}")

        return result

    def test_concurrent_sessions(self) -> Dict[str, Any]:
        """Test concurrent session handling"""
        Logger.info("\nTesting concurrent session handling...")

        result = {
            'allows_concurrent': None,
            'details': ''
        }

        # This test requires authenticated sessions
        Logger.info("  (Requires manual testing with multiple logins)")
        Logger.info("  Steps:")
        Logger.info("  1. Login from Browser A, note session token")
        Logger.info("  2. Login from Browser B with same credentials")
        Logger.info("  3. Check if Browser A session is invalidated")

        return result

    def test_logout_invalidation(self, logout_url: str) -> Dict[str, Any]:
        """Test if logout properly invalidates session"""
        Logger.info("\nTesting logout session invalidation...")

        result = {
            'properly_invalidated': False,
            'details': ''
        }

        if not self.session_cookie:
            Logger.warning("Session cookie required for this test")
            return result

        try:
            session = requests.Session()
            session.headers.update({'User-Agent': DEFAULT_USER_AGENT})

            # Parse and set the session cookie
            for c in self.session_cookie.split(';'):
                if '=' in c:
                    name, value = c.strip().split('=', 1)
                    session.cookies.set(name, value)

            # Make request to verify session works
            pre_logout = session.get(self.target, timeout=DEFAULT_TIMEOUT, verify=False)

            # Logout
            logout_response = session.get(
                urljoin(self.target, logout_url),
                timeout=DEFAULT_TIMEOUT,
                verify=False
            )

            # Try to use old session
            old_session = requests.Session()
            old_session.headers.update({'User-Agent': DEFAULT_USER_AGENT})
            for c in self.session_cookie.split(';'):
                if '=' in c:
                    name, value = c.strip().split('=', 1)
                    old_session.cookies.set(name, value)

            post_logout = old_session.get(self.target, timeout=DEFAULT_TIMEOUT, verify=False)

            # Compare responses
            if len(post_logout.text) == len(pre_logout.text):
                result['properly_invalidated'] = False
                result['details'] = 'Session appears to remain valid after logout'
                Logger.finding('high', 'Session NOT invalidated after logout')
            else:
                result['properly_invalidated'] = True
                result['details'] = 'Session appears to be invalidated after logout'
                Logger.finding('info', 'Session properly invalidated after logout')

        except requests.exceptions.RequestException as e:
            Logger.error(f"Test failed: {e}")

        return result


# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generate security assessment report"""

    def __init__(self, results: Dict[str, Any]):
        self.results = results

    def print_summary(self):
        """Print assessment summary"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}SESSION SECURITY ASSESSMENT SUMMARY{Colors.END}")
        print(f"{'='*60}\n")

        findings = self.results.get('findings', [])

        # Count by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        print(f"Total Findings: {len(findings)}")
        print(f"  {Colors.RED}Critical:{Colors.END} {severity_counts['critical']}")
        print(f"  {Colors.RED}High:{Colors.END}     {severity_counts['high']}")
        print(f"  {Colors.YELLOW}Medium:{Colors.END}   {severity_counts['medium']}")
        print(f"  {Colors.CYAN}Low:{Colors.END}      {severity_counts['low']}")
        print(f"  {Colors.BLUE}Info:{Colors.END}     {severity_counts['info']}")

        if severity_counts['critical'] > 0 or severity_counts['high'] > 0:
            print(f"\n{Colors.RED}[!] CRITICAL/HIGH SEVERITY ISSUES FOUND{Colors.END}")
            for finding in findings:
                if finding.get('severity', '').lower() in ['critical', 'high']:
                    print(f"  - {finding.get('issue')}")
                    if finding.get('recommendation'):
                        print(f"    Recommendation: {finding.get('recommendation')}")

    def export_json(self, filepath: str):
        """Export results to JSON"""
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        Logger.success(f"Results exported to: {filepath}")


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Session Security Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis (unauthenticated)
  %(prog)s -t https://target.com

  # Analysis with authentication
  %(prog)s -t https://target.com --login-url /login -u admin -p password

  # Full analysis with additional tests
  %(prog)s -t https://target.com --full-analysis

  # Export results
  %(prog)s -t https://target.com --output report.json
        """
    )

    parser.add_argument('-t', '--target', required=True, help='Target URL')
    parser.add_argument('--login-url', help='Login endpoint path')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('--user-field', default='username', help='Username field name')
    parser.add_argument('--pass-field', default='password', help='Password field name')
    parser.add_argument('--samples', type=int, default=SAMPLE_SIZE, help='Number of sessions to collect')
    parser.add_argument('--cookie', help='Existing session cookie to test')
    parser.add_argument('--logout-url', help='Logout endpoint for invalidation test')
    parser.add_argument('--full-analysis', action='store_true', help='Run all additional tests')
    parser.add_argument('--output', '-o', help='Output JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.CYAN}       SESSION SECURITY ANALYZER{Colors.END}")
    print(f"{Colors.CYAN}       For Authorized Testing Only{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}\n")

    Logger.info(f"Target: {args.target}")

    # Collect sessions
    collector = SessionCollector(
        target=args.target,
        login_url=args.login_url,
        username=args.username,
        password=args.password,
        username_field=args.user_field,
        password_field=args.pass_field
    )

    # Collect unauthenticated sessions
    sessions = collector.collect_unauthenticated(args.samples)

    # Collect authenticated sessions if credentials provided
    if args.login_url and args.username and args.password:
        auth_sessions = collector.collect_authenticated(args.samples)
        sessions.extend(auth_sessions)

    if not sessions:
        Logger.error("No sessions collected. Exiting.")
        sys.exit(1)

    # Analyze tokens
    analyzer = TokenAnalyzer(sessions)
    results = analyzer.analyze_all()

    # Run additional tests
    if args.full_analysis:
        tester = SessionTests(args.target, args.cookie)

        fixation_result = tester.test_session_fixation()
        if fixation_result['vulnerable']:
            results['findings'].append({
                'severity': 'high',
                'issue': 'Session fixation vulnerability',
                'description': fixation_result['details']
            })

        if args.logout_url:
            logout_result = tester.test_logout_invalidation(args.logout_url)
            if not logout_result['properly_invalidated']:
                results['findings'].append({
                    'severity': 'high',
                    'issue': 'Session not invalidated after logout',
                    'description': logout_result['details']
                })

    # Generate report
    report = ReportGenerator(results)
    report.print_summary()

    if args.output:
        report.export_json(args.output)


if __name__ == '__main__':
    main()
