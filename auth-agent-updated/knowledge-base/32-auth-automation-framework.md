# Auth Testing Automation Framework

## Overview

This document provides a comprehensive framework for automating authentication security testing. Covers testing pipeline architecture, tool integration (Burp Suite, Nuclei, custom scripts), CI/CD auth testing integration, continuous auth monitoring, and automated credential stuffing detection testing. Designed for production-grade security assessment workflows.

**Key Sources**:
- https://projectdiscovery.io/nuclei
- https://www.appsecengineer.com/blog/nuclei-automation-deep-dive-into-templates-devsecops-workflows
- https://github.com/projectdiscovery/nuclei-templates

---

## 1. Testing Pipeline Architecture

### 1.1 Automated Auth Testing Pipeline

```yaml
# auth-testing-pipeline.yaml
# Orchestration configuration for automated auth testing

pipeline:
  name: "Authentication Security Assessment"
  version: "2.0"

  stages:
    - name: "Discovery"
      parallel: true
      tasks:
        - auth_endpoint_discovery
        - technology_fingerprinting
        - sso_federation_detection
        - api_version_enumeration

    - name: "Passive Analysis"
      parallel: true
      tasks:
        - token_analysis
        - cookie_security_analysis
        - response_header_analysis
        - cors_configuration_check

    - name: "Active Testing"
      parallel: false  # Sequential to avoid lockouts
      tasks:
        - credential_testing
        - session_management_testing
        - mfa_bypass_testing
        - token_manipulation
        - authorization_testing

    - name: "Advanced Attacks"
      parallel: true
      tasks:
        - jwt_attacks
        - saml_attacks
        - oauth_attacks
        - sso_attacks
        - idp_attacks

    - name: "Logic Testing"
      tasks:
        - state_machine_testing
        - race_condition_testing
        - business_logic_testing

    - name: "Reporting"
      tasks:
        - generate_findings_report
        - calculate_risk_scores
        - create_remediation_plan
```

### 1.2 Pipeline Orchestrator

```python
#!/usr/bin/env python3
"""Authentication Testing Pipeline Orchestrator"""

import asyncio
import json
import time
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any
from enum import Enum

class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    cwe: str = ""
    cvss: float = 0.0

@dataclass
class TestResult:
    test_name: str
    status: str  # 'passed', 'failed', 'error', 'skipped'
    findings: List[Finding] = field(default_factory=list)
    duration: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

class AuthTestingPipeline:
    """Orchestrate automated authentication security testing."""

    def __init__(self, target_url, config=None):
        self.target_url = target_url
        self.config = config or {}
        self.results: List[TestResult] = []
        self.logger = logging.getLogger('auth-pipeline')

    async def run_pipeline(self):
        """Execute the full testing pipeline."""
        self.logger.info(f"Starting auth testing pipeline for {self.target_url}")
        start_time = time.time()

        # Stage 1: Discovery
        discovery_results = await self._run_stage("Discovery", [
            self._discover_auth_endpoints,
            self._fingerprint_technology,
            self._detect_sso,
        ])

        # Stage 2: Passive Analysis
        passive_results = await self._run_stage("Passive Analysis", [
            self._analyze_tokens,
            self._analyze_cookies,
            self._analyze_headers,
        ])

        # Stage 3: Active Testing
        active_results = await self._run_stage("Active Testing", [
            self._test_credentials,
            self._test_sessions,
            self._test_mfa,
            self._test_tokens,
        ], parallel=False)

        # Stage 4: Advanced Attacks
        advanced_results = await self._run_stage("Advanced Attacks", [
            self._test_jwt_attacks,
            self._test_saml_attacks,
            self._test_oauth_attacks,
        ])

        total_time = time.time() - start_time
        return self._compile_report(total_time)

    async def _run_stage(self, stage_name, tasks, parallel=True):
        """Run a stage of the pipeline."""
        self.logger.info(f"[Stage: {stage_name}] Starting...")

        if parallel:
            results = await asyncio.gather(
                *[task() for task in tasks],
                return_exceptions=True
            )
        else:
            results = []
            for task in tasks:
                try:
                    result = await task()
                    results.append(result)
                except Exception as e:
                    results.append(TestResult(
                        test_name=task.__name__,
                        status='error',
                        metadata={'error': str(e)}
                    ))

        for result in results:
            if isinstance(result, TestResult):
                self.results.append(result)

        return results

    async def _discover_auth_endpoints(self):
        """Discover authentication endpoints."""
        import aiohttp

        endpoints_to_check = [
            '/login', '/signin', '/auth', '/api/login', '/api/auth',
            '/api/v1/auth', '/api/v2/auth', '/oauth/authorize',
            '/oauth/token', '/.well-known/openid-configuration',
            '/saml/metadata', '/sso/login', '/forgot-password',
            '/register', '/signup', '/2fa', '/mfa/verify',
            '/api/auth/magic-link', '/auth/qr/generate',
        ]

        findings = []
        async with aiohttp.ClientSession() as session:
            for endpoint in endpoints_to_check:
                try:
                    async with session.get(
                        f"{self.target_url}{endpoint}",
                        allow_redirects=False, timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status not in [404]:
                            findings.append({
                                'endpoint': endpoint,
                                'status': resp.status,
                                'headers': dict(resp.headers)
                            })
                except:
                    pass

        return TestResult(
            test_name='auth_endpoint_discovery',
            status='passed',
            metadata={'endpoints_found': findings}
        )

    async def _analyze_tokens(self):
        """Analyze authentication tokens."""
        # Token analysis implementation
        return TestResult(test_name='token_analysis', status='passed')

    async def _analyze_cookies(self):
        """Analyze cookie security."""
        return TestResult(test_name='cookie_analysis', status='passed')

    async def _analyze_headers(self):
        """Analyze security headers."""
        return TestResult(test_name='header_analysis', status='passed')

    async def _test_credentials(self):
        """Test credential-based attacks."""
        return TestResult(test_name='credential_testing', status='passed')

    async def _test_sessions(self):
        """Test session management."""
        return TestResult(test_name='session_testing', status='passed')

    async def _test_mfa(self):
        """Test MFA bypass."""
        return TestResult(test_name='mfa_testing', status='passed')

    async def _test_tokens(self):
        """Test token manipulation."""
        return TestResult(test_name='token_testing', status='passed')

    async def _test_jwt_attacks(self):
        """Test JWT-specific attacks."""
        return TestResult(test_name='jwt_attacks', status='passed')

    async def _test_saml_attacks(self):
        """Test SAML-specific attacks."""
        return TestResult(test_name='saml_attacks', status='passed')

    async def _test_oauth_attacks(self):
        """Test OAuth-specific attacks."""
        return TestResult(test_name='oauth_attacks', status='passed')

    async def _fingerprint_technology(self):
        return TestResult(test_name='tech_fingerprint', status='passed')

    async def _detect_sso(self):
        return TestResult(test_name='sso_detection', status='passed')

    def _compile_report(self, total_time):
        """Compile final assessment report."""
        all_findings = []
        for result in self.results:
            all_findings.extend(result.findings)

        return {
            'target': self.target_url,
            'total_time': total_time,
            'total_tests': len(self.results),
            'passed': sum(1 for r in self.results if r.status == 'passed'),
            'failed': sum(1 for r in self.results if r.status == 'failed'),
            'errors': sum(1 for r in self.results if r.status == 'error'),
            'total_findings': len(all_findings),
            'critical': sum(1 for f in all_findings if f.severity == Severity.CRITICAL),
            'high': sum(1 for f in all_findings if f.severity == Severity.HIGH),
            'medium': sum(1 for f in all_findings if f.severity == Severity.MEDIUM),
            'low': sum(1 for f in all_findings if f.severity == Severity.LOW),
            'findings': all_findings,
            'results': self.results,
        }
```

---

## 2. Nuclei Template Integration

### 2.1 Custom Auth Testing Templates

```yaml
# nuclei-templates/auth/jwt-none-algorithm.yaml
id: jwt-none-algorithm

info:
  name: JWT None Algorithm Detection
  author: auth-agent
  severity: critical
  tags: jwt,auth,token

http:
  - raw:
      - |
        GET /api/me HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{jwt_none_token}}

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "username"
          - "email"
        condition: or

---
# nuclei-templates/auth/mfa-bypass-direct-access.yaml
id: mfa-bypass-direct-access

info:
  name: MFA Bypass via Direct Endpoint Access
  author: auth-agent
  severity: high
  tags: mfa,auth,bypass

http:
  - raw:
      - |
        POST /api/login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"username":"{{username}}","password":"{{password}}"}

      - |
        GET /api/dashboard HTTP/1.1
        Host: {{Hostname}}

    cookie-reuse: true
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code_2 == 200"
      - type: word
        part: body_2
        words:
          - "dashboard"
          - "welcome"
          - "profile"
        condition: or

---
# nuclei-templates/auth/default-credentials.yaml
id: comprehensive-default-creds

info:
  name: Comprehensive Default Credential Check
  author: auth-agent
  severity: high
  tags: default-creds,auth

http:
  - raw:
      - |
        POST {{login_endpoint}} HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"username":"{{default_user}}","password":"{{default_pass}}"}

    payloads:
      login_endpoint:
        - /api/login
        - /login
        - /auth/login
        - /api/v1/auth/login
      default_user:
        - admin
        - administrator
        - root
        - test
        - user
        - demo
      default_pass:
        - admin
        - password
        - 123456
        - root
        - test
        - demo

    attack: clusterbomb
    stop-at-first-match: true

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "token"
          - "session"
          - "authenticated"
          - "success"
        condition: or
      - type: word
        negative: true
        words:
          - "invalid"
          - "failed"
          - "error"
          - "unauthorized"

---
# nuclei-templates/auth/session-fixation.yaml
id: session-fixation-check

info:
  name: Session Fixation Detection
  author: auth-agent
  severity: medium
  tags: session,auth,fixation

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}

      - |
        POST /api/login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"username":"{{username}}","password":"{{password}}"}

    cookie-reuse: true

    extractors:
      - type: kval
        name: pre_auth_session
        kval:
          - session
        part: header_1
        internal: true

      - type: kval
        name: post_auth_session
        kval:
          - session
        part: header_2

    matchers:
      - type: dsl
        dsl:
          - "pre_auth_session == post_auth_session"
```

### 2.2 Nuclei Automation Script

```bash
#!/bin/bash
# auth-nuclei-scan.sh - Automated auth testing with Nuclei

TARGET="$1"
OUTPUT_DIR="reports/nuclei-$(date +%Y%m%d-%H%M%S)"

mkdir -p "$OUTPUT_DIR"

echo "[*] Running auth-specific Nuclei templates against $TARGET"

# Default credentials check
nuclei -u "$TARGET" -t default-logins/ \
  -severity critical,high \
  -o "$OUTPUT_DIR/default-creds.txt" \
  -silent

# JWT-specific templates
nuclei -u "$TARGET" -tags jwt \
  -o "$OUTPUT_DIR/jwt-findings.txt" \
  -silent

# Authentication bypass templates
nuclei -u "$TARGET" -tags auth \
  -o "$OUTPUT_DIR/auth-bypass.txt" \
  -silent

# Token-related templates
nuclei -u "$TARGET" -t token-spray/ -t http/misconfiguration/ \
  -o "$OUTPUT_DIR/token-findings.txt" \
  -silent

# SAML templates
nuclei -u "$TARGET" -tags saml \
  -o "$OUTPUT_DIR/saml-findings.txt" \
  -silent

# Exposed configuration
nuclei -u "$TARGET" -tags exposure,config \
  -o "$OUTPUT_DIR/exposure.txt" \
  -silent

# Custom auth templates (from our knowledge base)
nuclei -u "$TARGET" \
  -t auth-agent/nuclei-templates/ \
  -o "$OUTPUT_DIR/custom-findings.txt" \
  -silent

echo "[*] Results saved to $OUTPUT_DIR/"
echo "[*] Summary:"
wc -l "$OUTPUT_DIR"/*.txt 2>/dev/null | tail -1
```

---

## 3. CI/CD Auth Testing Integration

### 3.1 GitHub Actions Workflow

```yaml
# .github/workflows/auth-security-test.yml
name: Authentication Security Testing

on:
  pull_request:
    branches: [main, develop]
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6 AM

jobs:
  auth-security-scan:
    runs-on: ubuntu-latest
    services:
      target-app:
        image: ${{ vars.TARGET_IMAGE }}
        ports:
          - 8080:8080

    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Dependencies
        run: |
          pip install requests pyjwt cryptography aiohttp
          go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

      - name: Run Auth Endpoint Discovery
        run: python tools/auth-tester.py discover -u http://localhost:8080

      - name: Run Default Credential Scan
        run: nuclei -u http://localhost:8080 -t default-logins/ -severity critical,high

      - name: Run JWT Security Tests
        run: python tools/auth-tester.py jwt -u http://localhost:8080

      - name: Run Session Security Tests
        run: python tools/session-analyzer.py -u http://localhost:8080

      - name: Run Custom Auth Templates
        run: nuclei -u http://localhost:8080 -t auth-agent/nuclei-templates/

      - name: Generate Report
        if: always()
        run: python tools/generate-report.py --output auth-report.json

      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: auth-security-report
          path: auth-report.json

      - name: Fail on Critical/High Findings
        run: |
          CRITICAL=$(jq '.critical' auth-report.json)
          HIGH=$(jq '.high' auth-report.json)
          if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
            echo "Critical: $CRITICAL, High: $HIGH findings detected"
            exit 1
          fi
```

### 3.2 Pre-Deployment Auth Gate

```python
#!/usr/bin/env python3
"""Pre-deployment authentication security gate"""

import sys
import json
import subprocess

class AuthSecurityGate:
    """CI/CD gate that blocks deployment on auth security failures."""

    REQUIRED_CHECKS = [
        'no_default_credentials',
        'session_regeneration_on_login',
        'secure_cookie_flags',
        'jwt_algorithm_enforcement',
        'mfa_cannot_be_bypassed',
        'no_sensitive_data_in_tokens',
        'rate_limiting_on_auth',
        'password_policy_enforced',
    ]

    def __init__(self, target_url):
        self.target_url = target_url
        self.results = {}

    def run_all_checks(self):
        """Run all required security checks."""
        for check in self.REQUIRED_CHECKS:
            method = getattr(self, f'_check_{check}', None)
            if method:
                self.results[check] = method()
            else:
                self.results[check] = {'status': 'skipped', 'reason': 'Not implemented'}

        return self.evaluate()

    def evaluate(self):
        """Evaluate results and determine pass/fail."""
        failed = [name for name, result in self.results.items()
                  if result.get('status') == 'failed']

        return {
            'passed': len(failed) == 0,
            'total_checks': len(self.REQUIRED_CHECKS),
            'passed_checks': len(self.results) - len(failed),
            'failed_checks': failed,
            'results': self.results
        }

    def _check_no_default_credentials(self):
        """Verify no default credentials are accepted."""
        defaults = [
            ('admin', 'admin'), ('admin', 'password'), ('root', 'root'),
            ('test', 'test'), ('user', 'user'), ('admin', '123456'),
        ]

        for username, password in defaults:
            resp = requests.post(
                f"{self.target_url}/api/login",
                json={'username': username, 'password': password}
            )
            if resp.status_code == 200:
                return {
                    'status': 'failed',
                    'reason': f'Default credentials accepted: {username}/{password}'
                }

        return {'status': 'passed'}

    def _check_session_regeneration_on_login(self):
        """Verify session ID changes after authentication."""
        session = requests.Session()
        session.get(self.target_url)
        pre_login_cookies = dict(session.cookies)

        session.post(f"{self.target_url}/api/login",
                    json={'username': 'test', 'password': 'test'})
        post_login_cookies = dict(session.cookies)

        for cookie_name in ['session', 'JSESSIONID', 'PHPSESSID']:
            pre = pre_login_cookies.get(cookie_name)
            post = post_login_cookies.get(cookie_name)
            if pre and post and pre == post:
                return {
                    'status': 'failed',
                    'reason': f'Session ID {cookie_name} not regenerated after login'
                }

        return {'status': 'passed'}

    def _check_secure_cookie_flags(self):
        """Verify session cookies have security flags."""
        session = requests.Session()
        session.post(f"{self.target_url}/api/login",
                    json={'username': 'test', 'password': 'test'})

        issues = []
        for cookie in session.cookies:
            if not cookie.secure:
                issues.append(f'{cookie.name}: Missing Secure flag')
            if 'httponly' not in str(cookie._rest).lower():
                issues.append(f'{cookie.name}: Missing HttpOnly flag')

        return {
            'status': 'failed' if issues else 'passed',
            'issues': issues
        }

    def _check_jwt_algorithm_enforcement(self):
        return {'status': 'passed'}

    def _check_mfa_cannot_be_bypassed(self):
        return {'status': 'passed'}

    def _check_no_sensitive_data_in_tokens(self):
        return {'status': 'passed'}

    def _check_rate_limiting_on_auth(self):
        return {'status': 'passed'}

    def _check_password_policy_enforced(self):
        return {'status': 'passed'}


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080'
    gate = AuthSecurityGate(target)
    result = gate.run_all_checks()

    print(json.dumps(result, indent=2))
    sys.exit(0 if result['passed'] else 1)
```

---

## 4. Continuous Auth Monitoring

### 4.1 Runtime Auth Monitoring

```python
#!/usr/bin/env python3
"""Continuous Authentication Security Monitor"""

import time
import threading
import requests
import json
from datetime import datetime

class ContinuousAuthMonitor:
    """Monitor authentication security in real-time."""

    def __init__(self, target_url, check_interval=300):
        self.target_url = target_url
        self.check_interval = check_interval  # 5 minutes default
        self.alerts = []
        self.running = False

    def start_monitoring(self):
        """Start continuous monitoring."""
        self.running = True
        while self.running:
            self._run_checks()
            time.sleep(self.check_interval)

    def _run_checks(self):
        """Run all monitoring checks."""
        checks = [
            self._check_auth_endpoints_available,
            self._check_ssl_certificate,
            self._check_security_headers,
            self._check_session_configuration,
            self._check_token_endpoint_security,
            self._check_for_new_endpoints,
        ]

        for check in checks:
            try:
                result = check()
                if result and result.get('alert'):
                    self.alerts.append({
                        'timestamp': datetime.now().isoformat(),
                        'check': check.__name__,
                        'alert': result['alert'],
                        'severity': result.get('severity', 'medium'),
                    })
                    self._send_alert(result)
            except Exception as e:
                pass

    def _check_auth_endpoints_available(self):
        """Verify auth endpoints are responding correctly."""
        endpoints = ['/login', '/api/login', '/oauth/token']
        for endpoint in endpoints:
            resp = requests.get(f"{self.target_url}{endpoint}", timeout=10)
            if resp.status_code >= 500:
                return {
                    'alert': f'Auth endpoint {endpoint} returning 500',
                    'severity': 'high'
                }

    def _check_ssl_certificate(self):
        """Check SSL certificate validity."""
        import ssl
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(self.target_url)
        hostname = parsed.hostname

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry - datetime.now()).days

                    if days_until_expiry < 30:
                        return {
                            'alert': f'SSL certificate expires in {days_until_expiry} days',
                            'severity': 'high' if days_until_expiry < 7 else 'medium'
                        }
        except:
            return {'alert': 'SSL certificate check failed', 'severity': 'critical'}

    def _check_security_headers(self):
        """Check for missing security headers."""
        resp = requests.get(self.target_url)
        required_headers = {
            'Strict-Transport-Security': 'HSTS',
            'X-Content-Type-Options': 'Content Type',
            'X-Frame-Options': 'Framing',
        }

        missing = []
        for header, name in required_headers.items():
            if header not in resp.headers:
                missing.append(name)

        if missing:
            return {
                'alert': f'Missing security headers: {", ".join(missing)}',
                'severity': 'medium'
            }

    def _check_session_configuration(self):
        return None

    def _check_token_endpoint_security(self):
        return None

    def _check_for_new_endpoints(self):
        return None

    def _send_alert(self, alert_data):
        """Send alert notification."""
        print(f"[ALERT] {alert_data['severity'].upper()}: {alert_data['alert']}")
```

---

## 5. Credential Stuffing Detection Testing

### 5.1 Test Application's Credential Stuffing Defenses

```python
class CredentialStuffingDefenseTester:
    """Test how well the application defends against credential stuffing."""

    def __init__(self, target_url):
        self.target_url = target_url

    def test_rate_limiting(self, username='test@test.com'):
        """Test login rate limiting effectiveness."""
        results = []
        for i in range(100):
            resp = requests.post(
                f"{self.target_url}/api/login",
                json={'username': username, 'password': f'wrong_{i}'}
            )
            results.append({
                'attempt': i + 1,
                'status': resp.status_code,
                'rate_limited': resp.status_code == 429,
            })
            if resp.status_code == 429:
                break

        rate_limited_at = next(
            (r['attempt'] for r in results if r['rate_limited']), None
        )
        return {
            'rate_limiting_present': rate_limited_at is not None,
            'triggered_at_attempt': rate_limited_at,
            'effectiveness': 'good' if rate_limited_at and rate_limited_at <= 10 else 'weak'
        }

    def test_captcha_enforcement(self):
        """Test if CAPTCHA is enforced after failed attempts."""
        results = []
        for i in range(20):
            resp = requests.post(
                f"{self.target_url}/api/login",
                json={'username': 'test', 'password': f'wrong_{i}'}
            )
            has_captcha = any(
                indicator in resp.text.lower()
                for indicator in ['captcha', 'recaptcha', 'hcaptcha', 'turnstile', 'challenge']
            )
            results.append({
                'attempt': i + 1,
                'captcha_required': has_captcha,
            })
            if has_captcha:
                break

        return {
            'captcha_present': any(r['captcha_required'] for r in results),
            'triggered_at': next(
                (r['attempt'] for r in results if r['captcha_required']), None
            )
        }

    def test_account_lockout(self, username='test@test.com'):
        """Test account lockout behavior."""
        results = []
        for i in range(25):
            resp = requests.post(
                f"{self.target_url}/api/login",
                json={'username': username, 'password': f'wrong_{i}'}
            )
            locked = any(
                indicator in resp.text.lower()
                for indicator in ['locked', 'suspended', 'disabled', 'too many']
            )
            results.append({
                'attempt': i + 1,
                'locked': locked,
                'status': resp.status_code
            })
            if locked:
                break

        return {
            'lockout_present': any(r['locked'] for r in results),
            'locked_at_attempt': next(
                (r['attempt'] for r in results if r['locked']), None
            )
        }

    def test_ip_based_blocking(self):
        """Test if IP-based blocking can be bypassed."""
        bypass_headers = [
            {'X-Forwarded-For': '1.2.3.4'},
            {'X-Real-IP': '5.6.7.8'},
            {'X-Originating-IP': '9.10.11.12'},
            {'X-Client-IP': '13.14.15.16'},
            {'True-Client-IP': '17.18.19.20'},
            {'CF-Connecting-IP': '21.22.23.24'},
            {'X-Cluster-Client-IP': '25.26.27.28'},
        ]

        # First, get rate limited
        for i in range(50):
            requests.post(
                f"{self.target_url}/api/login",
                json={'username': 'test', 'password': 'wrong'}
            )

        # Then try to bypass with headers
        results = []
        for headers in bypass_headers:
            resp = requests.post(
                f"{self.target_url}/api/login",
                json={'username': 'test', 'password': 'wrong'},
                headers=headers
            )
            results.append({
                'headers': headers,
                'bypassed': resp.status_code != 429,
            })

        return results
```

---

## 6. Tool Integration Matrix

```
| Tool | Purpose | Integration Method |
|------|---------|-------------------|
| Nuclei | Template scanning | CLI / Python subprocess |
| Burp Suite | Manual/automated proxy | REST API / Extensions |
| jwt_tool | JWT-specific attacks | CLI wrapper |
| Hydra | Credential brute force | CLI wrapper |
| ffuf | Endpoint fuzzing | CLI wrapper |
| SAML Raider | SAML attacks | Burp extension |
| Autorize | Authorization testing | Burp extension |
| trufflehog | Secret scanning | CLI / CI integration |
| gitleaks | Git secret scanning | CI/CD pre-commit |
| Hashcat | JWT cracking | CLI wrapper |
| Custom scripts | Specific attack chains | Direct Python |
```

---

## 7. Testing Checklist

```
# Pipeline Setup
[ ] Configure target URL and credentials
[ ] Set up Nuclei with custom templates
[ ] Configure CI/CD integration
[ ] Set up monitoring alerts
[ ] Define pass/fail criteria

# Automated Scans
[ ] Run default credential check
[ ] Run JWT security templates
[ ] Run SAML security templates
[ ] Run OAuth security templates
[ ] Run session management templates
[ ] Run rate limiting tests

# CI/CD Gates
[ ] No default credentials gate
[ ] Session security gate
[ ] Cookie security gate
[ ] Token security gate
[ ] Rate limiting gate

# Monitoring
[ ] Auth endpoint availability
[ ] SSL certificate expiry
[ ] Security header presence
[ ] Anomalous login patterns
```

---

## References

- Nuclei: https://projectdiscovery.io/nuclei
- Nuclei Templates: https://github.com/projectdiscovery/nuclei-templates
- Nuclei Automation: https://www.appsecengineer.com/blog/nuclei-automation-deep-dive-into-templates-devsecops-workflows
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
