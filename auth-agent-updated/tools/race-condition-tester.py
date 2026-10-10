#!/usr/bin/env python3
"""
Race Condition Auth Tester
Tests for single-packet race conditions in auth flows:
MFA bypass, registration races, coupon/token reuse.
"""

import requests
import sys
import threading
import time
import socket
import ssl

class RaceConditionTester:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.findings = []

    def _send_parallel(self, prepared_requests, count=10):
        """Send multiple requests in parallel using threads."""
        results = [None] * count
        barriers = threading.Barrier(count)

        def send_req(idx, req):
            session = requests.Session()
            barriers.wait()
            try:
                results[idx] = session.send(req, allow_redirects=False, timeout=15)
            except Exception as e:
                results[idx] = e

        threads = []
        for i in range(count):
            t = threading.Thread(target=send_req, args=(i, prepared_requests[i % len(prepared_requests)]))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=20)

        return results

    def test_mfa_race(self, login_url, mfa_url, credentials, mfa_code):
        """Test MFA bypass via race condition - submit code multiple times."""
        print("[*] Testing MFA bypass race condition...")
        session = requests.Session()

        # Login first
        session.post(login_url, data=credentials, allow_redirects=False)

        # Prepare parallel MFA submissions
        reqs = []
        for _ in range(10):
            req = requests.Request('POST', mfa_url, data={'code': mfa_code})
            prepared = session.prepare_request(req)
            reqs.append(prepared)

        results = self._send_parallel(reqs, 10)
        successes = sum(1 for r in results if isinstance(r, requests.Response) and r.status_code == 200)

        if successes > 1:
            self.findings.append({
                'severity': 'HIGH',
                'type': 'MFA Race Condition',
                'details': f'{successes}/10 parallel MFA submissions succeeded',
            })
            print(f"  [HIGH] {successes}/10 MFA submissions succeeded")
        else:
            print(f"  [-] MFA race: {successes}/10 succeeded (no race)")

    def test_registration_race(self, register_url, email):
        """Test duplicate account creation via race condition."""
        print("[*] Testing registration race condition...")
        reqs = []
        session = requests.Session()

        for i in range(10):
            data = {'email': email, 'password': f'TestPass{i}!', 'username': f'racetest_{i}'}
            req = requests.Request('POST', register_url, data=data)
            reqs.append(session.prepare_request(req))

        results = self._send_parallel(reqs, 10)
        successes = sum(1 for r in results if isinstance(r, requests.Response) and r.status_code in [200, 201, 302])

        if successes > 1:
            self.findings.append({
                'severity': 'MEDIUM',
                'type': 'Registration Race Condition',
                'details': f'{successes}/10 registrations succeeded for same email',
            })
            print(f"  [MEDIUM] {successes}/10 registrations succeeded")
        else:
            print(f"  [-] Registration race: {successes}/10 (properly serialized)")

    def test_token_reuse_race(self, reset_url, token):
        """Test password reset token reuse via race condition."""
        print("[*] Testing token reuse race condition...")
        reqs = []
        session = requests.Session()

        for i in range(10):
            data = {'token': token, 'new_password': f'NewPass{i}!'}
            req = requests.Request('POST', reset_url, data=data)
            reqs.append(session.prepare_request(req))

        results = self._send_parallel(reqs, 10)
        successes = sum(1 for r in results if isinstance(r, requests.Response) and r.status_code in [200, 302])

        if successes > 1:
            self.findings.append({
                'severity': 'HIGH',
                'type': 'Token Reuse Race Condition',
                'details': f'{successes}/10 token uses succeeded',
            })
            print(f"  [HIGH] {successes}/10 token uses succeeded")

    def test_rate_limit_race(self, login_url, credentials):
        """Test if rate limiting can be bypassed via race."""
        print("[*] Testing rate limit bypass via race...")
        reqs = []
        session = requests.Session()

        for _ in range(20):
            req = requests.Request('POST', login_url, data=credentials)
            reqs.append(session.prepare_request(req))

        results = self._send_parallel(reqs, 20)
        non_rate_limited = sum(1 for r in results
                              if isinstance(r, requests.Response) and r.status_code != 429)

        if non_rate_limited > 10:
            self.findings.append({
                'severity': 'MEDIUM',
                'type': 'Rate Limit Race Bypass',
                'details': f'{non_rate_limited}/20 requests not rate-limited',
            })
            print(f"  [MEDIUM] {non_rate_limited}/20 avoided rate limit")

    def report(self):
        print(f"\n{'='*60}")
        print(f"Race Condition Test Results: {len(self.findings)} findings")
        print(f"{'='*60}")
        for f in self.findings:
            print(f"  [{f['severity']}] {f['type']}: {f['details']}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print("Requires manual configuration of endpoints and credentials.")
        sys.exit(1)

    tester = RaceConditionTester(sys.argv[1])
    print("Race Condition Tester initialized.")
    print("Configure test parameters in script or use as library.")
    tester.report()
