#!/usr/bin/env python3
"""
GraphQL Authentication & Authorization Tester
Tests for introspection, batching bypass, alias bypass,
unprotected mutations, and nested query auth issues.
"""

import requests
import sys
import json

class GraphQLAuthTester:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.session = requests.Session()
        self.findings = []

    def test_introspection(self):
        """Check if GraphQL introspection is enabled."""
        print("[*] Testing introspection...")
        queries = [
            '{ __schema { types { name fields { name type { name } } } } }',
            '{ __schema { queryType { name } mutationType { name } } }',
        ]
        for q in queries:
            resp = self.session.post(self.endpoint, json={'query': q})
            if resp.status_code == 200:
                data = resp.json()
                if 'data' in data and '__schema' in data.get('data', {}):
                    self.findings.append({
                        'severity': 'HIGH',
                        'type': 'GraphQL Introspection Enabled',
                        'details': 'Full schema exposed'
                    })
                    print("  [HIGH] Introspection enabled - schema exposed")
                    self._analyze_schema(data['data']['__schema'])
                    return data['data']['__schema']
        print("  [-] Introspection disabled")
        return None

    def _analyze_schema(self, schema):
        """Find sensitive types and fields in schema."""
        sensitive_keywords = ['admin', 'delete', 'role', 'permission',
                             'password', 'secret', 'token', 'key', 'internal']
        for t in schema.get('types', []):
            if t['name'].startswith('__'):
                continue
            for f in (t.get('fields') or []):
                if any(kw in f['name'].lower() for kw in sensitive_keywords):
                    print(f"    [!] Sensitive field: {t['name']}.{f['name']}")

    def test_batching(self):
        """Test query batching for rate limit bypass."""
        print("[*] Testing batching...")
        batch = [
            {'query': '{ __typename }'},
            {'query': '{ __typename }'},
            {'query': '{ __typename }'},
        ]
        resp = self.session.post(self.endpoint, json=batch)
        if resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) == 3:
                    self.findings.append({
                        'severity': 'MEDIUM',
                        'type': 'GraphQL Batching Enabled',
                        'details': 'Rate limit bypass possible via query batching'
                    })
                    print("  [MEDIUM] Batching enabled - rate limit bypass possible")
                    return True
            except:
                pass
        print("  [-] Batching not supported")
        return False

    def test_alias_bypass(self):
        """Test alias-based rate limit bypass."""
        print("[*] Testing alias bypass...")
        query = '{ ' + ' '.join(f'a{i}: __typename' for i in range(20)) + ' }'
        resp = self.session.post(self.endpoint, json={'query': query})
        if resp.status_code == 200:
            data = resp.json()
            if 'data' in data and len(data['data']) >= 20:
                self.findings.append({
                    'severity': 'MEDIUM',
                    'type': 'GraphQL Alias Bypass',
                    'details': 'Multiple operations via aliases in single request'
                })
                print("  [MEDIUM] Alias bypass works - 20 operations in one query")
                return True
        return False

    def test_common_mutations(self):
        """Test common admin mutations without auth."""
        print("[*] Testing unprotected mutations...")
        mutations = [
            ('updateUserRole', 'mutation { updateUserRole(userId:"1",role:"admin") { id } }'),
            ('deleteUser', 'mutation { deleteUser(id:"1") { success } }'),
            ('createApiKey', 'mutation { createApiKey(name:"test") { key } }'),
            ('createUser', 'mutation { createUser(email:"test@test.com",role:"admin") { id } }'),
        ]
        for name, mutation in mutations:
            resp = self.session.post(self.endpoint, json={'query': mutation})
            if resp.status_code == 200:
                data = resp.json()
                if 'data' in data and data['data'] is not None:
                    has_errors = bool(data.get('errors'))
                    if not has_errors:
                        self.findings.append({
                            'severity': 'CRITICAL',
                            'type': f'Unprotected Mutation: {name}',
                        })
                        print(f"  [CRITICAL] Mutation accessible: {name}")

    def test_depth_limit(self):
        """Test for missing query depth limits (DoS)."""
        print("[*] Testing depth limits...")
        deep_query = '{ __schema ' + '{ types ' * 10 + '{ name }' + ' }' * 10 + ' }'
        resp = self.session.post(self.endpoint, json={'query': deep_query}, timeout=10)
        if resp.status_code == 200:
            print("  [LOW] No query depth limit detected")

    def run(self):
        """Execute all GraphQL auth tests."""
        print(f"{'='*60}")
        print(f"GraphQL Auth Tester")
        print(f"Endpoint: {self.endpoint}")
        print(f"{'='*60}")

        self.test_introspection()
        self.test_batching()
        self.test_alias_bypass()
        self.test_common_mutations()
        self.test_depth_limit()

        print(f"\n{'='*60}")
        print(f"RESULTS: {len(self.findings)} findings")
        print(f"{'='*60}")
        for f in self.findings:
            print(f"  [{f['severity']}] {f['type']}")

        return self.findings


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <graphql_endpoint>")
        print(f"Example: {sys.argv[0]} https://target.com/graphql")
        sys.exit(1)

    tester = GraphQLAuthTester(sys.argv[1])
    tester.run()
