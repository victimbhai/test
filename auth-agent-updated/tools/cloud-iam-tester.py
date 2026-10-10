#!/usr/bin/env python3
"""
Cloud IAM Privilege Escalation Tester
Tests AWS IAM, Azure AD, and GCP for auth misconfigurations
and privilege escalation paths.
"""

import subprocess
import json
import sys

class CloudIAMTester:
    def __init__(self, cloud_provider):
        self.provider = cloud_provider.lower()
        self.findings = []

    def run_cmd(self, cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'timeout', 1

    # --- AWS ---
    def test_aws_identity(self):
        print("[*] AWS: Checking caller identity...")
        out, err, rc = self.run_cmd('aws sts get-caller-identity 2>/dev/null')
        if rc == 0:
            identity = json.loads(out)
            print(f"  Account: {identity.get('Account')}")
            print(f"  ARN: {identity.get('Arn')}")
            return identity
        print("  [-] Not authenticated to AWS")
        return None

    def test_aws_iam_enum(self):
        print("[*] AWS: Enumerating IAM permissions...")
        dangerous_actions = [
            ('iam:CreateUser', 'aws iam create-user --user-name test-enum-probe --dry-run 2>&1'),
            ('iam:AttachUserPolicy', 'aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d/ -f2) 2>&1'),
            ('iam:PassRole', 'aws iam list-roles --query "Roles[?contains(RoleName,\'lambda\')]" 2>&1'),
            ('sts:AssumeRole', 'aws iam list-roles --query "Roles[*].{Name:RoleName,Trust:AssumeRolePolicyDocument}" 2>&1'),
            ('lambda:CreateFunction', 'aws lambda list-functions --max-items 1 2>&1'),
        ]

        for action, cmd in dangerous_actions:
            out, err, rc = self.run_cmd(cmd)
            if rc == 0 and 'AccessDenied' not in out and 'AccessDenied' not in err:
                self.findings.append({
                    'severity': 'HIGH',
                    'type': f'AWS Escalation Path: {action}',
                })
                print(f"  [HIGH] Has permission: {action}")

    def test_aws_metadata(self):
        print("[*] AWS: Testing metadata service...")
        out, err, rc = self.run_cmd('curl -s -m 5 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null')
        if rc == 0 and out.strip():
            role_name = out.strip().split('\n')[0]
            self.findings.append({
                'severity': 'CRITICAL',
                'type': 'AWS IMDSv1 Accessible',
                'details': f'Role: {role_name}',
            })
            print(f"  [CRITICAL] IMDSv1 accessible, role: {role_name}")

    def test_aws_confused_deputy(self):
        print("[*] AWS: Checking for confused deputy conditions...")
        out, err, rc = self.run_cmd('aws iam list-roles --query "Roles[?AssumeRolePolicyDocument.Statement[?Condition==null && Principal.Service]]" 2>&1')
        if rc == 0:
            try:
                roles = json.loads(out)
                for role in roles[:5]:
                    self.findings.append({
                        'severity': 'HIGH',
                        'type': 'AWS Confused Deputy Risk',
                        'details': f"Role {role.get('RoleName')} has no ExternalId condition",
                    })
                    print(f"  [HIGH] No ExternalId: {role.get('RoleName')}")
            except:
                pass

    # --- Azure ---
    def test_azure_identity(self):
        print("[*] Azure: Checking identity...")
        out, err, rc = self.run_cmd('az account show 2>/dev/null')
        if rc == 0:
            identity = json.loads(out)
            print(f"  Tenant: {identity.get('tenantId')}")
            print(f"  User: {identity.get('user', {}).get('name')}")
            return identity
        print("  [-] Not authenticated to Azure")
        return None

    def test_azure_roles(self):
        print("[*] Azure: Enumerating role assignments...")
        out, err, rc = self.run_cmd('az role assignment list --all 2>/dev/null')
        if rc == 0:
            try:
                assignments = json.loads(out)
                high_priv_roles = ['Owner', 'Contributor', 'User Access Administrator',
                                   'Global Administrator', 'Privileged Role Administrator']
                for a in assignments:
                    if any(r in a.get('roleDefinitionName', '') for r in high_priv_roles):
                        self.findings.append({
                            'severity': 'HIGH',
                            'type': f"Azure High-Priv Role: {a.get('roleDefinitionName')}",
                            'details': f"Principal: {a.get('principalName')}",
                        })
                        print(f"  [HIGH] {a.get('roleDefinitionName')}: {a.get('principalName')}")
            except:
                pass

    # --- GCP ---
    def test_gcp_identity(self):
        print("[*] GCP: Checking identity...")
        out, err, rc = self.run_cmd('gcloud auth list --format=json 2>/dev/null')
        if rc == 0:
            try:
                accounts = json.loads(out)
                for a in accounts:
                    if a.get('status') == 'ACTIVE':
                        print(f"  Account: {a.get('account')}")
                        return a
            except:
                pass
        print("  [-] Not authenticated to GCP")
        return None

    def test_gcp_sa_impersonation(self):
        print("[*] GCP: Checking SA impersonation...")
        out, err, rc = self.run_cmd('gcloud iam service-accounts list --format=json 2>/dev/null')
        if rc == 0:
            try:
                sas = json.loads(out)
                for sa in sas[:5]:
                    email = sa.get('email', '')
                    iam_out, _, _ = self.run_cmd(
                        f'gcloud iam service-accounts get-iam-policy {email} --format=json 2>/dev/null'
                    )
                    if 'iam.serviceAccountTokenCreator' in iam_out:
                        self.findings.append({
                            'severity': 'HIGH',
                            'type': 'GCP SA Impersonation',
                            'details': f'Can impersonate: {email}',
                        })
                        print(f"  [HIGH] Can impersonate SA: {email}")
            except:
                pass

    def test_gcp_metadata(self):
        print("[*] GCP: Testing metadata service...")
        out, err, rc = self.run_cmd(
            'curl -s -m 5 -H "Metadata-Flavor: Google" '
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token 2>/dev/null'
        )
        if rc == 0 and 'access_token' in out:
            self.findings.append({
                'severity': 'CRITICAL',
                'type': 'GCP Metadata Token Accessible',
            })
            print("  [CRITICAL] GCP metadata token accessible")

    def run(self):
        print(f"{'='*60}")
        print(f"Cloud IAM Tester - Provider: {self.provider}")
        print(f"{'='*60}")

        if self.provider == 'aws':
            if self.test_aws_identity():
                self.test_aws_iam_enum()
                self.test_aws_metadata()
                self.test_aws_confused_deputy()
        elif self.provider == 'azure':
            if self.test_azure_identity():
                self.test_azure_roles()
        elif self.provider == 'gcp':
            if self.test_gcp_identity():
                self.test_gcp_sa_impersonation()
                self.test_gcp_metadata()
        elif self.provider == 'all':
            self.test_aws_identity() and (self.test_aws_iam_enum(), self.test_aws_metadata(), self.test_aws_confused_deputy())
            self.test_azure_identity() and self.test_azure_roles()
            self.test_gcp_identity() and (self.test_gcp_sa_impersonation(), self.test_gcp_metadata())

        print(f"\n{'='*60}")
        print(f"RESULTS: {len(self.findings)} findings")
        print(f"{'='*60}")
        for f in self.findings:
            print(f"  [{f['severity']}] {f['type']}")
        return self.findings


if __name__ == '__main__':
    provider = sys.argv[1] if len(sys.argv) > 1 else 'all'
    if provider not in ['aws', 'azure', 'gcp', 'all']:
        print(f"Usage: {sys.argv[0]} [aws|azure|gcp|all]")
        sys.exit(1)
    tester = CloudIAMTester(provider)
    tester.run()
