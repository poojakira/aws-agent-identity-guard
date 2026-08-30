# Runbook — AWS Agent Identity Guard v0.3.0

**Last updated:** 2026-08-08  
**Audience:** SREs, DevSecOps, Cloud Security Engineers  
**Severity:** This tool gates deployments. If it's broken, insecure agent roles may reach production.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Configuration](#3-configuration)
4. [Usage — Static Scan](#4-usage--static-scan)
5. [Usage — Live AWS Scan](#5-usage--live-aws-scan)
6. [Usage — Remediation](#6-usage--remediation)
7. [Interpreting Results](#7-interpreting-results)
8. [Exit Codes](#8-exit-codes)
9. [CI/CD Integration](#9-cicd-integration)
10. [Troubleshooting](#10-troubleshooting)
11. [Alerting & Escalation](#11-alerting--escalation)
12. [Maintenance](#12-maintenance)

---

## 1. Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | Verify with `python --version` or `py --version` (Windows) |
| pip | Latest | Comes with Python. Upgrade: `python -m pip install --upgrade pip` |
| boto3 | ≥1.34.0 | **Only required for live AWS scanning.** Not needed for static analysis. |
| AWS Credentials | N/A | Only for live scanning. Static mode analyzes JSON files locally. |

### Verify Prerequisites

**Windows (PowerShell):**
```powershell
py --version
# Expected: Python 3.10.x or higher

py -m pip --version
# Expected: pip 24.x from ...
```

**Linux / macOS (bash):**
```bash
python3 --version
# Expected: Python 3.10.x or higher

python3 -m pip --version
# Expected: pip 24.x from ...
```

---

## 2. Installation

### Option A: Install from PyPI (Recommended for CI and production use)

**Windows (PowerShell):**
```powershell
# Static analysis only (zero dependencies)
py -m pip install aws-agent-identity-guard

# With live AWS scanning support
py -m pip install "aws-agent-identity-guard[live]"

# Verify installation
aws-agent-identity-guard --version
# Expected: aws-agent-identity-guard 0.3.0
```

**Linux / macOS (bash):**
```bash
# Static analysis only (zero dependencies)
pip install aws-agent-identity-guard

# With live AWS scanning support
pip install "aws-agent-identity-guard[live]"

# Verify installation
aws-agent-identity-guard --version
# Expected: aws-agent-identity-guard 0.3.0
```

### Option B: Install from Source (for development or unreleased fixes)

**Windows (PowerShell):**
```powershell
git clone https://github.com/poojakira/aws-agent-identity-guard.git
cd aws-agent-identity-guard
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install -e .

# With live scanning
py -m pip install -e ".[live]"

# With dev tools (pytest, ruff, pyright, moto)
py -m pip install -e ".[dev]"

# Verify
aws-agent-identity-guard --version
# Expected: aws-agent-identity-guard 0.3.0
```

**Linux / macOS (bash):**
```bash
git clone https://github.com/poojakira/aws-agent-identity-guard.git
cd aws-agent-identity-guard
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .

# With live scanning
pip install -e ".[live]"

# With dev tools (pytest, ruff, pyright, moto)
pip install -e ".[dev]"

# Verify
aws-agent-identity-guard --version
# Expected: aws-agent-identity-guard 0.3.0
```

> **Note:** If PowerShell blocks venv activation, run `Set-ExecutionPolicy -Scope Process Bypass` first.

---

## 3. Configuration

### Static Mode (Default)

No configuration required. The tool reads a JSON policy file and applies 25 rules locally. Zero network calls.

### Live Mode — Environment Variables

Set these before running `--live-scan`:

| Variable | Required | Description |
|----------|----------|-------------|
| `AWS_ACCESS_KEY_ID` | Yes* | IAM access key with read-only permissions |
| `AWS_SECRET_ACCESS_KEY` | Yes* | Corresponding secret key |
| `AWS_DEFAULT_REGION` | Yes | Region to scan (e.g., `us-east-1`) |
| `AWS_SESSION_TOKEN` | No | Required if using temporary credentials (STS) |
| `AWS_PROFILE` | No | Use named profile from `~/.aws/credentials` instead of env vars |

*Not required if using instance profiles (EC2/ECS), `~/.aws/credentials`, or `AWS_PROFILE`.

**Windows (PowerShell):**
```powershell
$env:AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
$env:AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
$env:AWS_DEFAULT_REGION = "us-east-1"
```

**Linux / macOS (bash):**
```bash
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"
```

### Required IAM Permissions for Live Scan

The scanning identity needs read-only IAM access:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:ListRoles",
      "iam:ListUsers",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:GetRolePolicy",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:GetRole",
      "iam:ListUserPolicies",
      "iam:ListAttachedUserPolicies",
      "iam:GetUserPolicy"
    ],
    "Resource": "*"
  }]
}
```

---

## 4. Usage — Static Scan

### Basic scan (human-readable text output)

```bash
aws-agent-identity-guard policy.json
```

**Expected output:**
```
[CRITICAL] AIG002: Wildcard action detected — Statement 0 grants "s3:*"
[HIGH]     AIG003: Wildcard resource — Statement 0 uses "Resource": "*"
────────────────────────────────────────
2 findings (1 critical, 1 high, 0 medium)
Exit code: 1
```

### JSON output (for programmatic consumption)

```bash
aws-agent-identity-guard policy.json --format json
```

**Expected output:**
```json
{
  "findings": [
    {
      "rule_id": "AIG002",
      "severity": "critical",
      "message": "Agent policy grants wildcard service or full-account actions...",
      "remediation": "Scope actions to the exact APIs the agent tool calls...",
      "statement_index": 0
    }
  ]
}
```

> The JSON output is a single object with a top-level `findings` array. Each
> finding carries `rule_id`, `severity` (lowercase: `critical`/`high`/`medium`),
> `message`, `remediation`, and `statement_index` (may be `null` for
> policy-wide/kill-chain rules). Severity counts are shown in the human-readable
> `text` output, not embedded in the JSON.

### SARIF output (for GitHub Advanced Security / Code Scanning)

```bash
aws-agent-identity-guard policy.json --format sarif > results.sarif
```

Upload `results.sarif` to GitHub Code Scanning or any SARIF-compatible viewer.

### Scan multiple files

```bash
aws-agent-identity-guard deploy/role-a.json deploy/role-b.json --format json
```

---

## 5. Usage — Live AWS Scan

### Scan all IAM roles in the configured account/region

```bash
aws-agent-identity-guard --live-scan --format json
```

**Expected output:**
```json
{
  "account_id": "123456789012",
  "region": "us-east-1",
  "roles_scanned": 47,
  "findings": [...],
  "summary": {"critical": 3, "high": 12, "medium": 5, "total": 20}
}
```

### Scan a single role

```bash
aws-agent-identity-guard --live-scan --role-name my-bedrock-agent-role --format text
```

### Write output to file

```bash
aws-agent-identity-guard --live-scan --format sarif --output scan-results.sarif
```

---

## 6. Usage — Remediation

Generate remediation suggestions for findings:

```bash
aws-agent-identity-guard policy.json --remediate
```

**Expected output:**
```
[CRITICAL] AIG002: Wildcard action detected — Statement 0 grants "s3:*"
  → REMEDIATION: Replace "s3:*" with specific actions: s3:GetObject, s3:PutObject
    Scope Resource to specific bucket ARN: arn:aws:s3:::my-bucket/*

[HIGH] AIG003: Wildcard resource — Statement 0 uses "Resource": "*"
  → REMEDIATION: Replace "Resource": "*" with specific resource ARNs
```

---

## 7. Interpreting Results

### Severity Levels

| Severity | Meaning | Action Required |
|----------|---------|-----------------|
| **CRITICAL** | Privilege escalation, wildcard admin, confused deputy — active exploit path | **Block deployment immediately.** Fix before merge. Page on-call if in production. |
| **HIGH** | Over-permissive scope, unscoped tool execution, cross-account risk | **Block deployment.** Fix in current sprint. Notify security team. |
| **MEDIUM** | Missing defense-in-depth controls, missing conditions | **Warning.** Fix within 2 sprints. Track in backlog. |

### When to Block Deployments

- **Always block** on CRITICAL or HIGH findings (exit code 1)
- **Warn but allow** on MEDIUM-only findings (exit code 0)
- **Investigate** exit code 2 (tool error — do NOT assume clean)

### Rule Categories

| Rule Range | Category | What It Checks |
|------------|----------|---------------|
| AIG001–AIG021 | Identity Policy | Permission scope, wildcards, escalation paths, blast radius |
| AIG-TP001–AIG-TP003 | Trust Policy | Who can assume the role (principals, conditions) |
| AIG-PB001 | Permission Boundary | Whether high-risk roles have boundaries applied |

---

## 8. Exit Codes

| Code | Meaning | CI Action |
|------|---------|-----------|
| `0` | No HIGH or CRITICAL findings | Deploy is safe to proceed |
| `1` | At least one HIGH or CRITICAL finding | **Block the deploy** |
| `2` | Runtime error (bad input, missing creds, parse failure) | **Investigate before deploying** |

---

## 9. CI/CD Integration

### GitHub Actions

```yaml
name: IAM Policy Lint

on:
  pull_request:
    paths:
      - 'deploy/**'
      - 'infra/**'
      - '*.json'

jobs:
  iam-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install aws-agent-identity-guard
        run: pip install aws-agent-identity-guard

      - name: Scan IAM policies
        run: |
          aws-agent-identity-guard deploy/agent-role-policy.json --format sarif > results.sarif
          aws-agent-identity-guard deploy/agent-role-policy.json --format text

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: iam-agent-lint
```

### GitLab CI

```yaml
iam-policy-lint:
  stage: security
  image: python:3.12-slim
  before_script:
    - pip install aws-agent-identity-guard
  script:
    - aws-agent-identity-guard deploy/agent-role-policy.json --format json > gl-iam-report.json
    - aws-agent-identity-guard deploy/agent-role-policy.json --format text
  artifacts:
    reports:
      security: gl-iam-report.json
    paths:
      - gl-iam-report.json
    when: always
  rules:
    - changes:
        - deploy/**
        - infra/**
```

### Jenkins Pipeline

```groovy
pipeline {
    agent { docker { image 'python:3.12-slim' } }

    stages {
        stage('Install') {
            steps {
                sh 'pip install aws-agent-identity-guard'
            }
        }
        stage('Scan IAM Policies') {
            steps {
                sh '''
                    aws-agent-identity-guard deploy/agent-role-policy.json --format json > iam-findings.json
                    aws-agent-identity-guard deploy/agent-role-policy.json --format text
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'iam-findings.json', allowEmptyArchive: true
        }
        failure {
            slackSend channel: '#security-alerts',
                      message: "⚠️ IAM policy lint FAILED on ${env.JOB_NAME} #${env.BUILD_NUMBER}"
        }
    }
}
```

---

## 10. Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `ModuleNotFoundError: No module named 'boto3'` | Live scanning requires boto3 | `pip install "aws-agent-identity-guard[live]"` |
| `NoCredentialsError` during `--live-scan` | No AWS creds configured | Set `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` env vars, or configure `~/.aws/credentials` |
| `AccessDenied` on live scan | Scanning identity lacks IAM read permissions | Attach the read-only IAM policy from Section 3 above |
| Exit code `2` with no output | JSON parse error or file not found | Check stderr: `aws-agent-identity-guard policy.json 2>&1` — look for file path or JSON syntax errors |
| `command not found: aws-agent-identity-guard` | Not in PATH | Verify install: `pip show aws-agent-identity-guard`. Use `python -m aws_agent_identity_guard` as fallback. |
| Wrong Python version | Running with Python < 3.10 | Use `py -3.12` (Windows) or `python3.12` (Linux) explicitly |
| `UnicodeDecodeError` reading policy file | File has non-UTF-8 encoding | Re-save the file as UTF-8. On Windows: `Get-Content policy.json | Set-Content -Encoding UTF8 policy-fixed.json` |
| SARIF file is empty | Redirect captured stderr too | Use `aws-agent-identity-guard policy.json --format sarif > results.sarif 2>errors.log` |
| Findings count differs from last run | Rules updated between versions | Pin version in CI: `pip install aws-agent-identity-guard==0.3.0` |

---

## 11. Alerting & Escalation

### When CRITICAL Findings Are Detected

**Immediate actions (within 15 minutes):**

1. **Block the deployment.** Exit code 1 should already prevent merge/deploy in CI.
2. **Identify the policy owner.** Check git blame on the policy file.
3. **Notify the security team.** Post to `#security-alerts` with:
   - Repository and PR link
   - Rule IDs triggered (e.g., AIG002, AIG004)
   - Affected IAM role name
4. **If already deployed to production:**
   - Apply a permission boundary immediately to contain blast radius
   - Open a SEV-2 incident
   - Rotate any credentials that may have been exposed via the overprivileged role

**Escalation matrix:**

| Scenario | Escalate To | SLA |
|----------|-------------|-----|
| CRITICAL in PR (not deployed) | Policy author + security reviewer | Fix before merge |
| CRITICAL in production role | Security on-call → Engineering Manager | 4 hours to remediate |
| AIG004 (PassRole without condition) | Security Lead | 2 hours — potential privilege escalation |
| AIG-TP001 (wildcard principal) | Security Lead + Cloud Architect | 1 hour — anyone can assume this role |

### Recommended Alert Channels

- **Slack/Teams:** Post JSON output to `#ml-security-alerts`
- **PagerDuty/OpsGenie:** Trigger on exit code 1 in production scan pipelines
- **SIEM:** Forward SARIF findings to your SIEM for correlation

---

## 12. Maintenance

### Updating to Latest Version

```bash
# Check current version
aws-agent-identity-guard --version

# Update from PyPI
pip install --upgrade aws-agent-identity-guard

# Verify
aws-agent-identity-guard --version
```

### Pinning Versions in CI

Always pin to avoid unexpected rule changes breaking builds:

```bash
pip install aws-agent-identity-guard==0.3.0
```

Update pinned version after testing new rules in a non-blocking mode first.

### Adding Custom Rules

The tool currently ships with 25 built-in rules. Custom rule extensions are not yet supported — file an issue at https://github.com/poojakira/aws-agent-identity-guard/issues if you need custom rules.

### Checking for New Releases

```bash
pip index versions aws-agent-identity-guard
```

Or watch the GitHub repository for releases:
https://github.com/poojakira/aws-agent-identity-guard/releases

### Running Tests After Update

```bash
# Clone and run the test suite to validate
pytest tests/test_scanner.py -v
pytest tests/test_live_scanner.py -v   # Uses moto, no real AWS calls
```

---

## Quick Reference Card

```bash
# Static scan (text output)
aws-agent-identity-guard policy.json

# Static scan (JSON for CI)
aws-agent-identity-guard policy.json --format json

# Static scan (SARIF for GitHub)
aws-agent-identity-guard policy.json --format sarif > results.sarif

# Live scan (all roles in account)
aws-agent-identity-guard --live-scan --format json

# Live scan (single role)
aws-agent-identity-guard --live-scan --role-name my-agent-role --format text

# Remediation suggestions
aws-agent-identity-guard policy.json --remediate
```
