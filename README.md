# AWS Agent Identity Guard

Static IAM policy analyzer that catches over-permissioned AI agent roles before they reach production. 25 deterministic rules, zero runtime dependencies, exits non-zero on critical findings so your CI pipeline blocks the merge.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://github.com/poojakira/aws-agent-identity-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/aws-agent-identity-guard/actions/workflows/ci.yml)
[![Coverage: 98%](https://img.shields.io/badge/coverage-98%25-brightgreen)](https://github.com/poojakira/aws-agent-identity-guard/actions)
[![CI](https://github.com/poojakira/aws-agent-identity-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/aws-agent-identity-guard/actions/workflows/ci.yml)

## Key Numbers

| Metric | Value |
|--------|-------|
| Detection rules | 25 deterministic |
| Runtime dependencies | 0 (pure Python) |
| Workloads covered | Bedrock, SageMaker, Lambda |
| Output formats | Text, JSON, SARIF 2.1 |
| CI gate behavior | Exit code 1 on critical/high |
| Modes | Local (no AWS creds) / Live (boto3) |
| Code coverage | 98% |

## Overview

AI agents on AWS get IAM roles provisioned by infrastructure teams that don't think adversarially about what an agent can do with `iam:PassRole` and no condition keys. This tool runs in CI, catches the patterns that matter for agent-specific threats (credential chaining, lateral movement to other ML services, audit-trail tampering), and blocks the merge automatically if the policy is dangerous. Zero dependencies means it runs anywhere Python runs.

## Architecture

```
IAM Policy JSON (local file or boto3 fetch)
        │
        ▼
┌─────────────────────────────────────────────────────┐
│              POLICY PARSER                           │
│  • Statement normalization                          │
│  • Wildcard expansion (s3:* → all s3 actions)       │
│  • Condition key extraction                         │
│  • Resource ARN parsing                             │
└───────────────────────┬─────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────┐
│           RULE ENGINE (25 rules)                    │
│                                                     │
│  Category 1: Wildcard Abuse (5 rules)               │
│  Category 2: Privilege Escalation (4 rules)         │
│  Category 3: Credential Harvest (4 rules)           │
│  Category 4: Audit-Trail Tampering (3 rules)        │
│  Category 5: Lateral Movement (5 rules)             │
│  Category 6: Missing Conditions (4 rules)           │
└───────────────────────┬─────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────┐
│           OUTPUT FORMATTER                           │
│  • Text (human-readable, terminal)                  │
│  • JSON (machine-parseable)                         │
│  • SARIF 2.1 (GitHub Code Scanning)                 │
└───────────────────────┬─────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────┐
│           EXIT CODE LOGIC                           │
│  • Critical or High → exit 1 (blocks merge)         │
│  • Medium or lower → exit 0                         │
│  • --fail-on flag overrides threshold               │
└─────────────────────────────────────────────────────┘
```

## What It Detects

### Wildcard Abuse
- Full-service wildcards (`s3:*`, `iam:*`, `bedrock:*`, `ec2:*`)
- Action wildcards on sensitive services

### Privilege Escalation
- `iam:PassRole` without `aws:RequestedRegion` or resource constraint
- `iam:CreatePolicyVersion`
- `iam:AttachRolePolicy` without permission boundaries

### Credential Harvest
- `sts:AssumeRole` cross-account without `ExternalId`
- `sts:GetFederationToken` on `*`
- `secretsmanager:GetSecretValue` on `*`

### Audit-Trail Tampering
- `cloudtrail:DeleteTrail`
- `cloudtrail:StopLogging`
- `cloudtrail:UpdateTrail` (redirect to attacker-controlled bucket)

### Lateral Movement
- `lambda:InvokeFunction` on `*`
- `sagemaker:CreateNotebookInstance`
- `bedrock:InvokeModel` with no resource scope

### Missing Conditions
- No `aws:SourceVpc` on network-sensitive actions
- No `aws:PrincipalOrgId` on trust policies
- No MFA condition on destructive actions

## Quick Start

```bash
pip install -e .

# Scan a local policy file
python -m aws_agent_identity_guard policy.json

# SARIF output for GitHub Code Scanning
python -m aws_agent_identity_guard policy.json --format sarif --output findings.sarif

# Live mode — pull policies from AWS account
python -m aws_agent_identity_guard --live-scan --role-name my-agent-role --format sarif
```

## Sample Output

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/sarif-schema-2.1.0.json",
  "runs": [{
    "tool": {
      "driver": {
        "name": "aws-agent-identity-guard",
        "version": "1.0.0",
        "rules": [{
          "id": "WILD-001",
          "name": "WildcardServicePrefix",
          "shortDescription": {"text": "Full-service wildcard action detected"}
        }]
      }
    },
    "results": [{
      "ruleId": "WILD-001",
      "level": "error",
      "message": {
        "text": "Action 's3:*' grants all S3 operations. Agent role should use least-privilege: specify exact actions needed."
      },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "policy.json"},
          "region": {"startLine": 12}
        }
      }],
      "properties": {
        "severity": "HIGH",
        "category": "wildcard_abuse",
        "workload": "bedrock_agent",
        "remediation": "Replace s3:* with specific actions. Scope Resource to the bucket ARN the agent needs."
      }
    }]
  }]
}
```

## CI Integration

```yaml
name: IAM Policy Gate
on:
  pull_request:
    paths: ['iam/**', 'terraform/**/*.tf']

jobs:
  iam-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install agent-guard
        run: pip install aws-agent-identity-guard

      - name: Scan IAM policies
        run: |
          python -m aws_agent_identity_guard iam/agent-role-policy.json \
            --format sarif \
            --output iam-findings.sarif

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: iam-findings.sarif
          category: iam-agent-guard
```

Exit code 1 on critical/high findings causes the workflow to fail, blocking the PR from merging.

## Performance

| Metric | Value |
|--------|-------|
| Single policy scan | < 50 ms |
| 100 policies batch | < 2 s |
| Memory | < 30 MB RSS |
| Dependencies | 0 (local mode) |

## Standards Coverage

### MITRE ATT&CK Cloud Matrix

| Technique ID | Name | Rules |
|-------------|------|-------|
| T1078.004 | Valid Accounts: Cloud Accounts | CRED-001, CRED-002 |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | PRIV-001, PRIV-002 |
| T1098.003 | Account Manipulation: Additional Cloud Roles | PRIV-003 |
| T1562.008 | Impair Defenses: Disable Cloud Logs | AUDIT-001, AUDIT-002 |
| T1580 | Cloud Infrastructure Discovery | WILD-003 |
| T1537 | Transfer Data to Cloud Account | CRED-003 |

## Modes

- **Local** — pure Python static analysis. Hand it a policy JSON file and it tells you what's wrong. No AWS credentials, no network access, no Docker required.
- **Live** — optional boto3 mode pulls policies from a real AWS account. Useful for auditing existing deployments.

## Contributing

File an issue before writing code. Include a real-world IAM policy demonstrating the threat and a test case showing detection. Run `make test lint` before submitting.

## License

MIT
