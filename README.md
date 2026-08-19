# AWS Agent Identity Guard

Static analyzer that catches over-permissioned IAM policies on AI agent roles before they reach production. 25 deterministic rules, zero runtime dependencies, exits non-zero on critical findings so your CI pipeline blocks the merge.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://github.com/poojakira/aws-agent-identity-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/aws-agent-identity-guard/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)](https://github.com/poojakira/aws-agent-identity-guard/actions)
[![CI](https://github.com/poojakira/aws-agent-identity-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/aws-agent-identity-guard/actions/workflows/ci.yml)

## Numbers

| Metric | Value |
|--------|-------|
| Detection rules | 25 deterministic |
| Runtime dependencies | 0 (pure Python) |
| Workloads covered | Bedrock, SageMaker, Lambda |
| Output formats | Text, JSON, SARIF |
| CI gate behavior | Exit code 1 on critical/high |
| Modes | Local (no AWS creds) / Live (boto3) |

## Why I Built This

AI agents on AWS get IAM roles provisioned by infrastructure teams that don't think adversarially about what an agent can do with `iam:PassRole` and no condition keys. I kept seeing Bedrock and SageMaker agent roles with `s3:*` and `sts:AssumeRole` scoped to `*`  -  not because anyone wanted that, but because nobody caught it before deployment.

Manual review during security design reviews doesn't scale when you're deploying dozens of agent roles per quarter. I wanted something that runs in CI, catches the patterns that matter for agent-specific threats (credential chaining, lateral movement to other ML services, audit-trail tampering), and blocks the merge automatically if the policy is dangerous.

Zero dependencies means it runs anywhere Python runs  -  no Docker, no AWS credentials, no network access required. Hand it a policy JSON file and it tells you what's wrong.

See [DESIGN_DECISIONS.md](DESIGN_DECISIONS.md) for why 25 rules, why pure Python, and what I chose not to build.

## Architecture

```
IAM Policy JSON (local file or boto3 fetch)
        │
        ▼
┌─────────────────────────────────────────────────────┐
│              POLICY PARSER                           │
│  • Statement normalization                          │
│  • Wildcard expansion (s3:* -> all s3 actions)       │
│  • Condition key extraction                         │
│  • Resource ARN parsing                             │
└───────────────────────┬─────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────┐
│           RULE ENGINE (25 rules)                    │
│                                                     │
│  Category 1: Wildcard Abuse                         │
│    • Full-service wildcards (s3:*, iam:*, ec2:*)    │
│    • Action wildcards on sensitive services          │
│                                                     │
│  Category 2: Privilege Escalation                   │
│    • iam:PassRole without aws:RequestedRegion       │
│    • iam:CreatePolicyVersion                        │
│    • iam:AttachRolePolicy without boundaries        │
│                                                     │
│  Category 3: Credential Harvest                     │
│    • sts:AssumeRole cross-account, no ExternalId    │
│    • sts:GetFederationToken on *                    │
│    • secretsmanager:GetSecretValue on *             │
│                                                     │
│  Category 4: Audit-Trail Tampering                  │
│    • cloudtrail:DeleteTrail                         │
│    • cloudtrail:StopLogging                         │
│    • cloudtrail:UpdateTrail (redirect to attacker)  │
│                                                     │
│  Category 5: Lateral Movement                       │
│    • lambda:InvokeFunction on *                     │
│    • sagemaker:CreateNotebookInstance                │
│    • bedrock:InvokeModel with no resource scope     │
│                                                     │
│  Category 6: Missing Conditions                     │
│    • No aws:SourceVpc on network-sensitive actions   │
│    • No aws:PrincipalOrgId on trust policies        │
│    • No MFA condition on destructive actions        │
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
│  • Critical or High finding -> exit 1               │
│  • Medium or lower only -> exit 0                   │
│  • --fail-on flag overrides threshold              │
└─────────────────────────────────────────────────────┘
```

## What It Detects

- **Wildcard service prefixes**  -  `s3:*`, `iam:*`, `bedrock:*`, etc.
- **iam:PassRole without conditions**  -  the most common privilege escalation path for agent roles
- **Privilege-management actions**  -  `iam:CreatePolicyVersion`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`
- **Audit-trail tampering**  -  `cloudtrail:DeleteTrail`, `cloudtrail:StopLogging`, `cloudtrail:UpdateTrail`
- **Credential-harvest chains**  -  `sts:AssumeRole` targeting `*` or cross-account without `ExternalId`; combined with `secretsmanager:GetSecretValue` on broad resources
- **Cross-account trust without ExternalId**  -  the confused-deputy pattern
- **Lateral movement**  -  `lambda:InvokeFunction` on `*`, `sagemaker:CreateNotebookInstance`, `bedrock:InvokeModel` with no resource constraint
- **Missing condition keys**  -  policies missing `aws:SourceVpc`, `aws:PrincipalOrgId`, or MFA conditions

## Quick Start

```bash
pip install -e .

# Scan a local policy file
py -m aws_agent_identity_guard policy.json
```

```
CRITICAL  iam:PassRole without conditions (rule: PRIV-003)
HIGH      s3:* wildcard on Resource * (rule: WILD-001)
HIGH      sts:AssumeRole cross-account, no ExternalId (rule: CRED-002)

3 findings (1 critical, 2 high, 0 medium)
Exit code: 1
```

```bash
# SARIF output for GitHub Code Scanning
py -m aws_agent_identity_guard policy.json --format sarif --output findings.sarif

# Live mode  -  pull policies from AWS account
py -m aws_agent_identity_guard --live-scan --role-name my-agent-role --format sarif
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
          "shortDescription": {
            "text": "Full-service wildcard action detected"
          }
        }]
      }
    },
    "results": [{
      "ruleId": "WILD-001",
      "level": "error",
      "message": {
        "text": "Action 's3:*' grants all S3 operations. Agent role should use least-privilege: specify exact actions needed (e.g., s3:GetObject, s3:PutObject on a specific bucket)."
      },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "policy.json" },
          "region": { "startLine": 12 }
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
    paths:
      - 'iam/**'
      - 'terraform/**/*.tf'

jobs:
  iam-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install agent-guard
        run: pip install aws-agent-identity-guard

      - name: Scan IAM policies
        run: |
          agent-guard scan iam/agent-role-policy.json \
            --format sarif \
            --output iam-findings.sarif

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: iam-findings.sarif
          category: iam-agent-guard
```

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

## Contributing

File an issue before writing code. Include a real-world IAM policy demonstrating the threat and a test case showing detection. Run `make test lint` before submitting.

## License

MIT.
