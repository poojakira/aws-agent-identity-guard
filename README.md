# AWS Agent Identity Guard

Static analyzer that catches over-permissioned IAM policies before they reach production. 25 deterministic rules, zero runtime dependencies, exits non-zero on critical findings so CI blocks the merge.

**Status:** Personal project. Works for basic IAM policy scanning. Not a substitute for AWS Access Analyzer or commercial tools.

## Install

```bash
pip install -e .
```

## Usage

```bash
# Scan a local policy file
py -m aws_agent_identity_guard policy.json

# SARIF output for GitHub Code Scanning
py -m aws_agent_identity_guard policy.json --format sarif --output findings.sarif

# Live mode - pull policies from AWS account
py -m aws_agent_identity_guard --live-scan --role-name my-agent-role --format sarif
```

## Example Output

```
CRITICAL  iam:PassRole without conditions (rule: PRIV-003)
HIGH      s3:* wildcard on Resource * (rule: WILD-001)
HIGH      sts:AssumeRole cross-account, no ExternalId (rule: CRED-002)

3 findings (1 critical, 2 high, 0 medium)
Exit code: 1
```

## Rules (25 total)

### Wildcard Abuse
- Full-service wildcards (`s3:*`, `iam:*`, `bedrock:*`, etc.)
- Action wildcards on sensitive services

### Privilege Escalation
- `iam:PassRole` without condition keys
- `iam:CreatePolicyVersion`
- `iam:AttachRolePolicy` without permission boundaries

### Credential Harvest
- `sts:AssumeRole` cross-account without `ExternalId`
- `sts:GetFederationToken` on `*`
- `secretsmanager:GetSecretValue` on `*`

### Audit-Trail Tampering
- `cloudtrail:DeleteTrail`
- `cloudtrail:StopLogging`
- `cloudtrail:UpdateTrail`

### Lateral Movement
- `lambda:InvokeFunction` on `*`
- `sagemaker:CreateNotebookInstance`
- `bedrock:InvokeModel` with no resource scope

### Missing Conditions
- No `aws:SourceVpc` on network-sensitive actions
- No `aws:PrincipalOrgId` on trust policies
- No MFA condition on destructive actions

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
      - run: pip install aws-agent-identity-guard
      - run: |
          agent-guard scan iam/agent-role-policy.json \
            --format sarif --output iam-findings.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: iam-findings.sarif
```

## Output Formats

- **Text** — human-readable terminal output
- **JSON** — machine-parseable
- **SARIF 2.1** — GitHub Code Scanning compatible

## Exit Codes

- `1` — Critical or High finding detected
- `0` — Medium or lower only (override with `--fail-on`)

## Modes

- **Local** — no AWS credentials needed, reads policy JSON files directly
- **Live** — uses boto3 to pull policies from an AWS account

## Contributing

File an issue before writing code. Include a real-world IAM policy demonstrating the threat and a test case showing detection. Run `make test lint` before submitting.

## License

MIT
