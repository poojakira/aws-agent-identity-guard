# RUNBOOK  -  AWS Agent Identity Guard

## Prerequisites

- Python 3.10+
- For live scanning: AWS credentials configured (`~/.aws/credentials` or env vars)
- For live scanning: `boto3` installed

## Install

```bash
git clone <repo-url> && cd aws-agent-identity-guard
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Local-only (zero deps)
pip install -e .

# With live AWS scanning
pip install -e ".[aws]"
```

## Scan a Local Policy File

```bash
# Single file
aws-agent-identity-guard policy.json

# With SARIF output
aws-agent-identity-guard policy.json --format sarif --output findings.sarif

# With severity threshold (fail on HIGH+)
aws-agent-identity-guard policy.json --fail-on high
```

## Scan Live AWS Account

```bash
# Specific role
aws-agent-identity-guard --live-scan --role-name agent-execution-role

# Specific region
aws-agent-identity-guard --live-scan --role-name my-agent --region us-west-2 --format json
```

## Output Formats

```bash
aws-agent-identity-guard policy.json                        # text (default)
aws-agent-identity-guard policy.json --format json          # JSON
aws-agent-identity-guard policy.json --format sarif         # SARIF 2.1
```

## CI Integration

```yaml
# GitHub Actions example
- name: Scan IAM Policies
  run: |
    pip install aws-agent-identity-guard
    aws-agent-identity-guard iam/agent-role-policy.json --format sarif --output results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `No policies found` | Wrong path or empty dir | Verify path, check `--recursive` flag |
| `AccessDenied` on live scan | Insufficient IAM perms | Scanner needs `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListPolicies` |
| False positives on wildcards | Context-dependent permissions | Use `--ignore-rules RULE_ID` or add to `.identityguard-ignore` |
| Slow live scan | Large account with many policies | Use `--role-name` to scope, or paginate with `--max-results` |
