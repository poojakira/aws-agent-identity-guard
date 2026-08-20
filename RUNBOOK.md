# RUNBOOK — AWS Agent Identity Guard

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
identity-guard scan policy.json

# Directory of policies
identity-guard scan ./policies/ --recursive

# With severity threshold (fail on HIGH+)
identity-guard scan policy.json --min-severity high --exit-code
```

## Scan Live AWS Account

```bash
# Scan all IAM policies in account
identity-guard scan-live --profile prod-account

# Specific role
identity-guard scan-live --role-name agent-execution-role

# Specific region
identity-guard scan-live --region us-west-2
```

## Output Formats

```bash
identity-guard scan policy.json                          # table (default)
identity-guard scan policy.json --format json > out.json # JSON
identity-guard scan policy.json --format sarif > out.sarif # SARIF
identity-guard scan policy.json --format csv             # CSV
```

## CI Integration

```yaml
# GitHub Actions example
- name: Scan IAM Policies
  run: |
    pip install aws-agent-identity-guard
    identity-guard scan ./iam-policies/ --recursive --format sarif --exit-code > results.sarif
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
