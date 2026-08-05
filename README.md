# AWS Agent Identity Guard

[![Live Dashboard](https://img.shields.io/badge/Live_Dashboard-View-blue)](https://poojakira.github.io/aws-agent-identity-guard/)

A static linter for IAM policies attached to AI agent roles on AWS. It reads IAM policy JSON files, flags overly permissive patterns, and exits non-zero if it finds problems. No AWS credentials needed — it's pure static analysis.

## Scope and Limitations

This is a **static IAM policy linter** with 7 core rule categories. It reads policy JSON and flags specific anti-patterns. It does not:

- Calculate effective permissions by combining identity policies, resource policies, SCPs, permission boundaries, session policies, and trust relationships
- Understand cross-account trust or condition key semantics at runtime
- Simulate AWS authorization logic

For complete effective-permission analysis, use AWS IAM Access Analyzer or the AWS Policy Simulator. This tool catches the most common agent-role mistakes quickly in CI, without requiring AWS credentials.

## What It Checks

**Wildcard abuse**
- `Action: *` or `Resource: *` in policies meant for agent runtimes

**PassRole without constraints**
- `iam:PassRole` missing `iam:PassedToService` conditions

**Privilege escalation paths**
- `iam:*`, `sts:AssumeRole`, policy attachment APIs (`iam:AttachRolePolicy`, `iam:PutRolePolicy`, etc.)

**Overly broad service permissions**
- Wide access to Bedrock, Lambda, SSM, Secrets Manager, KMS, S3, CloudWatch Logs

**Weak trust policies**
- Missing external ID, missing `aws:SourceAccount` / `aws:SourceArn` constraints, no session-tag expectations

Each finding includes a severity level and a remediation suggestion.

## Install

Requires Python 3.10+. No external dependencies.

```bash
# From the repo root
pip install -e .

# Or install from a built wheel
pip install aws-agent-identity-guard
```

## Usage

```bash
# Text output (human-readable)
aws-agent-identity-guard examples/agent_policy_wildcard.json --format text

# JSON output (for CI pipelines)
aws-agent-identity-guard examples/agent_policy_wildcard.json --format json
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No high or critical findings |
| 1 | At least one high or critical finding |
| 2 | Invalid input or CLI error |

## Use in CI

Run it in a GitHub Actions step before deploying any agent that gets AWS permissions — Bedrock agents, MCP servers, Lambda-based tools, etc. If it exits 1, block the deploy.

```yaml
- name: Lint agent IAM policy
  run: aws-agent-identity-guard deploy/agent-role-policy.json --format text
```

## Running Tests

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
