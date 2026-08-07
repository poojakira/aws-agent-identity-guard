# AWS Agent Identity Guard

Static IAM policy linter built specifically for AI agent roles on AWS.

Catches overly-permissive patterns that are common when teams grant Bedrock, SageMaker, Lambda, SSM, or ECS permissions to autonomous AI agents. Flags privilege escalation paths, blast-radius issues, and missing tenant isolation — then tells you exactly how to fix them.

**Zero runtime dependencies.** Pure Python stdlib for static analysis. Optional `boto3` for live account scanning.

## Why This Exists

When you deploy a Bedrock agent or an MCP server on Lambda, the default IAM policy is usually too broad. Nobody bothers to scope `iam:PassRole` with `iam:PassedToService`. Nobody restricts which Lambda functions the agent can invoke. Nobody adds session tags for audit trails.

This tool catches those mistakes in CI before they become production incidents.

Parliament and Prowler check 300+ general AWS rules, but they don't understand agent-specific risks: an AI agent with `bedrock:CreateAgent` can reconfigure its own capabilities. An agent with `cloudtrail:StopLogging` can cover its tracks. These are the patterns we catch.

## What It Checks (22 Rules)

### Identity Policy Rules (AIG001–AIG018)

| Rule | Severity | What It Catches |
|------|----------|-----------------|
| AIG001 | HIGH | NotAction/NotResource in agent policies |
| AIG002 | CRITICAL | Wildcard service or full-account actions |
| AIG003 | HIGH | Resource: '*' (unbounded blast radius) |
| AIG004 | CRITICAL | iam:PassRole without PassedToService |
| AIG005 | CRITICAL | Privilege-management actions (iam:*, policy modification) |
| AIG006 | HIGH | Tool execution (Lambda, SSM, ECS, Bedrock) without resource scoping |
| AIG007 | MEDIUM | Sensitive data access without ABAC tags |
| AIG008 | CRITICAL | Bedrock control-plane actions (agent can modify itself) |
| AIG009 | HIGH | SageMaker control-plane (deploy endpoints, start training) |
| AIG010 | HIGH | Network egress modification (ENI, security groups) |
| AIG011 | CRITICAL | Audit trail tampering (CloudTrail, GuardDuty, Config) |
| AIG012 | MEDIUM | Excessive action breadth (>15 actions per statement) |
| AIG013 | MEDIUM | Resource: '*' with zero Condition keys |
| AIG014 | HIGH | S3 write/delete without key-prefix scoping |
| AIG015 | MEDIUM | Bedrock InvokeModel without model-ID scoping |
| AIG016 | HIGH | Lambda invoke without function-name scoping |
| AIG017 | HIGH | sts:AssumeRole without session tag requirements |
| AIG018 | HIGH | Database full-table access without row-level conditions |

### Trust Policy Rules (AIG-TP001–TP003)

| Rule | Severity | What It Catches |
|------|----------|-----------------|
| AIG-TP001 | CRITICAL | Wildcard principal ('*') in trust policy |
| AIG-TP002 | HIGH | Cross-account trust without sts:ExternalId |
| AIG-TP003 | HIGH | Cross-account trust without aws:SourceArn |

### Live Scan Rules (AIG-PB001)

| Rule | Severity | What It Catches |
|------|----------|-----------------|
| AIG-PB001 | MEDIUM | Role has critical/high findings but no permission boundary |

## Install

```bash
pip install aws-agent-identity-guard
```

Or from source:

```bash
git clone https://github.com/poojakira/aws-agent-identity-guard
cd aws-agent-identity-guard
pip install -e .
```

For live AWS account scanning:

```bash
pip install 'aws-agent-identity-guard[live]'
```

## Usage

### Static Analysis (No AWS Credentials Required)

```bash
# Human-readable output
aws-agent-identity-guard deploy/agent-role-policy.json

# JSON for CI pipelines
aws-agent-identity-guard deploy/agent-role-policy.json --format json

# SARIF for GitHub Advanced Security
aws-agent-identity-guard deploy/agent-role-policy.json --format sarif
```

### Live AWS Account Scanning

```bash
# Scan all roles in current account
aws-agent-identity-guard --live-scan --format json

# Scan a specific agent role
aws-agent-identity-guard --live-scan --role-name my-bedrock-agent-role

# Output SARIF for GitHub code scanning
aws-agent-identity-guard --live-scan --format sarif --output scan.sarif
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No high or critical findings |
| 1 | At least one high or critical finding |
| 2 | Invalid input or CLI error |

## CI Integration

Block deploys when agent IAM policies are overly permissive:

```yaml
# .github/workflows/iam-lint.yml
name: Agent IAM Lint
on: [pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install aws-agent-identity-guard
      - run: aws-agent-identity-guard deploy/agent-role-policy.json --format sarif --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Scope and Limitations

This is a **static linter**. It reads policy JSON and flags patterns. It does not:

- Calculate effective permissions (combining identity policies + resource policies + SCPs + permission boundaries + session policies)
- Simulate AWS authorization logic at runtime
- Replace AWS IAM Access Analyzer for effective-permission analysis

It catches the most common agent-role mistakes in seconds, without AWS credentials, at zero cost.

## Required IAM Permissions for Live Scanning

```json
{
  "Effect": "Allow",
  "Action": [
    "iam:ListRoles", "iam:ListUsers", "iam:GetRole", "iam:GetUser",
    "iam:ListRolePolicies", "iam:ListAttachedRolePolicies",
    "iam:GetRolePolicy", "iam:GetPolicy", "iam:GetPolicyVersion",
    "iam:ListUserPolicies", "iam:ListAttachedUserPolicies",
    "iam:ListUserTags", "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

## Running Tests

```bash
pip install -e ".[dev]"
pytest -v
```

## License

MIT
