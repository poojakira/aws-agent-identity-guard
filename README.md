# AWS Agent Identity Guard

**Your AI agents are shipping with admin-level IAM. This tool catches it before deploy.**

83% of enterprises are deploying AI agents. Only 29% have security controls around them. The result: Bedrock agents with `iam:PassRole` to anything. Lambda-based tool executors with `*` resources. MCP servers that can disable their own audit trails.

Traditional IAM linters don't catch this. Parliament and Prowler check general AWS policy hygiene, but they have no concept of agent-specific risks. A Bedrock agent with `bedrock:CreateAgent` can reconfigure its own capabilities. An agent with `cloudtrail:StopLogging` can cover its tracks. An agent with unscoped `sts:AssumeRole` can pivot to any role in the account.

**aws-agent-identity-guard** is a static IAM policy linter purpose-built for AI agent roles. 25 rules. Zero runtime dependencies. Blocks bad deploys in CI. SARIF output for GitHub Advanced Security.

No AWS credentials required. No cloud calls. Just feed it your policy JSON.

## Install

```bash
pip install aws-agent-identity-guard
```

30 seconds from install to first scan.

## Usage

```bash
aws-agent-identity-guard deploy/agent-role-policy.json
```

### Output

```
CRITICAL AIG002 statement=0: Wildcard service prefix 'bedrock:*' grants full Bedrock control
  remediation: Replace bedrock:* with specific actions: bedrock:InvokeModel, bedrock:InvokeModelWithResponseStream
CRITICAL AIG004 statement=0: iam:PassRole without iam:PassedToService condition
  remediation: Add Condition: {"StringEquals": {"iam:PassedToService": "bedrock.amazonaws.com"}}
CRITICAL AIG005 statement=0: Policy grants privilege-management action: iam:AttachRolePolicy
  remediation: Remove iam:AttachRolePolicy — agents must not modify their own permissions
CRITICAL AIG011 statement=0: Policy grants audit-tampering action: cloudtrail:StopLogging
  remediation: Remove cloudtrail:StopLogging — no agent should disable its audit trail
HIGH AIG003 statement=0: Resource '*' with 12 actions creates unbounded blast radius
  remediation: Scope Resource to specific ARNs for each action
HIGH AIG006 statement=0: lambda:InvokeFunction without function-name scoping
  remediation: Restrict Resource to arn:aws:lambda:REGION:ACCOUNT:function:FUNCTION_NAME
HIGH AIG009 statement=0: SageMaker control-plane action sagemaker:CreateEndpoint in agent role
  remediation: Remove sagemaker:CreateEndpoint or scope to specific endpoint configs
HIGH AIG010 statement=0: Network egress modification action ec2:CreateNetworkInterface
  remediation: Remove ec2:CreateNetworkInterface — agents should not modify network paths
HIGH AIG014 statement=0: s3:* includes write/delete without key-prefix scoping
  remediation: Scope to specific bucket and prefix: arn:aws:s3:::bucket/prefix/*
```

Exit code `1`. Deploy blocked.

### Output Formats

```bash
# Human-readable (default)
aws-agent-identity-guard policy.json

# JSON for programmatic consumption
aws-agent-identity-guard policy.json --format json

# SARIF for GitHub Advanced Security
aws-agent-identity-guard policy.json --format sarif --output results.sarif
```

## CI Integration: Block Bad Deploys in 3 Lines

```yaml
- run: pip install aws-agent-identity-guard
- run: aws-agent-identity-guard deploy/agent-role-policy.json --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Findings appear inline on pull requests via GitHub Code Scanning. Critical or high findings fail the pipeline (exit code 1).

Full workflow example:

```yaml
name: Agent IAM Lint
on: [pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
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

## What It Catches: 25 rules

| Rule | Severity | Pattern |
|------|----------|---------|
| AIG001 | HIGH | NotAction/NotResource in agent policies |
| AIG002 | CRITICAL | Wildcard service prefix (`bedrock:*`, `s3:*`) |
| AIG003 | HIGH | `Resource: "*"` - unbounded blast radius |
| AIG004 | CRITICAL | `iam:PassRole` without `iam:PassedToService` condition |
| AIG005 | CRITICAL | Privilege-management actions (iam:*, policy modification) |
| AIG006 | HIGH | Tool execution (Lambda, SSM, ECS, Bedrock) without resource scoping |
| AIG007 | MEDIUM | Sensitive data access without ABAC tags |
| AIG008 | CRITICAL | Bedrock control-plane, agent can modify itself |
| AIG009 | HIGH | SageMaker control-plane in a runtime role |
| AIG010 | HIGH | Network egress modification (ENI, security groups) |
| AIG011 | CRITICAL | Audit trail tampering (CloudTrail, GuardDuty, Config) |
| AIG012 | MEDIUM | Excessive action breadth (>15 actions per statement) |
| AIG013 | MEDIUM | `Resource: "*"` with zero Condition keys |
| AIG014 | HIGH | S3 write/delete without key-prefix scoping |
| AIG015 | MEDIUM | Bedrock InvokeModel without model-ID scoping |
| AIG016 | HIGH | Lambda invoke without function-name scoping |
| AIG017 | HIGH | `sts:AssumeRole` without session tag requirements |
| AIG018 | HIGH | Database full-table access without row-level conditions |
| AIG019 | CRITICAL | **Credential-harvest + lateral-movement combination** (the 2026 OpenAI-Hugging Face breach chain) |
| AIG020 | HIGH | **Credential-harvest + cloud-metadata reach** (the SSRF-to-IMDS credential-theft path) |
| AIG021 | CRITICAL | **Complete breach chain** (harvest → metadata → lateral) in one identity |
| AIG-TP001 | CRITICAL | Wildcard principal (`*`) in trust policy |
| AIG-TP002 | HIGH | Cross-account trust without `sts:ExternalId` |
| AIG-TP003 | HIGH | Cross-account trust without `aws:SourceArn` |
| AIG-PB001 | MEDIUM | Role with critical findings but no permission boundary |

## Live Account Scanning

Scan roles in a running AWS account (requires `boto3`):

```bash
pip install 'aws-agent-identity-guard[live]'

# Scan all roles
aws-agent-identity-guard --live-scan --format json

# Scan a specific agent role
aws-agent-identity-guard --live-scan --role-name my-bedrock-agent-role

# SARIF output
aws-agent-identity-guard --live-scan --format sarif --output scan.sarif
```

## Why Not Parliament / Prowler / IAM Access Analyzer?

| | aws-agent-identity-guard | Parliament | Prowler | IAM Access Analyzer |
|---|---|---|---|---|
| Agent-specific rules | ✓ 25 rules | ✗ | ✗ | ✗ |
| Bedrock self-modification detection | ✓ | ✗ | ✗ | ✗ |
| PassRole without PassedToService | ✓ | ✗ | ✗ | Partial |
| Audit-tampering detection | ✓ | ✗ | ✓ (runtime) | ✗ |
| Static (no credentials needed) | ✓ | ✓ | ✗ | ✗ |
| SARIF output | ✓ | ✗ | ✗ | ✗ |
| Zero dependencies | ✓ | ✗ | ✗ | N/A (AWS service) |
| Pre-deploy CI gate | ✓ | ✓ | ✗ | ✗ |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical or high findings, safe to deploy |
| 1 | Critical or high findings, deploy blocked |
| 2 | Invalid input or CLI error |

## License

MIT — see [LICENSE](LICENSE).
