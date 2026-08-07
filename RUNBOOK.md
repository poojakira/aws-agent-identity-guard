# Runbook — AWS Agent Identity Guard

## Prerequisites

- Python 3.10+
- **Static mode**: No AWS credentials needed (pure JSON analysis)
- **Live mode**: AWS credentials with read-only IAM permissions (see README)

## Setup

```bash
git clone https://github.com/poojakira/aws-agent-identity-guard.git
cd aws-agent-identity-guard
python -m venv .venv

# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

# Static analysis only (no external deps)
pip install -e .

# With live AWS scanning support
pip install -e ".[live]"

# Development (includes test + lint tools)
pip install -e ".[dev]"
```

## Run the Scanner — Static Mode

Scan a local policy JSON file:

```bash
# Human-readable text output (default)
aws-agent-identity-guard examples/agent_policy_wildcard.json --format text

# JSON output (for CI pipelines)
aws-agent-identity-guard examples/agent_policy_wildcard.json --format json

# SARIF 2.1.0 output (for GitHub Code Scanning)
aws-agent-identity-guard examples/agent_policy_wildcard.json --format sarif
```

## Run the Scanner — Live AWS Mode

Scan all IAM roles in a live AWS account:

```bash
# Requires AWS credentials configured (env vars, ~/.aws/, instance profile)
aws-agent-identity-guard --live-scan --format json

# Scan a single role
aws-agent-identity-guard --live-scan --role-name my-bedrock-agent-role --format text

# Write SARIF to file
aws-agent-identity-guard --live-scan --format sarif --output scan-results.sarif
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No high or critical findings |
| 1 | At least one high or critical finding (deploy should be blocked) |
| 2 | Invalid input, missing credentials, or runtime error |

## Rules

### Identity Policy Rules (scan_policy_document)

| Rule | Severity | Detects |
|------|----------|---------|
| AIG001 | HIGH | NotAction or NotResource (hard to reason about for agents) |
| AIG002 | CRITICAL | Wildcard actions (`*` or `service:*`) |
| AIG003 | HIGH | Wildcard resources (`Resource: *`) |
| AIG004 | CRITICAL | `iam:PassRole` without `iam:PassedToService` condition |
| AIG005 | CRITICAL | Privilege-management actions (iam:*, sts:AssumeRole, policy attachment) |
| AIG006 | HIGH | Tool execution actions (Lambda, SSM, ECS, Bedrock) not resource-scoped |
| AIG007 | MEDIUM | Sensitive-data actions without principal/session tag condition |
| AIG008-AIG018 | HIGH–CRITICAL | Agent-specific escalation and blast-radius rules targeting Bedrock, SageMaker, network, and audit controls |

### Trust Policy Rules (scan_trust_policy)

| Rule | Severity | Detects |
|------|----------|---------|
| AIG-TP001 | CRITICAL | Wildcard principal (`"*"`) — any identity can assume the role |
| AIG-TP002 | HIGH | Cross-account trust without `sts:ExternalId` (confused-deputy) |
| AIG-TP003 | HIGH | Cross-account trust without `aws:SourceArn` condition |

### Live Scan Additional

| Rule | Severity | Detects |
|------|----------|---------|
| AIG-PB001 | MEDIUM | Role with high/critical findings and no permission boundary |

## Run Tests

```bash
# Static scanner tests (no AWS credentials needed)
pytest tests/test_scanner.py -v

# Live scanner tests (uses moto — no real AWS calls)
pytest tests/test_live_scanner.py -v

# All tests
pytest -v
```

## CI Usage

```yaml
- name: Lint agent IAM policy
  run: |
    pip install aws-agent-identity-guard
    aws-agent-identity-guard deploy/agent-role-policy.json --format text
```

## Known Limitations

- **Static mode**: Analyzes one policy document at a time. Cannot compute effective permissions (requires combining identity policies + resource policies + SCPs + permission boundaries + session policies + explicit denies).
- **Live mode**: Enumerates roles and users but does not:
  - Evaluate resource-based policies on target resources
  - Query SCPs from AWS Organizations
  - Simulate authorization decisions (use IAM Policy Simulator for that)
  - Analyze session policies from STS AssumeRole calls
- Rule set covers 22 rules across 3 categories. Not a replacement for IAM Access Analyzer.
- No support for ABAC-heavy environments where tag conditions are the primary control.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: No module named 'boto3'` | Install with `pip install 'aws-agent-identity-guard[live]'` |
| `NoCredentialsError` during live scan | Configure AWS credentials (env vars, `~/.aws/credentials`, or instance profile) |
| `AccessDenied` errors | Ensure the scanning identity has the IAM read-only permissions listed in README |
| Exit code 2 with no output | Check stderr — likely a JSON parse error or missing file |
