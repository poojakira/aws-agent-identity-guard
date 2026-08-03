# Runbook — AWS Agent Identity Guard

## Prerequisites

- Python 3.10+
- No AWS credentials needed (this is pure static analysis of JSON policy files)

## Setup

```bash
git clone https://github.com/poojakira/aws-agent-identity-guard.git
cd aws-agent-identity-guard
python -m venv .venv

# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -e ".[dev]"
```

## Run the Scanner

Scan a policy file:

```bash
aws-agent-identity-guard examples/agent_policy_wildcard.json
```

Output formats:

```bash
# Plain text (default)
aws-agent-identity-guard policy.json --format text

# JSON output
aws-agent-identity-guard policy.json --format json

# Exit code only (for CI)
aws-agent-identity-guard policy.json --format quiet
```

## What It Checks

| Rule | Severity | Detects |
|------|----------|---------|
| AIG001 | CRITICAL | Wildcard actions (`*`) in agent policies |
| AIG002 | HIGH | `iam:PassRole` without `iam:PassedToService` constraint |
| AIG003 | HIGH | Privilege escalation actions (iam:*, sts:AssumeRole, policy attachment) |
| AIG004 | MEDIUM | Broad Bedrock/Lambda/SSM/Secrets Manager permissions |
| AIG005 | MEDIUM | Broad S3/CloudWatch Logs permissions |
| AIG006 | HIGH | Trust policy missing external ID or source constraints |
| AIG007 | MEDIUM | Trust policy missing session-tag expectations |

## Run Tests

```bash
pytest tests/ -v
```

## CI Usage

```yaml
- name: Check agent IAM policy
  run: |
    pip install -e .
    aws-agent-identity-guard path/to/agent_policy.json --format quiet
```

The CLI exits non-zero if any CRITICAL or HIGH findings are found.

## View the Dashboard

```bash
python -m http.server 8080 --directory dashboard
# Open http://localhost:8080
```

Or view hosted: https://poojakira.github.io/mlsec-dashboards/aws-agent-identity-guard/

## Known Limitations

- Static analysis only — does not connect to AWS APIs
- Cannot detect runtime privilege escalation chains
- Does not evaluate resource-based policies or SCPs
- Small rule set (7 rules) — not comprehensive
