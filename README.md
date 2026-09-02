# AWS Agent Identity Guard

Static IAM policy checks for AWS roles used by AI agents and tool executors.

AI agents and tool executors can turn overbroad cloud permissions into real actions: invoking Lambda functions, assuming roles, changing Bedrock/SageMaker control-plane resources, reading secrets, or disabling audit trails. `aws-agent-identity-guard` checks IAM policy JSON for these agent-specific risk patterns before deployment.

This tool is a static linter. It does not call AWS in default mode, does not prove an agent is safe, and does not replace IAM Access Analyzer, Prowler, Parliament, CloudTrail, Security Hub, or threat modeling. Its narrow job is to produce reviewable findings for policies that grant risky permissions to autonomous or semi-autonomous workloads.

Current implemented surface:
- 25 deterministic rules for identity policies, trust policies, and permission-boundary presence.
- Text, JSON, and SARIF output.
- Zero runtime dependencies for static local-file scanning.
- Optional live account scan mode when installed with `boto3`.

No AWS credentials required. No cloud calls. Just feed it your policy JSON.

## Install

```bash
pip install aws-agent-identity-guard
```

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

Exit code `1` means at least one high or critical finding was detected. Whether that blocks deployment is controlled by your CI policy.

### Output Formats

```bash
# Human-readable (default)
aws-agent-identity-guard policy.json

# JSON for programmatic consumption
aws-agent-identity-guard policy.json --format json

# SARIF for GitHub Advanced Security
aws-agent-identity-guard policy.json --format sarif --output results.sarif
```

## CI Integration

```yaml
- run: pip install aws-agent-identity-guard
- run: aws-agent-identity-guard deploy/agent-role-policy.json --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Findings can appear inline on pull requests through GitHub Code Scanning. Critical or high findings return exit code `1`, so a workflow can use the result as a merge gate.

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
| AIG019 | CRITICAL | Credential-harvest plus lateral-movement permission combination |
| AIG020 | HIGH | Credential-harvest plus cloud-metadata reachability pattern |
| AIG021 | CRITICAL | Combined credential-harvest, metadata, and lateral-movement chain in one identity |
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

## Relationship to Other IAM Tools

Use this alongside mature AWS security tools. It is intentionally narrower than account-wide posture products and focuses on pre-deploy policy review for agent roles.

| | aws-agent-identity-guard | Parliament | Prowler | IAM Access Analyzer |
|---|---|---|---|---|
| Main role | Agent-role static linter | General IAM linting | Account posture assessment | AWS policy analysis service |
| Default data path | Local policy JSON | Local policy JSON | AWS account/API scan | AWS service APIs |
| Agent-specific rules | Implemented in this repo | Out of scope for this audit | Out of scope for this audit | Out of scope for this audit |
| SARIF output | Implemented in this repo | Tool/version dependent | Workflow dependent | Export/integration dependent |
| Account-wide cloud context | No | No | Yes | Yes |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical or high findings found by these rules |
| 1 | Critical or high findings found |
| 2 | Invalid input or CLI error |

## Local Test Note

Some developer workstations load unrelated pytest plugins globally. To run this project's tests in an isolated way:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests -q
```

## Known Limitations

- **Static analysis only.** This tool reads IAM policy JSON and produces findings. It does not intercept API calls, enforce runtime deny decisions, or act as a policy enforcement point. There is no "fail-closed" behavior because it is not a runtime system.
- **No semantic understanding of Condition keys.** The scanner checks for the *presence* of specific Condition keys (e.g., `iam:PassedToService`, `aws:SourceArn`) but does not evaluate whether the condition values are logically sufficient to mitigate a risk.
- **Single-policy scope.** Each invocation analyzes one policy document in isolation. Cross-policy interactions (e.g., a permissive identity policy constrained by an SCP or permission boundary) are not considered.
- **Action pattern matching is prefix-based.** Wildcard detection uses prefix/fnmatch logic. Unusual action name formats or future AWS service namespaces may not be covered until rules are updated.
- **No AWS API calls in default mode.** The tool cannot resolve resource ARNs, check whether a role actually exists, or determine effective permissions. Use IAM Access Analyzer or CloudTrail for runtime validation.
- **Trust policy analysis requires explicit invocation.** `scan_trust_policy()` must be called separately; it is not triggered by passing a standard identity policy to `scan_policy_document()`.
- **Large policies may produce many findings.** A policy with 200+ actions in a single statement will trigger multiple overlapping rules. Findings are not deduplicated across rules by design — each rule surfaces a distinct risk vector.

## Failure Semantics

This tool is a static linter. It reads a file, analyzes it, and exits. There is no persistent process, no daemon, no network listener, and no fail-open/fail-closed runtime behavior.

| Exit Code | Meaning | When It Happens |
|-----------|---------|-----------------|
| **0** | Clean scan | No critical or high-severity findings were detected. The policy may still have medium/low findings. |
| **1** | Findings detected | At least one critical or high-severity finding exists. In `--enforce` mode with `--live-scan`, also returned when the scan was incomplete or encountered errors. |
| **2** | Input/CLI error | The input file does not exist, is not valid JSON, is not a JSON object, cannot be decoded as UTF-8, or the CLI was invoked with invalid arguments. The tool prints a diagnostic message to stderr/stdout and exits immediately. |

**Design rationale:** Exit code 2 signals "the tool could not do its job" — the input was unusable. Exit code 1 signals "the tool did its job and found problems." CI pipelines should treat exit 2 as an infrastructure failure (fix the input), and exit 1 as a policy gate (fix the policy or accept the risk).

**No fail-closed behavior:** Because this is not a runtime gatekeeper, there is no concept of "fail closed." If the tool cannot parse the input, it exits 2 and produces no findings — it does not block or allow anything. Whether a CI pipeline treats exit 2 as a blocking failure is a pipeline-configuration decision, not a tool decision.

## Verification

| Field | Value |
|-------|-------|
| Tested commit | `ee090fda4a20b27874da96b30ea1eb073dd8ac11` |
| Environment | Python 3.12, Windows 11, pytest 8.x |
| Last verified | 2026-08-27 |
| Test command | `python -m pytest tests/ -q` |
| Coverage | All 25 rules have positive/negative test cases; failure modes tested in `tests/test_failure_modes.py` |

To re-verify after changes:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests/ -q
```


## Additional Documentation

- [INCIDENT_RUNBOOK.md](INCIDENT_RUNBOOK.md) - incident response for false positives and escalation patterns
- [docs/PERFORMANCE_BASELINE.md](docs/PERFORMANCE_BASELINE.md) - scan performance baselines and regression gates
- [benchmarks/perf_gate.py](benchmarks/perf_gate.py) - CI performance gate (p95 < 10ms, >1000 policies/sec)

## License

MIT — see [LICENSE](LICENSE).
