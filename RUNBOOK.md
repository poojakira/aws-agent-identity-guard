# Operations runbook

## Choose the correct interface

| Interface | Entry point | Input and boundary |
|---|---|---|
| Local studio | `python -m aws_agent_identity_guard.studio` / `iam-studio` | Bounded identity/trust JSON; real browser/static evidence, no AWS |
| Static CLI | `aws-agent-identity-guard POLICY.json` | One local identity-policy object per invocation; no AWS |
| Python trust API | `scan_trust_policy` | Supplied trust document; no effective-permission evaluation |
| Optional live collector | `aws-agent-identity-guard --live-scan` | Operator-authorized IAM/STS reads using Boto3 credentials |

Use [README setup](README.md#start-locally) for the studio. It binds only to loopback, has no multi-user login/database, and stops with Ctrl+C. `GET /health` reports liveness, rule inventory and source provenance; health is not a security or effective-permission verdict. A wheel reports source UNKNOWN outside the exact tracked source root. An occupied port can be changed with `--port`; the bind address cannot.

## Static CLI

Use this reviewed source checkout/virtual environment. A PyPI name/version is not proof that a registry distribution matches this candidate; verify distribution provenance separately. After source installation:

```sh
aws-agent-identity-guard --version
aws-agent-identity-guard --help
aws-agent-identity-guard examples/agent_policy_wildcard.json --format json
aws-agent-identity-guard examples/agent_policy_wildcard.json --format sarif --output /tmp/iam-results.sarif
```

The intentionally broad synthetic fixture normally returns a finding exit status. Inspect outputs, not only shell success. `--output` writes machine-readable JSON/SARIF; do not combine `--remediate` with machine-readable stdout because appended template text is not JSON. Static CLI JSON has a top-level `findings` array. Findings contain rule ID, lowercase severity, message, remediation and optional statement index; text mode prints a block per finding with no severity-count summary. A no-finding text response is a scanner result, not permission to deploy. The static CLI does not accept a trust-policy flag; use the studio or `scan_trust_policy` for trust input.

### Exit status

| Status | Actual meaning | Operator interpretation |
|---|---|---|
| 0 | No high/critical findings; medium findings may remain | No configured blocking pattern matched; safety/effective permissions unknown |
| 1 | High/critical findings; live `--enforce` also fails on incomplete/error reports | Preserve/review output; retain the configured CI gate |
| 2 | Unusable input/configuration/runtime failure, including unavailable live prerequisites | No successful clean scan established |

CLI reads a local object as UTF-8 JSON and rejects duplicate keys. It does not apply every studio structural/size bound. Do not assume an arbitrary CLI JSON object was fully validated as AWS policy language. Analyze one file at a time; if writing a batch wrapper, aggregate every exit status and distinguish findings from tool errors. Do not mask nonzero statuses or make incomplete scans appear clean.

## Optional live collection

**Not executed by this documentation pass.** It requires an explicitly authorized target account and `.[live]`/Boto3, and may consume AWS API/service quotas. Prefer an existing short-lived workload identity or read-only profile through the standard provider chain. Never put credentials in source, shell examples, screenshots or outputs. The studio needs none of these prerequisites.

```sh
aws-agent-identity-guard --live-scan --enforce --format json --output /tmp/iam-account-scan.json
aws-agent-identity-guard --live-scan --enforce --role-name exact-role-name --region us-east-1 --format json --output /tmp/iam-role-scan.json
```

`--role-name` selects one exact role name, not a wildcard and not a cross-account traversal. Account access comes from the configured SDK identity, not from this flag. Region defaults to the session region or us-east-1; IAM itself is global. The collector enumerates roles, users and collected policy documents, invokes canonical static rules, and adds AIG-PB001 for flagged roles without a boundary. It does not calculate all effective permissions, evaluate group inheritance/intersections, or infer authorization from boundary attachment.

Required reads follow the actual collector: STS `GetCallerIdentity`; IAM `ListRoles`, `GetRole`, `ListUsers`, `ListRolePolicies`, `GetRolePolicy`, `ListAttachedRolePolicies`, `GetPolicy`, `GetPolicyVersion`, `ListUserPolicies`, `GetUserPolicy`, `ListAttachedUserPolicies`, and `ListUserTags`. Review scope/conditions for your environment rather than copying an account-wide wildcard policy blindly. [Terraform/trust guidance](docs/aws-architecture.md) distinguishes account-principal AssumeRole from OIDC web identity. No CloudWatch log delivery or CloudTrail lookup is implemented by the ordinary collector despite older source commentary.

JSON reports include `scan_complete`, `errors`, `roles_discovered`, `completeness_reason`, counts, findings and collected role context. A role cap of 500 can truncate a scan; it is a constructor option rather than a documented CLI flag. API errors can also make collection incomplete. Without `--enforce`, a partial report with no high/critical findings may exit 0. Use the flag and inspect all completeness fields for CI. Absence of findings in a partial scan is not absence of risk. Do not infer completeness from the number of roles alone.

## Remediation output

```sh
aws-agent-identity-guard examples/agent_policy_wildcard.json --remediate
```

Static `--remediate` invokes rule-keyed templates in `remediate.py` for supported findings. The CLI prints explanations and Terraform HCL; template objects may also contain CloudFormation/fixed-policy representations, but the CLI does not print every representation. Template selection is rule-based, but generated content can include a generation timestamp, so repeated outputs need not be byte-identical. It does not apply infrastructure or prove the suggestions correct for your resources. Placeholders, account/region/service/resource names, workload requirements and policy intersections require independent review and testing. Treat the help phrase “ready-to-apply” as a description of emitted template syntax, not deployment approval. Live mode returns before the static remediation branch; `--live-scan --remediate` does not perform live auto-remediation.

## Data, CI and recovery

Studio input/comparisons stay in memory; downloads remain on the operator's disk. CLI/live reports can reveal ARNs, account/role names, policies and error details. Protect their storage and access; they are not automatically anonymized. There is no persistent studio backup to restore. For retained CLI/live reports use your own reviewed retention/encryption/backup policy.

Use [the repository verification workflow](docs/EVIDENCE.md), pin reviewed source/artifact and Actions revisions in your own CI, and retain nonzero finding/error statuses. Generic JSON is not automatically a GitLab security-report schema; use it as a normal artifact or supply a separately validated adapter. SARIF schema validity does not prove security conclusions. No Slack/Jira/email should receive policy context without explicit authorization and redaction. The [n8n template](integrations/N8N_WORKFLOW.md) needs error/completeness and downstream-side-effect review before activation.

For failure: preserve the exact source/version, non-secret input/configuration hashes, actual stderr/outcome, and a synthetic reproduction. Use [SECURITY.md](SECURITY.md) for private vulnerability reports. Do not bypass gates, broadly suppress findings or mutate AWS just to obtain a green check. Roll back in a separate reviewed checkout/virtual environment after preserving local changes; re-run its checks. Code rollback does not undo AWS changes or revoke credentials. [Incident guidance](INCIDENT_RUNBOOK.md) is a template, not a staffed SLA.

## Troubleshooting

| Observation | Check and recovery |
|---|---|
| Studio connection refused | Check owned terminal, printed port, Python version and virtual environment |
| Studio 403 | Use exact `127.0.0.1` origin/port; alternate Host/proxying is refused |
| Studio 400/413/415 | Correct supported JSON, bounded size and request framing; no successful review is established |
| Studio 429 | Wait for the serial server's local rate budget to refill |
| Export disabled after editing/upload | Review the current snapshot again; old output is intentionally invalidated |
| Command absent | Activate the environment or use `python -m aws_agent_identity_guard.cli`; inspect `--help` |
| Live missing Boto3/credentials/access | Keep result incomplete/error; install/configure approved live prerequisites only if that separate operation is authorized |
| Findings differ across versions | Compare exact rules/configuration/input and pin the reviewed version; never equate count reduction with verified permission reduction |
