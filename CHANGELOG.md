# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.0] — 2026-09-01

### Added
- Policy-wide kill-chain combination rules (AIG019–AIG021): credential-harvest
  + lateral-movement, credential-harvest + metadata-reach, and the full
  harvest→metadata→lateral chain in a single identity.
- Permission-boundary presence check (AIG-PB001) in live-scan mode.
- Deterministic IaC remediation generator (`--remediate`): Terraform HCL /
  CloudFormation / fixed policy JSON from rule-keyed templates.
- `--enforce` mode: fail CI on incomplete/errored live scans in addition to
  high/critical findings.
- `--output` support for machine-readable formats (json/sarif) so the
  documented `upload-sarif` CI flow works end to end.

### Fixed
- CLI now exits with code **2** (not 1) on unusable input (missing file,
  invalid JSON, non-object JSON, non-UTF-8), matching the documented Failure
  Semantics. Failure-mode tests now assert the exit code, not just the message.
- RUNBOOK "Expected output" samples corrected to match the tool's real text
  and `--remediate` output; removed a false "scan multiple files" example
  (the CLI analyzes one policy per invocation).
- `ruff format` drift in two test files fixed so the CI format gate passes.

### Changed
- Removed the inaccurate "AI-Powered Infrastructure Automation" label from the
  remediation generator and CLI banner; it is deterministic template code with
  no ML/LLM involved.

## [0.2.0] — 2026-08-07

### Added
- 11 new agent-specific detection rules (AIG008-AIG018)
- Bedrock control-plane detection (AIG008)
- SageMaker control-plane detection (AIG009)
- Network egress modification detection (AIG010)
- Audit trail tampering detection (AIG011)
- Excessive action breadth check (AIG012)
- Missing condition keys check (AIG013)
- S3 write without prefix scoping (AIG014)
- Bedrock model-ID scoping check (AIG015)
- Lambda function-name scoping check (AIG016)
- AssumeRole session tag check (AIG017)
- Database access scoping check (AIG018)
- Well-scoped and overprivileged example policies

### Changed
- Expanded PRIVILEGE_ACTIONS, TOOL_EXECUTION_PATTERNS, SENSITIVE_DATA_PATTERNS
- Improved _matches_any function for pattern vs exact matching

## [0.1.1] — agent/security-hardening-v1

### Added
- `scan_trust_policy()` function with 3 rules: wildcard principal (AIG-TP001), missing ExternalId (AIG-TP002), missing aws:SourceArn (AIG-TP003)
- Live Boto3 account scanner (`live_scanner.py`) — enumerates IAM roles and users, runs all static rules against collected policy documents
- `--live-scan` CLI flag with `--role-name` filter and `--region` override
- SARIF 2.1.0 output format (`--format sarif`)
- `SECURITY.md`, `THREAT_MODEL.md`, `CONTRIBUTING.md`, `.github/dependabot.yml`
- GitHub Actions SHA-pinned in CI workflow

### Changed
- `README.md` updated to describe both static and live scanning modes
- `SECURITY_AUDIT.md` updated with new rules and findings

### Fixed
- CI actions (`actions/checkout`, `actions/setup-python`, `actions/upload-artifact`) pinned to commit SHAs

## [0.1.0] — Initial release

### Added
- Static IAM policy linter with 7 core rule categories (AIG001–AIG007)
- CLI with `--format text/json` output
- Trust-policy scanning (AIG-TP001–AIG-TP003)
- Exit code 0 (clean) / 1 (high+critical findings) / 2 (input error)
- Example policy fixture (`examples/agent_policy_wildcard.json`)
- GitHub Actions CI (lint + security + test matrix)
