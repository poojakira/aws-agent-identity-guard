# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — agent/security-hardening-v1

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
