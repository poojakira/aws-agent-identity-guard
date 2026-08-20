# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-20

### 🎉 Production Release

AWS Agent Identity Guard reaches production stability with comprehensive security
coverage for AI agents operating in AWS environments.

### Added

- **Runtime Authorization Engine**: Real-time policy evaluation for agent actions with sub-millisecond decision latency.
- **Attack Path Analysis**: Graph-based analysis detecting multi-step privilege escalation paths across IAM roles, policies, and trust relationships.
- **Privilege Escalation Detection**: 25+ known escalation patterns detected including CreateRole→AttachPolicy chains, PassRole abuse, and cross-service pivots.
- **Policy Engine v2**: YAML-based security policy language supporting deny, require_approval, warn, audit, and constraint rule types.
- **Production Policy Set**: Strict production-environment policies with 17 rules covering destructive actions, IAM mutations, and network changes.
- **SARIF Output**: Full SARIF 2.1.0 compliant output for CI/CD integration with GitHub Code Scanning, Azure DevOps, and other SARIF consumers.
- **REST API Server**: Uvicorn-based API for runtime authorization queries with Redis-backed caching.
- **CLI Tool**: Complete command-line interface for policy validation, IAM linting, attack path scanning, and report generation.
- **Risk Scoring Engine**: Composite risk scoring combining action severity, resource sensitivity, environment context, and historical patterns.
- **CloudTrail Integration**: Real-time monitoring of agent API calls with anomaly detection and policy violation alerting.
- **Cross-Account Detection**: Automatic warning when agents attempt to assume roles in external AWS accounts.
- **Data Classification Awareness**: Policy rules that consider data classification labels (CONFIDENTIAL, SECRET, REGULATED) for access decisions.
- **Session Duration Constraints**: Enforcement of maximum session durations for agent credentials.
- **MFA Context Validation**: Verification that production actions originate from MFA-authenticated calling chains.
- **Bedrock Agent Support**: Native integration with Amazon Bedrock agent role patterns and action groups.
- **SageMaker Agent Support**: Policy templates and detection rules for SageMaker notebook and endpoint agent roles.
- **ECS Task Role Support**: Analysis of ECS task role configurations for container-based agents.
- **Lambda Agent Support**: Policy enforcement for Lambda-based agent execution roles.
- **Custom Policy Authoring**: Full documentation and validation for user-defined security policies.
- **Policy Inheritance**: Production policies can extend and override default baselines.
- **Typed Codebase**: Full type annotations with Pyright standard mode compliance.

### Changed

- **Breaking**: Package restructured under `src/` layout for proper namespace isolation.
- **Breaking**: CLI entry point renamed from `agent-guard` to `aws-agent-identity-guard`.
- **Breaking**: Policy file format updated to v1.0 schema with `metadata` block.
- Minimum Python version raised to 3.10 (from 3.9).
- Switched from black+isort to ruff for formatting and linting.
- IAM analysis engine rewritten for 10x performance improvement on large policy sets.

### Fixed

- False positives on service-linked role detection.
- Incorrect severity mapping for KMS-related findings.
- SARIF output missing `ruleIndex` field causing validator warnings.
- Policy loader crash on empty YAML files.
- Cross-account detection failing for GovCloud and China partition ARNs.

### Security

- Added policy rules preventing CloudTrail deletion and logging disruption.
- Added detection for security group rules opening 0.0.0.0/0 ingress.
- Added secrets deletion prevention in production environments.

---

## [0.5.0] - 2026-07-15

### Added

- Initial SARIF output support (v2.1.0 schema).
- Policy loader with basic deny/allow rule evaluation.
- Risk scoring prototype with action-severity weighting.
- Bedrock agent role detection heuristics.

### Changed

- Migrated to pyproject.toml from setup.py.
- Improved error messages for malformed IAM policies.

### Fixed

- Wildcard expansion not handling `s3:*` correctly.
- CLI crash when no policy file specified.

---

## [0.4.0] - 2026-06-01

### Added

- Attack path analysis prototype using adjacency graph.
- Privilege escalation detection for 10 known patterns.
- CloudTrail event parsing for real-time monitoring.
- Initial REST API skeleton with health check endpoint.

### Changed

- Refactored IAM analyzer into separate concern modules.
- Improved test coverage to 85%.

### Fixed

- Memory leak in graph traversal for large role networks.
- Incorrect trust policy parsing for service principals.

---

## [0.3.0] - 2026-04-20

### Added

- Core IAM policy parser and analyzer.
- Basic CLI with `lint` and `scan` commands.
- Default security policy with 5 baseline rules.
- Initial project structure and CI pipeline.
- Unit test framework with moto-based AWS mocking.
- Type annotations for core modules.

### Changed

- Initial public release structure.

---

[1.0.0]: https://github.com/poojakira/aws-agent-identity-guard/compare/v0.5.0...v1.0.0
[0.5.0]: https://github.com/poojakira/aws-agent-identity-guard/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/poojakira/aws-agent-identity-guard/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/poojakira/aws-agent-identity-guard/releases/tag/v0.3.0
