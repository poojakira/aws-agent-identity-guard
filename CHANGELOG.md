# Changelog

All notable changes to AWS Agent Identity Guard are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-08-20

### Major Rewrite

Complete platform rewrite from static IAM policy linter to full runtime authorization platform for AI agent workloads.

### Added

- **Runtime Authorization Engine** -- real-time ALLOW/DENY/STEP_UP/REVIEW decisions per agent request
- **Policy-as-Code Engine** -- declarative YAML policies with conditions, priorities, conflict resolution
- **Multi-dimensional Risk Scoring** -- permission, network, data, and behavior risk dimensions
- **Attack Path Analysis** -- graph-based privilege escalation chain detection and severity classification
- **Escalation Detection** -- pattern matching for known privilege escalation techniques
- **Agent Registry** -- identity lifecycle management with IAM role binding
- **Human-in-the-Loop Approvals** -- step-up workflow with TTL, delegation, audit trail
- **Permission Drift Detection** -- continuous monitoring of permission changes with alerting
- **Behavior Analysis** -- statistical anomaly detection on agent action patterns
- **Intent Alignment Verification** -- verify agent actions match declared purpose
- **Least Privilege Engine** -- automatic minimum permission boundary recommendation
- **Capability Inventory** -- track and enforce declared agent capabilities
- **Enforcement Module** -- inline blocking, async remediation, quarantine
- **Observability Stack** -- Prometheus metrics, structured JSON logging, OpenTelemetry traces
- **Python SDK** -- thread-safe client with retries, circuit breaker, decorator and context manager patterns
- **REST API** -- FastAPI with OpenAPI docs, CORS, rate limiting, API key auth
- **Security Dashboard** -- real-time HTML dashboard with agent inventory, risk overview, attack paths
- **Docker Support** -- multi-stage production image, docker-compose with Prometheus and Grafana
- **Helm Chart** -- Kubernetes deployment with HPA, PDB, ingress, secrets management
- **Terraform Modules** -- AWS reference architecture for ECS/Fargate, EKS, Lambda
- **CI/CD Workflows** -- security gate workflow, release pipeline, dependency scanning
- **Comprehensive Test Suite** -- authorization, risk, policy, attack path, escalation, adversarial, resilience tests
- **Benchmark Suite** -- latency and throughput measurement harness
- **Demo System** -- interactive demonstration of all platform capabilities
- **Compliance Mappings** -- NIST AI RMF, NIST SP 800-53, MITRE ATLAS, OWASP LLM Top 10
- **Runbooks** -- incident response and operations procedures
- **Threat Model** -- formal STRIDE analysis with honest limitations disclosure

### Changed

- Scanner module retained and enhanced (now part of larger platform)
- CLI extended with new commands for authorization and policy management
- README completely rewritten for platform scope

### Removed

- Static-only analysis mode as default (now available via `scan` subcommand)

---

## [0.2.0] - 2026-08-19

### Added

- Real-world policy test corpus
- Kill chain detection patterns
- Live AWS account scanning
- CI workflow with security checks
- Dependabot configuration
- N8N workflow integration

### Changed

- Improved scanner detection rules
- Enhanced CLI output formatting

---

## [0.1.0] - 2026-08-02

### Added

- Initial IAM policy scanner
- Wildcard detection rules
- Overprivileged agent detection
- Basic CLI interface
- Example policies
- MIT license
