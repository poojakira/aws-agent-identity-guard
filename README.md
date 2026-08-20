# AWS Agent Identity Guard

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen.svg)](.github/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-94%25-brightgreen.svg)](tests/)
[![Security Audit](https://img.shields.io/badge/security-audited-blueviolet.svg)](SECURITY_AUDIT.md)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg)](Dockerfile)
[![Helm](https://img.shields.io/badge/helm-chart-0F1689.svg)](helm/)
[![PyPI](https://img.shields.io/badge/pypi-v1.0.0-orange.svg)](https://pypi.org/project/aws-agent-identity-guard/)

**AI agent identity security platform for AWS.** Runtime authorization, risk scoring, attack-path analysis, policy-as-code, and enforcement for Bedrock, Lambda, SageMaker, and ECS agent workloads.

---

## Quick Start

```bash
# Install
pip install aws-agent-identity-guard

# Run the demo (authorization, risk scoring, attack paths)
python -m demo.run_demo

# Start the API server
uvicorn aws_agent_identity_guard.api:app --host 0.0.0.0 --port 8000
```

---

## Architecture

```
+--------+     +-----+     +-------------------+     +---------------+     +-------------+     +----------+
| Agent  | --> | SDK | --> | Authorization API | --> | Policy Engine | --> | Risk Engine | --> | Decision |
+--------+     +-----+     +-------------------+     +---------------+     +-------------+     +----------+
                                    |                        |                     |
                                    v                        v                     v
                            +---------------+       +--------------+      +----------------+
                            | Audit / Trace |       | Policy Store |      | Attack Paths   |
                            +---------------+       +--------------+      +----------------+
```

Every authorization request flows through: identity resolution, policy evaluation, risk scoring, and enforcement. Decisions are logged with full correlation IDs for audit.

---

## Feature Matrix

| Feature | Status | Description |
|---------|--------|-------------|
| Runtime Authorization | GA | Real-time ALLOW/DENY/STEP_UP decisions per request |
| Policy Engine | GA | Declarative YAML policies with conditions, priorities, versioning |
| Risk Scoring | GA | Multi-dimensional scoring (permission, network, data, behavior) |
| Attack Path Analysis | GA | Graph-based privilege escalation chain detection |
| Agent Registry | GA | Identity lifecycle management with metadata binding |
| Human-in-the-Loop | GA | Step-up approvals with TTL and delegation |
| Permission Drift Detection | GA | Continuous monitoring of permission changes |
| Escalation Detection | GA | Pattern matching for privilege escalation attempts |
| Behavior Analysis | GA | Anomaly detection on agent action patterns |
| Intent Alignment | GA | Verify agent actions match declared purpose |
| Least Privilege Enforcement | GA | Automatic permission boundary recommendation |
| Capability Inventory | GA | Track and limit agent capabilities |
| Observability | GA | Prometheus metrics, structured logs, OpenTelemetry traces |
| SDK (Python) | GA | Thread-safe client with retries, circuit breaker |
| REST API | GA | FastAPI with OpenAPI docs, CORS, rate limiting |
| Docker | GA | Multi-stage production image |
| Helm Chart | GA | Kubernetes deployment with HPA, PDB |
| Terraform Modules | GA | AWS reference architecture (ECS, EKS, Lambda) |

---

## Core Components

| Module | Purpose |
|--------|---------|
| `authorization.py` | Central authorization engine; orchestrates policy + risk decisions |
| `policy_engine.py` | YAML policy evaluation with conditions, priorities, conflict resolution |
| `risk_engine.py` | Multi-dimensional risk scoring and classification |
| `attack_paths.py` | Graph traversal for privilege escalation chains |
| `escalation_engine.py` | Real-time escalation pattern detection |
| `models.py` | Canonical data models (agents, permissions, decisions, events) |
| `api.py` | FastAPI REST API with versioned endpoints |
| `sdk.py` | Python SDK with retries, circuit breaker, decorators |
| `approval.py` | Human-in-the-loop approval workflow |
| `drift_detector.py` | Permission drift monitoring and alerting |
| `behavior_analyzer.py` | Behavioral anomaly detection |
| `intent_alignment.py` | Action-to-purpose alignment verification |
| `least_privilege.py` | Minimum permission boundary calculation |
| `capability_inventory.py` | Agent capability tracking and enforcement |
| `enforcement.py` | Decision enforcement and remediation |
| `observability.py` | Metrics, logging, tracing infrastructure |
| `scanner.py` | Static IAM policy analysis |
| `live_scanner.py` | Live AWS account scanning |
| `remediate.py` | Automated remediation actions |

---

## SDK Usage

```python
from aws_agent_identity_guard import AgentIdentityGuard

# Initialize client
guard = AgentIdentityGuard(base_url="http://localhost:8000")

# Authorize a request
decision = guard.authorize(
    agent_id="agent-bedrock-001",
    action="s3:GetObject",
    resource="arn:aws:s3:::data-bucket/reports/q4.csv",
    context={"session_id": "sess-abc123", "data_classification": "CONFIDENTIAL"}
)

if decision.decision == "ALLOW":
    # Proceed with action
    pass
elif decision.decision == "STEP_UP":
    # Request human approval
    pass
else:
    # Denied -- log and alert
    print(f"Denied: {decision.reasons}")
```

### Decorator Pattern

```python
from aws_agent_identity_guard import AgentIdentityGuard

guard = AgentIdentityGuard(base_url="http://localhost:8000")

@guard.authorize_action(agent_id="agent-bedrock-001")
def fetch_customer_data(customer_id: str):
    """This function is gated by authorization."""
    return db.query(f"SELECT * FROM customers WHERE id = {customer_id}")
```

---

## Policy-as-Code

```yaml
# policies/production-agents.yaml
version: "1.0"
policies:
  - id: deny-admin-actions
    effect: DENY
    priority: 100
    description: "Block administrative actions from all agents"
    conditions:
      action_pattern: "iam:*"
      environment: PRODUCTION

  - id: allow-read-data
    effect: ALLOW
    priority: 50
    description: "Allow read access to designated data buckets"
    conditions:
      action_pattern: "s3:GetObject"
      resource_pattern: "arn:aws:s3:::approved-data-*"
      data_classification:
        - PUBLIC
        - INTERNAL

  - id: step-up-sensitive
    effect: STEP_UP
    priority: 75
    description: "Require approval for sensitive data access"
    conditions:
      data_classification: CONFIDENTIAL
      environment: PRODUCTION
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/authorize` | Authorize an agent action |
| POST | `/v1/agents` | Register a new agent |
| GET | `/v1/agents` | List registered agents |
| GET | `/v1/agents/{id}` | Get agent details |
| PUT | `/v1/agents/{id}` | Update agent |
| DELETE | `/v1/agents/{id}` | Deregister agent |
| POST | `/v1/approvals` | Create approval request |
| PUT | `/v1/approvals/{id}` | Approve or reject |
| GET | `/v1/approvals` | List pending approvals |
| GET | `/v1/agents/{id}/risk` | Get agent risk score |
| GET | `/v1/agents/{id}/attack-paths` | Get attack paths |
| GET | `/v1/agents/{id}/permissions` | Get effective permissions |
| GET | `/health` | Health check |
| GET | `/metrics` | Prometheus metrics |

Full API documentation: [docs/api-reference.md](docs/api-reference.md)

---

## CI/CD Integration

```yaml
# .github/workflows/security-gate.yml
- name: Agent Identity Guard Check
  run: |
    pip install aws-agent-identity-guard
    agent-identity-guard scan --format sarif --output results.sarif
    agent-identity-guard authorize --policy policies/ --fail-on deny
```

---

## Deployment Options

| Method | Command |
|--------|---------|
| pip | `pip install aws-agent-identity-guard` |
| Docker | `docker compose up -d` |
| Helm | `helm install agent-guard ./helm/agent-identity-guard` |
| Terraform | `terraform apply -var-file=prod.tfvars` |

See [docs/deployment-guide.md](docs/deployment-guide.md) for full instructions.

---

## Benchmarks

| Metric | Value |
|--------|-------|
| p50 latency | 2.1 ms |
| p95 latency | 4.8 ms |
| p99 latency | 8.3 ms |
| Throughput | 12,400 decisions/sec |
| Policy evaluation | 0.8 ms avg |
| Risk scoring | 1.2 ms avg |
| Attack path (cached) | 3.1 ms avg |

Measured on c5.2xlarge (8 vCPU, 16 GB RAM), Python 3.12, uvicorn with 4 workers. See [docs/benchmarks.md](docs/benchmarks.md).

---

## Security Model

- All agent identities are cryptographically bound to IAM roles
- Policies are evaluated in strict priority order; explicit DENY always wins
- Risk scoring is multi-dimensional and context-aware
- Audit trail is immutable with correlation IDs
- mTLS supported for API communication
- API keys with scoped permissions and rotation
- No secrets stored in memory beyond request lifecycle
- Defense-in-depth: multiple independent checks per request

See [docs/threat-model.md](docs/threat-model.md) for the formal threat model.

---

## Compliance Mappings

| Framework | Coverage | Document |
|-----------|----------|----------|
| NIST AI RMF | Govern, Map, Measure, Manage | [nist-ai-rmf-mapping.md](docs/compliance/nist-ai-rmf-mapping.md) |
| NIST SP 800-53 | AC, AU, IA, SI, CM families | [nist-800-53-mapping.md](docs/compliance/nist-800-53-mapping.md) |
| MITRE ATLAS | 18 techniques mapped | [mitre-atlas-mapping.md](docs/compliance/mitre-atlas-mapping.md) |
| OWASP LLM Top 10 | All 10 items | [owasp-llm-mapping.md](docs/compliance/owasp-llm-mapping.md) |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, code style, and PR process.

## License

[MIT](LICENSE)

## Acknowledgments

- AWS IAM and Bedrock documentation for service model reference
- MITRE ATLAS framework for AI/ML threat taxonomy
- NIST AI RMF and SP 800-53 for control frameworks
- OWASP LLM Top 10 for application security guidance
