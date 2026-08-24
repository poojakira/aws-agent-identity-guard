# AWS Agent Identity Guard

**Runtime authorization, risk scoring, and attack-path analysis for AI agents running on AWS.**

---

## The Problem No One Talks About

IAM tells you whether a principal *can* perform an action. It does not tell you whether an AI agent *should*.

Picture this: your company deploys a Bedrock-powered agent that processes customer support tickets. It has an IAM role with S3 read access to a data bucket. One day the agent starts reading objects from an HR payroll bucket in the same account because its prompt was manipulated. IAM says ALLOW because the policy permits `s3:GetObject` on `*`. Nothing fires. No alarm. No audit trail that connects the action back to the agent's stated purpose.

AWS Agent Identity Guard sits between the agent and AWS, asking a different question at every request: "Given this agent's declared purpose, its behavioral history, and the sensitivity of the target resource, should this action proceed?"

---

## Executive Summary

This project is for platform engineers, security teams, and ML infrastructure operators who run agentic AI workloads on AWS (Bedrock, Lambda, SageMaker, ECS) and need authorization controls that go beyond what IAM alone provides.

It solves three specific problems:

1. **Overprivileged agents** that accumulate permissions over time without anyone reviewing whether those permissions match the agent's actual job.
2. **No runtime intent verification** - IAM cannot distinguish between an agent performing its intended task and an agent acting on a manipulated prompt.
3. **Invisible attack paths** - privilege escalation chains through agent roles that static IAM analysis tools miss because they do not model agent behavior.

---

## Why This Repository Exists

AWS IAM is a powerful authorization system, but it was designed for human-driven workflows and service-to-service communication. Agentic AI workloads introduce new failure modes:

- Agents make thousands of decisions per minute with no human in the loop
- Prompt injection can redirect an agent's actions without changing its IAM permissions
- Agents accumulate permissions across deployments (permission drift)
- Traditional IAM analysis tools do not model agent intent or behavioral baselines

This repository answers:

- How do I enforce least privilege on AI agents that need flexible access?
- How do I detect when an agent deviates from its declared purpose?
- How do I identify privilege escalation chains that an agent could exploit?
- How do I add human approval gates for sensitive actions without blocking the entire workflow?
- How do I get an audit trail that ties every agent action to a policy decision?

---

## Architecture Overview

```
+--------+     +-----+     +-------------------+     +---------------+     +-------------+     +----------+
| Agent  | --> | SDK | --> | Authorization API | --> | Policy Engine | --> | Risk Engine | --> | Decision |
+--------+     +-----+     +-------------------+     +---------------+     +-------------+     +----------+
                                    |                        |                     |
                                    v                        v                     v
                            +---------------+       +--------------+      +----------------+
                            | Audit / Trace |       | Policy Store |      | Attack Paths   |
                            +---------------+       +--------------+      +----------------+
                                    |
                                    v
                           +------------------+
                           | Observability    |
                           | (Prometheus,     |
                           |  OpenTelemetry)  |
                           +------------------+
```

### Component Responsibilities

| Component | What it does |
|-----------|-------------|
| SDK (`sdk.py`) | Thread-safe Python client with retries and circuit breaker. Wraps HTTP calls to the Guard API. |
| Authorization API (`api.py`) | FastAPI server that receives authorize requests, orchestrates policy + risk evaluation, returns ALLOW/DENY/STEP_UP. |
| Policy Engine (`policy_engine.py`) | Evaluates declarative YAML policies with conditions, priorities, and conflict resolution. Explicit DENY always wins. |
| Risk Engine (`risk_engine.py`) | Computes an 8-dimension risk score (permission scope, network exposure, data sensitivity, behavioral anomaly, etc.). |
| Attack Paths (`attack_paths.py`) | Graph traversal that finds privilege escalation chains reachable from an agent's current permissions. |
| Behavior Analyzer (`behavior_analyzer.py`) | Builds behavioral baselines per agent and flags anomalous action patterns. |
| Intent Alignment (`intent_alignment.py`) | Verifies agent actions against a declared manifest of purpose. |
| Drift Detector (`drift_detector.py`) | Monitors IAM permission changes and alerts on unauthorized expansion. |
| Escalation Engine (`escalation_engine.py`) | Pattern matching for known privilege escalation techniques (iam:PassRole, sts:AssumeRole chains). |
| Approval (`approval.py`) | Human-in-the-loop workflow with TTL-based approval tokens and delegation. |
| Enforcement (`enforcement.py`) | Executes decisions: blocks requests, triggers remediation, notifies operators. |
| Observability (`observability.py`) | Prometheus metrics, structured JSON logs, OpenTelemetry trace propagation. |
| Scanner (`scanner.py`) | Static IAM policy analysis (zero external dependencies, runs in CI). |
| Live Scanner (`live_scanner.py`) | Connects to a live AWS account via boto3 to scan actual IAM state. |

---

## End-to-End Workflow

Here is how a single authorization request flows through the system:

1. **Agent calls action** - The agent (Bedrock, Lambda, etc.) invokes an AWS API through the SDK decorator or explicit `guard.authorize()` call.

2. **Identity resolution** - The SDK sends the agent ID, requested action, target resource ARN, and context (session, data classification, environment) to the Guard API.

3. **Policy evaluation** - The Policy Engine loads applicable YAML policies, filters by agent/action/resource conditions, and evaluates in priority order. Explicit DENY is terminal.

4. **Risk scoring** - If no DENY matched, the Risk Engine computes a multi-dimensional score. High-risk actions (sensitive data + production + anomalous behavior) trigger STEP_UP even if policies allow them.

5. **Attack path check** - The system checks whether the requested action opens a new escalation path. If it does, the risk score is elevated.

6. **Decision** - The API returns ALLOW, DENY, or STEP_UP with reasons and a correlation ID.

7. **STEP_UP flow** - If STEP_UP, the approval system creates a time-bounded approval request. A human reviewer approves or rejects. The agent retries after approval.

8. **Audit** - Every decision is logged with a hash-chain linking it to the previous event, creating a tamper-evident audit trail.

9. **Metrics** - Decision latency, allow/deny ratios, risk score distributions, and escalation counts are exported to Prometheus.

---

## Design Decisions and Trade-offs

**Fail-closed in production.** If the Guard API is unreachable, agents are denied by default. This is the safe choice for production. Development environments can opt into fail-open. The trade-off: a Guard outage becomes an availability incident for all gated agents. Mitigation: the SDK has a circuit breaker that caches recent decisions.

**YAML policies, not a DSL.** Policies are YAML files stored in Git. This means security teams use the same review and merge workflow as developers. The trade-off: YAML is verbose and lacks programmatic expressiveness. Complex conditions require multiple policy files rather than a single rule with logic. We chose simplicity and auditability over power.

**8-dimension risk scores instead of HIGH/MEDIUM/LOW.** A single severity label loses context. An action rated HIGH in production with CONFIDENTIAL data is fundamentally different from HIGH in dev with synthetic data. The trade-off: consumers must understand multi-dimensional scores, which adds integration complexity.

**Zero dependencies for static scanning.** The CLI scanner uses only Python stdlib. It can run in any CI environment without installing packages. The runtime API adds PyYAML, FastAPI, and optional Redis. This separation means you can adopt static scanning today and add runtime enforcement later.

**Hash-chain audit trail.** Each audit event includes a cryptographic hash of the previous event. If any event is tampered with or deleted, integrity verification breaks. The trade-off: reading the audit log requires traversing the chain, and bulk queries are slower than a simple table scan.

**Performance budget of 10ms.** Inline authorization must not materially slow down agent execution. Policy evaluation and risk scoring run synchronously within 10ms. Expensive operations (attack path traversal, drift detection) run asynchronously and cache results.

---

## Tech Stack, Installation, and Quick Start

### Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.10+ |
| API Framework | FastAPI + Uvicorn |
| Policy Format | YAML (PyYAML) |
| Caching | Redis (optional) |
| Observability | Prometheus, OpenTelemetry |
| Container | Docker (multi-stage build) |
| Orchestration | Helm chart for Kubernetes |
| Infrastructure | Terraform modules (ECS, EKS, Lambda) |
| Testing | pytest, moto (AWS mocking), httpx |
| Linting | Ruff, Pyright |

### Installation

```bash
# Basic install (static scanning, CLI)
pip install aws-agent-identity-guard

# With API server support
pip install aws-agent-identity-guard[api]

# With live AWS scanning
pip install aws-agent-identity-guard[live]

# Full install (API + live + observability + Redis caching)
pip install aws-agent-identity-guard[all]

# Development
pip install aws-agent-identity-guard[dev]
```

### Quick Start

```bash
# 1. Install
pip install aws-agent-identity-guard[api]

# 2. Run the demo (no AWS credentials needed)
python -m demo.run_demo

# 3. Start the API server
uvicorn aws_agent_identity_guard.api:app --host 0.0.0.0 --port 8000

# 4. Static scan of IAM policies (CI integration)
agent-guard scan --format sarif --output results.sarif
```

### Docker

```bash
docker compose up -d
```

### Helm (Kubernetes)

```bash
helm install agent-guard ./helm/agent-identity-guard
```

### Usage Examples

**Authorize an agent action:**

```python
from aws_agent_identity_guard import AgentIdentityGuard

guard = AgentIdentityGuard(base_url="http://localhost:8000")

decision = guard.authorize(
    agent_id="agent-bedrock-001",
    action="s3:GetObject",
    resource="arn:aws:s3:::data-bucket/reports/q4.csv",
    context={"session_id": "sess-abc123", "data_classification": "CONFIDENTIAL"}
)

if decision.decision == "ALLOW":
    proceed()
elif decision.decision == "STEP_UP":
    request_human_approval()
else:
    log_and_alert(decision.reasons)
```

**Decorator pattern (gate functions automatically):**

```python
@guard.authorize_action(agent_id="agent-bedrock-001")
def fetch_customer_data(customer_id: str):
    return db.query(customer_id)
```

**Policy-as-code (YAML):**

```yaml
version: "1.0"
policies:
  - id: deny-admin-actions
    effect: DENY
    priority: 100
    conditions:
      action_pattern: "iam:*"
      environment: PRODUCTION

  - id: step-up-sensitive
    effect: STEP_UP
    priority: 75
    conditions:
      data_classification: CONFIDENTIAL
      environment: PRODUCTION
```

**CI/CD gate:**

```yaml
# .github/workflows/security-gate.yml
- name: Agent Identity Guard Check
  run: |
    pip install aws-agent-identity-guard
    agent-guard scan --format sarif --output results.sarif
    agent-guard authorize --policy policies/ --fail-on deny
```

---

## Threat Model and Mitigation Strategies

### Trust Boundaries

1. **Agent to Guard API** (untrusted) - agents are treated as potentially compromised
2. **Guard API to Policy Store** (trusted) - policies are integrity-checked
3. **Guard API to AWS APIs** (semi-trusted) - live scanning uses least-privilege credentials
4. **Dashboard to Guard API** (authenticated) - mTLS or API key with scoped permissions

### Threats and Mitigations

| Threat | Impact | Mitigation |
|--------|--------|-----------|
| Agent bypasses authorization entirely | Full uncontrolled access | Fail-closed enforcement; SDK middleware intercepts all calls; network policies restrict direct AWS API access |
| Policy tampering | Attacker grants themselves access | Policies versioned in Git; integrity hash on load; changes require PR review |
| Audit trail manipulation | Cover tracks after attack | Hash-chain integrity (tamper-evident); append-only storage |
| Privilege escalation via the Guard itself | Attacker gains admin | Guard runs with minimal IAM role (read-only for scanning, no admin permissions) |
| Denial of service against Guard | Agents cannot authorize, fail-closed blocks work | Rate limiting; circuit breaker in SDK caches recent allow decisions; horizontal scaling via Kubernetes HPA |
| Credential exposure in logs | Leaked secrets | No secrets logged; environment variables only; structured logging excludes sensitive fields |
| Prompt injection redirecting agent | Agent performs unintended actions with valid permissions | Intent alignment verification; behavioral anomaly detection; manifest-based purpose checking |

### Explicit Non-goals

The system does not protect against:
- Compromised AWS control plane
- Physical access to infrastructure
- Supply-chain attacks on AWS SDKs themselves
- Insider threat with admin access to the Guard service
- Network-level attacks below the application layer

---

## Evaluation Methods, Results, and Limitations

### Benchmarks

| Metric | Value |
|--------|-------|
| p50 authorization latency | 2.1 ms |
| p95 authorization latency | 4.8 ms |
| p99 authorization latency | 8.3 ms |
| Throughput | 12,400 decisions/sec |
| Policy evaluation | 0.8 ms avg |
| Risk scoring | 1.2 ms avg |
| Attack path (cached) | 3.1 ms avg |

Measured on c5.2xlarge (8 vCPU, 16 GB RAM), Python 3.12, Uvicorn with 4 workers.

### Testing

- Unit tests with pytest (80%+ coverage requirement enforced in CI)
- Integration tests using moto for AWS mocking
- Adversarial test suite that attempts privilege escalation, policy bypass, and audit tampering
- Benchmark tests for latency regression detection

### Limitations

- **Cold start latency**: First request after deployment takes longer due to policy loading and cache warming. Mitigated by readiness probes.
- **Policy complexity ceiling**: Very large policy sets (1000+ rules) degrade evaluation time beyond the 10ms budget. Recommend splitting into service-specific policy files.
- **Attack path staleness**: Graph analysis runs asynchronously. A newly created escalation path may not be detected for up to 60 seconds (configurable).
- **No real-time IAM event stream**: Drift detection polls CloudTrail rather than consuming a real-time feed. Detection latency is bounded by poll interval.
- **Single-region by default**: The Guard API runs in one region. Multi-region deployments require separate instances with shared policy storage.

---

## Production Readiness Assessment

| Criteria | Status | Notes |
|----------|--------|-------|
| CI/CD pipeline | Yes | GitHub Actions with lint, type check, test, security audit |
| Coverage threshold | Yes | 80% enforced via pytest-cov |
| Container image | Yes | Multi-stage Docker build, non-root user |
| Health checks | Yes | `/health` endpoint for liveness/readiness |
| Metrics endpoint | Yes | `/metrics` for Prometheus scraping |
| Structured logging | Yes | JSON logs with correlation IDs |
| Helm chart with HPA/PDB | Yes | Horizontal pod autoscaler, pod disruption budget |
| Terraform modules | Yes | ECS, EKS, Lambda reference architectures |
| Runbook | Yes | `RUNBOOK.md` with incident response procedures |
| Threat model | Yes | `THREAT_MODEL.md` with trust boundaries and mitigations |
| Security policy | Yes | `SECURITY.md` with vulnerability disclosure process |
| Typed codebase | Yes | Pyright in standard mode, full type annotations |
| Dependency pinning | Yes | `uv.lock` for reproducible builds |

---

## Roadmap and Future Improvements

- **Multi-region active-active** - Replicate policy decisions across regions with eventual consistency
- **AWS Organizations integration** - Enforce guardrails across all accounts in an organization from a single policy set
- **Bedrock Guardrails native integration** - Plug into Bedrock's built-in guardrail hooks for zero-SDK-change enforcement
- **Real-time CloudTrail streaming** - Replace polling with EventBridge for sub-second drift detection
- **Policy simulation mode** - Dry-run new policies against historical traffic before enforcement
- **Agent capability discovery** - Automatically infer an agent's actual permission usage and generate minimal policies
- **SIEM integration** - Native connectors for Splunk, Datadog, and AWS Security Hub

---

## References

- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html) - Foundational guidance on least privilege and permission boundaries
- [NIST AI Risk Management Framework (AI RMF)](https://www.nist.gov/artificial-intelligence/ai-risk-management-framework) - Govern, Map, Measure, Manage lifecycle for AI systems
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) - Security and privacy controls (AC, AU, IA, SI, CM families)
- [MITRE ATLAS](https://atlas.mitre.org/) - Adversarial threat landscape for AI systems
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) - Application security risks specific to LLM deployments
- [AWS Bedrock Security Documentation](https://docs.aws.amazon.com/bedrock/latest/userguide/security.html) - Service-specific security model
- [Zero Trust Architecture (NIST SP 800-207)](https://csrc.nist.gov/publications/detail/sp/800-207/final) - Never trust, always verify design principles

---

## License and Author

MIT License. See [LICENSE](LICENSE) for the full text.

**Author:** Pooja Kiran ([GitHub](https://github.com/poojakira))

---

## Engineering Lessons

Building this project reinforced a few things worth sharing:

The hardest part of agent security is not the technology. It is defining what "intended behavior" means for a system that makes its own decisions. Without a declared manifest of purpose, you are reduced to anomaly detection, which will always have false positives. The manifest approach shifts the problem from "detect bad" to "verify good," which is a much more tractable engineering problem.

Also: security controls that add more than 10ms of latency do not get adopted. Teams will route around them. The performance budget is not an optimization goal. It is an adoption requirement.
