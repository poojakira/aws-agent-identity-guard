# NIST AI Risk Management Framework (AI RMF) Mapping

This document maps AWS Agent Identity Guard capabilities to the NIST AI RMF functions and categories. Each mapping references specific code, APIs, or features that provide evidence of compliance.

Reference: NIST AI 100-1 (AI Risk Management Framework)

---

## GOVERN Function

The Govern function establishes the organizational context for AI risk management.

### GV-1: Policies, processes, and procedures for AI risk management

| Sub-category | Project Feature | Evidence |
|--------------|----------------|----------|
| GV-1.1 | Policy-as-code engine | `src/policy_engine.py` -- declarative YAML policies define permitted/denied actions |
| GV-1.2 | Policy versioning and audit | Git-tracked policies with change history; `POST /v1/policies` creates versioned records |
| GV-1.3 | Default-deny posture | `AGENT_GUARD_DEFAULT_EFFECT=DENY` configuration; explicit allow required |
| GV-1.4 | Approval workflows | `src/approval.py` -- human-in-the-loop for elevated risk decisions |

### GV-2: Accountability structures

| Sub-category | Project Feature | Evidence |
|--------------|----------------|----------|
| GV-2.1 | Agent ownership tracking | `AgentIdentity.owner` field; required at registration via `POST /v1/agents` |
| GV-2.2 | Correlation IDs for tracing | Every decision includes `correlation_id`; full audit trail in `src/observability.py` |
| GV-2.3 | Role-based API access | API key scoping (read-only, authorize, admin) in `src/api.py` |

### GV-3: Workforce diversity and AI expertise

| Sub-category | Project Feature | Evidence |
|--------------|----------------|----------|
| GV-3.1 | Multi-reviewer approvals | `ApprovalManager` supports delegation chains; `src/approval.py` |
| GV-3.2 | Security review workflow | REVIEW effect flags actions for async human assessment |

---

## MAP Function

The Map function identifies and categorizes AI risks.

### MP-1: Context is established

| Sub-category | Project Feature | Evidence |
|--------------|----------------|----------|
| MP-1.1 | Agent identity context | `src/models.py` -- AgentIdentity captures type, environment, purpose, capabilities |
| MP-1.2 | Environment classification | `Environment` enum (DEVELOPMENT, STAGING, PRODUCTION) |
| MP-1.3 | Data classification | `DataClassification` enum (PUBLIC through REGULATED) |

### MP-2: AI risks are categorized

| Sub-category | Project Feature | Evidence |
|--------------|----------------|----------|
| MP-2.1 | Multi-dimensional risk scoring | `src/risk_engine.py` -- permission, network, data, behavior dimensions |
| MP-2.2 | Risk level classification | `classify_risk()` maps scores to LOW/MEDIUM/HIGH/CRITICAL |
| MP-2.3 | Attack path identification | `src/attack_paths.py` -- graph-based escalation chain discovery |

### MP-3: AI risks are prioritized

| Sub-category | Project Feature | Evidence |
|--------------|----------------|----------|
| MP-3.1 | Priority-based policy evaluation | `PolicyEngine` evaluates by priority; higher priority policies dominate |
| MP-3.2 | Severity classification for attack paths | `AttackPathInfo.severity` (LOW, MEDIUM, HIGH, CRITICAL) |
| MP-3.3 | Risk score thresholds | Configurable threshold triggers STEP_UP/DENY decisions |

---

## MEASURE Function

The Measure function quantifies AI risks using metrics and monitoring.

### MS-1: AI risks are measured

| Sub-category | Project Feature | Evidence |
|--------------|----------------|----------|
| MS-1.1 | Quantitative risk scoring | `RiskEngine.compute_risk_score()` returns 0-100 numeric score |
| MS-1.2 | Per-dimension breakdown | Risk response includes permission_score, network_score, data_score, behavior_score |
| MS-1.3 | Behavioral baselines | `src/behavior_analyzer.py` -- statistical modeling of normal agent behavior |

### MS-2: AI systems are monitored

| Sub-category | Project Feature | Evidence |
|--------------|----------------|----------|
| MS-2.1 | Real-time metrics | `src/observability.py` -- Prometheus metrics at `/metrics` |
| MS-2.2 | Decision audit logging | Every authorization decision logged with full context |
| MS-2.3 | Drift detection | `src/drift_detector.py` -- continuous permission change monitoring |
| MS-2.4 | Anomaly detection | `src/behavior_analyzer.py` -- deviation from historical patterns |

### MS-3: Feedback mechanisms

| Sub-category | Project Feature | Evidence |
|--------------|----------------|----------|
| MS-3.1 | Approval feedback loop | Human decisions on STEP_UP requests inform risk calibration |
| MS-3.2 | False positive tracking | Metrics track overrides and manual allows |
| MS-3.3 | Benchmark suite | `tests/benchmarks/benchmark_authorization.py` -- continuous performance measurement |

---

## MANAGE Function

The Manage function applies treatments to identified risks.

### MG-1: AI risks are treated

| Sub-category | Project Feature | Evidence |
|--------------|----------------|----------|
| MG-1.1 | Inline enforcement | `src/enforcement.py` -- block denied requests before execution |
| MG-1.2 | Step-up authentication | STEP_UP decision triggers human approval workflow |
| MG-1.3 | Automated remediation | `src/remediate.py` -- automated permission revocation and quarantine |
| MG-1.4 | Least privilege enforcement | `src/least_privilege.py` -- recommends minimum required permissions |

### MG-2: Residual risks are managed

| Sub-category | Project Feature | Evidence |
|--------------|----------------|----------|
| MG-2.1 | AUDIT mode | Non-blocking mode logs decisions without enforcement for gradual rollout |
| MG-2.2 | Fail-open/fail-closed config | `AGENT_GUARD_FAIL_OPEN` controls behavior when engine fails |
| MG-2.3 | Risk acceptance documentation | REVIEW effect creates explicit record of accepted risk |

### MG-3: Risks are communicated

| Sub-category | Project Feature | Evidence |
|--------------|----------------|----------|
| MG-3.1 | Structured decision reasons | `AuthorizeResponse.reasons` provides human-readable explanations |
| MG-3.2 | Alert integration | Webhook support for Slack, PagerDuty, SNS |
| MG-3.3 | Dashboard visualization | `dashboard/index.html` -- real-time risk overview |
| MG-3.4 | Attack path reporting | `GET /v1/agents/{id}/attack-paths` provides remediation guidance |

### MG-4: Risks are regularly reviewed

| Sub-category | Project Feature | Evidence |
|--------------|----------------|----------|
| MG-4.1 | Policy review metadata | `metadata.last_reviewed` field in policy files |
| MG-4.2 | Capability inventory audits | `src/capability_inventory.py` -- tracks declared vs actual capabilities |
| MG-4.3 | Intent alignment checks | `src/intent_alignment.py` -- verifies actions match stated purpose |
