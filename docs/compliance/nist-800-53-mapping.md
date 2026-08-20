# NIST SP 800-53 Control Mapping

This document maps AWS Agent Identity Guard capabilities to relevant NIST SP 800-53 Rev. 5 security controls. Each entry references specific project features and code that implement the control.

---

## AC - Access Control Family

### AC-1: Policy and Procedures

| Control | Implementation | Evidence |
|---------|---------------|----------|
| AC-1a | Policy-as-code engine with declarative YAML policies | `src/policy_engine.py`, `docs/policy-language.md` |
| AC-1b | Policy versioning via git, metadata includes owner and review date | Policy file `metadata.last_reviewed` field |

### AC-2: Account Management

| Control | Implementation | Evidence |
|---------|---------------|----------|
| AC-2a | Agent registry with full identity lifecycle | `POST /v1/agents`, `DELETE /v1/agents/{id}` |
| AC-2d | Agent deregistration revokes all permissions | `DELETE` handler in `src/api.py` |
| AC-2f | Agent metadata includes owner, purpose, environment | `AgentIdentity` model in `src/models.py` |
| AC-2g | Capability inventory tracks declared permissions | `src/capability_inventory.py` |

### AC-3: Access Enforcement

| Control | Implementation | Evidence |
|---------|---------------|----------|
| AC-3 | Runtime authorization on every agent action | `POST /v1/authorize` in `src/api.py` |
| AC-3(8) | Default-deny posture; explicit ALLOW required | `AGENT_GUARD_DEFAULT_EFFECT=DENY` |

### AC-4: Information Flow Enforcement

| Control | Implementation | Evidence |
|---------|---------------|----------|
| AC-4 | Data classification-aware decisions | `DataClassification` enum; policy conditions on classification |
| AC-4(4) | Cross-account access requires step-up | Policies with `resource_pattern` matching cross-account ARNs |

### AC-5: Separation of Duties

| Control | Implementation | Evidence |
|---------|---------------|----------|
| AC-5 | Agent type and environment restrictions | Policies scope by `agent_type` and `environment` |
| AC-5(1) | No agent can self-approve | Approval requires different identity than requester |

### AC-6: Least Privilege

| Control | Implementation | Evidence |
|---------|---------------|----------|
| AC-6 | Least privilege engine | `src/least_privilege.py` -- computes minimum permissions |
| AC-6(1) | Explicit authorization for each action | Per-action policy evaluation |
| AC-6(5) | Privileged actions require approval | STEP_UP effect on sensitive operations |
| AC-6(9) | Audit of privileged function use | All decisions logged with correlation IDs |
| AC-6(10) | Capability boundaries prevent lateral movement | `src/capability_inventory.py` enforcement |

### AC-17: Remote Access

| Control | Implementation | Evidence |
|---------|---------------|----------|
| AC-17(1) | mTLS for API communication | TLS configuration in deployment guide |
| AC-17(2) | API key authentication with scoping | `X-API-Key` header validation in `src/api.py` |

### AC-24: Access Control Decisions

| Control | Implementation | Evidence |
|---------|---------------|----------|
| AC-24 | Real-time authorization decisions with full context | Authorization engine considers identity, action, resource, risk, behavior |
| AC-24(1) | Decision includes explanation and policy reference | `AuthorizeResponse` includes `reasons`, `policy`, `explanation` |

---

## AU - Audit and Accountability Family

### AU-2: Event Logging

| Control | Implementation | Evidence |
|---------|---------------|----------|
| AU-2a | All authorization decisions are logged | `src/observability.py` structured logging |
| AU-2b | Decision logs include: agent_id, action, resource, decision, risk_score, timestamp | JSON log schema |

### AU-3: Content of Audit Records

| Control | Implementation | Evidence |
|---------|---------------|----------|
| AU-3 | Logs include who, what, when, where, outcome | Correlation ID, agent_id, action, resource, timestamp, decision |
| AU-3(1) | Additional context: risk score, policy matched, reasons | Full `AuthorizeResponse` serialized to audit |

### AU-6: Audit Record Review, Analysis, and Reporting

| Control | Implementation | Evidence |
|---------|---------------|----------|
| AU-6 | Dashboard for security review | `dashboard/index.html` |
| AU-6(1) | Prometheus metrics enable automated analysis | `/metrics` endpoint, Grafana integration |
| AU-6(3) | Correlation IDs enable cross-system tracing | `X-Correlation-ID` propagation |

### AU-8: Time Stamps

| Control | Implementation | Evidence |
|---------|---------------|----------|
| AU-8 | UTC timestamps on all events | `datetime.now(timezone.utc)` in `src/models.py` |

### AU-12: Audit Record Generation

| Control | Implementation | Evidence |
|---------|---------------|----------|
| AU-12a | System generates audit records for all authorization events | `src/observability.py` logs every decision |
| AU-12b | Audit records cannot be disabled by agents | Logging is server-side, not agent-controlled |
| AU-12(1) | Structured JSON format for machine parsing | JSON log format with consistent schema |

---

## IA - Identification and Authentication Family

### IA-2: Identification and Authentication

| Control | Implementation | Evidence |
|---------|---------------|----------|
| IA-2 | Agent identity resolution on every request | `AgentRegistry` lookup by `agent_id` in `src/authorization.py` |
| IA-2(1) | API key authentication for SDK clients | `X-API-Key` validation |
| IA-2(6) | mTLS for mutual authentication | TLS certificate validation |

### IA-3: Device Identification and Authentication

| Control | Implementation | Evidence |
|---------|---------------|----------|
| IA-3 | Agent identity bound to IAM role | `AgentIdentity.iam_role_arn` binding in `src/models.py` |

### IA-4: Identifier Management

| Control | Implementation | Evidence |
|---------|---------------|----------|
| IA-4a | Unique agent_id assigned at registration | UUID generation in `POST /v1/agents` |
| IA-4d | Agent deregistration available | `DELETE /v1/agents/{id}` |
| IA-4e | Agent metadata prevents reuse confusion | Created/updated timestamps, owner field |

### IA-5: Authenticator Management

| Control | Implementation | Evidence |
|---------|---------------|----------|
| IA-5(1) | API keys rotatable via configuration | `AGENT_GUARD_API_KEYS` environment variable |
| IA-5(2) | TLS certificates with expiration | Certificate management in deployment guide |

### IA-8: Identification and Authentication (Non-Organizational)

| Control | Implementation | Evidence |
|---------|---------------|----------|
| IA-8 | Cross-account agent identification | `principal` field in authorization requests maps to external IAM roles |

---

## SI - System and Information Integrity Family

### SI-3: Malicious Code Protection

| Control | Implementation | Evidence |
|---------|---------------|----------|
| SI-3 | Attack path detection blocks escalation chains | `src/attack_paths.py` |
| SI-3(7) | Non-signature-based detection (behavioral) | `src/behavior_analyzer.py` anomaly detection |

### SI-4: System Monitoring

| Control | Implementation | Evidence |
|---------|---------------|----------|
| SI-4 | Continuous monitoring of agent actions | Every action evaluated by authorization engine |
| SI-4(2) | Real-time alerting on violations | Webhook integration for DENY/STEP_UP events |
| SI-4(4) | Inbound/outbound action monitoring | Both request authorization and drift detection |
| SI-4(5) | Alert on escalation patterns | `src/escalation_engine.py` pattern matching |

### SI-5: Security Alerts and Advisories

| Control | Implementation | Evidence |
|---------|---------------|----------|
| SI-5 | Attack path advisories with mitigations | `AttackPathInfo.mitigations` list |
| SI-5(1) | Risk score recommendations | `RiskScoreInfo.recommendation` field |

### SI-6: Security and Privacy Function Verification

| Control | Implementation | Evidence |
|---------|---------------|----------|
| SI-6 | Health check verifies all components | `GET /health` checks policy_store, risk_engine, agent_registry |
| SI-6(2) | Automated test suite | `tests/` with 94% coverage |

### SI-7: Software, Firmware, and Information Integrity

| Control | Implementation | Evidence |
|---------|---------------|----------|
| SI-7 | Intent alignment verification | `src/intent_alignment.py` -- actions checked against declared purpose |
| SI-7(1) | Drift detection for permission changes | `src/drift_detector.py` alerts on unauthorized changes |

---

## CM - Configuration Management Family

### CM-2: Baseline Configuration

| Control | Implementation | Evidence |
|---------|---------------|----------|
| CM-2 | Policy files define security baseline | `policies/` directory, git-versioned |
| CM-2(1) | Behavior baselines per agent | `src/behavior_analyzer.py` maintains rolling baseline |

### CM-3: Configuration Change Control

| Control | Implementation | Evidence |
|---------|---------------|----------|
| CM-3 | Policy changes tracked via git | Immutable audit of policy modifications |
| CM-3(2) | Policy validation before deployment | `agent-identity-guard policy validate` CLI command |
| CM-3(5) | Hot-reload without service restart | PolicyEngine watches file changes |

### CM-5: Access Restrictions for Change

| Control | Implementation | Evidence |
|---------|---------------|----------|
| CM-5 | Admin API key scope required for policy changes | API key scoping (read-only vs admin) |
| CM-5(1) | Separation between policy authors and enforcer | Policy files separate from runtime code |

### CM-6: Configuration Settings

| Control | Implementation | Evidence |
|---------|---------------|----------|
| CM-6 | All settings documented with defaults | Environment variable reference in deployment guide |
| CM-6(1) | Centralized configuration | Single `.env` or environment variables |

### CM-7: Least Functionality

| Control | Implementation | Evidence |
|---------|---------------|----------|
| CM-7 | Minimal Docker image (no shell, non-root) | Multi-stage Dockerfile |
| CM-7(1) | Capability boundaries restrict agent functions | `src/capability_inventory.py` |

### CM-8: System Component Inventory

| Control | Implementation | Evidence |
|---------|---------------|----------|
| CM-8 | Agent inventory with full metadata | `GET /v1/agents` lists all registered agents |
| CM-8(1) | Agent capability tracking | `declared_capabilities` field, capability inventory module |
| CM-8(3) | Unauthorized agent detection | Unregistered agent_id returns 404/DENY |
