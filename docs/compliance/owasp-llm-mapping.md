# OWASP LLM Top 10 Mapping

This document maps the OWASP Top 10 for LLM Applications to AWS Agent Identity Guard controls. Each item includes the project features that detect, prevent, or mitigate the vulnerability.

Reference: OWASP Top 10 for LLM Applications (2025)

---

## LLM01: Prompt Injection

| Aspect | Detail |
|--------|--------|
| Risk | Attacker manipulates LLM via crafted inputs to perform unauthorized actions |
| Detection | Authorization API is structurally separate from LLM reasoning; all actions independently verified |
| Prevention | Every agent action requires explicit authorization regardless of prompt content |
| Controls | `POST /v1/authorize` validates structured JSON only; no natural language parsing in decision path |
| Evidence | `src/api.py` Pydantic validation; `src/authorization.py` independent evaluation |

**Key point**: Even if an agent is prompt-injected, the authorization layer independently verifies every action. The agent cannot bypass authorization because the enforcement is external.

---

## LLM02: Insecure Output Handling

| Aspect | Detail |
|--------|--------|
| Risk | LLM output triggers unintended downstream actions |
| Detection | Intent alignment verifies actions match declared purpose |
| Prevention | Capability boundaries restrict what actions an agent can take, regardless of its outputs |
| Controls | Capability inventory enforcement; resource pattern restrictions in policies |
| Evidence | `src/intent_alignment.py`; `src/capability_inventory.py` |

---

## LLM03: Training Data Poisoning

| Aspect | Detail |
|--------|--------|
| Risk | Compromised training data causes agent to behave maliciously |
| Detection | Behavior analyzer detects deviation from established baselines |
| Prevention | Authorization decisions are deterministic (policy-based), not ML-based |
| Controls | Behavioral anomaly scoring; drift detection on permission patterns |
| Evidence | `src/behavior_analyzer.py`; `src/drift_detector.py` |

**Key point**: This system does not use ML for access control decisions. Policies are deterministic YAML rules evaluated at runtime.

---

## LLM04: Model Denial of Service

| Aspect | Detail |
|--------|--------|
| Risk | Resource exhaustion attacks against the agent or authorization service |
| Detection | Rate limiting; latency monitoring; health checks |
| Prevention | Per-client rate limits; HPA auto-scaling; circuit breaker |
| Controls | Rate limiting in API; Kubernetes HPA; configurable timeout |
| Evidence | `src/api.py` rate limiting; Helm chart `autoscaling`; `src/authorization.py` timeout |

---

## LLM05: Supply Chain Vulnerabilities

| Aspect | Detail |
|--------|--------|
| Risk | Compromised dependencies or model components |
| Detection | Capability inventory detects unexpected capability expansion |
| Prevention | Pinned dependencies; Dependabot automated updates; minimal Docker image |
| Controls | `requirements.txt` with pinned versions; `.github/dependabot.yml`; multi-stage Dockerfile |
| Evidence | `requirements.txt`; `.github/dependabot.yml`; `Dockerfile` |

---

## LLM06: Sensitive Information Disclosure

| Aspect | Detail |
|--------|--------|
| Risk | Agent exposes confidential data through outputs |
| Detection | Data classification-aware authorization; access to sensitive data requires elevated approval |
| Prevention | DENY/STEP_UP policies on CONFIDENTIAL/SECRET/REGULATED data access |
| Controls | `DataClassification` enum; policy conditions; data dimension in risk scoring |
| Evidence | `src/models.py` classification; `src/risk_engine.py` data_score; policy `data_classification` condition |

---

## LLM07: Insecure Plugin Design

| Aspect | Detail |
|--------|--------|
| Risk | Agent plugins/tools have excessive permissions |
| Detection | Per-tool authorization; capability inventory tracks which tools are permitted |
| Prevention | Each tool invocation requires independent authorization with specific resource constraints |
| Controls | `tool` field in authorization request; capability declarations at registration |
| Evidence | `AuthorizeRequest.tool` field in `src/api.py`; `declared_capabilities` in registration |

---

## LLM08: Excessive Agency

| Aspect | Detail |
|--------|--------|
| Risk | Agent performs actions beyond its intended scope |
| Detection | Intent alignment checks; capability boundary enforcement; behavioral anomaly detection |
| Prevention | Least privilege enforcement; capability boundaries; default-deny posture |
| Controls | `src/intent_alignment.py`; `src/least_privilege.py`; `src/capability_inventory.py` |
| Evidence | Purpose declaration at registration; action-to-purpose verification at runtime |

**Key point**: This is the primary threat this platform addresses. Every action is verified against:
1. Declared capabilities (what the agent is allowed to do)
2. Active policies (what the environment permits)
3. Intent alignment (whether the action matches the agent's purpose)
4. Risk scoring (whether the action's risk is acceptable)

---

## LLM09: Overreliance

| Aspect | Detail |
|--------|--------|
| Risk | Humans overtrust agent outputs and approve without scrutiny |
| Detection | Approval audit trail tracks approval patterns; bulk approvals flagged |
| Prevention | Time-bounded approvals (TTL); approval context includes risk details |
| Controls | TTL expiration on approvals; risk score visible to reviewer; delegation chains |
| Evidence | `src/approval.py` TTL; `AuthorizeResponse` risk details provided to approver |

---

## LLM10: Model Theft

| Aspect | Detail |
|--------|--------|
| Risk | Adversary exfiltrates agent model or configuration |
| Detection | Resource pattern matching on access to model artifacts; volume anomaly detection |
| Prevention | Policies restrict access to model storage; cross-account transfer requires STEP_UP |
| Controls | Resource-level policies on S3/SageMaker model artifacts; data classification |
| Evidence | Policy `resource_pattern` conditions; `src/risk_engine.py` network_score for external access |

---

## Summary Matrix

| OWASP Item | Primary Control | Secondary Controls |
|------------|-----------------|-------------------|
| LLM01: Prompt Injection | External authorization gate | Structured API, no NLP in decisions |
| LLM02: Insecure Output | Capability boundaries | Intent alignment, resource restrictions |
| LLM03: Data Poisoning | Deterministic policies | Behavior baselines, drift detection |
| LLM04: Model DoS | Rate limiting, HPA | Circuit breaker, timeout |
| LLM05: Supply Chain | Pinned deps, Dependabot | Minimal image, capability detection |
| LLM06: Info Disclosure | Data classification | STEP_UP on sensitive access |
| LLM07: Insecure Plugins | Per-tool authorization | Capability inventory |
| LLM08: Excessive Agency | Least privilege + intent alignment | Policy engine, risk scoring |
| LLM09: Overreliance | TTL approvals, risk context | Audit trail, delegation |
| LLM10: Model Theft | Resource restrictions | Volume detection, cross-account control |
