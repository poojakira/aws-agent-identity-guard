# NIST AI Risk Management Framework (AI RMF) Mapping

## Overview

This document maps AWS Agent Identity Guard capabilities to the [NIST AI Risk Management Framework](https://www.nist.gov/artificial-intelligence/ai-risk-management-framework) (AI RMF 1.0, January 2023). The AI RMF provides organizations with a framework for managing risks from AI systems across their lifecycle.

Agent Identity Guard specifically addresses risks arising from AI agents operating with AWS IAM permissions  -  focusing on the **security, accountability, and controllability** dimensions of trustworthy AI.

---

## AI RMF Core Functions

### GOVERN  -  Establishing AI Risk Management Culture

| Subcategory | AI RMF Requirement | Guard Capability | Coverage |
|-------------|-------------------|-----------------|----------|
| GOVERN 1.1 | Legal and regulatory requirements are identified | Compliance mapping documentation (this doc, NIST 800-53, OWASP) | ◐ |
| GOVERN 1.2 | Trustworthy AI characteristics are integrated into policies | Policy-as-code defines security expectations for AI agents declaratively | ● |
| GOVERN 1.4 | Ongoing monitoring mechanisms are in place | Runtime behavior analysis, drift detection, metrics dashboards | ● |
| GOVERN 1.5 | Risk management processes include AI risks | Multi-dimensional risk scoring engine with configurable profiles | ● |
| GOVERN 2.1 | Roles and responsibilities are defined | Approval workflows define who can authorize what; role-based policies | ◐ |
| GOVERN 2.2 | AI risk management is resourced | Automated scanning in CI reduces manual review burden | ◐ |
| GOVERN 4.1 | Organizational practices are reviewed | Policy versioning and testing enable regular policy review cycles | ◐ |
| GOVERN 4.2 | Feedback mechanisms are in place | Audit trail enables post-incident review; behavior reports for analysis | ● |

### MAP  -  Contextualizing AI Risks

| Subcategory | AI RMF Requirement | Guard Capability | Coverage |
|-------------|-------------------|-----------------|----------|
| MAP 1.1 | AI system purpose is defined | Intent alignment engine requires agent manifests declaring purpose and capabilities | ● |
| MAP 1.3 | Potential benefits and costs are assessed | Risk scoring provides quantitative assessment of agent risk | ◐ |
| MAP 1.5 | AI system interactions with other systems are identified | Capability graph maps all services, resources, and roles an agent can access | ● |
| MAP 2.1 | Scientific integrity is maintained | Deterministic rule-based analysis; reproducible benchmark corpus | ◐ |
| MAP 2.3 | AI system risks are identified | Attack path analysis discovers concrete exploitation chains | ● |
| MAP 3.1 | AI risks are prioritized | Multi-dimensional risk scoring with configurable thresholds and profiles | ● |
| MAP 3.4 | Impacts from AI risks are assessed | Blast radius analysis quantifies potential damage; severity classification | ● |
| MAP 5.1 | AI actors throughout lifecycle are identified | Agent registry with lifecycle tracking (ACTIVE → DECOMMISSIONED) | ● |

### MEASURE  -  Analyzing and Assessing AI Risks

| Subcategory | AI RMF Requirement | Guard Capability | Coverage |
|-------------|-------------------|-----------------|----------|
| MEASURE 1.1 | Appropriate methods for measuring AI risks are identified | Precision/recall benchmarks for detection; risk score accuracy metrics | ● |
| MEASURE 1.3 | Risks are measured with quantitative/qualitative methods | Risk engine produces numeric scores (0-100) with qualitative explanations | ● |
| MEASURE 2.1 | AI system is tested before deployment | Static scanner runs in CI before production deployment | ● |
| MEASURE 2.2 | AI system is monitored in production | Runtime authorization, behavior analysis, drift detection | ● |
| MEASURE 2.3 | AI system performance is monitored | Prometheus metrics for latency, throughput, decision rates | ● |
| MEASURE 2.5 | AI system is regularly evaluated | Benchmark corpus enables regression testing; historical results tracked | ● |
| MEASURE 2.6 | Measurement results are documented | Structured audit trail; benchmark documentation; compliance evidence | ● |
| MEASURE 2.9 | AI system performance is compared over time | Historical benchmark results track detection accuracy evolution | ● |
| MEASURE 3.2 | Risk metrics are collected and reported | Risk scores, finding counts, denial rates, anomaly counts aggregated | ● |
| MEASURE 4.1 | Measurement approaches address identified risks | Per-category detection rates (precision/recall) for each threat type | ● |

### MANAGE  -  Prioritizing and Acting on AI Risks

| Subcategory | AI RMF Requirement | Guard Capability | Coverage |
|-------------|-------------------|-----------------|----------|
| MANAGE 1.1 | Treatment plans are defined for AI risks | Remediation engine generates specific policy fixes; least-privilege recommendations | ● |
| MANAGE 1.2 | Treatment actions are prioritized | Risk scores enable prioritization; severity classification (CRITICAL→LOW) | ● |
| MANAGE 1.3 | Risks are responded to based on impact | Configurable enforcement: deny (high risk), approve (medium), warn (low) | ● |
| MANAGE 2.1 | Mechanisms exist to reduce or manage risks | Policy engine, approval workflows, enforcement modes, circuit breakers | ● |
| MANAGE 2.2 | Risk treatments are implemented | CI gate blocks risky deployments; runtime authorization blocks risky actions | ● |
| MANAGE 2.3 | Risk mitigation effectiveness is monitored | Detection accuracy benchmarks; false positive/negative tracking | ● |
| MANAGE 2.4 | Processes exist for decommissioning AI systems | Agent status lifecycle (SUSPENDED, DECOMMISSIONED); immediate access revocation | ● |
| MANAGE 3.1 | AI risks and benefits are communicated | Structured findings with explanations; dashboard visualizations | ● |
| MANAGE 3.2 | Risk documentation is maintained | Audit trail, policy versions, benchmark history, compliance mappings | ● |
| MANAGE 4.1 | Incident response plans include AI risks | Behavior anomaly alerts; denial event notifications; runbook documentation | ● |
| MANAGE 4.2 | Incident response is tested | Policy testing framework; benchmark corpus for validation | ◐ |

---

## Trustworthy AI Characteristics Coverage

The AI RMF identifies seven characteristics of trustworthy AI. Guard's coverage:

| Characteristic | Relevance to Guard | Guard Coverage | Notes |
|---------------|-------------------|---------------|-------|
| **Valid and Reliable** | Agent actions produce expected outcomes | ◐ | Intent alignment verifies agent acts within declared purpose |
| **Safe** | Agents don't cause harm | ● | Authorization prevents dangerous actions; deny rules block destructive operations |
| **Secure and Resilient** | Agents resist attack | ● | Primary focus: attack path analysis, privilege escalation prevention, drift detection |
| **Accountable** | Agent actions are traceable | ● | Tamper-evident audit trail; approval workflows with identity binding |
| **Transparent** | Decisions are explainable | ● | Authorization decisions include explanation, matched rules, and risk breakdown |
| **Explainable** | System behavior is understandable | ● | Policy-as-code is human-readable; SARIF findings include remediation guidance |
| **Privacy-Enhanced** | Data is protected | ◐ | Data classification enforcement; scoped resource access |
| **Fair** | Equitable treatment | ○ | Not directly applicable (access control, not ML inference fairness) |

---

## AI RMF Profile: Autonomous AI Agents on AWS

This section defines an AI RMF profile specific to autonomous AI agents operating with IAM permissions.

### High-Priority Risks

| Risk | AI RMF Category | Guard Mitigation |
|------|-----------------|-----------------|
| Agent performs unauthorized destructive action | Safety | Deny rules + approval workflows |
| Agent escalates its own privileges | Security | Scanner + attack path + runtime deny |
| Agent accesses data above its clearance | Privacy | Data classification policies |
| Agent covers its tracks | Accountability | Audit tampering prevention + immutable logs |
| Agent operates outside intended scope | Validity | Intent alignment + behavior analysis |
| Agent is exploited via prompt injection | Security | Runtime auth evaluates actions, not intent |
| Agent permissions drift over time | Reliability | Drift detector + baseline comparison |
| Agent creates resource exhaustion | Safety | Rate limiting + resource scoping |

### Implementation Priorities

| Priority | Action | AI RMF Mapping |
|----------|--------|---------------|
| 1 (Critical) | Deploy static scanner in CI pipeline | MEASURE 2.1, MANAGE 2.2 |
| 2 (Critical) | Enable runtime authorization for production agents | MANAGE 2.1, GOVERN 1.4 |
| 3 (High) | Define agent manifests for all agents | MAP 1.1, MAP 5.1 |
| 4 (High) | Configure deny policies for destructive actions | MANAGE 1.3, MANAGE 2.1 |
| 5 (Medium) | Enable drift detection | MEASURE 2.2, GOVERN 1.4 |
| 6 (Medium) | Implement approval workflows for sensitive ops | GOVERN 2.1, MANAGE 2.1 |
| 7 (Low) | Tune risk score thresholds per environment | MEASURE 1.3, MAP 3.1 |

---

## Summary Coverage

| AI RMF Function | Subcategories Covered | Direct (●) | Partial (◐) | Not Applicable (○) |
|-----------------|----------------------|-----------|-------------|-------------------|
| GOVERN | 8 | 4 | 4 | 0 |
| MAP | 8 | 6 | 2 | 0 |
| MEASURE | 10 | 10 | 0 | 0 |
| MANAGE | 11 | 10 | 1 | 0 |
| **Total** | **37** | **30** | **7** | **0** |
