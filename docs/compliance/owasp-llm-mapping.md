# OWASP LLM Top 10 Mapping

## Overview

This document maps AWS Agent Identity Guard capabilities to the [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) (2025 edition). While Agent Identity Guard focuses on IAM-level controls rather than application-layer LLM security, several OWASP LLM risks are directly mitigated or partially addressed by infrastructure-level authorization and policy enforcement.

---

## Mapping

### LLM01: Prompt Injection

**Risk:** Attacker manipulates LLM via crafted inputs to execute unintended actions.

| Aspect | Guard Coverage | Details |
|--------|---------------|---------|
| Prevention | ○ Not covered | Guard does not inspect or filter prompts |
| Impact Mitigation | ● **Strong** | Runtime authorization evaluates every agent action regardless of how the LLM decided to take it. Even if prompt injection succeeds at the reasoning level, the authorization layer blocks unauthorized AWS API calls |
| Detection | ● **Strong** | Behavior analyzer detects when an agent suddenly performs actions outside its learned baseline — a strong signal of prompt injection |

**Guard-Specific Mitigation:**
- Policy engine denies actions not in agent's allowed set
- Behavior analyzer alerts on unexpected tool/service usage
- Deny rules prevent high-impact actions (audit tampering, privilege escalation) regardless of agent reasoning
- Approval workflow forces human review for sensitive operations

---

### LLM02: Insecure Output Handling

**Risk:** LLM output passed to downstream systems without validation.

| Aspect | Guard Coverage | Details |
|--------|---------------|---------|
| Prevention | ◐ Partial | When LLM output becomes an AWS API call (agent action), Guard validates the action against policies before execution |
| Detection | ◐ Partial | Unusual patterns in agent actions may indicate malicious output being executed |

**Guard-Specific Mitigation:**
- SDK middleware intercepts boto3 calls generated from LLM output
- Resource scoping prevents access to unintended targets
- Data classification prevents access to sensitive resources

---

### LLM03: Training Data Poisoning

**Risk:** Manipulation of training data to introduce vulnerabilities.

| Aspect | Guard Coverage | Details |
|--------|---------------|---------|
| Prevention | ◐ Partial | Policy engine can restrict write access to training data buckets/tables |
| Detection | ○ Not covered | Guard does not inspect training data content |

**Guard-Specific Mitigation:**
- Approval workflow for `sagemaker:CreateTrainingJob` modifications
- Resource scoping limits which S3 buckets agents can write to
- Audit trail records all data access for forensic analysis

---

### LLM04: Model Denial of Service

**Risk:** Resource exhaustion attacks against LLM inference endpoints.

| Aspect | Guard Coverage | Details |
|--------|---------------|---------|
| Prevention | ◐ Partial | Rate limiting on authorization API; resource-scoped policies limit which endpoints agents can invoke |
| Detection | ● Strong | Volume anomaly detection in behavior analyzer flags unusual call frequency |

**Guard-Specific Mitigation:**
- Token bucket rate limiting per client
- Behavior analyzer detects volume anomalies (>3 std deviations from baseline)
- Policy can restrict `bedrock:InvokeModel` to specific models/throughput

---

### LLM05: Supply Chain Vulnerabilities

**Risk:** Dependencies, pre-trained models, or third-party components introduce risk.

| Aspect | Guard Coverage | Details |
|--------|---------------|---------|
| Prevention | ● Strong (for Guard itself) | Zero runtime dependencies eliminates dependency-based supply chain risk for the security control |
| Detection | ◐ Partial | Dependabot alerts for dev dependencies |

**Guard-Specific Mitigation:**
- Core scanner: zero external dependencies (pure Python stdlib)
- SDK: minimal dependencies (httpx only), pinned versions
- Container images scanned for CVEs
- Signed releases with checksums

---

### LLM06: Sensitive Information Disclosure

**Risk:** LLM reveals sensitive data in responses or through data access.

| Aspect | Guard Coverage | Details |
|--------|---------------|---------|
| Prevention | ● Strong | Data classification-aware authorization prevents agents from accessing data above their clearance level |
| Detection | ● Strong | Audit trail records all data access; anomaly detection flags unexpected data access patterns |

**Guard-Specific Mitigation:**
- Five-level data classification: PUBLIC → INTERNAL → CONFIDENTIAL → SECRET → REGULATED
- Policies can deny agent access to resources with higher classification
- Scanner flags `secretsmanager:GetSecretValue` on wildcard resources
- Audit rule type ensures all secret/sensitive data access is recorded
- VPC conditions prevent data leaving approved network boundaries

---

### LLM07: Insecure Plugin/Tool Design

**Risk:** LLM plugins or tools operate with excessive permissions or lack access controls.

| Aspect | Guard Coverage | Details |
|--------|---------------|---------|
| Prevention | ● **Strong** | This is Guard's primary use case — ensuring AI agent tools (AWS API calls) operate with least privilege |
| Detection | ● **Strong** | Intent alignment detects tools operating outside declared capabilities |

**Guard-Specific Mitigation:**
- Static scanner catches over-permissioned agent roles before deployment
- Least-privilege engine generates minimum-necessary policies
- Intent alignment compares granted permissions against declared tool capabilities
- Capability inventory enumerates exactly what an agent's tools can access
- Attack path analysis shows how tool permissions chain into escalation paths
- Runtime authorization blocks tool execution outside approved scope

---

### LLM08: Excessive Agency

**Risk:** LLM-based agents are granted too much autonomy or permissions to act.

| Aspect | Guard Coverage | Details |
|--------|---------------|---------|
| Prevention | ● **Strong** | Direct and primary mitigation target |
| Detection | ● **Strong** | Multi-layered detection of excessive agency |

**Guard-Specific Mitigation:**
- **CI Gate**: Scanner blocks deployment of over-permissioned agent roles
- **Intent Alignment**: Flags permissions not declared in agent manifest (OVER_PRIVILEGE finding)
- **Least Privilege Engine**: Generates minimum-permission policies tailored to agent's actual needs
- **Approval Workflow**: Forces human decision for high-impact actions
- **Behavior Baseline**: Alerts when agent exercises permissions outside historical norm
- **Risk Scoring**: Quantifies how much agency an agent has (blast radius, privilege level)
- **Enforcement Modes**: Gradually restrict agency (monitor → dry_run → enforce)
- **Data Classification**: Prevents agency from extending to sensitive data without clearance
- **Time Windows**: Restrict agency to approved operational hours

---

### LLM09: Overreliance

**Risk:** Excessive dependence on LLM output without verification.

| Aspect | Guard Coverage | Details |
|--------|---------------|---------|
| Prevention | ● Strong | Every agent decision to act is independently verified by authorization service — not reliant on LLM's self-assessment |
| Detection | ◐ Partial | Anomaly detection identifies when LLM actions diverge from expected patterns |

**Guard-Specific Mitigation:**
- Authorization is independent of agent's reasoning — provides external verification
- Step-up approval creates human verification checkpoint
- Multi-dimensional risk scoring provides independent risk assessment
- Behavior analysis detects when agent's actions don't match expected patterns

---

### LLM10: Model Theft

**Risk:** Unauthorized copying or extraction of proprietary model weights.

| Aspect | Guard Coverage | Details |
|--------|---------------|---------|
| Prevention | ● Strong | IAM-level controls restrict access to model artifacts |
| Detection | ● Strong | Audit trail and anomaly detection for model access |

**Guard-Specific Mitigation:**
- Scanner flags `s3:GetObject` on wildcard (could access model weight buckets)
- Data classification: model weights marked SECRET/REGULATED
- Policy engine restricts `sagemaker:DescribeModel` and `bedrock:GetFoundationModel`
- Audit trail records all model artifact access
- Behavior analyzer detects unusual volume of model-related API calls (extraction attempt)
- VPC conditions prevent model data from leaving approved networks

---

## Coverage Summary

| OWASP LLM Risk | Prevention | Detection | Overall | Primary Guard Component |
|----------------|-----------|-----------|---------|------------------------|
| LLM01: Prompt Injection | ○ | ● | ◐ | Authorization + Behavior Analyzer |
| LLM02: Insecure Output | ◐ | ◐ | ◐ | SDK Middleware + Policy Engine |
| LLM03: Training Data Poisoning | ◐ | ○ | ◐ | Policy Engine + Approval |
| LLM04: Model DoS | ◐ | ● | ◐ | Rate Limiting + Behavior Analyzer |
| LLM05: Supply Chain | ● | ◐ | ● | Zero Dependencies + Signing |
| LLM06: Sensitive Info Disclosure | ● | ● | ● | Data Classification + Audit |
| LLM07: Insecure Plugin/Tool Design | ● | ● | ● | Scanner + Intent Alignment |
| LLM08: Excessive Agency | ● | ● | ● | Scanner + Policy + Least Privilege |
| LLM09: Overreliance | ● | ◐ | ● | Independent Authorization |
| LLM10: Model Theft | ● | ● | ● | Policy + Data Classification |

### Legend
- ● Strong coverage
- ◐ Partial coverage
- ○ Not directly covered / out of scope

---

## Key Insight

Agent Identity Guard provides the strongest coverage for **LLM07 (Insecure Plugin/Tool Design)** and **LLM08 (Excessive Agency)** — these are the OWASP risks most directly addressable at the IAM/infrastructure layer. For application-layer risks like prompt injection (LLM01) and training data poisoning (LLM03), Guard provides **impact mitigation** rather than root-cause prevention. The defense-in-depth principle ensures that even if an application-layer attack succeeds, the infrastructure-layer controls limit the damage.

---

## Complementary Controls

For risks where Guard provides partial or no coverage, complement with:

| Gap | Recommended Control | Integration Point |
|-----|--------------------|--------------------|
| Prompt injection prevention | Input validation/sanitization layer | Application layer, before agent execution |
| Training data integrity | Data pipeline validation, provenance tracking | ML pipeline, pre-training |
| Output validation | Response filtering, content safety classifiers | Application layer, post-LLM |
| Model robustness | Adversarial testing, red teaming | ML development lifecycle |
| Inference DoS | AWS WAF, API Gateway throttling | Network edge |
