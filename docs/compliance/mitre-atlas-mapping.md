# MITRE ATLAS Mapping

This document maps MITRE ATLAS (Adversarial Threat Landscape for AI Systems) techniques to AWS Agent Identity Guard detection and mitigation capabilities.

Reference: https://atlas.mitre.org/

---

## Technique Mappings

### AML.T0000 - ML Model Access

| Aspect | Detail |
|--------|--------|
| Description | Adversary gains access to the ML model or agent |
| Detection | Agent registry validates identity on every request; unregistered agents receive DENY |
| Mitigation | IAM role binding (`iam_role_arn`); API key authentication; mTLS |
| Evidence | `src/authorization.py` -- AgentRegistry lookup; `src/api.py` -- API key validation |

### AML.T0001 - ML Supply Chain Compromise

| Aspect | Detail |
|--------|--------|
| Description | Compromise of model training pipeline or dependencies |
| Detection | Capability inventory detects unexpected capability expansion |
| Mitigation | Declared capabilities at registration; expansion requires approval |
| Evidence | `src/capability_inventory.py` -- capability boundary enforcement |

### AML.T0003 - Data Poisoning / Data Manipulation

| Aspect | Detail |
|--------|--------|
| Description | Adversary manipulates data accessed by the agent |
| Detection | Data classification-aware authorization; anomalous data access patterns flagged |
| Mitigation | DENY/STEP_UP on access to higher classification levels than declared |
| Evidence | `DataClassification` enum in `src/models.py`; policy conditions on classification |

### AML.T0004 - ML Model Inference API Access

| Aspect | Detail |
|--------|--------|
| Description | Unauthorized queries to agent inference endpoints |
| Detection | All agent actions gated by authorization; rate limiting prevents enumeration |
| Mitigation | API key scoping; risk scoring on excessive query patterns |
| Evidence | `src/api.py` rate limiting; `src/behavior_analyzer.py` frequency analysis |

### AML.T0005 - Functional Extraction

| Aspect | Detail |
|--------|--------|
| Description | Adversary attempts to replicate agent capabilities |
| Detection | Behavior analyzer flags unusual access patterns; volume-based anomaly |
| Mitigation | Rate limiting; capability boundaries prevent broad access |
| Evidence | `src/behavior_analyzer.py` -- action frequency histograms |

### AML.T0010 - ML Model Evasion

| Aspect | Detail |
|--------|--------|
| Description | Crafting inputs to bypass security controls |
| Detection | Policy engine uses strict pattern matching; no ML-based bypass possible |
| Mitigation | Deterministic policy evaluation; risk scoring is multi-dimensional |
| Evidence | `src/policy_engine.py` -- glob matching, not ML inference |

### AML.T0011 - User Compromise / Social Engineering

| Aspect | Detail |
|--------|--------|
| Description | Compromised human approves malicious action |
| Detection | Approval audit trail; time-bounded TTL on approvals |
| Mitigation | Approval delegation chains; multi-reviewer options |
| Evidence | `src/approval.py` -- TTL expiration, audit logging |

### AML.T0012 - Exploit Public-Facing Application

| Aspect | Detail |
|--------|--------|
| Description | Exploiting the authorization API itself |
| Detection | Input validation; rate limiting; structured error responses |
| Mitigation | Pydantic request validation; non-root container; mTLS |
| Evidence | `src/api.py` -- Pydantic models; `Dockerfile` -- non-root user |

### AML.T0015 - Denial of ML Service

| Aspect | Detail |
|--------|--------|
| Description | Overloading the authorization service |
| Detection | Rate limiting; latency monitoring; health checks |
| Mitigation | HPA auto-scaling; circuit breaker; configurable timeout |
| Evidence | Helm chart HPA; `src/authorization.py` -- circuit breaker and timeout |

### AML.T0018 - Backdoor ML Model

| Aspect | Detail |
|--------|--------|
| Description | Agent behavior deviates due to backdoor |
| Detection | Behavior analyzer detects deviation from baseline; intent alignment check |
| Mitigation | Continuous behavioral monitoring; DENY on anomalous patterns |
| Evidence | `src/behavior_analyzer.py`; `src/intent_alignment.py` |

### AML.T0024 - Exfiltration via ML Inference API

| Aspect | Detail |
|--------|--------|
| Description | Using agent to exfiltrate data |
| Detection | Data classification controls; volume anomaly detection; cross-account alerts |
| Mitigation | DENY on data access above declared classification; STEP_UP on bulk access |
| Evidence | Policy conditions on `data_classification`; `src/drift_detector.py` |

### AML.T0025 - Exfiltration via Cyber Means

| Aspect | Detail |
|--------|--------|
| Description | Agent writes data to external locations |
| Detection | Resource pattern matching detects access to unexpected destinations |
| Mitigation | Policies restrict resource patterns; cross-account access requires STEP_UP |
| Evidence | `resource_pattern` conditions in policy engine |

### AML.T0029 - Denial of ML Service via Model Poisoning

| Aspect | Detail |
|--------|--------|
| Description | Degrading authorization quality via manipulation |
| Detection | Health checks verify component integrity; deterministic policy evaluation |
| Mitigation | No ML in decision path; policies are code-reviewed YAML |
| Evidence | `GET /health` component checks; policy-as-code in git |

### AML.T0034 - Cost Harvesting

| Aspect | Detail |
|--------|--------|
| Description | Adversary uses agent for unauthorized compute |
| Detection | Capability inventory detects usage outside declared scope |
| Mitigation | Capability boundaries; action-to-purpose alignment |
| Evidence | `src/capability_inventory.py`; `src/intent_alignment.py` |

### AML.T0040 - Prompt Injection (Indirect)

| Aspect | Detail |
|--------|--------|
| Description | Injecting instructions via agent context |
| Detection | Authorization is separate from agent reasoning; input to authorize is structured |
| Mitigation | Authorization API accepts only structured JSON; no natural language parsing |
| Evidence | Pydantic request validation in `src/api.py` |

### AML.T0042 - Credential Access via Agent

| Aspect | Detail |
|--------|--------|
| Description | Agent acquires credentials beyond its role |
| Detection | STS and IAM actions trigger escalation engine; attack path analysis |
| Mitigation | DENY on `sts:AssumeRole` and `iam:*` for most agents |
| Evidence | `src/escalation_engine.py`; `src/attack_paths.py` |

### AML.T0043 - Privilege Escalation

| Aspect | Detail |
|--------|--------|
| Description | Agent elevates its own permissions |
| Detection | Attack path analyzer identifies multi-step escalation chains |
| Mitigation | DENY on PassRole, CreateRole, AttachPolicy; capability boundaries |
| Evidence | `src/attack_paths.py` -- graph traversal for escalation paths |

### AML.T0044 - Lateral Movement via Agent

| Aspect | Detail |
|--------|--------|
| Description | Agent pivots to other accounts or services |
| Detection | Cross-account resource patterns trigger STEP_UP; network risk scoring |
| Mitigation | Resource constraints in policies; per-agent capability limits |
| Evidence | Policy `resource_pattern` conditions; `src/risk_engine.py` network_score |

---

## Escalation Pattern Reference

The following privilege escalation patterns are detected by the escalation engine:

| Pattern | Steps | Severity |
|---------|-------|----------|
| PassRole Chain | `iam:PassRole` -> `sts:AssumeRole` -> Admin access | CRITICAL |
| Policy Attachment | `iam:AttachRolePolicy` -> Admin policy -> Full access | CRITICAL |
| STS Chain | `sts:AssumeRole` -> Cross-account -> `sts:AssumeRole` -> Target | HIGH |
| Lambda Pivot | `lambda:CreateFunction` -> `iam:PassRole` -> Execution role | HIGH |
| EC2 SSRF | `ec2:RunInstances` -> IMDS -> Role credentials | HIGH |
| S3 Policy | `s3:PutBucketPolicy` -> Open bucket -> Data exfil | MEDIUM |
| CloudFormation | `cloudformation:CreateStack` -> IAM resources | HIGH |
| SageMaker Notebook | `sagemaker:CreateNotebookInstance` -> Role access | MEDIUM |

Each pattern is defined in `src/escalation_engine.py` with detection rules and recommended mitigations.
