# MITRE ATLAS Mapping

## Overview

This document maps AWS Agent Identity Guard capabilities to the [MITRE ATLAS](https://atlas.mitre.org/) (Adversarial Threat Landscape for AI Systems) framework. ATLAS extends ATT&CK to cover threats specific to machine learning and AI systems.

Agent Identity Guard focuses on the **infrastructure and access control** dimension of AI security — specifically preventing AI agents from being used as attack vectors against AWS resources.

---

## Applicable ATLAS Techniques

### Reconnaissance

| ATLAS ID | Technique | Guard Mitigation | Coverage |
|----------|-----------|-----------------|----------|
| AML.T0000 | ML Model Discovery | Scanner detects overly broad `sagemaker:Describe*` and `bedrock:List*` permissions that would enable model enumeration | Detect |
| AML.T0001 | ML Artifact Collection | Policy engine can deny `s3:GetObject` on model artifact buckets; data classification protects model weights | Prevent + Detect |

### Initial Access

| ATLAS ID | Technique | Guard Mitigation | Coverage |
|----------|-----------|-----------------|----------|
| AML.T0010 | ML Supply Chain Compromise | Zero runtime dependencies in core scanner reduces supply chain attack surface; Dependabot monitoring | Partial |
| AML.T0011 | Valid ML Credentials | Scanner flags `sts:AssumeRole` without ExternalId; drift detector alerts on new credential grants | Detect + Alert |
| AML.T0012 | Publish Poisoned Model | Policy engine can restrict `sagemaker:CreateModel` and `bedrock:CreateModelCustomizationJob` to approved sources | Prevent |

### Execution

| ATLAS ID | Technique | Guard Mitigation | Coverage |
|----------|-----------|-----------------|----------|
| AML.T0020 | Inference API Access | Runtime authorization gates all `bedrock:InvokeModel` and `sagemaker:InvokeEndpoint` calls | Prevent |
| AML.T0021 | ML Service Abuse | Intent alignment engine detects when agent invokes services outside its declared capability manifest | Detect |
| AML.T0022 | Autonomous Agent Exploitation | Runtime authorization evaluates every agent action regardless of how decision was made (defense against prompt injection) | Prevent |

### Persistence

| ATLAS ID | Technique | Guard Mitigation | Coverage |
|----------|-----------|-----------------|----------|
| AML.T0030 | Backdoor ML Model | Policy engine restricts `sagemaker:UpdateEndpoint` and model artifact writes in production | Prevent |
| AML.T0031 | Modify ML Pipeline | Scanner flags `codepipeline:*` and `sagemaker:UpdatePipeline` permissions; drift detector monitors changes | Detect |

### Privilege Escalation

| ATLAS ID | Technique | Guard Mitigation | Coverage |
|----------|-----------|-----------------|----------|
| AML.T0040 | ML Privilege Escalation | Attack path analyzer identifies chains: Agent → PassRole → SageMaker Execution Role → Admin; scanner flags passrole without conditions | Prevent + Detect |
| AML.T0041 | Exploit ML Service Vulnerabilities | Behavior analyzer detects abnormal API call patterns that may indicate exploitation; resource scoping limits blast radius | Detect |

### Evasion

| ATLAS ID | Technique | Guard Mitigation | Coverage |
|----------|-----------|-----------------|----------|
| AML.T0050 | Evade ML Detection | Scanner rule AUDIT-001/002/003 flags attempts to disable CloudTrail, GuardDuty, or Config; hardcoded deny at highest priority | Prevent |
| AML.T0051 | Manipulate ML Monitoring | Policy engine denies modifications to monitoring infrastructure; drift detector catches changes | Prevent |

### Impact

| ATLAS ID | Technique | Guard Mitigation | Coverage |
|----------|-----------|-----------------|----------|
| AML.T0060 | ML Model Theft | Data classification policies restrict access to model artifacts (SECRET/REGULATED); audit trail records all access | Prevent + Detect |
| AML.T0061 | ML Data Poisoning | Policy engine can restrict training data writes; approval workflow for pipeline modifications | Partial |
| AML.T0062 | ML Model Degradation | Approval required for model endpoint updates in production; drift detection on model configurations | Detect |
| AML.T0063 | ML Denial of Service | Rate limiting on authorization API; resource quotas enforced via policy; behavior analyzer detects volume anomalies | Detect + Mitigate |

### Exfiltration

| ATLAS ID | Technique | Guard Mitigation | Coverage |
|----------|-----------|-----------------|----------|
| AML.T0070 | ML Data Exfiltration | Data classification enforcement; VPC condition requirements; resource ARN scoping prevents cross-boundary data movement | Prevent |
| AML.T0071 | Model Extraction via API | Rate-based anomaly detection; `bedrock:InvokeModel` scoped to specific models; audit trail for volume analysis | Detect |

---

## ATLAS Tactic Coverage Matrix

| ATLAS Tactic | Techniques Covered | Prevention | Detection | Partial |
|-------------|-------------------|-----------|-----------|---------|
| Reconnaissance | 2 | 0 | 2 | 0 |
| Initial Access | 3 | 1 | 1 | 1 |
| Execution | 3 | 2 | 1 | 0 |
| Persistence | 2 | 1 | 1 | 0 |
| Privilege Escalation | 2 | 1 | 1 | 0 |
| Evasion | 2 | 2 | 0 | 0 |
| Impact | 4 | 1 | 2 | 1 |
| Exfiltration | 2 | 1 | 1 | 0 |
| **Total** | **20** | **9** | **9** | **2** |

---

## Guard Component Mapping to ATLAS

| Guard Component | Primary ATLAS Coverage |
|----------------|----------------------|
| Scanner (static analysis) | Privilege Escalation, Evasion |
| Policy Engine | Execution, Persistence, Impact |
| Risk Engine | All (risk-based gating) |
| Authorization Service | Execution, Privilege Escalation |
| Behavior Analyzer | Execution, Exfiltration, Impact |
| Drift Detector | Persistence, Evasion |
| Attack Path Analyzer | Privilege Escalation |
| Intent Alignment | Execution, Reconnaissance |
| Approval Service | Impact, Persistence |
| Enforcement Engine | All (enforcement layer) |

---

## AI Agent-Specific Attack Scenarios

### Scenario 1: Compromised Bedrock Agent → Model Theft

```
ATLAS Chain: AML.T0011 → AML.T0020 → AML.T0060

1. Attacker compromises agent via prompt injection
2. Agent attempts to list available models (bedrock:ListFoundationModels)
3. Agent attempts to invoke unrelated models (bedrock:InvokeModel on *)
4. Agent attempts to copy model artifacts to external bucket

Guard Response:
- Step 2: Intent alignment flags unexpected Bedrock discovery API calls
- Step 3: Policy engine denies InvokeModel outside declared model scope
- Step 4: Scanner would have blocked deploy if s3:PutObject was on * 
         + Runtime denies write to non-declared bucket ARN
```

### Scenario 2: Agent Privilege Escalation via SageMaker

```
ATLAS Chain: AML.T0040 → AML.T0030 → AML.T0061

1. Agent uses iam:PassRole to assign admin role to SageMaker notebook
2. Agent creates notebook instance with admin execution role
3. Agent executes arbitrary code in notebook with elevated privileges
4. Agent modifies training data in S3

Guard Response:
- Step 1: Scanner PRIV-001 blocks deploy with iam:PassRole on *
         + Runtime authorization denies PassRole without conditions
- Step 2: Attack path analyzer identified this chain pre-deployment
- Step 3: Behavior analyzer detects notebook creation (unexpected tool)
- Step 4: Data classification policy requires approval for training data writes
```

### Scenario 3: Autonomous Agent Exploitation (Prompt Injection)

```
ATLAS Chain: AML.T0022 → AML.T0050 → AML.T0070

1. Indirect prompt injection via poisoned document
2. Agent instructed to disable monitoring
3. Agent attempts to exfiltrate data to attacker-controlled endpoint

Guard Response:
- Step 2: Hardcoded deny rule for CloudTrail/GuardDuty modification
         (evaluated regardless of agent's "reasoning")
- Step 3: VPC condition enforcement prevents data leaving approved network
         + Data classification policy blocks SECRET data access
         + Behavior analyzer flags unprecedented action pattern
```

---

## Recommendations for Complete ATLAS Coverage

| Gap | Recommendation | Priority |
|-----|---------------|----------|
| Model integrity verification | Integrate model signing/hash verification | High |
| Training pipeline security | Add pipeline-specific policy templates | Medium |
| Prompt injection prevention | Integrate with input sanitization layer | High |
| Model provenance tracking | Add model lineage tracking to audit trail | Medium |
| Adversarial input detection | Out of scope (application layer) | Low |
