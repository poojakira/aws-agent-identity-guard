# NIST SP 800-53 Control Mapping

## Overview

This document maps AWS Agent Identity Guard capabilities to NIST Special Publication 800-53 Rev. 5 security controls. The mapping identifies which controls the tool directly implements, supports, or contributes evidence toward.

**Legend:**
- ● Direct Implementation  -  Guard directly satisfies this control
- ◐ Partial/Supporting  -  Guard contributes to or supports this control
- ○ Evidence Provider  -  Guard generates evidence for compliance audits

---

## Access Control (AC)

| Control ID | Control Name | Coverage | Guard Capability |
|------------|-------------|----------|-----------------|
| AC-2 | Account Management | ◐ | Agent registry tracks all AI agent identities, their permissions, and lifecycle status (ACTIVE/INACTIVE/SUSPENDED/DECOMMISSIONED) |
| AC-2(4) | Automated Audit Actions | ● | Audit trail automatically logs agent registration, modification, and decommissioning events |
| AC-3 | Access Enforcement | ● | Runtime authorization service enforces access decisions for every agent action |
| AC-3(8) | Revocation of Access Authorizations | ● | Agent suspension immediately blocks all authorization requests for that agent |
| AC-4 | Information Flow Enforcement | ◐ | Data classification-aware policies restrict agent access based on sensitivity levels |
| AC-5 | Separation of Duties | ● | Approval service requires different identity for requestor vs. approver; role-based policies |
| AC-6 | Least Privilege | ● | Least-privilege engine generates minimum-necessary policies; scanner flags over-privilege |
| AC-6(1) | Authorize Access to Security Functions | ● | Deny rules prevent agents from modifying audit/security infrastructure (CloudTrail, GuardDuty) |
| AC-6(2) | Non-privileged Access for Non-security Functions | ◐ | Intent alignment engine flags permissions unrelated to agent's declared purpose |
| AC-6(5) | Privileged Accounts | ◐ | Scanner specifically targets agent roles (first-class autonomous principals) |
| AC-6(9) | Log Use of Privileged Functions | ● | Audit trail records all privileged actions with full context |
| AC-6(10) | Prohibit Non-privileged Users from Executing Privileged Functions | ● | Policy engine denies agent access to privileged actions without approval |
| AC-17 | Remote Access | ◐ | Network-level condition checks (aws:SourceVpc, aws:SourceIp) enforced by scanner rules |
| AC-24 | Access Control Decisions | ● | Authorization service provides real-time PDP with multi-dimensional evaluation |

---

## Audit and Accountability (AU)

| Control ID | Control Name | Coverage | Guard Capability |
|------------|-------------|----------|-----------------|
| AU-2 | Event Logging | ● | All authorization decisions logged with agent, action, resource, decision, risk score |
| AU-3 | Content of Audit Records | ● | Structured audit events include timestamp, correlation ID, agent ID, principal, action, resource, decision, risk score, matched rules |
| AU-3(1) | Additional Audit Information | ● | Context metadata, data classification, environment, and behavior analysis results included |
| AU-6 | Audit Record Review, Analysis, and Reporting | ◐ | Prometheus metrics and Grafana dashboards enable analysis; audit trail queryable |
| AU-8 | Time Stamps | ● | UTC timestamps with timezone info on all audit events |
| AU-9 | Protection of Audit Information | ● | Tamper-evident audit trail with cryptographic hash chaining |
| AU-9(2) | Store on Separate Physical Systems | ◐ | Supports external audit storage backends; CloudWatch log groups |
| AU-10 | Non-repudiation | ● | Hash-chained audit trail ensures events cannot be retroactively modified |
| AU-12 | Audit Record Generation | ● | Automatic audit generation for all authorization decisions and policy evaluations |
| AU-12(1) | System-wide/Time-correlated Audit Trail | ◐ | Correlation IDs enable cross-system tracing |

---

## Configuration Management (CM)

| Control ID | Control Name | Coverage | Guard Capability |
|------------|-------------|----------|-----------------|
| CM-2 | Baseline Configuration | ● | Permission baselines captured by drift detector; policy versioning tracks configuration |
| CM-3 | Configuration Change Control | ◐ | Policy versioning with git integration; drift detection alerts on unauthorized changes |
| CM-4 | Impact Analyses | ● | Policy testing framework validates changes before deployment; risk scoring on changes |
| CM-6 | Configuration Settings | ◐ | Scanner enforces IAM configuration standards (condition keys, resource scoping) |
| CM-7 | Least Functionality | ● | Scanner and intent alignment engine flag unnecessary permissions |

---

## Identification and Authentication (IA)

| Control ID | Control Name | Coverage | Guard Capability |
|------------|-------------|----------|-----------------|
| IA-2 | Identification and Authentication | ● | API key authentication; agent identity binding |
| IA-2(6) | Access to Accounts  -  Separate Device | ◐ | Approval workflow requires separate approver identity for step-up |
| IA-4 | Identifier Management | ● | Unique agent IDs with lifecycle management (create, suspend, decommission) |
| IA-8 | Identification and Authentication (Non-Organizational Users) | ◐ | ExternalId enforcement for cross-account access (scanner rule) |

---

## Incident Response (IR)

| Control ID | Control Name | Coverage | Guard Capability |
|------------|-------------|----------|-----------------|
| IR-4 | Incident Handling | ◐ | Behavior anomaly detection triggers alerts; deny decisions log full context |
| IR-5 | Incident Monitoring | ● | Real-time drift detection, behavior anomaly alerts, denial rate monitoring |
| IR-6 | Incident Reporting | ◐ | Structured audit events provide forensic evidence; webhook notifications |

---

## Risk Assessment (RA)

| Control ID | Control Name | Coverage | Guard Capability |
|------------|-------------|----------|-----------------|
| RA-3 | Risk Assessment | ● | Multi-dimensional risk scoring for every agent and transaction |
| RA-5 | Vulnerability Monitoring and Scanning | ● | Static IAM policy scanning in CI; live scanning of deployed roles |
| RA-5(2) | Update Vulnerabilities to be Scanned | ◐ | Rule set updated with new attack patterns; MITRE ATT&CK mapping |
| RA-5(5) | Privileged Access | ● | Scanner specifically targets privilege escalation patterns |

---

## System and Communications Protection (SC)

| Control ID | Control Name | Coverage | Guard Capability |
|------------|-------------|----------|-----------------|
| SC-4 | Information in Shared System Resources | ◐ | Data classification policies prevent cross-boundary data access |
| SC-7 | Boundary Protection | ◐ | Scanner enforces SourceVpc conditions; network boundary awareness |
| SC-7(5) | Deny by Default | ● | fail_closed mode denies all when enforcement unavailable; deny-first policy evaluation |

---

## System and Information Integrity (SI)

| Control ID | Control Name | Coverage | Guard Capability |
|------------|-------------|----------|-----------------|
| SI-3 | Malicious Code Protection | ◐ | Attack path analysis detects exploitation chains; behavior analysis detects compromise |
| SI-4 | System Monitoring | ● | Runtime behavior analysis, drift detection, anomaly alerting |
| SI-4(2) | Automated Tools and Mechanisms for Real-time Analysis | ● | Real-time authorization with risk scoring; async drift monitoring |
| SI-4(5) | System-generated Alerts | ● | Alerts on behavior anomalies, permission drift, high-risk authorizations |
| SI-4(12) | Automated Organization-generated Alerts | ◐ | Webhook and SNS notifications for security events |
| SI-7 | Software, Firmware, and Information Integrity | ◐ | Hash-chained audit trail; policy file integrity via read-only mounts |

---

## Supply Chain Risk Management (SR)

| Control ID | Control Name | Coverage | Guard Capability |
|------------|-------------|----------|-----------------|
| SR-3 | Supply Chain Controls and Processes | ◐ | Zero runtime dependencies minimizes supply chain risk; Dependabot scanning |
| SR-4 | Provenance | ◐ | Container image signing; reproducible builds |
| SR-11 | Component Authenticity | ◐ | Pinned dependency versions; official PyPI package |

---

## Summary

| Control Family | Direct (●) | Partial (◐) | Evidence (○) | Total |
|---------------|-----------|-------------|-------------|-------|
| Access Control (AC) | 10 | 4 | 0 | 14 |
| Audit (AU) | 8 | 2 | 0 | 10 |
| Configuration (CM) | 3 | 2 | 0 | 5 |
| Identification (IA) | 2 | 2 | 0 | 4 |
| Incident Response (IR) | 1 | 2 | 0 | 3 |
| Risk Assessment (RA) | 3 | 1 | 0 | 4 |
| System Protection (SC) | 1 | 2 | 0 | 3 |
| System Integrity (SI) | 3 | 3 | 0 | 6 |
| Supply Chain (SR) | 0 | 3 | 0 | 3 |
| **Total** | **31** | **21** | **0** | **52** |
