# Threat Model

## Scope

This document presents the formal threat model for AWS Agent Identity Guard, covering the security control itself, its deployment environment, and the threats it is designed to mitigate and those it explicitly does not address.

---

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY 1: External Network                                          │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  TRUST BOUNDARY 2: VPC / Internal Network                              │  │
│  │                                                                        │  │
│  │  ┌──────────────────────────────────────────────────────────────────┐  │  │
│  │  │  TRUST BOUNDARY 3: Application Container                          │  │  │
│  │  │                                                                    │  │  │
│  │  │  ┌────────────────┐     ┌────────────────────────────────────┐    │  │  │
│  │  │  │  API Layer     │────▶│  Decision Engine (trusted core)     │    │  │  │
│  │  │  │  (auth gate)   │     │  • Policy Engine                   │    │  │  │
│  │  │  └────────────────┘     │  • Risk Engine                     │    │  │  │
│  │  │                         │  • Authorization Service            │    │  │  │
│  │  │                         └────────────────────────────────────┘    │  │  │
│  │  │                                                                    │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  │                                                                        │  │
│  │  ┌──────────────────────┐    ┌──────────────────────┐                 │  │
│  │  │  Redis (cache/state) │    │  Policy Files (ro)    │                 │  │
│  │  │  TB4: Data Store     │    │  TB5: Config Store    │                 │  │
│  │  └──────────────────────┘    └──────────────────────┘                 │  │
│  │                                                                        │  │
│  │  ┌──────────────────────────────────────────────────────────────────┐  │  │
│  │  │  TRUST BOUNDARY 6: AWS Control Plane                              │  │  │
│  │  │  IAM · CloudTrail · Secrets Manager · STS                         │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  │                                                                        │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  TRUST BOUNDARY 7: AI Agent Runtime                                    │  │
│  │  Bedrock Agent · Lambda Function · ECS Task · SageMaker Endpoint       │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Assets

| Asset | Classification | Description |
|-------|---------------|-------------|
| Policy definitions | CONFIDENTIAL | Security rules governing agent behavior |
| Authorization decisions | INTERNAL | Allow/deny decisions and audit records |
| API keys | SECRET | Authentication credentials for the Guard API |
| Agent registry | CONFIDENTIAL | List of agents, permissions, and metadata |
| Audit trail | REGULATED | Tamper-evident log of all authorization events |
| Risk scores | INTERNAL | Agent and transaction risk assessments |
| Attack path data | CONFIDENTIAL | Discovered exploitation chains |
| Decision cache (Redis) | INTERNAL | Cached authorization results |
| Terraform state | SECRET | Infrastructure configuration and secrets |

---

## Attacker Capabilities

### Threat Actor Profiles

| Profile | Access | Motivation | Capability |
|---------|--------|------------|------------|
| Compromised Agent | Agent's IAM role | Data exfiltration, lateral movement | Automated, fast, can chain API calls |
| Prompt-Injected Agent | Agent's IAM role via manipulated input | Execute attacker-controlled actions | Depends on agent's permissions |
| Malicious Insider | Account access, possibly admin | Deploy over-permissioned agent roles | Full infrastructure access |
| External Attacker | Network access (if exposed) | Bypass authorization, steal data | Limited by network boundary |
| Supply Chain | Dependency injection | Persistent access, credential theft | Code execution in build pipeline |

### Assumed Attacker Capabilities

1. Can craft arbitrary IAM policy documents
2. Can manipulate agent inputs (prompt injection)
3. Can make API calls at machine speed (thousands/second)
4. Can chain AWS API calls across services within a single session
5. May have access to one IAM role and seek to escalate
6. May attempt to disable security monitoring before acting

---

## STRIDE Analysis

### Spoofing

| Threat | Component | Mitigation | Residual Risk |
|--------|-----------|------------|---------------|
| S1: Forge API key to bypass auth | API Server | API key validation, rate limiting | Low — keys rotated regularly |
| S2: Agent impersonation (claim different agent_id) | Authorization | Agent ID bound to IAM principal in production | Medium — depends on deployment |
| S3: Replay authorized requests | API Server | Correlation ID uniqueness, cache TTL, non-replayable approvals | Low |

### Tampering

| Threat | Component | Mitigation | Residual Risk |
|--------|-----------|------------|---------------|
| T1: Modify policy files on disk | Policy Engine | Read-only volume mounts, file integrity monitoring | Low |
| T2: Tamper with audit trail | Observability | Cryptographic hash chaining (tamper-evident) | Low |
| T3: Modify cached decisions in Redis | Decision Cache | Redis AUTH, network isolation, encrypted transit | Medium |
| T4: Inject malicious policy via API | API Server | Policy validation, schema enforcement, approval workflow | Low |

### Repudiation

| Threat | Component | Mitigation | Residual Risk |
|--------|-----------|------------|---------------|
| R1: Agent denies performing action | Audit Trail | Immutable audit log with hash chain | Low |
| R2: Approver denies approving action | Approval Service | Cryptographically signed approvals with identity binding | Low |
| R3: Missing audit for allowed actions | Observability | Audit rule type ensures recording regardless of decision | Low |

### Information Disclosure

| Threat | Component | Mitigation | Residual Risk |
|--------|-----------|------------|---------------|
| I1: Policy rules leaked (reveals bypass strategies) | Policy Engine | Policies classified CONFIDENTIAL, access-controlled | Medium |
| I2: Risk scores reveal security posture | Risk Engine | Scores not exposed externally, internal API only | Low |
| I3: Attack paths leaked to attacker | Attack Path Analyzer | Results only available to authenticated admins | Low |
| I4: API key in logs | Observability | Structured logging excludes auth headers | Low |

### Denial of Service

| Threat | Component | Mitigation | Residual Risk |
|--------|-----------|------------|---------------|
| D1: Flood authorization endpoint | API Server | Token bucket rate limiting per IP | Medium |
| D2: Exhaust decision cache | Redis | LRU eviction, memory limits | Low |
| D3: Submit policies that cause evaluation loops | Policy Engine | Evaluation timeout, rule count limits | Low |
| D4: Make Guard unavailable to force fail-open | All | `fail_closed` default in production | Low |

### Elevation of Privilege

| Threat | Component | Mitigation | Residual Risk |
|--------|-----------|------------|---------------|
| E1: Agent escalates via iam:PassRole | Scanner + Policy Engine | PRIV-001 detection rule, runtime deny policy | Low |
| E2: Agent creates new policy version | Scanner + Policy Engine | PRIV-002 detection rule | Low |
| E3: Bypass Guard via direct AWS call | Enforcement Engine | SDK middleware intercepts all boto3 calls | Medium — only if middleware deployed |
| E4: Self-approve step-up request | Approval Service | Approver cannot be same as requestor, role-based policies | Low |
| E5: Use expired approval | Approval Service | TTL enforcement, one-time use, non-replayable tokens | Low |

---

## What This Control Protects Against

### Protected Threat Scenarios

1. **Over-permissioned agent deployment** — Static scanner blocks CI merge when policy grants dangerous permissions (iam:PassRole without conditions, wildcard actions, etc.)

2. **Privilege escalation chains** — Attack path analyzer identifies multi-step escalation paths (Agent → PassRole → Lambda → Admin) before they can be exploited.

3. **Compromised agent lateral movement** — Runtime authorization denies unexpected cross-service actions that deviate from the agent's declared intent.

4. **Audit trail tampering** — Scanner flags and policy engine denies actions that would disable CloudTrail, GuardDuty, or Config.

5. **Data exfiltration via agent** — Data classification-aware policies restrict agent access to data above its clearance level.

6. **Behavioral anomaly exploitation** — Behavior analyzer detects when a compromised agent deviates from its learned baseline (new services, unusual times, volume spikes).

7. **Permission drift** — Drift detector identifies when agent permissions change outside the approved CI/CD pipeline.

8. **Missing security conditions** — Scanner catches policies lacking condition keys (SourceVpc, PrincipalOrgId, MFA) that would constrain abuse.

9. **Prompt injection leading to unauthorized actions** — Runtime authorization evaluates every action regardless of how the agent decided to take it, providing defense-in-depth against prompt injection.

10. **Shadow IT agent deployments** — Live scanner discovers agent roles that bypassed the CI gate.

---

## What This Control Does NOT Protect Against

### Out of Scope

| Threat | Why Out of Scope | Complementary Control |
|--------|------------------|----------------------|
| Compromise of the Guard service itself | If attacker has admin access to Guard, all bets are off | Infrastructure security, access controls, monitoring |
| Attacks that don't use IAM (e.g., application-layer SQL injection) | Guard operates at IAM/AWS API layer | Application security testing (SAST/DAST) |
| Prompt injection prevention | Guard doesn't inspect or filter prompts | Input validation, prompt engineering guardrails |
| Network-layer attacks (DDoS, MITM on non-TLS) | Guard assumes network integrity | TLS, VPC security groups, WAF |
| Physical access to infrastructure | Beyond software control scope | Physical security controls |
| Insider with direct AWS Console access bypassing CI | Guard only enforces if integrated into deployment path | SCPs, CloudTrail monitoring, detective controls |
| Model poisoning / training data attacks | Guard operates at inference-time authorization | ML pipeline security, model provenance |
| Credential theft from outside AWS (phished human passwords) | Guard doesn't manage human authentication | MFA, SSO, identity provider security |
| Zero-day vulnerabilities in AWS services | Guard relies on AWS APIs functioning correctly | AWS shared responsibility model |
| Actions taken before Guard deployment | Historical actions cannot be retroactively blocked | CloudTrail forensics, remediation |

### Important Limitations

1. **Bypass if not deployed** — Guard only protects workloads where it is integrated. An agent calling AWS directly (without SDK middleware or API gateway enforcement) is not protected at runtime.

2. **Fail-open risk** — If configured with `fail_mode=open` and the Guard service becomes unavailable, all actions are allowed. Production MUST use `fail_closed`.

3. **Static analysis coverage** — The 24 scanning rules cover known patterns. Novel attack techniques not yet codified as rules will not be detected until rules are updated.

4. **Policy correctness** — The Guard enforces whatever policies are loaded. Incorrect policies (too permissive allow rules) reduce protection. Policy testing and review processes are essential.

---

## Attack Tree

```
ROOT: Unauthorized Action by AI Agent
├── 1. Deploy Over-Permissioned Role
│   ├── 1.1 Bypass CI Gate
│   │   ├── 1.1.1 Commit directly to main (no branch protection)
│   │   │   └── Mitigation: Branch protection rules
│   │   ├── 1.1.2 Modify CI workflow to skip scan
│   │   │   └── Mitigation: CODEOWNERS on .github/workflows
│   │   └── 1.1.3 Use --fail-on=critical (ignore HIGH findings)
│   │       └── Mitigation: Org policy mandates --fail-on=high
│   ├── 1.2 Deploy via AWS Console (skip CI entirely)
│   │   └── Mitigation: SCPs + Live Scanner + CloudTrail alerts
│   └── 1.3 Gradually add permissions across multiple PRs
│       └── Mitigation: Temporal analysis (diff-based scanning)
│
├── 2. Exploit Existing Permissions
│   ├── 2.1 Privilege Escalation
│   │   ├── 2.1.1 iam:PassRole → Lambda with admin role
│   │   │   └── Mitigation: Scanner PRIV-001 + runtime deny
│   │   ├── 2.1.2 iam:CreatePolicyVersion → add admin
│   │   │   └── Mitigation: Scanner PRIV-002 + runtime deny
│   │   ├── 2.1.3 iam:AttachRolePolicy → attach admin policy
│   │   │   └── Mitigation: Scanner PRIV-003 + runtime deny
│   │   └── 2.1.4 sts:AssumeRole → cross-account admin
│   │       └── Mitigation: Scanner CRED-001 + ExternalId check
│   │
│   ├── 2.2 Lateral Movement
│   │   ├── 2.2.1 lambda:InvokeFunction on * → execute in other contexts
│   │   │   └── Mitigation: Scanner LATERAL-001 + resource scoping
│   │   ├── 2.2.2 sagemaker:CreateNotebookInstance → code exec
│   │   │   └── Mitigation: Scanner LATERAL-002 + runtime deny
│   │   └── 2.2.3 bedrock:InvokeModel on * → access other models
│   │       └── Mitigation: Scanner LATERAL-003 + resource scoping
│   │
│   ├── 2.3 Data Exfiltration
│   │   ├── 2.3.1 s3:GetObject on * → read all data
│   │   │   └── Mitigation: Scanner WILD-001 + data classification
│   │   ├── 2.3.2 secretsmanager:GetSecretValue on * → steal secrets
│   │   │   └── Mitigation: Scanner CRED-003 + audit rule
│   │   └── 2.3.3 Copy data to attacker-controlled bucket
│   │       └── Mitigation: VPC endpoint policies + resource restrictions
│   │
│   └── 2.4 Cover Tracks
│       ├── 2.4.1 cloudtrail:StopLogging
│       │   └── Mitigation: Scanner AUDIT-001 + runtime deny (highest priority)
│       ├── 2.4.2 cloudtrail:DeleteTrail
│       │   └── Mitigation: Scanner AUDIT-002 + runtime deny
│       └── 2.4.3 cloudtrail:UpdateTrail → redirect to attacker bucket
│           └── Mitigation: Scanner AUDIT-003 + runtime deny
│
├── 3. Compromise Agent via Prompt Injection
│   ├── 3.1 Direct injection (malicious user input)
│   │   └── Mitigation: Runtime authorization blocks unauthorized actions
│   ├── 3.2 Indirect injection (poisoned data source)
│   │   └── Mitigation: Runtime authorization + behavior anomaly detection
│   └── 3.3 Multi-turn manipulation
│       └── Mitigation: Behavior analyzer detects unusual action sequences
│
├── 4. Attack the Guard Service Itself
│   ├── 4.1 DoS the Guard → force fail-open
│   │   └── Mitigation: fail_closed mode, rate limiting, auto-scaling
│   ├── 4.2 Steal API key → impersonate legitimate client
│   │   └── Mitigation: Key rotation, Secrets Manager, per-client keys
│   ├── 4.3 Modify policies to allow attacker actions
│   │   └── Mitigation: Read-only mounts, policy versioning, git audit
│   └── 4.4 Poison decision cache → allow malicious actions
│       └── Mitigation: Redis AUTH, cache TTL, network isolation
│
└── 5. Supply Chain Attack
    ├── 5.1 Compromise a dependency → gain code execution
    │   └── Mitigation: Zero runtime dependencies (core), pinned versions
    ├── 5.2 Typosquatting on PyPI package name
    │   └── Mitigation: Official package name, documented install instructions
    └── 5.3 Compromise CI pipeline → inject backdoor
        └── Mitigation: Signed releases, reproducible builds, CI hardening
```

---

## Risk Summary Matrix

| Threat Category | Likelihood | Impact | Risk | Primary Mitigation |
|-----------------|-----------|--------|------|-------------------|
| Over-permissioned deployment | High | Critical | Critical | CI gate (scanner) |
| Privilege escalation chain | Medium | Critical | High | Attack path analysis + runtime deny |
| Prompt injection exploitation | High | High | High | Runtime authorization |
| Lateral movement | Medium | High | High | Intent alignment + behavior analysis |
| Audit trail tampering | Low | Critical | Medium | Hardcoded deny rules |
| Guard service compromise | Low | Critical | Medium | Infrastructure security |
| Permission drift | Medium | Medium | Medium | Drift detector + alerting |
| Supply chain attack | Low | High | Medium | Zero dependencies |
| DoS on Guard service | Medium | Medium | Medium | Rate limiting + fail_closed |
| Data exfiltration | Medium | High | High | Data classification policies |
