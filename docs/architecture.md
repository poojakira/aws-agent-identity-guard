# Architecture

## System Overview

AWS Agent Identity Guard is a comprehensive security platform for AI agent identity management on AWS. It provides static policy analysis, runtime authorization, behavioral monitoring, and least-privilege enforcement across AI agent workloads (Bedrock, SageMaker, Lambda, ECS, EKS).

```
                          ┌─────────────────────────────────────────────┐
                          │           Client Layer                       │
                          │  ┌─────────┐  ┌──────────┐  ┌───────────┐  │
                          │  │ Python  │  │  Boto3   │  │   REST    │  │
                          │  │   SDK   │  │Middleware│  │   API     │  │
                          │  └────┬────┘  └────┬─────┘  └─────┬─────┘  │
                          └───────┼────────────┼──────────────┼────────┘
                                  │            │              │
                          ┌───────▼────────────▼──────────────▼────────┐
                          │            API Server (api.py)              │
                          │  Rate Limiting · Auth · Routing · Metrics   │
                          └───────────────────┬────────────────────────┘
                                              │
              ┌───────────────────────────────┼───────────────────────────────┐
              │                               │                               │
    ┌─────────▼─────────┐         ┌──────────▼──────────┐        ┌──────────▼──────────┐
    │  Static Analysis   │         │ Runtime Authorization│        │   Observability      │
    │                    │         │                      │        │                      │
    │ ┌────────────────┐ │         │ ┌──────────────────┐ │        │ ┌──────────────────┐ │
    │ │    Scanner     │ │         │ │  Authorization   │ │        │ │ MetricsCollector │ │
    │ │  (24 rules)    │ │         │ │    Service       │ │        │ │ StructuredLogger │ │
    │ └────────────────┘ │         │ └────────┬─────────┘ │        │ │   AuditTrail     │ │
    │ ┌────────────────┐ │         │          │           │        │ └──────────────────┘ │
    │ │ Live Scanner   │ │         │ ┌────────▼─────────┐ │        └──────────────────────┘
    │ │  (boto3 mode)  │ │         │ │  Policy Engine   │ │
    │ └────────────────┘ │         │ │ (YAML policies)  │ │
    │ ┌────────────────┐ │         │ └────────┬─────────┘ │
    │ │  Remediation   │ │         │          │           │
    │ │  (fix output)  │ │         │ ┌────────▼─────────┐ │
    │ └────────────────┘ │         │ │  Risk Engine     │ │
    └────────────────────┘         │ │ (multi-dim score)│ │
                                   │ └────────┬─────────┘ │
              ┌────────────────────│──────────┼───────────│────────────────────┐
              │                    │          │           │                    │
    ┌─────────▼─────────┐         │ ┌────────▼─────────┐ │        ┌──────────▼──────────┐
    │  Deep Analysis     │         │ │Approval Service  │ │        │   Enforcement        │
    │                    │         │ │(step-up auth)    │ │        │                      │
    │ ┌────────────────┐ │         │ └──────────────────┘ │        │ ┌──────────────────┐ │
    │ │  Effective     │ │         └──────────────────────┘        │ │EnforcementEngine │ │
    │ │  Permissions   │ │                                         │ │(monitor/enforce/ │ │
    │ └────────────────┘ │                                         │ │ dry_run)         │ │
    │ ┌────────────────┐ │                                         │ └──────────────────┘ │
    │ │  Capability    │ │                                         │ ┌──────────────────┐ │
    │ │  Inventory     │ │                                         │ │ Drift Detector   │ │
    │ └────────────────┘ │                                         │ └──────────────────┘ │
    │ ┌────────────────┐ │                                         │ ┌──────────────────┐ │
    │ │  Attack Path   │ │                                         │ │BehaviorAnalyzer  │ │
    │ │  Analyzer      │ │                                         │ └──────────────────┘ │
    │ └────────────────┘ │                                         └──────────────────────┘
    │ ┌────────────────┐ │
    │ │  Escalation    │ │
    │ │  Engine        │ │
    │ └────────────────┘ │
    │ ┌────────────────┐ │
    │ │Intent Alignment│ │
    │ └────────────────┘ │
    │ ┌────────────────┐ │
    │ │Least Privilege │ │
    │ │  Engine        │ │
    │ └────────────────┘ │
    └────────────────────┘
```

---

## Component Descriptions

### 1. Scanner (`scanner.py`)

The core static analysis engine. Applies 24 deterministic rules to IAM policy JSON documents to detect agent-specific security threats.

| Attribute | Value |
|-----------|-------|
| Dependencies | Zero (pure Python stdlib) |
| Input | IAM policy JSON documents |
| Output | Findings in Text, JSON, SARIF 2.1 format |
| Rule categories | Wildcard abuse, privilege escalation, credential harvest, audit-trail tampering, lateral movement, missing conditions |

**Rule Categories:**

| Category | Rules | Description |
|----------|-------|-------------|
| Wildcard Abuse | AIG001–AIG005 | Full-service wildcards on sensitive services |
| Privilege Escalation | AIG006–AIG009 | PassRole, CreatePolicyVersion, AttachRolePolicy |
| Credential Harvest | AIG010–AIG013 | Cross-account AssumeRole, GetSecretValue |
| Audit-Trail Tampering | AIG014–AIG016 | CloudTrail deletion/modification |
| Lateral Movement | AIG017–AIG021 | Lambda invoke, SageMaker notebooks, Bedrock scope |
| Missing Conditions | AIG022–AIG025 | Missing SourceVpc, PrincipalOrgId, MFA |

### 2. Live Scanner (`live_scanner.py`)

Optional boto3-powered scanner that pulls policies directly from a running AWS account for drift detection and audit of deployed roles.

- Calls `iam:GetRolePolicy`, `iam:ListAttachedRolePolicies`
- Feeds discovered policies into the same 24-rule engine
- Requires `pip install aws-agent-identity-guard[live]`

### 3. Remediation (`remediate.py`)

Generates actionable fix suggestions for each finding, including concrete policy snippets showing what the policy should look like after remediation.

### 4. Models (`models.py`)

Canonical domain model defining:
- `Agent`, `AuthorizationRequest`, `AuthorizationDecision`
- `Permission`, `PermissionEffect`, `PermissionSource`
- `RiskScore`, `Policy`, `PolicyRule`
- `AuditEvent`, `ApprovalRequest`, `DriftEvent`, `AttackPath`, `AttackStep`
- Enumerations: `DataClassification`, `Environment`, `WorkloadType`, `Decision`, `Severity`, `ApprovalStatus`

### 5. Effective Permissions (`effective_permissions.py`)

Implements the complete AWS authorization evaluation logic across all five IAM policy layers:

1. Identity policies (inline + managed)
2. Resource policies
3. Permission boundaries
4. Service Control Policies (SCPs)
5. Session policies

Resolves to a set of `EffectivePermission` objects with effect, source, conditions, and resource scope.

### 6. Intent Alignment (`intent_alignment.py`)

Compares declared agent capabilities (YAML manifest) against effective permissions and observed usage. Detects:
- **OVER_PRIVILEGE**: Permissions granted but not declared
- **UNUSED_PERMISSIONS**: Permissions never exercised
- **DANGEROUS_UNRELATED**: High-risk permissions unrelated to stated purpose
- **MISSING_PERMISSIONS**: Actions in manifest but not in effective permissions

Produces an alignment score (0–100) with category breakdowns.

### 7. Capability Inventory (`capability_inventory.py`)

Graph-based capability enumeration and analysis:
- Discovers accessible services, resources, roles, data stores, and endpoints
- Builds a directed `CapabilityGraph` with typed nodes and edges
- Supports path finding, blast radius analysis, and lateral movement detection
- Exports to DOT format and JSON for visualization

### 8. Attack Path Analyzer (`attack_paths.py`)

Graph-based attack chain discovery using BFS/DFS with cycle detection:
- Enumerates multi-step exploitation paths (e.g., Agent → PassRole → Role B → Lambda → S3 → Secret)
- Maps each step to MITRE ATT&CK techniques
- Ranks paths by likelihood, impact, and exploitability
- Supports `AttackPatternCategory`: privilege escalation, lateral movement, data exfiltration, credential theft, arbitrary execution, persistence

### 9. Escalation Engine (`escalation_engine.py`)

Identifies privilege escalation paths specific to AI agent workloads. Detects chains where an agent can incrementally gain higher privileges through valid AWS API sequences.

### 10. Risk Engine (`risk_engine.py`)

Multi-dimensional risk scoring engine replacing simplistic severity-only findings:

| Dimension | Description |
|-----------|-------------|
| Privilege | Level of privilege the action grants |
| Sensitivity | Data classification of affected resources |
| Blast radius | Number of resources/accounts affected |
| Data exposure | Potential for data exfiltration |
| Persistence | Ability to maintain access |
| Lateral movement | Ability to pivot to other services |
| Environment | Production vs dev risk multiplier |
| Transaction context | Runtime context signals |

Supports configurable risk profiles (strict/standard/permissive) with non-linear composite scoring and toxic combination detection.

### 11. Authorization Service (`authorization.py`)

Core Policy Decision Point (PDP) for runtime agent authorization:
- Evaluates transactions against configurable policy pipelines
- Supports fail-closed/fail-open modes
- Integrates risk scoring and step-up authentication
- LRU decision cache for sub-10ms cached decisions
- Full audit trail for every decision

### 12. Approval Service (`approval.py`)

Human-in-the-loop step-up approval workflow:
- Identity-bound, time-limited, action-specific approvals
- Role-based approval policies (who can approve what)
- Pluggable backend via `ApprovalStore` protocol
- Non-replayable decisions with TTL expiry
- Full audit log integration

### 13. Policy Engine (`policy_engine.py`)

Declarative security policy-as-code engine:
- YAML-based policy language
- Rule types: `deny`, `allow`, `require_approval`, `warn`, `audit`
- Action/resource pattern matching with wildcards and regex
- Conditions: environment, data classification, agent type, time windows
- Policy versioning and priority ordering
- Built-in policy testing framework

### 14. Drift Detector (`drift_detector.py`)

Permission drift detection and monitoring:
- Captures permission baselines at a point in time
- Detects additions, removals, and modifications of effective permissions
- Classifies drift severity based on dangerous action lists
- Async generator for real-time drift event streaming
- Alerting via webhook, SNS, and structured logs

### 15. Behavior Analyzer (`behavior_analyzer.py`)

Runtime behavioral analysis engine:
- Records agent actions in bounded buffers
- Learns behavioral baselines per agent
- Detects anomalies: unexpected tools, services, resources, privilege jumps, unusual sequences, time anomalies, volume anomalies
- Produces behavior reports with timelines and risk indicators

### Supporting Components

| Component | File | Purpose |
|-----------|------|---------|
| Enforcement Engine | `enforcement.py` | Runtime enforcement with monitor/enforce/dry_run modes, circuit breaker, SDK middleware proxy |
| Observability | `observability.py` | Prometheus metrics, OpenTelemetry tracing, structured logging, tamper-evident audit trails |
| Least Privilege Engine | `least_privilege.py` | Generates concrete replacement policies with unified diffs |
| API Server | `api.py` | REST API with rate limiting, auth, and full endpoint suite |
| CLI | `cli.py` | Command-line interface for all modes |

---

## Data Flow

### Static Analysis (CI Pipeline)

```
Developer commits IAM policy JSON
         │
         ▼
┌─────────────────────┐
│  CI Runner          │
│  pip install ...    │
│  python -m aws_...  │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐     ┌──────────────────┐
│  Scanner            │────▶│  Output Formatter │
│  • Parse policy     │     │  • Text           │
│  • Normalize        │     │  • JSON           │
│  • Apply 24 rules   │     │  • SARIF 2.1      │
└─────────────────────┘     └────────┬─────────┘
                                     │
                                     ▼
                            ┌──────────────────┐
                            │  Exit Code Logic  │
                            │  Critical/High→1  │
                            │  Medium/Low→0     │
                            └──────────────────┘
```

### Runtime Authorization

```
Agent Action Request
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  API Server / SDK Middleware                         │
│  • Authenticate (API key)                           │
│  • Rate limit (token bucket)                        │
│  • Parse request                                    │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│  Authorization Service (PDP)                         │
│  1. Check decision cache (LRU)                      │
│  2. Resolve effective permissions                   │
│  3. Evaluate policy engine (YAML rules)             │
│  4. Calculate risk score (multi-dimensional)        │
│  5. Check behavior baseline for anomalies           │
│  6. Apply enforcement mode (monitor/enforce)        │
└───────────────────────┬─────────────────────────────┘
                        │
              ┌─────────┼─────────┐
              │         │         │
              ▼         ▼         ▼
         ┌────────┐ ┌────────┐ ┌────────────┐
         │ ALLOW  │ │  DENY  │ │  STEP_UP   │
         │        │ │        │ │ (approval) │
         └────────┘ └────────┘ └─────┬──────┘
                                     │
                                     ▼
                            ┌──────────────────┐
                            │ Approval Service  │
                            │ Human-in-loop     │
                            └──────────────────┘
```

---

## Decision Pipeline

The authorization decision follows a strict evaluation order:

```
1. Cache Check
   └─ Hit? → Return cached decision (< 1ms)
   └─ Miss? → Continue

2. Effective Permission Resolution
   └─ Explicit DENY in any layer? → DENY (short-circuit)
   └─ No ALLOW across identity + SCP + boundary? → DENY

3. Policy Engine Evaluation (priority-ordered)
   └─ First matching DENY rule → DENY
   └─ First matching REQUIRE_APPROVAL rule → STEP_UP
   └─ First matching WARN rule → ALLOW + emit warning
   └─ First matching AUDIT rule → ALLOW + emit audit event
   └─ First matching ALLOW rule → Continue to risk check
   └─ No match → Apply default (configurable)

4. Risk Scoring
   └─ Score > critical_threshold → DENY
   └─ Score > high_threshold → STEP_UP
   └─ Toxic combination detected → DENY

5. Behavior Analysis
   └─ Anomaly score > threshold → STEP_UP or DENY
   └─ Normal behavior → Continue

6. Final Decision
   └─ Emit audit event
   └─ Update metrics
   └─ Cache decision
   └─ Return to caller
```

---

## Integration Points

| Integration | Protocol | Description |
|-------------|----------|-------------|
| CI/CD (GitHub Actions) | CLI exit code + SARIF upload | Block PRs on critical/high findings |
| CI/CD (GitLab, Jenkins) | CLI exit code + JSON/SARIF | Same gate behavior, different upload |
| Boto3 SDK | Python middleware (GuardedSession) | Transparent authorization on every AWS call |
| REST API | HTTP/JSON on port 8080 | Language-agnostic authorization endpoint |
| Prometheus | HTTP metrics on port 9090 | `/v1/metrics` endpoint in exposition format |
| Grafana | Prometheus data source | Pre-built dashboards for authorization metrics |
| Redis | TCP 6379 | Decision caching and session state |
| CloudTrail | Log correlation | Drift detection, CloudTrail-based unused permission analysis |
| SNS/Webhooks | HTTP POST | Drift and anomaly alerting |
| n8n | Workflow automation | IAM posture scanning workflow |
| GitHub Code Scanning | SARIF 2.1 | Inline PR annotations |

---

## Performance Characteristics

| Metric | Target | Notes |
|--------|--------|-------|
| Single policy scan (static) | < 50 ms | Pure Python, zero dependencies |
| 100 policies batch scan | < 2 s | Linear scaling |
| Authorization (cached) | < 1 ms | LRU cache hit |
| Authorization (uncached) | < 10 ms | Full pipeline evaluation |
| Throughput | > 10,000 req/s | Per instance, cached decisions |
| Memory (scanner) | < 30 MB RSS | Minimal object allocation |
| Memory (API server) | < 512 MB | Bounded buffers, LRU eviction |
| Startup time | < 2 s | Lazy module loading via `__getattr__` |

---

## Availability Model

### Standalone Deployment

- Single container deployment with health checks
- Liveness: `GET /v1/health` (process alive, basic sanity)
- Readiness: `GET /v1/health/ready` (dependencies connected, policies loaded)
- Restart policy: `unless-stopped` (Docker) / `Always` (Kubernetes)

### High Availability (Production)

```
┌─────────────────────────────────────────────────────────┐
│                   Load Balancer (ALB)                     │
└──────────┬──────────────┬──────────────┬────────────────┘
           │              │              │
    ┌──────▼──────┐┌─────▼──────┐┌─────▼──────┐
    │  Guard API  ││  Guard API  ││  Guard API  │
    │  (Pod 1)    ││  (Pod 2)    ││  (Pod 3)    │
    └──────┬──────┘└─────┬──────┘└─────┬──────┘
           │              │              │
    ┌──────▼──────────────▼──────────────▼──────┐
    │             Redis Cluster                   │
    │       (decision cache, state)              │
    └────────────────────────────────────────────┘
```

- **Minimum replicas**: 3 (configurable)
- **Auto-scaling**: HPA on CPU (70%) and memory (80%), up to 10 replicas
- **Fail mode**: Configurable per deployment
  - `fail_closed` (production default): Deny all if enforcement unavailable
  - `fail_open` (development): Allow all if enforcement unavailable
- **Circuit breaker**: Protects against cascading failures when backend services are degraded
  - States: CLOSED → OPEN → HALF_OPEN → CLOSED
  - Trips after configurable failure threshold
  - Auto-recovery probe in HALF_OPEN state

### Failure Modes

| Failure | Behavior (fail_closed) | Behavior (fail_open) |
|---------|------------------------|---------------------|
| Redis unavailable | Evaluate without cache (slower) | Same |
| Policy file corrupt | Reject all (last-known-good if available) | Allow all |
| High latency | Circuit breaker trips → deny | Circuit breaker → allow |
| OOM | Container restarts, LB routes away | Same |

---

## Security Model

### Authentication

- API key authentication via `X-API-Key` header
- Correlation ID tracking via `X-Correlation-ID` header
- All API keys validated against in-memory store (pluggable backend)

### Authorization (Internal)

- Rate limiting per client IP (token bucket algorithm)
- Default: 100 tokens, refill 10/s per client
- Configurable via Helm values and environment variables

### Data Protection

- No secrets stored in application state
- Policy files mounted read-only (`ro` volume mount)
- Audit trail with cryptographic hash chaining (tamper-evident)
- Structured logging with no PII/credential leakage

### Container Security

- Non-root execution (`USER guard`)
- Minimal base image (`python:3.12-slim`)
- No shell access in production image
- Resource limits enforced (CPU/memory)
- Read-only filesystem where possible

### Network Security

- Internal-only ALB (no public exposure)
- ClusterIP service type (Kubernetes)
- Metrics endpoint on separate port (9090)
- Health probes accessible only within cluster

### Supply Chain

- Zero runtime dependencies (core scanner)
- Optional `boto3` only for live scanning
- Dependabot enabled for dev dependencies
- Container image signed and scanned via CI

### Trust Boundaries

```
┌────────────────────────────────────────────────────────────┐
│  Trust Boundary: Network Perimeter                          │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Trust Boundary: Application                          │  │
│  │                                                      │  │
│  │  ┌────────────┐    ┌─────────────────┐              │  │
│  │  │  API Layer │───▶│ Decision Engine │              │  │
│  │  │  (authn)   │    │ (core logic)    │              │  │
│  │  └────────────┘    └─────────────────┘              │  │
│  │                                                      │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Trust Boundary: Data Stores                          │  │
│  │  Redis (cache) · Policy files (read-only)            │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
└────────────────────────────────────────────────────────────┘
```
