# Architecture

## System Overview

AWS Agent Identity Guard is a runtime authorization platform that intercepts every AI agent action and evaluates it against policies, risk models, and behavioral baselines before allowing execution.

```
                                  +---------------------------+
                                  |      Control Plane        |
                                  |  (Policy CRUD, Agent Mgmt)|
                                  +---------------------------+
                                               |
+----------+    +----------+    +-----------------------------+    +------------------+
|  Agent   | -> |   SDK    | -> |     Authorization API       | -> |   Audit Store    |
| Workload |    | (Python) |    |   (FastAPI, /v1/authorize)  |    | (Structured Log) |
+----------+    +----------+    +-----------------------------+    +------------------+
                                     |           |          |
                          +----------+    +------+------+   +----------+
                          |               |             |              |
                   +------v------+  +-----v------+  +--v---------+  +-v-----------+
                   | Policy      |  | Risk       |  | Attack     |  | Escalation  |
                   | Engine      |  | Engine     |  | Path       |  | Detection   |
                   +-------------+  +------------+  | Analyzer   |  +-------------+
                          |               |         +------------+
                   +------v------+  +-----v------+
                   | Policy      |  | Behavior   |
                   | Store       |  | Baselines  |
                   +-------------+  +------------+
```

---

## Data Flow: Authorization Request

1. **Agent SDK** sends POST to `/v1/authorize` with agent_id, action, resource, context
2. **API layer** validates request, assigns correlation_id, starts latency timer
3. **Agent Registry** resolves agent identity, verifies binding to IAM role
4. **Policy Engine** evaluates all matching policies in priority order
   - Explicit DENY short-circuits evaluation
   - Conditions checked: action_pattern, resource_pattern, environment, data_classification, time_window
5. **Risk Engine** computes multi-dimensional score:
   - Permission score (breadth of access)
   - Network score (cross-account, cross-region)
   - Data score (classification sensitivity)
   - Behavior score (deviation from baseline)
6. **Attack Path Analyzer** checks for privilege escalation chains involving this action
7. **Escalation Engine** evaluates if action matches known escalation patterns
8. **Decision Aggregation**: combine policy effect + risk score + escalation signals
   - ALLOW: policy permits, risk acceptable, no escalation
   - DENY: explicit policy deny, or risk exceeds threshold
   - STEP_UP: risk is elevated, human approval required
   - REVIEW: flagged for async security review
9. **Audit**: decision logged with full context, correlation_id, latency
10. **Response** returned to SDK within SLA (p99 < 10ms)

---

## Component Descriptions

### Authorization Engine (`authorization.py`)

Central orchestrator. Manages request lifecycle, coordinates sub-engines, handles fallback modes (fail-open vs fail-closed), maintains latency tracking.

- Supports modes: ENFORCE, AUDIT, DRY_RUN
- Circuit breaker for downstream failures
- Configurable timeout per request

### Policy Engine (`policy_engine.py`)

Evaluates declarative YAML policies against authorization requests.

- Priority-based evaluation (higher priority wins)
- Condition types: action_pattern, resource_pattern, environment, data_classification, time_window, agent_type, tags
- Effects: ALLOW, DENY, STEP_UP, REVIEW
- Policy versioning and hot-reload
- Conflict resolution: explicit DENY > STEP_UP > ALLOW

### Risk Engine (`risk_engine.py`)

Computes risk scores across four dimensions, weighted and normalized to 0-100.

- Permission risk: action breadth, wildcard usage, admin-level access
- Network risk: cross-account, cross-region, internet-facing
- Data risk: classification level, volume, destination
- Behavior risk: deviation from historical patterns

### Attack Path Analyzer (`attack_paths.py`)

Graph-based analysis of privilege escalation chains.

- Builds permission graph from agent capabilities
- Identifies multi-step escalation paths (e.g., PassRole -> AssumeRole -> AdminAccess)
- Severity classification: LOW, MEDIUM, HIGH, CRITICAL
- Caches results with TTL for performance

### Escalation Engine (`escalation_engine.py`)

Real-time pattern matching for privilege escalation attempts.

- Known patterns: PassRole chains, STS abuse, cross-account pivots
- Configurable sensitivity levels
- Integration with alert channels

### Approval Manager (`approval.py`)

Human-in-the-loop workflow for STEP_UP decisions.

- Time-bounded approval requests with TTL
- Delegation chains (escalate if no response)
- Audit trail for all approval actions
- Integration with Slack, PagerDuty, SNS

### Drift Detector (`drift_detector.py`)

Monitors permission changes over time.

- Compares current permissions to baseline
- Alerts on unexpected grants or removals
- Tracks policy document changes
- Scheduled and event-driven modes

### Behavior Analyzer (`behavior_analyzer.py`)

Builds and evaluates behavioral baselines per agent.

- Action frequency histograms
- Resource access patterns
- Time-of-day anomalies
- Peer group comparison

### Intent Alignment (`intent_alignment.py`)

Verifies agent actions align with declared purpose.

- Purpose declaration at registration
- Action-to-purpose mapping rules
- Drift alerting when actions diverge from purpose

### Capability Inventory (`capability_inventory.py`)

Tracks declared vs actual capabilities.

- Registration-time capability declaration
- Runtime enforcement of capability boundaries
- Capability expansion requires approval

### Enforcement (`enforcement.py`)

Executes decisions and manages remediation.

- Inline enforcement (block request)
- Async enforcement (revoke permission, quarantine agent)
- Remediation playbooks

### Observability (`observability.py`)

Metrics, logging, and tracing infrastructure.

- Prometheus metrics (decisions/sec, latency histograms, error rates)
- Structured JSON logging with correlation IDs
- OpenTelemetry trace export
- Grafana dashboard integration

### API Layer (`api.py`)

FastAPI application with versioned endpoints.

- Request validation via Pydantic models
- CORS, rate limiting, API key auth
- OpenAPI/Swagger auto-generated docs
- Health and readiness probes

### SDK (`sdk.py`)

Production Python client.

- Thread-safe with connection pooling
- Configurable retries with exponential backoff
- Circuit breaker pattern
- Decorator and context manager interfaces
- Timeout configuration per-call

---

## Integration Points

| System | Integration Method | Purpose |
|--------|-------------------|---------|
| AWS IAM | STS, IAM APIs | Role binding, permission resolution |
| AWS Bedrock | Event hooks | Agent action interception |
| AWS Lambda | Extension layer | Request-level authorization |
| AWS ECS | Sidecar container | Transparent proxy |
| Prometheus | /metrics endpoint | Operational metrics |
| Grafana | Dashboard JSON | Visualization |
| Slack/PagerDuty | Webhook | Approval notifications |
| SIEM (Splunk, etc.) | Structured logs | Security event correlation |

---

## Storage Architecture

| Data | Store | Retention | Access Pattern |
|------|-------|-----------|----------------|
| Policies | YAML files / DynamoDB | Versioned indefinitely | Read-heavy, rare writes |
| Agent identities | In-memory + DynamoDB | Lifetime of agent | Read-heavy |
| Decisions (audit) | CloudWatch Logs / S3 | 90 days hot, 7 years cold | Write-heavy, rare reads |
| Risk baselines | In-memory + S3 | Rolling 30 days | Read on every request |
| Attack path cache | In-memory (LRU) | 5 min TTL | Read on every request |
| Approval state | DynamoDB | 7 days | Read/write balanced |

---

## HA and Scaling

- **Stateless API**: horizontal scaling via container replicas
- **Policy store**: read replicas with eventual consistency (< 1s propagation)
- **Risk baselines**: shared via S3 with local cache
- **Attack path cache**: per-instance LRU; cold start is acceptable (< 50ms)
- **Health checks**: /health endpoint for load balancer probes
- **Deployment**: rolling updates with zero downtime
- **Recommended sizing**:
  - Small (< 1000 agents): 2 replicas, 0.5 vCPU / 1 GB each
  - Medium (1000-10000 agents): 4 replicas, 1 vCPU / 2 GB each
  - Large (> 10000 agents): 8+ replicas with HPA, 2 vCPU / 4 GB each

---

## Performance Characteristics

| Operation | p50 | p95 | p99 | Notes |
|-----------|-----|-----|-----|-------|
| Full authorization | 2.1 ms | 4.8 ms | 8.3 ms | Policy + risk + attack path |
| Policy evaluation only | 0.5 ms | 0.8 ms | 1.2 ms | Cached policies |
| Risk scoring | 0.8 ms | 1.2 ms | 2.1 ms | With baseline lookup |
| Attack path (cached) | 0.3 ms | 1.5 ms | 3.1 ms | LRU cache hit |
| Attack path (cold) | 15 ms | 28 ms | 45 ms | Full graph traversal |
| Agent lookup | 0.1 ms | 0.2 ms | 0.4 ms | In-memory registry |

All measurements on c5.2xlarge, 4 uvicorn workers, Python 3.12.
