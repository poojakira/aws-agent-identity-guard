# API Reference

## Overview

The Agent Identity Guard REST API provides runtime authorization, agent management, policy evaluation, and approval workflows. The server uses Python's built-in `http.server` module with zero external dependencies.

**Base URL:** `http://localhost:8080/v1`
**Metrics URL:** `http://localhost:9090/v1/metrics`

---

## Authentication

All API requests require authentication via the `X-API-Key` header.

```http
X-API-Key: your-api-key-here
```

Optional headers:

| Header | Description |
|--------|-------------|
| `X-Correlation-ID` | Client-generated trace ID for distributed tracing. If omitted, the server generates one. |
| `Content-Type` | Must be `application/json` for POST/PUT requests. |

### Authentication Errors

```json
{
  "error": "unauthorized",
  "message": "Invalid or missing API key",
  "status": 401
}
```

---

## Rate Limiting

Rate limiting uses a per-client-IP token bucket algorithm.

| Parameter | Default | Description |
|-----------|---------|-------------|
| Bucket capacity | 100 tokens | Maximum burst size |
| Refill rate | 10 tokens/sec | Steady-state throughput |

When rate limited, the API returns:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 1

{
  "error": "rate_limited",
  "message": "Rate limit exceeded. Retry after 1 second.",
  "status": 429
}
```

---

## Versioning

The API is versioned via URL path prefix (`/v1`). Breaking changes increment the version number. Non-breaking additions (new fields, new endpoints) do not change the version.

Current version: **v1**

---

## Endpoints

### Authorization

#### POST /v1/authorize

Authorize an agent action against the policy pipeline.

**Request:**

```json
{
  "agent": "invoice-processor",
  "tool": "s3:GetObject",
  "resource": "arn:aws:s3:::invoices-prod/2024/invoice-001.pdf",
  "principal": "user:jane@company.com",
  "data_classification": "CONFIDENTIAL",
  "context": {
    "environment": "production",
    "source_ip": "10.0.1.50",
    "session_id": "sess-abc123"
  },
  "correlation_id": "corr-550e8400-e29b-41d4-a716-446655440000"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent` | string | Yes | Agent identifier |
| `tool` | string | Yes | AWS action or tool being invoked |
| `resource` | string | Yes | Target resource ARN |
| `principal` | string | No | Identity on whose behalf the agent acts |
| `data_classification` | string | No | `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `SECRET`, `REGULATED` |
| `context` | object | No | Additional key-value context for policy evaluation |
| `correlation_id` | string | No | Client-provided trace ID |

**Response (200 OK  -  Allowed):**

```json
{
  "allowed": true,
  "denied": false,
  "step_up_required": false,
  "risk_score": 25,
  "reasons": [],
  "explanation": "Action permitted by policy 'allow-s3-read-invoices' with low risk score.",
  "correlation_id": "corr-550e8400-e29b-41d4-a716-446655440000",
  "cached": false,
  "evaluation_time_ms": 4.2
}
```

**Response (200 OK  -  Denied):**

```json
{
  "allowed": false,
  "denied": true,
  "step_up_required": false,
  "risk_score": 92,
  "reasons": [
    "Policy 'deny-wildcard-access' explicitly denies s3:* actions",
    "Risk score 92 exceeds critical threshold (85)"
  ],
  "explanation": "Denied: wildcard action on production S3 resources violates least-privilege policy.",
  "correlation_id": "corr-550e8400-e29b-41d4-a716-446655440000",
  "cached": false,
  "evaluation_time_ms": 6.8
}
```

**Response (200 OK  -  Step-Up Required):**

```json
{
  "allowed": false,
  "denied": false,
  "step_up_required": true,
  "risk_score": 72,
  "reasons": [
    "Policy 'require-approval-destructive' requires human approval for delete operations"
  ],
  "explanation": "Step-up authentication required. Submit approval request via POST /v1/approvals.",
  "approval_request_id": "apr-7f1c8a2e-4b9d-4f3a-8c1e-2d5f6a7b8c9d",
  "correlation_id": "corr-550e8400-e29b-41d4-a716-446655440000",
  "cached": false,
  "evaluation_time_ms": 8.1
}
```

---

### Agent Management

#### POST /v1/agents

Register a new agent.

**Request:**

```json
{
  "name": "invoice-processor",
  "permissions": [
    "s3:GetObject",
    "s3:PutObject",
    "dynamodb:PutItem"
  ],
  "environment": "production",
  "metadata": {
    "team": "finance",
    "workload_type": "BEDROCK_AGENT",
    "owner": "alice@company.com"
  }
}
```

**Response (201 Created):**

```json
{
  "agent_id": "agt-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "invoice-processor",
  "permissions": ["s3:GetObject", "s3:PutObject", "dynamodb:PutItem"],
  "environment": "production",
  "status": "ACTIVE",
  "metadata": {
    "team": "finance",
    "workload_type": "BEDROCK_AGENT",
    "owner": "alice@company.com"
  },
  "created_at": "2026-08-20T13:00:00Z"
}
```

#### GET /v1/agents

List all registered agents.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 100 | Maximum results per page |
| `offset` | int | 0 | Pagination offset |

**Response (200 OK):**

```json
{
  "agents": [
    {
      "agent_id": "agt-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "name": "invoice-processor",
      "status": "ACTIVE",
      "environment": "production",
      "permissions": ["s3:GetObject", "s3:PutObject", "dynamodb:PutItem"],
      "created_at": "2026-08-20T13:00:00Z"
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

#### GET /v1/agents/{agent_id}

Get details of a specific agent.

**Response (200 OK):**

```json
{
  "agent_id": "agt-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "invoice-processor",
  "status": "ACTIVE",
  "environment": "production",
  "permissions": ["s3:GetObject", "s3:PutObject", "dynamodb:PutItem"],
  "metadata": {
    "team": "finance",
    "workload_type": "BEDROCK_AGENT",
    "owner": "alice@company.com"
  },
  "risk_score": 25,
  "created_at": "2026-08-20T13:00:00Z",
  "last_activity": "2026-08-20T13:30:00Z"
}
```

#### GET /v1/agents/{agent_id}/permissions

Get effective permissions for an agent.

**Response (200 OK):**

```json
{
  "agent_id": "agt-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "effective_permissions": [
    {
      "action": "s3:GetObject",
      "resource": "arn:aws:s3:::invoices-prod/*",
      "effect": "ALLOW",
      "source": "identity_policy",
      "conditions": {
        "aws:SourceVpc": "vpc-abc123"
      }
    },
    {
      "action": "s3:PutObject",
      "resource": "arn:aws:s3:::invoices-prod/*",
      "effect": "ALLOW",
      "source": "identity_policy",
      "conditions": {}
    }
  ],
  "policy_layers_evaluated": ["identity_policy", "scp", "permission_boundary"]
}
```

#### GET /v1/agents/{agent_id}/attack-paths

Get discovered attack paths for an agent.

**Response (200 OK):**

```json
{
  "agent_id": "agt-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "attack_paths": [
    {
      "path_id": "atp-1234abcd",
      "description": "Privilege escalation via PassRole to Lambda execution role",
      "severity": "HIGH",
      "mitre_techniques": ["T1078", "T1648"],
      "steps": [
        "Agent uses iam:PassRole to assign admin-role to new Lambda",
        "Agent creates Lambda function with admin-role",
        "Lambda executes with admin privileges",
        "Agent invokes Lambda to perform privileged operations"
      ],
      "blast_radius": 3,
      "exploitability": "HIGH"
    }
  ],
  "total_paths": 1,
  "highest_severity": "HIGH"
}
```

#### GET /v1/agents/{agent_id}/risk

Get risk assessment for an agent.

**Response (200 OK):**

```json
{
  "agent_id": "agt-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "score": 42,
  "risk_level": "MEDIUM",
  "dimensions": {
    "privilege": 35,
    "sensitivity": 60,
    "blast_radius": 25,
    "data_exposure": 45,
    "persistence": 20,
    "lateral_movement": 30,
    "environment": 80
  },
  "factors": [
    "Access to CONFIDENTIAL data classification",
    "Production environment multiplier applied",
    "No cross-account access detected"
  ],
  "recommendations": [
    "Add aws:SourceVpc condition to S3 permissions",
    "Restrict s3:PutObject to specific prefix"
  ]
}
```

---

### Policy Management

#### POST /v1/policies

Upload a security policy.

**Request:**

```json
{
  "name": "deny-wildcard-production",
  "version": "1.0.0",
  "description": "Deny wildcard actions in production environments",
  "rules": [
    {
      "id": "deny-star-actions",
      "type": "deny",
      "actions": ["*:*"],
      "resources": ["*"],
      "conditions": {
        "environment": ["production"]
      },
      "message": "Wildcard actions are not permitted in production"
    }
  ]
}
```

**Response (201 Created):**

```json
{
  "policy_id": "pol-abc123def456",
  "name": "deny-wildcard-production",
  "version": "1.0.0",
  "status": "active",
  "rules_count": 1,
  "created_at": "2026-08-20T13:00:00Z"
}
```

#### GET /v1/policies

List all policies.

**Response (200 OK):**

```json
{
  "policies": [
    {
      "policy_id": "pol-abc123def456",
      "name": "deny-wildcard-production",
      "version": "1.0.0",
      "status": "active",
      "rules_count": 1,
      "priority": 100,
      "created_at": "2026-08-20T13:00:00Z"
    }
  ],
  "total": 1
}
```

#### POST /v1/policies/evaluate

Evaluate an action against loaded policies (dry-run).

**Request:**

```json
{
  "action": "s3:DeleteBucket",
  "resource": "arn:aws:s3:::production-data",
  "agent": "data-cleanup-agent",
  "environment": "production",
  "data_classification": "CONFIDENTIAL"
}
```

**Response (200 OK):**

```json
{
  "decision": "deny",
  "matched_rules": [
    {
      "policy_id": "pol-abc123def456",
      "rule_id": "deny-destructive-prod",
      "type": "deny",
      "message": "Destructive actions on production resources require explicit exception"
    }
  ],
  "evaluation_trace": [
    "Evaluated policy 'deny-wildcard-production' (priority 100)",
    "Rule 'deny-destructive-prod' matched: action=s3:DeleteBucket, env=production"
  ]
}
```

---

### Approval Workflow

#### GET /v1/approvals

List pending approvals.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | `PENDING` | Filter by status |
| `agent_id` | string |  -  | Filter by agent |
| `limit` | int | 50 | Max results |

**Response (200 OK):**

```json
{
  "approvals": [
    {
      "request_id": "apr-7f1c8a2e-4b9d-4f3a-8c1e-2d5f6a7b8c9d",
      "agent_id": "agt-a1b2c3d4",
      "action": "s3:DeleteBucket",
      "resource": "arn:aws:s3:::production-data",
      "status": "PENDING",
      "risk_score": 92,
      "requestor": "automation-pipeline",
      "reason": "Scheduled cleanup of deprecated bucket",
      "expires_at": "2026-08-20T14:00:00Z",
      "created_at": "2026-08-20T13:00:00Z"
    }
  ],
  "total": 1
}
```

#### POST /v1/approvals/{request_id}/approve

Approve a pending request.

**Request:**

```json
{
  "approver": "admin@company.com",
  "justification": "Approved per change request CR-4521",
  "conditions": {
    "valid_until": "2026-08-20T15:00:00Z",
    "max_invocations": 1
  }
}
```

**Response (200 OK):**

```json
{
  "request_id": "apr-7f1c8a2e-4b9d-4f3a-8c1e-2d5f6a7b8c9d",
  "status": "APPROVED",
  "approver": "admin@company.com",
  "approved_at": "2026-08-20T13:15:00Z",
  "valid_until": "2026-08-20T15:00:00Z"
}
```

#### POST /v1/approvals/{request_id}/deny

Deny a pending request.

**Request:**

```json
{
  "approver": "admin@company.com",
  "reason": "No valid change request found for this operation"
}
```

**Response (200 OK):**

```json
{
  "request_id": "apr-7f1c8a2e-4b9d-4f3a-8c1e-2d5f6a7b8c9d",
  "status": "DENIED",
  "approver": "admin@company.com",
  "denied_at": "2026-08-20T13:15:00Z",
  "reason": "No valid change request found for this operation"
}
```

---

### Observability

#### GET /v1/metrics

Prometheus-compatible metrics endpoint.

**Response (200 OK  -  text/plain):**

```
# HELP guard_requests_total Total authorization requests processed
# TYPE guard_requests_total counter
guard_requests_total{decision="ALLOW"} 15234
guard_requests_total{decision="DENY"} 892
guard_requests_total{decision="STEP_UP"} 45

# HELP guard_request_duration_seconds Authorization request latency
# TYPE guard_request_duration_seconds histogram
guard_request_duration_seconds_bucket{le="0.005"} 12000
guard_request_duration_seconds_bucket{le="0.01"} 14500
guard_request_duration_seconds_bucket{le="0.025"} 15800
guard_request_duration_seconds_bucket{le="0.05"} 16100
guard_request_duration_seconds_bucket{le="+Inf"} 16171
guard_request_duration_seconds_sum 82.45
guard_request_duration_seconds_count 16171

# HELP guard_agents_registered Total registered agents
# TYPE guard_agents_registered gauge
guard_agents_registered 12

# HELP guard_policies_loaded Total loaded policies
# TYPE guard_policies_loaded gauge
guard_policies_loaded 5

# HELP guard_cache_hit_ratio Decision cache hit ratio
# TYPE guard_cache_hit_ratio gauge
guard_cache_hit_ratio 0.78
```

#### GET /v1/health

Liveness probe.

**Response (200 OK):**

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 86400
}
```

#### GET /v1/health/ready

Readiness probe  -  confirms dependencies are available and policies are loaded.

**Response (200 OK):**

```json
{
  "status": "ready",
  "checks": {
    "policies_loaded": true,
    "redis_connected": true,
    "cache_warm": true
  }
}
```

**Response (503 Service Unavailable):**

```json
{
  "status": "not_ready",
  "checks": {
    "policies_loaded": true,
    "redis_connected": false,
    "cache_warm": false
  }
}
```

---

## Error Codes

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | `bad_request` | Malformed request body or missing required fields |
| 401 | `unauthorized` | Missing or invalid API key |
| 403 | `forbidden` | API key valid but insufficient permissions |
| 404 | `not_found` | Resource (agent, policy, approval) not found |
| 409 | `conflict` | Resource already exists or state conflict |
| 422 | `validation_error` | Request body valid JSON but fails schema validation |
| 429 | `rate_limited` | Token bucket exhausted |
| 500 | `internal_error` | Unexpected server error |
| 503 | `service_unavailable` | Server not ready (dependencies down) |

### Error Response Format

All errors follow a consistent format:

```json
{
  "error": "validation_error",
  "message": "Field 'agent' is required",
  "status": 422,
  "correlation_id": "corr-550e8400-e29b-41d4-a716-446655440000",
  "details": {
    "field": "agent",
    "constraint": "required"
  }
}
```

---

## SDKs

### Python SDK

```bash
pip install agent-identity-guard
```

```python
from agent_identity_guard import AgentIdentityGuard

guard = AgentIdentityGuard(
    endpoint="http://localhost:8080",
    api_key="your-api-key",
)

decision = guard.authorize(
    agent="invoice-processor",
    tool="s3:GetObject",
    resource="arn:aws:s3:::invoices-prod/123.pdf",
)
```

### Async Python SDK

```python
from agent_identity_guard import AsyncAgentIdentityGuard

guard = AsyncAgentIdentityGuard(
    endpoint="http://localhost:8080",
    api_key="your-api-key",
)

decision = await guard.authorize(
    agent="invoice-processor",
    tool="s3:GetObject",
    resource="arn:aws:s3:::invoices-prod/123.pdf",
)
```

### cURL

```bash
curl -X POST http://localhost:8080/v1/authorize \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "agent": "invoice-processor",
    "tool": "s3:GetObject",
    "resource": "arn:aws:s3:::invoices-prod/123.pdf"
  }'
```

### HTTPie

```bash
http POST localhost:8080/v1/authorize \
  X-API-Key:your-api-key \
  agent=invoice-processor \
  tool=s3:GetObject \
  resource=arn:aws:s3:::invoices-prod/123.pdf
```

---

## Pagination

List endpoints support cursor-based pagination:

| Parameter | Description |
|-----------|-------------|
| `limit` | Maximum items per page (default: 100, max: 1000) |
| `offset` | Number of items to skip |

Response includes total count for UI pagination:

```json
{
  "items": [...],
  "total": 250,
  "limit": 100,
  "offset": 0
}
```

---

## Idempotency

Authorization requests with the same `correlation_id` return cached results within the cache TTL window. This ensures idempotent retries without re-evaluation.

---

## WebSocket (Future)

A WebSocket endpoint for real-time drift and anomaly notifications is planned for v2:

```
ws://localhost:8080/v2/events
```
