# API Reference

Base URL: `http://localhost:8000` (development) or your deployed endpoint.

All endpoints are prefixed with `/v1/` for versioned APIs. Health and metrics endpoints are unversioned.

---

## Authentication

### API Key

Pass the API key in the `X-API-Key` header:

```
X-API-Key: your-api-key-here
```

API keys are scoped to specific operations (read-only, authorize, admin). Rotate keys via the `/v1/admin/keys` endpoint or environment variable `AGENT_GUARD_API_KEYS`.

### mTLS

For production deployments, configure mutual TLS:

```yaml
# config.yaml
tls:
  enabled: true
  cert_file: /certs/server.crt
  key_file: /certs/server.key
  ca_file: /certs/ca.crt
  require_client_cert: true
```

---

## Rate Limiting

| Tier | Limit | Window |
|------|-------|--------|
| Default | 10,000 requests | per minute |
| Authorize | 50,000 requests | per minute |
| Admin | 1,000 requests | per minute |

Rate limit headers returned on every response:

```
X-RateLimit-Limit: 10000
X-RateLimit-Remaining: 9847
X-RateLimit-Reset: 1693000000
```

When exceeded, returns `429 Too Many Requests`.

---

## Common Headers

| Header | Direction | Description |
|--------|-----------|-------------|
| `X-API-Key` | Request | Authentication |
| `X-Correlation-ID` | Request/Response | Distributed tracing ID (auto-generated if missing) |
| `X-Request-Duration-Ms` | Response | Server-side processing time |
| `Content-Type` | Both | Always `application/json` |

---

## Endpoints

### POST /v1/authorize

Authorize an agent action. This is the primary endpoint called on every agent request.

**Request:**

```json
{
  "agent_id": "agent-bedrock-001",
  "principal": "arn:aws:iam::123456789012:role/AgentRole",
  "tool": "data-retrieval",
  "action": "s3:GetObject",
  "resource": "arn:aws:s3:::my-bucket/data.json",
  "data_classification": "CONFIDENTIAL",
  "context": {
    "session_id": "sess-abc123",
    "source_ip": "10.0.1.50"
  }
}
```

**Response (200 OK):**

```json
{
  "decision": "ALLOW",
  "risk_score": 32.5,
  "risk_details": {
    "permission_score": 20.0,
    "network_score": 10.0,
    "data_score": 45.0,
    "behavior_score": 15.0
  },
  "reasons": [],
  "policy": "allow-read-data",
  "explanation": "Action permitted by policy allow-read-data; risk within threshold.",
  "correlation_id": "corr-7f3a2b1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c"
}
```

**Response (200 OK -- denied):**

```json
{
  "decision": "DENY",
  "risk_score": 85.0,
  "risk_details": {
    "permission_score": 90.0,
    "network_score": 60.0,
    "data_score": 95.0,
    "behavior_score": 70.0
  },
  "reasons": [
    "Policy deny-admin-actions explicitly blocks iam:* actions",
    "Risk score 85.0 exceeds threshold 70.0"
  ],
  "policy": "deny-admin-actions",
  "explanation": "Administrative actions blocked in production.",
  "correlation_id": "corr-1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"
}
```

---

### POST /v1/agents

Register a new agent identity.

**Request:**

```json
{
  "name": "data-analyst-agent",
  "agent_type": "BEDROCK",
  "owner": "data-team",
  "environment": "PRODUCTION",
  "purpose": "Analyze customer data and generate reports",
  "description": "Bedrock agent for quarterly data analysis",
  "iam_role_arn": "arn:aws:iam::123456789012:role/DataAnalystAgent",
  "data_classification": "CONFIDENTIAL",
  "declared_capabilities": ["s3:GetObject", "athena:StartQueryExecution"],
  "tags": {"team": "data", "cost-center": "analytics"}
}
```

**Response (201 Created):**

```json
{
  "agent_id": "agent-a1b2c3d4",
  "name": "data-analyst-agent",
  "agent_type": "BEDROCK",
  "owner": "data-team",
  "environment": "PRODUCTION",
  "purpose": "Analyze customer data and generate reports",
  "description": "Bedrock agent for quarterly data analysis",
  "iam_role_arn": "arn:aws:iam::123456789012:role/DataAnalystAgent",
  "data_classification": "CONFIDENTIAL",
  "declared_capabilities": ["s3:GetObject", "athena:StartQueryExecution"],
  "tags": {"team": "data", "cost-center": "analytics"},
  "created_at": "2026-08-20T12:00:00Z",
  "updated_at": "2026-08-20T12:00:00Z",
  "risk_score": null,
  "risk_level": null
}
```

---

### GET /v1/agents

List all registered agents. Supports pagination.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 50 | Max results per page |
| `offset` | int | 0 | Pagination offset |
| `environment` | string | - | Filter by environment |
| `agent_type` | string | - | Filter by type |

**Response (200 OK):**

```json
{
  "agents": [...],
  "total": 142,
  "limit": 50,
  "offset": 0
}
```

---

### GET /v1/agents/{agent_id}

Get full details for a specific agent.

**Response (200 OK):** Same schema as registration response, with populated risk_score and risk_level.

**Response (404 Not Found):**

```json
{
  "detail": "Agent not found",
  "correlation_id": "corr-..."
}
```

---

### PUT /v1/agents/{agent_id}

Update agent metadata. Partial updates supported.

**Request:** Same schema as registration (all fields optional).

**Response (200 OK):** Updated agent object.

---

### DELETE /v1/agents/{agent_id}

Deregister an agent. This revokes all active permissions and cancels pending approvals.

**Response (204 No Content)**

---

### POST /v1/approvals

Create a step-up approval request.

**Request:**

```json
{
  "agent_id": "agent-bedrock-001",
  "action": "iam:PassRole",
  "resource": "arn:aws:iam::123456789012:role/AdminRole",
  "requester": "authorization-engine",
  "ttl_seconds": 300
}
```

**Response (201 Created):**

```json
{
  "approval_id": "apr-9f8e7d6c",
  "agent_id": "agent-bedrock-001",
  "action": "iam:PassRole",
  "resource": "arn:aws:iam::123456789012:role/AdminRole",
  "status": "PENDING",
  "requester": "authorization-engine",
  "created_at": "2026-08-20T12:00:00Z",
  "expires_at": "2026-08-20T12:05:00Z"
}
```

---

### PUT /v1/approvals/{approval_id}

Approve or reject a pending request.

**Request:**

```json
{
  "status": "APPROVED",
  "reviewer": "security-team@example.com",
  "reason": "One-time access approved for quarterly report generation"
}
```

**Response (200 OK):** Updated approval object.

---

### GET /v1/approvals

List approval requests.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | `PENDING` | Filter: PENDING, APPROVED, REJECTED, EXPIRED |
| `agent_id` | string | - | Filter by agent |
| `limit` | int | 50 | Max results |

---

### GET /v1/agents/{agent_id}/risk

Get current risk score for an agent.

**Response (200 OK):**

```json
{
  "agent_id": "agent-bedrock-001",
  "overall_score": 45,
  "permission_score": 30,
  "network_score": 20,
  "data_score": 65,
  "behavior_score": 25,
  "level": "MEDIUM",
  "factors": [
    "Access to CONFIDENTIAL data",
    "Cross-account role assumption capability"
  ],
  "recommendation": "Restrict s3:* to specific bucket prefixes"
}
```

---

### GET /v1/agents/{agent_id}/attack-paths

Get privilege escalation paths involving this agent.

**Response (200 OK):**

```json
{
  "agent_id": "agent-bedrock-001",
  "paths": [
    {
      "path_id": "path-abc123",
      "severity": "HIGH",
      "description": "PassRole to admin role enables full account access",
      "steps": [
        "iam:PassRole on role/AdminRole",
        "sts:AssumeRole on role/AdminRole",
        "Full administrative access"
      ],
      "mitigations": [
        "Remove iam:PassRole capability",
        "Add resource constraint to PassRole"
      ],
      "risk_score": 85,
      "exploitability": "MEDIUM"
    }
  ]
}
```

---

### GET /v1/agents/{agent_id}/permissions

Get effective permissions for an agent.

**Response (200 OK):**

```json
{
  "agent_id": "agent-bedrock-001",
  "permissions": [
    {
      "permission_id": "perm-001",
      "action": "s3:GetObject",
      "resource": "arn:aws:s3:::data-bucket/*",
      "effect": "ALLOW",
      "conditions": {"StringEquals": {"s3:prefix": "reports/"}},
      "granted_at": "2026-08-01T00:00:00Z",
      "expires_at": null
    }
  ]
}
```

---

### GET /health

Health check endpoint for load balancers.

**Response (200 OK):**

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 86400,
  "checks": {
    "policy_store": "ok",
    "risk_engine": "ok",
    "agent_registry": "ok"
  }
}
```

---

### GET /metrics

Prometheus-format metrics.

```
# HELP agent_guard_decisions_total Total authorization decisions
# TYPE agent_guard_decisions_total counter
agent_guard_decisions_total{decision="ALLOW"} 145832
agent_guard_decisions_total{decision="DENY"} 2341
agent_guard_decisions_total{decision="STEP_UP"} 567

# HELP agent_guard_latency_seconds Authorization latency
# TYPE agent_guard_latency_seconds histogram
agent_guard_latency_seconds_bucket{le="0.005"} 120000
agent_guard_latency_seconds_bucket{le="0.01"} 145000
```

---

## Error Codes

| HTTP Status | Code | Description |
|-------------|------|-------------|
| 400 | `INVALID_REQUEST` | Malformed request body |
| 401 | `UNAUTHORIZED` | Missing or invalid API key |
| 403 | `FORBIDDEN` | API key lacks required scope |
| 404 | `NOT_FOUND` | Resource does not exist |
| 409 | `CONFLICT` | Agent already registered |
| 422 | `VALIDATION_ERROR` | Request validation failed |
| 429 | `RATE_LIMITED` | Rate limit exceeded |
| 500 | `INTERNAL_ERROR` | Server error |
| 503 | `SERVICE_UNAVAILABLE` | Dependency failure |

All error responses include:

```json
{
  "detail": "Human-readable error message",
  "code": "ERROR_CODE",
  "correlation_id": "corr-..."
}
```

---

## Versioning Strategy

- API version is in the URL path: `/v1/...`
- Breaking changes increment the version: `/v2/...`
- Non-breaking additions (new fields, new endpoints) do not increment
- Deprecated versions are supported for 12 months after successor release
- Version sunset is announced 6 months in advance via response header `X-API-Deprecated: true`
