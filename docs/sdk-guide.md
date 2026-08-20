# SDK Guide

Python SDK for AWS Agent Identity Guard. Thread-safe, production-ready client with retries, circuit breaker, and multiple usage patterns.

---

## Installation

```bash
pip install aws-agent-identity-guard-sdk
```

Or install from the monorepo:

```bash
pip install -e ./sdk/python
```

Requirements: Python 3.9+, `requests` >= 2.28.0

---

## Quick Start

```python
from aws_agent_identity_guard import AgentIdentityGuard

# Initialize
guard = AgentIdentityGuard(
    base_url="http://localhost:8000",
    api_key="your-api-key"
)

# Authorize an action
decision = guard.authorize(
    agent_id="agent-bedrock-001",
    action="s3:GetObject",
    resource="arn:aws:s3:::data-bucket/report.csv"
)

print(f"Decision: {decision.decision}")  # ALLOW, DENY, STEP_UP, or REVIEW
print(f"Risk: {decision.risk_score}")
print(f"Reasons: {decision.reasons}")
```

---

## All Methods

### authorize()

Make an authorization decision for an agent action.

```python
decision = guard.authorize(
    agent_id="agent-bedrock-001",
    action="s3:GetObject",
    resource="arn:aws:s3:::bucket/key",
    context={
        "data_classification": "CONFIDENTIAL",
        "session_id": "sess-123",
        "source_ip": "10.0.1.50"
    }
)
```

Returns: `Decision` dataclass with fields: `decision`, `risk_score`, `reasons`, `policy`, `explanation`, `correlation_id`

### register_agent()

Register a new agent identity.

```python
agent = guard.register_agent(
    name="data-analyst",
    agent_type="BEDROCK",
    owner="data-team",
    environment="PRODUCTION",
    purpose="Generate quarterly data reports",
    iam_role_arn="arn:aws:iam::123456789012:role/DataAnalyst",
    declared_capabilities=["s3:GetObject", "athena:StartQueryExecution"],
    data_classification="CONFIDENTIAL",
    tags={"team": "data", "cost-center": "analytics"}
)

print(f"Agent ID: {agent.agent_id}")
```

Returns: `AgentInfo` dataclass

### get_agent()

Retrieve agent details.

```python
agent = guard.get_agent("agent-bedrock-001")
```

Returns: `AgentInfo` dataclass

### list_agents()

List registered agents with optional filters.

```python
agents = guard.list_agents(
    environment="PRODUCTION",
    agent_type="BEDROCK",
    limit=50
)
```

Returns: `list[AgentInfo]`

### get_risk_score()

Get the current risk assessment for an agent.

```python
risk = guard.get_risk_score("agent-bedrock-001")

print(f"Overall: {risk.overall_score}")
print(f"Permission: {risk.permission_score}")
print(f"Behavior: {risk.behavior_score}")
print(f"Recommendation: {risk.recommendation}")
```

Returns: `RiskScoreInfo` dataclass

### get_attack_paths()

Get privilege escalation paths for an agent.

```python
paths = guard.get_attack_paths("agent-bedrock-001")

for path in paths:
    print(f"[{path.severity}] {path.description}")
    for step in path.steps:
        print(f"  -> {step}")
    for fix in path.mitigations:
        print(f"  FIX: {fix}")
```

Returns: `list[AttackPathInfo]`

### get_permissions()

Get effective permissions for an agent.

```python
permissions = guard.get_permissions("agent-bedrock-001")

for perm in permissions:
    print(f"{perm.effect} {perm.action} on {perm.resource}")
```

Returns: `list[PermissionInfo]`

### create_approval()

Create a step-up approval request.

```python
approval = guard.create_approval(
    agent_id="agent-bedrock-001",
    action="iam:PassRole",
    resource="arn:aws:iam::123456789012:role/AdminRole",
    requester="authorization-engine",
    ttl_seconds=300
)

print(f"Approval ID: {approval.approval_id}")
print(f"Expires: {approval.expires_at}")
```

Returns: `ApprovalInfo` dataclass

### resolve_approval()

Approve or reject a pending request.

```python
guard.resolve_approval(
    approval_id="apr-9f8e7d6c",
    status="APPROVED",
    reviewer="security-team@example.com",
    reason="One-time access for quarterly report"
)
```

### health_check()

Check service health.

```python
health = guard.health_check()
print(f"Status: {health['status']}")
```

Returns: `dict`

---

## Error Handling

The SDK raises typed exceptions for all failure modes:

```python
from aws_agent_identity_guard import (
    AgentIdentityGuard,
    GuardError,
    AuthorizationError,
    GuardConnectionError,
    GuardTimeoutError,
)

guard = AgentIdentityGuard(base_url="http://localhost:8000")

try:
    decision = guard.authorize(
        agent_id="agent-001",
        action="s3:GetObject",
        resource="arn:aws:s3:::bucket/key"
    )
except AuthorizationError as e:
    # Server returned an error (4xx/5xx)
    print(f"Auth error: {e.status_code} - {e.message}")
except GuardTimeoutError as e:
    # Request timed out
    print(f"Timeout after {e.timeout_seconds}s")
except GuardConnectionError as e:
    # Cannot reach the server
    print(f"Connection failed: {e}")
except GuardError as e:
    # Base exception for all SDK errors
    print(f"Guard error: {e}")
```

### Exception Hierarchy

```
GuardError (base)
  |-- AuthorizationError (server returned error)
  |-- GuardConnectionError (network failure)
  |-- GuardTimeoutError (deadline exceeded)
```

---

## Retry Configuration

The SDK includes built-in retry logic with exponential backoff.

```python
guard = AgentIdentityGuard(
    base_url="http://localhost:8000",
    max_retries=3,              # Number of retry attempts
    retry_backoff=0.5,          # Base backoff in seconds
    retry_on_status=[429, 503], # HTTP status codes to retry
    timeout=5.0                 # Per-request timeout in seconds
)
```

Retry behavior:
- Retries on connection errors and configured status codes
- Exponential backoff: `retry_backoff * 2^attempt` seconds
- Jitter added to prevent thundering herd
- Total timeout is `timeout * (max_retries + 1)` in worst case
- Non-retryable: 400, 401, 403, 404 (client errors)

---

## Decorator Pattern

Gate function execution behind authorization:

```python
from aws_agent_identity_guard import AgentIdentityGuard

guard = AgentIdentityGuard(base_url="http://localhost:8000")

@guard.authorize_action(
    agent_id="agent-bedrock-001",
    action="s3:GetObject",
    resource="arn:aws:s3:::data-bucket/*"
)
def fetch_report(report_id: str) -> dict:
    """Only executes if authorization succeeds."""
    return storage.get(f"reports/{report_id}.json")


# Raises AuthorizationError if denied
result = fetch_report("q4-2026")
```

### Dynamic Resource Resolution

```python
@guard.authorize_action(
    agent_id="agent-bedrock-001",
    action="s3:GetObject",
    resource_from_arg="bucket_path"  # Uses the named argument as resource
)
def fetch_data(bucket_path: str) -> bytes:
    return s3.get_object(Bucket="data", Key=bucket_path)
```

---

## Context Manager Pattern

For scoped authorization sessions:

```python
from aws_agent_identity_guard import AgentIdentityGuard

guard = AgentIdentityGuard(base_url="http://localhost:8000")

with guard.session(agent_id="agent-bedrock-001") as session:
    # All calls within this block share the same session context
    decision = session.authorize(
        action="s3:GetObject",
        resource="arn:aws:s3:::bucket/key"
    )

    if decision.decision == "ALLOW":
        data = s3.get_object(Bucket="bucket", Key="key")

    # Session automatically tracks actions for behavior analysis
```

---

## Advanced: Custom Transport

Override the HTTP transport for specialized environments:

```python
import requests.adapters

class CustomAdapter(requests.adapters.HTTPAdapter):
    def send(self, request, **kwargs):
        # Add custom headers, logging, or proxy logic
        request.headers["X-Custom-Header"] = "value"
        return super().send(request, **kwargs)

guard = AgentIdentityGuard(
    base_url="http://localhost:8000",
    session_adapter=CustomAdapter()
)
```

### mTLS Configuration

```python
guard = AgentIdentityGuard(
    base_url="https://agent-guard.internal.example.com",
    cert=("/path/to/client.crt", "/path/to/client.key"),
    verify="/path/to/ca-bundle.crt"
)
```

---

## Advanced: Mocking for Tests

Use the built-in mock for unit testing without a running server:

```python
from aws_agent_identity_guard import AgentIdentityGuard, Decision
from unittest.mock import patch, MagicMock

def test_my_function():
    mock_guard = MagicMock(spec=AgentIdentityGuard)
    mock_guard.authorize.return_value = Decision(
        decision="ALLOW",
        risk_score=25,
        reasons=[],
        policy="test-policy",
        explanation="Allowed by test",
        correlation_id="test-corr-id"
    )

    # Inject the mock into your application code
    result = my_function(guard=mock_guard)
    assert result is not None
    mock_guard.authorize.assert_called_once()
```

### Using responses Library

```python
import responses

@responses.activate
def test_authorize_allowed():
    responses.add(
        responses.POST,
        "http://localhost:8000/v1/authorize",
        json={
            "decision": "ALLOW",
            "risk_score": 20.0,
            "risk_details": {},
            "reasons": [],
            "policy": "allow-all-dev",
            "explanation": "Allowed in development",
            "correlation_id": "test-123"
        },
        status=200
    )

    guard = AgentIdentityGuard(base_url="http://localhost:8000")
    decision = guard.authorize(
        agent_id="test-agent",
        action="s3:GetObject",
        resource="arn:aws:s3:::test-bucket/key"
    )

    assert decision.decision == "ALLOW"
    assert decision.risk_score == 20
```

---

## Thread Safety

The SDK is fully thread-safe. A single `AgentIdentityGuard` instance can be shared across threads:

```python
import threading

guard = AgentIdentityGuard(base_url="http://localhost:8000")

def worker(agent_id: str):
    decision = guard.authorize(
        agent_id=agent_id,
        action="s3:GetObject",
        resource="arn:aws:s3:::bucket/key"
    )
    print(f"{agent_id}: {decision.decision}")

threads = [
    threading.Thread(target=worker, args=(f"agent-{i}",))
    for i in range(10)
]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

Connection pooling is managed internally via `requests.Session` with configurable pool size.
