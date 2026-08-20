# Python SDK Developer Guide

## Overview

The Agent Identity Guard Python SDK provides synchronous and asynchronous clients for AI agent authorization, governance, risk scoring, and policy management. It wraps the REST API with connection pooling, retry logic, and type-safe responses.

---

## Installation

### Basic (authorization only)

```bash
pip install agent-identity-guard
```

### With Boto3 Middleware

```bash
pip install agent-identity-guard[boto3]
```

### All Optional Dependencies

```bash
pip install agent-identity-guard[all]
```

### Development

```bash
pip install agent-identity-guard[dev]
```

### Requirements

- Python 3.10+
- `httpx >= 0.25.0, < 1.0.0` (automatically installed)
- `boto3 >= 1.28.0` (optional, for middleware)

---

## Quick Start

```python
from agent_identity_guard import AgentIdentityGuard

# Initialize the client
guard = AgentIdentityGuard(
    endpoint="http://localhost:8080",
    api_key="your-api-key",
    environment="production",
)

# Authorize an agent action
decision = guard.authorize(
    agent="invoice-processor",
    tool="s3:GetObject",
    resource="arn:aws:s3:::invoices-prod/2024/invoice-001.pdf",
    principal="user:jane@company.com",
    data_classification="CONFIDENTIAL",
)

if decision.allowed:
    print(f"Access granted (risk score: {decision.risk_score})")
elif decision.step_up_required:
    print(f"Approval needed: {decision.explanation}")
else:
    print(f"Access denied: {'; '.join(decision.reasons)}")
```

---

## authorize() Examples

### Basic Authorization

```python
decision = guard.authorize(
    agent="data-pipeline-agent",
    tool="dynamodb:PutItem",
    resource="arn:aws:dynamodb:us-east-1:123456789012:table/orders",
)

if decision.allowed:
    # Proceed with DynamoDB write
    pass
```

### With Full Context

```python
decision = guard.authorize(
    agent="ml-training-agent",
    tool="sagemaker:CreateTrainingJob",
    resource="arn:aws:sagemaker:us-east-1:123456789012:training-job/*",
    principal="role:ml-pipeline-role",
    data_classification="CONFIDENTIAL",
    context={
        "source_ip": "10.0.1.50",
        "session_id": "sess-abc123",
        "model_name": "fraud-detection-v2",
        "instance_type": "ml.p3.2xlarge",
    },
)
```

### Handling Step-Up (Approval Required)

```python
decision = guard.authorize(
    agent="cleanup-agent",
    tool="s3:DeleteBucket",
    resource="arn:aws:s3:::deprecated-data-bucket",
    data_classification="SECRET",
)

if decision.step_up_required:
    # Request human approval
    approval = guard.request_approval(
        agent="cleanup-agent",
        action="s3:DeleteBucket",
        resource="arn:aws:s3:::deprecated-data-bucket",
    )
    print(f"Approval request created: {approval.request_id}")
    print(f"Status: {approval.status}")
    # Wait for approval or implement callback
```

### Batch Authorization Pattern

```python
actions_to_authorize = [
    ("s3:GetObject", "arn:aws:s3:::data-lake/raw/file1.parquet"),
    ("s3:GetObject", "arn:aws:s3:::data-lake/raw/file2.parquet"),
    ("s3:PutObject", "arn:aws:s3:::data-lake/processed/output.parquet"),
]

results = []
for tool, resource in actions_to_authorize:
    decision = guard.authorize(
        agent="etl-pipeline",
        tool=tool,
        resource=resource,
        principal="role:etl-execution-role",
    )
    results.append((tool, resource, decision))

denied = [(t, r, d) for t, r, d in results if d.denied]
if denied:
    print(f"Blocked {len(denied)} actions:")
    for tool, resource, decision in denied:
        print(f"  {tool} on {resource}: {decision.reasons}")
```

---

## Boto3 Middleware

The `GuardedSession` automatically enforces authorization on every AWS API call made through boto3.

### Setup

```python
from agent_identity_guard import AgentIdentityGuard
from agent_identity_guard.middleware import GuardedSession

# Create the guard client
guard = AgentIdentityGuard(
    endpoint="http://localhost:8080",
    api_key="your-api-key",
    environment="production",
)

# Create a guarded boto3 session
session = GuardedSession(
    guard=guard,
    agent_id="invoice-processor",
    fail_mode="closed",            # "closed" = deny on guard failure
    principal="user:app-service",
    data_classification="CONFIDENTIAL",
)

# Use like a normal boto3 session  -  authorization happens transparently
s3 = session.client("s3")
```

### Transparent Authorization

```python
# This call is automatically authorized before execution
response = s3.get_object(Bucket="invoices-prod", Key="2024/invoice-001.pdf")

# If authorized, the call proceeds normally
body = response["Body"].read()
```

### Handling Denials

```python
from agent_identity_guard.middleware import AuthorizationDeniedError, StepUpRequiredError

try:
    s3.delete_bucket(Bucket="production-data")
except AuthorizationDeniedError as e:
    print(f"Blocked: {e.decision.reasons}")
    print(f"Risk score: {e.decision.risk_score}")
except StepUpRequiredError as e:
    print(f"Approval needed: {e.decision.explanation}")
```

### Fail Modes

| Mode | Behavior on Guard Failure |
|------|---------------------------|
| `closed` | Deny all requests (production default) |
| `open` | Allow all requests (development/testing) |

```python
# Production: deny if guard service is unreachable
session = GuardedSession(guard=guard, agent_id="prod-agent", fail_mode="closed")

# Development: allow through if guard is unavailable
session = GuardedSession(guard=guard, agent_id="dev-agent", fail_mode="open")
```

### Multiple Services

```python
# Same session works across all AWS services
s3 = session.client("s3")
dynamodb = session.client("dynamodb")
sqs = session.client("sqs")
lambda_client = session.client("lambda")

# Each call is authorized independently
s3.get_object(Bucket="data", Key="file.txt")
dynamodb.put_item(TableName="orders", Item={"id": {"S": "123"}})
```

---

## Error Handling

### Exception Hierarchy

```
AgentGuardError (base)
├── AuthorizationError     # 401/403 responses
├── ConnectionError        # Cannot reach the service
└── TimeoutError           # Request exceeded timeout
```

### Handling Errors

```python
from agent_identity_guard import (
    AgentIdentityGuard,
    AgentGuardError,
    AuthorizationError,
    ConnectionError,
    TimeoutError,
)

guard = AgentIdentityGuard(
    endpoint="http://localhost:8080",
    api_key="your-api-key",
    timeout=5.0,
    max_retries=3,
)

try:
    decision = guard.authorize(
        agent="my-agent",
        tool="s3:GetObject",
        resource="arn:aws:s3:::bucket/key",
    )
except AuthorizationError as e:
    # API key invalid or insufficient permissions
    print(f"Auth failed ({e.status_code}): {e}")
    print(f"Response: {e.response_body}")

except ConnectionError as e:
    # Service unreachable after all retries
    print(f"Cannot reach guard service: {e}")
    # Implement fallback logic

except TimeoutError as e:
    # All attempts timed out
    print(f"Timeout after 5s: {e}")
    # Implement fallback logic

except AgentGuardError as e:
    # Catch-all for other API errors (4xx/5xx)
    print(f"API error ({e.status_code}): {e}")
```

### Retry Behavior

The SDK automatically retries on transient failures:

| Status Code | Retried? | Description |
|-------------|----------|-------------|
| 429 | Yes | Rate limited |
| 500 | Yes | Internal server error |
| 502 | Yes | Bad gateway |
| 503 | Yes | Service unavailable |
| 504 | Yes | Gateway timeout |
| 401/403 | No | Authentication/authorization (not transient) |
| 400/404/422 | No | Client errors (not transient) |

Retry uses exponential backoff with full jitter:

```
delay = random(0, min(base * 2^attempt, max_delay))
```

- Default max retries: 3
- Default backoff base: 0.5s
- Default backoff max: 10s

### Custom Retry Configuration

```python
guard = AgentIdentityGuard(
    endpoint="http://localhost:8080",
    api_key="your-api-key",
    timeout=10.0,       # 10 second timeout per attempt
    max_retries=5,      # Up to 5 retries
)
```

---

## Async Usage

### AsyncAgentIdentityGuard

```python
import asyncio
from agent_identity_guard import AsyncAgentIdentityGuard

async def main():
    guard = AsyncAgentIdentityGuard(
        endpoint="http://localhost:8080",
        api_key="your-api-key",
        environment="production",
    )

    # Single authorization
    decision = await guard.authorize(
        agent="async-agent",
        tool="s3:GetObject",
        resource="arn:aws:s3:::data-bucket/file.csv",
    )

    print(f"Allowed: {decision.allowed}, Risk: {decision.risk_score}")

    # Clean up
    await guard.close()

asyncio.run(main())
```

### Async Context Manager

```python
async def process_batch():
    async with AsyncAgentIdentityGuard(
        endpoint="http://localhost:8080",
        api_key="your-api-key",
    ) as guard:
        # Client is automatically closed on exit
        decision = await guard.authorize(
            agent="batch-agent",
            tool="dynamodb:BatchWriteItem",
            resource="arn:aws:dynamodb:us-east-1:*:table/results",
        )
        return decision
```

### Concurrent Authorization

```python
import asyncio
from agent_identity_guard import AsyncAgentIdentityGuard

async def authorize_batch():
    async with AsyncAgentIdentityGuard(
        endpoint="http://localhost:8080",
        api_key="your-api-key",
    ) as guard:
        # Authorize multiple actions concurrently
        tasks = [
            guard.authorize(agent="etl", tool="s3:GetObject", resource=f"arn:aws:s3:::data/{i}.csv")
            for i in range(100)
        ]
        decisions = await asyncio.gather(*tasks)

        allowed = sum(1 for d in decisions if d.allowed)
        denied = sum(1 for d in decisions if d.denied)
        print(f"Authorized: {allowed}, Denied: {denied}")

asyncio.run(authorize_batch())
```

---

## Configuration

### Client Configuration Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `endpoint` | str | `http://localhost:8080` | Guard service URL |
| `api_key` | str | `""` | API key for authentication |
| `environment` | str | `production` | Environment label sent with requests |
| `timeout` | float | `5.0` | Request timeout (seconds) |
| `max_retries` | int | `3` | Maximum retry attempts |

### Connection Pooling

The sync client uses `httpx.Client` with connection pooling:

| Setting | Value |
|---------|-------|
| Max connections | 100 |
| Max keepalive | 20 |
| Keepalive expiry | 30s |

### Environment Variables

The SDK respects these environment variables as fallbacks:

| Variable | Maps To |
|----------|---------|
| `AGENT_GUARD_ENDPOINT` | `endpoint` |
| `AGENT_GUARD_API_KEY` | `api_key` |
| `AGENT_GUARD_ENVIRONMENT` | `environment` |
| `AGENT_GUARD_TIMEOUT` | `timeout` |

```python
import os
os.environ["AGENT_GUARD_ENDPOINT"] = "http://guard.internal:8080"
os.environ["AGENT_GUARD_API_KEY"] = "production-key"

# Client picks up env vars automatically when parameters aren't specified
guard = AgentIdentityGuard()
```

---

## Additional Operations

### Agent Management

```python
# Register a new agent
agent = guard.register_agent(
    name="invoice-processor",
    permissions=["s3:GetObject", "s3:PutObject", "dynamodb:PutItem"],
    environment="production",
    metadata={"team": "finance", "owner": "alice@company.com"},
)
print(f"Agent ID: {agent.agent_id}")

# Get agent details
agent = guard.get_agent("agt-abc123")

# List all agents
agents = guard.list_agents(limit=50, offset=0)
```

### Risk Assessment

```python
# Get risk score for an agent
risk = guard.get_risk_score("agt-abc123")
print(f"Risk score: {risk.score}/100")
print(f"Factors: {risk.factors}")
```

### Attack Path Analysis

```python
# Discover attack paths
paths = guard.get_attack_paths("agt-abc123")
for path in paths:
    print(f"[{path.severity}] {path.description}")
    for step in path.steps:
        print(f"  → {step}")
```

### Policy Scanning

```python
import json

# Scan a policy document
with open("agent-role-policy.json") as f:
    policy = json.load(f)

result = guard.scan_policy(policy)
if not result.compliant:
    print("Policy has issues:")
    for finding in result.findings:
        print(f"  ⚠ {finding}")
    for rec in result.recommendations:
        print(f"  → {rec}")
```

---

## Best Practices

1. **Reuse clients**  -  Create one `AgentIdentityGuard` instance and share it across your application. The connection pool handles concurrency.

2. **Set appropriate timeouts**  -  In hot paths, use shorter timeouts (1-2s) with `fail_mode="open"`. For security-critical paths, use longer timeouts (5-10s) with `fail_mode="closed"`.

3. **Handle all decision types**  -  Always check `denied`, `step_up_required`, and `allowed`. Don't assume `not denied == allowed`.

4. **Include context**  -  Richer context enables better policy evaluation. Include `data_classification`, `principal`, and relevant `context` fields.

5. **Use correlation IDs**  -  Pass your existing trace ID as `correlation_id` in the context for end-to-end tracing.

6. **Monitor the SDK**  -  Track authorization latency and error rates in your application metrics. Alert if denial rates spike unexpectedly.
