# AWS Agent Identity Guard SDK

Python SDK for runtime authorization of AI agents. Provides thread-safe
authorization checks, agent registration, risk scoring, and attack path analysis.

## Installation

```bash
pip install aws-agent-identity-guard-sdk
```

## Quick Start

```python
from aws_agent_identity_guard import AgentIdentityGuard

guard = AgentIdentityGuard(
    endpoint="http://localhost:8000",
    api_key="your-api-key",
)

# Authorize an agent action
decision = guard.authorize(
    agent="data-processing-agent",
    action="s3:GetObject",
    resource="arn:aws:s3:::my-bucket/data.csv",
)

if decision.decision == "ALLOW":
    print("Action authorized")
else:
    print(f"Denied: {decision.explanation}")
```

## Decorator Usage

```python
@guard.protect(agent="my-agent", action="s3:GetObject")
def read_s3_object(bucket, key):
    # Only executes if authorized
    ...
```

## Context Manager

```python
with guard.transaction("my-agent", "s3:PutObject", "arn:aws:s3:::bucket/key") as txn:
    if txn.allowed:
        upload_file()
```

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| endpoint | http://localhost:8000 | Guard service URL |
| api_key | None | Authentication key |
| timeout | 5.0 | Request timeout (seconds) |
| fail_open | False | Allow actions when service unreachable |

## License

Apache-2.0
