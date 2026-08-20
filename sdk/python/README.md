# agent-identity-guard

Python SDK for AWS Agent Identity Guard.

## Installation

```bash
pip install agent-identity-guard
```

## Quick Start

```python
from agent_identity_guard import AgentIdentityGuard

guard = AgentIdentityGuard(
    endpoint='http://localhost:8080',
    api_key='your-api-key'
)

# Authorize an agent action
decision = guard.authorize(
    agent='invoice-agent',
    tool='s3:GetObject',
    resource='arn:aws:s3:::invoices-prod/123.pdf'
)

if decision.denied:
    print(f"DENIED: {decision.explanation}")
elif decision.step_up_required:
    print(f"Approval needed: {decision.reasons}")
else:
    print("Authorized")
```

## Boto3 Middleware

```python
from agent_identity_guard.middleware import GuardedSession

session = GuardedSession(guard=guard, agent_id='invoice-agent')
client = session.client('s3')

# All calls automatically authorized
client.get_object(Bucket='invoices-prod', Key='123.pdf')
```

## Async Support

```python
from agent_identity_guard import AsyncAgentIdentityGuard

async with AsyncAgentIdentityGuard(endpoint='http://localhost:8080') as guard:
    decision = await guard.authorize(...)
```

## Documentation

Full documentation: https://github.com/poojakira/aws-agent-identity-guard/tree/main/docs
