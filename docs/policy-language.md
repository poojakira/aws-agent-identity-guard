# Policy Language Reference

AWS Agent Identity Guard uses a declarative YAML-based policy language for access control decisions. Policies are evaluated at runtime on every authorization request.

---

## Syntax Specification

```yaml
version: "1.0"
metadata:
  name: "policy-set-name"
  description: "Description of this policy set"
  owner: "team-name"
  last_reviewed: "2026-08-01"

policies:
  - id: unique-policy-id
    effect: ALLOW | DENY | STEP_UP | REVIEW
    priority: 1-1000
    description: "Human-readable policy description"
    enabled: true | false
    conditions:
      # All conditions must match (logical AND)
      agent_id: "agent-*"
      agent_type: BEDROCK | LAMBDA | ECS | EKS | SAGEMAKER | CUSTOM
      environment: DEVELOPMENT | STAGING | PRODUCTION
      action_pattern: "s3:Get*"
      resource_pattern: "arn:aws:s3:::bucket-name/*"
      data_classification: PUBLIC | INTERNAL | CONFIDENTIAL | SECRET | REGULATED
      tags:
        key: "value"
      time_window:
        start: "09:00"
        end: "17:00"
        timezone: "UTC"
      risk_score:
        operator: lt | gt | lte | gte | eq
        value: 70
      source_ip:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
      capabilities:
        includes: ["s3:GetObject"]
        excludes: ["iam:*"]
```

---

## Effects

| Effect | Behavior | Use Case |
|--------|----------|----------|
| `ALLOW` | Permit the action | Normal authorized operations |
| `DENY` | Block the action | Explicit prohibitions, security boundaries |
| `STEP_UP` | Require human approval before allowing | Sensitive operations, elevated risk |
| `REVIEW` | Allow but flag for async security review | Audit trail, investigation triggers |

### Evaluation Order

1. All matching policies are collected
2. Sorted by priority (highest first)
3. Explicit DENY always wins regardless of priority
4. Among non-DENY policies, highest priority determines outcome
5. If no policies match, the default effect applies (configurable; default is DENY)

---

## Conditions

### action_pattern

Glob pattern matching against the IAM action string.

```yaml
conditions:
  action_pattern: "s3:Get*"        # Matches s3:GetObject, s3:GetBucketPolicy
  action_pattern: "iam:*"          # Matches all IAM actions
  action_pattern: "s3:PutObject"   # Exact match
```

### resource_pattern

Glob pattern matching against the resource ARN.

```yaml
conditions:
  resource_pattern: "arn:aws:s3:::my-bucket/*"
  resource_pattern: "arn:aws:s3:::*-prod-*"
  resource_pattern: "arn:aws:iam::123456789012:role/*"
```

### environment

Match agent's deployment environment.

```yaml
conditions:
  environment: PRODUCTION

# Or multiple (OR logic within this condition):
conditions:
  environment:
    - STAGING
    - PRODUCTION
```

### agent_type

Match the agent execution environment.

```yaml
conditions:
  agent_type: BEDROCK

# Multiple:
conditions:
  agent_type:
    - BEDROCK
    - LAMBDA
```

### agent_id

Glob pattern matching against agent identifier.

```yaml
conditions:
  agent_id: "agent-bedrock-*"
  agent_id: "agent-data-analyst-001"
```

### data_classification

Match the data sensitivity level of the request.

```yaml
conditions:
  data_classification: CONFIDENTIAL

# Multiple (OR):
conditions:
  data_classification:
    - CONFIDENTIAL
    - SECRET
    - REGULATED
```

### tags

Match agent metadata tags. All specified tags must match (AND).

```yaml
conditions:
  tags:
    team: "data-engineering"
    cost-center: "analytics"
```

### time_window

Restrict policy to specific time ranges.

```yaml
conditions:
  time_window:
    start: "09:00"
    end: "17:00"
    timezone: "America/New_York"
    days:
      - Monday
      - Tuesday
      - Wednesday
      - Thursday
      - Friday
```

### risk_score

Condition based on computed risk score.

```yaml
conditions:
  risk_score:
    operator: gt
    value: 70
```

Operators: `lt`, `gt`, `lte`, `gte`, `eq`

### source_ip

Match request source IP against CIDR ranges.

```yaml
conditions:
  source_ip:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
```

### capabilities

Match against agent's declared capabilities.

```yaml
conditions:
  capabilities:
    includes: ["s3:GetObject", "s3:PutObject"]
    excludes: ["iam:*", "sts:AssumeRole"]
```

---

## Examples

### Block All Admin Actions in Production

```yaml
policies:
  - id: deny-admin-production
    effect: DENY
    priority: 1000
    description: "No administrative actions in production"
    conditions:
      action_pattern: "iam:*"
      environment: PRODUCTION
```

### Allow Read-Only S3 Access

```yaml
policies:
  - id: allow-s3-reads
    effect: ALLOW
    priority: 50
    description: "Permit S3 read operations on approved buckets"
    conditions:
      action_pattern: "s3:Get*"
      resource_pattern: "arn:aws:s3:::approved-data-*"
      data_classification:
        - PUBLIC
        - INTERNAL
```

### Step-Up for Cross-Account Access

```yaml
policies:
  - id: step-up-cross-account
    effect: STEP_UP
    priority: 200
    description: "Require approval for cross-account operations"
    conditions:
      action_pattern: "sts:AssumeRole"
      resource_pattern: "arn:aws:iam::*:role/*"
```

### Time-Based Restrictions

```yaml
policies:
  - id: deny-after-hours
    effect: DENY
    priority: 300
    description: "Block sensitive operations outside business hours"
    conditions:
      data_classification:
        - SECRET
        - REGULATED
      time_window:
        start: "18:00"
        end: "08:00"
        timezone: "UTC"
```

### Risk-Based Escalation

```yaml
policies:
  - id: escalate-high-risk
    effect: STEP_UP
    priority: 500
    description: "Require approval when risk score exceeds threshold"
    conditions:
      risk_score:
        operator: gt
        value: 70
      environment: PRODUCTION
```

### Agent-Type Specific Permissions

```yaml
policies:
  - id: bedrock-agent-limits
    effect: DENY
    priority: 400
    description: "Bedrock agents cannot modify IAM"
    conditions:
      agent_type: BEDROCK
      action_pattern: "iam:Put*"
```

---

## Testing Policies

### Dry-Run Mode

Test policies without enforcement:

```bash
agent-identity-guard policy test \
  --policy-file policies/production.yaml \
  --request '{"agent_id":"agent-001","action":"s3:GetObject","resource":"arn:aws:s3:::bucket/key"}'
```

### Policy Validation

Validate syntax before deployment:

```bash
agent-identity-guard policy validate --policy-file policies/production.yaml
```

Output:

```
Policy set: production-agents
  - deny-admin-production: VALID
  - allow-s3-reads: VALID
  - step-up-cross-account: VALID
Total: 3 policies, 0 errors, 0 warnings
```

### Unit Testing Policies

```python
from aws_agent_identity_guard.policy_engine import PolicyEngine

engine = PolicyEngine()
engine.load_policies("policies/production.yaml")

# Test that admin actions are denied
result = engine.evaluate(
    agent_id="agent-001",
    action="iam:CreateUser",
    resource="arn:aws:iam::123456789012:user/test",
    environment="PRODUCTION"
)
assert result.effect == "DENY"
assert result.policy_id == "deny-admin-production"
```

---

## Versioning

- Policy files include a `version` field for schema version
- Policy sets are versioned independently of the application
- Changes are tracked via git; each commit is an auditable change
- Hot-reload: the engine watches for file changes and reloads without restart
- Rollback: revert to previous git commit to restore prior policy state
- Policy history is retained in audit logs (before/after on each change)

### Schema Versions

| Version | Changes |
|---------|---------|
| 1.0 | Initial release: effects, conditions, priorities |
| 1.1 (planned) | Add `unless` blocks for condition negation |
| 1.2 (planned) | Add policy inheritance and composition |
