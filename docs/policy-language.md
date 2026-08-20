# Policy-as-Code Language Reference

## Overview

Agent Identity Guard uses a YAML-based declarative policy language for defining security rules. Policies are evaluated in priority order against every authorization request, enabling fine-grained control over what AI agents can and cannot do.

---

## YAML Schema

### Policy Document Structure

```yaml
# Required metadata
apiVersion: v1
kind: SecurityPolicy
metadata:
  name: string                    # Unique policy name (kebab-case)
  version: string                 # Semantic version (e.g., "1.2.0")
  description: string             # Human-readable description
  author: string                  # Policy author
  created: datetime               # ISO 8601 timestamp
  labels:                         # Optional key-value labels
    team: string
    compliance: string

# Policy configuration
spec:
  priority: integer               # Evaluation order (lower = evaluated first)
  enabled: boolean                # Toggle policy on/off without deletion
  environments:                   # Optional: restrict to specific environments
    - production
    - staging
  
  rules:                          # One or more rules
    - id: string                  # Unique rule ID within policy
      type: deny | allow | require_approval | warn | audit
      description: string         # What this rule does
      
      match:                      # What this rule matches
        actions:                  # Action patterns (required)
          - string
        resources:                # Resource patterns (optional)
          - string
        agents:                   # Agent ID/name patterns (optional)
          - string
        principals:               # Principal patterns (optional)
          - string
      
      conditions:                 # When this rule applies (optional)
        environment: [string]
        data_classification: [string]
        workload_type: [string]
        time_window:
          days: [string]
          hours_utc: {start: int, end: int}
        risk_score:
          min: float
          max: float
        custom:                   # Arbitrary key-value conditions
          key: [value]
      
      message: string            # Human-readable explanation
      
      # Type-specific fields
      approval_config:           # Only for require_approval
        roles: [string]
        ttl_seconds: integer
        max_approvers: integer
      
      severity: string           # For warn/audit: CRITICAL|HIGH|MEDIUM|LOW
      notify: [string]           # Notification channels
```

---

## Rule Types

### deny

Explicitly blocks the action. No further evaluation occurs for this request once a deny rule matches.

```yaml
rules:
  - id: deny-wildcard-production
    type: deny
    description: Block wildcard actions in production
    match:
      actions:
        - "*:*"
        - "iam:*"
        - "s3:*"
    conditions:
      environment: [production]
    message: "Wildcard actions are prohibited in production environments"
```

**Behavior:**
- Returns `DENY` decision immediately
- Short-circuits all subsequent rule evaluation
- Logged as authorization denial in audit trail
- Increments `guard_requests_denied` metric

### allow

Explicitly permits the action. Allow rules only take effect if no deny rule has matched.

```yaml
rules:
  - id: allow-s3-read-invoices
    type: allow
    description: Allow invoice processing agent to read from invoices bucket
    match:
      actions:
        - "s3:GetObject"
        - "s3:ListBucket"
      resources:
        - "arn:aws:s3:::invoices-prod/*"
        - "arn:aws:s3:::invoices-prod"
      agents:
        - "invoice-processor"
    conditions:
      environment: [production, staging]
    message: "Permitted: invoice agent S3 read access"
```

**Behavior:**
- Allows the action to proceed
- Still subject to risk scoring (high risk may override)
- Logged in audit trail

### require_approval

Pauses the action and creates an approval request that must be fulfilled by a human before the action can proceed.

```yaml
rules:
  - id: require-approval-delete-production
    type: require_approval
    description: Require human approval for destructive actions in production
    match:
      actions:
        - "s3:DeleteBucket"
        - "s3:DeleteObject"
        - "dynamodb:DeleteTable"
        - "rds:DeleteDBInstance"
        - "ec2:TerminateInstances"
      resources:
        - "*"
    conditions:
      environment: [production]
      data_classification: [CONFIDENTIAL, SECRET, REGULATED]
    message: "Destructive action on sensitive production resource requires approval"
    approval_config:
      roles:
        - security-admin
        - team-lead
      ttl_seconds: 900
      max_approvers: 1
```

**Behavior:**
- Returns `STEP_UP` decision with approval request ID
- Creates time-limited approval request
- Action blocked until approved or TTL expires
- Approval is non-replayable (one-time use)

### warn

Allows the action but emits a warning event. Useful for monitoring potentially risky patterns before enforcing.

```yaml
rules:
  - id: warn-cross-account-access
    type: warn
    description: Warn on cross-account resource access
    match:
      actions:
        - "sts:AssumeRole"
      resources:
        - "arn:aws:iam::*:role/*"
    conditions:
      custom:
        cross_account: [true]
    message: "Cross-account access detected — verify this is intended"
    severity: MEDIUM
    notify:
      - slack-security-channel
```

**Behavior:**
- Allows the action to proceed
- Emits structured warning event
- Increments warning metrics
- Triggers configured notifications

### audit

Silently records the action for compliance and forensics. No user-visible impact.

```yaml
rules:
  - id: audit-secret-access
    type: audit
    description: Audit all access to secrets
    match:
      actions:
        - "secretsmanager:GetSecretValue"
        - "ssm:GetParameter"
        - "kms:Decrypt"
    message: "Secret/sensitive data access recorded for compliance"
    severity: INFORMATIONAL
```

**Behavior:**
- Allows the action to proceed
- Creates detailed audit record
- No user-visible notification
- Used for compliance evidence

---

## Matching Syntax

### Action Patterns

Actions use AWS IAM action format (`service:Action`) with glob matching:

| Pattern | Matches |
|---------|---------|
| `s3:GetObject` | Exact match |
| `s3:*` | All S3 actions |
| `*:*` | All actions on all services |
| `s3:Get*` | All S3 Get actions (`s3:GetObject`, `s3:GetBucketPolicy`, etc.) |
| `iam:*Role*` | All IAM actions containing "Role" |
| `lambda:Invoke*` | `lambda:InvokeFunction`, `lambda:InvokeAsync` |

### Resource Patterns

Resources use ARN format with glob matching:

| Pattern | Matches |
|---------|---------|
| `arn:aws:s3:::my-bucket/*` | All objects in `my-bucket` |
| `arn:aws:s3:::*` | All S3 buckets |
| `arn:aws:iam::123456789012:role/*` | All roles in specific account |
| `arn:aws:*:us-east-1:*:*` | All resources in us-east-1 |
| `*` | Any resource |

### Agent Patterns

Agent identifiers support exact match and glob patterns:

| Pattern | Matches |
|---------|---------|
| `invoice-processor` | Exact agent name |
| `finance-*` | All agents starting with "finance-" |
| `*-prod` | All agents ending with "-prod" |
| `*` | Any agent |

### Principal Patterns

| Pattern | Matches |
|---------|---------|
| `user:jane@company.com` | Specific user |
| `role:admin-*` | All admin roles |
| `service:bedrock.amazonaws.com` | Bedrock service |
| `*` | Any principal |

---

## Conditions

Conditions narrow when a rule applies. All specified conditions must be true (AND logic). Multiple values within a condition use OR logic.

### environment

```yaml
conditions:
  environment: [production]           # Only in production
  environment: [production, staging]  # In production OR staging
```

Valid values: `dev`, `staging`, `production`

### data_classification

```yaml
conditions:
  data_classification: [CONFIDENTIAL, SECRET, REGULATED]
```

Valid values: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `SECRET`, `REGULATED`

Hierarchy: `PUBLIC < INTERNAL < CONFIDENTIAL < SECRET < REGULATED`

### workload_type

```yaml
conditions:
  workload_type: [BEDROCK_AGENT, LAMBDA]
```

Valid values: `BEDROCK_AGENT`, `LAMBDA`, `ECS`, `EKS`, `SAGEMAKER`, `CUSTOM`

### time_window

Restrict rule to specific time windows (UTC):

```yaml
conditions:
  time_window:
    days: [monday, tuesday, wednesday, thursday, friday]
    hours_utc:
      start: 9
      end: 17
```

Useful for requiring approval outside business hours.

### risk_score

Match based on calculated risk score:

```yaml
conditions:
  risk_score:
    min: 70      # Only when risk >= 70
    max: 100     # And risk <= 100
```

### custom

Arbitrary key-value conditions evaluated against request context:

```yaml
conditions:
  custom:
    source_vpc: [vpc-prod-123, vpc-prod-456]
    department: [finance, legal]
    has_mfa: [true]
```

---

## Complete Examples

### Example 1: Comprehensive Production Policy

```yaml
apiVersion: v1
kind: SecurityPolicy
metadata:
  name: production-guardrails
  version: "2.1.0"
  description: Production security guardrails for all AI agents
  author: security-team
  created: "2026-08-01T00:00:00Z"
  labels:
    team: platform-security
    compliance: soc2

spec:
  priority: 10
  enabled: true
  environments:
    - production

  rules:
    # Hard deny: no wildcards ever
    - id: deny-all-wildcards
      type: deny
      description: Block any wildcard action in production
      match:
        actions: ["*:*", "iam:*", "s3:*", "ec2:*", "lambda:*"]
      message: "Wildcard actions are never permitted in production"

    # Hard deny: no audit trail tampering
    - id: deny-audit-tampering
      type: deny
      description: No agent may modify audit infrastructure
      match:
        actions:
          - "cloudtrail:DeleteTrail"
          - "cloudtrail:StopLogging"
          - "cloudtrail:UpdateTrail"
          - "guardduty:DeleteDetector"
          - "config:StopConfigurationRecorder"
      message: "Agents cannot modify audit/security monitoring infrastructure"

    # Approval: destructive data operations
    - id: require-approval-data-destruction
      type: require_approval
      description: Human approval required for production data deletion
      match:
        actions:
          - "s3:DeleteBucket"
          - "s3:DeleteObject"
          - "dynamodb:DeleteTable"
          - "rds:DeleteDBInstance"
          - "rds:DeleteDBCluster"
      conditions:
        data_classification: [CONFIDENTIAL, SECRET, REGULATED]
      message: "Production data deletion requires security team approval"
      approval_config:
        roles: [security-admin, data-owner]
        ttl_seconds: 1800
        max_approvers: 2

    # Warn: high-risk but permitted operations
    - id: warn-privilege-escalation-patterns
      type: warn
      description: Alert on actions that could enable privilege escalation
      match:
        actions:
          - "iam:PassRole"
          - "iam:CreatePolicyVersion"
          - "iam:AttachRolePolicy"
          - "sts:AssumeRole"
      severity: HIGH
      message: "Privilege escalation pattern detected — review required"
      notify: [slack-security, pagerduty-on-call]

    # Allow: specific well-scoped actions
    - id: allow-invoice-processing
      type: allow
      description: Invoice agent can read/write invoices bucket
      match:
        actions: ["s3:GetObject", "s3:PutObject"]
        resources: ["arn:aws:s3:::invoices-prod/*"]
        agents: ["invoice-processor"]
      message: "Permitted: invoice processing"

    # Audit: track all secret access
    - id: audit-secrets-access
      type: audit
      description: Record all access to secrets for SOC 2 evidence
      match:
        actions:
          - "secretsmanager:GetSecretValue"
          - "ssm:GetParameter"
          - "kms:Decrypt"
      severity: INFORMATIONAL
      message: "Secret access recorded"
```

### Example 2: After-Hours Lockdown

```yaml
apiVersion: v1
kind: SecurityPolicy
metadata:
  name: after-hours-lockdown
  version: "1.0.0"
  description: Require approval for high-risk actions outside business hours
  author: security-team

spec:
  priority: 5
  enabled: true

  rules:
    - id: require-approval-after-hours
      type: require_approval
      description: High-risk actions outside 9-5 UTC Mon-Fri need approval
      match:
        actions:
          - "iam:*"
          - "s3:Delete*"
          - "ec2:TerminateInstances"
          - "lambda:DeleteFunction"
      conditions:
        time_window:
          days: [saturday, sunday]
          hours_utc:
            start: 0
            end: 24
        environment: [production]
      message: "Weekend operations require on-call approval"
      approval_config:
        roles: [on-call-engineer, security-admin]
        ttl_seconds: 600
        max_approvers: 1

    - id: require-approval-night-shift
      type: require_approval
      match:
        actions: ["iam:*", "s3:Delete*", "ec2:TerminateInstances"]
      conditions:
        time_window:
          days: [monday, tuesday, wednesday, thursday, friday]
          hours_utc:
            start: 22
            end: 6
        environment: [production]
      message: "Night-time operations require on-call approval"
      approval_config:
        roles: [on-call-engineer]
        ttl_seconds: 600
        max_approvers: 1
```

### Example 3: Data Classification Gate

```yaml
apiVersion: v1
kind: SecurityPolicy
metadata:
  name: data-classification-gate
  version: "1.0.0"
  description: Enforce data classification-based access controls

spec:
  priority: 20
  enabled: true

  rules:
    - id: deny-regulated-without-approval
      type: deny
      description: No agent may access REGULATED data without pre-approval
      match:
        actions: ["*:*"]
      conditions:
        data_classification: [REGULATED]
        custom:
          pre_approved: [false]
      message: "Access to REGULATED data requires pre-approval via compliance workflow"

    - id: deny-secret-in-dev
      type: deny
      description: SECRET data cannot be accessed from dev environment
      match:
        actions: ["*:*"]
      conditions:
        data_classification: [SECRET, REGULATED]
        environment: [dev]
      message: "SECRET/REGULATED data is not accessible from dev environments"

    - id: warn-confidential-bulk-access
      type: warn
      description: Alert on bulk access to CONFIDENTIAL resources
      match:
        actions: ["s3:GetObject", "dynamodb:Scan", "dynamodb:Query"]
      conditions:
        data_classification: [CONFIDENTIAL]
        custom:
          batch_size_gt: [100]
      severity: HIGH
      message: "Bulk access to confidential data detected"
      notify: [dlp-team]
```

---

## Testing Policies

The policy engine includes a built-in testing framework. Define test cases alongside policies.

### Test Case Format

```yaml
apiVersion: v1
kind: PolicyTest
metadata:
  name: test-production-guardrails
  policy: production-guardrails

tests:
  - name: wildcard_denied_in_production
    input:
      action: "s3:*"
      resource: "arn:aws:s3:::production-data"
      agent: "rogue-agent"
      environment: production
    expected:
      decision: deny
      matched_rule: deny-all-wildcards

  - name: specific_action_allowed
    input:
      action: "s3:GetObject"
      resource: "arn:aws:s3:::invoices-prod/file.pdf"
      agent: "invoice-processor"
      environment: production
    expected:
      decision: allow
      matched_rule: allow-invoice-processing

  - name: destructive_requires_approval
    input:
      action: "s3:DeleteBucket"
      resource: "arn:aws:s3:::production-data"
      agent: "cleanup-agent"
      environment: production
      data_classification: CONFIDENTIAL
    expected:
      decision: require_approval
      matched_rule: require-approval-data-destruction

  - name: audit_trail_tampering_blocked
    input:
      action: "cloudtrail:StopLogging"
      resource: "*"
      agent: "any-agent"
      environment: production
    expected:
      decision: deny
      matched_rule: deny-audit-tampering
```

### Running Tests

```bash
# Test all policies in a directory
python -m aws_agent_identity_guard test-policies ./policies/

# Test a specific policy file
python -m aws_agent_identity_guard test-policies ./policies/production-guardrails.yaml

# Verbose output
python -m aws_agent_identity_guard test-policies ./policies/ --verbose

# JSON output for CI integration
python -m aws_agent_identity_guard test-policies ./policies/ --format json
```

### Expected Output

```
Testing production-guardrails (4 test cases)
  ✓ wildcard_denied_in_production              PASS
  ✓ specific_action_allowed                    PASS
  ✓ destructive_requires_approval              PASS
  ✓ audit_trail_tampering_blocked              PASS

4/4 tests passed
```

---

## Versioning

### Policy Versions

Each policy has a semantic version in `metadata.version`:

```yaml
metadata:
  name: production-guardrails
  version: "2.1.0"  # Major.Minor.Patch
```

**Version semantics:**
- **Major**: Breaking changes (new deny rules that may block previously allowed actions)
- **Minor**: New rules or conditions (additive, non-breaking)
- **Patch**: Bug fixes, documentation, message updates

### Version Deployment

Multiple versions can coexist. The engine uses the highest version of each named policy unless pinned:

```yaml
# Pin to specific version in deployment config
policies:
  - name: production-guardrails
    version: "2.1.0"    # Exact version
  - name: data-classification
    version: ">=1.0.0"  # Minimum version
```

### Policy Lifecycle

```
DRAFT → ACTIVE → DEPRECATED → ARCHIVED
  │        │         │
  │        │         └─ No longer evaluated, kept for audit
  │        └─ Currently enforced
  └─ Testing only, not evaluated in production
```

### Git Integration

Policies should be version-controlled alongside application code:

```
policies/
├── production-guardrails.yaml     # v2.1.0
├── data-classification.yaml       # v1.0.0
├── after-hours-lockdown.yaml      # v1.0.0
└── tests/
    ├── test-production.yaml
    ├── test-data-classification.yaml
    └── test-after-hours.yaml
```

CI pipeline validates policies on every commit:

```yaml
# .github/workflows/policy-validation.yml
- name: Validate policies
  run: python -m aws_agent_identity_guard validate-policies ./policies/

- name: Test policies
  run: python -m aws_agent_identity_guard test-policies ./policies/
```

---

## Schema Validation

Validate policy files against the schema before deployment:

```bash
python -m aws_agent_identity_guard validate-policies ./policies/

# Output:
# ✓ production-guardrails.yaml — valid (5 rules)
# ✓ data-classification.yaml — valid (3 rules)
# ✗ broken-policy.yaml — invalid:
#     Line 15: Unknown rule type 'block' (valid: deny, allow, require_approval, warn, audit)
#     Line 22: Missing required field 'match.actions'
```

### Common Validation Errors

| Error | Cause | Fix |
|-------|-------|-----|
| Unknown rule type | Typo in `type` field | Use: `deny`, `allow`, `require_approval`, `warn`, `audit` |
| Missing `match.actions` | Rule has no action patterns | Add at least one action pattern |
| Invalid data classification | Unrecognized value | Use: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `SECRET`, `REGULATED` |
| Duplicate rule ID | Two rules share same `id` | Ensure unique IDs within each policy |
| Invalid priority | Non-integer or negative | Use positive integers (lower = higher priority) |
