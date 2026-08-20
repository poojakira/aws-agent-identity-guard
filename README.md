# AWS Agent Identity Guard

> Production-grade security platform for AI agent identities on AWS. Runtime authorization, attack-path analysis, privilege-escalation detection, and policy enforcement.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/aws-agent-identity-guard/aws-agent-identity-guard/ci.yml?label=CI)](https://github.com/aws-agent-identity-guard/aws-agent-identity-guard/actions)
[![Coverage](https://img.shields.io/badge/coverage-94%25-brightgreen.svg)](https://github.com/aws-agent-identity-guard/aws-agent-identity-guard/actions)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](CHANGELOG.md)
[![PyPI](https://img.shields.io/pypi/v/aws-agent-identity-guard.svg)](https://pypi.org/project/aws-agent-identity-guard/)

---

## The Problem

AI agents operating on AWS are fundamentally different from human users and traditional service accounts. An agent autonomously decides which API calls to make, chains tool invocations dynamically, and often operates across trust boundaries—all without a human in the loop for each action. Standard IAM policies were designed for static, human-authored permission sets. They answer "can this principal call this API?" but not "should this agent, given its current task context, invoke this sequence of actions on these specific resources right now?" Traditional IAM linting tools catch misconfigurations at deploy time; they are blind to runtime behavior, lateral movement patterns, and privilege-escalation chains that emerge only when an agent is executing.

The attack surface is new and expanding. An agent with `sts:AssumeRole` and `iam:PassRole` can chain assumptions to reach resources its direct policy never granted. An agent with `s3:GetObject` on a bucket containing Terraform state files can extract credentials embedded in infrastructure definitions. An agent that can invoke other agents creates transitive trust relationships invisible to static analysis. These are not theoretical risks—they are the natural consequence of giving autonomous software broad permissions "just in case" it needs them, which is the default posture of most agent frameworks today.

Existing tools—AWS Access Analyzer, IAM linters, CSPM scanners—solve adjacent problems. They validate policy syntax, flag overly broad resource wildcards, or detect publicly exposed resources. None of them model agent-specific threat patterns: tool-chaining escalation, cross-agent delegation abuse, context-dependent authorization, or runtime behavioral drift. AWS Agent Identity Guard fills this gap with purpose-built detection logic, a runtime authorization layer, and continuous posture assessment designed specifically for the agent threat model.

---

## What This Does

- **Runtime authorization decisions** — sub-millisecond allow/deny verdicts for every agent tool invocation
- **Static policy analysis** — scan IAM policies, SCPs, and resource policies for agent-specific misconfigurations
- **Privilege escalation detection** — 45+ rules identifying escalation paths unique to agent architectures
- **Attack-path graph analysis** — computes reachable resource sets through role chaining, delegation, and tool composition
- **Cross-agent trust modeling** — maps implicit trust relationships when agents can invoke other agents
- **Behavioral drift detection** — baselines normal agent behavior and alerts on deviations
- **Context-aware authorization** — factors in task context, session history, and resource sensitivity
- **Policy-as-code enforcement** — define security invariants in YAML, enforce them in CI and at runtime
- **SARIF output for IDE integration** — findings surface directly in VS Code, IntelliJ, and GitHub code scanning
- **Risk scoring engine** — multidimensional scoring across blast radius, exploitability, and business impact
- **Least-privilege recommendations** — generates minimal policy sets from observed agent behavior
- **Session replay and forensics** — full audit trail of every authorization decision with context
- **Anomaly detection** — statistical models flag unusual API call patterns and resource access
- **Toxic combination detection** — identifies dangerous permission combinations (e.g., `iam:CreateRole` + `sts:AssumeRole`)
- **Resource sensitivity classification** — auto-labels resources by data sensitivity for risk-weighted decisions
- **Multi-account support** — works across AWS Organizations with delegated administrator model
- **Real-time event streaming** — publishes decisions and alerts to EventBridge, SNS, or webhooks
- **Custom rule authoring** — write detection rules in Python or declarative YAML
- **Compliance mapping** — maps findings to NIST 800-53, MITRE ATT&CK, and OWASP Top 10 for LLMs
- **Guardrail templates** — pre-built policy sets for common agent patterns (RAG, tool-use, multi-agent)
- **Break-glass override** — emergency escalation path with mandatory justification and audit
- **Integration SDK** — Python SDK for embedding authorization checks in any agent framework
- **Dashboard and reporting** — Grafana-compatible metrics and executive summary reports
- **Kubernetes admission controller** — blocks pod deployments with overprivileged agent roles

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          AWS Agent Identity Guard                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────────────────┐   │
│  │  Agent SDK    │    │   CLI Tool    │    │    CI/CD Integration      │   │
│  │  (Python)     │    │  (Static Scan)│    │  (GitHub Actions/GitLab)  │   │
│  └───────┬───────┘    └───────┬───────┘    └─────────────┬─────────────┘   │
│          │                    │                           │                  │
│          ▼                    ▼                           ▼                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     Authorization Gateway (FastAPI)                   │   │
│  │                     POST /v1/authorize                                │   │
│  │                     GET  /v1/agents/{id}/risk                         │   │
│  │                     GET  /v1/agents/{id}/attack-paths                 │   │
│  └──────────┬──────────────────┬──────────────────────┬────────────────┘   │
│             │                  │                      │                     │
│             ▼                  ▼                      ▼                     │
│  ┌──────────────────┐ ┌───────────────┐ ┌─────────────────────────────┐   │
│  │  Policy Engine   │ │  Risk Scorer  │ │   Attack Path Analyzer      │   │
│  │                  │ │               │ │                             │   │
│  │ • Rule evaluator │ │ • Blast radius│ │ • Graph traversal          │   │
│  │ • Context merge  │ │ • Exploit prob│ │ • Role chain enumeration   │   │
│  │ • Decision cache │ │ • Sensitivity │ │ • Transitive trust compute │   │
│  └────────┬─────────┘ └───────┬───────┘ └──────────────┬──────────────┘   │
│           │                   │                         │                   │
│           ▼                   ▼                         ▼                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Detection Engine                              │   │
│  │                                                                      │   │
│  │  ┌─────────────┐ ┌──────────────┐ ┌─────────────┐ ┌─────────────┐  │   │
│  │  │ Priv Escal  │ │ Lateral Move │ │  Behavioral │ │   Toxic     │  │   │
│  │  │ Rules (45+) │ │ Rules (30+)  │ │  Drift (ML) │ │ Combos (25+)│  │   │
│  │  └─────────────┘ └──────────────┘ └─────────────┘ └─────────────┘  │   │
│  └──────────┬──────────────────────────────────────────────────────────┘   │
│             │                                                               │
│             ▼                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         Data Layer                                    │   │
│  │                                                                      │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │   │
│  │  │  Policy Store │  │ Audit Log    │  │  Agent Registry          │  │   │
│  │  │  (DynamoDB /  │  │ (CloudWatch  │  │  (Identity Catalog)      │  │   │
│  │  │   PostgreSQL) │  │  / S3)       │  │                          │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  External Integrations                                                      │
│  ┌────────────┐ ┌────────────┐ ┌───────────┐ ┌──────────┐ ┌───────────┐  │
│  │ EventBridge│ │ CloudTrail │ │ Grafana   │ │ PagerDuty│ │ Slack     │  │
│  └────────────┘ └────────────┘ └───────────┘ └──────────┘ └───────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Install

```bash
pip install aws-agent-identity-guard
```

Or with all optional dependencies:

```bash
pip install aws-agent-identity-guard[full]
```

### Scan a Policy (Static Analysis)

Analyze an IAM policy file for agent-specific security issues:

```bash
python -m aws_agent_identity_guard scan policy.json --format sarif
```

Scan all policies in a directory:

```bash
python -m aws_agent_identity_guard scan ./policies/ --format table --severity high,critical
```

Example output:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ AWS Agent Identity Guard — Static Analysis Results                            │
├────────┬────────────────────────────────────────┬──────────┬─────────────────┤
│ Rule   │ Description                            │ Severity │ Location        │
├────────┼────────────────────────────────────────┼──────────┼─────────────────┤
│ PE-001 │ Agent can escalate via iam:PassRole    │ CRITICAL │ policy.json:14  │
│ PE-012 │ Unrestricted sts:AssumeRole target     │ HIGH     │ policy.json:23  │
│ LM-004 │ Cross-account access without boundary  │ HIGH     │ policy.json:31  │
│ TC-002 │ Toxic combo: CreateRole + AssumeRole   │ CRITICAL │ policy.json:8   │
└────────┴────────────────────────────────────────┴──────────┴─────────────────┘

4 findings (2 critical, 2 high, 0 medium, 0 low)
```

### Runtime Authorization

Embed authorization checks directly in your agent code:

```python
from agent_identity_guard import AgentIdentityGuard

guard = AgentIdentityGuard(endpoint='http://localhost:8080')

# Authorize a tool invocation
decision = guard.authorize(
    agent='invoice-agent',
    tool='s3:GetObject',
    resource='arn:aws:s3:::invoices-prod/123.pdf'
)

if decision.allowed:
    # Proceed with the action
    result = s3_client.get_object(Bucket='invoices-prod', Key='123.pdf')
else:
    # Handle denial
    print(f"Blocked: {decision.reason}")
    print(f"Risk score: {decision.risk_score}")
    print(f"Suggested alternative: {decision.recommendation}")
```

With context enrichment:

```python
decision = guard.authorize(
    agent='invoice-agent',
    tool='s3:GetObject',
    resource='arn:aws:s3:::invoices-prod/123.pdf',
    context={
        'task_id': 'task-abc-123',
        'session_id': 'sess-xyz-789',
        'user_request': 'Download invoice #123',
        'preceding_actions': ['s3:ListBucket'],
    }
)
```

### Deploy the Server

```bash
# Clone the repository
git clone https://github.com/aws-agent-identity-guard/aws-agent-identity-guard.git
cd aws-agent-identity-guard

# Start the full stack (API server + database + monitoring)
docker-compose up -d
```

Verify deployment:

```bash
curl http://localhost:8080/health
# {"status": "healthy", "version": "1.0.0", "rules_loaded": 142}
```

### Run the Demo

```bash
python demo/run_demo.py
```

The demo provisions a simulated multi-agent environment, demonstrates privilege escalation detection, and shows runtime authorization in action. See `demo/README.md` for walkthrough details.

---

## API

### POST /v1/authorize

Make an authorization decision for an agent action.

**Request:**

```json
{
  "agent_id": "invoice-agent",
  "action": "s3:GetObject",
  "resource": "arn:aws:s3:::invoices-prod/123.pdf",
  "context": {
    "task_id": "task-abc-123",
    "session_id": "sess-xyz-789",
    "preceding_actions": ["s3:ListBucket"]
  }
}
```

**Response:**

```json
{
  "decision": "ALLOW",
  "risk_score": 12,
  "latency_ms": 1.3,
  "matched_rules": [],
  "audit_id": "aud-2026-08-20-001234",
  "context_factors": {
    "resource_sensitivity": "medium",
    "behavioral_baseline_match": true,
    "session_risk_accumulation": 12
  }
}
```

**Denial response:**

```json
{
  "decision": "DENY",
  "risk_score": 87,
  "latency_ms": 1.1,
  "matched_rules": ["PE-001", "TC-002"],
  "reason": "Action would enable privilege escalation via role chaining",
  "recommendation": "Use scoped role arn:aws:iam::123456789012:role/invoice-readonly",
  "audit_id": "aud-2026-08-20-001235"
}
```

### GET /v1/agents/{id}/risk

Retrieve the current risk posture for an agent.

**Response:**

```json
{
  "agent_id": "invoice-agent",
  "overall_risk": 34,
  "dimensions": {
    "blast_radius": 22,
    "privilege_level": 45,
    "behavioral_drift": 8,
    "exposure_score": 61
  },
  "top_findings": [
    {
      "rule": "PE-012",
      "severity": "high",
      "description": "Unrestricted sts:AssumeRole allows assumption of 14 roles"
    }
  ],
  "last_assessed": "2026-08-20T14:00:00Z"
}
```

### GET /v1/agents/{id}/attack-paths

Enumerate attack paths reachable from an agent's current permissions.

**Response:**

```json
{
  "agent_id": "invoice-agent",
  "paths_found": 3,
  "critical_paths": 1,
  "paths": [
    {
      "severity": "critical",
      "steps": [
        "sts:AssumeRole → arn:aws:iam::123456789012:role/deploy-role",
        "iam:AttachRolePolicy → AdministratorAccess",
        "* → Full account compromise"
      ],
      "blast_radius": "full_account",
      "exploitability": "high"
    }
  ]
}
```

### Additional Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/policies` | GET | List all loaded security policies |
| `/v1/policies` | POST | Upload a new security policy |
| `/v1/agents` | GET | List registered agents |
| `/v1/agents/{id}/history` | GET | Authorization decision history |
| `/v1/agents/{id}/baseline` | POST | Trigger behavioral baseline computation |
| `/v1/scan` | POST | Submit a policy document for static analysis |
| `/v1/rules` | GET | List active detection rules |
| `/v1/rules/{id}` | PUT | Enable/disable a detection rule |
| `/v1/metrics` | GET | Prometheus-compatible metrics endpoint |
| `/health` | GET | Health check |

---

## Security Policy as Code

Define security invariants in YAML and enforce them across all agents:

```yaml
# policies/agent-guardrails.yaml
apiVersion: agent-identity-guard/v1
kind: SecurityPolicy
metadata:
  name: production-agent-guardrails
  namespace: invoicing
spec:
  targets:
    - agent: "invoice-*"
      environment: production

  rules:
    # No agent can assume roles outside its own account
    - name: deny-cross-account-assume
      action: DENY
      condition:
        action: "sts:AssumeRole"
        resource_account: "!= ${agent.account_id}"
      severity: critical

    # Agents cannot modify their own permissions
    - name: deny-self-escalation
      action: DENY
      condition:
        action:
          - "iam:AttachRolePolicy"
          - "iam:PutRolePolicy"
          - "iam:CreateRole"
        resource: "${agent.role_arn}"
      severity: critical

    # Restrict S3 access to designated buckets
    - name: restrict-s3-scope
      action: DENY
      condition:
        action: "s3:*"
        resource: "!arn:aws:s3:::invoices-*"
      severity: high

    # Time-based restrictions
    - name: deny-after-hours
      action: DENY
      condition:
        time_window:
          outside: "06:00-22:00 America/New_York"
      severity: medium
      allow_break_glass: true

    # Rate limiting
    - name: rate-limit-writes
      action: DENY
      condition:
        action: "s3:PutObject"
        rate:
          max: 100
          window: 60s
      severity: medium

  alerts:
    - channel: slack
      webhook: "${SLACK_SECURITY_WEBHOOK}"
      on: [critical, high]
    - channel: pagerduty
      routing_key: "${PD_ROUTING_KEY}"
      on: [critical]
```

Apply policies:

```bash
python -m aws_agent_identity_guard policy apply policies/agent-guardrails.yaml
```

Validate policies before applying:

```bash
python -m aws_agent_identity_guard policy validate policies/agent-guardrails.yaml
```

---

## CI/CD Integration

### GitHub Actions

Block pull requests that introduce privilege escalation risks:

```yaml
# .github/workflows/agent-security.yml
name: Agent Identity Security Scan
on:
  pull_request:
    paths:
      - 'infrastructure/**'
      - 'policies/**'
      - 'agents/**'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Agent Identity Guard
        run: pip install aws-agent-identity-guard

      - name: Scan IAM policies
        run: |
          python -m aws_agent_identity_guard scan \
            ./infrastructure/iam/ \
            --format sarif \
            --output results.sarif \
            --fail-on high,critical

      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Post PR comment
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const sarif = JSON.parse(fs.readFileSync('results.sarif', 'utf8'));
            const findings = sarif.runs[0].results;
            let comment = '## 🚨 Agent Identity Guard — Security Findings\n\n';
            comment += `Found **${findings.length}** security issues:\n\n`;
            findings.forEach(f => {
              comment += `- **${f.ruleId}** (${f.level}): ${f.message.text}\n`;
            });
            comment += '\n\nFix these before merging to protect agent identity security.';
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

### GitLab CI

```yaml
# .gitlab-ci.yml
agent-security-scan:
  stage: test
  image: python:3.12-slim
  script:
    - pip install aws-agent-identity-guard
    - python -m aws_agent_identity_guard scan ./infrastructure/iam/ --format gitlab-sast --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
  rules:
    - changes:
        - infrastructure/**
        - policies/**
```

---

## Detection Capabilities

| Category | Rules | Description |
|----------|-------|-------------|
| Privilege Escalation | 45 | Role chaining, PassRole abuse, policy attachment, service-linked role exploitation |
| Lateral Movement | 32 | Cross-account assumptions, resource-based policy pivots, VPC endpoint abuse |
| Toxic Combinations | 25 | Dangerous permission pairs that enable escalation when combined |
| Data Exfiltration | 18 | Bulk reads, cross-region copies, public bucket writes |
| Persistence | 15 | Access key creation, role trust policy modification, Lambda backdoors |
| Credential Exposure | 14 | Secrets in environment variables, metadata service access, parameter store reads |
| Behavioral Drift | 12 | Anomalous API patterns, unusual resource access, time-based anomalies |
| Cross-Agent Trust | 10 | Delegation chains, transitive permission inheritance, agent-to-agent invocation |
| Resource Misconfiguration | 9 | Overly permissive resource policies, missing encryption, public exposure |
| **Total** | **180** | |

### Example Detection: PE-001 (PassRole Escalation)

```
Rule:     PE-001
Severity: CRITICAL
Title:    Agent can escalate via iam:PassRole to privileged service role

Trigger:  Agent has iam:PassRole permission with resource wildcard or target
          role that has higher privileges than the agent's own role.

Impact:   Agent can create a Lambda/ECS task/Glue job with an admin role,
          execute code in that context, and gain the admin role's permissions.

Remediation:
  - Restrict iam:PassRole to specific role ARNs the agent legitimately needs
  - Add condition key iam:PassedToService to limit target services
  - Use permission boundaries on roles the agent can pass
```

---

## Risk Scoring

The risk scoring engine evaluates agent posture across four independent dimensions, combined into a weighted composite score (0–100):

### Dimensions

| Dimension | Weight | Description |
|-----------|--------|-------------|
| Blast Radius | 30% | How many resources and accounts can this agent reach? |
| Privilege Level | 30% | How powerful are the agent's effective permissions? |
| Behavioral Drift | 20% | How far is current behavior from established baseline? |
| Exposure Score | 20% | How accessible is the agent from external vectors? |

### Scoring Methodology

```
composite_risk = (blast_radius × 0.30) +
                 (privilege_level × 0.30) +
                 (behavioral_drift × 0.20) +
                 (exposure_score × 0.20)
```

**Blast Radius** considers:
- Number of directly accessible resources
- Reachable resources via role chaining (transitive closure)
- Data sensitivity of accessible resources
- Cross-account reach

**Privilege Level** considers:
- Effective permissions after policy evaluation
- Presence of admin-equivalent permissions
- Ability to self-escalate
- Access to security-sensitive APIs (IAM, KMS, STS)

**Behavioral Drift** considers:
- Statistical deviation from the 30-day behavioral baseline
- Novel API calls not seen in baseline period
- Unusual resource access patterns
- Time-of-day anomalies

**Exposure Score** considers:
- Network accessibility (public endpoints, VPC exposure)
- Authentication strength (MFA, session duration)
- Trust relationship breadth
- Credential rotation age

### Risk Thresholds

| Score Range | Classification | Response |
|-------------|---------------|----------|
| 0–25 | Low | Informational, no action required |
| 26–50 | Medium | Review recommended within 7 days |
| 51–75 | High | Action required within 24 hours |
| 76–100 | Critical | Immediate response, consider agent isolation |

---

## Attack Path Analysis

The attack-path analyzer builds a directed graph of all permission-reachable states from an agent's current position, then identifies paths that terminate at high-value targets.

### Example: Invoice Agent → Full Account Compromise

```
invoice-agent (initial permissions)
│
├─[1] sts:AssumeRole
│     Target: arn:aws:iam::123456789012:role/data-pipeline-role
│     Condition: Trust policy allows invoice-agent's role
│
├─[2] data-pipeline-role has iam:PassRole + lambda:CreateFunction
│     Can pass: arn:aws:iam::123456789012:role/admin-execution-role
│
├─[3] lambda:Invoke on created function
│     Executes with admin-execution-role permissions
│
└─[4] admin-execution-role has AdministratorAccess
      Result: FULL ACCOUNT COMPROMISE

Chain length: 4 hops
Exploitability: HIGH (no external dependencies)
Blast radius: FULL ACCOUNT
Detection difficulty: MEDIUM (spans multiple services)
```

### Graph Computation

The analyzer uses breadth-first traversal with the following edge types:

- **AssumeRole edges** — role trust relationships
- **PassRole edges** — ability to delegate roles to services
- **Resource policy edges** — cross-account access grants
- **Service-linked edges** — implicit permissions granted by service roles
- **Delegation edges** — agent-to-agent invocation permissions

Pruning heuristics keep computation tractable:
- Maximum chain depth: 8 hops (configurable)
- Only explores roles with higher privilege than current
- Caches subgraph results across agents sharing roles
- Parallelized traversal for multi-account graphs

---

## Performance

| Metric | Value | Conditions |
|--------|-------|------------|
| Authorization latency (p50) | < 2ms | Warm cache, single rule evaluation |
| Authorization latency (p99) | < 15ms | Cold path, full rule set evaluation |
| Throughput | > 10,000 decisions/sec | Single instance, 4 vCPU |
| Static scan (100 policies) | < 2s | Standard rule set (180 rules) |
| Memory (RSS) | < 128MB | Steady state with 1,000 agents registered |
| Attack-path computation | < 5s | 50-role graph, max depth 8 |
| Startup time | < 3s | Full rule loading + policy compilation |
| Rule hot-reload | < 100ms | No downtime, atomic swap |

### Benchmarking

Run the included benchmark suite:

```bash
python -m aws_agent_identity_guard benchmark --duration 30s --concurrency 16
```

---

## Compliance

### Framework Mapping

| Finding Category | NIST 800-53 | MITRE ATT&CK | OWASP Top 10 for LLMs |
|-----------------|-------------|---------------|----------------------|
| Privilege Escalation | AC-6, AC-2(7) | T1078, T1548 | LLM06: Excessive Agency |
| Lateral Movement | AC-4, SC-7 | T1021, T1550 | LLM06: Excessive Agency |
| Toxic Combinations | AC-5, AC-6(1) | T1078.004 | LLM08: Excessive Permissions |
| Data Exfiltration | AC-4, SC-7, SI-4 | T1537, T1567 | LLM02: Data Leakage |
| Credential Exposure | IA-5, SC-12, SC-28 | T1552, T1555 | LLM06: Excessive Agency |
| Behavioral Drift | SI-4, AU-6 | T1071 | LLM09: Overreliance |
| Persistence | AC-2(4), AU-12 | T1098, T1136 | LLM06: Excessive Agency |
| Cross-Agent Trust | AC-4, AC-17 | T1199 | LLM05: Insecure Plugin Design |
| Resource Misconfig | CM-6, CM-7 | T1562 | LLM08: Excessive Permissions |

### Compliance Reports

Generate compliance-specific reports:

```bash
# NIST 800-53 mapping report
python -m aws_agent_identity_guard report --framework nist-800-53 --output report.html

# MITRE ATT&CK coverage report
python -m aws_agent_identity_guard report --framework mitre-attack --output report.json

# Executive summary
python -m aws_agent_identity_guard report --format executive --output summary.pdf
```

---

## Deployment Options

### pip install (CLI and SDK)

```bash
pip install aws-agent-identity-guard
```

Suitable for CI/CD pipelines, static analysis, and embedding in agent frameworks.

### Docker (Single Container)

```bash
docker run -d \
  --name agent-identity-guard \
  -p 8080:8080 \
  -e AWS_REGION=us-east-1 \
  -v ./policies:/app/policies:ro \
  ghcr.io/aws-agent-identity-guard/server:1.0.0
```

### Docker Compose (Full Stack)

Includes the API server, PostgreSQL for policy storage, Redis for decision caching, and Grafana for monitoring:

```bash
docker-compose up -d
```

```yaml
# docker-compose.yml (overview)
services:
  server:
    image: ghcr.io/aws-agent-identity-guard/server:1.0.0
    ports: ["8080:8080"]
    depends_on: [postgres, redis]

  postgres:
    image: postgres:16-alpine
    volumes: [pgdata:/var/lib/postgresql/data]

  redis:
    image: redis:7-alpine

  grafana:
    image: grafana/grafana:10
    ports: ["3000:3000"]
```

### Kubernetes / Helm

```bash
helm repo add agent-identity-guard https://charts.agent-identity-guard.io
helm repo update

helm install agent-identity-guard agent-identity-guard/agent-identity-guard \
  --namespace security \
  --create-namespace \
  --set server.replicas=3 \
  --set server.resources.requests.memory=128Mi \
  --set server.resources.requests.cpu=250m \
  --set ingress.enabled=true \
  --set ingress.host=agent-guard.internal.example.com
```

### AWS ECS / Fargate

```bash
# Deploy using the included CloudFormation template
aws cloudformation deploy \
  --template-file deploy/cloudformation/ecs-fargate.yaml \
  --stack-name agent-identity-guard \
  --parameter-overrides \
    VpcId=vpc-12345678 \
    SubnetIds=subnet-a,subnet-b \
    DesiredCount=2 \
  --capabilities CAPABILITY_IAM
```

### AWS EKS

```bash
# Deploy using the Helm chart on EKS
eksctl create cluster --name agent-guard-cluster --region us-east-1
helm install agent-identity-guard agent-identity-guard/agent-identity-guard \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::123456789012:role/AgentGuardRole
```

---

## Configuration

Configuration via environment variables or `config.yaml`:

```yaml
# config.yaml
server:
  host: 0.0.0.0
  port: 8080
  workers: 4

authorization:
  default_decision: DENY
  cache_ttl: 300s
  max_context_depth: 8

detection:
  rules_path: /app/rules/
  custom_rules_path: /app/custom-rules/
  severity_threshold: low

risk_scoring:
  weights:
    blast_radius: 0.30
    privilege_level: 0.30
    behavioral_drift: 0.20
    exposure_score: 0.20
  baseline_window_days: 30

storage:
  backend: postgresql  # or dynamodb, sqlite
  connection_string: ${DATABASE_URL}

audit:
  enabled: true
  destination: cloudwatch  # or s3, stdout
  retention_days: 90

alerts:
  channels:
    - type: slack
      webhook_url: ${SLACK_WEBHOOK}
      severity: [critical, high]
    - type: pagerduty
      routing_key: ${PD_KEY}
      severity: [critical]
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture Guide](docs/architecture.md) | Detailed system design and component interactions |
| [Rule Reference](docs/rules.md) | Complete catalog of all 180 detection rules |
| [Policy Language](docs/policy-language.md) | Full specification of the policy-as-code YAML format |
| [API Reference](docs/api.md) | OpenAPI specification with all endpoints |
| [SDK Guide](docs/sdk.md) | Python SDK usage, configuration, and patterns |
| [Deployment Guide](docs/deployment.md) | Production deployment patterns and sizing guidance |
| [Tuning Guide](docs/tuning.md) | Reducing false positives, custom thresholds, exclusions |
| [Custom Rules](docs/custom-rules.md) | Writing detection rules in Python and YAML |
| [Multi-Account Setup](docs/multi-account.md) | AWS Organizations integration and cross-account scanning |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and debugging procedures |
| [Changelog](CHANGELOG.md) | Version history and migration guides |

---

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Development environment setup
- Code style and testing requirements
- How to add detection rules
- PR review process and expectations

```bash
# Development setup
git clone https://github.com/aws-agent-identity-guard/aws-agent-identity-guard.git
cd aws-agent-identity-guard
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pre-commit install

# Run tests
pytest --cov=aws_agent_identity_guard --cov-report=term-missing

# Run linting
ruff check .
mypy aws_agent_identity_guard/
```

---

## License

MIT License. See [LICENSE](LICENSE) for the full text.

---

<p align="center">
  Built for the age of autonomous AI agents.<br>
  Because <code>Action: *</code> on <code>Resource: *</code> is not a security strategy.
</p>
