# Threat Model

Formal threat model for AWS Agent Identity Guard using STRIDE methodology.

---

## Assets

| Asset | Classification | Description |
|-------|---------------|-------------|
| Agent Identities | CONFIDENTIAL | Registry of all agent IDs, IAM bindings, capabilities |
| Policies | CONFIDENTIAL | Access control rules that govern all decisions |
| Authorization Decisions | INTERNAL | Real-time ALLOW/DENY outcomes |
| Audit Logs | CONFIDENTIAL | Complete history of all authorization events |
| Risk Baselines | INTERNAL | Behavioral patterns used for anomaly detection |
| API Keys | SECRET | Authentication credentials for API access |
| TLS Certificates | SECRET | Private keys for mTLS communication |
| Attack Path Data | CONFIDENTIAL | Known escalation chains and vulnerabilities |
| Approval State | INTERNAL | Pending/completed human-in-the-loop decisions |

---

## Trust Boundaries

```
+---------------------------------------------------------------+
|  UNTRUSTED: Agent Workloads                                   |
|  (May be compromised, prompt-injected, or malicious)          |
+---------------------------------------------------------------+
                            | SDK calls (authenticated)
                            v
+---------------------------------------------------------------+
|  SEMI-TRUSTED: Authorization API                              |
|  (Validates input, enforces rate limits, checks API keys)     |
+---------------------------------------------------------------+
                            | Internal calls
                            v
+---------------------------------------------------------------+
|  TRUSTED: Decision Engines                                    |
|  (Policy, Risk, Attack Path, Escalation)                      |
+---------------------------------------------------------------+
                            | Read access
                            v
+---------------------------------------------------------------+
|  HIGHLY TRUSTED: Policy Store, Configuration                  |
|  (Git-versioned, admin-only write access)                     |
+---------------------------------------------------------------+
```

Key boundaries:
1. Agent workloads are NEVER trusted -- they are the subjects of control
2. The API layer is the enforcement boundary
3. Policy modifications require admin-level access
4. Audit logs are write-once (append-only from the service perspective)

---

## Threat Actors

### TA-1: Compromised Agent

- **Motivation**: Escalate privileges, access unauthorized data, pivot laterally
- **Capabilities**: Full control of agent logic, can craft any API request
- **Constraints**: Must authenticate via API key or mTLS; subject to all policies

### TA-2: Malicious Insider

- **Motivation**: Bypass controls, exfiltrate data, sabotage
- **Capabilities**: May have admin API access, knowledge of policies, ability to modify configuration
- **Constraints**: Actions are logged; policy changes require git commit

### TA-3: External Attacker

- **Motivation**: Compromise agent infrastructure, steal credentials, DoS
- **Capabilities**: Network access (if exposed), stolen credentials
- **Constraints**: No internal access; subject to rate limiting, authentication, network controls

### TA-4: Supply Chain Attacker

- **Motivation**: Inject malicious code into dependencies
- **Capabilities**: Can modify package behavior
- **Constraints**: Dependencies are pinned; Dependabot monitors for known vulns

---

## Attack Vectors

### AV-1: Agent SDK Bypass

| Aspect | Detail |
|--------|--------|
| Description | Agent calls AWS APIs directly, skipping the authorization SDK |
| Likelihood | MEDIUM |
| Impact | HIGH -- all authorization controls bypassed |
| Mitigation | Network-level enforcement (VPC endpoint policies, SCPs), IAM condition keys requiring auth header |
| Residual Risk | If network controls are misconfigured, bypass is possible |

### AV-2: API Key Theft

| Aspect | Detail |
|--------|--------|
| Description | Attacker obtains API key from environment variable or configuration |
| Likelihood | MEDIUM |
| Impact | HIGH -- can make unauthorized authorization calls |
| Mitigation | Key rotation, scoped keys, mTLS (key alone insufficient), secrets management |
| Residual Risk | Window between theft and rotation |

### AV-3: Policy Manipulation

| Aspect | Detail |
|--------|--------|
| Description | Adversary modifies policy files to allow malicious actions |
| Likelihood | LOW |
| Impact | CRITICAL -- authorization decisions corrupted |
| Mitigation | Git-based policy store with PR review, admin-only write access, policy change alerts |
| Residual Risk | Compromised admin account |

### AV-4: Denial of Service

| Aspect | Detail |
|--------|--------|
| Description | Overload the authorization API to prevent legitimate decisions |
| Likelihood | MEDIUM |
| Impact | MEDIUM to HIGH (depends on fail-open/fail-closed config) |
| Mitigation | Rate limiting, HPA, circuit breaker, configurable timeout |
| Residual Risk | Sustained volumetric attack beyond scaling capacity |

### AV-5: Decision Replay

| Aspect | Detail |
|--------|--------|
| Description | Replay a previous ALLOW decision to bypass current controls |
| Likelihood | LOW |
| Impact | MEDIUM -- single action authorized |
| Mitigation | Decisions are not tokens; each request is independently evaluated; correlation IDs are unique |
| Residual Risk | None -- decisions are not replayable by design |

### AV-6: Audit Log Tampering

| Aspect | Detail |
|--------|--------|
| Description | Adversary deletes or modifies audit logs to cover tracks |
| Likelihood | LOW |
| Impact | HIGH -- loss of forensic evidence |
| Mitigation | Logs shipped to immutable store (CloudWatch, S3 with Object Lock); separation of duties |
| Residual Risk | If log destination is compromised |

### AV-7: Time-of-Check to Time-of-Use (TOCTOU)

| Aspect | Detail |
|--------|--------|
| Description | Conditions change between authorization check and action execution |
| Likelihood | LOW |
| Impact | LOW -- narrow window |
| Mitigation | Short decision lifetime; re-check on sensitive operations; behavioral monitoring |
| Residual Risk | Inherent in any check-then-act pattern |

### AV-8: Insider Policy Backdoor

| Aspect | Detail |
|--------|--------|
| Description | Admin adds a hidden policy that allows specific malicious actions |
| Likelihood | LOW |
| Impact | HIGH |
| Mitigation | PR review for policy changes; automated policy analysis in CI; audit of all policy modifications |
| Residual Risk | Collusion between reviewers |

---

## STRIDE Analysis

### Spoofing

| Threat | Control |
|--------|---------|
| Agent impersonation (fake agent_id) | API key authentication; mTLS; IAM role binding |
| SDK spoofing (fake client) | mTLS client certificates; API key scoping |
| Approval reviewer impersonation | Approval requires authenticated identity |

### Tampering

| Threat | Control |
|--------|---------|
| Policy file modification | Git-versioned; admin-only write; file integrity monitoring |
| Audit log modification | Append-only store; ship to immutable destination |
| Risk baseline poisoning | Baselines computed from verified decisions only |
| Request modification in transit | TLS encryption; mTLS for mutual auth |

### Repudiation

| Threat | Control |
|--------|---------|
| Agent denies taking action | Every decision logged with correlation_id and agent_id |
| Admin denies policy change | Git commit history with author attribution |
| Reviewer denies approval | Approval audit trail with reviewer identity and timestamp |

### Information Disclosure

| Threat | Control |
|--------|---------|
| API key exposure in logs | Keys never logged; only key prefix shown in audit |
| Agent registry enumeration | API key required; list endpoint rate-limited |
| Policy disclosure to agents | Agents see decision outcome only, not policy details |
| Attack path disclosure | Attack paths only returned to admin-scoped keys |

### Denial of Service

| Threat | Control |
|--------|---------|
| API flooding | Rate limiting per client; HPA scaling |
| Large request payloads | Request size limits; Pydantic validation |
| Slowloris / connection exhaustion | Timeout configuration; connection limits |
| Policy evaluation bomb (complex regex) | No regex in policies; glob patterns only; evaluation timeout |

### Elevation of Privilege

| Threat | Control |
|--------|---------|
| Agent escalates own permissions | Attack path detection; escalation engine; DENY on IAM modifications |
| Read-only key attempts admin operations | API key scope enforcement |
| Agent approves own step-up | Self-approval prevented; different identity required |
| Container escape | Non-root user; read-only filesystem; no capabilities |

---

## What This System Does NOT Protect Against

Transparency about limitations:

1. **SDK bypass at network level** -- If an agent can reach AWS APIs directly without going through the authorization layer, policies are not enforced. Mitigation: use SCPs and VPC endpoint policies as a backstop, but this is outside the system's control.

2. **Compromised administrator** -- An admin with access to both the policy store and the API key configuration can create arbitrary backdoors. Mitigation: separation of duties, PR reviews, but a sufficiently privileged insider can circumvent.

3. **Availability under sustained DDoS** -- While the system scales horizontally, a volumetric attack exceeding infrastructure capacity will degrade service. If `fail-open` is configured, this means authorization lapses.

4. **Pre-existing permissions** -- The system controls future actions but cannot revoke permissions that were granted before deployment. It detects them (drift detection) but does not auto-remediate without explicit configuration.

5. **Agent logic correctness** -- The system controls what actions an agent CAN take, not whether its logic is correct. A buggy agent making legitimate (but wrong) API calls within its authorized scope will not be blocked.

6. **Data already accessed** -- Authorization is evaluated before access. If data was accessed before the system was deployed or before a DENY policy was added, that access cannot be undone.

7. **Side-channel attacks** -- Timing attacks on the authorization API (inferring policy rules from response times) are theoretically possible but practically difficult given the sub-10ms response variance.

8. **Physical security** -- The system assumes the underlying infrastructure (AWS, Kubernetes, compute) is not physically compromised.

---

## Risk Summary

| Risk | Likelihood | Impact | Residual Risk |
|------|-----------|--------|---------------|
| Agent privilege escalation | HIGH | CRITICAL | LOW (primary design goal) |
| Policy bypass via SDK skip | MEDIUM | HIGH | MEDIUM (requires network controls) |
| API key compromise | MEDIUM | HIGH | LOW (with mTLS + rotation) |
| Policy tampering | LOW | CRITICAL | LOW (git + review + alerts) |
| Denial of service | MEDIUM | MEDIUM | LOW (scaling + fail-closed) |
| Audit log loss | LOW | HIGH | LOW (immutable destinations) |
| Insider attack | LOW | CRITICAL | MEDIUM (hardest to fully prevent) |
