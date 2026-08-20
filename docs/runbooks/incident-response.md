# Incident Response Runbook

This runbook covers security incidents detected by AWS Agent Identity Guard. Each scenario includes detection, containment, investigation, remediation, and recovery steps.

---

## IR-1: Privilege Escalation Detected

**Trigger**: Escalation engine or attack path analyzer flags a multi-step privilege escalation attempt.

**Severity**: CRITICAL

### Detect

- Alert from `src/escalation_engine.py` pattern match
- Attack path with severity HIGH or CRITICAL identified
- Authorization decision: DENY with reason "Escalation pattern detected"
- Prometheus metric: `agent_guard_escalation_detected_total` increments

### Contain

1. Immediately verify the agent is in DENY state (check recent decisions)
2. If agent is still operational, quarantine it:
   ```bash
   curl -X PUT http://localhost:8000/v1/agents/{agent_id} \
     -H "X-API-Key: $ADMIN_KEY" \
     -d '{"environment": "QUARANTINE"}'
   ```
3. Revoke the agent's IAM role session:
   ```bash
   aws iam put-role-policy --role-name AgentRole \
     --policy-name DenyAll --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
   ```
4. Notify security team via configured alert channel

### Investigate

1. Pull audit logs for the agent (last 24 hours):
   ```bash
   # CloudWatch Logs Insights
   fields @timestamp, action, resource, decision, risk_score
   | filter agent_id = "{agent_id}"
   | sort @timestamp desc
   | limit 500
   ```
2. Identify the escalation chain:
   ```bash
   curl http://localhost:8000/v1/agents/{agent_id}/attack-paths
   ```
3. Check for successful actions before detection (was any step completed?)
4. Review CloudTrail for IAM actions matching the escalation pattern
5. Determine if the escalation was automated (agent logic) or manual (compromised credentials)

### Remediate

1. Remove escalation capabilities from the agent:
   - Remove `iam:PassRole`, `sts:AssumeRole`, `iam:Attach*` from declared capabilities
   - Update IAM policy to remove these permissions
2. Add explicit DENY policy for the detected pattern:
   ```yaml
   - id: block-escalation-{incident_id}
     effect: DENY
     priority: 1000
     conditions:
       agent_id: "{agent_id}"
       action_pattern: "iam:PassRole"
   ```
3. If agent logic caused escalation, file a bug with the agent development team

### Recover

1. Verify remediation by running attack path analysis again
2. Remove quarantine status if agent is cleared
3. Monitor for 72 hours with elevated alerting threshold
4. Document incident in security incident tracker
5. Update escalation patterns if a new pattern was discovered

---

## IR-2: Unauthorized Cross-Account Access

**Trigger**: Agent attempts to access resources in an account not listed in its authorized scope.

**Severity**: HIGH

### Detect

- Authorization DENY with cross-account resource ARN
- Risk engine network_score spike
- Drift detector alerts on new cross-account patterns

### Contain

1. Deny all pending approvals for the agent:
   ```bash
   curl -X PUT http://localhost:8000/v1/approvals/{approval_id} \
     -d '{"status": "REJECTED", "reviewer": "incident-response", "reason": "Cross-account incident"}'
   ```
2. Add temporary DENY policy for cross-account actions:
   ```yaml
   - id: emergency-deny-cross-account-{agent_id}
     effect: DENY
     priority: 999
     conditions:
       agent_id: "{agent_id}"
       action_pattern: "sts:AssumeRole"
   ```
3. Revoke any active cross-account sessions via STS

### Investigate

1. Identify the target account and resource
2. Check if access was successfully obtained before DENY
3. Review the agent's declared purpose -- is cross-account access expected?
4. Check CloudTrail in both source and target accounts
5. Determine attack vector: compromised credentials, misconfigured policy, or agent logic error

### Remediate

1. If access was never intended, add permanent DENY policy
2. If access should be scoped, update resource_pattern conditions
3. Review and tighten IAM trust policies in target account
4. Update agent's declared capabilities to reflect correct scope

### Recover

1. Verify the agent operates correctly within its authorized scope
2. Remove emergency DENY policy once permanent fix is in place
3. Run full policy evaluation to confirm no gaps
4. Update threat model with findings

---

## IR-3: Data Exfiltration Attempt

**Trigger**: Agent attempts to access or transfer data above its classification level or in unusual volume.

**Severity**: HIGH to CRITICAL (based on classification)

### Detect

- DENY on access to SECRET/REGULATED data by an agent with lower clearance
- Behavior analyzer flags unusual data volume
- Risk engine data_score exceeds threshold
- Multiple rapid-fire data access requests

### Contain

1. Immediately block the agent (set to QUARANTINE)
2. If data was accessed, identify what was retrieved:
   - Check S3 access logs
   - Check CloudTrail for successful GetObject calls
3. Block network egress from the agent's compute environment if possible:
   ```bash
   # For ECS tasks
   aws ec2 revoke-security-group-egress --group-id sg-xxx --protocol -1 --cidr 0.0.0.0/0
   ```

### Investigate

1. Determine what data was accessed (classification, volume, type)
2. Determine where data was sent (if anywhere)
3. Check if the agent's credentials were compromised
4. Review the agent's behavior history for patterns leading to this event
5. Check for data in agent's output channels (logs, responses, storage)

### Remediate

1. If data was exfiltrated, activate data breach response procedures
2. Rotate any credentials that may have been exposed
3. Add strict resource_pattern policies limiting data access
4. Reduce agent's data_classification clearance
5. Add volume-based DENY policies

### Recover

1. Confirm no ongoing access to sensitive data
2. Verify egress controls are restored correctly
3. Enable enhanced monitoring for 30 days
4. Report to compliance team if regulated data was involved
5. Update data access policies organization-wide if systemic issue

---

## IR-4: Policy Bypass Detected

**Trigger**: Agent takes an action that should have been blocked but was not caught by the policy engine.

**Severity**: HIGH

### Detect

- Post-hoc audit reveals allowed action that violates security intent
- Gap analysis identifies missing policy coverage
- CloudTrail shows action not present in authorization logs (agent bypassed SDK)

### Contain

1. Add emergency DENY policy covering the gap:
   ```yaml
   - id: emergency-gap-{incident_id}
     effect: DENY
     priority: 999
     conditions:
       action_pattern: "{uncontrolled_action}"
   ```
2. If agent bypassed SDK entirely, revoke its IAM role credentials immediately
3. Enable ENFORCE mode if running in AUDIT mode

### Investigate

1. Determine how the bypass occurred:
   - Policy gap (action not covered by any policy)
   - SDK bypass (agent called AWS directly without authorization check)
   - Configuration error (wrong mode, fail-open)
2. Check if other agents have the same gap
3. Review policy test coverage for the missed scenario

### Remediate

1. Write policies to close the gap
2. If SDK bypass, enforce authorization at network level (VPC endpoint policies, SCPs)
3. Add test case for the specific bypass scenario
4. Review all agents with similar capabilities

### Recover

1. Validate the fix with dry-run testing
2. Run full policy evaluation against all registered agents
3. Update policy testing procedures to prevent recurrence
4. Consider mandatory SDK enforcement (block direct AWS calls)

---

## IR-5: Agent Compromise

**Trigger**: Evidence that an agent's identity or execution environment has been taken over by an adversary.

**Severity**: CRITICAL

### Detect

- Sudden behavior change (new actions never seen before)
- Access from unexpected source IPs
- Actions outside declared purpose
- Failed authentication followed by successful unusual actions
- Behavior score spike above 90

### Contain

1. **Immediately deregister the agent**:
   ```bash
   curl -X DELETE http://localhost:8000/v1/agents/{agent_id} \
     -H "X-API-Key: $ADMIN_KEY"
   ```
2. Revoke all IAM sessions for the agent's role:
   ```bash
   aws iam put-role-policy --role-name CompromisedRole \
     --policy-name EmergencyDeny \
     --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
   ```
3. Stop the agent's compute environment:
   ```bash
   # ECS
   aws ecs update-service --cluster prod --service agent-service --desired-count 0
   # Lambda
   aws lambda put-function-concurrency --function-name agent-fn --reserved-concurrent-executions 0
   ```
4. Preserve forensic evidence (do not terminate instances, snapshot them)

### Investigate

1. Determine compromise vector:
   - Credential theft
   - Container escape
   - Supply chain attack
   - Insider threat
2. Scope the impact -- what did the adversary access?
3. Check for persistence mechanisms (new roles, policies, backdoors)
4. Review all actions taken by the agent since compromise began
5. Check for lateral movement to other agents or services

### Remediate

1. Rebuild the agent's execution environment from scratch
2. Rotate all credentials (IAM role, API keys, secrets)
3. Patch the vulnerability that enabled compromise
4. Re-register agent with fresh identity and tighter capabilities
5. Add detection rules for the specific compromise technique

### Recover

1. Deploy rebuilt agent in AUDIT mode first
2. Verify behavior matches expected baseline for 48 hours
3. Promote to ENFORCE mode
4. Conduct post-incident review
5. Update threat model and runbooks with findings

---

## General Incident Response Checklist

- [ ] Incident detected and classified (severity assigned)
- [ ] Containment actions taken within SLA (15 min for CRITICAL)
- [ ] Security team notified
- [ ] Evidence preserved (logs, snapshots, network captures)
- [ ] Investigation scope determined
- [ ] Root cause identified
- [ ] Remediation applied
- [ ] Fix verified
- [ ] Monitoring enhanced for recurrence
- [ ] Post-incident review scheduled
- [ ] Runbooks updated with lessons learned
- [ ] Stakeholders informed (compliance, management, affected teams)
