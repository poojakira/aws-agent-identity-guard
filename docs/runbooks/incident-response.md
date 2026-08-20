# Incident Response Runbook

## Purpose

This runbook covers incident response procedures for security events detected by AWS Agent Identity Guard. It provides step-by-step guidance for triage, containment, investigation, and remediation.

---

## Severity Classification

| Severity | Definition | Response Time | Examples |
|----------|-----------|---------------|----------|
| **P1  -  Critical** | Active exploitation or imminent data loss | 15 minutes | Agent privilege escalation in progress; audit trail tampering detected |
| **P2  -  High** | Confirmed security violation, no active exploitation | 1 hour | Unauthorized cross-account access; data classification violation |
| **P3  -  Medium** | Policy violation with limited blast radius | 4 hours | Permission drift detected; unexpected service access |
| **P4  -  Low** | Minor policy deviations, informational | 24 hours | Missing condition key; unused permissions flagged |

---

## Incident Scenarios

### Scenario 1: Agent Privilege Escalation Detected

**Trigger:** Attack path analyzer identifies an agent actively using a privilege escalation chain, or authorization service denies a known escalation pattern with evidence of prior steps succeeding.

**Indicators:**
- Authorization denial for `iam:PassRole`, `iam:CreatePolicyVersion`, or `iam:AttachRolePolicy`
- Preceding successful actions in the same escalation chain
- Behavior analyzer shows privilege jump anomaly

**Response Steps:**

1. **Triage (5 min)**
   ```bash
   # Identify the agent and its recent activity
   curl -s http://guard:8080/v1/agents/{agent_id} | jq .
   curl -s http://guard:8080/v1/agents/{agent_id}/attack-paths | jq .
   ```

2. **Contain (10 min)**
   ```bash
   # Suspend the agent immediately
   curl -X POST http://guard:8080/v1/agents/{agent_id}/suspend \
     -H "X-API-Key: $ADMIN_KEY"

   # Attach deny-all permission boundary via AWS CLI
   aws iam put-role-permission-boundary \
     --role-name {agent_role_name} \
     --permissions-boundary "arn:aws:iam::aws:policy/AWSDenyAll"

   # If agent has active sessions, revoke them
   aws iam put-role-policy \
     --role-name {agent_role_name} \
     --policy-name emergency-deny-all \
     --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}}]}'
   ```

3. **Investigate (30 min)**
   ```bash
   # Pull CloudTrail events for the agent role
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=Username,AttributeValue={role_session_name} \
     --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ) \
     --max-results 100

   # Check Guard audit trail
   curl -s "http://guard:8080/v1/audit?agent_id={agent_id}&limit=100" | jq .

   # Check for successfully assumed roles
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
     --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)
   ```

4. **Eradicate**
   - Remove the escalated permissions
   - Detach any policies added by the compromised agent
   - Rotate credentials for any roles assumed
   - Delete any resources created during the escalation

5. **Recover**
   - Deploy corrected IAM policy via CI/CD
   - Verify scanner passes on new policy
   - Re-enable agent with corrected permissions
   - Monitor closely for 24 hours

6. **Lessons Learned**
   - Document the escalation path
   - Add scanner rule if novel pattern
   - Update policy-as-code to prevent recurrence

---

### Scenario 2: Audit Trail Tampering Attempt

**Trigger:** Authorization service denies `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, or `cloudtrail:UpdateTrail`.

**Indicators:**
- Denial event logged in Guard audit trail
- Agent behavior deviated from baseline before the attempt
- Potential preceding data access (cover tracks after exfiltration)

**Response Steps:**

1. **Triage (5 min)**
   - This is ALWAYS P1  -  audit tampering indicates active attack
   - Verify CloudTrail is still logging: `aws cloudtrail get-trail-status --name {trail}`
   - Notify security on-call immediately

2. **Contain (10 min)**
   ```bash
   # Suspend the agent
   curl -X POST http://guard:8080/v1/agents/{agent_id}/suspend \
     -H "X-API-Key: $ADMIN_KEY"

   # Deny-all boundary
   aws iam put-role-permission-boundary \
     --role-name {agent_role_name} \
     --permissions-boundary "arn:aws:iam::aws:policy/AWSDenyAll"

   # Verify all trails are active
   aws cloudtrail describe-trails | jq '.trailList[].Name' | \
     xargs -I {} aws cloudtrail get-trail-status --name {}
   ```

3. **Investigate**
   - Determine what actions preceded the tampering attempt
   - Check for data exfiltration patterns in preceding actions
   - Identify the root cause (compromised agent, malicious deployment, prompt injection)
   - Review all actions by this agent in the last 24 hours

4. **Eradicate**
   - Remove the agent's ability to interact with security services
   - Verify no other agents have similar permissions (live scan)
   ```bash
   python -m aws_agent_identity_guard --live-scan --format json | \
     jq '.[] | select(.rule_id | startswith("AUDIT"))'
   ```

---

### Scenario 3: Behavioral Anomaly  -  Possible Compromise

**Trigger:** Behavior analyzer detects multiple anomalies in short succession for a single agent.

**Indicators:**
- `UNEXPECTED_SERVICE`: Agent accessing services outside its baseline
- `PRIVILEGE_JUMP`: Sudden increase in permission level exercised
- `UNUSUAL_SEQUENCE`: Action pattern never seen before
- `TIME_ANOMALY`: Activity outside normal operating hours
- `VOLUME_ANOMALY`: Action rate > 3 standard deviations from norm

**Response Steps:**

1. **Triage (15 min)**
   ```bash
   # Get behavior report
   curl -s http://guard:8080/v1/agents/{agent_id}/behavior | jq .

   # Check recent denials
   curl -s "http://guard:8080/v1/audit?agent_id={agent_id}&decision=DENY&limit=50" | jq .
   ```

2. **Assess**
   - Single anomaly type → likely benign (new feature, config change) → P3
   - Multiple anomaly types simultaneously → likely compromise → P2
   - Anomaly + denial of privilege escalation → active attack → P1

3. **Contain (if P1/P2)**
   - Switch enforcement mode to ENFORCE if currently MONITOR
   - Consider suspending agent pending investigation
   - Notify agent owner and security team

4. **Investigate**
   - Compare current actions against agent manifest
   - Check for prompt injection indicators in agent input logs
   - Review preceding user interactions
   - Look for initial compromise vector

---

### Scenario 4: Permission Drift Detected

**Trigger:** Drift detector identifies new permissions added to an agent role outside the CI/CD pipeline.

**Indicators:**
- HIGH severity: dangerous actions added (iam:PassRole, etc.)
- MEDIUM severity: new service access added
- LOW severity: minor permission changes

**Response Steps:**

1. **Triage**
   ```bash
   # Get drift details
   curl -s http://guard:8080/v1/agents/{agent_id}/drift | jq .
   ```

2. **Assess**
   - Was this an authorized change? Check change management system
   - Who made the change? Check CloudTrail for `PutRolePolicy`/`AttachRolePolicy`
   - Is the change dangerous? Run scanner against the new policy

3. **Remediate**
   ```bash
   # If unauthorized, revert to last known good policy
   aws iam put-role-policy \
     --role-name {agent_role_name} \
     --policy-name {policy_name} \
     --policy-document file://last-known-good.json

   # Or detach the unauthorized managed policy
   aws iam detach-role-policy \
     --role-name {agent_role_name} \
     --policy-arn {unauthorized_policy_arn}
   ```

4. **Prevent Recurrence**
   - Enable SCP to restrict who can modify agent roles
   - Add CloudTrail alert for role policy modifications
   - Review IAM access for the identity that made the change

---

### Scenario 5: Guard Service Degradation (Fail-Closed Active)

**Trigger:** Guard service latency exceeds SLO or becomes unavailable, causing `fail_closed` behavior to deny all requests.

**Indicators:**
- All agent requests being denied
- High error rate in metrics
- Circuit breaker in OPEN state
- Agents reporting authorization failures

**Response Steps:**

1. **Triage (5 min)**
   ```bash
   # Check service health
   curl -s http://guard:8080/v1/health
   curl -s http://guard:8080/v1/health/ready

   # Check container status
   kubectl get pods -n agent-guard
   kubectl describe pod {pod_name} -n agent-guard

   # Check Redis connectivity
   redis-cli -h {redis_host} ping
   ```

2. **Mitigate**
   - If Redis is the issue: service can operate without cache (slower but functional)
   - If OOM: scale up memory limits or add replicas
   - If policy load failure: check policy volume mount

3. **Emergency Override (USE WITH CAUTION)**
   ```bash
   # ONLY if business-critical agents are blocked AND no security incident
   # Temporarily switch to fail_open for specific agents
   # Document this decision and set a timer to revert

   # Scale up replicas
   kubectl scale deployment agent-guard -n agent-guard --replicas=5

   # Restart pods if stuck
   kubectl rollout restart deployment agent-guard -n agent-guard
   ```

4. **Recovery**
   - Verify all pods healthy
   - Verify readiness probe passing
   - Monitor for 30 minutes
   - Review denied requests during outage for any that need retry

---

## Communication Templates

### P1 Notification

```
🚨 P1 SECURITY INCIDENT  -  Agent Identity Guard

WHAT: [Brief description - e.g., "Agent privilege escalation detected"]
WHEN: [Timestamp UTC]
AGENT: [agent_id]
IMPACT: [What could be affected]
STATUS: Containment in progress
RESPONSE: [On-call engineer name]
NEXT UPDATE: [Time - within 30 minutes]
```

### P2 Notification

```
⚠️ P2 SECURITY EVENT  -  Agent Identity Guard

WHAT: [Brief description]
WHEN: [Timestamp UTC]
AGENT: [agent_id]
IMPACT: [Current assessment]
STATUS: Investigation in progress
RESPONSE: [Assigned engineer]
NEXT UPDATE: [Time - within 2 hours]
```

---

## Post-Incident Actions

### Required for All Incidents (P1-P3)

- [ ] Timeline documented with all actions taken
- [ ] Root cause identified
- [ ] Containment verified (no ongoing access)
- [ ] Evidence preserved (CloudTrail logs, Guard audit trail, screenshots)
- [ ] Affected systems identified and verified clean
- [ ] Policy/rule updates implemented to prevent recurrence
- [ ] Post-incident review scheduled (within 5 business days for P1/P2)

### Additional for P1

- [ ] Executive notification sent
- [ ] Legal/compliance notified if data breach suspected
- [ ] Impacted customers/users identified
- [ ] Customer notification plan created (if applicable)
- [ ] External reporting obligations assessed

---

## Escalation Matrix

| Condition | Escalate To | Method |
|-----------|-------------|--------|
| P1 not contained in 30 min | Engineering Director | Phone call |
| Data breach suspected | Legal + CISO | Phone + email |
| Multiple agents compromised | VP Engineering | Immediate |
| CloudTrail confirmed disabled | AWS Support + CISO | AWS Abuse form + phone |
| Guard service unrecoverable | Platform team lead | PagerDuty |

---

## Tools and Access Required

| Tool | Purpose | Access Required |
|------|---------|----------------|
| Guard API | Agent status, audit queries | Admin API key |
| AWS CLI | IAM policy modification, CloudTrail | IAM admin role |
| kubectl | Pod management, logs | cluster-admin or namespace admin |
| CloudWatch | Log analysis | ReadOnly access |
| PagerDuty | Alerting and escalation | On-call schedule |
