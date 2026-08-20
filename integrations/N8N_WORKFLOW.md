# n8n Workflow Integration

Scheduled n8n workflow for continuous IAM posture monitoring of AI agent roles.

## Pipeline: Cron → Scan → Alert → Remediation Ticket

**File:** `integrations/n8n-iam-posture-scan.json`

### What it does

1. **Scheduled trigger**  -  runs every weekday at 6 AM (configurable cron)
2. **Live IAM scan**  -  executes `aws-agent-identity-guard --live-scan --format json` against the current AWS account
3. **Parse & categorize**  -  groups findings by role, separates critical/high from medium
4. **Route by severity:**
   - **Critical/High found:** Alert Slack → Generate remediations → Create Jira ticket
   - **Clean:** Post summary to Slack (X roles scanned, 0 critical/high)

### Import into n8n

```bash
n8n import:workflow --input integrations/n8n-iam-posture-scan.json
```

### Prerequisites

1. `aws-agent-identity-guard` installed on the n8n worker:
   ```bash
   pip install aws-agent-identity-guard[live]
   ```

2. AWS credentials configured for the n8n worker (env vars, instance profile, or SSO)

3. IAM permissions for the scanner identity (read-only):
   ```
   iam:ListRoles, iam:GetRole, iam:ListRolePolicies, iam:GetRolePolicy,
   iam:ListAttachedRolePolicies, iam:GetPolicy, iam:GetPolicyVersion,
   iam:ListUsers, iam:ListUserPolicies, sts:GetCallerIdentity
   ```

### Required credentials

| Credential | Environment Variable | Purpose |
|-----------|---------------------|---------|
| Slack webhook | `SLACK_WEBHOOK_URL` | Alert `#cloud-security` |
| Jira API | `JIRA_BASE_URL`, `JIRA_PROJECT_KEY` | Remediation tickets |
| AWS (scanner) | Standard AWS credential chain | IAM read access |

### What the alert looks like

```
🚨 Agent IAM Posture Alert
Account: 111122223333
Roles Scanned: 47
Critical: 2 | High: 5 | Medium: 12

Top findings:
* AIG004 on `bedrock-agent-prod`: iam:PassRole without PassedToService...
* AIG011 on `data-pipeline-role`: cloudtrail:StopLogging in agent runtime...
* AIG008 on `mcp-server-role`: bedrock:CreateAgent in runtime role...
```

### Customization

- Change cron to `0 */4 * * *` for every-4-hours scanning
- Add a `--role-name` filter to scan specific agent roles only
- Chain with the model provenance scan workflow for full ML security posture
- Add AWS Config rule creation for continuous monitoring (beyond scheduled scans)

### Multi-account scanning

For AWS Organizations, run one workflow per account or use cross-account assume-role:

```bash
aws-agent-identity-guard --live-scan --role-name bedrock-agent-* --format json
```

Deploy the n8n worker in a security tooling account with cross-account read roles in each target account.
