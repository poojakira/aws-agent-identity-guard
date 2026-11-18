# n8n integration template — not activation-ready evidence

`integrations/n8n-iam-posture-scan.json` is an optional workflow template, not a running monitor or a studio dependency. It declares a weekday 06:00 cron (n8n timezone/configuration applies), command execution, finding categorization, Slack webhook posts and Jira issue creation. No n8n import/activation, AWS scan, Slack message or Jira ticket was executed by this documentation pass. Such actions require explicit authorization, approved target identities, secrets and report-sharing policy; this guide grants none.

## Source behavior and gaps

| Template component | Checked-in behavior | Review needed before use |
|---|---|---|
| Command node | `aws-agent-identity-guard --live-scan --format json` | High/critical findings return exit 1 and can stop command-node execution; capture findings and tool failures distinctly |
| Parse/classify | Reads stdout and severity lists | Does not validate `scan_complete`, `errors` or truncation; a partial result can be misleading |
| Clean branch | Posts a success-style Slack message | Zero high/critical patterns is not complete IAM authorization or evidence that no action is needed |
| Remediation node | Maps finding strings into suggestion records | Does not invoke the canonical IaC generator or prove a fixed policy |
| Slack/Jira paths | Sends policy/account/role context to configured external services | Redaction, service permissions, n8n credential bindings and per-action authorization; both branches reaching Jira can create duplicate tickets |

Before activation, review an approved copy's exit propagation, enforce/completeness handling, error routing, deduplication, delivery failures and downstream transformations with synthetic data. Do not make essential checks non-blocking to produce a clean branch. The template is not proven compatible with a particular n8n/runtime version, and importing JSON is not end-to-end verification.

## Prerequisites for an independently authorized deployment

An operator would need a suitable n8n worker/command-execution environment, reviewed scanner source/distribution with the Boto3 live extra, an approved read-only AWS SDK identity, and separately approved Slack/Jira destinations/credential bindings. `SLACK_WEBHOOK_URL`, `JIRA_BASE_URL`, `JIRA_PROJECT_KEY` and the n8n HTTP-basic credential referenced by the Jira node are configuration placeholders, not permission or complete auth setup. Keep secret values in the target runtime's secret store, never in workflow source or logs.

`--role-name` selects an **exact** role name; `bedrock-agent-*` is not a supported wildcard/multi-account scan command. The scanner does not traverse Organizations or automatically assume cross-account roles. A separate operator-managed invocation/credential context is required for each approved account. No combination with another security product is required or established.

Use [the live-collection contract](../RUNBOOK.md#optional-live-collection), [AWS trust distinctions](../docs/aws-architecture.md), [threat model](../THREAT_MODEL.md), and [release/evidence gates](../docs/EVIDENCE.md). The template remains NOT VERIFIED for live delivery and requires remediation/review of these integration gaps before relying on it.
