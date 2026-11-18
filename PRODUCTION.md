# Release and deployment governance

**Decision: PARTIAL. No production deployment is approved.** This product performs static IAM review and optional read-only account collection. It does not enforce AWS permissions, prove exploitability or authorize a deployment.

## Promotion gates

Freeze the candidate, then execute complete applicable regression/integration/browser, schema/export, lint/type, dependency/security, performance, build/container and documentation checks. Record the actual SHA/clean state, UTC interval, environment/tool versions, commands, outcomes, skips and artifact hashes. Preserve blocking thresholds and collection/completeness failures. A green workflow named Production Gate is not operational approval. [Evidence status](docs/EVIDENCE.md) distinguishes prior-source results from later-head pending proof.

The local studio remains a trusted single-operator loopback service. Public/multi-user hosting, effective-policy intersections, complete live inventory, field accuracy, immutable deployment/build attestations, privacy signoff and environment-specific operational recovery remain missing or unverified. Keep the studio off public tunnels/proxies. Read-only AWS collection still requires approved account credentials/permissions and review of report contents before sharing.

## Operating boundaries

Production users must choose their own response targets, trusted identity, retention/encryption/backup, quota/error handling and CI promotion policy. No uptime, severity-response or recovery-time commitment is supplied. Use `--enforce` and inspect live completeness; never promote a truncated/error scan as clean. Generated remediation is advisory text/templates requiring review, not approved infrastructure. Terraform, OIDC, n8n, Slack/Jira and external validation are separate configured integrations, not functionality proved by the studio.

## Branch/release state

Main remains the integration branch. Preserve active PRs and unique work; archive verified recovery references before removing proven merged/unused branches. Two merged poster branches were deleted after content/reference/recovery checks; see [branch disposition](docs/EVIDENCE.md#branch-disposition). Earlier forensic tables retain their original date. No main history rewrite, automatic package/container publication, cloud resource or production release follows from this documentation change. Roll back in a separate reviewed checkout and re-run checks; code rollback does not undo AWS actions or rotate credentials.
