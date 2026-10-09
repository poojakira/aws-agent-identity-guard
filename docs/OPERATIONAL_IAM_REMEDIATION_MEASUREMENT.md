# Verified reduction in high-risk IAM roles

1. With an explicitly authorized **read-only** AWS account connection, run the repository's live scanner and save full JSON account snapshots as `before.json` and `after.json` in a controlled, private evidence location, not Git.
2. Verify both scans are complete, from the same AWS account, with identical role ARN sets and no collection errors. Keep snapshots and time boundaries auditable.
3. Obtain change approval before applying changes. Verify real effective permissions and required workload actions after the remediation; IAM static findings alone are not sufficient. Track evidence of approved change tickets and IAM simulation/actual workload tests without storing secrets.
4. Create private `validation.json` mapping role ARNs to:
   `{"authorization_verified":true,"required_actions_verified":true,"change_approved":true,"evidence_ref":"ticket-or-test-id","environment":"live_aws"}`.
5. Run `python scripts/measure_iam_role_remediation.py before.json after.json validation.json`.

Reported reduction is **number of originally high/critical-flagged roles that become finding-free and have the live verification evidence / number of originally high/critical-flagged roles**, multiplied by 100. The numerator is not merely the count of static findings eliminated. Newly introduced roles or incomplete scans reject the comparison. If none were initially flagged, no percentage is defined.

CAUTION: Scanner rule alerts are policy-analysis findings, not proof of effective permissions. This evidence file is an audit assertion; retain independently verifiable IAM policy simulator outputs, service authorization decisions, and tickets. No automatic IAM modifications are made by this tool. The examples and synthetic tests do not establish an operational percentage.
