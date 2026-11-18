# Incident-response template

This is a template for an operator's CI/review workflow, not a staffed service, committed SLA or instruction to change AWS. Populate contacts, severity criteria, response targets and authorization procedures in your own private operating system. The project is owner-maintained under the [contribution terms](CONTRIBUTING.md).

## Triage and preserve

1. Identify the affected interface: studio, static CLI, optional live collection, generated remediation or a downstream integration. Record exact source/version, non-secret configuration/input hashes, UTC interval, actual exit/error and report integrity.
2. Preserve policy reports in controlled storage; they may contain sensitive ARNs, names and relationships. Use a minimal synthetic reproduction for a public bug report, and [private disclosure](SECURITY.md) for exploitable issues.
3. Distinguish a pattern alert, tool failure, incomplete account collection and verified unauthorized effect. Neither finding severity nor an existing workload's apparent success proves actual IAM authorization.
4. Keep existing blocking checks. Do not change a job to non-blocking, suppress findings broadly, or delete forensic state to obtain a green result. Any separate operational risk acceptance belongs to the named owner under an explicit reviewed process.

## Failure and investigation paths

| Observation | Safe response |
|---|---|
| Suspected false positive | Preserve exact statement/action/resource/condition and applicable counter-context; reproduce with synthetic data, review canonical rule logic, and add a scoped regression before changing behavior |
| New suspected escalation pattern | Establish the relevant identity/resource/trust/SCP/session context and authoritative service behavior; collect evidence and privately propose the smallest rule/test/documentation change |
| Live throttling/access/cap errors | Retain `scan_complete`, `errors`, `roles_discovered` and reason; use `--enforce`, approved exact-role scoping or exported offline input; investigate SDK retry configuration without claiming complete coverage |
| Misleading remediation | Stop downstream application, inspect `remediate.py` and actual CLI rendering; distinguish advisory Terraform/CloudFormation/fixed-policy templates from an applied or workload-validated fix |
| Browser evidence mismatch | Preserve source/version and a synthetic sequence of edits/uploads/reviews; stale output should remain invalidated; do not attach old evidence to new input |
| Credential exposure | Revoke/rotate at the provider first, then preserve evidence and remediate source/history/log/artifact exposure; deleting a file is insufficient |
| Integration says clean after errors | Inspect exit/completeness propagation before resuming; zero high/critical findings in partial input is not a clean authorization assessment |

For optional AWS CLI export, a command such as `aws iam get-role-policy` returns an envelope; the scanner expects its `PolicyDocument` object, not the entire response. Export only an explicitly authorized role/policy, verify decoding and document shape, and retain it privately. Do not execute a live account query merely to reproduce this documentation.

## Recovery and review

Use a separate previously reviewed checkout/virtual environment or validated artifact, preserve local changes and re-run the relevant checks. Software rollback does not remove cloud changes, restore workload permissions, reverse notifications/tickets or revoke credentials. Infrastructure remediation, release tags, publication and external messages require their own authorization/review; this template grants none.

Record actual impact, evidence custody, timeline, root cause, hypotheses, mitigation, verification and follow-up owners. No fixed incident-response deadline, automatic IAM boundary attachment, unverified CloudWatch metric or emergency signed-release command is prescribed. The [operations runbook](RUNBOOK.md) documents actual CLI/completeness behavior and the [release policy](PRODUCTION.md) lists remaining gates.
