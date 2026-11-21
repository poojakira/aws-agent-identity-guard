# Audit findings

## Repository state

Default branch main is acbba97bc43d77031ee31bda8f2b04ed0030f7c2. Review started at abe1c0a1e5953b18eae762a5c41f400ff677adb2. The collected inventory contains 75 pull requests, 0 issues and 10 Git tags. The public Releases API returned zero release records.

### Open pull requests

- [#75 Add local IAM permission review studio and source-scoped verification](https://github.com/poojakira/aws-agent-identity-guard/pull/75)

Draft #75 was open and mergeable at the observed base and head. Audit assessment is **NEEDS FIXES**.

### Open issues

No open issues in the collected inventory.



### Hosted runs in collected history

- Success on abe1c0a1e5953b18eae762a5c41f400ff677adb2, 2026-11-19T00:21:32Z. [Poster Artifact Parity](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/44428284756)
- Failure on 5646ffec463e8c07ad17407a7fef45af0d022491, 2026-10-14T20:36:09Z. [Production Gate](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/38630929061)
- Cancelled on 94a6b2da646b29fd90b68b7e4125d4b205c9c702, 2026-10-09T19:07:41Z. [Production Gate](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/37978026556)

Historical Production Gate failure 38630929061 had zero jobs in the collected record. Category E/F remains undetermined. No application job failure is attributed.

## Confirmed defects

| ID | Severity | Affected file and lines | Root cause, impact and remediation | Status |
|---|---|---|---|---|
| IAM-01 | Medium | src/aws_agent_identity_guard/studio/__main__.py:107–138 | The request parser and review engine shared an exception handler. Valid input with a synthetic engine ValueError or TypeError returned HTTP 400. The revised handler gives internal failures a scrubbed HTTP 500 and reports body read timeouts separately. | Implemented locally |
| IAM-02 | Low | README.md and docs/BRANCHES.md | Both files referenced a missing branch-cleanup.json in the evidence archive. HTTP returned 404 and the named object was absent from Git. The links now point to the existing immutable manifest or cleanup record. | Implemented locally |

## Residual risk

The candidate adds local static review and SARIF export. No inline review threads were returned. Offline IAM policy and trust checks cannot establish effective permissions under all AWS policy intersections, live account behavior or real authorization decisions.

The review includes the named PRs, selected source, local workflow syntax, relative file targets in Markdown, and the executed checks in [verification](VERIFICATION_REPORT.md). Complete source review, historical per-run root cause classification and validation of all operational documentation remain incomplete.
