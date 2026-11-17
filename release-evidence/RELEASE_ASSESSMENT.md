# IAM Studio candidate assessment

PRODUCT: poojakira/aws-agent-identity-guard
SOURCE: 970d1e1e3d5e65e91bd45fe16bb59725eec7b1dc
BRANCH: codex/local-workbench-20261116
DECISION: **PARTIAL** under the full acceptance contract. No production approval.

The independent loopback browser studio passes supplied identity/trust JSON to the canonical static scanners. It supports strict bounded parsing, exact statement source evidence, an edit/rescan delta, a graph derived only from supplied context, JSON/text reports and official-schema-validated SARIF2.1.0 exports. App version0.3.0. The inventory is24 static rules (21identity and3trust) plus separately scoped live-context AIG-PB001, which the offline studio does not run. It is incorrect to call all25 rules static.

## Fresh executed evidence

The clean exact-source engineering run ran from2026-11-17T21:10:40.942086+00:00 to2026-11-17T21:11:10.788491+00:00. It collected270 tests:267 passed,3 skipped, no failures/errors. Statement coverage was77.14791851195749%. The skipped tests are the three TestRulesModule tests in test_coverage_boost.py, with reason `rules module not importable`; they are not credential/live-AWS skips or successful validation. Exact commands, settings, dependencies, UTC intervals and artifact hashes are in manifest.json.

Lint/format, focused studio typing, medium/high Bandit, actual browser uploads/edit/delta/downloads and official SARIF schema validation, package build, installed dependency audit and the existing500-policy performance gate passed. Supplementary Python3.10 tests23/23, workflow validation, repository security script, JavaScript syntax, tracked-file type validation, environment SBOM and isolated installed-wheel HTTP startup/analysis passed. The SBOM describes the verification environment, not a container/OS image. Secret scanning's90 new heuristic matches were reviewed:88 baseline file hashes and two copies of the public official-schema digest. No live secret checking was performed and heuristic scanning cannot prove absence of secrets.

Independent remediation review at this same source passed38/38 actual engine/HTTP/Chromium checks and23/23 Python3.10 tests. It verified the42 then-frozen engineering artifact digests. A new wheel installed under an unrelated Git project returnedUNKNOWN source/status during actual HTTP analysis. The independent reviewer did not repeat the entire270-test engineering suite. See independent-review/REMEDIATION_REVIEW.md and its proof artifacts.

All seven candidate-associated remote workflows succeeded, including local studio acceptance44179660845, CI44179660511, documentation44179660809, security hygiene44179660554, poster parity44179660652, Production Gate44179660628 and the PR automation44179652556. The new studio job explicitly checked out the actual candidate head and recorded the same270/267/3 and coverage. Its actual downloaded artifact ZIP has SHA2566a256f10cd69a8fc47fd9db6fdff245052c883ed58eafcaf45600addfa580641; all26 embedded digests matched. Other legacy workflows used GitHub's default PR merge ref9809b4de1d0526cc75d6476c5237eb97f90e322b, whose tree7afafdababd63e06fe348025c7436b26def65ae4 exactly equals the candidate tree. We distinguish identical-tree checks from actual-head execution. No current container build/runtime check or live AWS validation is claimed. A workflow name does not confer production approval.

## Security autopsy and observed fixes

Independent review reproduced two MEDIUM defects at earlier source68d109d: AIG003/AIG007 described list-only policies as granting unrelated/content/secret capabilities, and delayed File.text completion could pair newly assigned editor content with an older completed review. Canonical descriptions now limit claims to listed actions and supplied context without removing rule conditions, IDs or severities. Both identity and trust upload paths discard obsolete reads and invalidate again when assigning content. Browser regressions exercise real scans completing during pending file reads and newer manual edits/reviews superseding those reads. Both findings are independently CLOSED at this source. The CSP was preserved; the test harness observes a DOM marker rather than eval polling.

Boundary checks cover duplicate escaped keys, malformed/deep/oversized/non-finite input, exact source spans, Deny/condition counter-context, official SARIF/source regions, supplied-only graph, stable input/configuration hashes, Host/Origin/body/extra-target rejection, safe HTML rendering, mobile bounds, stale-response rejection and no uncaught browser errors. These checks establish only the specific tested properties.

## Launch, lifecycle and branch state

Use README.md's Python3.10+ editable installation, then `python -m aws_agent_identity_guard.studio`; open http://127.0.0.1:8762. No AWS credentials, keys, database or external paid service is required. Input remains in browser/backend memory; downloaded reports may contain supplied policy context and remain wherever the operator saves them. This is a trusted single-operator local workflow with no authenticated public multi-user deployment.

DraftPR75 contains source; main remains unchanged. The squash-merged poster-source-provenance branch was deleted only after all four branch delta blobs were found byte-identical in main, PR64's squash merge was reachable from main, fresh regression/browser/CI passed, and PR/protection/active-CI/release/deployment/workflow checks found no dependency. Its exact prior tip is retained at archive/iam/poster-source-provenance-20261117 and in a verified private local bundle. See branch-disposition.json. The other older poster branch and open dependency PR branches retain unique or unresolved work and remain held. The evidence archive uses an immutable non-release tag and no permanent evidence branch.

## Remaining blockers

Effective-IAM evaluation, applicable Deny/SCP/boundary/session/resource-policy intersections, live identity/role context and proven exploitability remain NOT IMPLEMENTED in the local static flow. The studio explicitly reports effective permissionsUNKNOWN. Full historical semantic documentation/diagram/example reconciliation, complete branch consolidation, detailed protection-rule visibility, complete platform/build-source locks, current container validation and environment-specific operational/security approval remain incomplete. The tracked-file/type audit is bounded and is not an exhaustive semantic review. Those gaps prevent VERIFIED LOCAL RELEASE CANDIDATE and production-ready claims.

NEXT SAFE ACTION: reviewPR75, preserve unique work, complete the outstanding contract gates, and rerun exact-source evidence for any later changes. No default-branch merge, public deployment, cloud resource or software release occurred.
