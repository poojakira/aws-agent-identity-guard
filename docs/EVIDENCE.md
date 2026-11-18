# Evidence and release status

**Complete-contract decision: PARTIAL.** A working static-review journey and successful named checks establish their tested scope; they do not establish effective permissions, every authorization intersection, representative accuracy, public deployment or operational approval.

## Published implementation-source proof

The tested source is `970d1e1e3d5e65e91bd45fe16bb59725eec7b1dc`; immutable archive commit `9d829ee9a65df098ba91fe4672d88bfd63788999` is evidence-only, not the executed source or a software release. Its tag is `evidence/local-workbench-20261116`.

- [Assessment, launch, security findings and limitations](https://github.com/poojakira/aws-agent-identity-guard/blob/9d829ee9a65df098ba91fe4672d88bfd63788999/release-evidence/RELEASE_ASSESSMENT.md)
- [Manifest: exact commands, UTC times, source/environment, results and hashes](https://github.com/poojakira/aws-agent-identity-guard/blob/9d829ee9a65df098ba91fe4672d88bfd63788999/release-evidence/manifest.json)
- [Review proposal: PR #75](https://github.com/poojakira/aws-agent-identity-guard/pull/75)

That source recorded 267 passed and 3 absent legacy rules-module skips (270 collected), 77.14791851195749% coverage, focused independent 38-observation/23-Python-3.10 success and seven successful associated workflows. The studio workflow explicitly checked out that head; legacy workflows used a PR merge ref with an identical tree. Installed-wheel checks correctly reported source UNKNOWN under an unrelated Git project. Independent AIG003/AIG007 capability-wording and delayed-file-read authority findings were closed at that source. Earlier static/API/field claims are not upgraded by these results. Parent publication verification matched 64 archived file hashes.

## Documentation-reconciliation head

Later-head regression/browser/schema/security/build and document checks remain pending **until a fresh manifest identifies that exact candidate**. Planned archive `evidence/docs-reconciliation-20261118` is an out-of-tree non-release tag; a planned name is not proof it exists. The draft PR records actual publication and hosted-check status. Do not substitute prior 970d counts or screenshots as new-head execution.

[DOCUMENTATION_AUDIT.md](DOCUMENTATION_AUDIT.md) inventories every original tracked text document, corrections, source relationships and executed/reviewed/blocked boundaries. The [initial baseline](internal/REPOSITORY_AUDIT.md) records pre-studio main and its original governance state. Its old dashboard and no-cleanup observations are historical, not the later implementation state.

## Reproduce and verify

Follow [README verification](../README.md#develop-and-verify) with the checksum-verified official OASIS schema and actual Chromium. `scripts/studio_verify.py` requires clean source and out-of-checkout output, then runs complete applicable local regression, lint/format, focused typing, Bandit, actual browser/upload/edit/delta/download/SARIF schema tests, build, dependency audit and the existing synthetic performance gate. It records actual return codes and failed/skipped checks rather than inferring success from file existence. Test dependencies are a verification snapshot, not complete artifact-hash/build locks.

Record repository, actual SHA/branch/clean state, run IDs/UTC interval, tool/dependency versions and schema/pin hashes, commands/outcomes, individual JUnit units, coverage settings, browser/engine evidence, artifact checksums and remaining limits. Separately identify installed-wheel/runtime and optional/mocked/live tests. A source commit cannot contain its own future post-execution hash. Public-byte verification must compare all reviewed archive files, including logs/packages ignored by ordinary Git staging.

## Branch disposition

The completed implementation pass retained seven remote branches: main, this one candidate and five active dependency PR branches. Two proven merged poster branches were deleted after content, PR/reference/CI and verified recovery checks:

| Deleted branch | Recovery tag |
|---|---|
| `fix/poster-source-provenance-20261014` | `archive/iam/poster-source-provenance-20261117` |
| `fix/poster-active-metrics-20261013` | `archive/iam/poster-active-metrics-20261117` |

Exact tips/restore information are in the implementation PR's final cleanup update; a verified private Git bundle is retained and not published. The archive's earlier narrative predates the second deletion; the PR explicitly records that later cleanup. No unique/ambiguous/active PR branch was deleted, and no permanent evidence branch is needed. Re-read remote state before another cleanup; this is a recorded disposition, not a live branch API. No main history rewrite, default merge, deployment or software release occurred.

## Remaining gates

Complete effective-IAM/condition/applicability evaluation, live identity/account coverage, representative accuracy evidence, authenticated shared hosting, complete build/platform locks, current product-container validation and environment-specific privacy/operational approval remain missing or unverified. Document reconciliation does not validate every external historical assertion, optional cloud command or deployment. See [PRODUCTION.md](../PRODUCTION.md) and the [studio contract](STUDIO.md).
