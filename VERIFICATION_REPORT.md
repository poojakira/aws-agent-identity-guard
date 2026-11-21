# Verification report

**LOCAL ONLY.** Tested source: 8e14fa4c9402b7da325502e82fab4368d924888c. Fixing source at report time: 8e14fa4c9402b7da325502e82fab4368d924888c. Hosted observations in [audit findings](AUDIT_FINDINGS.md) identify their separate source SHAs.

Docker Python 3.12.16, Ruff 0.17.1. Install requirements-studio-test.txt and editable package. Run Ruff check and format check on src and tests, then pytest with pytest-cov. Browser and live AWS checks need separate evidence.

The baseline HTTP case produced 2 failures and 1 pass. The restored patched source produced 274 passed, 0 failed, 3 legacy rules-module skips and 76.71353251318102% coverage. The official SARIF schema passed its pinned digest check and was supplied to the tests. Command log: aws-agent-identity-guard.verified-check.log.

- TOTAL                                                         1138    265    77%
- =========================== short test summary info ============================
- exit=0

The local workflow syntax check used actionlint 1.7.7. The Markdown lexical check inspected relative file targets. It does not establish heading fragments, external targets, or example commands. Logs and command wrappers are in the workspace audit directory.
