> **Historical/source-bounded record.** Statements below retain their cited source/date or author-recorded context. They do not attest to a later documentation head, deployment or field outcome. External historical assertions remain unverified in this pass. See [current evidence status](../EVIDENCE.md).

# Read-only forensic baseline: poojakira/aws-agent-identity-guard

UTC: 2026-11-17T02:26:33.787101+00:00. Audit role: independent forensic reviewer. Decision: PARTIAL baseline; product release NOT VERIFIED.

## Repository identity

Authoritative connected-account match: `poojakira/aws-agent-identity-guard`; public; remote `https://github.com/poojakira/aws-agent-identity-guard.git`; default `main`; HEAD `acbba97bc43d77031ee31bda8f2b04ed0030f7c2`. Full fetched reachable history contains 205 commits; no shallow clone, no source/remote mutation performed. No AGENTS.md found. Commit metadata and all reachable commit parents/dates/subjects: `git-baseline.json`, `history.txt`.

Initial checkout status: ''. MCP six trailing mixed-CRLF lines normalize on checkout under .gitattributes; preserved in normalization.patch. Do not attribute these to user edits. No reset or overwrite performed.

## Product baseline

Capabilities: Python offline IAM/trust pattern scanner, CLI, remediation guidance, existing SARIF writer. No runtime dependency required for static core.

Gaps: Dashboard is hardcoded static results with new Date() presented as Last scan; no real browser analysis, edit/rescan, graph or evidence-linked source lines. Current scanner literal inventory is 24 distinct IDs (AIG001-021 plus AIG-TP001-003), conflicting with advertised 25.

Risk: HIGH accuracy boundary: pattern findings do not establish effective IAM permissions or exploitability; complete SCP/boundary/session/resource/trust evaluation unavailable. Input schema is permissive and silently discards non-object Statement members. Pin drift: pyproject ruff 0.17.1 versus CI 0.8.4.

Minimal complete journey: Paste/upload policy plus optional trust JSON -> actual scan_policy_document/scan_trust_policy -> statement-linked findings -> edit and rescan delta -> supplied-context graph -> validated SARIF/report.

Enforcement/source entrypoints: src/aws_agent_identity_guard/scanner.py: scan_policy_document, scan_trust_policy, _scan_killchain_combinations, _condition_has_key; src/aws_agent_identity_guard/cli.py: _build_sarif. dashboard/index.html hardcodes result rows and synthesizes scan-time from wall clock.

Recommended next milestone: Add separate keyless loopback local workbench around canonical scanner; strictly validate bounded JSON before engine, expose 24 actual rule IDs and assumptions, source locations, risk deltas, safe exports. Preserve all open dependency PR branches; reconcile poster branches semantically.

## Current CI and executable evidence

Main CI success run 39520135218 at acbba97b; recent dependency PR CI run 43903899333 SUCCESS at c5401e60. Retrieved historical metadata, not fresh release evidence.

Fresh local command (from repository root):

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src /workspace/work/tooling/venv/bin/python -m pytest -p no:cacheprovider tests/test_scanner.py tests/test_condition_structural.py tests/test_killchain.py -q --junitxml=/workspace/work/audit/aws-agent-identity-guard/baseline-junit.xml
```

Result: 99 passed, 0 failed, 0 skipped; focused suite only; no coverage measured. Actual captured output: baseline-tests.log; JUnit: baseline-junit.xml. Tests were run from original main source in audit tooling venv; this is not a candidate release run. Python 3.12.14; Node 24.22.1; Linux. Generic tooling venv is not the complete pinned product dependency environment. Exact run timestamps/counts are in JUnit. Final candidate tests, full regression, browser E2E, supply-chain audit, container build and release validation are NOT VERIFIED. Do not treat retrieved historic CI as fresh evidence.

## File inventory and validation

Every tracked default-branch path inventoried: **88**. `inventory.json` records path, size, SHA256, type, symlink state, AST/JSON syntax validation; `tracked-files.txt` is complete path list. Python AST syntax and tracked JSON parsing completed with 0 errors. `configuration-validation.json` records safe TOML and shell syntax checks. `documentation-inventory.json` inventories 27 text documentation files and candidate broken local links; external URLs, anchors, all facts/examples and media visual accessibility remain NOT VERIFIED. `workflow-audit.json` records source workflow pin/permissions indicators; parser/trigger and gate semantics need final review. No arbitrary tracked binary/executable or model was executed. Binary fixture hashes are inventory evidence, not proof of safety. No submodules. Test classes inferred from source include unit, integration, negative/adversarial; exact taxonomy and coverage exclusions must be reviewed for candidate.

All tracked-file semantic/security review is NOT COMPLETE. All remote branch tips have diff-stat and changed-path evidence; only selected important source paths were reviewed semantically. This records the audit boundary rather than falsely claiming every historical branch file/claim was verified.

## Branch governance

All refs preserved. Ahead/behind are ancestry counts, not evidence that squash-merged content is missing. No branches merged/deleted; none is yet DELETE ELIGIBLE. Full unique commit lists are in git-baseline.json. PR metadata latest first-page stored in github-prs.json (max 100; older pagination not yet exhausted). Open PRs visible in first page retained. Tags: none. Releases: none returned. Rulesets: empty returned. Branch-protection inspection BLOCKED by GitHub integration 403; lack of visibility does not establish absent protection. Workflow collection endpoint was rejected; checked-in workflow sources and action-run endpoints were read.

| Ref | SHA | Ahead / behind main | Disposition | Related PR |
|---|---|---:|---|---|
| `refs/heads/main` | `acbba97bc43d77031ee31bda8f2b04ed0030f7c2` | 0 / 0 | KEEP |  |
| `refs/remotes/origin/HEAD` | `acbba97bc43d77031ee31bda8f2b04ed0030f7c2` | 0 / 0 | KEEP |  |
| `refs/remotes/origin/dependabot/github_actions/actions/setup-python-7.1.0` | `5ff310e715e55f7b8e7808414e4f024602406ba3` | 1 / 0 | HOLD FOR REVIEW | #68 open |
| `refs/remotes/origin/dependabot/github_actions/docker/login-action-4.8.0` | `f6d96aa935b6bf61d6f90a52b6d4839d1453914b` | 1 / 0 | HOLD FOR REVIEW | #73 open |
| `refs/remotes/origin/dependabot/github_actions/pypa/gh-action-pypi-publish-1.14.3` | `d611f0af7fbbcc298ce4f00b1dd4dd1e6deb968a` | 1 / 0 | HOLD FOR REVIEW | #69 open |
| `refs/remotes/origin/dependabot/github_actions/softprops/action-gh-release-3.0.4` | `72bb253dbaca43151916cce2b63ad76ad4aec8eb` | 1 / 0 | HOLD FOR REVIEW | #72 open |
| `refs/remotes/origin/dependabot/pip/ruff-0.17.5` | `c5401e60a2969922de0c71cc2cb18ebf9f4b766f` | 1 / 0 | HOLD FOR REVIEW | #74 open |
| `refs/remotes/origin/fix/poster-active-metrics-20261013` | `eebd811df4fee01a8ca0f0f6a8199ae98b48b56a` | 6 / 4 | HOLD FOR REVIEW | #62 closed merged |
| `refs/remotes/origin/fix/poster-source-provenance-20261014` | `a153605608c5be4158437c8a0849fa59267e78d4` | 11 / 2 | HOLD FOR REVIEW | #64 closed merged |
| `refs/remotes/origin/main` | `acbba97bc43d77031ee31bda8f2b04ed0030f7c2` | 0 / 0 | KEEP |  |

## Phase report

PRODUCT: poojakira/aws-agent-identity-guard
SOURCE: acbba97bc43d77031ee31bda8f2b04ed0030f7c2 BRANCH: main UTC: 2026-11-17T02:26:33.787101+00:00
PHASE: 0 forensic baseline
DONE: complete default tracked-path/hash inventory; reachable refs/history; selected engine/UI/docs/workflow analysis; raw provider evidence.
EXECUTED: command above; safe Python AST/JSON/TOML/bash syntax checks; git read-only inventory; GitHub GET metadata.
RESULTS: 99 passed, 0 failed, 0 skipped; focused suite only; no coverage measured.
NEGATIVE / ADVERSARIAL TESTS: focused existing tests named by command; no new full acceptance attack matrix executed.
CLAIMS VERIFIED: source existence and selected behavior only; see checks above.
CLAIMS RETRACTED: no source changes during audit; unsupported/stale claims flagged above for implementation/docs reviewer.
BRANCH CHANGES: none; all KEEP or HOLD FOR REVIEW.
RISKS / BLOCKERS: incomplete release acceptance and provider protection visibility; product-specific items above.
DECISION: PARTIAL baseline; NOT VERIFIED release.
NEXT SAFE ACTION: Add separate keyless loopback local workbench around canonical scanner; strictly validate bounded JSON before engine, expose 24 actual rule IDs and assumptions, source locations, risk deltas, safe exports. Preserve all open dependency PR branches; reconcile poster branches semantically.
