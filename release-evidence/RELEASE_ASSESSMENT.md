# Release assessment: aws-agent-identity-guard

SOURCE: `abe1c0a1e5953b18eae762a5c41f400ff677adb2`  
BRANCH: `codex/local-workbench-20261116`  
ASSEMBLED UTC: 2026-11-19T00:50:25.051837+00:00  
DECISION: **PARTIAL**. No software release, main merge or public full-app deployment is approved by this assessment.

Cloud developers paste bounded IAM and optional trust policies, run the actual static scanners, navigate exact statement evidence, change the policy and export a schema-validated SARIF review. No AWS credentials are used.

## Working entry points

- [Current source README and exact local prerequisites/launch](https://github.com/poojakira/aws-agent-identity-guard/blob/abe1c0a1e5953b18eae762a5c41f400ff677adb2/README.md)
- [Free CPU guided notebook](https://colab.research.google.com/github/poojakira/aws-agent-identity-guard/blob/codex/local-workbench-20261116/notebooks/try_product.ipynb) — public page HTTP 200; actual committed cells passed locally from a fresh public checkout, **hosted Colab kernel NOT VERIFIED**.
- [Readable overview](https://github.com/poojakira/aws-agent-identity-guard/blob/abe1c0a1e5953b18eae762a5c41f400ff677adb2/docs/architecture/overview.svg), [detailed source-mapped architecture](https://github.com/poojakira/aws-agent-identity-guard/blob/abe1c0a1e5953b18eae762a5c41f400ff677adb2/docs/ARCHITECTURE.md), and locally served zoom/pan viewer in `docs/index.html`.

Actual broad policy findings, scoped policy findings and canonical before/after delta; effective permissions remain UNKNOWN.

The full browser UI remains a local application with its own documented supported inputs. Notebook fixtures do not establish representative field detection, a public hosted full UI, continuous monitoring or multi-user isolation. GitHub Pages configuration failed with HTTP403 "Resource not accessible by integration"; no working Pages URL is asserted. No Render/HF compute resource, paid service, billable provider API call or new credential was used. Existing optional cloud/deployment templates can cost money if separately enabled; see `cost-and-access-audit.json`.

## Fresh execution evidence

The clean candidate has **272 passed, 3 skipped, 0 failed and 0 errors** across 275 individual testcases. Local statement/line coverage is **77.14791851%** (871/1129); recorded gate no new threshold introduced. Native subtests: {'passed': 0, 'failed': 0, 'skipped': 0}. Separate Python3.10 focused execution: {'individual_cases': 23, 'passed': 23, 'failed': 0, 'skipped': 0}. Focused/optional/native/browser observations are not added to the individual full-suite total.

See `manifest.json`, `primary-run-manifest.json` where present, `tests-run.json` for Aegis, `executed-test-inventory.json`, original logs, and `browser/` for exact commands, execution times, clean source, environments, skip reasons and actual screenshots/exports. Required named local gates passed. No check threshold was reduced. Installed-wheel execution uses an unrelated Git project and verifies UNKNOWN instead of inheriting its HEAD.

Current hosted runs: 7 observed; all successful: True. `remote-ci/status.json` records actual URLs and statuses. The downloaded acceptance ZIP digest and every embedded artifact hash were independently recomputed locally; the manifest identifies this exact clean source. Hosted coverage is kept in remote-ci/hosted-manifest.json and is not substituted for local coverage. No publishing workflow or release was invoked.

The full suite retains three explicit skips for the absent legacy TestRulesModule. The focused Python 3.10 studio suite and installed-wheel HTTP journey are separate executions, not additional full-suite test totals. SARIF validation is an executable acceptance gate, not a guarantee of per-export runtime schema validation.

## File, documentation, branch and security audit

123 tracked files were inventoried with SHA256 and per-type validation; all current local documentation target checks, 4 SVG XML parses, notebook JSON/compiled cells and viewer JavaScript syntax passed. Actual viewer controls and every diagram loaded in desktop/mobile Chromium with no page errors. Four sequential product documentation reviewers inspected architecture symbols/enforcement/limits; the parent corrected remaining source mismatches and readability. Historical documents/artifacts retain their dated source bounds. This audit does not certify every external link's factual content, chronology, optional toolchain or cloud/deployment command.

Only `main` and `codex/local-workbench-20261116` remain as remote branches at recorded readback. Main remains `acbba97bc43d77031ee31bda8f2b04ed0030f7c2`. 5 additional tips were preserved in verified annotated recovery tags and a private verified bundle before exact-lease atomic deletion. 5 associated PRs are closed without merging their unreviewed changes. Unique security/cross-language work remains recoverable, not advertised as current functionality. Restore commands, tag/SHA pairs and final PR states are in `branch-disposition.json`. Tags are not extra branches. Future dependency automation may create branches; its protections were not disabled.

The reviewed offline Gitleaks scan covered all local Git refs/history, including recovery history, with redaction and default detectors. It produced 360 historical generic-rule occurrences, explicitly classified in `secret-history-triage.json`; no confirmed provider credential was found in that reviewed scope. Current tracked-file scanning found no new heuristic secret values. Hashes, public signing fingerprints and intentional synthetic/local test examples are distinguished from provider credentials. No live credential validation, suppression baseline or absolute secret-absence claim is made. Private raw history/author context, backups, product credentials, session tokens and real patient/user data are excluded from publication.

## Independent review boundary and remaining release gates

Historical focused independent security reviews remain attached to their real earlier source. Current whole-suite/browser/build/type/security checks were freshly executed by the parent. Documentation role separation is not a newly completed independent adversarial closing review at this candidate. HF's explicit blocked review remains blocked, with no bypass or reroute. No perfect/production-ready claim is justified.

- Static patterns do not establish effective permissions or proven exploitability. Complete Deny/SCP/boundary/session/resource-policy/service-condition intersections and live context are NOT VERIFIED or NOT IMPLEMENTED.
- Current product-container runtime, full transitive clean-build locks and authenticated public hosting are NOT VERIFIED.
- Deployment-specific privacy, operations, recovery and independent current-source adversarial signoff remain NOT VERIFIED.

`product-matrix.json` maps current implementation/evidence and gaps. `executed-test-inventory.json` identifies actual positive/negative/recovery cases and skipped checks. A new current-source independent review, the missing product-specific acceptance gates and deployment-specific signoff would be required to change this decision.

NEXT SAFE ACTION: review the existing draft PR and the source-scoped archive; complete the listed acceptance gates. Any later source change requires fresh applicable regression/browser/security evidence.
