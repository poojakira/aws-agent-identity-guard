# Research Brief — Poster 02

## Repository
`github.com/poojakira/aws-agent-identity-guard` (public, default branch `main`, primary language Python). MIT • Python 3.12 • HEAD b01690a • verified 2026-09-26

## Academic Project Title
**Static Security Analysis of AWS IAM Policies for AI Workload Identities**

### Subtitle
Detecting Excessive Privilege and Identity-Pivot Risks Before Deployment

## One-Sentence Contribution
A deterministic, non-executing IAM linter specialized for AI-agent roles — 25 rules spanning identity, trust, and permission-boundary risks, emitting SARIF for CI gating. Intentionally narrower than account-wide posture tools; complements Access Analyzer.

## Problem Statement
AI agents and tool executors assume IAM roles. An over-broad role turns a manipulated agent into real cloud actions: invoke Lambda, assume roles, change Bedrock/SageMaker control planes, read secrets, or disable CloudTrail. The risk exists at deploy time, before any runtime monitoring sees a single call.

## Threat Model
Chain: OVER-PRIVILEGED ROLE -> MANIPULATED AGENT -> PRIVILEGED CLOUD ACTION -> STATIC LINT BOUNDARY -> REVIEWABLE FINDING.
Adversary capability: crafts policy or exploits an over-scoped role; Assumptions: operator controls input; read-only in live mode; Out of scope: runtime enforcement; effective-permission proof; cross-policy/SCP context; Residual risk: false negatives; condition values not evaluated.

## Research / Engineering Question
> Can dangerous IAM patterns in AI-agent roles be identified before deployment through deterministic, non-executing policy analysis?

## Objective
Determine whether deterministic rules can flag agent- specific IAM risk patterns pre-deploy, emitting CI- gating findings in text, JSON, and SARIF.

## Engineering Sub-Objectives
O1 — 25 rules: identity, trust, boundary
O2 — Severity + remediation per finding
O3 — SARIF 2.1.0 + CI exit codes
O4 — Optional read-only live account scan

## Methodology
1 Load (policy JSON) -> 2 Classify (statements) -> 3 Match (25 rules) -> 4 Score (severity) -> 5 Emit (SARIF) -> 6·7 Exit + gate (code 0/1/2)

## Current Verified Evidence + Claim Ledger
- **VERIFIED_CURRENT** — 235 tests passed, 3 skipped (local, Py 3.12, HEAD b01690a) — Independent local run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests -q -> '235 passed, 3 skipped'.
- **VERIFIED_CURRENT** — 25 deterministic rule IDs — Distinct AIG001-021, AIG-TP001-003, AIG-PB001 counted in src; README rule table; all test-covered.
- **VERIFIED_CURRENT** — Text / JSON / SARIF 2.1.0 output — README + CLI; SARIF invariants tested in tests/test_cli_output.py.
- **VERIFIED_HISTORICAL** — 231 passed/3 skipped; p95 1.10ms; 1913 policies/sec — CI run 35808439923 (001fb2c, 2026-09-23). Perf are CI-gate thresholds on 500 synthetic policies, not SLOs.
- **PARTIAL** — Local benchmark 0.69ms p95 / 3178 pps — VERIFIED_METRICS.md local repair note; environment-scoped, single machine.
- **UNSUPPORTED (disclaimed)** — Runtime enforcement / effective-permission proof — README states static-only, no fail-closed; not claimed on poster.

## Important Negative / Honest Results
See RESULTS panel: Severity distribution across the 25 rule IDs. Counts from README rule table.

## Limitations
1. Static analysis only — no runtime enforcement.
2. No semantic evaluation of Condition key values.
3. Single-policy scope; no SCP/boundary interaction.
4. Prefix-based action matching may miss new namespaces.
5. False negatives accepted; not a full IAM engine.

## Future Work
• Cross-policy / SCP-aware evaluation.
• Condition-value semantic analysis.
• Broader live-account coverage.
• Effective-permission integration (Access Analyzer).
• Expanded namespace / action catalog.

## Reproducibility
```
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests -q
aws-agent-identity-guard policy.json --format sarif
```
Evidence: VERIFIED_METRICS.md, benchmarks/perf_gate.py

## References
[1] AWS IAM Best Practices · [2] IAM Access Analyzer · [3] OWASP Top 10 for LLM Apps · [4] MITRE ATLAS · [5] SARIF 2.1.0 (OASIS) · [6] NIST AI RMF 1.0
