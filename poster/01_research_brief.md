# Research Brief - Poster 02

> Evidence status: Refreshed against verified code snapshot `229605c9c53068f4c0d7116d67554d19afe30183` and successful CI run `37170669504` on 2026-10-04.

## Repository

`github.com/poojakira/aws-agent-identity-guard` - public, default branch `main`.

## Academic Project Title

**Static Security Analysis of AWS IAM Policies for AI Workload Identities**

### Subtitle

Detecting Excessive Privilege and Identity-Pivot Risks Before Deployment

## One-Sentence Contribution

A deterministic, non-executing IAM linter specialized for AI-agent roles with **24 offline policy/trust rules** plus an optional role-metadata permission-boundary check (25 total IDs), emitting text, JSON, and SARIF for pre-deployment review and CI gating.

## Method

1. Parse one IAM policy document without executing cloud actions.
2. Classify statements and trust-policy structure.
3. Apply offline privilege/trust checks; missing-boundary checks require optional role metadata.
4. Emit findings with stable rule IDs and severity.
5. Return CI-friendly exit codes and optional SARIF.

## Verified Evidence at Cited Snapshot

Cited snapshot CI on Python 3.12 reports:

- **243 collected: 240 passed, 3 skipped**, 0 failures/errors.
- **24 offline rules** and **1 optional role-metadata check** are implemented (25 total IDs).
- Current performance gate over 500 synthetic policies: **0.8397 ms p95** and **2,573 policies/sec**, both passing configured gates.
- Ruff/format and security-audit jobs complete successfully.

## Claim Boundary

- Performance values are CI microbenchmarks on synthetic policies, not production SLOs.
- The tool is a static analyzer, not a runtime authorization proxy.
- It does not prove account-wide effective permissions or every cross-resource escalation path.
- The 3 skipped tests are disabled separate-rule-API tests (HAS_RULES=False); they are not skipped for missing AWS credentials.

## Reproducibility

```bash
git clone https://github.com/poojakira/aws-agent-identity-guard.git
cd aws-agent-identity-guard
git checkout 229605c9c53068f4c0d7116d67554d19afe30183
python -m pip install -e ".[dev]"
pytest tests/ -q
python benchmarks/perf_gate.py
```

Expected test evidence: **240 passed, 3 skipped**.


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
