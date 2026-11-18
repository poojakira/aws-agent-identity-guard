> **Historical poster: October 14, 2026 source snapshot.** Values below attest only to their cited code/run, not to the later studio or documentation head. See [source-scoped evidence](../docs/EVIDENCE.md).

# Research Brief - Poster 02

> Evidence status: Refreshed against verified code snapshot `718582f5fd8419b0b8c2ca21361f7b0c715cb54b` and successful CI run `38497940763` on 2026-10-14.

## Repository

`github.com/poojakira/aws-agent-identity-guard` - public, default branch `main`.

## Academic Project Title

**Static Security Analysis of AWS IAM Policies for AI Workload Identities**

### Subtitle

Detecting Excessive Privilege and Identity-Pivot Risks Before Deployment

## One-Sentence Contribution

A deterministic, non-executing IAM linter specialized for AI-agent roles with **25 product rule IDs** (24 static plus one live-context boundary-presence rule) spanning identity/trust patterns and role context, emitting text, JSON, and SARIF for pre-deployment review and CI gating.

## Method

1. Parse one IAM policy document without executing cloud actions.
2. Classify statements and trust-policy structure.
3. Apply deterministic rule checks for privilege escalation, excessive privilege, trust weaknesses, audit tampering, and missing boundaries.
4. Emit findings with stable rule IDs and severity.
5. Return CI-friendly exit codes and optional SARIF.

## Verified Evidence at Poster Snapshot

The cited October 14 CI on Python 3.12 reports:

- **247 collected: 244 passed, 3 skipped**, 0 failures/errors.
- **25 product rule IDs** comprise 24 static checks and one live-context boundary-presence check.
- Separately anchored earlier synthetic performance gate over 500 policies (not a measured result in the current test count): **0.8397 ms p95** and **2,573 policies/sec**, both passing configured gates.
- Ruff/format and security-audit jobs complete successfully.

## Claim Boundary

- Performance values are CI microbenchmarks on synthetic policies, not production SLOs.
- The tool is a static analyzer, not a runtime authorization proxy.
- It does not prove account-wide effective permissions or every cross-resource escalation path.
- The 3 skipped tests are legacy rules-module API tests (`rules module not importable`), as recorded in the cited source; they are not live-AWS checks.

## Reproducibility

```bash
git clone https://github.com/poojakira/aws-agent-identity-guard.git
cd aws-agent-identity-guard
git checkout 718582f5fd8419b0b8c2ca21361f7b0c715cb54b
python -m pip install -e ".[dev]"
pytest tests/ -q
python benchmarks/perf_gate.py
```

Expected test evidence: **244 passed, 3 skipped** (Oct 14 2026 CI run 38497940763).

