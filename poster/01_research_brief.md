# Research Brief - Poster 02

> Evidence status: Refreshed against current code snapshot `c39ba67f43ef6ebddd03a8ce429b42afec0c08a9` and successful CI run `36781556871` on 2026-09-30.

## Repository

`github.com/poojakira/aws-agent-identity-guard` - public, default branch `main`.

## Academic Project Title

**Static Security Analysis of AWS IAM Policies for AI Workload Identities**

### Subtitle

Detecting Excessive Privilege and Identity-Pivot Risks Before Deployment

## One-Sentence Contribution

A deterministic, non-executing IAM linter specialized for AI-agent roles with **25 rule IDs** spanning identity policies, trust policies, and permission-boundary risks, emitting text, JSON, and SARIF for pre-deployment review and CI gating.

## Method

1. Parse one IAM policy document without executing cloud actions.
2. Classify statements and trust-policy structure.
3. Apply deterministic rule checks for privilege escalation, excessive privilege, trust weaknesses, audit tampering, and missing boundaries.
4. Emit findings with stable rule IDs and severity.
5. Return CI-friendly exit codes and optional SARIF.

## Current Verified Evidence

Current-main CI on Python 3.12 reports:

- **238 collected: 235 passed, 3 skipped**, 0 failures/errors.
- **25 deterministic rule IDs** remain implemented and test-covered.
- Current performance gate over 500 synthetic policies: **1.1460 ms p95** and **1,846 policies/sec**, both passing configured gates.
- Ruff/format and security-audit jobs complete successfully.

## Claim Boundary

- Performance values are CI microbenchmarks on synthetic policies, not production SLOs.
- The tool is a static analyzer, not a runtime authorization proxy.
- It does not prove account-wide effective permissions or every cross-resource escalation path.
- The 3 skipped tests require live AWS credentials; users must supply their own credentials through the standard AWS provider chain.

## Reproducibility

```bash
git clone https://github.com/poojakira/aws-agent-identity-guard.git
cd aws-agent-identity-guard
git checkout c39ba67f43ef6ebddd03a8ce429b42afec0c08a9
python -m pip install -e ".[dev]"
pytest tests/ -q
python benchmarks/perf_gate.py
```

Expected test evidence: **235 passed, 3 skipped**.
