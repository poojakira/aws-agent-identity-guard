# Reproduce the Work — Poster 02

> Evidence status: This is a dated repository snapshot at the commit identified below. `VERIFIED_AT_SNAPSHOT` means verified for that commit and environment; it does not assert the same result on the latest `main`. Compare newer claims with the repository evidence before reuse.

**Repository:** `github.com/poojakira/aws-agent-identity-guard` · MIT • Python 3.12 • HEAD e1f19cd • verified 2026-09-26

```
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests -q
aws-agent-identity-guard policy.json --format sarif
```

Evidence artifacts: VERIFIED_METRICS.md, benchmarks/perf_gate.py
