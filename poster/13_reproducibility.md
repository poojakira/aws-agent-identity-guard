# Reproduce the Work — Poster 02

**Repository:** `github.com/poojakira/aws-agent-identity-guard` · MIT • Python 3.12 • HEAD e1f19cd • verified 2026-09-26

```
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests -q
aws-agent-identity-guard policy.json --format sarif
```

Evidence artifacts: VERIFIED_METRICS.md, benchmarks/perf_gate.py
