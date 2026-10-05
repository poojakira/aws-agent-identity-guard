# Reproduce the Work - Poster 02

**Repository:** `github.com/poojakira/aws-agent-identity-guard`  
**Verified code snapshot:** `229605c9c53068f4c0d7116d67554d19afe30183`  
**CI run:** `37170669504`

```bash
git clone https://github.com/poojakira/aws-agent-identity-guard.git
cd aws-agent-identity-guard
git checkout 229605c9c53068f4c0d7116d67554d19afe30183
python -m pip install -e ".[dev]"
pytest tests/ -q
python benchmarks/perf_gate.py
```

Expected CI test evidence: **243 collected, 240 passed, 3 skipped**.

Current CI performance evidence: **0.8397 ms p95**, **2,573 policies/sec** on the repository's synthetic 500-policy gate.
