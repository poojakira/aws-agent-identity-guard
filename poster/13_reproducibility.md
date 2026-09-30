# Reproduce the Work - Poster 02

**Repository:** `github.com/poojakira/aws-agent-identity-guard`  
**Verified code snapshot:** `c39ba67f43ef6ebddd03a8ce429b42afec0c08a9`  
**CI run:** `36781556871`

```bash
git clone https://github.com/poojakira/aws-agent-identity-guard.git
cd aws-agent-identity-guard
git checkout c39ba67f43ef6ebddd03a8ce429b42afec0c08a9
python -m pip install -e ".[dev]"
pytest tests/ -q
python benchmarks/perf_gate.py
```

Expected CI test evidence: **238 collected, 235 passed, 3 skipped**.

Current CI performance evidence: **1.1460 ms p95**, **1,846 policies/sec** on the repository's synthetic 500-policy gate.
