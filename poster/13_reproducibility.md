# Reproduce the Work — AWS Identity Guard Poster 02

**Current code snapshot:** `718582f5fd8419b0b8c2ca21361f7b0c715cb54b`  
**Successful main CI:** [run 38497940763](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/38497940763) (October 14, 2026 UTC)

```bash
git clone https://github.com/poojakira/aws-agent-identity-guard.git
cd aws-agent-identity-guard
git checkout 718582f5fd8419b0b8c2ca21361f7b0c715cb54b
python -m pip install -e ".[dev]"
pytest tests/ -q
```

Expected from Python 3.12 JUnit: **247 collected, 244 passed, 3 skipped** (credential-dependent). Static rule inventory: **25 deterministic rule IDs**, without implying effective permissions in a real AWS account.

Historical synthetic performance measurements, from [October 4 CI run 37170669504](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/37170669504), were **0.8397 ms p95** and **2,573 policies/second** on 500 artificial policies. That is a distinct benchmark and not a production SLO or a result measured in this current test run. The historical test snapshot was 243/240/3.
