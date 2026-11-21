> **Historical research poster, October 14, 2026 UTC.** Its measurements apply to source `718582f5fd8419b0b8c2ca21361f7b0c715cb54b` and the [associated GitHub Actions run](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/38497940763). See the [later candidate manifest](https://raw.githubusercontent.com/poojakira/aws-agent-identity-guard/a396433a4070a0ddc68aa83f9b1093e87fc3224f/release-evidence/manifest.json) for separately scoped local verification.

# Reproduce the Work — AWS Identity Guard Poster 02

**Poster code snapshot:** `718582f5fd8419b0b8c2ca21361f7b0c715cb54b`
**Successful main CI:** [run 38497940763](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/38497940763) (October 14, 2026 UTC)

```bash
git clone https://github.com/poojakira/aws-agent-identity-guard.git
cd aws-agent-identity-guard
git checkout 718582f5fd8419b0b8c2ca21361f7b0c715cb54b
python -m pip install -e ".[dev]"
pytest tests/ -q
```

Expected from Python 3.12 JUnit: **247 collected, 244 passed, 3 skipped** (absent legacy rules API). Product inventory: **25 IDs: 24 static plus one live-context check**, without implying effective permissions in a real AWS account.

Historical synthetic performance measurements, from [October 4 CI run 37170669504](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/37170669504), were **0.8397 ms p95** and **2,573 policies/second** on 500 artificial policies. That is a distinct benchmark and not a production SLO or a result measured in this cited test run. The historical test snapshot was 243/240/3.

Use a clean checkout at the poster SHA when reproducing these figures. Record test failures and skips, tool versions, coverage configuration, and digests with any newly generated evidence.
