# Verified Metrics

This file is the evidence anchor for quantitative résumé and portfolio claims about this repository.

## Verified baseline

**Audited code commit:** `d5a72870a9a296878a5b4ca562d194da157f9857`  
**Successful main CI run:** https://github.com/poojakira/aws-agent-identity-guard/actions/runs/33730289448  
**Verification date:** 2026-09-03

| Claim | Verified value | Evidence |
|---|---:|---|
| Deterministic rule IDs | **25** | `src/aws_agent_identity_guard/scanner.py` + `live_scanner.py`: AIG001–AIG021, AIG-TP001–AIG-TP003, AIG-PB001 |
| Test result | **230 passed, 3 skipped** | README verification record and successful Python 3.10/3.11/3.12 CI matrix |
| SARIF | **2.1.0 output implemented and tested** | CLI/output tests and README |
| Performance latency gate | **p95 < 10 ms/policy** | `benchmarks/perf_gate.py`; now enforced by `.github/workflows/ci.yml` |
| Performance throughput gate | **> 1,000 policies/sec** | `benchmarks/perf_gate.py`; now enforced by `.github/workflows/ci.yml` |

## Rule-count proof

The 25 emitted rule IDs are:

- Identity-policy rules: AIG001–AIG021 = 21
- Trust-policy rules: AIG-TP001–AIG-TP003 = 3
- Permission-boundary rule: AIG-PB001 = 1

Total: **25**.

## Performance claim boundary

The latency and throughput values above are **CI gate thresholds**, not fixed measured production performance. The benchmark uses 500 synthetic policies, a fixed seed, 1–15 statements per policy, a 5-policy warm-up, and no network I/O. CI writes the actual measurement to `perf-results.json`.

## Reproduce

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests -q
python benchmarks/perf_gate.py --policies 500 --output perf-results.json
```

When tests, rule IDs, or benchmark behavior change, reconcile this file, the README, the portfolio, and résumé claims together.
