# Verified Metrics

This file is the evidence anchor for quantitative résumé and portfolio claims about this repository.

## Verified baseline

**Audited code commit:** `d5a72870a9a296878a5b4ca562d194da157f9857`  
**Successful main CI run:** https://github.com/poojakira/aws-agent-identity-guard/actions/runs/33730289448  
**Verification date:** 2026-09-21

**Fresh exact-count CI proof:** https://github.com/poojakira/aws-agent-identity-guard/actions/runs/35637577557  
**Fresh head commit:** `e95fc426e326e1ce9d2ffe03c39cc7d203631f15`

| Claim | Verified value | Evidence |
|---|---:|---|
| Deterministic rule IDs | **25** | `src/aws_agent_identity_guard/scanner.py` + `live_scanner.py`: AIG001–AIG021, AIG-TP001–AIG-TP003, AIG-PB001 |
| Test result | **230 passed, 3 skipped** | Run 35637577557; Python 3.11 job 106458771376 emits `PYTEST_EVIDENCE tests=233 passed=230 skipped=3 failures=0 errors=0`; the exact-count gate runs across Python 3.10/3.11/3.12 |
| SARIF | **2.1.0 output implemented and tested** | CLI/output tests and README |
| Performance latency gate | **p95 < 10 ms/policy** | Run 35637577557, job 106458771333: measured 0.8491 ms p95; gate PASS |
| Performance throughput gate | **> 1,000 policies/sec** | Same job: measured 2,596 policies/sec; gate PASS |

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
