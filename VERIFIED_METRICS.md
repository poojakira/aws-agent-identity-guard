# Verified Metrics

This file is the evidence anchor for quantitative résumé and portfolio claims about this repository.

## Historical main CI baseline

**Audited code commit:** `001fb2ccd828ae157150d6f1a53bbd0741dc51d9`  
**Successful main CI run:** https://github.com/poojakira/aws-agent-identity-guard/actions/runs/35808439923  
**Verification date:** 2026-09-23

| Claim | Verified value | Evidence |
|---|---:|---|
| Deterministic rule IDs | **25** | `src/aws_agent_identity_guard/scanner.py` + `live_scanner.py`: AIG001–AIG021, AIG-TP001–AIG-TP003, AIG-PB001 |
| Test result | **231 passed, 3 skipped** | Run 35808439923; Python 3.11 job 107014379871 emits `PYTEST_EVIDENCE tests=234 passed=231 skipped=3 failures=0 errors=0`; the evidence gate also runs across Python 3.10/3.11/3.12 |
| SARIF | **2.1.0 output implemented and tested** | CLI/output tests and README |
| Performance latency gate | **p95 < 10 ms/policy** | Run 35808439923, job 107014379859: measured 1.1040 ms p95; gate PASS |
| Performance throughput gate | **> 1,000 policies/sec** | Same job: measured 1,913 policies/sec; gate PASS |

## Rule-count proof

The 25 emitted rule IDs are:

- Identity-policy rules: AIG001–AIG021 = 21
- Trust-policy rules: AIG-TP001–AIG-TP003 = 3
- Permission-boundary rule: AIG-PB001 = 1

Total: **25**.

## Performance claim boundary

The latency and throughput values above are **CI gate thresholds**, not fixed measured production performance. The benchmark uses 500 synthetic policies, a fixed seed, 1–15 statements per policy, a 5-policy warm-up, and no network I/O. CI writes the actual measurement to `perf-results.json`.

## Local repair verification (2026-09-24)

The cross-statement combination logic now distinguishes `Action` grants from
`NotAction` exclusions and matches service wildcards only to their service.
The CLI rejects duplicate JSON keys. With this checkout's source forced via
`PYTHONPATH=src`, the suite reports **235 passed, 3 skipped**. Ruff lint and
format pass. A local 500-synthetic-policy benchmark measured **0.6935 ms p95**
and **3,178 policies/sec** on this workspace. These are local measurements,
not production performance or a new main-branch CI result.

## Reproduce

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests -q
python benchmarks/perf_gate.py --policies 500 --output perf-results.json
```

When tests, rule IDs, or benchmark behavior change, reconcile this file, the README, the portfolio, and résumé claims together.
