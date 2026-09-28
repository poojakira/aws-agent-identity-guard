# Claim Ledger — Poster 02 (02-aws-agent-identity-guard)

MIT • Python 3.12 • HEAD b01690a • verified 2026-09-26. Classification: VERIFIED_CURRENT / VERIFIED_HISTORICAL / PARTIAL / UNVERIFIED / UNSUPPORTED.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 235 tests passed, 3 skipped (local, Py 3.12, HEAD b01690a) | VERIFIED_CURRENT | Independent local run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests -q -> '235 passed, 3 skipped'. |
| 2 | 25 deterministic rule IDs | VERIFIED_CURRENT | Distinct AIG001-021, AIG-TP001-003, AIG-PB001 counted in src; README rule table; all test-covered. |
| 3 | Text / JSON / SARIF 2.1.0 output | VERIFIED_CURRENT | README + CLI; SARIF invariants tested in tests/test_cli_output.py. |
| 4 | 231 passed/3 skipped; p95 1.10ms; 1913 policies/sec | VERIFIED_HISTORICAL | CI run 35808439923 (001fb2c, 2026-09-23). Perf are CI-gate thresholds on 500 synthetic policies, not SLOs. |
| 5 | Local benchmark 0.69ms p95 / 3178 pps | PARTIAL | VERIFIED_METRICS.md local repair note; environment-scoped, single machine. |
| 6 | Runtime enforcement / effective-permission proof | UNSUPPORTED (disclaimed) | README states static-only, no fail-closed; not claimed on poster. |

## Policy applied
- Only VERIFIED_CURRENT figures appear as prominent current results.
- Historical/projected values are labeled (dashed box / explicit note).
- Unsupported production/accuracy claims are omitted or shown in the red "NOT ESTABLISHED" box.
