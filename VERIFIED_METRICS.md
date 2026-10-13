# Verified Metrics

## Latest directly checked hosted CI - 2026-10-10

**Main commit:** [`bc35752dbfd72a7ce80eb1ad992bc6bc656d70fe`](https://github.com/poojakira/aws-agent-identity-guard/commit/bc35752dbfd72a7ce80eb1ad992bc6bc656d70fe)

**Successful CI:** [GitHub Actions run 38009457205](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/38009457205)

- Python 3.12 JUnit-derived summary: **247 collected, 244 passed, 3 skipped, 0 failures, 0 errors**.
- Python 3.10, 3.11 and 3.12 tests, lint/format, security audit and synthetic performance gate completed successfully in the cited run.
- The current local source skips three direct rule-module tests because the suite explicitly sets `HAS_RULES = False` for an unavailable separate rules API. Supplying AWS credentials does not enable this separate API. This is a static analyzer; no live AWS effective-permission evaluation is implied.
- Historical poster and September benchmark figures below remain valid only for their anchored snapshot; the October CI summary does not assert a new benchmark value.

## Historical main verification - 2026-09-30

**Code commit:** `c39ba67f43ef6ebddd03a8ce429b42afec0c08a9`  
**Successful CI:** https://github.com/poojakira/aws-agent-identity-guard/actions/runs/36781556871

| Claim | Historical verified value | Scope |
|---|---:|---|
| Test result | **243 collected, 240 passed, 3 skipped** | September 2026 CI at cited commit |
| Deterministic rule IDs | **25** | Static rule inventory at cited commit |
| Performance p95 | **0.8397 ms/policy** | September 2026 CI, 500 synthetic policies |
| Performance throughput | **2,573 policies/sec** | Same synthetic gate |
| Configured p95 gate | **< 10 ms/policy** | Gate threshold, not an SLO |
| Configured throughput gate | **> 1,000 policies/sec** | Gate threshold, not an SLO |

The historical count of 3 skips is retained above. The current local skip reasons are documented below; do not infer that supplying AWS credentials will enable those tests. Never commit credentials.

## Claim boundary

This repository performs static IAM analysis. It does not establish runtime enforcement, production reliability, or complete account-wide effective permissions.

## Skip-reason verification, October 12, 2026

A fresh local Python 3.12 run passed 244 tests and skipped 3. Pytest identifies all
three skips in `tests/test_coverage_boost.py::TestRulesModule` as `rules module not
importable`. The guard is `skipif(not HAS_RULES)`; `HAS_RULES` is hardcoded false because
rules are data/patterns in `scanner.py`, not a separate public rules API. The prior statement that these skips require live
AWS credentials was not supported by this source or run. Historical counts and
run links above are preserved; this correction does not execute live AWS or
certify effective permissions. Ruff 0.8.4 lint passed.
