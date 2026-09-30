# Claim Ledger - Poster 02

> Verified code snapshot: `c39ba67f43ef6ebddd03a8ce429b42afec0c08a9`; successful CI run `36781556871`, 2026-09-30.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 235 passed, 3 skipped | VERIFIED_AT_SNAPSHOT | CI emits `PYTEST_EVIDENCE tests=238 passed=235 skipped=3 failures=0 errors=0`. |
| 2 | 25 deterministic rule IDs | VERIFIED_AT_SNAPSHOT | AIG001-AIG021, AIG-TP001-AIG-TP003, AIG-PB001; current README/code/tests. |
| 3 | Text / JSON / SARIF output | VERIFIED_AT_SNAPSHOT | Current CLI and tests. |
| 4 | p95 1.1460 ms on 500 synthetic policies | VERIFIED_AT_SNAPSHOT | Current CI performance gate; environment-scoped microbenchmark. |
| 5 | 1,846 policies/sec on the same synthetic gate | VERIFIED_AT_SNAPSHOT | Current CI performance gate; not an SLO. |
| 6 | Runtime enforcement or account-wide effective-permission proof | UNSUPPORTED | Static analyzer; not a runtime gatekeeper or full account graph analyzer. |

Prominent poster numbers must stay scoped to this snapshot and environment.
