# Claim Ledger - Poster 02

> Verified code snapshot: `229605c9c53068f4c0d7116d67554d19afe30183`; successful CI run `37170669504`, 2026-10-04.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 240 passed, 3 skipped | VERIFIED_AT_SNAPSHOT | CI emits `PYTEST_EVIDENCE tests=243 passed=240 skipped=3 failures=0 errors=0`. |
| 2 | 25 deterministic rule IDs | VERIFIED_AT_SNAPSHOT | AIG001-AIG021, AIG-TP001-AIG-TP003, AIG-PB001; current README/code/tests. |
| 3 | Text / JSON / SARIF output | VERIFIED_AT_SNAPSHOT | Current CLI and tests. |
| 4 | p95 0.8397 ms on 500 synthetic policies | VERIFIED_AT_SNAPSHOT | Current CI performance gate; environment-scoped microbenchmark. |
| 5 | 2,573 policies/sec on the same synthetic gate | VERIFIED_AT_SNAPSHOT | Current CI performance gate; not an SLO. |
| 6 | Runtime enforcement or account-wide effective-permission proof | UNSUPPORTED | Static analyzer; not a runtime gatekeeper or full account graph analyzer. |

Prominent poster numbers must stay scoped to this snapshot and environment.
