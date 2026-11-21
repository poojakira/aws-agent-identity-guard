> **Historical research poster, October 14, 2026 UTC.** Its measurements apply to source `718582f5fd8419b0b8c2ca21361f7b0c715cb54b` and the [associated GitHub Actions run](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/38497940763). See the [later candidate manifest](https://raw.githubusercontent.com/poojakira/aws-agent-identity-guard/a396433a4070a0ddc68aa83f9b1093e87fc3224f/release-evidence/manifest.json) for separately scoped local verification.

# Claim Ledger - Poster 02

> Verified code snapshot: `718582f5fd8419b0b8c2ca21361f7b0c715cb54b`; successful CI run `38497940763`, 2026-10-14.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 244 passed, 3 skipped | VERIFIED_AT_SNAPSHOT | CI emits `PYTEST_EVIDENCE tests=247 passed=244 skipped=3 failures=0 errors=0`. Oct 14 2026 main CI run 38497940763. |
| 2 | 25 deterministic rule IDs | VERIFIED_AT_SNAPSHOT | AIG001-AIG021, AIG-TP001-AIG-TP003, AIG-PB001; code/tests at the cited snapshot. |
| 3 | Text / JSON / SARIF output | VERIFIED_AT_SNAPSHOT | CLI/tests at the cited snapshot. |
| 4 | p95 0.8397 ms on 500 synthetic policies | VERIFIED_AT_SNAPSHOT | Older cited October 4 synthetic policy benchmark; not that test-run latency. |
| 5 | 2,573 policies/sec on the same synthetic gate | VERIFIED_AT_SNAPSHOT | Older cited October 4 synthetic benchmark; not a production SLO. |
| 6 | Runtime enforcement or account-wide effective-permission proof | UNSUPPORTED | Static analyzer; not a runtime gatekeeper or full account graph analyzer. |

Prominent poster numbers must stay scoped to this snapshot and environment.

## Interpretation

The poster inventory includes 24 static rule IDs and one live-context rule ID. Mocked AWS calls support local regression and require separate evidence for live IAM behavior.
