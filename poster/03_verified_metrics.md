> **Historical poster: October 14, 2026 source snapshot.** Values below attest only to their cited code/run, not to the later studio or documentation head. See [source-scoped evidence](../docs/EVIDENCE.md).

# Verified Metrics - Poster 02

**Poster code snapshot:** `718582f5fd8419b0b8c2ca21361f7b0c715cb54b`
**Successful Python 3.12 CI:** https://github.com/poojakira/aws-agent-identity-guard/actions/runs/38497940763

| Metric | Cited historical test snapshot |
|---|---:|
| Tests collected | **247** |
| Tests passed | **244** |
| Tests skipped (legacy rules API absent) | **3** |
| Product IDs (24 static + 1 live-context) | **25** |

## Separate historical synthetic performance evidence

The older [October 4, 2026 CI](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/37170669504) at commit `229605c9c53068f4c0d7116d67554d19afe30183` recorded **0.8397 ms synthetic-policy p95** and **2,573 synthetic policies/sec**, from 500 artificial policies. These are not measurements in the cited historical test run, are not production SLOs, and must not be combined with the cited test count as if all were one run.

The same archived October 4 poster originally recorded **243 collected, 240 passed, 3 skipped**. See [VERIFIED_METRICS.md](../VERIFIED_METRICS.md) for the dated split.
