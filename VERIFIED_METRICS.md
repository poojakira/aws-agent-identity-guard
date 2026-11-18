# Source-scoped verification snapshots

## Published implementation source

Source **`970d1e1e3d5e65e91bd45fe16bb59725eec7b1dc`**: **270 collected, 267 passed, 3 skipped, 0 failures/errors; 77.14791851195749% statement coverage**. The skipped `TestRulesModule` tests in `tests/test_coverage_boost.py` have reason `rules module not importable`; they do not require live credentials. The optional separate rules API is absent, while canonical procedural rules are tested.

At that same source, focused independent review passed 38 observations and 23 Python 3.10 tests. Seven associated hosted workflows succeeded; explicit-head studio execution and identical-tree legacy PR-merge execution are distinguished in the [published assessment](https://github.com/poojakira/aws-agent-identity-guard/blob/9d829ee9a65df098ba91fe4672d88bfd63788999/release-evidence/RELEASE_ASSESSMENT.md). These are prior-source results, not evidence for later documentation commits. See [current procedure/status](docs/EVIDENCE.md).

## Historical records

| Snapshot | Recorded outcome | Boundary |
|---|---|---|
| October 14, 2026 source `718582f5fd8419b0b8c2ca21361f7b0c715cb54b`, [run 38497940763](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/38497940763) | 247 collected, 244 passed, 3 skipped | Three legacy rules-module skips; no live AWS validation |
| October 13, 2026 [run 38462296804](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/38462296804) | 247 collected, 244 passed, 3 skipped | Historical CI, not a new benchmark |
| October 10, 2026 source `4098ff55`, [run 38009457205](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/38009457205) | 247 collected, 244 passed, 3 skipped | Historical CI source; skips are not successful validation |
| September 30, 2026 source `c39ba67f43ef6ebddd03a8ce429b42afec0c08a9`, [run 36781556871](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/36781556871) | Earlier synthetic performance: p95 0.8397 ms/policy, 2,573 policies/sec | 500 artificial policies; not field workload or SLO |

The 25 product IDs comprise 21 identity rules, 3 trust rules and 1 live-context boundary-presence check. They are not 25 static checks. The existing synthetic benchmark enforces p95 below 10 ms/policy and throughput above 1,000 policies/sec; threshold values are not measured results or universal guarantees. Historical performance/test snapshots must not be joined as if measured in one run.

Historical artifacts, submitted résumé figures and poster source values remain dated. External run retention, original research/chronology and field outcomes have not been independently revalidated by a documentation rewrite. A new candidate needs fresh exact-source evidence before its metrics are called current.
