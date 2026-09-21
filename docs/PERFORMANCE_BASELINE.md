# Performance Gate — aws-agent-identity-guard

## Evidence policy

The repository makes **two performance-gate claims**:

| Metric | Enforced threshold | Source |
|---|---:|---|
| p95 scan latency | **< 10 ms per policy** | `benchmarks/perf_gate.py` |
| Throughput | **> 1,000 policies/second** | `benchmarks/perf_gate.py` |

These are regression **thresholds**, not universal performance guarantees. Hardware, Python version, policy complexity, and runner load affect measured values.

The repository does **not** claim a fixed "typical" p95, fixed throughput, memory footprint, or startup time unless a raw benchmark result artifact is committed or attached to a cited CI run.

## Benchmark methodology

`benchmarks/perf_gate.py`:

- generates 500 synthetic IAM policies by default;
- uses a fixed random seed of 42;
- varies policies from 1 to 15 statements;
- warms up on 5 policies;
- scans single-threaded with no network I/O;
- measures per-policy latency with `time.perf_counter()`;
- computes p50, p90, p95, p99, mean, median, standard deviation, and throughput;
- exits non-zero when either gate fails.

Run it with:

```bash
python benchmarks/perf_gate.py --policies 500 --output perf-results.json
```

The JSON result contains the measured latency distribution, throughput, gate booleans, Python version, timestamp, and policy count.

## CI enforcement

The real workflow `.github/workflows/ci.yml` runs:

```bash
python benchmarks/perf_gate.py --policies 500 --output perf-results.json
```

and uploads `perf-results.json` as the `performance-results` artifact. The job fails if p95 is not below 10 ms or throughput is not above 1,000 policies/second.

## Claim wording

Safe résumé/portfolio wording:

> Performance-gated in CI at p95 <10 ms per synthetic policy and >1,000 policies/second on the committed 500-policy benchmark.

Do not convert those gates into a claim that production AWS IAM scanning will always achieve those values.
