# Performance Baseline — aws-agent-identity-guard

## Overview

This document establishes the performance baseline for the IAM policy scanner. All benchmarks are automated via `benchmarks/perf_gate.py` and enforced in CI.

## Performance Gates

| Metric | Gate Threshold | Typical Value | Notes |
|--------|---------------|---------------|-------|
| p95 latency | < 10 ms/policy | ~2-4 ms | Single policy scan (parse + evaluate 25 rules) |
| Throughput | > 1,000 policies/sec | ~2,000-5,000 | Varies by policy complexity |
| Memory | < 100 MB | ~30-50 MB | For 500 concurrent policy documents |
| Startup time | < 500 ms | ~100 ms | Module import + rule loading |

## Benchmark Methodology

### Test Configuration

- **Workload:** 500 synthetic IAM policies
- **Policy complexity:** 1–15 statements per policy (random distribution)
- **Statement features:** Mix of Allow/Deny, wildcards, conditions, NotAction/NotResource
- **Random seed:** Fixed (42) for reproducibility
- **Warm-up:** 5 policies scanned before timing begins
- **Environment:** Single-threaded, no network I/O

### Running Benchmarks

```bash
# Standard benchmark (500 policies)
python benchmarks/perf_gate.py

# Extended benchmark with JSON output
python benchmarks/perf_gate.py --policies 5000 --output results.json

# Quick smoke test
python benchmarks/perf_gate.py --policies 50
```

### Output Format

```json
{
  "metadata": {
    "num_policies": 500,
    "timestamp": "2026-08-27T19:42:00Z",
    "python_version": "3.12.4"
  },
  "latency_ms": {
    "min": 0.1234,
    "max": 8.5678,
    "mean": 2.3456,
    "median": 2.1000,
    "p90": 4.5000,
    "p95": 5.8000,
    "p99": 7.2000,
    "stddev": 1.2345
  },
  "throughput": {
    "policies_per_second": 3456.78,
    "total_seconds": 0.1446
  },
  "gates": {
    "p95_under_10ms": true,
    "throughput_over_1000": true
  },
  "passed": true
}
```

## Performance Characteristics

### Scaling Behavior

| Policies | Expected Total Time | Notes |
|----------|-------------------|-------|
| 100 | < 100 ms | Quick CI check |
| 500 | < 500 ms | Standard gate |
| 1,000 | < 1 sec | Extended validation |
| 10,000 | < 10 sec | Load testing |
| 100,000 | < 2 min | Enterprise-scale simulation |

Scanning is **O(n × r)** where n = number of statements and r = number of rules (25). Each rule evaluation is O(1) for fixed-pattern rules and O(a) for action-list rules where a = number of actions in the statement.

### Complexity Factors

The following increase per-policy scan time:

1. **Number of statements** — Linear scaling (dominant factor)
2. **Wildcard actions** — Slightly faster (early-match in pattern rules)
3. **Condition blocks** — Parsed but add ~0.1ms per condition
4. **NotAction/NotResource** — Requires additional logic, ~0.2ms overhead
5. **Large action lists** — Linear in number of actions per statement

### Memory Profile

| Component | Memory Usage |
|-----------|-------------|
| Rule definitions (25 rules) | ~50 KB |
| Single policy (parsed dict) | ~2-10 KB |
| 500 policies in memory | ~2-5 MB |
| Scanner working memory | ~1 MB |
| Total peak (500 policies) | ~10 MB |

## CI Integration

### GitHub Actions Performance Gate

The performance gate runs on every PR and push to main:

```yaml
- name: Run performance gate
  run: python benchmarks/perf_gate.py --output perf-results.json

- name: Check gate passed
  run: |
    python -c "
    import json, sys
    r = json.load(open('perf-results.json'))
    if not r['passed']:
        print('PERFORMANCE REGRESSION DETECTED')
        print(f\"p95: {r['latency_ms']['p95']:.2f}ms (gate: <10ms)\")
        print(f\"Throughput: {r['throughput']['policies_per_second']:.0f}/s (gate: >1000)\")
        sys.exit(1)
    "
```

### Handling CI Variability

CI runners have variable performance. The gates are set conservatively:

- **p95 < 10ms** is 2-5x above typical values, accounting for noisy neighbors.
- **Throughput > 1000/sec** is well below typical 3000-5000/sec, providing headroom.

If CI becomes flaky due to runner performance:
1. Check if the regression is reproducible locally.
2. If CI-only, consider raising thresholds by 50%.
3. Never disable the gate entirely.

## Regression Investigation

When a performance gate fails:

### Step 1: Reproduce Locally

```bash
python benchmarks/perf_gate.py --policies 500 --output local-results.json
```

### Step 2: Profile

```bash
python -m cProfile -o profile.out benchmarks/perf_gate.py --policies 100
python -c "
import pstats
p = pstats.Stats('profile.out')
p.sort_stats('cumulative')
p.print_stats(20)
"
```

### Step 3: Compare with Baseline

```bash
# Run on main branch
git stash
python benchmarks/perf_gate.py --output baseline.json

# Run on feature branch
git stash pop
python benchmarks/perf_gate.py --output feature.json

# Compare
python -c "
import json
b = json.load(open('baseline.json'))
f = json.load(open('feature.json'))
delta_p95 = f['latency_ms']['p95'] - b['latency_ms']['p95']
delta_tput = f['throughput']['policies_per_second'] - b['throughput']['policies_per_second']
print(f'p95 delta: {delta_p95:+.2f}ms')
print(f'Throughput delta: {delta_tput:+.0f} policies/sec')
"
```

### Common Causes of Regression

| Cause | Impact | Fix |
|-------|--------|-----|
| New rule with O(n²) logic | p95 increase | Optimize rule to O(n) |
| Regex compilation per call | Throughput drop | Pre-compile at module load |
| Deep copy of policy dicts | Memory + latency | Use read-only traversal |
| Unnecessary JSON re-serialization | Throughput drop | Pass dicts directly |
| New dependency import at scan time | Startup regression | Lazy import |

## Historical Baselines

| Version | p95 (ms) | Throughput (pol/s) | Rules | Date |
|---------|----------|-------------------|-------|------|
| 0.1.0 | 1.8 | 4,200 | 10 | 2026-03-15 |
| 0.2.0 | 2.5 | 3,800 | 18 | 2026-05-20 |
| 0.3.0 | 3.2 | 3,400 | 25 | 2026-08-01 |

*Note: Slight throughput decrease is expected as rule count grows linearly.*

## Design Decisions for Performance

1. **Zero runtime dependencies** — No serialization overhead from third-party libraries.
2. **Pre-compiled rule patterns** — All regex patterns compiled at import time.
3. **Single-pass evaluation** — Each statement is evaluated against all rules in one pass.
4. **No deep copy** — Policies are read-only during scanning.
5. **Early termination** — Rules short-circuit on first non-match.
6. **String interning** — Common AWS action prefixes are interned for fast comparison.
