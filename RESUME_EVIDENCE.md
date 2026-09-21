# Resume Evidence

This file anchors the quantitative claims used on Pooja Kiran's resume.

## Resume claims

- **25 rule IDs**
- **230 passing tests**
- performance gate: **p95 under 10 ms per policy**
- performance gate: **more than 1,000 policies/second**

### 25 rule IDs

The emitted rule IDs are:

- AIG001-AIG021 = 21 identity-policy rules
- AIG-TP001-AIG-TP003 = 3 trust-policy rules
- AIG-PB001 = 1 permission-boundary rule

Total: **25**.

The implementation lives in `src/aws_agent_identity_guard/scanner.py` and `src/aws_agent_identity_guard/live_scanner.py`.

### 230 passing tests

The verified test snapshot records **230 passed, 3 skipped**. Coverage includes positive/negative rule cases, parser edge cases and Hypothesis fuzzing, SARIF output validation, and failure-mode tests.

### Performance gates

The CI workflow runs:

```text
python benchmarks/perf_gate.py --policies 500 --output perf-results.json
```

The benchmark enforces:

- **p95 latency < 10 ms per policy**
- **throughput > 1,000 policies/second**

A successful current CI performance job on 2026-09-21 reported:

```text
p95 latency: 1.1473 ms (gate: <10ms)
Throughput: 1866 policies/sec (gate: >1000)
p95 gate: PASS
Throughput gate: PASS
```

GitHub Actions run: https://github.com/poojakira/aws-agent-identity-guard/actions/runs/35555722252

These values are regression gates measured on a 500-policy synthetic benchmark, not universal production-performance guarantees.
