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

Fresh current-head proof:

- GitHub Actions run: https://github.com/poojakira/aws-agent-identity-guard/actions/runs/35637577557
- Python 3.11 test job: `106458771376`
- Head commit: `e95fc426e326e1ce9d2ffe03c39cc7d203631f15`

The workflow emits a machine-readable JUnit-derived summary and fails if the documented count drifts:

```text
PYTEST_EVIDENCE tests=233 passed=230 skipped=3 failures=0 errors=0
```

The same exact-count gate runs in the Python 3.10/3.11/3.12 matrix. Coverage includes positive/negative rule cases, parser edge cases and Hypothesis fuzzing, SARIF output validation, and failure-mode tests.

### Performance gates

The CI workflow runs:

```text
python benchmarks/perf_gate.py --policies 500 --output perf-results.json
```

The benchmark enforces:

- **p95 latency < 10 ms per policy**
- **throughput > 1,000 policies/second**

The same fresh current-head CI run reported:

```text
p95 latency: 0.8491 ms (gate: <10ms)
Throughput: 2596 policies/sec (gate: >1000)
p95 gate: PASS
Throughput gate: PASS
```

GitHub Actions run: https://github.com/poojakira/aws-agent-identity-guard/actions/runs/35637577557  
Performance job: `106458771333`

These values are regression gates measured on a 500-policy synthetic benchmark, not universal production-performance guarantees.
