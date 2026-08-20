# Benchmark Corpus

Reproducible test data for performance benchmarking of the AWS Agent Identity Guard system.

## Contents

| File | Description | Count |
|------|-------------|-------|
| `agents.json` | Sample agent identities spanning all types and risk levels | 10 |
| `policies.json` | Security policies with varying effects and conditions | 10 |
| `transactions.json` | Transaction requests covering benign, risky, and malicious actions | 50 |

## Reproducing Benchmarks

1. Ensure the project is installed:

```bash
cd /path/to/aws-agent-identity-guard
pip install -e .
```

2. Run the benchmark script:

```bash
python tests/benchmarks/benchmark_authorization.py
```

3. Results are written to `benchmark_results.json` in the project root.

## Corpus Design Principles

- **Deterministic**: All IDs and values are fixed. No randomness. Re-running produces identical inputs.
- **Representative**: Covers all agent types (BEDROCK, LAMBDA, ECS, EKS, SAGEMAKER, CUSTOM), all environments (DEVELOPMENT, STAGING, PRODUCTION), and all data classifications.
- **Adversarial mix**: Includes both benign and malicious transaction patterns so benchmarks measure both fast-path (allow) and slow-path (deny with full evaluation) performance.
- **Scalable**: The benchmark script can use this corpus as a seed and scale to 100, 1000, or 10000 requests by cycling through the corpus.

## Data Schema

### agents.json

Each agent object:
- `agent_id`: Unique identifier
- `name`: Human-readable name
- `agent_type`: One of BEDROCK, LAMBDA, ECS, EKS, SAGEMAKER, CUSTOM
- `owner`: Responsible team
- `environment`: DEVELOPMENT, STAGING, or PRODUCTION
- `data_classification`: PUBLIC, INTERNAL, CONFIDENTIAL, SECRET, or REGULATED
- `purpose`: Description of intended function

### policies.json

Each policy object:
- `name`: Rule identifier
- `effect`: DENY, ALLOW, STEP_UP, or REQUIRE_APPROVAL
- `actions`: List of IAM action patterns
- `resources`: List of resource ARN patterns
- `environments`: (optional) Environment scope
- `conditions`: (optional) Condition map
- `priority`: Evaluation priority (higher = first)
- `description`: Human-readable explanation

### transactions.json

Each transaction object:
- `agent_id`: The requesting agent
- `action`: IAM action being attempted
- `resource`: Target resource ARN
- `tool`: The tool/function invoking the action

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| authorize() p50 | < 1ms | Single authorization decision |
| authorize() p95 | < 5ms | Under sustained load |
| authorize() p99 | < 10ms | Worst-case tail latency |
| Risk scoring p50 | < 0.5ms | Six-dimension scoring |
| Policy evaluation p50 | < 0.2ms | Rule matching and conditions |
