"""
tests/benchmarks/benchmark_authorization.py
--------------------------------------------
Performance benchmarks for the authorization engine.

Measures latency percentiles (p50, p95, p99) for authorize(), risk scoring,
and policy evaluation. Outputs results in JSON format.

Usage:
    python -m tests.benchmarks.benchmark_authorization
    # or:
    python tests/benchmarks/benchmark_authorization.py
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from aws_agent_identity_guard.authorization import (
    AuthorizationConfig,
    AuthorizationEngine,
    AuthorizationMode,
)
from aws_agent_identity_guard.models import (
    AgentIdentity,
    AgentType,
    DataClassification,
    EffectiveEffect,
    EffectivePermission,
    Environment,
    TransactionRequest,
)
from aws_agent_identity_guard.policy_engine import PolicyEngine
from aws_agent_identity_guard.risk_engine import RiskEngine


# ─── Corpus Generation ────────────────────────────────────────────────────────


def _generate_agents(count: int) -> list[AgentIdentity]:
    """Generate a reproducible set of test agents."""
    agents = []
    envs = [Environment.DEVELOPMENT, Environment.STAGING, Environment.PRODUCTION]
    types = [AgentType.BEDROCK, AgentType.LAMBDA, AgentType.ECS, AgentType.EKS]
    classifications = [
        DataClassification.PUBLIC,
        DataClassification.INTERNAL,
        DataClassification.CONFIDENTIAL,
        DataClassification.SECRET,
    ]
    for i in range(count):
        agent = AgentIdentity(
            agent_id=f"bench-agent-{i:04d}",
            name=f"BenchAgent-{i:04d}",
            agent_type=types[i % len(types)],
            owner="bench-team",
            environment=envs[i % len(envs)],
            data_classification=classifications[i % len(classifications)],
        )
        agents.append(agent)
    return agents


def _generate_requests(agents: list[AgentIdentity], count: int) -> list[TransactionRequest]:
    """Generate a reproducible set of test requests."""
    actions = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "iam:PassRole",
        "iam:CreatePolicyVersion",
        "lambda:InvokeFunction",
        "secretsmanager:GetSecretValue",
        "sts:AssumeRole",
        "ec2:RunInstances",
        "dynamodb:Scan",
    ]
    resources = [
        "arn:aws:s3:::bucket/key",
        "*",
        "arn:aws:lambda:us-east-1:123456789012:function:func",
        "arn:aws:iam::123456789012:role/Role",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:key",
    ]

    requests = []
    for i in range(count):
        agent = agents[i % len(agents)]
        req = TransactionRequest(
            agent_id=agent.agent_id,
            principal=f"arn:aws:iam::123456789012:role/BenchRole-{i % 10}",
            tool=f"bench-tool-{i % 5}",
            action=actions[i % len(actions)],
            resource=resources[i % len(resources)],
        )
        requests.append(req)
    return requests


def _generate_permissions(count: int) -> list[EffectivePermission]:
    """Generate a reproducible set of effective permissions."""
    actions = [
        "s3:GetObject", "s3:PutObject", "iam:PassRole",
        "lambda:InvokeFunction", "sts:AssumeRole",
        "secretsmanager:GetSecretValue", "dynamodb:Scan",
    ]
    perms = []
    for i in range(count):
        perms.append(
            EffectivePermission(
                action=actions[i % len(actions)],
                resource="*",
                effective_effect=EffectiveEffect.ALLOWED,
            )
        )
    return perms


# ─── Benchmark Functions ──────────────────────────────────────────────────────


def _percentile(data: list[float], pct: float) -> float:
    """Compute a percentile from a sorted list."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    idx = int(len(sorted_data) * pct / 100)
    idx = min(idx, len(sorted_data) - 1)
    return sorted_data[idx]


def benchmark_authorize(request_count: int) -> dict:
    """
    Benchmark the authorize() method.

    Args:
        request_count: Number of requests to benchmark.

    Returns:
        Dictionary with latency statistics.
    """
    # Setup
    policy_engine = PolicyEngine()
    policy_engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: deny-iam-mutate
    effect: deny
    actions: ['iam:*']
    resources: ['*']
    priority: 100
  - name: allow-s3-read
    effect: allow
    actions: ['s3:GetObject']
    resources: ['*']
    priority: 50
  - name: step-up-secrets
    effect: step_up
    actions: ['secretsmanager:GetSecretValue']
    resources: ['*']
    priority: 80
""")

    config = AuthorizationConfig(
        mode=AuthorizationMode.FAIL_CLOSED,
        step_up_threshold=70.0,
        deny_threshold=90.0,
    )
    engine = AuthorizationEngine(
        config=config,
        risk_engine=RiskEngine(),
        policy_engine=policy_engine,
    )

    agents = _generate_agents(10)
    for agent in agents:
        engine.agent_registry.register(agent)
    requests = _generate_requests(agents, request_count)

    # Warm up
    for req in requests[:min(10, request_count)]:
        engine.authorize(req)

    # Benchmark
    latencies = []
    for req in requests:
        start = time.perf_counter()
        engine.authorize(req)
        elapsed_ms = (time.perf_counter() - start) * 1000
        latencies.append(elapsed_ms)

    return {
        "operation": "authorize",
        "request_count": request_count,
        "p50_ms": round(_percentile(latencies, 50), 4),
        "p95_ms": round(_percentile(latencies, 95), 4),
        "p99_ms": round(_percentile(latencies, 99), 4),
        "min_ms": round(min(latencies), 4),
        "max_ms": round(max(latencies), 4),
        "mean_ms": round(statistics.mean(latencies), 4),
        "stddev_ms": round(statistics.stdev(latencies), 4) if len(latencies) > 1 else 0.0,
        "total_time_s": round(sum(latencies) / 1000, 4),
    }


def benchmark_risk_scoring(request_count: int) -> dict:
    """
    Benchmark the risk scoring engine.

    Args:
        request_count: Number of scoring calls.

    Returns:
        Dictionary with latency statistics.
    """
    engine = RiskEngine()
    agents = _generate_agents(10)
    permissions = _generate_permissions(20)

    latencies = []
    for i in range(request_count):
        agent = agents[i % len(agents)]
        start = time.perf_counter()
        engine.score_agent(agent, permissions, [])
        elapsed_ms = (time.perf_counter() - start) * 1000
        latencies.append(elapsed_ms)

    return {
        "operation": "risk_scoring",
        "request_count": request_count,
        "p50_ms": round(_percentile(latencies, 50), 4),
        "p95_ms": round(_percentile(latencies, 95), 4),
        "p99_ms": round(_percentile(latencies, 99), 4),
        "min_ms": round(min(latencies), 4),
        "max_ms": round(max(latencies), 4),
        "mean_ms": round(statistics.mean(latencies), 4),
        "stddev_ms": round(statistics.stdev(latencies), 4) if len(latencies) > 1 else 0.0,
        "total_time_s": round(sum(latencies) / 1000, 4),
    }


def benchmark_policy_evaluation(request_count: int) -> dict:
    """
    Benchmark the policy evaluation engine.

    Args:
        request_count: Number of evaluation calls.

    Returns:
        Dictionary with latency statistics.
    """
    from aws_agent_identity_guard.models import RiskScore

    policy_engine = PolicyEngine()
    policy_engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: deny-iam
    effect: deny
    actions: ['iam:*']
    resources: ['*']
    priority: 100
  - name: deny-secrets-prod
    effect: deny
    actions: ['secretsmanager:*']
    environments: ['PRODUCTION']
    priority: 90
  - name: allow-s3
    effect: allow
    actions: ['s3:GetObject', 's3:ListBucket']
    resources: ['*']
    priority: 50
  - name: step-up-delete
    effect: step_up
    actions: ['s3:DeleteObject', 's3:DeleteBucket']
    resources: ['*']
    priority: 70
  - name: allow-lambda-invoke
    effect: allow
    actions: ['lambda:InvokeFunction']
    resources: ['*']
    priority: 40
""")

    agents = _generate_agents(10)
    requests = _generate_requests(agents, request_count)
    risk_score = RiskScore(overall=50.0)

    latencies = []
    for i, req in enumerate(requests):
        agent = agents[i % len(agents)]
        start = time.perf_counter()
        policy_engine.evaluate(req, agent, risk_score)
        elapsed_ms = (time.perf_counter() - start) * 1000
        latencies.append(elapsed_ms)

    return {
        "operation": "policy_evaluation",
        "request_count": request_count,
        "p50_ms": round(_percentile(latencies, 50), 4),
        "p95_ms": round(_percentile(latencies, 95), 4),
        "p99_ms": round(_percentile(latencies, 99), 4),
        "min_ms": round(min(latencies), 4),
        "max_ms": round(max(latencies), 4),
        "mean_ms": round(statistics.mean(latencies), 4),
        "stddev_ms": round(statistics.stdev(latencies), 4) if len(latencies) > 1 else 0.0,
        "total_time_s": round(sum(latencies) / 1000, 4),
    }


# ─── Main Entry ───────────────────────────────────────────────────────────────


def main() -> None:
    """Run all benchmarks and output JSON results."""
    print("=" * 70)
    print("  AWS Agent Identity Guard - Performance Benchmarks")
    print("=" * 70)
    print()

    results = {"benchmarks": [], "metadata": {}}

    request_sizes = [100, 1000, 10000]

    for size in request_sizes:
        print(f"  Running authorize() benchmark with {size} requests...")
        result = benchmark_authorize(size)
        results["benchmarks"].append(result)
        print(f"    p50={result['p50_ms']:.4f}ms  p95={result['p95_ms']:.4f}ms  p99={result['p99_ms']:.4f}ms")

    for size in request_sizes:
        print(f"  Running risk_scoring benchmark with {size} requests...")
        result = benchmark_risk_scoring(size)
        results["benchmarks"].append(result)
        print(f"    p50={result['p50_ms']:.4f}ms  p95={result['p95_ms']:.4f}ms  p99={result['p99_ms']:.4f}ms")

    for size in request_sizes:
        print(f"  Running policy_evaluation benchmark with {size} requests...")
        result = benchmark_policy_evaluation(size)
        results["benchmarks"].append(result)
        print(f"    p50={result['p50_ms']:.4f}ms  p95={result['p95_ms']:.4f}ms  p99={result['p99_ms']:.4f}ms")

    # Output full results as JSON
    output_path = Path(__file__).parent.parent.parent / "benchmark_results.json"
    output_path.write_text(json.dumps(results, indent=2))
    print(f"\n  Results written to: {output_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
