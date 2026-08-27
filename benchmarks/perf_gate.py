#!/usr/bin/env python3
"""Performance regression gate for aws-agent-identity-guard.

Generates 500 synthetic IAM policy documents and benchmarks the scanner.
Asserts:
  - p95 latency < 10ms per policy
  - Throughput > 1000 policies/sec

Usage:
    python benchmarks/perf_gate.py [--output results.json] [--policies 500]

Exit codes:
    0 - All gates passed
    1 - Performance regression detected
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Synthetic policy generator
# ---------------------------------------------------------------------------

AWS_SERVICES = [
    "s3", "ec2", "iam", "lambda", "dynamodb", "sqs", "sns", "kms",
    "sts", "cloudwatch", "logs", "secretsmanager", "rds", "ecs",
    "eks", "cloudformation", "ssm", "config", "guardduty", "inspector",
]

ACTIONS_PER_SERVICE = [
    "Get*", "List*", "Describe*", "Put*", "Delete*", "Create*",
    "Update*", "Invoke*", "TagResource", "UntagResource",
]


def _random_action() -> str:
    svc = random.choice(AWS_SERVICES)
    action = random.choice(ACTIONS_PER_SERVICE)
    return f"{svc}:{action}"


def _random_resource() -> str:
    account = "".join([str(random.randint(0, 9)) for _ in range(12)])
    svc = random.choice(AWS_SERVICES)
    return f"arn:aws:{svc}:us-east-1:{account}:resource/{random.randint(1, 9999)}"


def generate_policy(num_statements: int = 5) -> dict:
    """Generate a realistic synthetic IAM policy document."""
    statements = []
    for _ in range(num_statements):
        effect = random.choice(["Allow", "Deny"])
        num_actions = random.randint(1, 8)
        num_resources = random.randint(1, 4)

        statement: dict = {
            "Effect": effect,
            "Action": [_random_action() for _ in range(num_actions)],
            "Resource": [_random_resource() for _ in range(num_resources)],
        }

        # Occasionally add conditions
        if random.random() < 0.3:
            statement["Condition"] = {
                "StringEquals": {"aws:RequestedRegion": "us-east-1"}
            }

        # Occasionally use wildcards (privilege escalation pattern)
        if random.random() < 0.15:
            statement["Action"] = ["*"]
            statement["Resource"] = ["*"]

        statements.append(statement)

    return {
        "Version": "2012-10-17",
        "Statement": statements,
    }


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------


def run_benchmark(num_policies: int = 500) -> dict:
    """Run the performance benchmark and return results."""
    # Import the scanner - adjust import path as needed
    try:
        from aws_agent_identity_guard import scan_policy
    except ImportError:
        try:
            from aws_agent_identity_guard.scanner import scan_policy
        except ImportError:
            # Fallback: try to find the module in the project
            sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
            try:
                from aws_agent_identity_guard import scan_policy
            except ImportError:
                from aws_agent_identity_guard.scanner import scan_policy

    # Generate policies
    random.seed(42)  # Reproducible benchmarks
    policies = [generate_policy(num_statements=random.randint(1, 15)) for _ in range(num_policies)]

    # Warm-up run (5 policies)
    for p in policies[:5]:
        scan_policy(p)

    # Timed benchmark
    latencies: list[float] = []
    start_total = time.perf_counter()

    for policy in policies:
        t0 = time.perf_counter()
        scan_policy(policy)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000)  # Convert to ms

    end_total = time.perf_counter()
    total_seconds = end_total - start_total

    # Compute statistics
    latencies_sorted = sorted(latencies)
    p50 = latencies_sorted[int(len(latencies_sorted) * 0.50)]
    p90 = latencies_sorted[int(len(latencies_sorted) * 0.90)]
    p95 = latencies_sorted[int(len(latencies_sorted) * 0.95)]
    p99 = latencies_sorted[int(len(latencies_sorted) * 0.99)]
    throughput = num_policies / total_seconds

    results = {
        "metadata": {
            "num_policies": num_policies,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "python_version": sys.version,
        },
        "latency_ms": {
            "min": round(min(latencies), 4),
            "max": round(max(latencies), 4),
            "mean": round(statistics.mean(latencies), 4),
            "median": round(p50, 4),
            "p90": round(p90, 4),
            "p95": round(p95, 4),
            "p99": round(p99, 4),
            "stddev": round(statistics.stdev(latencies), 4),
        },
        "throughput": {
            "policies_per_second": round(throughput, 2),
            "total_seconds": round(total_seconds, 4),
        },
        "gates": {
            "p95_under_10ms": p95 < 10.0,
            "throughput_over_1000": throughput > 1000.0,
        },
        "passed": p95 < 10.0 and throughput > 1000.0,
    }

    return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="Performance regression gate")
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Path to write JSON results (default: stdout)",
    )
    parser.add_argument(
        "--policies", "-n",
        type=int,
        default=500,
        help="Number of policies to benchmark (default: 500)",
    )
    args = parser.parse_args()

    print(f"Running performance benchmark with {args.policies} policies...", file=sys.stderr)
    results = run_benchmark(num_policies=args.policies)

    # Output results
    output_json = json.dumps(results, indent=2)
    if args.output:
        Path(args.output).write_text(output_json, encoding="utf-8")
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(output_json)

    # Report
    print("\n--- Performance Gate Results ---", file=sys.stderr)
    print(f"  Policies scanned:    {args.policies}", file=sys.stderr)
    print(f"  p95 latency:         {results['latency_ms']['p95']:.4f} ms (gate: <10ms)", file=sys.stderr)
    print(f"  Throughput:          {results['throughput']['policies_per_second']:.0f} policies/sec (gate: >1000)", file=sys.stderr)
    print(f"  p95 gate:            {'PASS' if results['gates']['p95_under_10ms'] else 'FAIL'}", file=sys.stderr)
    print(f"  Throughput gate:     {'PASS' if results['gates']['throughput_over_1000'] else 'FAIL'}", file=sys.stderr)
    print(f"  Overall:             {'PASS ✓' if results['passed'] else 'FAIL ✗'}", file=sys.stderr)

    return 0 if results["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
