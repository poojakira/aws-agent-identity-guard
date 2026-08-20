"""Performance benchmarks for the authorization system.

Measures authorization latency (p50, p95, p99), throughput (decisions/sec),
risk scoring latency, and policy evaluation latency.

Run with: pytest tests/benchmarks/benchmark_authorization.py -v --tb=short
"""

from __future__ import annotations

import statistics
import time
from typing import Any

import pytest

from aws_agent_identity_guard.models import (
    Agent,
    DataClassification,
    Environment,
    WorkloadType,
)
from aws_agent_identity_guard.authorization import (
    AuthorizationConfig,
    AuthorizationRequest,
    AuthorizationService,
    DecisionCache,
    DefaultPolicyEngine,
    DefaultRiskEngine,
)
from aws_agent_identity_guard.risk_engine import RiskEngine


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def service() -> AuthorizationService:
    """Authorization service for benchmarking."""
    return AuthorizationService(config=AuthorizationConfig())


@pytest.fixture
def uncached_service() -> AuthorizationService:
    """Authorization service with caching disabled."""
    config = AuthorizationConfig(cache_enabled=False)
    return AuthorizationService(config=config)


@pytest.fixture
def risk_engine() -> RiskEngine:
    """Risk engine for benchmarking."""
    return RiskEngine(profile="standard")


@pytest.fixture
def policy_engine() -> DefaultPolicyEngine:
    """Policy engine for benchmarking."""
    return DefaultPolicyEngine()


@pytest.fixture
def sample_requests() -> list[AuthorizationRequest]:
    """Generate a variety of authorization requests for benchmarking."""
    actions = [
        ("s3:GetObject", "arn:aws:s3:::bucket/key", DataClassification.PUBLIC),
        ("s3:PutObject", "arn:aws:s3:::prod-bucket/data", DataClassification.CONFIDENTIAL),
        ("iam:PassRole", "arn:aws:iam::123456789012:role/admin", DataClassification.SECRET),
        ("lambda:InvokeFunction", "arn:aws:lambda:us-east-1:123:function:proc", DataClassification.INTERNAL),
        ("dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:123:table/users", DataClassification.CONFIDENTIAL),
        ("secretsmanager:GetSecretValue", "arn:aws:secretsmanager:us-east-1:123:secret:cred", DataClassification.SECRET),
        ("ec2:RunInstances", "arn:aws:ec2:us-east-1:123:instance/*", DataClassification.INTERNAL),
        ("kms:Decrypt", "arn:aws:kms:us-east-1:123:key/master", DataClassification.REGULATED),
        ("cloudtrail:StopLogging", "arn:aws:cloudtrail:us-east-1:123:trail/main", DataClassification.INTERNAL),
        ("sts:AssumeRole", "arn:aws:iam::999999999999:role/external", DataClassification.SECRET),
    ]
    requests = []
    for i, (action, resource, classification) in enumerate(actions):
        for env in [Environment.DEV, Environment.STAGING, Environment.PRODUCTION]:
            req = AuthorizationRequest.create(
                agent_id=f"bench-agent-{i}",
                agent_name=f"benchmark-agent-{i}",
                principal=f"user{i}@corp.com",
                action=action,
                resource=resource,
                environment=env,
                data_classification=classification,
            )
            requests.append(req)
    return requests


# =============================================================================
# Helper Functions
# =============================================================================


def _percentile(data: list[float], pct: float) -> float:
    """Calculate percentile from a sorted list."""
    sorted_data = sorted(data)
    idx = int(len(sorted_data) * pct / 100.0)
    idx = min(idx, len(sorted_data) - 1)
    return sorted_data[idx]


# =============================================================================
# Test: Authorization Latency
# =============================================================================


class TestAuthorizationLatency:
    """Benchmark authorization decision latency."""

    def test_cached_authorization_latency(self, service: AuthorizationService, sample_requests: list[AuthorizationRequest]) -> None:
        """Measure cached authorization latency (p50, p95, p99).

        Target: <10ms for cached decisions.
        """
        # Warm up cache
        for req in sample_requests[:5]:
            service.authorize(req)

        # Measure cached latency
        latencies = []
        for _ in range(100):
            for req in sample_requests[:5]:
                start = time.perf_counter()
                service.authorize(req)
                elapsed_ms = (time.perf_counter() - start) * 1000
                latencies.append(elapsed_ms)

        p50 = _percentile(latencies, 50)
        p95 = _percentile(latencies, 95)
        p99 = _percentile(latencies, 99)

        print(f"\nCached Authorization Latency:")
        print(f"  p50: {p50:.3f}ms")
        print(f"  p95: {p95:.3f}ms")
        print(f"  p99: {p99:.3f}ms")
        print(f"  count: {len(latencies)}")

        # Performance assertions (generous for CI environments)
        assert p50 < 50.0, f"p50 latency {p50:.3f}ms exceeds 50ms target"
        assert p95 < 100.0, f"p95 latency {p95:.3f}ms exceeds 100ms target"

    def test_uncached_authorization_latency(self, uncached_service: AuthorizationService, sample_requests: list[AuthorizationRequest]) -> None:
        """Measure uncached authorization latency (full pipeline).

        Target: <50ms for uncached decisions.
        """
        latencies = []
        for req in sample_requests:
            start = time.perf_counter()
            uncached_service.authorize(req)
            elapsed_ms = (time.perf_counter() - start) * 1000
            latencies.append(elapsed_ms)

        p50 = _percentile(latencies, 50)
        p95 = _percentile(latencies, 95)
        p99 = _percentile(latencies, 99)

        print(f"\nUncached Authorization Latency:")
        print(f"  p50: {p50:.3f}ms")
        print(f"  p95: {p95:.3f}ms")
        print(f"  p99: {p99:.3f}ms")
        print(f"  count: {len(latencies)}")

        assert p50 < 200.0, f"p50 latency {p50:.3f}ms exceeds 200ms target"
        assert p95 < 500.0, f"p95 latency {p95:.3f}ms exceeds 500ms target"


# =============================================================================
# Test: Throughput (Decisions/sec)
# =============================================================================


class TestThroughput:
    """Benchmark authorization throughput."""

    def test_cached_throughput(self, service: AuthorizationService, sample_requests: list[AuthorizationRequest]) -> None:
        """Measure cached decisions per second.

        Target: >1000 decisions/sec for cached requests.
        """
        # Warm up cache
        for req in sample_requests[:10]:
            service.authorize(req)

        # Measure throughput
        count = 0
        start = time.perf_counter()
        duration = 1.0  # Run for 1 second

        while (time.perf_counter() - start) < duration:
            for req in sample_requests[:10]:
                service.authorize(req)
                count += 1
                if (time.perf_counter() - start) >= duration:
                    break

        elapsed = time.perf_counter() - start
        throughput = count / elapsed

        print(f"\nCached Throughput:")
        print(f"  Decisions/sec: {throughput:.0f}")
        print(f"  Total decisions: {count}")
        print(f"  Duration: {elapsed:.3f}s")

        assert throughput > 100, f"Throughput {throughput:.0f}/sec below 100/sec minimum"

    def test_uncached_throughput(self, uncached_service: AuthorizationService, sample_requests: list[AuthorizationRequest]) -> None:
        """Measure uncached decisions per second."""
        count = 0
        start = time.perf_counter()
        duration = 1.0

        while (time.perf_counter() - start) < duration:
            for req in sample_requests:
                uncached_service.authorize(req)
                count += 1
                if (time.perf_counter() - start) >= duration:
                    break

        elapsed = time.perf_counter() - start
        throughput = count / elapsed

        print(f"\nUncached Throughput:")
        print(f"  Decisions/sec: {throughput:.0f}")
        print(f"  Total decisions: {count}")

        assert throughput > 50, f"Uncached throughput {throughput:.0f}/sec below 50/sec minimum"


# =============================================================================
# Test: Risk Scoring Latency
# =============================================================================


class TestRiskScoringLatency:
    """Benchmark risk scoring engine performance."""

    def test_permission_scoring_latency(self, risk_engine: RiskEngine) -> None:
        """Measure individual permission scoring latency."""
        actions = [
            "iam:PassRole", "s3:GetObject", "lambda:CreateFunction",
            "sts:AssumeRole", "kms:Decrypt", "ec2:RunInstances",
            "secretsmanager:GetSecretValue", "cloudtrail:StopLogging",
            "iam:CreateRole", "s3:DeleteBucket",
        ]
        latencies = []
        for _ in range(100):
            for action in actions:
                start = time.perf_counter()
                risk_engine.score_permission(action, "*")
                elapsed_ms = (time.perf_counter() - start) * 1000
                latencies.append(elapsed_ms)

        p50 = _percentile(latencies, 50)
        p95 = _percentile(latencies, 95)
        p99 = _percentile(latencies, 99)

        print(f"\nPermission Scoring Latency:")
        print(f"  p50: {p50:.3f}ms")
        print(f"  p95: {p95:.3f}ms")
        print(f"  p99: {p99:.3f}ms")

        assert p50 < 50.0, f"Risk scoring p50 {p50:.3f}ms exceeds 50ms"
        assert p95 < 100.0, f"Risk scoring p95 {p95:.3f}ms exceeds 100ms"

    def test_agent_scoring_latency(self, risk_engine: RiskEngine) -> None:
        """Measure agent-level risk scoring latency."""
        agent = Agent.create(
            name="bench-agent", owner="ops",
            environment=Environment.PRODUCTION,
            workload_type=WorkloadType.BEDROCK_AGENT,
            iam_role_arn="arn:aws:iam::123456789012:role/bench",
            data_classification=DataClassification.SECRET,
        )
        agent_dict = agent.to_dict()
        agent_dict["identity_policies"] = [
            {
                "PolicyName": "full-access",
                "PolicyDocument": {
                    "Statement": [
                        {"Effect": "Allow", "Action": ["iam:*", "s3:*", "lambda:*", "ec2:*"], "Resource": "*"}
                    ]
                },
            }
        ]
        agent_loaded = Agent.from_dict(agent_dict)

        latencies = []
        for _ in range(50):
            start = time.perf_counter()
            risk_engine.score_agent(agent_loaded)
            elapsed_ms = (time.perf_counter() - start) * 1000
            latencies.append(elapsed_ms)

        p50 = _percentile(latencies, 50)
        p95 = _percentile(latencies, 95)

        print(f"\nAgent Scoring Latency:")
        print(f"  p50: {p50:.3f}ms")
        print(f"  p95: {p95:.3f}ms")

        assert p50 < 200.0, f"Agent scoring p50 {p50:.3f}ms exceeds 200ms"


# =============================================================================
# Test: Policy Evaluation Latency
# =============================================================================


class TestPolicyEvaluationLatency:
    """Benchmark policy evaluation engine performance."""

    def test_policy_evaluation_latency(self, policy_engine: DefaultPolicyEngine) -> None:
        """Measure policy evaluation latency with default rules."""
        requests = [
            AuthorizationRequest.create(
                agent_id=f"bench-{i}", agent_name=f"bench-{i}",
                principal="user@corp.com", action=action,
                resource=resource, environment=env,
                data_classification=DataClassification.INTERNAL,
            )
            for i, (action, resource, env) in enumerate([
                ("iam:PassRole", "*", Environment.PRODUCTION),
                ("s3:GetObject", "arn:aws:s3:::bucket/key", Environment.DEV),
                ("cloudtrail:StopLogging", "*", Environment.PRODUCTION),
                ("lambda:InvokeFunction", "arn:aws:lambda:us-east-1:123:function:f", Environment.STAGING),
                ("kms:ScheduleKeyDeletion", "*", Environment.PRODUCTION),
            ])
        ]

        latencies = []
        for _ in range(200):
            for req in requests:
                start = time.perf_counter()
                policy_engine.evaluate(req)
                elapsed_ms = (time.perf_counter() - start) * 1000
                latencies.append(elapsed_ms)

        p50 = _percentile(latencies, 50)
        p95 = _percentile(latencies, 95)
        p99 = _percentile(latencies, 99)

        print(f"\nPolicy Evaluation Latency:")
        print(f"  p50: {p50:.3f}ms")
        print(f"  p95: {p95:.3f}ms")
        print(f"  p99: {p99:.3f}ms")
        print(f"  count: {len(latencies)}")

        assert p50 < 20.0, f"Policy evaluation p50 {p50:.3f}ms exceeds 20ms"
        assert p95 < 50.0, f"Policy evaluation p95 {p95:.3f}ms exceeds 50ms"

    def test_policy_evaluation_with_many_rules(self) -> None:
        """Measure policy evaluation with a large rule set."""
        # Create engine with many rules
        rules = []
        for i in range(100):
            rules.append(PolicyRule.create(
                name=f"rule-{i}",
                action_patterns=[f"service{i}:Action{j}" for j in range(5)],
                resource_patterns=[f"arn:aws:service{i}:*:*:resource-{j}" for j in range(3)],
                effect=PermissionEffect.DENY if i % 3 == 0 else PermissionEffect.ALLOW,
                environments=[Environment.PRODUCTION],
                priority=i,
            ))

        engine = DefaultPolicyEngine(rules=rules)

        request = AuthorizationRequest.create(
            agent_id="bench-many", agent_name="many-rules",
            principal="user@corp.com", action="service50:Action2",
            resource="arn:aws:service50:us-east-1:123:resource-1",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )

        latencies = []
        for _ in range(100):
            start = time.perf_counter()
            engine.evaluate(request)
            elapsed_ms = (time.perf_counter() - start) * 1000
            latencies.append(elapsed_ms)

        p50 = _percentile(latencies, 50)
        p95 = _percentile(latencies, 95)

        print(f"\nLarge Ruleset Policy Evaluation:")
        print(f"  Rules: {len(rules)}")
        print(f"  p50: {p50:.3f}ms")
        print(f"  p95: {p95:.3f}ms")

        assert p50 < 100.0, f"Large ruleset p50 {p50:.3f}ms exceeds 100ms"


# =============================================================================
# Test: Cache Performance
# =============================================================================


class TestCachePerformance:
    """Benchmark cache operations."""

    def test_cache_hit_vs_miss_latency(self) -> None:
        """Compare cache hit vs miss latency."""
        cache = DecisionCache(max_size=1000, ttl_seconds=60.0)
        request = AuthorizationRequest.create(
            agent_id="hit-miss-bench", agent_name="bench",
            principal="user@corp.com", action="s3:GetObject",
            resource="arn:aws:s3:::bucket/key",
            environment=Environment.DEV,
            data_classification=DataClassification.PUBLIC,
        )
        from aws_agent_identity_guard.authorization import AuthorizationDecision as AD
        decision = AD.allow(reasons=["ok"], policy="", risk_score=0, correlation_id="c-hm")
        cache.put(request, decision)

        # Measure hit latency
        hit_latencies = []
        for _ in range(100):
            start = time.perf_counter()
            cache.get(request)
            hit_latencies.append((time.perf_counter() - start) * 1_000_000)

        # Measure miss latency
        miss_request = AuthorizationRequest.create(
            agent_id="miss-agent", agent_name="miss",
            principal="user@corp.com", action="ec2:RunInstances",
            resource="*", environment=Environment.DEV,
            data_classification=DataClassification.PUBLIC,
        )
        miss_latencies = []
        for _ in range(100):
            start = time.perf_counter()
            cache.get(miss_request)
            miss_latencies.append((time.perf_counter() - start) * 1_000_000)

        hit_p50 = _percentile(hit_latencies, 50)
        miss_p50 = _percentile(miss_latencies, 50)

        print(f"\nCache Hit vs Miss:")
        print(f"  Hit p50: {hit_p50:.1f}µs")
        print(f"  Miss p50: {miss_p50:.1f}µs")

        # Both should be sub-millisecond
        assert hit_p50 < 1000.0
        assert miss_p50 < 1000.0

    def test_cache_put_get_latency(self) -> None:
        """Measure cache put/get operation latency."""
        cache = DecisionCache(max_size=10000, ttl_seconds=60.0)

        # Populate cache
        requests = []
        for i in range(1000):
            req = AuthorizationRequest.create(
                agent_id=f"cache-bench-{i}", agent_name=f"bench-{i}",
                principal="user@corp.com", action=f"s3:Action{i}",
                resource=f"resource-{i}",
                environment=Environment.DEV,
                data_classification=DataClassification.PUBLIC,
            )
            requests.append(req)
            from aws_agent_identity_guard.authorization import AuthorizationDecision as AD
            decision = AD.allow(
                reasons=["ok"], policy="", risk_score=0, correlation_id=f"c-{i}"
            )
            cache.put(req, decision)

        # Measure get latency
        latencies = []
        for req in requests[:100]:
            start = time.perf_counter()
            cache.get(req)
            elapsed_us = (time.perf_counter() - start) * 1_000_000  # microseconds
            latencies.append(elapsed_us)

        p50 = _percentile(latencies, 50)
        p95 = _percentile(latencies, 95)

        print(f"\nCache Get Latency:")
        print(f"  p50: {p50:.1f}µs")
        print(f"  p95: {p95:.1f}µs")
        print(f"  Cache size: {cache.size}")

        # Cache gets should be sub-millisecond
        assert p50 < 1000.0, f"Cache get p50 {p50:.1f}µs exceeds 1ms"
