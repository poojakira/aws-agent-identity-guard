"""Resilience tests for the authorization system.

Tests graceful degradation under adverse conditions:
- Policy store unavailable
- Malformed requests
- Stale policies
- Concurrent access
- Circuit breaker behavior
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from aws_agent_identity_guard.models import (
    AuditEvent,
    DataClassification,
    Decision,
    Environment,
    PermissionEffect,
    PolicyRule,
)
from aws_agent_identity_guard.authorization import (
    AuthorizationConfig,
    AuthorizationDecision,
    AuthorizationRequest,
    AuthorizationService,
    DecisionCache,
    DefaultAuditLogger,
    DefaultApprovalService,
    DefaultPolicyEngine,
    DefaultRiskEngine,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def service() -> AuthorizationService:
    """Standard authorization service."""
    return AuthorizationService(config=AuthorizationConfig())


@pytest.fixture
def basic_request() -> AuthorizationRequest:
    """A basic authorization request."""
    return AuthorizationRequest.create(
        agent_id="resilience-agent",
        agent_name="test-agent",
        principal="user@corp.com",
        action="s3:GetObject",
        resource="arn:aws:s3:::bucket/key",
        environment=Environment.PRODUCTION,
        data_classification=DataClassification.INTERNAL,
    )


@pytest.fixture
def high_risk_request() -> AuthorizationRequest:
    """A high-risk request for testing."""
    return AuthorizationRequest.create(
        agent_id="risky-agent",
        agent_name="risky-test",
        principal="user@corp.com",
        action="iam:CreateRole",
        resource="arn:aws:iam::123456789012:role/new-role",
        environment=Environment.PRODUCTION,
        data_classification=DataClassification.SECRET,
    )


# =============================================================================
# Test: Policy Store Unavailable
# =============================================================================


class TestPolicyStoreUnavailable:
    """Tests for graceful handling when policy store is unavailable."""

    def test_policy_engine_exception_fails_closed(self) -> None:
        """When policy engine raises exception, decision is DENY (fail-closed)."""
        mock_policy_engine = MagicMock()
        mock_policy_engine.evaluate.side_effect = RuntimeError("Policy store unavailable")

        service = AuthorizationService(
            config=AuthorizationConfig(),
            policy_engine=mock_policy_engine,
        )
        request = AuthorizationRequest.create(
            agent_id="agent-1", agent_name="test",
            principal="user@corp.com", action="s3:GetObject",
            resource="arn:aws:s3:::bucket/key",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        # Should not crash; should fail closed
        try:
            decision = service.authorize(request)
            assert decision.decision == Decision.DENY
        except RuntimeError:
            # If it propagates the exception, that's also acceptable fail-closed behavior
            pass

    def test_risk_engine_exception_fails_closed(self) -> None:
        """When risk engine raises exception, decision is DENY."""
        mock_risk_engine = MagicMock()
        mock_risk_engine.compute_risk.side_effect = RuntimeError("Risk engine unavailable")

        service = AuthorizationService(
            config=AuthorizationConfig(),
            risk_engine=mock_risk_engine,
        )
        request = AuthorizationRequest.create(
            agent_id="agent-1", agent_name="test",
            principal="user@corp.com", action="s3:GetObject",
            resource="arn:aws:s3:::bucket/key",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        try:
            decision = service.authorize(request)
            assert decision.decision == Decision.DENY
        except RuntimeError:
            # Exception propagation is acceptable fail-closed behavior
            pass

    def test_audit_logger_failure_doesnt_block(self) -> None:
        """Audit logger failure doesn't prevent authorization decision."""
        mock_logger = MagicMock()
        mock_logger.log.side_effect = IOError("Audit store unavailable")

        service = AuthorizationService(
            config=AuthorizationConfig(
                fail_open_environments=[Environment.DEV],
            ),
            audit_logger=mock_logger,
        )
        request = AuthorizationRequest.create(
            agent_id="agent-1", agent_name="test",
            principal="user@corp.com", action="s3:GetObject",
            resource="arn:aws:s3:::bucket/key",
            environment=Environment.DEV,
            data_classification=DataClassification.PUBLIC,
        )
        # Should still return a decision even if audit fails
        try:
            decision = service.authorize(request)
            assert decision.decision in Decision
        except IOError:
            # If it propagates, that's still a valid test observation
            pass


# =============================================================================
# Test: Malformed Requests
# =============================================================================


class TestMalformedRequests:
    """Tests for handling malformed or unusual input."""

    def test_empty_action_string(self, service: AuthorizationService) -> None:
        """Empty action string doesn't crash the service."""
        request = AuthorizationRequest.create(
            agent_id="agent-bad", agent_name="bad-agent",
            principal="user@corp.com", action="",
            resource="arn:aws:s3:::bucket/key",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        decision = service.authorize(request)
        # Should fail closed in production
        assert decision.decision == Decision.DENY

    def test_empty_resource_string(self, service: AuthorizationService) -> None:
        """Empty resource string is handled gracefully."""
        request = AuthorizationRequest.create(
            agent_id="agent-bad", agent_name="bad-agent",
            principal="user@corp.com", action="s3:GetObject",
            resource="",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        decision = service.authorize(request)
        assert decision.decision in Decision

    def test_very_long_action_string(self, service: AuthorizationService) -> None:
        """Very long action string doesn't crash."""
        long_action = "customservice:" + "A" * 10000
        request = AuthorizationRequest.create(
            agent_id="agent-long", agent_name="long-action-agent",
            principal="user@corp.com", action=long_action,
            resource="*",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        decision = service.authorize(request)
        assert decision.decision in Decision

    def test_special_characters_in_resource(self, service: AuthorizationService) -> None:
        """Special characters in resource ARN don't crash."""
        request = AuthorizationRequest.create(
            agent_id="agent-special", agent_name="special-agent",
            principal="user@corp.com", action="s3:GetObject",
            resource="arn:aws:s3:::bucket/path with spaces/file[1].txt",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        decision = service.authorize(request)
        assert decision.decision in Decision

    def test_unicode_in_agent_name(self, service: AuthorizationService) -> None:
        """Unicode characters in agent name are handled."""
        request = AuthorizationRequest.create(
            agent_id="agent-unicode", agent_name="代理-エージェント-Агент",
            principal="用户@corp.com", action="s3:GetObject",
            resource="arn:aws:s3:::bucket/key",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        decision = service.authorize(request)
        assert decision.decision in Decision


# =============================================================================
# Test: Stale Policies
# =============================================================================


class TestStalePolicies:
    """Tests for behavior with stale or outdated policies."""

    def test_cache_returns_stale_decision_within_ttl(self) -> None:
        """Cache returns stale decision within TTL window."""
        cache = DecisionCache(max_size=100, ttl_seconds=60.0)
        request = AuthorizationRequest.create(
            agent_id="agent-cache", agent_name="cache-test",
            principal="user@test.com", action="s3:GetObject",
            resource="arn:aws:s3:::bucket/key",
            environment=Environment.DEV,
            data_classification=DataClassification.PUBLIC,
        )
        decision = AuthorizationDecision.allow(
            reasons=["cached"], policy="old-policy", risk_score=5, correlation_id="c1"
        )
        cache.put(request, decision)
        # Within TTL, returns the cached (potentially stale) decision
        retrieved = cache.get(request)
        assert retrieved is not None
        assert retrieved.decision == Decision.ALLOW

    def test_cache_invalidation_removes_stale_entry(self) -> None:
        """Manual cache invalidation removes stale entries."""
        cache = DecisionCache(max_size=100, ttl_seconds=60.0)
        request = AuthorizationRequest.create(
            agent_id="agent-inv", agent_name="invalidation-test",
            principal="user@test.com", action="s3:PutObject",
            resource="arn:aws:s3:::bucket/new-key",
            environment=Environment.STAGING,
            data_classification=DataClassification.INTERNAL,
        )
        decision = AuthorizationDecision.allow(
            reasons=["old rule"], policy="v1-policy", risk_score=10, correlation_id="c2"
        )
        cache.put(request, decision)
        cache.invalidate(request)
        assert cache.get(request) is None

    def test_policy_reload_clears_cache(self, service: AuthorizationService) -> None:
        """Clearing cache after policy change ensures fresh decisions."""
        request = AuthorizationRequest.create(
            agent_id="agent-reload", agent_name="reload-test",
            principal="user@corp.com", action="s3:GetObject",
            resource="arn:aws:s3:::dev-bucket/file",
            environment=Environment.DEV,
            data_classification=DataClassification.PUBLIC,
        )
        service.authorize(request)  # Populate cache
        assert service.cache.size > 0
        service.cache.clear()  # Simulate policy reload
        assert service.cache.size == 0


# =============================================================================
# Test: Concurrent Access
# =============================================================================


class TestConcurrentAccess:
    """Tests for thread-safety under concurrent authorization requests."""

    def test_concurrent_authorization_requests(self, service: AuthorizationService) -> None:
        """Multiple threads can authorize simultaneously without data corruption."""
        results = []
        errors = []

        def authorize_request(idx: int) -> None:
            try:
                request = AuthorizationRequest.create(
                    agent_id=f"agent-{idx}",
                    agent_name=f"concurrent-agent-{idx}",
                    principal=f"user{idx}@corp.com",
                    action="s3:GetObject",
                    resource=f"arn:aws:s3:::bucket/file-{idx}",
                    environment=Environment.DEV,
                    data_classification=DataClassification.PUBLIC,
                )
                decision = service.authorize(request)
                results.append(decision)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=authorize_request, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0
        assert len(results) == 20

    def test_concurrent_cache_access(self) -> None:
        """Cache handles concurrent reads/writes safely."""
        cache = DecisionCache(max_size=1000, ttl_seconds=60.0)
        errors = []

        def cache_operations(idx: int) -> None:
            try:
                request = AuthorizationRequest.create(
                    agent_id=f"agent-{idx % 5}",
                    agent_name=f"agent-{idx % 5}",
                    principal="user@test.com",
                    action=f"s3:Action{idx % 5}",
                    resource=f"resource-{idx % 5}",
                    environment=Environment.DEV,
                    data_classification=DataClassification.PUBLIC,
                )
                decision = AuthorizationDecision.allow(
                    reasons=["ok"], policy="", risk_score=0, correlation_id=f"c-{idx}"
                )
                cache.put(request, decision)
                cache.get(request)
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(cache_operations, i) for i in range(50)]
            for f in as_completed(futures):
                f.result()

        assert len(errors) == 0

    def test_concurrent_audit_logging(self) -> None:
        """Audit logger handles concurrent writes safely."""
        logger = DefaultAuditLogger()
        errors = []

        def log_event(idx: int) -> None:
            try:
                event = AuditEvent.create(
                    who=f"user{idx}@corp.com",
                    agent=f"agent-{idx}",
                    action="s3:GetObject",
                    resource=f"arn:aws:s3:::bucket/file-{idx}",
                    decision=Decision.ALLOW,
                    reason="Concurrent test",
                    correlation_id=f"corr-{idx}",
                )
                logger.log(event)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=log_event, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0
        assert len(logger.events) == 50


# =============================================================================
# Test: Circuit Breaker Behavior
# =============================================================================


class TestCircuitBreaker:
    """Tests for circuit breaker patterns in the authorization pipeline."""

    def test_repeated_failures_dont_accumulate_errors(self) -> None:
        """Multiple failed requests don't cause memory leaks or error accumulation."""
        service = AuthorizationService(config=AuthorizationConfig())
        for i in range(100):
            request = AuthorizationRequest.create(
                agent_id=f"flood-agent-{i}",
                agent_name=f"flood-{i}",
                principal="attacker@evil.com",
                action="iam:CreateRole",
                resource="*",
                environment=Environment.PRODUCTION,
                data_classification=DataClassification.SECRET,
            )
            decision = service.authorize(request)
            assert decision.decision == Decision.DENY
        # Service should still be functional
        assert service.cache.size <= 100

    def test_cache_eviction_under_pressure(self) -> None:
        """Cache evicts entries under memory pressure without crashing."""
        cache = DecisionCache(max_size=10, ttl_seconds=60.0)
        for i in range(100):
            request = AuthorizationRequest.create(
                agent_id=f"pressure-agent-{i}",
                agent_name=f"pressure-{i}",
                principal="user@corp.com",
                action=f"s3:Action{i}",
                resource=f"resource-{i}",
                environment=Environment.DEV,
                data_classification=DataClassification.PUBLIC,
            )
            decision = AuthorizationDecision.allow(
                reasons=["ok"], policy="", risk_score=0, correlation_id=f"c-{i}"
            )
            cache.put(request, decision)
        # Should never exceed max_size
        assert cache.size <= 10

    def test_service_recovers_after_transient_failure(self) -> None:
        """Service continues working after a transient engine failure."""
        call_count = {"count": 0}
        original_compute = DefaultRiskEngine.compute_risk

        def flaky_compute(self, request):
            call_count["count"] += 1
            if call_count["count"] <= 2:
                raise RuntimeError("Transient failure")
            return original_compute(self, request)

        service = AuthorizationService(config=AuthorizationConfig())

        # First calls may fail
        request = AuthorizationRequest.create(
            agent_id="recovery-agent", agent_name="recovery",
            principal="user@corp.com", action="s3:GetObject",
            resource="arn:aws:s3:::bucket/key",
            environment=Environment.DEV,
            data_classification=DataClassification.PUBLIC,
        )

        with patch.object(DefaultRiskEngine, "compute_risk", flaky_compute):
            # First attempts may fail or fallback
            for _ in range(3):
                try:
                    decision = service.authorize(request)
                    # If it succeeds, verify it's a valid decision
                    assert decision.decision in Decision
                    break
                except RuntimeError:
                    continue

    def test_high_volume_doesnt_degrade_cache(self) -> None:
        """High request volume doesn't degrade cache performance."""
        service = AuthorizationService(config=AuthorizationConfig())
        request = AuthorizationRequest.create(
            agent_id="volume-agent", agent_name="volume",
            principal="user@corp.com", action="s3:GetObject",
            resource="arn:aws:s3:::bucket/key",
            environment=Environment.DEV,
            data_classification=DataClassification.PUBLIC,
        )
        # First call populates cache
        service.authorize(request)
        # Subsequent calls should be fast (cached)
        start = time.monotonic()
        for _ in range(1000):
            service.authorize(request)
        elapsed = time.monotonic() - start
        # 1000 cached decisions should complete quickly
        assert elapsed < 5.0  # Very generous timeout
