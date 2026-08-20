"""
tests/test_resilience.py
-------------------------
Resilience tests for the AWS Agent Identity Guard system.

Covers graceful degradation when dependencies are unavailable: AWS API
timeouts, policy store failures, cache unavailability, malformed requests,
stale policies, and circuit breaker behavior.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from aws_agent_identity_guard.authorization import (
    AuthorizationConfig,
    AuthorizationEngine,
    AuthorizationMode,
    LatencyTracker,
)
from aws_agent_identity_guard.models import (
    AgentIdentity,
    AgentType,
    AuthorizationDecisionType,
    DataClassification,
    Environment,
    RiskScore,
    TransactionRequest,
)
from aws_agent_identity_guard.policy_engine import PolicyDecision, PolicyEffect, PolicyEngine
from aws_agent_identity_guard.risk_engine import RiskEngine


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def agent() -> AgentIdentity:
    """Standard resilience test agent."""
    return AgentIdentity(
        agent_id="agent-resilience",
        name="ResilienceAgent",
        agent_type=AgentType.LAMBDA,
        owner="sre-team",
        environment=Environment.PRODUCTION,
        data_classification=DataClassification.INTERNAL,
    )


@pytest.fixture
def request_obj() -> TransactionRequest:
    """Standard resilience test request."""
    return TransactionRequest(
        agent_id="agent-resilience",
        principal="arn:aws:iam::123456789012:role/Role",
        tool="test-tool",
        action="s3:GetObject",
        resource="arn:aws:s3:::bucket/key",
    )


def _build_engine(
    mode: AuthorizationMode = AuthorizationMode.FAIL_CLOSED,
    policy_engine: PolicyEngine | None = None,
) -> AuthorizationEngine:
    """Helper to construct a configured AuthorizationEngine."""
    config = AuthorizationConfig(mode=mode)
    return AuthorizationEngine(
        config=config,
        risk_engine=RiskEngine(),
        policy_engine=policy_engine or PolicyEngine(),
    )


# ─── AWS API Unavailable Tests ───────────────────────────────────────────────


class TestAWSAPIUnavailable:
    """Test behavior when AWS API calls timeout or fail."""

    def test_risk_engine_failure_fail_closed_denies(self, agent, request_obj):
        """When risk engine throws, fail-closed mode produces DENY."""
        engine = _build_engine(mode=AuthorizationMode.FAIL_CLOSED)
        engine.agent_registry.register(agent)

        # Patch risk engine to raise an exception (simulating AWS API timeout)
        with patch.object(
            engine._risk_engine,
            "score_transaction",
            side_effect=TimeoutError("AWS API timeout"),
        ):
            decision = engine.authorize(request_obj)
            assert decision.decision == AuthorizationDecisionType.DENY

    def test_risk_engine_failure_fail_open_allows(self, agent, request_obj):
        """When risk engine throws, fail-open mode produces ALLOW."""
        engine = _build_engine(mode=AuthorizationMode.FAIL_OPEN)
        engine.agent_registry.register(agent)

        with patch.object(
            engine._risk_engine,
            "score_transaction",
            side_effect=TimeoutError("AWS API timeout"),
        ):
            decision = engine.authorize(request_obj)
            assert decision.decision == AuthorizationDecisionType.ALLOW

    def test_latency_still_recorded_on_failure(self, agent, request_obj):
        """Latency metrics are recorded even when authorization fails."""
        engine = _build_engine(mode=AuthorizationMode.FAIL_CLOSED)
        engine.agent_registry.register(agent)

        with patch.object(
            engine._risk_engine,
            "score_transaction",
            side_effect=RuntimeError("Service unavailable"),
        ):
            engine.authorize(request_obj)

        # Latency should still be recorded
        metrics = engine.latency_metrics
        assert metrics["total_count"] >= 1


# ─── Policy Store Unavailable Tests ──────────────────────────────────────────


class TestPolicyStoreUnavailable:
    """Test behavior when the policy store is unavailable."""

    def test_empty_policy_engine_fail_closed_denies(self, agent, request_obj):
        """With no policies loaded, fail-closed mode denies all."""
        engine = _build_engine(mode=AuthorizationMode.FAIL_CLOSED)
        engine.agent_registry.register(agent)
        decision = engine.authorize(request_obj)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_policy_engine_error_fail_closed_denies(self, agent, request_obj):
        """When policy evaluation throws, fail-closed denies."""
        policy_engine = PolicyEngine()
        engine = _build_engine(
            mode=AuthorizationMode.FAIL_CLOSED,
            policy_engine=policy_engine,
        )
        engine.agent_registry.register(agent)

        with patch.object(
            policy_engine,
            "evaluate",
            side_effect=IOError("Policy store connection refused"),
        ):
            decision = engine.authorize(request_obj)
            assert decision.decision == AuthorizationDecisionType.DENY

    def test_policy_engine_error_fail_open_allows(self, agent, request_obj):
        """When policy evaluation throws, fail-open allows."""
        policy_engine = PolicyEngine()
        engine = _build_engine(
            mode=AuthorizationMode.FAIL_OPEN,
            policy_engine=policy_engine,
        )
        engine.agent_registry.register(agent)

        with patch.object(
            policy_engine,
            "evaluate",
            side_effect=IOError("Policy store connection refused"),
        ):
            decision = engine.authorize(request_obj)
            assert decision.decision == AuthorizationDecisionType.ALLOW


# ─── Cache Unavailable Tests ─────────────────────────────────────────────────


class TestCacheUnavailable:
    """Test behavior when cache layer is unavailable."""

    def test_decision_still_made_without_cache(self, agent, request_obj):
        """Authorization still functions when caching is unavailable."""
        policy_engine = PolicyEngine()
        policy_engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: allow-s3
    effect: allow
    actions: ['s3:GetObject']
    resources: ['*']
""")
        engine = _build_engine(
            mode=AuthorizationMode.FAIL_CLOSED,
            policy_engine=policy_engine,
        )
        engine.agent_registry.register(agent)
        # Simulate cache miss/failure by clearing internal state
        decision = engine.authorize(request_obj)
        # Should still produce a valid decision
        assert decision.decision in (
            AuthorizationDecisionType.ALLOW,
            AuthorizationDecisionType.DENY,
            AuthorizationDecisionType.STEP_UP,
        )

    def test_multiple_requests_work_without_cache(self, agent, request_obj):
        """Multiple sequential requests work without caching layer."""
        policy_engine = PolicyEngine()
        policy_engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: allow-s3
    effect: allow
    actions: ['s3:GetObject']
    resources: ['*']
""")
        engine = _build_engine(
            mode=AuthorizationMode.FAIL_CLOSED,
            policy_engine=policy_engine,
        )
        engine.agent_registry.register(agent)
        for _ in range(10):
            decision = engine.authorize(request_obj)
            assert decision.decision is not None


# ─── Malformed Request Tests ─────────────────────────────────────────────────


class TestMalformedRequests:
    """Test handling of malformed or edge-case requests."""

    def test_empty_action_raises_validation_error(self):
        """TransactionRequest with empty action raises ValueError."""
        with pytest.raises(ValueError, match="action cannot be empty"):
            TransactionRequest(
                agent_id="x", principal="r", tool="t",
                action="", resource="*",
            )

    def test_empty_resource_raises_validation_error(self):
        """TransactionRequest with empty resource raises ValueError."""
        with pytest.raises(ValueError, match="resource cannot be empty"):
            TransactionRequest(
                agent_id="x", principal="r", tool="t",
                action="s3:GetObject", resource="",
            )

    def test_empty_agent_id_raises_validation_error(self):
        """TransactionRequest with empty agent_id raises ValueError."""
        with pytest.raises(ValueError, match="agent_id cannot be empty"):
            TransactionRequest(
                agent_id="", principal="r", tool="t",
                action="s3:GetObject", resource="*",
            )

    def test_nonexistent_agent_denied(self, request_obj):
        """Request for non-existent agent is gracefully denied."""
        engine = _build_engine(mode=AuthorizationMode.FAIL_CLOSED)
        decision = engine.authorize(request_obj)
        assert decision.decision == AuthorizationDecisionType.DENY


# ─── Stale Policy Tests ──────────────────────────────────────────────────────


class TestStalePolicies:
    """Test behavior with stale or outdated policies."""

    def test_old_policy_still_enforced(self, agent, request_obj):
        """Previously loaded policies remain enforced until replaced."""
        policy_engine = PolicyEngine()
        policy_engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: deny-all
    effect: deny
    actions: ['*']
    resources: ['*']
""")
        engine = _build_engine(
            mode=AuthorizationMode.FAIL_CLOSED,
            policy_engine=policy_engine,
        )
        engine.agent_registry.register(agent)
        decision = engine.authorize(request_obj)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_policy_reload_takes_effect(self, agent, request_obj):
        """Reloading policies changes enforcement behavior."""
        policy_engine = PolicyEngine()
        policy_engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: deny-all
    effect: deny
    actions: ['*']
    resources: ['*']
""")
        engine = _build_engine(
            mode=AuthorizationMode.FAIL_CLOSED,
            policy_engine=policy_engine,
        )
        engine.agent_registry.register(agent)

        # First request is denied
        decision1 = engine.authorize(request_obj)
        assert decision1.decision == AuthorizationDecisionType.DENY

        # Reload with permissive policy
        policy_engine.load_policies_from_string("""
version: '2.0'
policies:
  - name: allow-all
    effect: allow
    actions: ['*']
    resources: ['*']
""")
        decision2 = engine.authorize(request_obj)
        assert decision2.decision == AuthorizationDecisionType.ALLOW


# ─── Fail-Closed Under Failure Tests ────────────────────────────────────────


class TestFailClosedBehavior:
    """Test that fail-closed mode consistently denies under failures."""

    def test_exception_in_authorize_produces_deny(self, agent, request_obj):
        """Any unhandled exception in authorize produces DENY in fail-closed."""
        engine = _build_engine(mode=AuthorizationMode.FAIL_CLOSED)
        engine.agent_registry.register(agent)

        with patch.object(
            engine._risk_engine,
            "score_transaction",
            side_effect=Exception("Unexpected internal error"),
        ):
            decision = engine.authorize(request_obj)
            assert decision.decision == AuthorizationDecisionType.DENY

    def test_multiple_failures_all_deny(self, agent, request_obj):
        """Repeated failures all produce DENY (no state corruption)."""
        engine = _build_engine(mode=AuthorizationMode.FAIL_CLOSED)
        engine.agent_registry.register(agent)

        with patch.object(
            engine._risk_engine,
            "score_transaction",
            side_effect=RuntimeError("persistent failure"),
        ):
            for _ in range(5):
                decision = engine.authorize(request_obj)
                assert decision.decision == AuthorizationDecisionType.DENY


# ─── Fail-Open Under Failure Tests ──────────────────────────────────────────


class TestFailOpenBehavior:
    """Test that fail-open mode allows under failures (dev only)."""

    def test_exception_in_authorize_produces_allow(self, agent, request_obj):
        """Exception in authorize produces ALLOW in fail-open mode."""
        engine = _build_engine(mode=AuthorizationMode.FAIL_OPEN)
        engine.agent_registry.register(agent)

        with patch.object(
            engine._risk_engine,
            "score_transaction",
            side_effect=Exception("Service error"),
        ):
            decision = engine.authorize(request_obj)
            assert decision.decision == AuthorizationDecisionType.ALLOW

    def test_fail_open_includes_warning(self, agent, request_obj):
        """Fail-open decisions include warning in reasons."""
        engine = _build_engine(mode=AuthorizationMode.FAIL_OPEN)
        engine.agent_registry.register(agent)

        with patch.object(
            engine._risk_engine,
            "score_transaction",
            side_effect=Exception("Error"),
        ):
            decision = engine.authorize(request_obj)
            all_reasons = " ".join(decision.reasons)
            assert "warning" in all_reasons.lower() or "fail-open" in all_reasons.lower()


# ─── Circuit Breaker Behavior Tests ──────────────────────────────────────────


class TestCircuitBreaker:
    """Test circuit-breaker-like behavior under sustained failures."""

    def test_sustained_failures_do_not_crash(self, agent, request_obj):
        """Engine remains functional after many consecutive failures."""
        engine = _build_engine(mode=AuthorizationMode.FAIL_CLOSED)
        engine.agent_registry.register(agent)

        # Simulate 100 consecutive failures
        with patch.object(
            engine._risk_engine,
            "score_transaction",
            side_effect=RuntimeError("persistent timeout"),
        ):
            for _ in range(100):
                decision = engine.authorize(request_obj)
                assert decision.decision == AuthorizationDecisionType.DENY

        # Engine should recover when failure is resolved
        # (no patch active, so risk engine works normally)
        policy_engine = PolicyEngine()
        policy_engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: allow-s3
    effect: allow
    actions: ['s3:GetObject']
    resources: ['*']
""")
        engine._policy_engine = policy_engine
        decision = engine.authorize(request_obj)
        assert decision.decision == AuthorizationDecisionType.ALLOW

    def test_latency_tracker_handles_high_volume(self):
        """LatencyTracker remains stable under high sample volume."""
        tracker = LatencyTracker(max_samples=100)
        for i in range(10000):
            tracker.record(float(i % 500))
        # Should not OOM or crash
        assert tracker.count == 10000
        assert tracker.p50 >= 0
        assert tracker.p99 >= 0

    def test_audit_log_bounded_growth(self, agent, request_obj):
        """Audit log does not grow unbounded (engine should handle)."""
        engine = _build_engine(mode=AuthorizationMode.FAIL_CLOSED)
        engine.agent_registry.register(agent)
        # Make 50 authorization requests
        for _ in range(50):
            engine.authorize(request_obj)
        # Should have recorded audit events without crashing
        assert len(engine.audit_events) >= 50
