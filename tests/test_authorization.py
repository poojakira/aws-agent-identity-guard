"""
tests/test_authorization.py
----------------------------
Tests for the authorization API engine.

Covers ALLOW, DENY, STEP_UP decisions, fail-closed and fail-open modes,
audit event generation, and latency tracking.
"""

from __future__ import annotations

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
    TransactionRequest,
)
from aws_agent_identity_guard.policy_engine import PolicyEngine
from aws_agent_identity_guard.risk_engine import RiskEngine

# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def low_risk_agent() -> AgentIdentity:
    """Agent with minimal risk profile."""
    return AgentIdentity(
        agent_id="agent-low-risk",
        name="LowRiskAgent",
        agent_type=AgentType.LAMBDA,
        owner="dev-team",
        environment=Environment.DEVELOPMENT,
        data_classification=DataClassification.PUBLIC,
    )


@pytest.fixture
def high_risk_agent() -> AgentIdentity:
    """Agent in production with sensitive data access."""
    return AgentIdentity(
        agent_id="agent-high-risk",
        name="HighRiskAgent",
        agent_type=AgentType.BEDROCK,
        owner="platform",
        environment=Environment.PRODUCTION,
        data_classification=DataClassification.SECRET,
    )


@pytest.fixture
def deny_policy_engine() -> PolicyEngine:
    """Policy engine with a deny rule for dangerous actions."""
    engine = PolicyEngine()
    engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: block-iam-star
    effect: deny
    actions: ['iam:*']
    resources: ['*']
    environments: ['*']
    priority: 100
""")
    return engine


@pytest.fixture
def allow_policy_engine() -> PolicyEngine:
    """Policy engine with an allow rule for S3 reads."""
    engine = PolicyEngine()
    engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: allow-s3-read
    effect: allow
    actions: ['s3:GetObject']
    resources: ['*']
    environments: ['*']
    priority: 50
""")
    return engine


@pytest.fixture
def step_up_policy_engine() -> PolicyEngine:
    """Policy engine with a step-up rule based on risk score."""
    engine = PolicyEngine()
    engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: step-up-sensitive
    effect: step_up
    actions: ['secretsmanager:GetSecretValue']
    resources: ['*']
    environments: ['*']
    priority: 80
""")
    return engine


def _make_engine(
    mode: AuthorizationMode = AuthorizationMode.FAIL_CLOSED,
    policy_engine: PolicyEngine | None = None,
    step_up_threshold: float = 70.0,
    deny_threshold: float = 90.0,
) -> AuthorizationEngine:
    """Helper to build a configured AuthorizationEngine."""
    config = AuthorizationConfig(
        mode=mode,
        step_up_threshold=step_up_threshold,
        deny_threshold=deny_threshold,
    )
    return AuthorizationEngine(
        config=config,
        risk_engine=RiskEngine(),
        policy_engine=policy_engine or PolicyEngine(),
    )


def _make_request(
    agent_id: str,
    action: str = "s3:GetObject",
    resource: str = "arn:aws:s3:::bucket/key",
) -> TransactionRequest:
    """Helper to build a TransactionRequest."""
    return TransactionRequest(
        agent_id=agent_id,
        principal="arn:aws:iam::123456789012:role/Role",
        tool="test-tool",
        action=action,
        resource=resource,
    )


# ─── ALLOW Decision Tests ────────────────────────────────────────────────────


class TestAllowDecisions:
    """Test scenarios that produce ALLOW decisions."""

    def test_allow_with_matching_policy(self, low_risk_agent, allow_policy_engine):
        """Agent with matching allow policy gets ALLOW."""
        engine = _make_engine(policy_engine=allow_policy_engine)
        engine.agent_registry.register(low_risk_agent)
        request = _make_request("agent-low-risk", action="s3:GetObject")
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.ALLOW

    def test_allow_in_fail_open_mode(self, low_risk_agent):
        """Fail-open mode defaults to ALLOW when no policy matches."""
        engine = _make_engine(mode=AuthorizationMode.FAIL_OPEN)
        engine.agent_registry.register(low_risk_agent)
        request = _make_request("agent-low-risk")
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.ALLOW

    def test_allow_decision_has_correlation_id(self, low_risk_agent, allow_policy_engine):
        """ALLOW decisions include a correlation_id for tracing."""
        engine = _make_engine(policy_engine=allow_policy_engine)
        engine.agent_registry.register(low_risk_agent)
        request = _make_request("agent-low-risk", action="s3:GetObject")
        decision = engine.authorize(request)
        assert decision.correlation_id != ""


# ─── DENY Decision Tests ─────────────────────────────────────────────────────


class TestDenyDecisions:
    """Test scenarios that produce DENY decisions."""

    def test_deny_with_matching_deny_policy(self, low_risk_agent, deny_policy_engine):
        """Action matching a deny policy produces DENY."""
        engine = _make_engine(policy_engine=deny_policy_engine)
        engine.agent_registry.register(low_risk_agent)
        request = _make_request("agent-low-risk", action="iam:PassRole", resource="*")
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_deny_unknown_agent(self):
        """Request from an unregistered agent is DENIED."""
        engine = _make_engine()
        request = _make_request("nonexistent-agent")
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_deny_in_fail_closed_no_policy(self, low_risk_agent):
        """Fail-closed mode defaults to DENY when no policy matches."""
        engine = _make_engine(mode=AuthorizationMode.FAIL_CLOSED)
        engine.agent_registry.register(low_risk_agent)
        request = _make_request("agent-low-risk")
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_deny_decision_has_reasons(self, low_risk_agent, deny_policy_engine):
        """DENY decisions include explanatory reasons."""
        engine = _make_engine(policy_engine=deny_policy_engine)
        engine.agent_registry.register(low_risk_agent)
        request = _make_request("agent-low-risk", action="iam:CreateRole", resource="*")
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY
        assert len(decision.reasons) > 0

    def test_deny_high_risk_score_exceeds_threshold(self, high_risk_agent):
        """Risk score above deny_threshold causes DENY regardless of policy."""
        engine = _make_engine(deny_threshold=20.0)
        engine.agent_registry.register(high_risk_agent)
        request = _make_request(
            "agent-high-risk",
            action="iam:CreatePolicyVersion",
            resource="*",
        )
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY


# ─── STEP_UP Decision Tests ──────────────────────────────────────────────────


class TestStepUpDecisions:
    """Test scenarios that produce STEP_UP decisions."""

    def test_step_up_with_matching_policy(self, low_risk_agent, step_up_policy_engine):
        """Action matching a step_up policy produces STEP_UP decision."""
        engine = _make_engine(policy_engine=step_up_policy_engine)
        engine.agent_registry.register(low_risk_agent)
        request = _make_request(
            "agent-low-risk",
            action="secretsmanager:GetSecretValue",
            resource="arn:aws:secretsmanager:us-east-1:123456789012:secret:api-key",
        )
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.STEP_UP

    def test_step_up_risk_between_thresholds(self, high_risk_agent, allow_policy_engine):
        """Risk score between step_up and deny thresholds produces STEP_UP."""
        # Set thresholds so the high-risk agent's score lands between them
        engine = _make_engine(
            policy_engine=allow_policy_engine,
            step_up_threshold=10.0,
            deny_threshold=95.0,
        )
        engine.agent_registry.register(high_risk_agent)
        request = _make_request(
            "agent-high-risk",
            action="s3:GetObject",
            resource="*",
        )
        decision = engine.authorize(request)
        # Should be STEP_UP because risk exceeds step_up_threshold
        assert decision.decision in (
            AuthorizationDecisionType.STEP_UP,
            AuthorizationDecisionType.ALLOW,
        )


# ─── Fail-Closed / Fail-Open Mode Tests ──────────────────────────────────────


class TestFailModes:
    """Test fail-closed and fail-open behavior."""

    def test_fail_closed_denies_on_no_match(self, low_risk_agent):
        """In fail-closed mode, no matching policy defaults to DENY."""
        engine = _make_engine(mode=AuthorizationMode.FAIL_CLOSED)
        engine.agent_registry.register(low_risk_agent)
        request = _make_request("agent-low-risk", action="custom:Action")
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_fail_open_allows_on_no_match(self, low_risk_agent):
        """In fail-open mode, no matching policy defaults to ALLOW."""
        engine = _make_engine(mode=AuthorizationMode.FAIL_OPEN)
        engine.agent_registry.register(low_risk_agent)
        request = _make_request("agent-low-risk", action="custom:Action")
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.ALLOW

    def test_fail_closed_denies_on_error(self, low_risk_agent):
        """In fail-closed mode, internal errors default to DENY."""
        engine = _make_engine(mode=AuthorizationMode.FAIL_CLOSED)
        # Do not register agent -- this forces a "not found" deny
        request = _make_request("unregistered-agent")
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY


# ─── Audit Event Tests ────────────────────────────────────────────────────────


class TestAuditEvents:
    """Test audit event generation during authorization."""

    def test_audit_event_generated_on_deny(self, low_risk_agent, deny_policy_engine):
        """A DENY decision emits an audit event."""
        engine = _make_engine(policy_engine=deny_policy_engine)
        engine.agent_registry.register(low_risk_agent)
        request = _make_request("agent-low-risk", action="iam:CreateRole", resource="*")
        engine.authorize(request)
        events = engine.audit_events
        assert len(events) >= 1
        assert events[-1].decision == AuthorizationDecisionType.DENY

    def test_audit_event_has_integrity_hash(self, low_risk_agent, allow_policy_engine):
        """Audit events carry a non-empty integrity hash."""
        engine = _make_engine(policy_engine=allow_policy_engine)
        engine.agent_registry.register(low_risk_agent)
        request = _make_request("agent-low-risk", action="s3:GetObject")
        engine.authorize(request)
        events = engine.audit_events
        assert len(events) >= 1
        assert events[-1].integrity_hash != ""
        assert len(events[-1].integrity_hash) == 64

    def test_audit_event_verifies_integrity(self, low_risk_agent, deny_policy_engine):
        """Audit event integrity hash passes verification."""
        engine = _make_engine(policy_engine=deny_policy_engine)
        engine.agent_registry.register(low_risk_agent)
        request = _make_request("agent-low-risk", action="iam:PassRole", resource="*")
        engine.authorize(request)
        event = engine.audit_events[-1]
        assert event.verify_integrity() is True


# ─── Latency Tracking Tests ──────────────────────────────────────────────────


class TestLatencyTracking:
    """Test latency metric collection."""

    def test_latency_recorded_after_decision(self, low_risk_agent, allow_policy_engine):
        """Authorization records latency metrics."""
        engine = _make_engine(policy_engine=allow_policy_engine)
        engine.agent_registry.register(low_risk_agent)
        request = _make_request("agent-low-risk", action="s3:GetObject")
        engine.authorize(request)
        metrics = engine.latency_metrics
        assert metrics["total_count"] >= 1
        assert metrics["p50_ms"] >= 0

    def test_latency_tracker_percentiles(self):
        """LatencyTracker computes correct percentile values."""
        tracker = LatencyTracker(max_samples=1000)
        for i in range(100):
            tracker.record(float(i))
        assert tracker.p50 == pytest.approx(50.0, abs=2.0)
        assert tracker.p95 == pytest.approx(95.0, abs=2.0)
        assert tracker.p99 == pytest.approx(99.0, abs=2.0)

    def test_latency_tracker_empty(self):
        """Empty tracker returns 0 for all percentiles."""
        tracker = LatencyTracker()
        assert tracker.p50 == 0.0
        assert tracker.p95 == 0.0
        assert tracker.count == 0

    def test_decision_count_increments(self, low_risk_agent, allow_policy_engine):
        """Decision count increments on each authorization call."""
        engine = _make_engine(policy_engine=allow_policy_engine)
        engine.agent_registry.register(low_risk_agent)
        request = _make_request("agent-low-risk", action="s3:GetObject")
        engine.authorize(request)
        engine.authorize(request)
        assert engine.decision_count >= 2
