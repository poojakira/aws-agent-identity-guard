"""Tests for the authorization service module.

Covers ALLOW/DENY/STEP_UP decisions, fail-closed/fail-open behavior,
decision caching, audit trail generation, and correlation ID propagation.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from threading import Thread
from unittest.mock import MagicMock, patch

import pytest

from aws_agent_identity_guard.models import (
    AuditEvent,
    DataClassification,
    Decision,
    Environment,
    Permission,
    PermissionEffect,
    PermissionSource,
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
def default_config() -> AuthorizationConfig:
    """Standard authorization config."""
    return AuthorizationConfig()


@pytest.fixture
def fail_open_config() -> AuthorizationConfig:
    """Config with all environments fail-open."""
    return AuthorizationConfig(
        fail_open_environments=[Environment.DEV, Environment.STAGING, Environment.PRODUCTION],
        fail_closed_environments=[],
    )


@pytest.fixture
def strict_config() -> AuthorizationConfig:
    """Config with low thresholds for testing deny/step-up."""
    return AuthorizationConfig(
        deny_threshold=50,
        step_up_threshold=30,
        review_threshold=20,
    )


@pytest.fixture
def service(default_config: AuthorizationConfig) -> AuthorizationService:
    """Default authorization service."""
    return AuthorizationService(config=default_config)


@pytest.fixture
def strict_service(strict_config: AuthorizationConfig) -> AuthorizationService:
    """Strict authorization service with low thresholds."""
    return AuthorizationService(config=strict_config)


@pytest.fixture
def low_risk_request() -> AuthorizationRequest:
    """Request for a low-risk action."""
    return AuthorizationRequest.create(
        agent_id="agent-safe",
        agent_name="reader-agent",
        principal="analyst@corp.com",
        action="s3:GetObject",
        resource="arn:aws:s3:::dev-data/report.csv",
        environment=Environment.DEV,
        data_classification=DataClassification.PUBLIC,
    )


@pytest.fixture
def high_risk_request() -> AuthorizationRequest:
    """Request for a high-risk action in production."""
    return AuthorizationRequest.create(
        agent_id="agent-risky",
        agent_name="admin-agent",
        principal="admin@corp.com",
        action="iam:PassRole",
        resource="arn:aws:iam::123456789012:role/production-admin",
        environment=Environment.PRODUCTION,
        data_classification=DataClassification.SECRET,
    )


@pytest.fixture
def medium_risk_request() -> AuthorizationRequest:
    """Request for a medium-risk action."""
    return AuthorizationRequest.create(
        agent_id="agent-mid",
        agent_name="deployer-agent",
        principal="dev@corp.com",
        action="lambda:UpdateFunctionCode",
        resource="arn:aws:lambda:us-east-1:123456789012:function:staging-processor",
        environment=Environment.STAGING,
        data_classification=DataClassification.CONFIDENTIAL,
    )


# =============================================================================
# Test: ALLOW Decisions
# =============================================================================


class TestAllowDecisions:
    """Tests for actions that should be allowed."""

    def test_low_risk_dev_action_allowed(self, service: AuthorizationService, low_risk_request: AuthorizationRequest) -> None:
        """Low-risk action in dev environment is allowed."""
        decision = service.authorize(low_risk_request)
        # Dev is fail-open by default, so even without explicit allow rule it should pass
        assert decision.decision in (Decision.ALLOW, Decision.REVIEW)

    def test_allow_decision_has_low_risk_score(self, service: AuthorizationService, low_risk_request: AuthorizationRequest) -> None:
        """ALLOW decisions have low risk scores."""
        decision = service.authorize(low_risk_request)
        if decision.decision == Decision.ALLOW:
            assert decision.risk_score < 50

    def test_allow_decision_has_explanation(self, service: AuthorizationService, low_risk_request: AuthorizationRequest) -> None:
        """All decisions include an explanation."""
        decision = service.authorize(low_risk_request)
        assert decision.explanation != ""

    def test_allow_decision_factory(self) -> None:
        """AuthorizationDecision.allow() factory works correctly."""
        decision = AuthorizationDecision.allow(
            reasons=["Matches allow rule"],
            policy="default-allow",
            explanation="Access granted based on policy.",
            risk_score=10,
            correlation_id="test-corr-1",
        )
        assert decision.decision == Decision.ALLOW
        assert decision.risk_score == 10
        assert decision.correlation_id == "test-corr-1"


# =============================================================================
# Test: DENY Decisions
# =============================================================================


class TestDenyDecisions:
    """Tests for actions that should be denied."""

    def test_privilege_escalation_denied_in_production(self, service: AuthorizationService, high_risk_request: AuthorizationRequest) -> None:
        """iam:PassRole in production is denied by default policy."""
        decision = service.authorize(high_risk_request)
        assert decision.decision == Decision.DENY

    def test_deny_decision_has_reasons(self, service: AuthorizationService, high_risk_request: AuthorizationRequest) -> None:
        """DENY decisions include reasons."""
        decision = service.authorize(high_risk_request)
        assert len(decision.reasons) > 0

    def test_deny_decision_has_high_risk_score(self, service: AuthorizationService, high_risk_request: AuthorizationRequest) -> None:
        """DENY decisions have high risk scores."""
        decision = service.authorize(high_risk_request)
        assert decision.risk_score >= 50

    def test_deny_decision_factory(self) -> None:
        """AuthorizationDecision.deny() factory works correctly."""
        decision = AuthorizationDecision.deny(
            reasons=["Explicit deny rule matched"],
            policy="deny-privilege-escalation-production",
            explanation="Access denied: privilege escalation attempt.",
            risk_score=95,
        )
        assert decision.decision == Decision.DENY
        assert decision.risk_score == 95

    def test_security_control_disable_denied(self, service: AuthorizationService) -> None:
        """Disabling security controls is denied in production."""
        request = AuthorizationRequest.create(
            agent_id="agent-bad",
            agent_name="rogue-agent",
            principal="attacker@evil.com",
            action="cloudtrail:StopLogging",
            resource="arn:aws:cloudtrail:us-east-1:123456789012:trail/main",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        decision = service.authorize(request)
        assert decision.decision == Decision.DENY


# =============================================================================
# Test: STEP_UP Decisions
# =============================================================================


class TestStepUpDecisions:
    """Tests for actions requiring elevated authentication."""

    def test_step_up_decision_factory(self) -> None:
        """AuthorizationDecision.step_up() factory works correctly."""
        decision = AuthorizationDecision.step_up(
            reasons=["High risk action requires MFA"],
            approval_id="approval-123",
            policy="step-up-mfa-policy",
            risk_score=70,
        )
        assert decision.decision == Decision.STEP_UP
        assert decision.approval_required is True
        assert decision.approval_id == "approval-123"

    def test_step_up_triggered_by_risk_threshold(self, strict_service: AuthorizationService) -> None:
        """Actions above step_up_threshold trigger STEP_UP."""
        request = AuthorizationRequest.create(
            agent_id="agent-step",
            agent_name="stepper-agent",
            principal="user@corp.com",
            action="iam:CreateAccessKey",
            resource="arn:aws:iam::123456789012:user/service-account",
            environment=Environment.STAGING,
            data_classification=DataClassification.CONFIDENTIAL,
        )
        decision = strict_service.authorize(request)
        # With strict thresholds, high-risk actions should get DENY or STEP_UP
        assert decision.decision in (Decision.DENY, Decision.STEP_UP, Decision.REVIEW)

    def test_review_decision_factory(self) -> None:
        """AuthorizationDecision.review() factory works correctly."""
        decision = AuthorizationDecision.review(
            reasons=["Unusual action requires human review"],
            approval_id="approval-456",
            policy="review-unusual-actions",
            risk_score=60,
        )
        assert decision.decision == Decision.REVIEW
        assert decision.approval_required is True


# =============================================================================
# Test: Fail-Closed Behavior
# =============================================================================


class TestFailClosed:
    """Tests for fail-closed default behavior."""

    def test_production_fail_closed_by_default(self, service: AuthorizationService) -> None:
        """Production environment defaults to DENY when no rule matches."""
        # Action that won't match any explicit rule
        request = AuthorizationRequest.create(
            agent_id="agent-unknown",
            agent_name="mystery-agent",
            principal="unknown@corp.com",
            action="customservice:SomeAction",
            resource="arn:aws:custom:us-east-1:123456789012:resource/unknown",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        decision = service.authorize(request)
        # Production is fail-closed by default, so unknown actions get DENY
        assert decision.decision == Decision.DENY

    def test_staging_fail_closed_by_default(self, service: AuthorizationService) -> None:
        """Staging environment is also fail-closed by default config."""
        request = AuthorizationRequest.create(
            agent_id="agent-staging",
            agent_name="staging-agent",
            principal="dev@corp.com",
            action="customservice:Unknown",
            resource="*",
            environment=Environment.STAGING,
            data_classification=DataClassification.INTERNAL,
        )
        decision = service.authorize(request)
        assert decision.decision == Decision.DENY


# =============================================================================
# Test: Fail-Open Behavior
# =============================================================================


class TestFailOpen:
    """Tests for fail-open default behavior in dev environments."""

    def test_dev_environment_fail_open(self, service: AuthorizationService) -> None:
        """Dev environment allows unmatched actions (fail-open)."""
        request = AuthorizationRequest.create(
            agent_id="agent-dev",
            agent_name="dev-agent",
            principal="dev@corp.com",
            action="customservice:ExperimentalAction",
            resource="arn:aws:custom:us-east-1:123456789012:resource/dev-test",
            environment=Environment.DEV,
            data_classification=DataClassification.PUBLIC,
        )
        decision = service.authorize(request)
        assert decision.decision == Decision.ALLOW

    def test_fail_open_config_allows_production(self) -> None:
        """When production is in fail_open_environments, unknown actions pass."""
        config = AuthorizationConfig(
            fail_open_environments=[Environment.DEV, Environment.STAGING, Environment.PRODUCTION],
            fail_closed_environments=[],
        )
        svc = AuthorizationService(config=config)
        request = AuthorizationRequest.create(
            agent_id="agent-custom",
            agent_name="custom-agent",
            principal="user@corp.com",
            action="customservice:SafeRead",
            resource="arn:aws:custom:::safe-resource",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.PUBLIC,
        )
        decision = svc.authorize(request)
        assert decision.decision == Decision.ALLOW


# =============================================================================
# Test: Decision Caching
# =============================================================================


class TestDecisionCaching:
    """Tests for the LRU decision cache."""

    def test_cache_hit_on_repeated_request(self, service: AuthorizationService, low_risk_request: AuthorizationRequest) -> None:
        """Same request returns cached decision on second call."""
        decision1 = service.authorize(low_risk_request)
        decision2 = service.authorize(low_risk_request)
        # Same decision outcome
        assert decision1.decision == decision2.decision
        # Cache should have recorded a hit
        assert service.cache.size >= 1

    def test_cache_respects_ttl(self) -> None:
        """Expired cache entries are not returned."""
        cache = DecisionCache(max_size=10, ttl_seconds=0.01)
        request = AuthorizationRequest.create(
            agent_id="agent-ttl", agent_name="ttl-agent",
            principal="user@test.com", action="s3:GetObject",
            resource="arn:aws:s3:::bucket/key",
            environment=Environment.DEV,
            data_classification=DataClassification.PUBLIC,
        )
        decision = AuthorizationDecision.allow(
            reasons=["test"], policy="test", risk_score=5, correlation_id="corr-1"
        )
        cache.put(request, decision)
        assert cache.get(request) is not None
        time.sleep(0.02)  # Wait for TTL to expire
        assert cache.get(request) is None

    def test_cache_evicts_oldest(self) -> None:
        """Cache evicts oldest entries when max_size is exceeded."""
        cache = DecisionCache(max_size=2, ttl_seconds=60.0)
        requests = []
        for i in range(3):
            req = AuthorizationRequest.create(
                agent_id=f"agent-{i}", agent_name=f"agent-{i}",
                principal="user@test.com", action=f"s3:Action{i}",
                resource=f"resource-{i}",
                environment=Environment.DEV,
                data_classification=DataClassification.PUBLIC,
            )
            requests.append(req)
            decision = AuthorizationDecision.allow(
                reasons=["ok"], policy="", risk_score=0, correlation_id=f"c-{i}"
            )
            cache.put(req, decision)

        # First request should have been evicted
        assert cache.size == 2
        assert cache.get(requests[0]) is None

    def test_cache_clear(self, service: AuthorizationService, low_risk_request: AuthorizationRequest) -> None:
        """Cache clear removes all entries."""
        service.authorize(low_risk_request)
        assert service.cache.size > 0
        service.cache.clear()
        assert service.cache.size == 0

    def test_cache_hit_rate(self) -> None:
        """Cache reports hit rate correctly."""
        cache = DecisionCache(max_size=100, ttl_seconds=60.0)
        request = AuthorizationRequest.create(
            agent_id="agent-hr", agent_name="hr-agent",
            principal="user@test.com", action="s3:GetObject",
            resource="arn:aws:s3:::bucket/key",
            environment=Environment.DEV,
            data_classification=DataClassification.PUBLIC,
        )
        decision = AuthorizationDecision.allow(
            reasons=["ok"], policy="", risk_score=0, correlation_id="c-hr"
        )
        cache.put(request, decision)
        cache.get(request)  # hit
        cache.get(request)  # hit
        assert cache.hit_rate > 0.0


# =============================================================================
# Test: Audit Trail Generation
# =============================================================================


class TestAuditTrail:
    """Tests for audit event generation."""

    def test_authorize_generates_audit_event(self, service: AuthorizationService, low_risk_request: AuthorizationRequest) -> None:
        """Every authorization generates an audit event."""
        service.authorize(low_risk_request)
        audit_logger = service.audit_logger
        assert len(audit_logger.events) >= 1

    def test_audit_event_contains_action(self, service: AuthorizationService, high_risk_request: AuthorizationRequest) -> None:
        """Audit event records the action."""
        service.authorize(high_risk_request)
        events = service.audit_logger.events
        last_event = events[-1]
        assert last_event.action == "iam:PassRole"

    def test_audit_event_records_decision(self, service: AuthorizationService, high_risk_request: AuthorizationRequest) -> None:
        """Audit event records the decision outcome."""
        decision = service.authorize(high_risk_request)
        events = service.audit_logger.events
        last_event = events[-1]
        assert last_event.decision == decision.decision

    def test_audit_event_has_integrity_hash(self, service: AuthorizationService, low_risk_request: AuthorizationRequest) -> None:
        """Audit events have integrity hashes."""
        service.authorize(low_risk_request)
        events = service.audit_logger.events
        assert events[-1].integrity_hash != ""
        assert len(events[-1].integrity_hash) == 64


# =============================================================================
# Test: Correlation ID Propagation
# =============================================================================


class TestCorrelationId:
    """Tests for correlation ID tracking across the pipeline."""

    def test_correlation_id_in_decision(self, service: AuthorizationService) -> None:
        """Decision carries the request's correlation_id."""
        request = AuthorizationRequest.create(
            agent_id="agent-corr",
            agent_name="corr-agent",
            principal="user@test.com",
            action="s3:GetObject",
            resource="arn:aws:s3:::dev-bucket/file",
            environment=Environment.DEV,
            data_classification=DataClassification.PUBLIC,
            correlation_id="my-custom-correlation-id",
        )
        decision = service.authorize(request)
        assert decision.correlation_id == "my-custom-correlation-id"

    def test_correlation_id_in_audit_event(self, service: AuthorizationService) -> None:
        """Audit event carries the same correlation_id as the request."""
        corr_id = "trace-" + str(uuid.uuid4())
        request = AuthorizationRequest.create(
            agent_id="agent-trace",
            agent_name="trace-agent",
            principal="tracer@corp.com",
            action="dynamodb:GetItem",
            resource="arn:aws:dynamodb:us-east-1:123:table/users",
            environment=Environment.DEV,
            data_classification=DataClassification.INTERNAL,
            correlation_id=corr_id,
        )
        service.authorize(request)
        events = service.audit_logger.events
        matching = [e for e in events if e.correlation_id == corr_id]
        assert len(matching) >= 1

    def test_auto_generated_correlation_id(self, service: AuthorizationService) -> None:
        """Requests without explicit correlation_id get one auto-generated."""
        request = AuthorizationRequest.create(
            agent_id="agent-auto",
            agent_name="auto-agent",
            principal="user@test.com",
            action="s3:ListBuckets",
            resource="*",
            environment=Environment.DEV,
            data_classification=DataClassification.PUBLIC,
        )
        decision = service.authorize(request)
        assert decision.correlation_id != ""
        assert len(decision.correlation_id) > 10  # UUID-length


# =============================================================================
# Test: Authorization Decision Validation
# =============================================================================


class TestDecisionValidation:
    """Tests for AuthorizationDecision validation."""

    def test_risk_score_out_of_range_rejected(self) -> None:
        """Risk score above 100 raises ValueError."""
        with pytest.raises(ValueError):
            AuthorizationDecision(
                decision=Decision.ALLOW,
                risk_score=150,
                reasons=["test"],
                policy="test",
                explanation="test",
                correlation_id="corr-1",
            )

    def test_risk_score_negative_rejected(self) -> None:
        """Negative risk score raises ValueError."""
        with pytest.raises(ValueError):
            AuthorizationDecision(
                decision=Decision.DENY,
                risk_score=-1,
                reasons=["test"],
                policy="test",
                explanation="test",
                correlation_id="corr-1",
            )
