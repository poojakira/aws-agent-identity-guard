"""Tests for the core domain models module.

Covers Agent creation/serialization, enumerations, AuthorizationRequest/Decision,
RiskScore, AuditEvent integrity hashing, validation, and edge cases.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from aws_agent_identity_guard.models import (
    Agent,
    AgentStatus,
    ApprovalRequest,
    ApprovalStatus,
    AttackPath,
    AttackStep,
    AuditEvent,
    AuthorizationDecision,
    AuthorizationRequest,
    DataClassification,
    Decision,
    EffectivePermission,
    Environment,
    Finding,
    FindingCategory,
    Permission,
    PermissionEffect,
    PermissionSource,
    PolicyRule,
    RiskScore,
    Severity,
    WorkloadType,
    _utcnow,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_agent() -> Agent:
    """Create a representative agent for testing."""
    return Agent.create(
        name="test-agent",
        owner="security-team",
        environment=Environment.PRODUCTION,
        workload_type=WorkloadType.BEDROCK_AGENT,
        iam_role_arn="arn:aws:iam::123456789012:role/test-agent-role",
        purpose="Unit testing",
        data_classification=DataClassification.CONFIDENTIAL,
        tags={"team": "security", "project": "guard"},
    )


@pytest.fixture
def sample_auth_request() -> AuthorizationRequest:
    """Create a sample authorization request."""
    return AuthorizationRequest.create(
        agent_id="agent-001",
        principal="user@example.com",
        action="s3:GetObject",
        resource="arn:aws:s3:::my-bucket/data.csv",
        tool="file-reader",
        data_classification=DataClassification.INTERNAL,
    )


@pytest.fixture
def sample_risk_score() -> RiskScore:
    """Create a valid risk score."""
    return RiskScore(
        privilege_score=0.7,
        sensitivity_score=0.5,
        blast_radius=0.3,
        data_exposure=0.4,
        persistence_risk=0.2,
        lateral_movement=0.1,
        environment_risk=0.8,
        transaction_context_risk=0.15,
        composite_score=0.55,
        calculation_details={"method": "test"},
    )


@pytest.fixture
def sample_audit_event() -> AuditEvent:
    """Create a sample audit event."""
    return AuditEvent.create(
        who="user@example.com",
        agent="test-agent",
        action="s3:GetObject",
        resource="arn:aws:s3:::bucket/key",
        decision=Decision.ALLOW,
        reason="Low risk action",
        policy_version="v1.0",
        correlation_id="corr-001",
    )


# =============================================================================
# Test: Agent Creation and Serialization
# =============================================================================


class TestAgentCreation:
    """Tests for Agent model creation and serialization."""

    def test_agent_create_factory(self, sample_agent: Agent) -> None:
        """Agent.create() produces a valid agent with auto-generated fields."""
        assert sample_agent.name == "test-agent"
        assert sample_agent.owner == "security-team"
        assert sample_agent.environment == Environment.PRODUCTION
        assert sample_agent.workload_type == WorkloadType.BEDROCK_AGENT
        assert sample_agent.status == AgentStatus.ACTIVE
        assert sample_agent.agent_id  # non-empty UUID
        assert sample_agent.created_at is not None
        assert sample_agent.last_activity is None

    def test_agent_serialization_roundtrip(self, sample_agent: Agent) -> None:
        """Agent serializes to dict and deserializes back correctly."""
        data = sample_agent.to_dict()
        restored = Agent.from_dict(data)
        assert restored.name == sample_agent.name
        assert restored.environment == sample_agent.environment
        assert restored.workload_type == sample_agent.workload_type
        assert restored.iam_role_arn == sample_agent.iam_role_arn

    def test_agent_is_production(self, sample_agent: Agent) -> None:
        """Agent in production environment reports is_production=True."""
        assert sample_agent.is_production is True

    def test_agent_is_active(self, sample_agent: Agent) -> None:
        """Active agent reports is_active=True."""
        assert sample_agent.is_active is True

    def test_agent_dev_environment(self) -> None:
        """Agent in dev environment reports is_production=False."""
        agent = Agent.create(
            name="dev-agent",
            owner="dev-team",
            environment=Environment.DEV,
            workload_type=WorkloadType.LAMBDA,
            iam_role_arn="arn:aws:iam::123456789012:role/dev-role",
        )
        assert agent.is_production is False


# =============================================================================
# Test: Enumerations
# =============================================================================


class TestEnumerations:
    """Tests for all domain enumerations."""

    def test_data_classification_values(self) -> None:
        """All DataClassification values exist and are strings."""
        expected = {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET", "REGULATED"}
        actual = {dc.value for dc in DataClassification}
        assert actual == expected

    def test_data_classification_comparison(self) -> None:
        """DataClassification supports ordering."""
        assert DataClassification.REGULATED > DataClassification.PUBLIC
        assert DataClassification.SECRET >= DataClassification.SECRET
        assert not (DataClassification.INTERNAL > DataClassification.CONFIDENTIAL)

    def test_environment_values(self) -> None:
        """All Environment enum values."""
        expected = {"dev", "staging", "production"}
        actual = {e.value for e in Environment}
        assert actual == expected

    def test_decision_values(self) -> None:
        """All Decision enum values."""
        expected = {"ALLOW", "DENY", "STEP_UP", "REVIEW"}
        actual = {d.value for d in Decision}
        assert actual == expected

    def test_severity_values(self) -> None:
        """All Severity enum values."""
        expected = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
        actual = {s.value for s in Severity}
        assert actual == expected

    def test_workload_type_values(self) -> None:
        """All WorkloadType enum values."""
        expected = {"BEDROCK_AGENT", "LAMBDA", "ECS", "EKS", "SAGEMAKER", "CUSTOM"}
        actual = {w.value for w in WorkloadType}
        assert actual == expected

    def test_approval_status_values(self) -> None:
        """All ApprovalStatus enum values."""
        expected = {"PENDING", "APPROVED", "DENIED", "EXPIRED", "CANCELLED"}
        actual = {a.value for a in ApprovalStatus}
        assert actual == expected

    def test_permission_effect_values(self) -> None:
        """All PermissionEffect enum values."""
        expected = {"ALLOW", "DENY", "CONDITION_DEPENDENT"}
        actual = {pe.value for pe in PermissionEffect}
        assert actual == expected

    def test_agent_status_values(self) -> None:
        """All AgentStatus enum values."""
        expected = {"ACTIVE", "INACTIVE", "SUSPENDED", "DECOMMISSIONED"}
        actual = {s.value for s in AgentStatus}
        assert actual == expected

    def test_finding_category_values(self) -> None:
        """All FindingCategory enum values."""
        expected = {
            "PRIVILEGE_ESCALATION", "EXCESSIVE_PERMISSIONS", "DATA_EXPOSURE",
            "LATERAL_MOVEMENT", "PERSISTENCE", "POLICY_VIOLATION",
            "DRIFT", "COMPLIANCE", "CONFIGURATION",
        }
        actual = {fc.value for fc in FindingCategory}
        assert actual == expected


# =============================================================================
# Test: AuthorizationRequest and Decision
# =============================================================================


class TestAuthorizationModels:
    """Tests for AuthorizationRequest and AuthorizationDecision."""

    def test_authorization_request_creation(self, sample_auth_request: AuthorizationRequest) -> None:
        """AuthorizationRequest.create() populates all fields."""
        assert sample_auth_request.agent_id == "agent-001"
        assert sample_auth_request.principal == "user@example.com"
        assert sample_auth_request.action == "s3:GetObject"
        assert sample_auth_request.resource == "arn:aws:s3:::my-bucket/data.csv"
        assert sample_auth_request.tool == "file-reader"
        assert sample_auth_request.data_classification == DataClassification.INTERNAL

    def test_authorization_request_serialization(self, sample_auth_request: AuthorizationRequest) -> None:
        """AuthorizationRequest serializes to dict."""
        data = sample_auth_request.to_dict()
        assert data["agent_id"] == "agent-001"
        assert data["action"] == "s3:GetObject"
        assert data["data_classification"] == "INTERNAL"

    def test_authorization_decision_allow(self) -> None:
        """AuthorizationDecision.allow() creates an ALLOW decision."""
        decision = AuthorizationDecision.allow(
            reasons=["Low risk"], policy_ref="default-allow", risk_score=0.1
        )
        assert decision.decision == Decision.ALLOW
        assert decision.risk_score == 0.1
        assert "Low risk" in decision.reasons

    def test_authorization_decision_deny(self) -> None:
        """AuthorizationDecision.deny() creates a DENY decision."""
        decision = AuthorizationDecision.deny(
            reasons=["Policy violation"], policy_ref="deny-escalation"
        )
        assert decision.decision == Decision.DENY
        assert "Policy violation" in decision.reasons

    def test_authorization_decision_step_up(self) -> None:
        """AuthorizationDecision.step_up() creates a STEP_UP decision."""
        decision = AuthorizationDecision.step_up(
            reasons=["High risk action"], policy_ref="step-up-rule"
        )
        assert decision.decision == Decision.STEP_UP

    def test_authorization_decision_review(self) -> None:
        """AuthorizationDecision.review() creates a REVIEW decision."""
        decision = AuthorizationDecision.review(
            reasons=["Needs human review"], policy_ref="review-rule"
        )
        assert decision.decision == Decision.REVIEW


# =============================================================================
# Test: RiskScore
# =============================================================================


class TestRiskScore:
    """Tests for the RiskScore model."""

    def test_risk_score_creation(self, sample_risk_score: RiskScore) -> None:
        """RiskScore stores all dimension scores."""
        assert sample_risk_score.privilege_score == 0.7
        assert sample_risk_score.composite_score == 0.55

    def test_risk_score_zero_factory(self) -> None:
        """RiskScore.zero() returns all-zero baseline."""
        zero = RiskScore.zero()
        assert zero.composite_score == 0.0
        assert zero.privilege_score == 0.0
        assert zero.is_high_risk is False
        assert zero.is_critical is False

    def test_risk_score_is_high_risk(self) -> None:
        """RiskScore above 0.7 threshold is high risk."""
        high = RiskScore(
            privilege_score=0.9, sensitivity_score=0.8, blast_radius=0.7,
            data_exposure=0.6, persistence_risk=0.5, lateral_movement=0.4,
            environment_risk=0.9, transaction_context_risk=0.3,
            composite_score=0.75, calculation_details={},
        )
        assert high.is_high_risk is True

    def test_risk_score_is_critical(self) -> None:
        """RiskScore above 0.9 threshold is critical."""
        critical = RiskScore(
            privilege_score=0.95, sensitivity_score=0.9, blast_radius=0.9,
            data_exposure=0.8, persistence_risk=0.7, lateral_movement=0.8,
            environment_risk=0.95, transaction_context_risk=0.5,
            composite_score=0.92, calculation_details={},
        )
        assert critical.is_critical is True

    def test_risk_score_validation_rejects_out_of_range(self) -> None:
        """RiskScore rejects scores outside 0.0-1.0 range."""
        with pytest.raises(ValueError, match="must be between 0.0 and 1.0"):
            RiskScore(
                privilege_score=1.5, sensitivity_score=0.5, blast_radius=0.3,
                data_exposure=0.4, persistence_risk=0.2, lateral_movement=0.1,
                environment_risk=0.8, transaction_context_risk=0.15,
                composite_score=0.55, calculation_details={},
            )

    def test_risk_score_serialization(self, sample_risk_score: RiskScore) -> None:
        """RiskScore serializes and deserializes correctly."""
        data = sample_risk_score.to_dict()
        restored = RiskScore.from_dict(data)
        assert restored.privilege_score == sample_risk_score.privilege_score
        assert restored.composite_score == sample_risk_score.composite_score


# =============================================================================
# Test: AuditEvent Integrity Hash
# =============================================================================


class TestAuditEventIntegrity:
    """Tests for AuditEvent cryptographic integrity."""

    def test_audit_event_creation(self, sample_audit_event: AuditEvent) -> None:
        """AuditEvent.create() generates integrity hash."""
        assert sample_audit_event.integrity_hash != ""
        assert len(sample_audit_event.integrity_hash) == 64  # SHA-256 hex

    def test_audit_event_verify_integrity(self, sample_audit_event: AuditEvent) -> None:
        """AuditEvent verifies its own integrity hash."""
        assert sample_audit_event.verify_integrity(previous_hash="") is True

    def test_audit_event_detects_tampering(self, sample_audit_event: AuditEvent) -> None:
        """AuditEvent detects incorrect previous_hash (tampered chain)."""
        # Passing a wrong previous hash should fail verification
        assert sample_audit_event.verify_integrity(previous_hash="wrong_hash") is False

    def test_audit_event_chain_integrity(self) -> None:
        """Two chained events maintain integrity through hash linking."""
        event1 = AuditEvent.create(
            who="user1", agent="agent-a", action="s3:GetObject",
            resource="arn:aws:s3:::bucket/file1", decision=Decision.ALLOW,
            reason="OK", policy_version="v1",
        )
        event2 = AuditEvent.create(
            who="user2", agent="agent-b", action="iam:PassRole",
            resource="arn:aws:iam::123:role/admin", decision=Decision.DENY,
            reason="Escalation", policy_version="v1",
            previous_hash=event1.integrity_hash,
        )
        # event2 can verify against event1's hash
        assert event2.verify_integrity(previous_hash=event1.integrity_hash) is True
        # But not against a different hash
        assert event2.verify_integrity(previous_hash="tampered") is False

    def test_audit_event_correlation_id_propagation(self) -> None:
        """AuditEvent preserves provided correlation_id."""
        event = AuditEvent.create(
            who="user", agent="agent", action="ec2:RunInstances",
            resource="*", decision=Decision.STEP_UP,
            correlation_id="custom-corr-123",
        )
        assert event.correlation_id == "custom-corr-123"


# =============================================================================
# Test: Validation
# =============================================================================


class TestValidation:
    """Tests for model validation constraints."""

    def test_risk_score_negative_value_rejected(self) -> None:
        """RiskScore rejects negative dimension scores."""
        with pytest.raises(ValueError):
            RiskScore(
                privilege_score=-0.1, sensitivity_score=0.5, blast_radius=0.3,
                data_exposure=0.4, persistence_risk=0.2, lateral_movement=0.1,
                environment_risk=0.8, transaction_context_risk=0.15,
                composite_score=0.55, calculation_details={},
            )

    def test_attack_path_validation(self) -> None:
        """AttackPath validates likelihood and impact ranges."""
        with pytest.raises(ValueError, match="likelihood"):
            AttackPath(
                source_node="agent-1", steps=[], target="admin-role",
                likelihood=1.5, impact=0.5, description="bad path",
            )
        with pytest.raises(ValueError, match="impact"):
            AttackPath(
                source_node="agent-1", steps=[], target="admin-role",
                likelihood=0.5, impact=-0.1, description="bad path",
            )

    def test_finding_risk_score_validation(self) -> None:
        """Finding validates risk_score range."""
        with pytest.raises(ValueError, match="risk_score"):
            Finding(
                rule_id="test", severity=Severity.HIGH,
                category=FindingCategory.PRIVILEGE_ESCALATION,
                message="test", remediation="", attack_chain=[],
                risk_score=2.0, affected_resources=[], compliance_mappings={},
            )


# =============================================================================
# Test: Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for boundary conditions and edge cases."""

    def test_permission_allow_factory(self) -> None:
        """Permission.allow() creates ALLOW permission."""
        perm = Permission.allow(
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket/*",
            source=PermissionSource.IDENTITY_POLICY,
        )
        assert perm.effect == PermissionEffect.ALLOW
        assert perm.conditions == {}

    def test_permission_deny_factory(self) -> None:
        """Permission.deny() creates DENY permission."""
        perm = Permission.deny(
            action="iam:*",
            resource="*",
            source=PermissionSource.SCP,
        )
        assert perm.effect == PermissionEffect.DENY

    def test_approval_request_expiry(self) -> None:
        """ApprovalRequest correctly detects expiry."""
        expired = ApprovalRequest(
            request_id="req-1", agent_id="agent-1", action="iam:PassRole",
            resource="*", requestor="user@test.com", approver="",
            status=ApprovalStatus.PENDING,
            expiry=datetime(2020, 1, 1, tzinfo=timezone.utc),
            created_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )
        assert expired.is_expired is True
        assert expired.is_pending is False

    def test_attack_path_risk_rating(self) -> None:
        """AttackPath.risk_rating is likelihood * impact."""
        path = AttackPath(
            source_node="agent-1", steps=[], target="secret",
            likelihood=0.8, impact=0.6, description="test",
        )
        assert path.risk_rating == pytest.approx(0.48)

    def test_risk_score_boundary_values(self) -> None:
        """RiskScore accepts exact boundary values 0.0 and 1.0."""
        score = RiskScore(
            privilege_score=0.0, sensitivity_score=1.0, blast_radius=0.0,
            data_exposure=1.0, persistence_risk=0.0, lateral_movement=1.0,
            environment_risk=0.0, transaction_context_risk=1.0,
            composite_score=0.5, calculation_details={},
        )
        assert score.privilege_score == 0.0
        assert score.sensitivity_score == 1.0

    def test_agent_empty_policies(self) -> None:
        """Agent with empty policies serializes correctly."""
        agent = Agent.create(
            name="minimal-agent", owner="ops",
            environment=Environment.DEV,
            workload_type=WorkloadType.CUSTOM,
            iam_role_arn="arn:aws:iam::000000000000:role/empty",
        )
        data = agent.to_dict()
        assert data["identity_policies"] == []
        assert data["permission_boundaries"] == []
