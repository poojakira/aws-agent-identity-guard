"""
tests/test_models.py
--------------------
Comprehensive tests for core data models.

Covers creation, validation, serialization, enum types, risk score bounds,
audit event integrity hashing, and attack path composite scoring.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest

from aws_agent_identity_guard.models import (
    AgentCapability,
    AgentIdentity,
    AgentType,
    AttackPath,
    AttackStep,
    AuditEvent,
    AuthorizationDecision,
    AuthorizationDecisionType,
    DataClassification,
    DriftEvent,
    EffectiveEffect,
    EffectivePermission,
    Environment,
    Permission,
    PermissionEffect,
    PolicyDocument,
    PolicySource,
    RiskScore,
    TransactionRequest,
    _validate_range,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def sample_agent() -> AgentIdentity:
    """Return a valid sample AgentIdentity for testing."""
    return AgentIdentity(
        agent_id="agent-001",
        name="TestAgent",
        agent_type=AgentType.BEDROCK,
        owner="security-team",
        environment=Environment.PRODUCTION,
        purpose="Unit testing",
        iam_role_arn="arn:aws:iam::123456789012:role/TestRole",
        data_classification=DataClassification.CONFIDENTIAL,
        declared_capabilities=["s3:read", "bedrock:invoke"],
        tags={"team": "platform"},
    )


@pytest.fixture
def sample_risk_score() -> RiskScore:
    """Return a valid sample RiskScore."""
    return RiskScore(
        overall=65.0,
        privilege=80.0,
        sensitivity=50.0,
        blast_radius=70.0,
        data_exposure=40.0,
        persistence=30.0,
        lateral_movement=60.0,
        environment_factor=1.5,
    )


@pytest.fixture
def sample_transaction() -> TransactionRequest:
    """Return a valid sample TransactionRequest."""
    return TransactionRequest(
        agent_id="agent-001",
        principal="arn:aws:iam::123456789012:role/TestRole",
        tool="s3-accessor",
        action="s3:GetObject",
        resource="arn:aws:s3:::my-bucket/data.csv",
        data_classification=DataClassification.CONFIDENTIAL,
    )


# ─── Enum Tests ───────────────────────────────────────────────────────────────


class TestEnums:
    """Test all enum types for correct values and membership."""

    def test_agent_type_values(self):
        """Verify all AgentType enum members."""
        expected = {"BEDROCK", "LAMBDA", "ECS", "EKS", "SAGEMAKER", "CUSTOM"}
        actual = {e.value for e in AgentType}
        assert actual == expected

    def test_environment_values(self):
        """Verify all Environment enum members."""
        expected = {"DEVELOPMENT", "STAGING", "PRODUCTION"}
        actual = {e.value for e in Environment}
        assert actual == expected

    def test_data_classification_values(self):
        """Verify all DataClassification enum members."""
        expected = {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET", "REGULATED"}
        actual = {e.value for e in DataClassification}
        assert actual == expected

    def test_permission_effect_values(self):
        """Verify PermissionEffect enum members."""
        assert PermissionEffect.ALLOW.value == "ALLOW"
        assert PermissionEffect.DENY.value == "DENY"

    def test_effective_effect_values(self):
        """Verify EffectiveEffect enum members."""
        expected = {"ALLOWED", "DENIED", "CONDITIONAL"}
        actual = {e.value for e in EffectiveEffect}
        assert actual == expected

    def test_authorization_decision_type_values(self):
        """Verify AuthorizationDecisionType enum members."""
        expected = {"ALLOW", "DENY", "STEP_UP", "REVIEW"}
        actual = {e.value for e in AuthorizationDecisionType}
        assert actual == expected

    def test_policy_source_values(self):
        """Verify PolicySource enum members."""
        expected = {
            "IDENTITY_POLICY",
            "RESOURCE_POLICY",
            "PERMISSION_BOUNDARY",
            "SCP",
            "SESSION_POLICY",
        }
        actual = {e.value for e in PolicySource}
        assert actual == expected


# ─── AgentIdentity Tests ──────────────────────────────────────────────────────


class TestAgentIdentity:
    """Test AgentIdentity creation, validation, and serialization."""

    def test_create_valid_agent(self, sample_agent):
        """Verify a properly constructed agent has expected attributes."""
        assert sample_agent.agent_id == "agent-001"
        assert sample_agent.name == "TestAgent"
        assert sample_agent.agent_type == AgentType.BEDROCK
        assert sample_agent.environment == Environment.PRODUCTION
        assert sample_agent.data_classification == DataClassification.CONFIDENTIAL

    def test_agent_requires_name(self):
        """Agent creation fails without a name."""
        with pytest.raises(ValueError, match="name cannot be empty"):
            AgentIdentity(agent_id="x", name="")

    def test_agent_validates_arn_format(self):
        """Agent creation fails with invalid ARN format."""
        with pytest.raises(ValueError, match="must be a valid ARN"):
            AgentIdentity(
                agent_id="x",
                name="Bad",
                iam_role_arn="not-an-arn",
            )

    def test_agent_string_enum_coercion(self):
        """String values for enums are coerced to proper enum types."""
        agent = AgentIdentity(
            agent_id="a1",
            name="Coerce",
            agent_type="LAMBDA",
            environment="STAGING",
            data_classification="SECRET",
        )
        assert agent.agent_type == AgentType.LAMBDA
        assert agent.environment == Environment.STAGING
        assert agent.data_classification == DataClassification.SECRET

    def test_agent_serialization_roundtrip(self, sample_agent):
        """to_dict / from_dict produces an equivalent object."""
        data = sample_agent.to_dict()
        restored = AgentIdentity.from_dict(data)
        assert restored.agent_id == sample_agent.agent_id
        assert restored.name == sample_agent.name
        assert restored.agent_type == sample_agent.agent_type
        assert restored.environment == sample_agent.environment
        assert restored.data_classification == sample_agent.data_classification
        assert restored.declared_capabilities == sample_agent.declared_capabilities


# ─── RiskScore Tests ──────────────────────────────────────────────────────────


class TestRiskScore:
    """Test RiskScore bounds validation and serialization."""

    def test_valid_risk_score(self, sample_risk_score):
        """Valid risk score is accepted without error."""
        assert sample_risk_score.overall == 65.0
        assert sample_risk_score.environment_factor == 1.5

    def test_overall_below_zero_rejected(self):
        """Overall score below 0 raises ValueError."""
        with pytest.raises(ValueError, match="overall must be between"):
            RiskScore(overall=-1.0)

    def test_overall_above_100_rejected(self):
        """Overall score above 100 raises ValueError."""
        with pytest.raises(ValueError, match="overall must be between"):
            RiskScore(overall=101.0)

    def test_privilege_out_of_bounds(self):
        """Privilege dimension above 100 raises ValueError."""
        with pytest.raises(ValueError, match="privilege must be between"):
            RiskScore(privilege=150.0)

    def test_sensitivity_below_zero(self):
        """Sensitivity dimension below 0 raises ValueError."""
        with pytest.raises(ValueError, match="sensitivity must be between"):
            RiskScore(sensitivity=-5.0)

    def test_negative_environment_factor_rejected(self):
        """Negative environment_factor raises ValueError."""
        with pytest.raises(ValueError, match="environment_factor must be non-negative"):
            RiskScore(environment_factor=-0.5)

    def test_zero_environment_factor_accepted(self):
        """Zero environment_factor is valid (edge case)."""
        score = RiskScore(environment_factor=0.0)
        assert score.environment_factor == 0.0

    def test_risk_score_serialization_roundtrip(self, sample_risk_score):
        """to_dict / from_dict roundtrip preserves all fields."""
        data = sample_risk_score.to_dict()
        restored = RiskScore.from_dict(data)
        assert restored.overall == sample_risk_score.overall
        assert restored.privilege == sample_risk_score.privilege
        assert restored.environment_factor == sample_risk_score.environment_factor


# ─── AuditEvent Tests ─────────────────────────────────────────────────────────


class TestAuditEvent:
    """Test AuditEvent integrity hash computation and verification."""

    def test_integrity_hash_auto_computed(self):
        """Integrity hash is automatically computed on creation."""
        event = AuditEvent(
            event_id="evt-001",
            correlation_id="corr-001",
            agent_id="agent-001",
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket/key",
            decision=AuthorizationDecisionType.DENY,
            reasons=["high risk"],
        )
        assert event.integrity_hash != ""
        assert len(event.integrity_hash) == 64  # SHA-256 hex digest

    def test_integrity_hash_verification_passes(self):
        """verify_integrity returns True for unmodified event."""
        event = AuditEvent(
            event_id="evt-002",
            agent_id="agent-002",
            action="iam:PassRole",
            resource="*",
            decision=AuthorizationDecisionType.DENY,
            reasons=["escalation detected"],
        )
        assert event.verify_integrity() is True

    def test_integrity_hash_detects_tampering(self):
        """Modifying event fields causes integrity verification to fail."""
        event = AuditEvent(
            event_id="evt-003",
            agent_id="agent-003",
            action="iam:CreateRole",
            resource="*",
            decision=AuthorizationDecisionType.DENY,
            reasons=["blocked"],
        )
        # Tamper with the action field
        event.action = "s3:GetObject"
        assert event.verify_integrity() is False

    def test_audit_event_serialization_roundtrip(self):
        """Serialization and deserialization preserve integrity hash."""
        event = AuditEvent(
            event_id="evt-004",
            correlation_id="corr-004",
            agent_id="agent-004",
            principal="arn:aws:iam::123456789012:role/X",
            action="lambda:InvokeFunction",
            resource="arn:aws:lambda:us-east-1:123456789012:function:myfunc",
            decision=AuthorizationDecisionType.ALLOW,
            reasons=["low risk"],
            policy_version="2.0.0",
        )
        data = event.to_dict()
        restored = AuditEvent.from_dict(data)
        assert restored.integrity_hash == event.integrity_hash
        assert restored.verify_integrity()


# ─── AttackPath Tests ─────────────────────────────────────────────────────────


class TestAttackPath:
    """Test AttackPath composite scoring and validation."""

    def test_composite_score_auto_computed(self):
        """composite_score is computed as likelihood * impact * 100."""
        path = AttackPath(
            steps=[
                AttackStep(
                    action="sts:AssumeRole",
                    resource="arn:aws:iam::123456789012:role/Admin",
                )
            ],
            likelihood=0.8,
            impact=0.9,
        )
        assert path.composite_score == pytest.approx(72.0, abs=0.01)

    def test_composite_score_zero_likelihood(self):
        """Zero likelihood produces zero composite score."""
        path = AttackPath(
            steps=[AttackStep(action="s3:GetObject", resource="*")],
            likelihood=0.0,
            impact=1.0,
        )
        assert path.composite_score == 0.0

    def test_likelihood_above_one_rejected(self):
        """Likelihood above 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="likelihood must be between"):
            AttackPath(likelihood=1.5, impact=0.5)

    def test_impact_below_zero_rejected(self):
        """Impact below 0.0 raises ValueError."""
        with pytest.raises(ValueError, match="impact must be between"):
            AttackPath(likelihood=0.5, impact=-0.1)

    def test_attack_path_serialization_roundtrip(self):
        """to_dict / from_dict roundtrip preserves steps and scores."""
        path = AttackPath(
            steps=[
                AttackStep(
                    action="iam:PassRole",
                    resource="*",
                    description="Pass admin role",
                    privilege_gained="Lambda execution as admin",
                ),
                AttackStep(
                    action="lambda:CreateFunction",
                    resource="*",
                    description="Create backdoor function",
                ),
            ],
            likelihood=0.85,
            impact=0.95,
            description="PassRole to Lambda exploitation chain",
        )
        data = path.to_dict()
        restored = AttackPath.from_dict(data)
        assert len(restored.steps) == 2
        assert restored.likelihood == 0.85
        assert restored.impact == 0.95
        assert restored.steps[0].action == "iam:PassRole"


# ─── Permission and EffectivePermission Tests ─────────────────────────────────


class TestPermission:
    """Test Permission validation and serialization."""

    def test_permission_requires_action(self):
        """Permission creation fails without action."""
        with pytest.raises(ValueError, match="action cannot be empty"):
            Permission(action="", resource="*", effect=PermissionEffect.ALLOW)

    def test_permission_requires_resource(self):
        """Permission creation fails without resource."""
        with pytest.raises(ValueError, match="resource cannot be empty"):
            Permission(action="s3:GetObject", resource="", effect=PermissionEffect.ALLOW)

    def test_permission_frozen(self):
        """Permission is immutable (frozen dataclass)."""
        perm = Permission(action="s3:GetObject", resource="*", effect=PermissionEffect.ALLOW)
        with pytest.raises(Exception):
            perm.action = "s3:PutObject"

    def test_permission_serialization(self):
        """Permission serializes and deserializes correctly."""
        perm = Permission(
            action="iam:PassRole",
            resource="arn:aws:iam::123456789012:role/Lambda",
            effect=PermissionEffect.ALLOW,
            source=PolicySource.IDENTITY_POLICY,
        )
        data = perm.to_dict()
        restored = Permission.from_dict(data)
        assert restored.action == perm.action
        assert restored.effect == perm.effect
        assert restored.source == perm.source


class TestEffectivePermission:
    """Test EffectivePermission model."""

    def test_effective_permission_creation(self):
        """Valid EffectivePermission is created without error."""
        ep = EffectivePermission(
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket/*",
            effective_effect=EffectiveEffect.ALLOWED,
            contributing_policies=["PolicyA"],
            evaluation_reason="Identity policy grants access",
        )
        assert ep.effective_effect == EffectiveEffect.ALLOWED

    def test_effective_permission_requires_action(self):
        """EffectivePermission creation fails without action."""
        with pytest.raises(ValueError, match="action cannot be empty"):
            EffectivePermission(action="", resource="*", effective_effect=EffectiveEffect.ALLOWED)


# ─── TransactionRequest Tests ─────────────────────────────────────────────────


class TestTransactionRequest:
    """Test TransactionRequest validation and serialization."""

    def test_transaction_requires_agent_id(self):
        """TransactionRequest requires non-empty agent_id."""
        with pytest.raises(ValueError, match="agent_id cannot be empty"):
            TransactionRequest(
                agent_id="",
                principal="role",
                tool="tool",
                action="s3:GetObject",
                resource="*",
            )

    def test_transaction_requires_action(self):
        """TransactionRequest requires non-empty action."""
        with pytest.raises(ValueError, match="action cannot be empty"):
            TransactionRequest(
                agent_id="a1",
                principal="role",
                tool="tool",
                action="",
                resource="*",
            )

    def test_transaction_serialization_roundtrip(self, sample_transaction):
        """Serialization roundtrip preserves all fields."""
        data = sample_transaction.to_dict()
        restored = TransactionRequest.from_dict(data)
        assert restored.agent_id == sample_transaction.agent_id
        assert restored.action == sample_transaction.action
        assert restored.data_classification == sample_transaction.data_classification


# ─── AuthorizationDecision Tests ──────────────────────────────────────────────


class TestAuthorizationDecision:
    """Test AuthorizationDecision model."""

    def test_decision_creation(self, sample_risk_score):
        """Valid AuthorizationDecision is created without error."""
        decision = AuthorizationDecision(
            decision=AuthorizationDecisionType.DENY,
            risk_score=sample_risk_score,
            reasons=["Too risky"],
            policy_matched="deny-high-risk",
        )
        assert decision.decision == AuthorizationDecisionType.DENY
        assert decision.correlation_id != ""

    def test_decision_string_coercion(self):
        """String value for decision is coerced to enum."""
        decision = AuthorizationDecision(decision="ALLOW")
        assert decision.decision == AuthorizationDecisionType.ALLOW


# ─── Utility Validation Tests ─────────────────────────────────────────────────


class TestValidationHelpers:
    """Test utility validation functions."""

    def test_validate_range_within_bounds(self):
        """Value within bounds passes validation."""
        _validate_range(50.0, 0.0, 100.0, "score")

    def test_validate_range_at_lower_bound(self):
        """Value at lower bound passes validation."""
        _validate_range(0.0, 0.0, 100.0, "score")

    def test_validate_range_at_upper_bound(self):
        """Value at upper bound passes validation."""
        _validate_range(100.0, 0.0, 100.0, "score")

    def test_validate_range_below_lower_bound(self):
        """Value below lower bound raises ValueError."""
        with pytest.raises(ValueError):
            _validate_range(-0.1, 0.0, 100.0, "score")

    def test_validate_range_above_upper_bound(self):
        """Value above upper bound raises ValueError."""
        with pytest.raises(ValueError):
            _validate_range(100.1, 0.0, 100.0, "score")
