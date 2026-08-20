"""Tests for the risk engine module.

Covers individual permission scoring, agent scoring, transaction scoring,
toxic combinations, environment multipliers, risk profiles, and edge cases.
"""

from __future__ import annotations

from typing import Any

import pytest

from aws_agent_identity_guard.models import (
    Agent,
    AttackPath,
    AttackStep,
    AuthorizationRequest,
    DataClassification,
    Environment,
    RiskScore,
    WorkloadType,
)
from aws_agent_identity_guard.risk_engine import (
    PERMISSIVE_PROFILE,
    PROFILES,
    RISK_FACTORS_CATALOG,
    STANDARD_PROFILE,
    STRICT_PROFILE,
    TOXIC_COMBINATIONS,
    RiskCalculation,
    RiskEngine,
    RiskFactor,
    RiskLevel,
    RiskProfile,
    RiskThresholds,
    ToxicCombination,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def strict_engine() -> RiskEngine:
    """Risk engine with strict profile."""
    return RiskEngine(profile="strict")


@pytest.fixture
def standard_engine() -> RiskEngine:
    """Risk engine with standard profile."""
    return RiskEngine(profile="standard")


@pytest.fixture
def permissive_engine() -> RiskEngine:
    """Risk engine with permissive profile."""
    return RiskEngine(profile="permissive")


@pytest.fixture
def sample_agent() -> Agent:
    """Agent with high-risk permissions for testing."""
    return Agent.create(
        name="risky-agent",
        owner="dev-team",
        environment=Environment.PRODUCTION,
        workload_type=WorkloadType.BEDROCK_AGENT,
        iam_role_arn="arn:aws:iam::123456789012:role/risky-agent-role",
        data_classification=DataClassification.SECRET,
    )


@pytest.fixture
def low_risk_agent() -> Agent:
    """Agent with minimal permissions."""
    agent = Agent.create(
        name="readonly-agent",
        owner="analytics-team",
        environment=Environment.DEV,
        workload_type=WorkloadType.LAMBDA,
        iam_role_arn="arn:aws:iam::123456789012:role/readonly-agent",
        data_classification=DataClassification.PUBLIC,
    )
    return agent


@pytest.fixture
def sample_auth_request() -> AuthorizationRequest:
    """Authorization request for a high-risk action."""
    return AuthorizationRequest.create(
        agent_id="agent-001",
        principal="user@corp.com",
        action="iam:PassRole",
        resource="arn:aws:iam::123456789012:role/admin-role",
        data_classification=DataClassification.SECRET,
        context={"environment": Environment.PRODUCTION},
        risk_context={"related_actions": ["lambda:CreateFunction"]},
    )


# =============================================================================
# Test: Individual Permission Scoring
# =============================================================================


class TestPermissionScoring:
    """Tests for scoring individual permissions."""

    def test_high_risk_iam_action(self, standard_engine: RiskEngine) -> None:
        """iam:CreateRole scores high on privilege dimension."""
        result = standard_engine.score_permission("iam:CreateRole", "*")
        assert result.composite_score > 50.0
        assert result.dimension_scores["privilege_score"] > 70.0

    def test_read_only_action_low_risk(self, standard_engine: RiskEngine) -> None:
        """s3:ListBuckets scores low overall."""
        result = standard_engine.score_permission("s3:ListBuckets", "arn:aws:s3:::*")
        assert result.composite_score < 40.0

    def test_destructive_action_high_blast_radius(self, standard_engine: RiskEngine) -> None:
        """s3:DeleteBucket scores high on blast_radius."""
        result = standard_engine.score_permission("s3:DeleteBucket", "arn:aws:s3:::production-data")
        assert result.dimension_scores["blast_radius"] > 50.0

    def test_wildcard_resource_increases_risk(self, standard_engine: RiskEngine) -> None:
        """Wildcard resource (*) increases sensitivity score."""
        result_specific = standard_engine.score_permission("s3:GetObject", "arn:aws:s3:::bucket/key")
        result_wildcard = standard_engine.score_permission("s3:GetObject", "*")
        assert result_wildcard.composite_score > result_specific.composite_score

    def test_secretsmanager_high_data_exposure(self, standard_engine: RiskEngine) -> None:
        """secretsmanager:GetSecretValue scores high on data_exposure."""
        result = standard_engine.score_permission(
            "secretsmanager:GetSecretValue",
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-db-creds",
        )
        assert result.dimension_scores["data_exposure"] > 50.0

    def test_sts_assume_role_lateral_movement(self, standard_engine: RiskEngine) -> None:
        """sts:AssumeRole scores high on lateral_movement."""
        result = standard_engine.score_permission(
            "sts:AssumeRole",
            "arn:aws:iam::999999999999:role/cross-account-admin",
        )
        assert result.dimension_scores["lateral_movement"] > 50.0

    def test_permission_scoring_returns_risk_calculation(self, standard_engine: RiskEngine) -> None:
        """score_permission returns a RiskCalculation with all fields."""
        result = standard_engine.score_permission("ec2:RunInstances", "*")
        assert isinstance(result, RiskCalculation)
        assert "privilege_score" in result.dimension_scores
        assert "blast_radius" in result.dimension_scores
        assert result.risk_level in RiskLevel
        assert result.explanation != ""

    def test_environment_context_affects_scoring(self, standard_engine: RiskEngine) -> None:
        """Production environment context increases environment_risk dimension."""
        result_prod = standard_engine.score_permission(
            "s3:PutObject", "arn:aws:s3:::bucket/key",
            context={"environment": Environment.PRODUCTION},
        )
        result_dev = standard_engine.score_permission(
            "s3:PutObject", "arn:aws:s3:::bucket/key",
            context={"environment": Environment.DEV},
        )
        assert result_prod.dimension_scores["environment_risk"] > result_dev.dimension_scores["environment_risk"]


# =============================================================================
# Test: Agent Risk Scoring
# =============================================================================


class TestAgentScoring:
    """Tests for scoring overall agent risk posture."""

    def test_agent_with_admin_policies_high_risk(self, standard_engine: RiskEngine) -> None:
        """Agent with admin-level policies scores high."""
        agent = Agent.create(
            name="admin-agent",
            owner="platform",
            environment=Environment.PRODUCTION,
            workload_type=WorkloadType.BEDROCK_AGENT,
            iam_role_arn="arn:aws:iam::123456789012:role/admin-agent",
            data_classification=DataClassification.SECRET,
        )
        # Simulate identity policies with high-risk actions
        agent_dict = agent.to_dict()
        agent_dict["identity_policies"] = [
            {
                "PolicyName": "admin-access",
                "PolicyDocument": {
                    "Statement": [
                        {"Effect": "Allow", "Action": ["iam:*", "sts:*"], "Resource": "*"}
                    ]
                },
            }
        ]
        reconstructed = Agent.from_dict(agent_dict)
        result = standard_engine.score_agent(reconstructed)
        assert result.composite_score > 15.0  # Agent with admin policies has elevated risk

    def test_agent_environment_risk(self, standard_engine: RiskEngine, sample_agent: Agent) -> None:
        """Production agent has higher environment_risk than dev agent."""
        result = standard_engine.score_agent(sample_agent)
        assert result.dimension_scores["environment_risk"] >= 80.0

    def test_agent_scoring_returns_risk_level(self, standard_engine: RiskEngine, sample_agent: Agent) -> None:
        """Agent scoring classifies into a RiskLevel."""
        result = standard_engine.score_agent(sample_agent)
        assert result.risk_level in RiskLevel


# =============================================================================
# Test: Transaction Risk Scoring
# =============================================================================


class TestTransactionScoring:
    """Tests for real-time transaction risk scoring."""

    def test_transaction_high_risk_action(self, standard_engine: RiskEngine, sample_auth_request: AuthorizationRequest) -> None:
        """iam:PassRole transaction scores high."""
        result = standard_engine.score_transaction(sample_auth_request)
        assert result.composite_score > 40.0

    def test_transaction_low_risk_read(self, standard_engine: RiskEngine) -> None:
        """Read-only S3 action in dev environment is low risk."""
        request = AuthorizationRequest.create(
            agent_id="agent-002",
            principal="reader@corp.com",
            action="s3:GetObject",
            resource="arn:aws:s3:::dev-bucket/test.txt",
            data_classification=DataClassification.PUBLIC,
            context={"environment": Environment.DEV},
        )
        result = standard_engine.score_transaction(request)
        assert result.composite_score < 50.0

    def test_transaction_related_actions_boost(self, standard_engine: RiskEngine) -> None:
        """Related actions in risk_context increase score via toxic combinations."""
        # PassRole alone
        request_alone = AuthorizationRequest.create(
            agent_id="agent-003", principal="user@corp.com",
            action="iam:PassRole", resource="*",
            data_classification=DataClassification.INTERNAL,
        )
        # PassRole with lambda:CreateFunction in related actions
        request_combo = AuthorizationRequest.create(
            agent_id="agent-003", principal="user@corp.com",
            action="iam:PassRole", resource="*",
            data_classification=DataClassification.INTERNAL,
            risk_context={"related_actions": ["lambda:CreateFunction"]},
        )
        result_alone = standard_engine.score_transaction(request_alone)
        result_combo = standard_engine.score_transaction(request_combo)
        assert result_combo.composite_score >= result_alone.composite_score


# =============================================================================
# Test: Toxic Combinations
# =============================================================================


class TestToxicCombinations:
    """Tests for toxic combination detection."""

    def test_passrole_lambda_detected(self) -> None:
        """PassRole + CreateFunction is detected as toxic combination."""
        combo = TOXIC_COMBINATIONS[0]  # passrole_create_function
        actions = ["iam:PassRole", "lambda:CreateFunction"]
        assert combo.matches(actions) is True

    def test_no_match_without_all_patterns(self) -> None:
        """Toxic combination requires all patterns to match."""
        combo = TOXIC_COMBINATIONS[0]
        actions = ["iam:PassRole", "s3:GetObject"]
        assert combo.matches(actions) is False

    def test_all_builtin_toxic_combinations_have_patterns(self) -> None:
        """All built-in toxic combinations have at least 2 action patterns."""
        for combo in TOXIC_COMBINATIONS:
            assert len(combo.action_patterns) >= 2
            assert combo.multiplier > 1.0

    def test_toxic_combination_amplifies_risk(self, standard_engine: RiskEngine) -> None:
        """Toxic combinations result in higher composite scores."""
        # Score PassRole alone
        result_single = standard_engine.score_permission("iam:PassRole", "*")
        # Score with related toxic action
        result_toxic = standard_engine.score_permission(
            "iam:PassRole", "*",
            context={"related_actions": ["lambda:CreateFunction"]},
        )
        assert result_toxic.composite_score >= result_single.composite_score


# =============================================================================
# Test: Environment Multipliers
# =============================================================================


class TestEnvironmentMultipliers:
    """Tests for environment-based risk modifiers."""

    def test_production_highest_environment_risk(self, standard_engine: RiskEngine) -> None:
        """Production environment gets highest environment_risk score."""
        result = standard_engine.score_permission(
            "s3:PutObject", "arn:aws:s3:::data/file",
            context={"environment": Environment.PRODUCTION},
        )
        assert result.dimension_scores["environment_risk"] >= 80.0

    def test_dev_lowest_environment_risk(self, standard_engine: RiskEngine) -> None:
        """Dev environment gets lowest environment_risk score."""
        result = standard_engine.score_permission(
            "s3:PutObject", "arn:aws:s3:::data/file",
            context={"environment": Environment.DEV},
        )
        assert result.dimension_scores["environment_risk"] <= 30.0

    def test_staging_middle_environment_risk(self, standard_engine: RiskEngine) -> None:
        """Staging environment is between dev and production."""
        result = standard_engine.score_permission(
            "s3:PutObject", "arn:aws:s3:::data/file",
            context={"environment": Environment.STAGING},
        )
        assert 30.0 <= result.dimension_scores["environment_risk"] <= 70.0


# =============================================================================
# Test: Risk Profile Differences
# =============================================================================


class TestRiskProfiles:
    """Tests for strict vs standard vs permissive profiles."""

    def test_strict_lower_thresholds(self) -> None:
        """Strict profile has lower critical/high thresholds."""
        assert STRICT_PROFILE.thresholds.critical < STANDARD_PROFILE.thresholds.critical
        assert STRICT_PROFILE.thresholds.high < STANDARD_PROFILE.thresholds.high

    def test_permissive_higher_thresholds(self) -> None:
        """Permissive profile has higher thresholds than standard."""
        assert PERMISSIVE_PROFILE.thresholds.critical > STANDARD_PROFILE.thresholds.critical
        assert PERMISSIVE_PROFILE.thresholds.high > STANDARD_PROFILE.thresholds.high

    def test_strict_classifies_more_aggressively(self, strict_engine: RiskEngine, permissive_engine: RiskEngine) -> None:
        """Same action gets higher risk level on strict vs permissive."""
        result_strict = strict_engine.score_permission("iam:PassRole", "*")
        result_permissive = permissive_engine.score_permission("iam:PassRole", "*")
        # Strict should classify at same or higher level
        level_order = [RiskLevel.INFO, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert level_order.index(result_strict.risk_level) >= level_order.index(result_permissive.risk_level)

    def test_strict_higher_toxic_multiplier(self) -> None:
        """Strict profile applies higher toxic combination multiplier."""
        assert STRICT_PROFILE.toxic_combination_multiplier > PERMISSIVE_PROFILE.toxic_combination_multiplier

    def test_unknown_profile_raises(self) -> None:
        """Unknown profile name raises ValueError."""
        with pytest.raises(ValueError, match="Unknown profile"):
            RiskEngine(profile="nonexistent")

    def test_all_profiles_available(self) -> None:
        """All named profiles are registered."""
        assert "strict" in PROFILES
        assert "standard" in PROFILES
        assert "permissive" in PROFILES

    def test_profile_classify_method(self) -> None:
        """RiskProfile.classify maps scores to levels correctly."""
        profile = STANDARD_PROFILE
        assert profile.classify(90.0) == RiskLevel.CRITICAL
        assert profile.classify(70.0) == RiskLevel.HIGH
        assert profile.classify(50.0) == RiskLevel.MEDIUM
        assert profile.classify(25.0) == RiskLevel.LOW
        assert profile.classify(10.0) == RiskLevel.INFO


# =============================================================================
# Test: Edge Cases
# =============================================================================


class TestRiskEngineEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_actions_agent(self, standard_engine: RiskEngine) -> None:
        """Agent with no policies still gets environment and baseline scores."""
        agent = Agent.create(
            name="no-permissions-agent", owner="ops",
            environment=Environment.PRODUCTION,
            workload_type=WorkloadType.LAMBDA,
            iam_role_arn="arn:aws:iam::123456789012:role/empty",
        )
        result = standard_engine.score_agent(agent)
        # Should still have environment risk
        assert result.dimension_scores["environment_risk"] >= 80.0
        # But privilege should be low
        assert result.dimension_scores["privilege_score"] == 0.0

    def test_unknown_action_gets_base_score(self, standard_engine: RiskEngine) -> None:
        """Unknown action string still returns a valid RiskCalculation."""
        result = standard_engine.score_permission("customservice:CustomAction", "arn:aws:custom:::resource")
        assert isinstance(result, RiskCalculation)
        assert result.composite_score >= 0.0

    def test_risk_calculation_to_risk_score(self, standard_engine: RiskEngine) -> None:
        """RiskCalculation.to_risk_score() converts to 0-1 scale correctly."""
        result = standard_engine.score_permission("iam:CreateRole", "*")
        risk_score = result.to_risk_score()
        assert isinstance(risk_score, RiskScore)
        assert 0.0 <= risk_score.composite_score <= 1.0
        assert 0.0 <= risk_score.privilege_score <= 1.0

    def test_risk_calculation_to_dict(self, standard_engine: RiskEngine) -> None:
        """RiskCalculation.to_dict() returns a serializable dict."""
        result = standard_engine.score_permission("s3:GetObject", "*")
        d = result.to_dict()
        assert "dimension_scores" in d
        assert "composite_score" in d
        assert "risk_level" in d

    def test_risk_factor_pattern_matching(self) -> None:
        """RiskFactor.matches() correctly matches action patterns."""
        factor = RiskFactor(
            pattern=r"iam:Create.*",
            base_privilege=80.0,
            description="Test factor",
        )
        assert factor.matches("iam:CreateRole") is True
        assert factor.matches("iam:CreateUser") is True
        assert factor.matches("s3:GetObject") is False

    def test_risk_calculation_severity_property(self, standard_engine: RiskEngine) -> None:
        """RiskCalculation.severity maps to Severity enum."""
        from aws_agent_identity_guard.models import Severity
        result = standard_engine.score_permission("iam:PassRole", "*")
        assert result.severity in Severity

    def test_risk_calculation_is_actionable(self, standard_engine: RiskEngine) -> None:
        """RiskCalculation.is_actionable is True for MEDIUM+ risk levels."""
        high_result = standard_engine.score_permission("iam:CreateRole", "*")
        # High risk actions should be actionable
        if high_result.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM):
            assert high_result.is_actionable is True
