"""
tests/test_risk_engine.py
-------------------------
Tests for the multidimensional risk scoring engine.

Covers score_agent, score_transaction, individual dimension scoring,
environment factor multipliers, and risk level thresholds.
"""

from __future__ import annotations

import pytest

from aws_agent_identity_guard.models import (
    AgentIdentity,
    AgentType,
    AttackPath,
    AttackStep,
    DataClassification,
    EffectiveEffect,
    EffectivePermission,
    Environment,
    RiskScore,
    TransactionRequest,
)
from aws_agent_identity_guard.risk_engine import (
    RiskEngine,
    RiskLevel,
    RiskWeights,
    classify_risk,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def engine() -> RiskEngine:
    """Return a default-configured RiskEngine."""
    return RiskEngine()


@pytest.fixture
def low_privilege_agent() -> AgentIdentity:
    """Agent with minimal access profile."""
    return AgentIdentity(
        agent_id="agent-low",
        name="LowPrivAgent",
        agent_type=AgentType.LAMBDA,
        owner="dev-team",
        environment=Environment.DEVELOPMENT,
        data_classification=DataClassification.PUBLIC,
    )


@pytest.fixture
def high_privilege_agent() -> AgentIdentity:
    """Agent in production with secret-level data access."""
    return AgentIdentity(
        agent_id="agent-high",
        name="HighPrivAgent",
        agent_type=AgentType.BEDROCK,
        owner="platform-team",
        environment=Environment.PRODUCTION,
        data_classification=DataClassification.SECRET,
    )


@pytest.fixture
def staging_agent() -> AgentIdentity:
    """Agent in staging environment."""
    return AgentIdentity(
        agent_id="agent-staging",
        name="StagingAgent",
        agent_type=AgentType.ECS,
        owner="qa-team",
        environment=Environment.STAGING,
        data_classification=DataClassification.INTERNAL,
    )


def _make_permissions(actions: list[str]) -> list[EffectivePermission]:
    """Helper to create ALLOWED effective permissions for given actions."""
    return [
        EffectivePermission(
            action=action,
            resource="*",
            effective_effect=EffectiveEffect.ALLOWED,
        )
        for action in actions
    ]


# ─── classify_risk Tests ──────────────────────────────────────────────────────


class TestClassifyRisk:
    """Test risk level classification thresholds."""

    def test_low_threshold(self):
        """Scores 0-25 are LOW."""
        assert classify_risk(0) == RiskLevel.LOW
        assert classify_risk(25) == RiskLevel.LOW

    def test_medium_threshold(self):
        """Scores 26-50 are MEDIUM."""
        assert classify_risk(26) == RiskLevel.MEDIUM
        assert classify_risk(50) == RiskLevel.MEDIUM

    def test_high_threshold(self):
        """Scores 51-75 are HIGH."""
        assert classify_risk(51) == RiskLevel.HIGH
        assert classify_risk(75) == RiskLevel.HIGH

    def test_critical_threshold(self):
        """Scores 76-100 are CRITICAL."""
        assert classify_risk(76) == RiskLevel.CRITICAL
        assert classify_risk(100) == RiskLevel.CRITICAL


# ─── score_agent Tests ────────────────────────────────────────────────────────


class TestScoreAgent:
    """Test score_agent with various permission sets."""

    def test_no_permissions_zero_score(self, engine, low_privilege_agent):
        """Agent with zero effective permissions has low risk."""
        result = engine.score_agent(low_privilege_agent, [], [])
        assert result.overall <= 25

    def test_wildcard_admin_max_privilege(self, engine, high_privilege_agent):
        """Agent with iam:* on * has maximum privilege dimension score."""
        perms = _make_permissions(["iam:*"])
        result = engine.score_agent(high_privilege_agent, perms, [])
        assert result.privilege == 100

    def test_critical_actions_raise_privilege_score(self, engine, high_privilege_agent):
        """Multiple critical IAM actions produce high privilege score."""
        perms = _make_permissions([
            "iam:CreatePolicyVersion",
            "iam:AttachRolePolicy",
            "iam:PassRole",
            "sts:AssumeRole",
        ])
        result = engine.score_agent(high_privilege_agent, perms, [])
        assert result.privilege >= 50

    def test_data_exposure_actions_scored(self, engine, low_privilege_agent):
        """S3 and DynamoDB scan actions increase data_exposure dimension."""
        perms = _make_permissions([
            "s3:GetObject",
            "s3:ListBucket",
            "dynamodb:Scan",
            "logs:GetLogEvents",
        ])
        result = engine.score_agent(low_privilege_agent, perms, [])
        assert result.data_exposure > 0

    def test_persistence_actions_scored(self, engine, low_privilege_agent):
        """IAM and event-based persistence actions increase persistence score."""
        perms = _make_permissions([
            "iam:CreateRole",
            "iam:CreateUser",
            "iam:CreateAccessKey",
            "events:PutRule",
        ])
        result = engine.score_agent(low_privilege_agent, perms, [])
        assert result.persistence > 0

    def test_attack_paths_increase_lateral_movement(self, engine, low_privilege_agent):
        """Known attack paths boost the lateral_movement dimension."""
        perms = _make_permissions(["sts:AssumeRole"])
        paths = [
            AttackPath(
                steps=[AttackStep(action="sts:AssumeRole", resource="*")],
                likelihood=0.9,
                impact=0.8,
            )
        ]
        result_with_paths = engine.score_agent(low_privilege_agent, perms, paths)
        result_without = engine.score_agent(low_privilege_agent, perms, [])
        assert result_with_paths.lateral_movement >= result_without.lateral_movement

    def test_none_agent_raises_value_error(self, engine):
        """Passing None agent raises ValueError."""
        with pytest.raises(ValueError, match="agent cannot be None"):
            engine.score_agent(None, [], [])

    def test_none_permissions_raises_value_error(self, engine, low_privilege_agent):
        """Passing None permissions raises ValueError."""
        with pytest.raises(ValueError, match="effective_permissions cannot be None"):
            engine.score_agent(low_privilege_agent, None, [])


# ─── score_transaction Tests ──────────────────────────────────────────────────


class TestScoreTransaction:
    """Test score_transaction for individual action evaluation."""

    def test_benign_read_action_low_risk(self, engine, low_privilege_agent):
        """A simple S3 read on public data has low risk."""
        tx = TransactionRequest(
            agent_id="agent-low",
            principal="arn:aws:iam::123456789012:role/ReadOnly",
            tool="s3-reader",
            action="s3:GetObject",
            resource="arn:aws:s3:::public-bucket/readme.txt",
            data_classification=DataClassification.PUBLIC,
        )
        result = engine.score_transaction(tx, low_privilege_agent, [])
        assert result.overall <= 50

    def test_dangerous_iam_action_high_risk(self, engine, high_privilege_agent):
        """iam:CreatePolicyVersion in production scores high."""
        tx = TransactionRequest(
            agent_id="agent-high",
            principal="arn:aws:iam::123456789012:role/Admin",
            tool="policy-manager",
            action="iam:CreatePolicyVersion",
            resource="*",
            data_classification=DataClassification.SECRET,
        )
        result = engine.score_transaction(tx, high_privilege_agent, [])
        assert result.overall >= 50

    def test_transaction_none_raises(self, engine, low_privilege_agent):
        """Passing None transaction raises ValueError."""
        with pytest.raises(ValueError, match="transaction cannot be None"):
            engine.score_transaction(None, low_privilege_agent, [])


# ─── Environment Factor Tests ─────────────────────────────────────────────────


class TestEnvironmentFactor:
    """Test that environment multiplier is correctly applied."""

    def test_production_factor_higher(self, engine, high_privilege_agent, low_privilege_agent):
        """Production environment produces higher overall score than dev for same perms."""
        perms = _make_permissions(["s3:GetObject", "s3:PutObject"])
        prod_result = engine.score_agent(high_privilege_agent, perms, [])
        dev_result = engine.score_agent(low_privilege_agent, perms, [])
        # Production should have higher overall due to 1.5 vs 0.8 factor
        assert prod_result.environment_factor == 1.5
        assert dev_result.environment_factor == 0.8
        assert prod_result.overall >= dev_result.overall

    def test_staging_factor_intermediate(self, engine, staging_agent):
        """Staging environment gets factor 1.2."""
        perms = _make_permissions(["s3:GetObject"])
        result = engine.score_agent(staging_agent, perms, [])
        assert result.environment_factor == 1.2


# ─── RiskWeights Tests ────────────────────────────────────────────────────────


class TestRiskWeights:
    """Test custom risk weight configuration."""

    def test_default_weights_normalize_to_one(self):
        """Default weights normalize to sum of 1.0."""
        weights = RiskWeights()
        normalized = weights.normalized()
        total = sum(normalized.values())
        assert total == pytest.approx(1.0, abs=1e-9)

    def test_zero_weights_raise_error(self):
        """All-zero weights raise ValueError on normalization."""
        weights = RiskWeights(
            privilege=0, sensitivity=0, blast_radius=0,
            data_exposure=0, persistence=0, lateral_movement=0,
        )
        with pytest.raises(ValueError, match="Total weight cannot be zero"):
            weights.normalized()

    def test_custom_weights_applied(self, low_privilege_agent):
        """Custom weights change the relative scoring."""
        perms = _make_permissions(["iam:PassRole", "iam:CreateRole"])
        # Heavy privilege weight
        engine_heavy_priv = RiskEngine(
            weights=RiskWeights(privilege=0.9, sensitivity=0.02, blast_radius=0.02,
                               data_exposure=0.02, persistence=0.02, lateral_movement=0.02)
        )
        # Heavy persistence weight
        engine_heavy_pers = RiskEngine(
            weights=RiskWeights(privilege=0.02, sensitivity=0.02, blast_radius=0.02,
                               data_exposure=0.02, persistence=0.9, lateral_movement=0.02)
        )
        r1 = engine_heavy_priv.score_agent(low_privilege_agent, perms, [])
        r2 = engine_heavy_pers.score_agent(low_privilege_agent, perms, [])
        # Different weighting should produce different overall scores
        assert r1.overall != r2.overall
