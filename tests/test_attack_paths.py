"""
tests/test_attack_paths.py
---------------------------
Tests for the attack path analysis engine.

Covers role chaining detection, PassRole exploitation, data exfiltration,
credential theft, and path ranking by composite score.
"""

from __future__ import annotations

import pytest

from aws_agent_identity_guard.attack_paths import AttackPathAnalyzer
from aws_agent_identity_guard.models import (
    AgentIdentity,
    AgentType,
    DataClassification,
    EffectiveEffect,
    EffectivePermission,
    Environment,
)

# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def analyzer() -> AttackPathAnalyzer:
    """Return a fresh AttackPathAnalyzer."""
    return AttackPathAnalyzer()


@pytest.fixture
def base_agent() -> AgentIdentity:
    """Return a standard agent for analysis."""
    return AgentIdentity(
        agent_id="agent-paths",
        name="PathTestAgent",
        agent_type=AgentType.BEDROCK,
        owner="security-team",
        environment=Environment.PRODUCTION,
        data_classification=DataClassification.CONFIDENTIAL,
    )


def _perms(actions: list[str], resource: str = "*") -> list[EffectivePermission]:
    """Helper to create ALLOWED effective permissions."""
    return [
        EffectivePermission(
            action=action,
            resource=resource,
            effective_effect=EffectiveEffect.ALLOWED,
        )
        for action in actions
    ]


# ─── Role Chaining Detection ─────────────────────────────────────────────────


class TestRoleChaining:
    """Test detection of role assumption chains."""

    def test_assume_role_wildcard_detected(self, analyzer, base_agent):
        """sts:AssumeRole with wildcard resource is detected as critical path."""
        perms = _perms(["sts:AssumeRole"])
        paths = analyzer.analyze(base_agent, perms)
        assert len(paths) > 0
        # At least one path should involve role assumption
        assume_paths = [p for p in paths if any("AssumeRole" in s.action for s in p.steps)]
        assert len(assume_paths) > 0

    def test_assume_role_with_saml_detected(self, analyzer, base_agent):
        """sts:AssumeRoleWithSAML is treated as role chaining."""
        perms = _perms(["sts:AssumeRoleWithSAML"])
        paths = analyzer.analyze(base_agent, perms)
        assert len(paths) > 0

    def test_assume_role_with_web_identity_detected(self, analyzer, base_agent):
        """sts:AssumeRoleWithWebIdentity is treated as role chaining."""
        perms = _perms(["sts:AssumeRoleWithWebIdentity"])
        paths = analyzer.analyze(base_agent, perms)
        assert len(paths) > 0

    def test_no_assume_role_no_chaining_paths(self, analyzer, base_agent):
        """Without any AssumeRole variant, no role chaining paths are found."""
        perms = _perms(["s3:GetObject", "s3:PutObject"])
        paths = analyzer.analyze(base_agent, perms)
        assume_paths = [p for p in paths if any("AssumeRole" in s.action for s in p.steps)]
        assert len(assume_paths) == 0


# ─── PassRole Exploitation ───────────────────────────────────────────────────


class TestPassRoleExploitation:
    """Test detection of PassRole to compute service paths."""

    def test_passrole_with_lambda_create(self, analyzer, base_agent):
        """iam:PassRole + lambda:CreateFunction is a critical escalation path."""
        perms = _perms(["iam:PassRole", "lambda:CreateFunction"])
        paths = analyzer.analyze(base_agent, perms)
        assert len(paths) > 0
        # Should find a PassRole path
        passrole_paths = [p for p in paths if any("PassRole" in s.action for s in p.steps)]
        assert len(passrole_paths) > 0

    def test_passrole_alone_limited(self, analyzer, base_agent):
        """iam:PassRole alone without compute service has lower impact."""
        perms = _perms(["iam:PassRole"])
        paths = analyzer.analyze(base_agent, perms)
        # PassRole alone may not produce as many paths
        # but it can still be flagged for potential exploitation
        if paths:
            for path in paths:
                assert path.likelihood >= 0.0


# ─── Data Exfiltration Paths ─────────────────────────────────────────────────


class TestDataExfiltration:
    """Test detection of data exfiltration paths."""

    def test_s3_exfiltration_detected(self, analyzer, base_agent):
        """S3 read/list operations on wildcard are flagged for exfiltration."""
        perms = _perms(["s3:GetObject", "s3:ListBucket", "s3:GetBucketPolicy"])
        paths = analyzer.analyze(base_agent, perms)
        # Should detect data exfiltration paths
        exfil_paths = [p for p in paths if any("s3:" in s.action.lower() for s in p.steps)]
        assert len(exfil_paths) > 0

    def test_dynamodb_scan_exfiltration(self, analyzer, base_agent):
        """DynamoDB Scan with wildcard resource is a data exfiltration path."""
        perms = _perms(["dynamodb:Scan", "dynamodb:GetItem"])
        paths = analyzer.analyze(base_agent, perms)
        exfil_paths = [p for p in paths if any("dynamodb" in s.action.lower() for s in p.steps)]
        assert len(exfil_paths) > 0


# ─── Credential Theft Paths ──────────────────────────────────────────────────


class TestCredentialTheft:
    """Test detection of credential theft paths."""

    def test_secrets_manager_access_detected(self, analyzer, base_agent):
        """secretsmanager:GetSecretValue is flagged as credential theft path."""
        perms = _perms(["secretsmanager:GetSecretValue", "secretsmanager:ListSecrets"])
        paths = analyzer.analyze(base_agent, perms)
        cred_paths = [p for p in paths if any("secret" in s.action.lower() for s in p.steps)]
        assert len(cred_paths) > 0

    def test_ssm_parameter_access_detected(self, analyzer, base_agent):
        """ssm:GetParameter is flagged as potential credential theft."""
        perms = _perms(["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"])
        paths = analyzer.analyze(base_agent, perms)
        assert len(paths) > 0


# ─── Path Ranking ─────────────────────────────────────────────────────────────


class TestPathRanking:
    """Test that paths are ranked by composite score (highest first)."""

    def test_paths_sorted_descending_by_score(self, analyzer, base_agent):
        """Results are sorted by composite_score descending."""
        perms = _perms(
            [
                "sts:AssumeRole",
                "iam:PassRole",
                "lambda:CreateFunction",
                "s3:GetObject",
                "secretsmanager:GetSecretValue",
            ]
        )
        paths = analyzer.analyze(base_agent, perms)
        if len(paths) >= 2:
            for i in range(len(paths) - 1):
                assert paths[i].composite_score >= paths[i + 1].composite_score

    def test_empty_permissions_no_paths(self, analyzer, base_agent):
        """Agent with no effective permissions has no attack paths."""
        paths = analyzer.analyze(base_agent, [])
        assert paths == []

    def test_denied_permissions_excluded(self, analyzer, base_agent):
        """DENIED permissions are excluded from path analysis."""
        perms = [
            EffectivePermission(
                action="iam:PassRole",
                resource="*",
                effective_effect=EffectiveEffect.DENIED,
            ),
            EffectivePermission(
                action="lambda:CreateFunction",
                resource="*",
                effective_effect=EffectiveEffect.DENIED,
            ),
        ]
        paths = analyzer.analyze(base_agent, perms)
        assert paths == []

    def test_none_agent_raises(self, analyzer):
        """Passing None agent raises ValueError."""
        with pytest.raises(ValueError, match="agent cannot be None"):
            analyzer.analyze(None, [])

    def test_none_permissions_raises(self, analyzer, base_agent):
        """Passing None permissions raises ValueError."""
        with pytest.raises(ValueError, match="effective_permissions cannot be None"):
            analyzer.analyze(base_agent, None)
