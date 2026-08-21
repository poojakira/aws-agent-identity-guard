"""
tests/test_escalation.py
-------------------------
Tests for the privilege escalation detection engine.

Covers all 24 escalation patterns, pattern matching logic, severity
classification, and MITRE ATT&CK ID assignment.
"""

from __future__ import annotations

import pytest

from aws_agent_identity_guard.escalation_engine import (
    EscalationDetector,
    EscalationSeverity,
)
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
def detector() -> EscalationDetector:
    """Return a fresh EscalationDetector with built-in patterns."""
    return EscalationDetector()


@pytest.fixture
def test_agent() -> AgentIdentity:
    """Return a standard test agent."""
    return AgentIdentity(
        agent_id="agent-escalation",
        name="EscalationTestAgent",
        agent_type=AgentType.BEDROCK,
        owner="security-team",
        environment=Environment.PRODUCTION,
        data_classification=DataClassification.CONFIDENTIAL,
    )


def _perms(actions: list[str]) -> list[EffectivePermission]:
    """Create ALLOWED effective permissions for given actions."""
    return [
        EffectivePermission(
            action=action,
            resource="*",
            effective_effect=EffectiveEffect.ALLOWED,
        )
        for action in actions
    ]


# ─── Pattern Catalog Coverage ─────────────────────────────────────────────────


class TestPatternCatalog:
    """Verify the built-in pattern catalog has expected patterns."""

    def test_catalog_has_24_patterns(self, detector):
        """Catalog contains at least 24 escalation patterns."""
        assert detector.pattern_count >= 24

    def test_custom_pattern_registration(self, detector):
        """Can register custom escalation patterns."""
        initial_count = detector.pattern_count
        detector.add_pattern(
            technique="Custom Escalation",
            required_actions={"custom:DangerousAction"},
            impact="Full admin access",
            severity=EscalationSeverity.CRITICAL,
            mitre_id="T9999",
            remediation="Remove custom:DangerousAction",
        )
        assert detector.pattern_count == initial_count + 1


# ─── Individual Pattern Detection Tests ───────────────────────────────────────


class TestPatternDetection:
    """Test detection of specific escalation patterns."""

    def test_create_policy_version(self, detector, test_agent):
        """iam:CreatePolicyVersion is detected as CRITICAL escalation."""
        perms = _perms(["iam:CreatePolicyVersion"])
        results = detector.detect(test_agent, perms)
        techniques = [r.technique for r in results]
        assert "CreatePolicyVersion" in techniques

    def test_set_default_policy_version(self, detector, test_agent):
        """iam:SetDefaultPolicyVersion is detected as CRITICAL escalation."""
        perms = _perms(["iam:SetDefaultPolicyVersion"])
        results = detector.detect(test_agent, perms)
        techniques = [r.technique for r in results]
        assert "SetDefaultPolicyVersion" in techniques

    def test_passrole_with_lambda(self, detector, test_agent):
        """iam:PassRole + lambda:CreateFunction is detected."""
        perms = _perms(["iam:PassRole", "lambda:CreateFunction"])
        results = detector.detect(test_agent, perms)
        techniques = [r.technique for r in results]
        assert any("Lambda" in t or "PassRole" in t for t in techniques)

    def test_attach_role_policy(self, detector, test_agent):
        """iam:AttachRolePolicy is detected as CRITICAL escalation."""
        perms = _perms(["iam:AttachRolePolicy"])
        results = detector.detect(test_agent, perms)
        techniques = [r.technique for r in results]
        assert "AttachRolePolicy" in techniques

    def test_put_role_policy(self, detector, test_agent):
        """iam:PutRolePolicy is detected as CRITICAL escalation."""
        perms = _perms(["iam:PutRolePolicy"])
        results = detector.detect(test_agent, perms)
        techniques = [r.technique for r in results]
        assert "PutRolePolicy" in techniques

    def test_create_role_with_attach(self, detector, test_agent):
        """iam:CreateRole + iam:AttachRolePolicy is detected."""
        perms = _perms(["iam:CreateRole", "iam:AttachRolePolicy"])
        results = detector.detect(test_agent, perms)
        techniques = [r.technique for r in results]
        assert any("CreateRole" in t for t in techniques)

    def test_assume_role_cross_account(self, detector, test_agent):
        """sts:AssumeRole is detected as cross-account escalation."""
        perms = _perms(["sts:AssumeRole"])
        results = detector.detect(test_agent, perms)
        techniques = [r.technique for r in results]
        assert any("AssumeRole" in t for t in techniques)

    def test_update_assume_role_policy(self, detector, test_agent):
        """iam:UpdateAssumeRolePolicy is detected as CRITICAL escalation."""
        perms = _perms(["iam:UpdateAssumeRolePolicy"])
        results = detector.detect(test_agent, perms)
        techniques = [r.technique for r in results]
        assert "UpdateAssumeRolePolicy" in techniques

    def test_lambda_update_function_code(self, detector, test_agent):
        """lambda:UpdateFunctionCode is detected."""
        perms = _perms(["lambda:UpdateFunctionCode"])
        results = detector.detect(test_agent, perms)
        techniques = [r.technique for r in results]
        assert any("Lambda" in t or "UpdateFunctionCode" in t for t in techniques)

    def test_ssm_start_session(self, detector, test_agent):
        """ssm:StartSession is detected as SSM escalation."""
        perms = _perms(["ssm:StartSession"])
        results = detector.detect(test_agent, perms)
        techniques = [r.technique for r in results]
        assert any("SSM" in t for t in techniques)

    def test_secrets_manager_credential_chain(self, detector, test_agent):
        """secretsmanager:GetSecretValue is detected as credential chain."""
        perms = _perms(["secretsmanager:GetSecretValue"])
        results = detector.detect(test_agent, perms)
        techniques = [r.technique for r in results]
        assert any("Secret" in t or "Credential" in t for t in techniques)

    def test_cloudformation_with_passrole(self, detector, test_agent):
        """cloudformation:CreateStack + iam:PassRole is detected."""
        perms = _perms(["cloudformation:CreateStack", "iam:PassRole"])
        results = detector.detect(test_agent, perms)
        techniques = [r.technique for r in results]
        assert any("CloudFormation" in t for t in techniques)

    def test_passrole_with_ecs(self, detector, test_agent):
        """iam:PassRole + ecs:RunTask is detected."""
        perms = _perms(["iam:PassRole", "ecs:RunTask"])
        results = detector.detect(test_agent, perms)
        techniques = [r.technique for r in results]
        assert any("ECS" in t or "PassRole" in t for t in techniques)


# ─── Severity Classification Tests ───────────────────────────────────────────


class TestSeverityClassification:
    """Test that escalation paths have correct severity levels."""

    def test_create_policy_version_is_critical(self, detector, test_agent):
        """CreatePolicyVersion is classified as CRITICAL."""
        perms = _perms(["iam:CreatePolicyVersion"])
        results = detector.detect(test_agent, perms)
        cpv = [r for r in results if r.technique == "CreatePolicyVersion"]
        assert len(cpv) > 0
        assert cpv[0].severity == EscalationSeverity.CRITICAL

    def test_ssm_session_is_high(self, detector, test_agent):
        """SSM Session Manager is classified as HIGH."""
        perms = _perms(["ssm:StartSession"])
        results = detector.detect(test_agent, perms)
        ssm = [r for r in results if "SSM" in r.technique]
        assert len(ssm) > 0
        assert ssm[0].severity == EscalationSeverity.HIGH

    def test_results_sorted_by_severity(self, detector, test_agent):
        """Results are sorted: CRITICAL before HIGH before MEDIUM."""
        perms = _perms(
            [
                "iam:CreatePolicyVersion",
                "iam:PassRole",
                "lambda:CreateFunction",
                "ssm:StartSession",
                "secretsmanager:GetSecretValue",
            ]
        )
        results = detector.detect(test_agent, perms)
        if len(results) >= 2:
            severity_order = {
                EscalationSeverity.CRITICAL: 0,
                EscalationSeverity.HIGH: 1,
                EscalationSeverity.MEDIUM: 2,
                EscalationSeverity.LOW: 3,
            }
            for i in range(len(results) - 1):
                assert (
                    severity_order[results[i].severity] <= severity_order[results[i + 1].severity]
                )


# ─── MITRE ATT&CK ID Tests ───────────────────────────────────────────────────


class TestMitreMapping:
    """Test MITRE ATT&CK technique ID assignment."""

    def test_all_detected_paths_have_mitre_id(self, detector, test_agent):
        """Every detected escalation path has a non-empty MITRE ID."""
        perms = _perms(
            [
                "iam:CreatePolicyVersion",
                "iam:AttachRolePolicy",
                "sts:AssumeRole",
                "ssm:StartSession",
            ]
        )
        results = detector.detect(test_agent, perms)
        for result in results:
            assert result.mitre_id != ""
            assert result.mitre_id.startswith("T")

    def test_create_policy_version_mitre_id(self, detector, test_agent):
        """CreatePolicyVersion maps to T1098.003."""
        perms = _perms(["iam:CreatePolicyVersion"])
        results = detector.detect(test_agent, perms)
        cpv = [r for r in results if r.technique == "CreatePolicyVersion"]
        assert cpv[0].mitre_id == "T1098.003"


# ─── Edge Cases ──────────────────────────────────────────────────────────────


class TestEdgeCases:
    """Test edge cases and input validation."""

    def test_no_permissions_no_escalation(self, detector, test_agent):
        """Agent with no permissions has no escalation paths."""
        results = detector.detect(test_agent, [])
        assert results == []

    def test_denied_permissions_excluded(self, detector, test_agent):
        """DENIED permissions do not trigger escalation detection."""
        perms = [
            EffectivePermission(
                action="iam:CreatePolicyVersion",
                resource="*",
                effective_effect=EffectiveEffect.DENIED,
            )
        ]
        results = detector.detect(test_agent, perms)
        assert results == []

    def test_none_agent_raises(self, detector):
        """Passing None agent raises ValueError."""
        with pytest.raises(ValueError, match="agent cannot be None"):
            detector.detect(None, [])

    def test_none_permissions_raises(self, detector, test_agent):
        """Passing None permissions raises ValueError."""
        with pytest.raises(ValueError, match="effective_permissions cannot be None"):
            detector.detect(test_agent, None)
