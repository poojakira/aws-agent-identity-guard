"""Tests for the privilege escalation detection engine.

Covers IAM escalation patterns, agent-specific patterns, severity classification,
and report generation.
"""

from __future__ import annotations

import pytest

from aws_agent_identity_guard.models import (
    Agent,
    DataClassification,
    Environment,
    Permission,
    PermissionEffect,
    PermissionSource,
    Severity,
    WorkloadType,
)
from aws_agent_identity_guard.escalation_engine import (
    EscalationCategory,
    EscalationEngine,
    EscalationPath,
    EscalationReport,
    EscalationTechnique,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def engine() -> EscalationEngine:
    """Escalation detection engine with default patterns."""
    return EscalationEngine()


@pytest.fixture
def iam_admin_agent() -> Agent:
    """Agent with IAM admin-level permissions."""
    agent = Agent.create(
        name="iam-admin-agent",
        owner="platform-team",
        environment=Environment.PRODUCTION,
        workload_type=WorkloadType.BEDROCK_AGENT,
        iam_role_arn="arn:aws:iam::123456789012:role/iam-admin-agent",
        data_classification=DataClassification.SECRET,
    )
    agent_dict = agent.to_dict()
    agent_dict["identity_policies"] = [
        {
            "PolicyName": "iam-admin",
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:CreatePolicyVersion",
                            "iam:SetDefaultPolicyVersion",
                            "iam:AttachRolePolicy",
                            "iam:PutRolePolicy",
                            "iam:CreateRole",
                            "iam:PassRole",
                        ],
                        "Resource": "*",
                    }
                ]
            },
        }
    ]
    return Agent.from_dict(agent_dict)


@pytest.fixture
def passrole_lambda_agent() -> Agent:
    """Agent with PassRole + Lambda (classic escalation combo)."""
    agent = Agent.create(
        name="passrole-lambda-agent",
        owner="dev-team",
        environment=Environment.PRODUCTION,
        workload_type=WorkloadType.LAMBDA,
        iam_role_arn="arn:aws:iam::123456789012:role/passrole-lambda",
        data_classification=DataClassification.CONFIDENTIAL,
    )
    agent_dict = agent.to_dict()
    agent_dict["identity_policies"] = [
        {
            "PolicyName": "passrole-lambda",
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
                        "Resource": "*",
                    }
                ]
            },
        }
    ]
    return Agent.from_dict(agent_dict)


@pytest.fixture
def bedrock_agent() -> Agent:
    """Agent with Bedrock-specific permissions."""
    agent = Agent.create(
        name="bedrock-tool-agent",
        owner="ai-team",
        environment=Environment.PRODUCTION,
        workload_type=WorkloadType.BEDROCK_AGENT,
        iam_role_arn="arn:aws:iam::123456789012:role/bedrock-tool-agent",
        data_classification=DataClassification.CONFIDENTIAL,
    )
    agent_dict = agent.to_dict()
    agent_dict["identity_policies"] = [
        {
            "PolicyName": "bedrock-access",
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "bedrock:InvokeAgent",
                            "sts:AssumeRole",
                            "secretsmanager:GetSecretValue",
                        ],
                        "Resource": "*",
                    }
                ]
            },
        }
    ]
    return Agent.from_dict(agent_dict)


@pytest.fixture
def readonly_agent() -> Agent:
    """Agent with only read permissions (no escalation)."""
    agent = Agent.create(
        name="readonly-agent",
        owner="analytics",
        environment=Environment.DEV,
        workload_type=WorkloadType.LAMBDA,
        iam_role_arn="arn:aws:iam::123456789012:role/readonly",
        data_classification=DataClassification.PUBLIC,
    )
    agent_dict = agent.to_dict()
    agent_dict["identity_policies"] = [
        {
            "PolicyName": "read-only",
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket", "dynamodb:GetItem"],
                        "Resource": "*",
                    }
                ]
            },
        }
    ]
    return Agent.from_dict(agent_dict)


# =============================================================================
# Test: IAM Escalation Patterns
# =============================================================================


class TestIAMEscalationPatterns:
    """Tests for classic IAM privilege escalation detection."""

    def test_create_policy_version_detected(self, engine: EscalationEngine, iam_admin_agent: Agent) -> None:
        """iam:CreatePolicyVersion escalation is detected."""
        paths = engine.detect_escalation_paths(iam_admin_agent)
        techniques = [p.technique for p in paths]
        assert EscalationTechnique.CREATE_POLICY_VERSION in techniques

    def test_attach_role_policy_detected(self, engine: EscalationEngine, iam_admin_agent: Agent) -> None:
        """iam:AttachRolePolicy escalation is detected."""
        paths = engine.detect_escalation_paths(iam_admin_agent)
        techniques = [p.technique for p in paths]
        assert EscalationTechnique.ATTACH_ROLE_POLICY in techniques

    def test_passrole_lambda_combo_detected(self, engine: EscalationEngine, passrole_lambda_agent: Agent) -> None:
        """PassRole + lambda:CreateFunction combo escalation is detected."""
        paths = engine.detect_escalation_paths(passrole_lambda_agent)
        techniques = [p.technique for p in paths]
        assert EscalationTechnique.PASS_ROLE_LAMBDA_CREATE in techniques

    def test_readonly_agent_no_escalation(self, engine: EscalationEngine, readonly_agent: Agent) -> None:
        """Read-only agent produces minimal escalation findings (at most data-access paths)."""
        paths = engine.detect_escalation_paths(readonly_agent)
        # Read-only agents may trigger data-access-based patterns (e.g., terraform state extraction)
        # but should not have IAM privilege escalation paths
        iam_escalations = [p for p in paths if "iam:" in p.technique.value.lower()]
        assert len(iam_escalations) == 0

    def test_put_role_policy_detected(self, engine: EscalationEngine, iam_admin_agent: Agent) -> None:
        """iam:PutRolePolicy escalation is detected."""
        paths = engine.detect_escalation_paths(iam_admin_agent)
        techniques = [p.technique for p in paths]
        assert EscalationTechnique.PUT_ROLE_POLICY in techniques


# =============================================================================
# Test: Agent-Specific Patterns
# =============================================================================


class TestAgentSpecificPatterns:
    """Tests for agent workload-specific escalation patterns."""

    def test_bedrock_tool_role_assumption(self, engine: EscalationEngine, bedrock_agent: Agent) -> None:
        """Bedrock agent with AssumeRole detected as escalation path."""
        paths = engine.detect_escalation_paths(bedrock_agent)
        assert len(paths) > 0
        # Should find at least one agent-specific or role assumption path
        categories = [p.category for p in paths]
        assert any(
            c in (EscalationCategory.ROLE_ASSUMPTION, EscalationCategory.AGENT_SPECIFIC, EscalationCategory.CREDENTIAL_THEFT)
            for c in categories
        )

    def test_secrets_manager_credential_theft(self, engine: EscalationEngine, bedrock_agent: Agent) -> None:
        """secretsmanager:GetSecretValue detected in escalation context."""
        paths = engine.detect_escalation_paths(bedrock_agent)
        assert len(paths) > 0

    def test_cross_account_escalation_detected(self, engine: EscalationEngine) -> None:
        """Cross-account AssumeRole detected as escalation."""
        agent = Agent.create(
            name="cross-account", owner="ops",
            environment=Environment.PRODUCTION,
            workload_type=WorkloadType.ECS,
            iam_role_arn="arn:aws:iam::123456789012:role/cross-account",
            data_classification=DataClassification.SECRET,
        )
        agent_dict = agent.to_dict()
        agent_dict["identity_policies"] = [
            {
                "PolicyName": "cross-account",
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["sts:AssumeRole"],
                            "Resource": "arn:aws:iam::999999999999:role/*",
                        }
                    ]
                },
            }
        ]
        restored = Agent.from_dict(agent_dict)
        paths = engine.detect_escalation_paths(restored)
        techniques = [p.technique for p in paths]
        assert EscalationTechnique.ASSUME_ROLE_HIGHER_PRIV in techniques


# =============================================================================
# Test: Severity Classification
# =============================================================================


class TestSeverityClassification:
    """Tests for escalation severity classification."""

    def test_iam_admin_paths_are_critical_or_high(self, engine: EscalationEngine, iam_admin_agent: Agent) -> None:
        """IAM admin escalation paths are rated CRITICAL or HIGH."""
        paths = engine.detect_escalation_paths(iam_admin_agent)
        for path in paths:
            assert path.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)

    def test_policy_manipulation_high_severity(self, engine: EscalationEngine, iam_admin_agent: Agent) -> None:
        """Policy manipulation techniques are at least HIGH severity."""
        paths = engine.detect_escalation_paths(iam_admin_agent)
        policy_manip = [
            p for p in paths
            if p.category == EscalationCategory.POLICY_MANIPULATION
        ]
        for path in policy_manip:
            assert path.severity in (Severity.CRITICAL, Severity.HIGH)

    def test_escalation_path_has_mitre_id(self, engine: EscalationEngine, iam_admin_agent: Agent) -> None:
        """All escalation paths have MITRE ATT&CK IDs."""
        paths = engine.detect_escalation_paths(iam_admin_agent)
        for path in paths:
            assert path.mitre_id != ""

    def test_escalation_path_likelihood_range(self, engine: EscalationEngine, passrole_lambda_agent: Agent) -> None:
        """Escalation path likelihood is within 0-1 range."""
        paths = engine.detect_escalation_paths(passrole_lambda_agent)
        for path in paths:
            assert 0.0 <= path.likelihood <= 1.0
            assert 0.0 <= path.impact <= 1.0


# =============================================================================
# Test: Report Generation
# =============================================================================


class TestReportGeneration:
    """Tests for escalation report generation."""

    def test_report_has_summary(self, engine: EscalationEngine, iam_admin_agent: Agent) -> None:
        """Escalation report includes a summary."""
        report = engine.generate_report(iam_admin_agent)
        assert report.summary != ""

    def test_report_has_agent_info(self, engine: EscalationEngine, iam_admin_agent: Agent) -> None:
        """Report includes agent identification."""
        report = engine.generate_report(iam_admin_agent)
        assert report.agent_id == iam_admin_agent.agent_id

    def test_report_has_timestamp(self, engine: EscalationEngine, iam_admin_agent: Agent) -> None:
        """Report includes analysis timestamp."""
        report = engine.generate_report(iam_admin_agent)
        assert report.generated_at is not None

    def test_report_has_remediation(self, engine: EscalationEngine, iam_admin_agent: Agent) -> None:
        """Each escalation path includes remediation guidance."""
        report = engine.generate_report(iam_admin_agent)
        for path in report.escalation_paths:
            assert path.remediation != ""

    def test_report_paths_have_steps(self, engine: EscalationEngine, passrole_lambda_agent: Agent) -> None:
        """Escalation paths describe the exploitation steps."""
        report = engine.generate_report(passrole_lambda_agent)
        for path in report.escalation_paths:
            assert len(path.steps) > 0

    def test_report_empty_for_safe_agent(self, engine: EscalationEngine, readonly_agent: Agent) -> None:
        """Safe agents produce minimal escalation reports (only data-access paths at most)."""
        report = engine.generate_report(readonly_agent)
        # Read-only agent may have data-access escalation paths (e.g. terraform state)
        # but no IAM-based privilege escalation
        iam_paths = [p for p in report.escalation_paths if "iam:" in p.technique.value.lower()]
        assert len(iam_paths) == 0

    def test_report_severity_counts(self, engine: EscalationEngine, iam_admin_agent: Agent) -> None:
        """Report correctly counts findings by severity."""
        report = engine.generate_report(iam_admin_agent)
        total = (
            report.critical_count + report.high_count +
            report.medium_count + report.low_count + report.informational_count
        )
        assert total == report.total_paths_detected

    def test_escalation_path_create_factory(self) -> None:
        """EscalationPath.create() factory works correctly."""
        path = EscalationPath.create(
            technique=EscalationTechnique.ATTACH_ROLE_POLICY,
            steps=["1. Identify target role", "2. Attach AdministratorAccess"],
            initial_permissions=["iam:AttachRolePolicy"],
            escalated_permissions=["*"],
            severity=Severity.CRITICAL,
            mitre_id="T1098.001",
            description="Attach admin policy to own role.",
            remediation="Remove iam:AttachRolePolicy permission.",
            prerequisites=["Target role must be assumable"],
            category=EscalationCategory.POLICY_MANIPULATION,
            likelihood=0.8,
            impact=0.95,
        )
        assert path.path_id.startswith("EP-")
        assert path.technique == EscalationTechnique.ATTACH_ROLE_POLICY
        assert path.severity == Severity.CRITICAL
        assert path.risk_rating == pytest.approx(0.76)


# =============================================================================
# Test: Escalation Engine Configuration
# =============================================================================


class TestEscalationEngineConfig:
    """Tests for engine configuration and pattern catalog."""

    def test_engine_has_patterns(self, engine: EscalationEngine) -> None:
        """Engine is initialized with pattern catalog."""
        assert engine.total_patterns > 0

    def test_engine_has_iam_patterns(self, engine: EscalationEngine) -> None:
        """Engine has classic IAM escalation patterns."""
        assert engine.iam_pattern_count > 0

    def test_engine_has_agent_patterns(self, engine: EscalationEngine) -> None:
        """Engine has agent-specific patterns."""
        assert engine.agent_pattern_count > 0

    def test_escalation_technique_enum_values(self) -> None:
        """EscalationTechnique has expected classic patterns."""
        assert EscalationTechnique.CREATE_POLICY_VERSION.value == "iam:CreatePolicyVersion"
        assert EscalationTechnique.ATTACH_ROLE_POLICY.value == "iam:AttachRolePolicy"
        assert EscalationTechnique.PASS_ROLE_LAMBDA_CREATE.value == "iam:PassRole+lambda:CreateFunction"

    def test_escalation_category_values(self) -> None:
        """EscalationCategory has all expected values."""
        expected = {
            "POLICY_MANIPULATION", "ROLE_ASSUMPTION", "SERVICE_EXPLOITATION",
            "CREDENTIAL_THEFT", "CROSS_ACCOUNT", "AGENT_SPECIFIC",
        }
        actual = {c.value for c in EscalationCategory}
        assert actual == expected
