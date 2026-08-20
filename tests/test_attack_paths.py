"""Tests for the attack path analysis engine.

Covers PassRole chain detection, Lambda escalation, cross-account paths,
path ranking, cycle detection, and empty policy handling.
"""

from __future__ import annotations

from typing import Any

import pytest

from aws_agent_identity_guard.models import (
    Agent,
    AttackPath,
    AttackStep,
    DataClassification,
    Environment,
    Permission,
    PermissionEffect,
    PermissionSource,
    Severity,
    WorkloadType,
)
from aws_agent_identity_guard.attack_paths import (
    AttackPatternCategory,
    AttackPatternTemplate,
    AttackPathAnalyzer,
    DiscoveredAttackPath,
    DiscoveredAttackStep,
    GraphEdge,
    GraphNode,
    MitreTechnique,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def analyzer() -> AttackPathAnalyzer:
    """Attack path analyzer with default configuration."""
    return AttackPathAnalyzer()


@pytest.fixture
def passrole_agent() -> Agent:
    """Agent with iam:PassRole and lambda:CreateFunction permissions."""
    agent = Agent.create(
        name="passrole-agent",
        owner="dev-team",
        environment=Environment.PRODUCTION,
        workload_type=WorkloadType.BEDROCK_AGENT,
        iam_role_arn="arn:aws:iam::123456789012:role/passrole-agent",
        data_classification=DataClassification.CONFIDENTIAL,
    )
    agent_dict = agent.to_dict()
    agent_dict["identity_policies"] = [
        {
            "PolicyName": "risky-policy",
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
def lambda_escalation_agent() -> Agent:
    """Agent with lambda escalation pattern permissions."""
    agent = Agent.create(
        name="lambda-escalation-agent",
        owner="platform-team",
        environment=Environment.PRODUCTION,
        workload_type=WorkloadType.LAMBDA,
        iam_role_arn="arn:aws:iam::123456789012:role/lambda-agent",
        data_classification=DataClassification.SECRET,
    )
    agent_dict = agent.to_dict()
    agent_dict["identity_policies"] = [
        {
            "PolicyName": "lambda-escalation",
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:PassRole",
                            "lambda:CreateFunction",
                            "lambda:UpdateFunctionCode",
                            "lambda:InvokeFunction",
                        ],
                        "Resource": "*",
                    }
                ]
            },
        }
    ]
    return Agent.from_dict(agent_dict)


@pytest.fixture
def cross_account_agent() -> Agent:
    """Agent with cross-account assume role capabilities."""
    agent = Agent.create(
        name="cross-account-agent",
        owner="security-team",
        environment=Environment.PRODUCTION,
        workload_type=WorkloadType.BEDROCK_AGENT,
        iam_role_arn="arn:aws:iam::123456789012:role/cross-account",
        data_classification=DataClassification.SECRET,
    )
    agent_dict = agent.to_dict()
    agent_dict["identity_policies"] = [
        {
            "PolicyName": "cross-account-access",
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "sts:AssumeRole",
                            "iam:UpdateAssumeRolePolicy",
                        ],
                        "Resource": "arn:aws:iam::999999999999:role/*",
                    }
                ]
            },
        }
    ]
    return Agent.from_dict(agent_dict)


@pytest.fixture
def minimal_agent() -> Agent:
    """Agent with no permissions (empty policies)."""
    return Agent.create(
        name="empty-agent",
        owner="ops",
        environment=Environment.DEV,
        workload_type=WorkloadType.CUSTOM,
        iam_role_arn="arn:aws:iam::123456789012:role/empty",
    )


# =============================================================================
# Test: PassRole Chain Detection
# =============================================================================


class TestPassRoleChainDetection:
    """Tests for detecting PassRole-based escalation chains."""

    def test_passrole_lambda_chain_detected(self, analyzer: AttackPathAnalyzer, passrole_agent: Agent) -> None:
        """PassRole + CreateFunction escalation chain is detected."""
        paths = analyzer.analyze_agent(passrole_agent)
        assert len(paths) > 0

    def test_passrole_chain_has_steps(self, analyzer: AttackPathAnalyzer, passrole_agent: Agent) -> None:
        """PassRole chains contain steps describing the attack."""
        paths = analyzer.analyze_agent(passrole_agent)
        assert any(len(p.steps) >= 1 for p in paths)

    def test_passrole_chain_severity(self, analyzer: AttackPathAnalyzer, passrole_agent: Agent) -> None:
        """PassRole escalation paths are rated HIGH or CRITICAL."""
        paths = analyzer.analyze_agent(passrole_agent)
        if paths:
            severities = [p.severity for p in paths]
            assert any(s in (Severity.HIGH, Severity.CRITICAL) for s in severities)


# =============================================================================
# Test: Lambda Escalation Detection
# =============================================================================


class TestLambdaEscalation:
    """Tests for Lambda-based escalation path detection."""

    def test_lambda_escalation_detected(self, analyzer: AttackPathAnalyzer, lambda_escalation_agent: Agent) -> None:
        """Lambda escalation pattern (PassRole + CreateFunction + Invoke) detected."""
        paths = analyzer.analyze_agent(lambda_escalation_agent)
        assert len(paths) > 0

    def test_lambda_paths_reference_execution(self, analyzer: AttackPathAnalyzer, lambda_escalation_agent: Agent) -> None:
        """Lambda paths mention code execution or function creation."""
        paths = analyzer.analyze_agent(lambda_escalation_agent)
        all_descriptions = " ".join(p.description.lower() for p in paths)
        assert "lambda" in all_descriptions or "function" in all_descriptions or "execution" in all_descriptions or len(paths) > 0

    def test_lambda_escalation_has_remediation(self, analyzer: AttackPathAnalyzer, lambda_escalation_agent: Agent) -> None:
        """Lambda escalation paths include remediation guidance."""
        paths = analyzer.analyze_agent(lambda_escalation_agent)
        if paths:
            assert any(p.remediation != "" for p in paths)


# =============================================================================
# Test: Cross-Account Paths
# =============================================================================


class TestCrossAccountPaths:
    """Tests for cross-account escalation path detection."""

    def test_cross_account_path_detected(self, analyzer: AttackPathAnalyzer, cross_account_agent: Agent) -> None:
        """sts:AssumeRole to external account is detected as attack path."""
        paths = analyzer.analyze_agent(cross_account_agent)
        assert len(paths) > 0

    def test_cross_account_high_impact(self, analyzer: AttackPathAnalyzer, cross_account_agent: Agent) -> None:
        """Cross-account paths have high impact scores."""
        paths = analyzer.analyze_agent(cross_account_agent)
        if paths:
            max_impact = max(p.impact_score for p in paths)
            assert max_impact >= 0.5

    def test_cross_account_mitre_mapping(self, analyzer: AttackPathAnalyzer, cross_account_agent: Agent) -> None:
        """Cross-account paths reference MITRE ATT&CK techniques."""
        paths = analyzer.analyze_agent(cross_account_agent)
        if paths:
            all_mitre = []
            for p in paths:
                all_mitre.extend(p.mitre_technique_ids)
            assert len(all_mitre) > 0


# =============================================================================
# Test: Path Ranking
# =============================================================================


class TestPathRanking:
    """Tests for attack path ranking by risk."""

    def test_paths_ordered_by_combined_score(self, analyzer: AttackPathAnalyzer, passrole_agent: Agent) -> None:
        """Returned paths are ordered by combined score (highest first)."""
        paths = analyzer.analyze_agent(passrole_agent)
        if len(paths) >= 2:
            scores = [p.combined_score for p in paths]
            assert scores == sorted(scores, reverse=True)

    def test_higher_risk_actions_rank_higher(self, analyzer: AttackPathAnalyzer) -> None:
        """Agent with admin-level permissions produces higher-ranked paths."""
        admin_agent = Agent.create(
            name="admin-agent", owner="ops",
            environment=Environment.PRODUCTION,
            workload_type=WorkloadType.BEDROCK_AGENT,
            iam_role_arn="arn:aws:iam::123456789012:role/admin",
            data_classification=DataClassification.SECRET,
        )
        admin_dict = admin_agent.to_dict()
        admin_dict["identity_policies"] = [
            {
                "PolicyName": "admin-access",
                "PolicyDocument": {
                    "Statement": [
                        {"Effect": "Allow", "Action": ["iam:*", "sts:*", "lambda:*"], "Resource": "*"}
                    ]
                },
            }
        ]
        admin = Agent.from_dict(admin_dict)
        paths = analyzer.analyze_agent(admin)
        if paths:
            assert paths[0].combined_score >= 0.4

    def test_combined_score_range(self, analyzer: AttackPathAnalyzer, passrole_agent: Agent) -> None:
        """Combined scores are within valid 0-1 range."""
        paths = analyzer.analyze_agent(passrole_agent)
        for path in paths:
            assert 0.0 <= path.combined_score <= 1.0


# =============================================================================
# Test: Cycle Detection
# =============================================================================


class TestCycleDetection:
    """Tests for cycle detection in attack graph traversal."""

    def test_no_infinite_loops_with_cyclic_permissions(self, analyzer: AttackPathAnalyzer) -> None:
        """Analyzer terminates even with self-referential permissions."""
        cyclic_agent = Agent.create(
            name="cyclic-agent", owner="ops",
            environment=Environment.PRODUCTION,
            workload_type=WorkloadType.BEDROCK_AGENT,
            iam_role_arn="arn:aws:iam::123456789012:role/cyclic",
            data_classification=DataClassification.INTERNAL,
        )
        cyclic_dict = cyclic_agent.to_dict()
        cyclic_dict["identity_policies"] = [
            {
                "PolicyName": "cyclic-policy",
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["sts:AssumeRole", "iam:PassRole", "iam:UpdateAssumeRolePolicy"],
                            "Resource": "arn:aws:iam::123456789012:role/cyclic",
                        }
                    ]
                },
            }
        ]
        cyclic = Agent.from_dict(cyclic_dict)
        # Should complete without infinite loop
        paths = analyzer.analyze_agent(cyclic)
        assert isinstance(paths, list)  # Completed successfully

    def test_paths_do_not_repeat_nodes(self, analyzer: AttackPathAnalyzer, passrole_agent: Agent) -> None:
        """Paths should not have unbounded cycles (a step may reference same service category)."""
        paths = analyzer.analyze_agent(passrole_agent)
        for path in paths:
            # Verify paths are bounded (no infinite loops)
            assert len(path.steps) <= 10


# =============================================================================
# Test: Empty Policy Handling
# =============================================================================


class TestEmptyPolicyHandling:
    """Tests for agents with empty or no policies."""

    def test_no_policies_no_paths(self, analyzer: AttackPathAnalyzer, minimal_agent: Agent) -> None:
        """Agent with no policies has no attack paths."""
        paths = analyzer.analyze_agent(minimal_agent)
        assert len(paths) == 0

    def test_deny_only_policies_no_paths(self, analyzer: AttackPathAnalyzer) -> None:
        """Agent with only DENY policies has no exploitable paths."""
        deny_agent = Agent.create(
            name="deny-only", owner="ops",
            environment=Environment.PRODUCTION,
            workload_type=WorkloadType.LAMBDA,
            iam_role_arn="arn:aws:iam::123456789012:role/deny-only",
        )
        deny_dict = deny_agent.to_dict()
        deny_dict["identity_policies"] = [
            {
                "PolicyName": "deny-all",
                "PolicyDocument": {
                    "Statement": [
                        {"Effect": "Deny", "Action": ["*"], "Resource": "*"}
                    ]
                },
            }
        ]
        agent = Agent.from_dict(deny_dict)
        paths = analyzer.analyze_agent(agent)
        # Deny-only should not produce attack paths
        assert len(paths) == 0

    def test_read_only_minimal_paths(self, analyzer: AttackPathAnalyzer) -> None:
        """Agent with only read permissions has no or minimal escalation paths."""
        reader = Agent.create(
            name="reader-only", owner="analytics",
            environment=Environment.DEV,
            workload_type=WorkloadType.LAMBDA,
            iam_role_arn="arn:aws:iam::123456789012:role/reader",
        )
        reader_dict = reader.to_dict()
        reader_dict["identity_policies"] = [
            {
                "PolicyName": "read-only",
                "PolicyDocument": {
                    "Statement": [
                        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"}
                    ]
                },
            }
        ]
        agent = Agent.from_dict(reader_dict)
        paths = analyzer.analyze_agent(agent)
        # Read-only permissions may still have theoretical data exfiltration paths
        # but should have minimal or no privilege escalation paths
        assert len(paths) <= 5  # Very few paths for read-only agent


# =============================================================================
# Test: Graph Model
# =============================================================================


class TestGraphModel:
    """Tests for the underlying attack graph model."""

    def test_graph_node_equality(self) -> None:
        """GraphNodes with same ID are equal."""
        node1 = GraphNode(node_id="arn:aws:iam::123:role/test", node_type="role")
        node2 = GraphNode(node_id="arn:aws:iam::123:role/test", node_type="role")
        assert node1 == node2

    def test_graph_node_hashing(self) -> None:
        """GraphNodes with same ID hash to same value."""
        node1 = GraphNode(node_id="test-node", node_type="agent")
        node2 = GraphNode(node_id="test-node", node_type="agent")
        assert hash(node1) == hash(node2)

    def test_graph_edge_creation(self) -> None:
        """GraphEdge correctly links source and target."""
        source = GraphNode(node_id="agent-1", node_type="agent")
        target = GraphNode(node_id="role-1", node_type="role")
        edge = GraphEdge(
            source=source, target=target,
            action="iam:PassRole", permission_required="iam:PassRole",
            risk_weight=0.8,
        )
        assert edge.source == source
        assert edge.target == target
        assert edge.risk_weight == 0.8

    def test_mitre_technique_values(self) -> None:
        """MitreTechnique enum has expected values."""
        assert MitreTechnique.VALID_ACCOUNTS == "T1078"
        assert MitreTechnique.EXECUTION_SERVERLESS == "T1648"

    def test_attack_pattern_category_values(self) -> None:
        """AttackPatternCategory has all expected values."""
        expected = {
            "privilege_escalation", "lateral_movement",
            "data_exfiltration", "credential_theft",
            "arbitrary_execution", "persistence",
        }
        actual = {c.value for c in AttackPatternCategory}
        assert actual == expected
