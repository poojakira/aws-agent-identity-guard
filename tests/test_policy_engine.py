"""
tests/test_policy_engine.py
----------------------------
Tests for the YAML policy engine.

Covers policy loading, rule matching, condition evaluation, policy validation,
and policy diff analysis.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from aws_agent_identity_guard.models import (
    AgentIdentity,
    AgentType,
    DataClassification,
    Environment,
    RiskScore,
    TransactionRequest,
)
from aws_agent_identity_guard.policy_engine import (
    PolicyDecision,
    PolicyDiff,
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PolicyVersion,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def engine() -> PolicyEngine:
    """Return a fresh PolicyEngine instance."""
    return PolicyEngine()


@pytest.fixture
def sample_agent() -> AgentIdentity:
    """Return a standard test agent."""
    return AgentIdentity(
        agent_id="agent-test",
        name="TestAgent",
        agent_type=AgentType.BEDROCK,
        owner="security-team",
        environment=Environment.PRODUCTION,
        data_classification=DataClassification.CONFIDENTIAL,
    )


@pytest.fixture
def dev_agent() -> AgentIdentity:
    """Return a development agent."""
    return AgentIdentity(
        agent_id="agent-dev",
        name="DevAgent",
        agent_type=AgentType.LAMBDA,
        owner="dev-team",
        environment=Environment.DEVELOPMENT,
        data_classification=DataClassification.INTERNAL,
    )


@pytest.fixture
def high_risk_score() -> RiskScore:
    """Return a high risk score."""
    return RiskScore(overall=85.0, privilege=90.0, sensitivity=70.0)


@pytest.fixture
def low_risk_score() -> RiskScore:
    """Return a low risk score."""
    return RiskScore(overall=15.0, privilege=10.0, sensitivity=5.0)


@pytest.fixture
def sample_request() -> TransactionRequest:
    """Return a standard test transaction request."""
    return TransactionRequest(
        agent_id="agent-test",
        principal="arn:aws:iam::123456789012:role/TestRole",
        tool="iam-manager",
        action="iam:PassRole",
        resource="*",
    )


# ─── YAML Policy Loading Tests ───────────────────────────────────────────────


class TestPolicyLoading:
    """Test YAML policy loading from string and directory."""

    def test_load_from_string(self, engine):
        """Load policies from a YAML string."""
        engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: deny-all-iam
    effect: deny
    actions: ['iam:*']
    resources: ['*']
    priority: 100
""")
        assert engine.rule_count == 1

    def test_load_from_directory(self, engine):
        """Load policies from a temp directory with YAML files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "test_policy.yaml"
            policy_path.write_text("""
version: '1.0'
policies:
  - name: allow-s3-read
    effect: allow
    actions: ['s3:GetObject']
    resources: ['*']
    priority: 50
  - name: deny-delete
    effect: deny
    actions: ['s3:DeleteObject']
    resources: ['*']
    priority: 100
""")
            engine.load_policies(Path(tmpdir))
            assert engine.rule_count == 2

    def test_load_nonexistent_directory_raises(self, engine):
        """Loading from non-existent directory raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            engine.load_policies(Path("/nonexistent/path"))

    def test_load_replaces_existing_rules(self, engine):
        """Reloading policies replaces previous rule set."""
        engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: rule-a
    effect: deny
    actions: ['iam:*']
""")
        assert engine.rule_count == 1
        engine.load_policies_from_string("""
version: '2.0'
policies:
  - name: rule-b
    effect: allow
    actions: ['s3:GetObject']
  - name: rule-c
    effect: deny
    actions: ['s3:DeleteObject']
""")
        assert engine.rule_count == 2


# ─── Rule Matching Tests ─────────────────────────────────────────────────────


class TestRuleMatching:
    """Test deny, allow, and require_approval rule matching."""

    def test_deny_rule_matches_action(self, engine, sample_agent, high_risk_score):
        """Deny rule matching specific action returns DENY."""
        engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: block-passrole
    effect: deny
    actions: ['iam:PassRole']
    resources: ['*']
""")
        request = TransactionRequest(
            agent_id="agent-test",
            principal="role",
            tool="tool",
            action="iam:PassRole",
            resource="*",
        )
        result = engine.evaluate(request, sample_agent, high_risk_score)
        assert result.effect == PolicyEffect.DENY
        assert "block-passrole" in result.matched_rules

    def test_allow_rule_matches(self, engine, sample_agent, low_risk_score):
        """Allow rule matching action returns ALLOW."""
        engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: allow-s3-read
    effect: allow
    actions: ['s3:GetObject']
    resources: ['*']
""")
        request = TransactionRequest(
            agent_id="agent-test",
            principal="role",
            tool="s3-reader",
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket/key",
        )
        result = engine.evaluate(request, sample_agent, low_risk_score)
        assert result.effect == PolicyEffect.ALLOW

    def test_require_approval_rule_matches(self, engine, sample_agent, low_risk_score):
        """Require approval rule produces REQUIRE_APPROVAL decision."""
        engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: approve-delete
    effect: require_approval
    actions: ['s3:DeleteObject']
    resources: ['*']
""")
        request = TransactionRequest(
            agent_id="agent-test",
            principal="role",
            tool="cleaner",
            action="s3:DeleteObject",
            resource="arn:aws:s3:::bucket/file",
        )
        result = engine.evaluate(request, sample_agent, low_risk_score)
        assert result.effect == PolicyEffect.REQUIRE_APPROVAL

    def test_deny_takes_precedence_over_allow(self, engine, sample_agent, low_risk_score):
        """When both deny and allow match, deny wins."""
        engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: allow-all-s3
    effect: allow
    actions: ['s3:*']
    resources: ['*']
    priority: 50
  - name: deny-public-bucket
    effect: deny
    actions: ['s3:*']
    resources: ['arn:aws:s3:::public-*']
    priority: 100
""")
        request = TransactionRequest(
            agent_id="agent-test",
            principal="role",
            tool="tool",
            action="s3:GetObject",
            resource="arn:aws:s3:::public-bucket/secret.csv",
        )
        result = engine.evaluate(request, sample_agent, low_risk_score)
        assert result.effect == PolicyEffect.DENY

    def test_no_matching_rule_defaults_deny(self, engine, sample_agent, low_risk_score):
        """When no rule matches, default is DENY (fail-closed)."""
        engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: allow-only-lambda
    effect: allow
    actions: ['lambda:InvokeFunction']
    resources: ['*']
""")
        request = TransactionRequest(
            agent_id="agent-test",
            principal="role",
            tool="tool",
            action="ec2:RunInstances",
            resource="*",
        )
        result = engine.evaluate(request, sample_agent, low_risk_score)
        assert result.effect == PolicyEffect.DENY


# ─── Condition Evaluation Tests ───────────────────────────────────────────────


class TestConditions:
    """Test condition-based rule matching."""

    def test_risk_score_above_condition(self, engine, sample_agent, high_risk_score, low_risk_score):
        """Rule with risk_score_above matches only when score exceeds threshold."""
        engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: deny-high-risk
    effect: deny
    actions: ['*']
    resources: ['*']
    conditions:
      risk_score_above: 70
""")
        request = TransactionRequest(
            agent_id="agent-test", principal="r", tool="t",
            action="s3:GetObject", resource="*",
        )
        result_high = engine.evaluate(request, sample_agent, high_risk_score)
        result_low = engine.evaluate(request, sample_agent, low_risk_score)
        assert result_high.effect == PolicyEffect.DENY
        # Low risk should NOT match the deny condition
        assert result_low.effect != PolicyEffect.DENY or "deny-high-risk" not in result_low.matched_rules

    def test_data_classification_in_condition(self, engine, sample_agent, low_risk_score):
        """Rule with data_classification_in matches based on request classification."""
        engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: deny-secret-access
    effect: deny
    actions: ['*']
    resources: ['*']
    conditions:
      data_classification_in: ['SECRET', 'REGULATED']
""")
        # Agent has CONFIDENTIAL, not SECRET/REGULATED
        request = TransactionRequest(
            agent_id="agent-test", principal="r", tool="t",
            action="s3:GetObject", resource="*",
            data_classification=DataClassification.SECRET,
        )
        result = engine.evaluate(request, sample_agent, low_risk_score)
        assert result.effect == PolicyEffect.DENY

    def test_environment_filter(self, engine, dev_agent, low_risk_score):
        """Rule scoped to production does not match development agent."""
        engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: prod-only-deny
    effect: deny
    actions: ['*']
    resources: ['*']
    environments: ['PRODUCTION']
""")
        request = TransactionRequest(
            agent_id="agent-dev", principal="r", tool="t",
            action="s3:GetObject", resource="*",
        )
        result = engine.evaluate(request, dev_agent, low_risk_score)
        # Should NOT match because agent is in DEVELOPMENT
        assert "prod-only-deny" not in result.matched_rules


# ─── Policy Validation Tests ─────────────────────────────────────────────────


class TestPolicyValidation:
    """Test policy YAML validation."""

    def test_valid_policy_passes(self, engine):
        """Well-formed policy produces no errors."""
        errors = engine.validate_policy("""
version: '1.0'
policies:
  - name: valid-rule
    effect: deny
    actions: ['iam:*']
    resources: ['*']
""")
        assert errors == []

    def test_missing_version_reported(self, engine):
        """Missing version field is reported as error."""
        errors = engine.validate_policy("""
policies:
  - name: rule
    effect: deny
""")
        assert any("version" in e for e in errors)

    def test_missing_name_reported(self, engine):
        """Missing name field is reported as error."""
        errors = engine.validate_policy("""
version: '1.0'
policies:
  - effect: deny
    actions: ['*']
""")
        assert any("name" in e for e in errors)

    def test_invalid_effect_reported(self, engine):
        """Invalid effect value is reported as error."""
        errors = engine.validate_policy("""
version: '1.0'
policies:
  - name: bad-effect
    effect: execute
    actions: ['*']
""")
        assert any("effect" in e.lower() for e in errors)

    def test_invalid_yaml_syntax(self, engine):
        """Malformed YAML produces a parse error."""
        errors = engine.validate_policy("{{invalid yaml::")
        assert any("parse error" in e.lower() or "yaml" in e.lower() for e in errors)


# ─── Policy Diff Tests ────────────────────────────────────────────────────────


class TestPolicyDiff:
    """Test policy version diffing."""

    def test_added_rules_detected(self, engine):
        """New rules in the new version are reported as added."""
        old = PolicyVersion(
            version="1.0",
            rules=[PolicyRule(name="rule-a", effect=PolicyEffect.DENY)],
        )
        new = PolicyVersion(
            version="2.0",
            rules=[
                PolicyRule(name="rule-a", effect=PolicyEffect.DENY),
                PolicyRule(name="rule-b", effect=PolicyEffect.ALLOW),
            ],
        )
        diff = engine.diff_policies(old, new)
        assert "rule-b" in diff.added_rules

    def test_removed_rules_detected(self, engine):
        """Rules missing from new version are reported as removed."""
        old = PolicyVersion(
            version="1.0",
            rules=[
                PolicyRule(name="rule-a", effect=PolicyEffect.DENY),
                PolicyRule(name="rule-b", effect=PolicyEffect.ALLOW),
            ],
        )
        new = PolicyVersion(
            version="2.0",
            rules=[PolicyRule(name="rule-a", effect=PolicyEffect.DENY)],
        )
        diff = engine.diff_policies(old, new)
        assert "rule-b" in diff.removed_rules

    def test_modified_rules_detected(self, engine):
        """Changed rules are detected in the diff."""
        old = PolicyVersion(
            version="1.0",
            rules=[PolicyRule(name="rule-a", effect=PolicyEffect.DENY, actions=["iam:*"])],
        )
        new = PolicyVersion(
            version="2.0",
            rules=[PolicyRule(name="rule-a", effect=PolicyEffect.ALLOW, actions=["iam:*"])],
        )
        diff = engine.diff_policies(old, new)
        assert "rule-a" in diff.modified_rules
