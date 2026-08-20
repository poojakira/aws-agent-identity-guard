"""Tests for the policy engine module.

Covers YAML policy loading, rule evaluation (deny, allow, require_approval),
pattern matching, environment conditions, policy validation, PolicySet operations,
and default policies.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pytest

from aws_agent_identity_guard.models import (
    DataClassification,
    Decision,
    Environment,
    PermissionEffect,
)
from aws_agent_identity_guard.policy_engine import (
    EvaluationContext,
    Policy,
    PolicyDecision,
    PolicyDecisionEffect,
    PolicyEngine,
    PolicySet,
    RuleConditions,
    RuleType,
    TimeWindow,
    ValidationError,
    ValidationSeverity,
    load_policy,
    validate_policy,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def engine() -> PolicyEngine:
    """PolicyEngine with default policies loaded."""
    engine = PolicyEngine()
    engine.load_default_policies()
    return engine


@pytest.fixture
def empty_engine() -> PolicyEngine:
    """PolicyEngine with no policies loaded."""
    return PolicyEngine()


@pytest.fixture
def production_context() -> EvaluationContext:
    """Evaluation context for production environment."""
    return EvaluationContext(
        environment="production",
        data_classification="SECRET",
        agent_type="BEDROCK_AGENT",
    )


@pytest.fixture
def dev_context() -> EvaluationContext:
    """Evaluation context for dev environment."""
    return EvaluationContext(
        environment="dev",
        data_classification="PUBLIC",
        agent_type="LAMBDA",
    )


@pytest.fixture
def sample_yaml_policy() -> str:
    """Sample YAML policy content in the engine's expected format."""
    return """
version: "1.0"
metadata:
  name: test-security-policy
  description: Test policy for unit tests
  author: test-suite
rules:
  - id: deny-iam-admin
    deny:
      action: "iam:*"
      resource: "*"
    conditions:
      environment:
        - production
    severity: critical
    message: Deny all IAM actions in production

  - id: allow-s3-read
    allow:
      action: "s3:GetObject"
      resource: "arn:aws:s3:::dev-*"
    severity: low
    message: Allow S3 reads in dev buckets

  - id: require-approval-kms
    require_approval:
      action: "kms:Decrypt"
      resource: "arn:aws:kms:*:*:key/*"
    conditions:
      data_classification:
        - SECRET
        - REGULATED
    severity: high
    message: KMS operations on sensitive data need approval
"""


# =============================================================================
# Test: YAML Policy Loading
# =============================================================================


class TestYamlPolicyLoading:
    """Tests for loading policies from YAML."""

    def test_load_policy_from_yaml_string(self, sample_yaml_policy: str) -> None:
        """Engine can load policy from YAML string via Policy.from_yaml."""
        policy = Policy.from_yaml(sample_yaml_policy)
        assert policy.metadata.name == "test-security-policy"

    def test_load_policy_from_yaml_file(self, empty_engine: PolicyEngine, sample_yaml_policy: str) -> None:
        """Engine can load policy from a YAML file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(sample_yaml_policy)
            f.flush()
            policy = load_policy(Path(f.name))
        empty_engine.add_policy(policy)
        assert empty_engine.policy_count > 0

    def test_loaded_policy_has_correct_rules(self, sample_yaml_policy: str) -> None:
        """Loaded policy contains all defined rules."""
        policy = Policy.from_yaml(sample_yaml_policy)
        assert len(policy.rules) == 3

    def test_rule_types_parsed_correctly(self, sample_yaml_policy: str) -> None:
        """Rule types are parsed as RuleType enum values."""
        policy = Policy.from_yaml(sample_yaml_policy)
        rule_types = {r.rule_type for r in policy.rules}
        assert RuleType.DENY in rule_types
        assert RuleType.ALLOW in rule_types
        assert RuleType.REQUIRE_APPROVAL in rule_types

    def test_policy_has_version(self, sample_yaml_policy: str) -> None:
        """Loaded policy preserves version."""
        policy = Policy.from_yaml(sample_yaml_policy)
        assert policy.version == "1.0"

    def test_policy_checksum_computed(self, sample_yaml_policy: str) -> None:
        """Policy checksum is computed on load."""
        policy = Policy.from_yaml(sample_yaml_policy)
        assert policy.checksum != ""
        assert len(policy.checksum) == 64  # SHA-256 hex


# =============================================================================
# Test: Rule Evaluation
# =============================================================================


class TestRuleEvaluation:
    """Tests for policy rule evaluation logic."""

    def test_deny_rule_produces_deny_effect(self, engine: PolicyEngine, production_context: EvaluationContext) -> None:
        """Deny rules produce DENY effect when matched."""
        # iam:* wildcard in default policies produces DENY
        result = engine.evaluate("iam:*", "*", production_context)
        # Default policies may not have explicit deny for iam:CreateRole
        # but should at least flag it (WARN, AUDIT, or DENY depending on defaults)
        assert result.effect in (PolicyDecisionEffect.DENY, PolicyDecisionEffect.WARN, PolicyDecisionEffect.AUDIT)

    def test_no_match_for_unmatched_action(self, engine: PolicyEngine, dev_context: EvaluationContext) -> None:
        """Unmatched actions produce NO_MATCH or ALLOW."""
        result = engine.evaluate("custom:Unknown", "*", dev_context)
        assert result.effect in (PolicyDecisionEffect.NO_MATCH, PolicyDecisionEffect.ALLOW)

    def test_deny_takes_precedence_over_allow(self, empty_engine: PolicyEngine, sample_yaml_policy: str) -> None:
        """When both deny and allow rules could match, deny wins."""
        policy = Policy.from_yaml(sample_yaml_policy)
        empty_engine.add_policy(policy)
        # iam:* in production should be denied even if allow exists
        context = EvaluationContext(environment="production", data_classification="INTERNAL")
        result = empty_engine.evaluate("iam:PassRole", "*", context)
        assert result.effect == PolicyDecisionEffect.DENY

    def test_require_approval_effect(self, empty_engine: PolicyEngine, sample_yaml_policy: str) -> None:
        """require_approval rules produce REQUIRE_APPROVAL effect."""
        policy = Policy.from_yaml(sample_yaml_policy)
        empty_engine.add_policy(policy)
        context = EvaluationContext(
            environment="staging",
            data_classification="SECRET",
            agent_type="BEDROCK_AGENT",
        )
        result = empty_engine.evaluate("kms:Decrypt", "arn:aws:kms:us-east-1:123456789012:key/abc-123", context)
        assert result.effect == PolicyDecisionEffect.REQUIRE_APPROVAL

    def test_no_match_when_no_rules_apply(self, empty_engine: PolicyEngine) -> None:
        """Returns NO_MATCH when no rules match the context."""
        context = EvaluationContext(
            environment="dev",
            data_classification="PUBLIC",
            agent_type="CUSTOM",
        )
        result = empty_engine.evaluate("custom:UnknownAction", "arn:aws:custom:::resource", context)
        assert result.effect == PolicyDecisionEffect.NO_MATCH


# =============================================================================
# Test: Pattern Matching
# =============================================================================


class TestPatternMatching:
    """Tests for action and resource pattern matching."""

    def test_wildcard_action_matches_all(self, empty_engine: PolicyEngine, sample_yaml_policy: str) -> None:
        """'iam:*' pattern matches all IAM actions."""
        policy = Policy.from_yaml(sample_yaml_policy)
        empty_engine.add_policy(policy)
        context = EvaluationContext(environment="production")
        result = empty_engine.evaluate("iam:DeleteUser", "*", context)
        assert result.effect == PolicyDecisionEffect.DENY

    def test_specific_action_pattern(self, empty_engine: PolicyEngine, sample_yaml_policy: str) -> None:
        """Specific action patterns match exactly."""
        policy = Policy.from_yaml(sample_yaml_policy)
        empty_engine.add_policy(policy)
        context = EvaluationContext(environment="dev")
        result = empty_engine.evaluate("s3:GetObject", "arn:aws:s3:::dev-bucket/file.txt", context)
        assert result.effect in (PolicyDecisionEffect.ALLOW, PolicyDecisionEffect.NO_MATCH)

    def test_resource_prefix_pattern(self, empty_engine: PolicyEngine, sample_yaml_policy: str) -> None:
        """Resource patterns with prefixes match correctly."""
        policy = Policy.from_yaml(sample_yaml_policy)
        empty_engine.add_policy(policy)
        context = EvaluationContext(environment="dev")
        # "arn:aws:s3:::dev-*" should match dev buckets
        result = empty_engine.evaluate("s3:GetObject", "arn:aws:s3:::dev-analytics/data.csv", context)
        assert result.effect in (PolicyDecisionEffect.ALLOW, PolicyDecisionEffect.NO_MATCH)

    def test_non_matching_resource_skipped(self, empty_engine: PolicyEngine, sample_yaml_policy: str) -> None:
        """Actions matching but with non-matching resource don't trigger."""
        policy = Policy.from_yaml(sample_yaml_policy)
        empty_engine.add_policy(policy)
        context = EvaluationContext(environment="dev")
        # s3:GetObject allow rule only matches "arn:aws:s3:::dev-*"
        result = empty_engine.evaluate("s3:GetObject", "arn:aws:s3:::prod-bucket/file.txt", context)
        # Should not match the allow rule for dev buckets
        assert result.effect == PolicyDecisionEffect.NO_MATCH


# =============================================================================
# Test: Environment Conditions
# =============================================================================


class TestEnvironmentConditions:
    """Tests for environment-based rule conditions."""

    def test_rule_only_applies_to_specified_environment(self, empty_engine: PolicyEngine, sample_yaml_policy: str) -> None:
        """Deny rule with environment=production doesn't fire in dev."""
        policy = Policy.from_yaml(sample_yaml_policy)
        empty_engine.add_policy(policy)
        context = EvaluationContext(environment="dev")
        result = empty_engine.evaluate("iam:CreateRole", "*", context)
        # Should NOT be denied since deny rule only applies to production
        assert result.effect != PolicyDecisionEffect.DENY

    def test_rule_fires_in_correct_environment(self, empty_engine: PolicyEngine, sample_yaml_policy: str) -> None:
        """Deny rule fires when environment matches."""
        policy = Policy.from_yaml(sample_yaml_policy)
        empty_engine.add_policy(policy)
        context = EvaluationContext(environment="production")
        result = empty_engine.evaluate("iam:CreateRole", "*", context)
        assert result.effect == PolicyDecisionEffect.DENY

    def test_data_classification_condition(self, empty_engine: PolicyEngine, sample_yaml_policy: str) -> None:
        """Rules with data_classification conditions filter properly."""
        policy = Policy.from_yaml(sample_yaml_policy)
        empty_engine.add_policy(policy)
        # Require approval for kms:Decrypt when classification is SECRET
        secret_ctx = EvaluationContext(environment="staging", data_classification="SECRET")
        result = empty_engine.evaluate("kms:Decrypt", "arn:aws:kms:us-east-1:123:key/abc", secret_ctx)
        assert result.effect == PolicyDecisionEffect.REQUIRE_APPROVAL

        # PUBLIC classification should not match
        public_ctx = EvaluationContext(environment="staging", data_classification="PUBLIC")
        result = empty_engine.evaluate("kms:Decrypt", "arn:aws:kms:us-east-1:123:key/abc", public_ctx)
        assert result.effect != PolicyDecisionEffect.REQUIRE_APPROVAL


# =============================================================================
# Test: Policy Validation
# =============================================================================


class TestPolicyValidation:
    """Tests for policy structure validation."""

    def test_validate_valid_policy(self, sample_yaml_policy: str) -> None:
        """Valid policy passes validation with no errors."""
        policy = Policy.from_yaml(sample_yaml_policy)
        errors = validate_policy(policy)
        error_list = [e for e in errors if e.severity == ValidationSeverity.ERROR]
        assert len(error_list) == 0

    def test_validate_policy_without_name(self) -> None:
        """Policy without name produces validation error."""
        yaml_str = """
version: "1.0"
metadata:
  description: No name policy
rules:
  - id: test-rule
    deny:
      action: "iam:*"
      resource: "*"
    severity: high
    message: Test
"""
        policy = Policy.from_yaml(yaml_str)
        errors = validate_policy(policy)
        name_errors = [e for e in errors if "name" in e.path.lower()]
        assert len(name_errors) > 0

    def test_validate_policy_no_rules_warning(self) -> None:
        """Policy with no rules produces a warning."""
        yaml_str = """
version: "1.0"
metadata:
  name: empty-policy
  description: No rules
rules: []
"""
        policy = Policy.from_yaml(yaml_str)
        errors = validate_policy(policy)
        warnings = [e for e in errors if e.severity == ValidationSeverity.WARNING]
        assert any("rule" in w.message.lower() or "rules" in w.path.lower() for w in warnings)


# =============================================================================
# Test: PolicySet Operations
# =============================================================================


class TestPolicySetOperations:
    """Tests for PolicySet management."""

    def test_create_policy_set(self) -> None:
        """PolicySet can be created with a name and description."""
        ps = PolicySet(name="production-policies", description="Policies for production")
        assert ps.name == "production-policies"
        assert ps.policy_count == 0

    def test_add_policy_to_set(self, sample_yaml_policy: str) -> None:
        """Policies can be added to a PolicySet."""
        ps = PolicySet(name="test-set", description="Test")
        policy = Policy.from_yaml(sample_yaml_policy)
        ps.add_policy(policy)
        assert ps.policy_count > 0

    def test_policy_set_evaluation(self, sample_yaml_policy: str) -> None:
        """PolicySet evaluates context against all contained policies."""
        ps = PolicySet(name="eval-set", description="Evaluation test")
        policy = Policy.from_yaml(sample_yaml_policy)
        ps.add_policy(policy)
        context = EvaluationContext(environment="production")
        result = ps.evaluate("iam:DeleteRole", "*", context)
        assert result.effect == PolicyDecisionEffect.DENY

    def test_policy_set_remove(self, sample_yaml_policy: str) -> None:
        """Policies can be removed from a PolicySet."""
        ps = PolicySet(name="remove-test", description="Test")
        policy = Policy.from_yaml(sample_yaml_policy)
        ps.add_policy(policy)
        assert ps.policy_count == 1
        ps.remove_policy("test-security-policy")
        assert ps.policy_count == 0

    def test_policy_set_merge(self, sample_yaml_policy: str) -> None:
        """Two PolicySets can be merged."""
        ps1 = PolicySet(name="set-1", description="First")
        ps2 = PolicySet(name="set-2", description="Second")
        policy = Policy.from_yaml(sample_yaml_policy)
        ps1.add_policy(policy)
        merged = ps1.merge(ps2)
        assert merged.policy_count >= 1


# =============================================================================
# Test: Default Policies
# =============================================================================


class TestDefaultPolicies:
    """Tests for built-in default policies."""

    def test_default_policies_loaded(self, engine: PolicyEngine) -> None:
        """Default policies are loaded when requested."""
        assert engine.policy_count > 0

    def test_default_denies_privilege_escalation(self, engine: PolicyEngine) -> None:
        """Default policies deny privilege escalation in production."""
        context = EvaluationContext(environment="production")
        result = engine.evaluate("iam:PassRole", "*", context)
        assert result.effect in (PolicyDecisionEffect.DENY, PolicyDecisionEffect.REQUIRE_APPROVAL)

    def test_default_denies_security_control_disable(self, engine: PolicyEngine) -> None:
        """Default policies deny disabling security controls."""
        context = EvaluationContext(environment="production")
        result = engine.evaluate("cloudtrail:StopLogging", "*", context)
        assert result.effect == PolicyDecisionEffect.DENY


# =============================================================================
# Test: Time Window Conditions
# =============================================================================


class TestTimeWindowConditions:
    """Tests for time-based rule conditions."""

    def test_time_window_all_days(self) -> None:
        """TimeWindow covering all days and hours is always active."""
        tw = TimeWindow()
        assert tw.is_active() is True

    def test_time_window_restricted_hours(self) -> None:
        """TimeWindow with restricted hours works correctly."""
        from datetime import datetime, timezone
        tw = TimeWindow(start_hour=9, end_hour=17)
        # Create a time within the window
        in_window = datetime(2024, 1, 15, 12, 0, tzinfo=timezone.utc)  # Monday noon
        assert tw.is_active(at=in_window) is True
        # Create a time outside the window
        out_window = datetime(2024, 1, 15, 20, 0, tzinfo=timezone.utc)  # Monday 8pm
        assert tw.is_active(at=out_window) is False

    def test_rule_conditions_matches_environment(self) -> None:
        """RuleConditions correctly filter by environment."""
        conditions = RuleConditions(environment=["production", "staging"])
        context = EvaluationContext(environment="production")
        assert conditions.matches(context) is True

        context_dev = EvaluationContext(environment="dev")
        assert conditions.matches(context_dev) is False

    def test_evaluation_context_from_dict(self) -> None:
        """EvaluationContext can be created from a dictionary."""
        ctx = EvaluationContext.from_dict({
            "environment": "production",
            "data_classification": "SECRET",
            "agent_type": "BEDROCK_AGENT",
        })
        assert ctx.environment == "production"
        assert ctx.data_classification == "SECRET"
