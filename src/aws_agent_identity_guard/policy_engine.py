"""
aws_agent_identity_guard/policy_engine.py
--------------------------------------------------------------------------------
Security policy-as-code framework for the AWS Agent Identity Guard system.

Implements a YAML-based policy language that enables declarative, version-
controlled security rules for AI agent authorization decisions. Policies
define allow, deny, require_approval, and step_up effects that the
AuthorizationEngine evaluates in priority order.

Policy evaluation order:
  1. Explicit DENY rules are evaluated first (highest priority always wins)
  2. REQUIRE_APPROVAL and STEP_UP rules are checked next
  3. ALLOW rules grant access only if no deny/escalation matched
  4. If no rule matches, the default effect is DENY (fail-closed)

Policy format (YAML):
  version: '1.0'
  metadata:
    author: security-team
    description: Production security policies
  policies:
    - name: block-secret-access-production
      effect: deny
      actions: ['secretsmanager:GetSecretValue']
      resources: ['*']
      environments: ['production']
      priority: 100

Design principles:
  - Policies are declarative and auditable
  - Version tracking with author and timestamp metadata
  - Supports policy testing with synthetic test cases
  - Diff analysis between policy versions for change management
  - Glob/wildcard matching for actions and resources
"""

from __future__ import annotations

import fnmatch
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

import yaml

from aws_agent_identity_guard.models import (
    AgentIdentity,
    Environment,
    RiskScore,
    TransactionRequest,
)

logger = logging.getLogger(__name__)


# --- Policy Effect Types ---


class PolicyEffect(str, Enum):
    """Effect type for a policy rule."""

    DENY = "DENY"
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    STEP_UP = "STEP_UP"


# --- Policy Data Structures ---


@dataclass
class PolicyRule:
    """
    A single security policy rule.

    Defines the conditions under which a specific effect (DENY, ALLOW,
    REQUIRE_APPROVAL, STEP_UP) is applied to an authorization request.

    Attributes:
        name: Human-readable rule identifier.
        effect: The effect to apply when this rule matches.
        actions: List of IAM action patterns (supports wildcards).
        resources: List of resource ARN patterns (supports wildcards).
        agents: List of agent IDs or patterns this rule applies to.
        environments: List of environments this rule applies to.
        conditions: Additional conditions (e.g., risk_score_above, time_window).
        priority: Rule priority (higher = evaluated first within same effect).
    """

    name: str
    effect: PolicyEffect
    actions: list[str] = field(default_factory=lambda: ["*"])
    resources: list[str] = field(default_factory=lambda: ["*"])
    agents: list[str] = field(default_factory=lambda: ["*"])
    environments: list[str] = field(default_factory=lambda: ["*"])
    conditions: dict[str, Any] = field(default_factory=dict)
    priority: int = 0

    def __post_init__(self) -> None:
        """Validate and normalize rule fields."""
        if not self.name:
            raise ValueError("PolicyRule name cannot be empty")
        if isinstance(self.effect, str):
            self.effect = PolicyEffect(self.effect.upper())

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary."""
        return {
            "name": self.name,
            "effect": self.effect.value,
            "actions": list(self.actions),
            "resources": list(self.resources),
            "agents": list(self.agents),
            "environments": list(self.environments),
            "conditions": dict(self.conditions),
            "priority": self.priority,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyRule:
        """Deserialize from a dictionary."""
        return cls(
            name=data["name"],
            effect=PolicyEffect(data["effect"].upper()),
            actions=data.get("actions", ["*"]),
            resources=data.get("resources", ["*"]),
            agents=data.get("agents", ["*"]),
            environments=data.get("environments", ["*"]),
            conditions=data.get("conditions", {}),
            priority=data.get("priority", 0),
        )


@dataclass
class PolicyDecision:
    """
    Result of evaluating policies against a request.

    Attributes:
        effect: The determined policy effect.
        matched_rules: List of rule names that matched the request.
        explanation: Human-readable explanation of the decision.
    """

    effect: PolicyEffect
    matched_rules: list[str] = field(default_factory=list)
    explanation: str = ""


@dataclass
class PolicyDiff:
    """
    Difference between two policy versions for change management.

    Attributes:
        added_rules: Rules present in new version but not old.
        removed_rules: Rules present in old version but not new.
        modified_rules: Rules that changed between versions.
        risk_assessment: Human-readable assessment of the change risk.
    """

    added_rules: list[str] = field(default_factory=list)
    removed_rules: list[str] = field(default_factory=list)
    modified_rules: list[str] = field(default_factory=list)
    risk_assessment: str = ""


@dataclass
class PolicyVersion:
    """
    Versioned policy set with metadata for audit trail.

    Attributes:
        version: Semantic version string of this policy set.
        author: Who authored or approved this policy version.
        timestamp: When this version was published.
        description: Change description or commit message.
        rules: The set of policy rules in this version.
        content_hash: SHA-256 hash of the serialized rules for integrity.
    """

    version: str
    author: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    description: str = ""
    rules: list[PolicyRule] = field(default_factory=list)
    content_hash: str = ""

    def __post_init__(self) -> None:
        """Compute content hash if not provided."""
        if not self.content_hash:
            self.content_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute SHA-256 hash of policy rules for integrity verification."""
        content = str([r.to_dict() for r in self.rules])
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify the content hash matches the current rules."""
        return self.content_hash == self._compute_hash()


@dataclass
class TestCase:
    """
    A synthetic test case for validating policy behavior.

    Attributes:
        name: Descriptive name for the test case.
        request: The simulated transaction request.
        agent: The simulated agent identity.
        risk_score: The simulated risk score.
        expected_effect: The expected policy decision effect.
    """

    name: str
    request: TransactionRequest
    agent: AgentIdentity
    risk_score: RiskScore
    expected_effect: PolicyEffect


@dataclass
class TestResult:
    """
    Results of running policy tests.

    Attributes:
        total: Total number of tests run.
        passed: Number of tests that passed.
        failed: Number of tests that failed.
        failures: Detailed failure information.
    """

    total: int = 0
    passed: int = 0
    failed: int = 0
    failures: list[dict[str, Any]] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Return True if all tests passed."""
        return self.failed == 0


# --- Policy Engine ---


class PolicyEngine:
    """
    Security policy-as-code evaluation engine.

    Loads, validates, and evaluates YAML-based security policies against
    transaction requests. Supports policy versioning, diff analysis, and
    automated testing.

    Usage:
        engine = PolicyEngine()
        engine.load_policies(Path("./policies"))
        decision = engine.evaluate(request, agent, risk_score)

    The engine evaluates rules in strict priority order within each effect
    category: DENY rules are always checked first, then REQUIRE_APPROVAL
    and STEP_UP, and finally ALLOW. The first matching rule within the
    highest-priority effect category determines the outcome.
    """

    def __init__(self) -> None:
        """Initialize the policy engine with empty rule sets."""
        self._rules: list[PolicyRule] = []
        self._versions: list[PolicyVersion] = []
        self._current_version: str = "0.0.0"
        self._policy_dir: Path | None = None
        logger.info("PolicyEngine initialized")

    @property
    def rules(self) -> list[PolicyRule]:
        """Return the current active rule set."""
        return list(self._rules)

    @property
    def current_version(self) -> str:
        """Return the current policy version string."""
        return self._current_version

    @property
    def rule_count(self) -> int:
        """Return the number of loaded rules."""
        return len(self._rules)

    def load_policies(self, policy_dir: Path) -> None:
        """
        Load all YAML policy files from a directory.

        Scans the given directory for .yaml and .yml files, parses each one,
        validates the structure, and adds the rules to the active policy set.
        Existing rules are replaced on reload.

        Args:
            policy_dir: Path to the directory containing policy YAML files.

        Raises:
            FileNotFoundError: If the directory does not exist.
            ValueError: If a policy file has invalid structure.
        """
        if not policy_dir.exists():
            raise FileNotFoundError(f"Policy directory not found: {policy_dir}")
        if not policy_dir.is_dir():
            raise ValueError(f"Path is not a directory: {policy_dir}")

        self._policy_dir = policy_dir
        new_rules: list[PolicyRule] = []
        policy_files = list(policy_dir.glob("*.yaml")) + list(policy_dir.glob("*.yml"))

        if not policy_files:
            logger.warning("No policy files found in %s", policy_dir)
            return

        for policy_file in sorted(policy_files):
            try:
                rules = self._parse_policy_file(policy_file)
                new_rules.extend(rules)
                logger.info(
                    "Loaded %d rules from %s", len(rules), policy_file.name
                )
            except Exception as exc:
                logger.error(
                    "Failed to load policy file %s: %s",
                    policy_file.name,
                    str(exc),
                )
                raise

        self._rules = new_rules
        self._current_version = self._extract_version(policy_files)
        logger.info(
            "Policy engine loaded %d rules from %d files (version: %s)",
            len(self._rules),
            len(policy_files),
            self._current_version,
        )

    def load_policies_from_string(self, policy_yaml: str) -> None:
        """
        Load policies from a YAML string directly.

        Useful for testing or dynamic policy injection.

        Args:
            policy_yaml: YAML string containing policy definitions.
        """
        rules = self._parse_policy_yaml(policy_yaml)
        self._rules = rules
        logger.info("Loaded %d rules from string input", len(rules))

    def evaluate(
        self,
        request: TransactionRequest,
        agent: AgentIdentity,
        risk_score: RiskScore,
    ) -> PolicyDecision:
        """
        Evaluate all loaded policies against a transaction request.

        Evaluation order:
          1. DENY rules (if any match, decision is DENY immediately)
          2. REQUIRE_APPROVAL rules
          3. STEP_UP rules
          4. ALLOW rules
          5. Default: DENY (fail-closed)

        Args:
            request: The transaction request to evaluate.
            agent: The agent identity making the request.
            risk_score: The computed risk score for this transaction.

        Returns:
            A PolicyDecision with the determined effect and matched rules.
        """
        if not self._rules:
            logger.warning("No policies loaded, defaulting to DENY (fail-closed)")
            return PolicyDecision(
                effect=PolicyEffect.DENY,
                matched_rules=[],
                explanation="No policies loaded; fail-closed default applies",
            )

        context = self._build_evaluation_context(request, agent, risk_score)

        # Sort rules by priority (descending) within each effect group
        deny_rules = sorted(
            [r for r in self._rules if r.effect == PolicyEffect.DENY],
            key=lambda r: r.priority,
            reverse=True,
        )
        approval_rules = sorted(
            [r for r in self._rules if r.effect == PolicyEffect.REQUIRE_APPROVAL],
            key=lambda r: r.priority,
            reverse=True,
        )
        step_up_rules = sorted(
            [r for r in self._rules if r.effect == PolicyEffect.STEP_UP],
            key=lambda r: r.priority,
            reverse=True,
        )
        allow_rules = sorted(
            [r for r in self._rules if r.effect == PolicyEffect.ALLOW],
            key=lambda r: r.priority,
            reverse=True,
        )

        # Phase 1: Check explicit denies
        matched_denies = [
            r.name for r in deny_rules if self._match_rule(r, request, agent, context)
        ]
        if matched_denies:
            explanation = (
                f"Request denied by {len(matched_denies)} policy rule(s): "
                f"{', '.join(matched_denies)}"
            )
            logger.info(
                "Policy DENY for agent=%s action=%s: %s",
                request.agent_id,
                request.action,
                explanation,
            )
            return PolicyDecision(
                effect=PolicyEffect.DENY,
                matched_rules=matched_denies,
                explanation=explanation,
            )

        # Phase 2: Check require_approval
        matched_approvals = [
            r.name
            for r in approval_rules
            if self._match_rule(r, request, agent, context)
        ]
        if matched_approvals:
            explanation = (
                f"Approval required by {len(matched_approvals)} policy rule(s): "
                f"{', '.join(matched_approvals)}"
            )
            logger.info(
                "Policy REQUIRE_APPROVAL for agent=%s action=%s: %s",
                request.agent_id,
                request.action,
                explanation,
            )
            return PolicyDecision(
                effect=PolicyEffect.REQUIRE_APPROVAL,
                matched_rules=matched_approvals,
                explanation=explanation,
            )

        # Phase 3: Check step_up
        matched_step_ups = [
            r.name
            for r in step_up_rules
            if self._match_rule(r, request, agent, context)
        ]
        if matched_step_ups:
            explanation = (
                f"Step-up authentication required by {len(matched_step_ups)} rule(s): "
                f"{', '.join(matched_step_ups)}"
            )
            logger.info(
                "Policy STEP_UP for agent=%s action=%s: %s",
                request.agent_id,
                request.action,
                explanation,
            )
            return PolicyDecision(
                effect=PolicyEffect.STEP_UP,
                matched_rules=matched_step_ups,
                explanation=explanation,
            )

        # Phase 4: Check explicit allows
        matched_allows = [
            r.name
            for r in allow_rules
            if self._match_rule(r, request, agent, context)
        ]
        if matched_allows:
            explanation = (
                f"Request allowed by {len(matched_allows)} policy rule(s): "
                f"{', '.join(matched_allows)}"
            )
            logger.debug(
                "Policy ALLOW for agent=%s action=%s: %s",
                request.agent_id,
                request.action,
                explanation,
            )
            return PolicyDecision(
                effect=PolicyEffect.ALLOW,
                matched_rules=matched_allows,
                explanation=explanation,
            )

        # Phase 5: No rule matched, default DENY
        explanation = (
            "No policy rule matched the request; fail-closed default applies"
        )
        logger.info(
            "Policy default DENY for agent=%s action=%s (no matching rules)",
            request.agent_id,
            request.action,
        )
        return PolicyDecision(
            effect=PolicyEffect.DENY,
            matched_rules=[],
            explanation=explanation,
        )

    def validate_policy(self, policy_yaml: str) -> list[str]:
        """
        Validate a YAML policy string for structural correctness.

        Checks for required fields, valid effect values, and well-formed
        conditions without loading the policy into the engine.

        Args:
            policy_yaml: YAML string to validate.

        Returns:
            A list of validation error strings. Empty list means valid.
        """
        errors: list[str] = []

        try:
            data = yaml.safe_load(policy_yaml)
        except yaml.YAMLError as exc:
            errors.append(f"YAML parse error: {exc}")
            return errors

        if not isinstance(data, dict):
            errors.append("Policy must be a YAML mapping (dict) at the top level")
            return errors

        # Check version field
        if "version" not in data:
            errors.append("Missing required field: 'version'")

        # Check policies list
        policies = data.get("policies", [])
        if not isinstance(policies, list):
            errors.append("'policies' must be a list")
            return errors

        if not policies:
            errors.append("'policies' list is empty")

        valid_effects = {"deny", "allow", "require_approval", "step_up"}

        for idx, policy in enumerate(policies):
            prefix = f"policies[{idx}]"

            if not isinstance(policy, dict):
                errors.append(f"{prefix}: must be a mapping")
                continue

            # Required: name
            if "name" not in policy:
                errors.append(f"{prefix}: missing required field 'name'")
            elif not isinstance(policy["name"], str) or not policy["name"].strip():
                errors.append(f"{prefix}: 'name' must be a non-empty string")

            # Required: effect
            if "effect" not in policy:
                errors.append(f"{prefix}: missing required field 'effect'")
            elif str(policy["effect"]).lower() not in valid_effects:
                errors.append(
                    f"{prefix}: invalid effect '{policy['effect']}'. "
                    f"Must be one of: {', '.join(sorted(valid_effects))}"
                )

            # Optional list fields validation
            for list_field in ("actions", "resources", "agents", "environments"):
                if list_field in policy:
                    if not isinstance(policy[list_field], list):
                        errors.append(
                            f"{prefix}: '{list_field}' must be a list"
                        )
                    elif not policy[list_field]:
                        errors.append(
                            f"{prefix}: '{list_field}' cannot be an empty list"
                        )

            # Conditions validation
            if "conditions" in policy:
                if not isinstance(policy["conditions"], dict):
                    errors.append(f"{prefix}: 'conditions' must be a mapping")
                else:
                    self._validate_conditions(
                        policy["conditions"], f"{prefix}.conditions", errors
                    )

            # Priority validation
            if "priority" in policy:
                if not isinstance(policy["priority"], int):
                    errors.append(f"{prefix}: 'priority' must be an integer")

        return errors

    def diff_policies(
        self, old_version: PolicyVersion, new_version: PolicyVersion
    ) -> PolicyDiff:
        """
        Compute the difference between two policy versions.

        Identifies added, removed, and modified rules, and provides a
        risk assessment of the change.

        Args:
            old_version: The previous policy version.
            new_version: The new policy version.

        Returns:
            A PolicyDiff describing the changes and risk assessment.
        """
        old_rules_by_name = {r.name: r for r in old_version.rules}
        new_rules_by_name = {r.name: r for r in new_version.rules}

        old_names = set(old_rules_by_name.keys())
        new_names = set(new_rules_by_name.keys())

        added = sorted(new_names - old_names)
        removed = sorted(old_names - new_names)

        modified: list[str] = []
        for name in sorted(old_names & new_names):
            if old_rules_by_name[name].to_dict() != new_rules_by_name[name].to_dict():
                modified.append(name)

        # Risk assessment
        risk_factors: list[str] = []
        if removed:
            deny_removed = [
                n for n in removed
                if old_rules_by_name[n].effect == PolicyEffect.DENY
            ]
            if deny_removed:
                risk_factors.append(
                    f"CRITICAL: {len(deny_removed)} DENY rule(s) removed: "
                    f"{', '.join(deny_removed)}"
                )
            else:
                risk_factors.append(
                    f"WARNING: {len(removed)} rule(s) removed"
                )

        if modified:
            deny_modified = [
                n for n in modified
                if old_rules_by_name[n].effect == PolicyEffect.DENY
            ]
            if deny_modified:
                risk_factors.append(
                    f"HIGH: {len(deny_modified)} DENY rule(s) modified: "
                    f"{', '.join(deny_modified)}"
                )

        if added:
            allow_added = [
                n for n in added
                if new_rules_by_name[n].effect == PolicyEffect.ALLOW
            ]
            if allow_added:
                risk_factors.append(
                    f"MEDIUM: {len(allow_added)} new ALLOW rule(s) added"
                )

        risk_assessment = "; ".join(risk_factors) if risk_factors else "LOW: No risky changes detected"

        return PolicyDiff(
            added_rules=added,
            removed_rules=removed,
            modified_rules=modified,
            risk_assessment=risk_assessment,
        )

    def test_policy(
        self, policy_yaml: str, test_cases: list[TestCase]
    ) -> TestResult:
        """
        Run test cases against a policy to verify expected behavior.

        Temporarily loads the policy, evaluates each test case, and
        reports pass/fail results without modifying the engine's active rules.

        Args:
            policy_yaml: The YAML policy string to test.
            test_cases: List of test cases with expected outcomes.

        Returns:
            A TestResult summarizing pass/fail counts and failure details.
        """
        # Save current state
        original_rules = self._rules

        try:
            # Load the test policy
            test_rules = self._parse_policy_yaml(policy_yaml)
            self._rules = test_rules

            result = TestResult(total=len(test_cases))

            for test_case in test_cases:
                decision = self.evaluate(
                    test_case.request, test_case.agent, test_case.risk_score
                )

                if decision.effect == test_case.expected_effect:
                    result.passed += 1
                else:
                    result.failed += 1
                    result.failures.append({
                        "test_name": test_case.name,
                        "expected": test_case.expected_effect.value,
                        "actual": decision.effect.value,
                        "matched_rules": decision.matched_rules,
                        "explanation": decision.explanation,
                    })

            return result

        finally:
            # Restore original state
            self._rules = original_rules

    # --- Private Methods ---

    def _match_rule(
        self,
        rule: PolicyRule,
        request: TransactionRequest,
        agent: AgentIdentity,
        context: dict[str, Any],
    ) -> bool:
        """
        Determine if a policy rule matches the given request context.

        A rule matches only if ALL of its criteria are satisfied:
          - Action matches one of the rule's action patterns
          - Resource matches one of the rule's resource patterns
          - Agent matches one of the rule's agent patterns
          - Environment matches one of the rule's environment list
          - All conditions evaluate to true

        Args:
            rule: The policy rule to test.
            request: The transaction request.
            agent: The agent identity.
            context: Pre-built evaluation context with derived values.

        Returns:
            True if the rule matches the request; False otherwise.
        """
        # Check action match
        if not self._matches_any_pattern(request.action, rule.actions):
            return False

        # Check resource match
        if not self._matches_any_pattern(request.resource, rule.resources):
            return False

        # Check agent match
        if not self._matches_any_pattern(request.agent_id, rule.agents):
            return False

        # Check environment match
        agent_env = agent.environment.value.lower()
        env_patterns = [e.lower() for e in rule.environments]
        if "*" not in env_patterns and agent_env not in env_patterns:
            return False

        # Check conditions
        if rule.conditions:
            if not self._evaluate_conditions(rule.conditions, context):
                return False

        return True

    def _evaluate_conditions(
        self, conditions: dict[str, Any], context: dict[str, Any]
    ) -> bool:
        """
        Evaluate all conditions in a rule against the evaluation context.

        Supported condition types:
          - risk_score_above: Overall risk score must exceed this threshold
          - risk_score_below: Overall risk score must be below this threshold
          - data_classification_in: Data classification must be in the given list
          - time_window: Current hour must be within start/end (UTC)
          - agent_type_in: Agent type must be in the given list
          - require_tag: Agent must have the specified tag key

        Args:
            conditions: Dictionary of condition_name -> threshold/value.
            context: Evaluation context with computed values.

        Returns:
            True if all conditions are satisfied; False otherwise.
        """
        for condition_name, condition_value in conditions.items():
            if condition_name == "risk_score_above":
                if context.get("risk_score_overall", 0) <= float(condition_value):
                    return False

            elif condition_name == "risk_score_below":
                if context.get("risk_score_overall", 0) >= float(condition_value):
                    return False

            elif condition_name == "data_classification_in":
                classifications = (
                    condition_value
                    if isinstance(condition_value, list)
                    else [condition_value]
                )
                if context.get("data_classification", "").upper() not in [
                    c.upper() for c in classifications
                ]:
                    return False

            elif condition_name == "time_window":
                if isinstance(condition_value, dict):
                    start_hour = condition_value.get("start", 0)
                    end_hour = condition_value.get("end", 24)
                    current_hour = context.get("current_hour", 0)
                    if not (start_hour <= current_hour < end_hour):
                        return False

            elif condition_name == "agent_type_in":
                agent_types = (
                    condition_value
                    if isinstance(condition_value, list)
                    else [condition_value]
                )
                if context.get("agent_type", "").upper() not in [
                    t.upper() for t in agent_types
                ]:
                    return False

            elif condition_name == "require_tag":
                tags = context.get("agent_tags", {})
                if isinstance(condition_value, str):
                    if condition_value not in tags:
                        return False
                elif isinstance(condition_value, dict):
                    for tag_key, tag_val in condition_value.items():
                        if tags.get(tag_key) != tag_val:
                            return False

            else:
                logger.warning(
                    "Unknown condition type '%s' in policy evaluation",
                    condition_name,
                )
                # Unknown conditions fail-closed (do not match)
                return False

        return True

    def _build_evaluation_context(
        self,
        request: TransactionRequest,
        agent: AgentIdentity,
        risk_score: RiskScore,
    ) -> dict[str, Any]:
        """
        Build the evaluation context used for condition checks.

        Args:
            request: The transaction request.
            agent: The agent identity.
            risk_score: The computed risk score.

        Returns:
            A flat dictionary of contextual values for condition evaluation.
        """
        now = datetime.now(timezone.utc)
        return {
            "risk_score_overall": risk_score.overall,
            "risk_score_privilege": risk_score.privilege,
            "risk_score_sensitivity": risk_score.sensitivity,
            "risk_score_blast_radius": risk_score.blast_radius,
            "risk_score_data_exposure": risk_score.data_exposure,
            "risk_score_persistence": risk_score.persistence,
            "risk_score_lateral_movement": risk_score.lateral_movement,
            "data_classification": request.data_classification.value,
            "agent_type": agent.agent_type.value,
            "agent_environment": agent.environment.value,
            "agent_tags": agent.tags,
            "current_hour": now.hour,
            "current_day": now.strftime("%A").lower(),
            "request_context": request.context,
        }

    def _matches_any_pattern(self, value: str, patterns: list[str]) -> bool:
        """
        Check if a value matches any of the given glob patterns.

        Case-insensitive matching using fnmatch-style wildcards.

        Args:
            value: The value to match.
            patterns: List of patterns to match against.

        Returns:
            True if any pattern matches; False otherwise.
        """
        value_lower = value.lower()
        for pattern in patterns:
            pattern_lower = pattern.lower()
            if pattern_lower == "*":
                return True
            if fnmatch.fnmatch(value_lower, pattern_lower):
                return True
        return False

    def _parse_policy_file(self, file_path: Path) -> list[PolicyRule]:
        """
        Parse a single YAML policy file into PolicyRule objects.

        Args:
            file_path: Path to the YAML file.

        Returns:
            List of PolicyRule objects parsed from the file.

        Raises:
            ValueError: If the file structure is invalid.
        """
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return self._parse_policy_yaml(content, source=str(file_path))

    def _parse_policy_yaml(
        self, yaml_content: str, source: str = "<string>"
    ) -> list[PolicyRule]:
        """
        Parse YAML policy content into PolicyRule objects.

        Args:
            yaml_content: YAML string to parse.
            source: Source identifier for error messages.

        Returns:
            List of PolicyRule objects.

        Raises:
            ValueError: If the YAML structure is invalid.
        """
        try:
            data = yaml.safe_load(yaml_content)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML in {source}: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError(
                f"Policy file {source} must contain a YAML mapping at top level"
            )

        policies = data.get("policies", [])
        if not isinstance(policies, list):
            raise ValueError(
                f"'policies' in {source} must be a list"
            )

        rules: list[PolicyRule] = []
        for idx, policy_data in enumerate(policies):
            if not isinstance(policy_data, dict):
                raise ValueError(
                    f"policies[{idx}] in {source} must be a mapping"
                )
            if "name" not in policy_data:
                raise ValueError(
                    f"policies[{idx}] in {source} is missing required field 'name'"
                )
            if "effect" not in policy_data:
                raise ValueError(
                    f"policies[{idx}] in {source} is missing required field 'effect'"
                )

            try:
                rule = PolicyRule.from_dict(policy_data)
                rules.append(rule)
            except (ValueError, KeyError) as exc:
                raise ValueError(
                    f"Error parsing policies[{idx}] '{policy_data.get('name', '?')}' "
                    f"in {source}: {exc}"
                ) from exc

        return rules

    def _extract_version(self, policy_files: list[Path]) -> str:
        """
        Extract version from the first policy file that declares one.

        Args:
            policy_files: List of policy file paths.

        Returns:
            The version string, or "1.0.0" if none found.
        """
        for policy_file in policy_files:
            try:
                with open(policy_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if isinstance(data, dict) and "version" in data:
                    return str(data["version"])
            except Exception:
                continue
        return "1.0.0"

    def _validate_conditions(
        self,
        conditions: dict[str, Any],
        prefix: str,
        errors: list[str],
    ) -> None:
        """
        Validate condition definitions within a policy rule.

        Args:
            conditions: The conditions dictionary to validate.
            prefix: Error message prefix for context.
            errors: List to append validation errors to.
        """
        known_conditions = {
            "risk_score_above",
            "risk_score_below",
            "data_classification_in",
            "time_window",
            "agent_type_in",
            "require_tag",
        }

        for key, value in conditions.items():
            if key not in known_conditions:
                errors.append(
                    f"{prefix}: unknown condition '{key}'. "
                    f"Known conditions: {', '.join(sorted(known_conditions))}"
                )

            if key in ("risk_score_above", "risk_score_below"):
                if not isinstance(value, (int, float)):
                    errors.append(
                        f"{prefix}.{key}: must be a number, got {type(value).__name__}"
                    )
                elif not (0 <= value <= 100):
                    errors.append(
                        f"{prefix}.{key}: must be between 0 and 100, got {value}"
                    )

            if key == "time_window":
                if not isinstance(value, dict):
                    errors.append(f"{prefix}.{key}: must be a mapping with 'start' and 'end'")
                elif "start" not in value or "end" not in value:
                    errors.append(f"{prefix}.{key}: must contain 'start' and 'end' keys")
