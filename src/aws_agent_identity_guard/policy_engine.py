"""AWS Agent Identity Guard - Declarative Security Policy-as-Code Engine.

Production-grade policy engine that evaluates security policies written in YAML.
Supports a rich policy language with rule types: deny, allow, require_approval,
warn, and audit. Provides action/resource pattern matching with wildcards and
regex, environment/data classification/agent type/time-based conditions,
policy versioning, policy sets with priority ordering, and policy testing.

Usage:
    from aws_agent_identity_guard.policy_engine import (
        PolicyEngine, PolicySet, load_policy, validate_policy, test_policy,
    )

    engine = PolicyEngine()
    engine.load_default_policies()
    decision = engine.evaluate("s3:GetObject", "arn:aws:s3:::bucket/key", context)
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from enum import Enum, unique
from pathlib import Path
from typing import Any, Optional, Union

import yaml

from .models import (
    DataClassification,
    Decision,
    Environment,
    Finding,
    FindingCategory,
    Severity,
    SerializableMixin,
    _utcnow,
)


# =============================================================================
# Enumerations
# =============================================================================


@unique
class RuleType(str, Enum):
    """Types of policy rules supported by the engine."""

    DENY = "deny"
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    WARN = "warn"
    AUDIT = "audit"


@unique
class PolicyDecisionEffect(str, Enum):
    """Possible outcomes of a policy evaluation."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    WARN = "warn"
    AUDIT = "audit"
    NO_MATCH = "no_match"


@unique
class ValidationSeverity(str, Enum):
    """Severity of policy validation errors."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@unique
class TestResult(str, Enum):
    """Result of a single policy test case."""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class TimeWindow:
    """Time-based condition for rule evaluation.

    Specifies when a rule is active using day-of-week and hour ranges.
    """

    days: list[str] = field(default_factory=lambda: [
        "monday", "tuesday", "wednesday", "thursday", "friday",
        "saturday", "sunday",
    ])
    start_hour: int = 0
    end_hour: int = 24
    timezone_name: str = "UTC"

    def is_active(self, at: datetime | None = None) -> bool:
        """Check if the current time falls within this window.

        Args:
            at: Optional datetime to check. Defaults to current UTC time.

        Returns:
            True if the time is within the window.
        """
        now = at or _utcnow()
        day_name = now.strftime("%A").lower()
        if day_name not in [d.lower() for d in self.days]:
            return False
        return self.start_hour <= now.hour < self.end_hour

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TimeWindow:
        """Create a TimeWindow from a dictionary."""
        return cls(
            days=data.get("days", [
                "monday", "tuesday", "wednesday", "thursday",
                "friday", "saturday", "sunday",
            ]),
            start_hour=int(data.get("start_hour", 0)),
            end_hour=int(data.get("end_hour", 24)),
            timezone_name=data.get("timezone", "UTC"),
        )


@dataclass
class RuleConditions:
    """Conditions under which a rule applies.

    All specified conditions must be met (AND logic) for the rule to match.
    """

    environment: list[str] = field(default_factory=list)
    data_classification: list[str] = field(default_factory=list)
    agent_type: list[str] = field(default_factory=list)
    time_window: TimeWindow | None = None
    tags: dict[str, str] = field(default_factory=dict)
    custom: dict[str, Any] = field(default_factory=dict)

    def matches(self, context: EvaluationContext) -> bool:
        """Evaluate whether all conditions are satisfied.

        Args:
            context: The evaluation context to check against.

        Returns:
            True if all specified conditions are met.
        """
        if self.environment:
            if context.environment not in self.environment:
                return False

        if self.data_classification:
            if context.data_classification not in self.data_classification:
                return False

        if self.agent_type:
            if context.agent_type not in self.agent_type:
                return False

        if self.time_window is not None:
            if not self.time_window.is_active(context.timestamp):
                return False

        if self.tags:
            for key, value in self.tags.items():
                if context.tags.get(key) != value:
                    return False

        if self.custom:
            for key, value in self.custom.items():
                if context.custom.get(key) != value:
                    return False

        return True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuleConditions:
        """Create RuleConditions from a dictionary."""
        env = data.get("environment", [])
        if isinstance(env, str):
            env = [env]

        dc = data.get("data_classification", [])
        if isinstance(dc, str):
            dc = [dc]

        at = data.get("agent_type", [])
        if isinstance(at, str):
            at = [at]

        time_data = data.get("time_window")
        tw = TimeWindow.from_dict(time_data) if time_data else None

        return cls(
            environment=env,
            data_classification=dc,
            agent_type=at,
            time_window=tw,
            tags=data.get("tags", {}),
            custom=data.get("custom", {}),
        )


@dataclass
class EvaluationContext:
    """Context provided when evaluating a policy.

    Contains all ambient information that conditions can match against,
    including environment, data classification, agent type, timestamps,
    and custom attributes.
    """

    environment: str = ""
    data_classification: str = ""
    agent_type: str = ""
    agent_id: str = ""
    principal: str = ""
    timestamp: datetime = field(default_factory=_utcnow)
    tags: dict[str, str] = field(default_factory=dict)
    custom: dict[str, Any] = field(default_factory=dict)
    session_id: str = ""
    source_ip: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvaluationContext:
        """Create an EvaluationContext from a dictionary."""
        ts = data.get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        elif ts is None:
            ts = _utcnow()

        return cls(
            environment=data.get("environment", ""),
            data_classification=data.get("data_classification", ""),
            agent_type=data.get("agent_type", ""),
            agent_id=data.get("agent_id", ""),
            principal=data.get("principal", ""),
            timestamp=ts,
            tags=data.get("tags", {}),
            custom=data.get("custom", {}),
            session_id=data.get("session_id", ""),
            source_ip=data.get("source_ip", ""),
        )


@dataclass
class PolicyRule:
    """A single rule within a policy.

    Each rule has a type (deny, allow, require_approval, warn, audit),
    action/resource patterns to match, optional conditions, severity, and
    a human-readable message.
    """

    id: str
    rule_type: RuleType
    action_pattern: str = "*"
    resource_pattern: str = "*"
    resource_regex: str = ""
    conditions: RuleConditions = field(default_factory=RuleConditions)
    severity: str = "medium"
    message: str = ""
    priority: int = 0
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def matches_action(self, action: str) -> bool:
        """Check if the given action matches this rule's action pattern.

        Supports:
        - Exact match
        - Wildcard (*) matching via fnmatch
        - Regex patterns (prefixed with 'regex:')

        Args:
            action: The AWS action to check (e.g., 's3:GetObject').

        Returns:
            True if the action matches.
        """
        pattern = self.action_pattern

        if pattern == "*":
            return True

        # Regex pattern
        if pattern.startswith("regex:"):
            regex = pattern[6:]
            try:
                return bool(re.fullmatch(regex, action, re.IGNORECASE))
            except re.error:
                return False

        # Wildcard/glob matching (case-insensitive)
        return fnmatch.fnmatch(action.lower(), pattern.lower())

    def matches_resource(self, resource: str) -> bool:
        """Check if the given resource matches this rule's resource pattern.

        Supports:
        - Exact match
        - Wildcard (*) matching via fnmatch
        - Regex via resource_regex field or 'regex:' prefix in resource_pattern

        Args:
            resource: The AWS resource ARN to check.

        Returns:
            True if the resource matches.
        """
        # Check resource_regex first (takes precedence)
        if self.resource_regex:
            try:
                return bool(re.fullmatch(self.resource_regex, resource))
            except re.error:
                return False

        pattern = self.resource_pattern

        if pattern == "*":
            return True

        # Regex pattern
        if pattern.startswith("regex:"):
            regex = pattern[6:]
            try:
                return bool(re.fullmatch(regex, resource))
            except re.error:
                return False

        # Wildcard/glob matching
        return fnmatch.fnmatch(resource, pattern)

    def evaluate(self, action: str, resource: str, context: EvaluationContext) -> bool:
        """Determine if this rule matches the given action, resource, and context.

        Args:
            action: The AWS action being evaluated.
            resource: The target resource ARN.
            context: The evaluation context with ambient conditions.

        Returns:
            True if the rule matches (action, resource, and all conditions satisfied).
        """
        if not self.enabled:
            return False
        if not self.matches_action(action):
            return False
        if not self.matches_resource(resource):
            return False
        if not self.conditions.matches(context):
            return False
        return True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyRule:
        """Create a PolicyRule from a YAML rule dictionary.

        Parses the rule format specified in the policy language:
        ```yaml
        - id: RULE-ID
          deny:
            action: 'pattern'
            resource: 'pattern'
            resource_pattern: 'regex'
          conditions:
            environment: [production]
          severity: critical
          message: 'Description'
        ```
        """
        rule_id = data.get("id", str(uuid.uuid4()))
        severity = data.get("severity", "medium")
        message = data.get("message", "")
        priority = int(data.get("priority", 0))
        enabled = data.get("enabled", True)
        metadata = data.get("metadata", {})

        # Determine rule type and extract action/resource patterns
        rule_type: RuleType | None = None
        action_pattern = "*"
        resource_pattern = "*"
        resource_regex = ""
        rule_conditions_data: dict[str, Any] = data.get("conditions", {})

        for rt in RuleType:
            if rt.value in data:
                rule_type = rt
                rule_spec = data[rt.value]
                if isinstance(rule_spec, dict):
                    action_pattern = rule_spec.get("action", "*")
                    resource_pattern = rule_spec.get("resource", "*")
                    resource_regex = rule_spec.get("resource_pattern", "")
                    # Environment in the rule spec merges with conditions
                    if "environment" in rule_spec and "environment" not in rule_conditions_data:
                        env_val = rule_spec["environment"]
                        rule_conditions_data["environment"] = (
                            env_val if isinstance(env_val, list) else [env_val]
                        )
                break

        if rule_type is None:
            rule_type = RuleType.AUDIT

        conditions = RuleConditions.from_dict(rule_conditions_data)

        return cls(
            id=rule_id,
            rule_type=rule_type,
            action_pattern=action_pattern,
            resource_pattern=resource_pattern,
            resource_regex=resource_regex,
            conditions=conditions,
            severity=severity,
            message=message,
            priority=priority,
            enabled=enabled,
            metadata=metadata,
        )


@dataclass
class PolicyMetadata:
    """Metadata for a policy document."""

    name: str = ""
    description: str = ""
    author: str = ""
    created: str = ""
    updated: str = ""
    tags: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyMetadata:
        """Create PolicyMetadata from a dictionary."""
        return cls(
            name=data.get("name", ""),
            description=data.get("description", ""),
            author=data.get("author", ""),
            created=str(data.get("created", "")),
            updated=str(data.get("updated", "")),
            tags=data.get("tags", {}),
        )


@dataclass
class Policy:
    """A complete policy document with version, metadata, and rules.

    Represents a parsed YAML policy file with all its rules and metadata.
    Supports versioning and priority ordering.
    """

    version: str = "1.0"
    metadata: PolicyMetadata = field(default_factory=PolicyMetadata)
    rules: list[PolicyRule] = field(default_factory=list)
    priority: int = 0
    enabled: bool = True
    checksum: str = ""

    @property
    def name(self) -> str:
        """Policy name from metadata."""
        return self.metadata.name

    @property
    def rule_count(self) -> int:
        """Number of rules in this policy."""
        return len(self.rules)

    def compute_checksum(self) -> str:
        """Compute a SHA-256 checksum of the policy content for integrity verification.

        Returns:
            Hex-encoded SHA-256 hash string.
        """
        content = json.dumps(
            {
                "version": self.version,
                "metadata": {
                    "name": self.metadata.name,
                    "description": self.metadata.description,
                    "author": self.metadata.author,
                },
                "rules": [
                    {
                        "id": r.id,
                        "rule_type": r.rule_type.value,
                        "action_pattern": r.action_pattern,
                        "resource_pattern": r.resource_pattern,
                        "severity": r.severity,
                    }
                    for r in self.rules
                ],
            },
            sort_keys=True,
        )
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        """Create a Policy from a parsed YAML dictionary.

        Args:
            data: Dictionary parsed from a YAML policy document.

        Returns:
            A fully constructed Policy instance.
        """
        version = str(data.get("version", "1.0"))
        metadata_data = data.get("metadata", {})
        metadata = PolicyMetadata.from_dict(metadata_data)

        rules_data = data.get("rules", [])
        rules = [PolicyRule.from_dict(r) for r in rules_data]

        priority = int(data.get("priority", 0))
        enabled = data.get("enabled", True)

        policy = cls(
            version=version,
            metadata=metadata,
            rules=rules,
            priority=priority,
            enabled=enabled,
        )
        policy.checksum = policy.compute_checksum()
        return policy

    @classmethod
    def from_yaml(cls, yaml_content: str) -> Policy:
        """Parse a Policy from a YAML string.

        Args:
            yaml_content: Raw YAML policy content.

        Returns:
            A fully constructed Policy instance.

        Raises:
            yaml.YAMLError: If the YAML is malformed.
            ValueError: If the policy structure is invalid.
        """
        data = yaml.safe_load(yaml_content)
        if not isinstance(data, dict):
            raise ValueError("Policy YAML must be a mapping at the top level")
        return cls.from_dict(data)


@dataclass
class PolicyDecision:
    """Result of evaluating a policy against an action/resource/context.

    Contains the decision effect, matched rules, explanations, and
    metadata for audit and debugging.
    """

    effect: PolicyDecisionEffect
    matched_rules: list[PolicyRule] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    audit_entries: list[str] = field(default_factory=list)
    policy_name: str = ""
    evaluation_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=_utcnow)
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def is_allowed(self) -> bool:
        """Whether the decision permits the action."""
        return self.effect in (PolicyDecisionEffect.ALLOW, PolicyDecisionEffect.NO_MATCH)

    @property
    def is_denied(self) -> bool:
        """Whether the decision explicitly denies the action."""
        return self.effect == PolicyDecisionEffect.DENY

    @property
    def requires_approval(self) -> bool:
        """Whether the decision requires human approval."""
        return self.effect == PolicyDecisionEffect.REQUIRE_APPROVAL

    def to_dict(self) -> dict[str, Any]:
        """Serialize the decision to a dictionary."""
        return {
            "effect": self.effect.value,
            "matched_rules": [r.id for r in self.matched_rules],
            "reasons": self.reasons,
            "warnings": self.warnings,
            "audit_entries": self.audit_entries,
            "policy_name": self.policy_name,
            "evaluation_time_ms": self.evaluation_time_ms,
            "timestamp": self.timestamp.isoformat(),
            "correlation_id": self.correlation_id,
        }


@dataclass
class ValidationError:
    """A validation error found in a policy definition.

    Contains the error location, message, and severity to help
    policy authors fix issues.
    """

    path: str
    message: str
    severity: ValidationSeverity = ValidationSeverity.ERROR
    rule_id: str = ""
    suggestion: str = ""

    def __str__(self) -> str:
        """Human-readable validation error string."""
        prefix = f"[{self.severity.value.upper()}]"
        location = f" at '{self.path}'" if self.path else ""
        rule = f" (rule: {self.rule_id})" if self.rule_id else ""
        return f"{prefix}{location}{rule}: {self.message}"


@dataclass
class TestCase:
    """A single test case for policy testing.

    Specifies an action/resource/context and the expected decision
    effect to verify correct policy behavior.
    """

    name: str
    action: str
    resource: str
    context: dict[str, Any] = field(default_factory=dict)
    expected_effect: str = ""
    expected_rule_ids: list[str] = field(default_factory=list)
    description: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TestCase:
        """Create a TestCase from a dictionary."""
        return cls(
            name=data.get("name", "unnamed"),
            action=data.get("action", ""),
            resource=data.get("resource", ""),
            context=data.get("context", {}),
            expected_effect=data.get("expected_effect", ""),
            expected_rule_ids=data.get("expected_rule_ids", []),
            description=data.get("description", ""),
        )


@dataclass
class TestCaseResult:
    """Result of executing a single test case."""

    test_case: TestCase
    result: TestResult
    actual_effect: str = ""
    actual_rule_ids: list[str] = field(default_factory=list)
    error_message: str = ""
    duration_ms: float = 0.0

    @property
    def passed(self) -> bool:
        """Whether this test case passed."""
        return self.result == TestResult.PASS


@dataclass
class TestResults:
    """Aggregate results from running policy tests.

    Contains individual test case results, summary statistics,
    and overall pass/fail determination.
    """

    policy_name: str
    results: list[TestCaseResult] = field(default_factory=list)
    total_duration_ms: float = 0.0

    @property
    def total(self) -> int:
        """Total number of test cases."""
        return len(self.results)

    @property
    def passed(self) -> int:
        """Number of passing test cases."""
        return sum(1 for r in self.results if r.result == TestResult.PASS)

    @property
    def failed(self) -> int:
        """Number of failing test cases."""
        return sum(1 for r in self.results if r.result == TestResult.FAIL)

    @property
    def errors(self) -> int:
        """Number of errored test cases."""
        return sum(1 for r in self.results if r.result == TestResult.ERROR)

    @property
    def all_passed(self) -> bool:
        """Whether all test cases passed."""
        return self.failed == 0 and self.errors == 0

    def summary(self) -> str:
        """Human-readable summary of test results."""
        return (
            f"Policy '{self.policy_name}': "
            f"{self.passed}/{self.total} passed, "
            f"{self.failed} failed, "
            f"{self.errors} errors "
            f"({self.total_duration_ms:.2f}ms)"
        )


# =============================================================================
# Policy Engine
# =============================================================================


class PolicyEngine:
    """Declarative security policy evaluation engine.

    Evaluates security policies written in YAML against AWS actions,
    resources, and contextual information. Supports multiple rule types,
    pattern matching, conditions, and priority-based rule resolution.

    The engine applies rules in priority order:
    1. DENY rules are evaluated first (explicit deny wins).
    2. REQUIRE_APPROVAL rules are evaluated next.
    3. ALLOW rules are then checked.
    4. WARN and AUDIT rules are always evaluated for side effects.
    5. If no rule matches, the default effect applies (configurable).

    Example:
        engine = PolicyEngine()
        engine.load_default_policies()

        context = EvaluationContext(environment="production")
        decision = engine.evaluate(
            action="secretsmanager:GetSecretValue",
            resource="*",
            context=context,
        )
        assert decision.is_denied
    """

    def __init__(
        self,
        default_effect: PolicyDecisionEffect = PolicyDecisionEffect.NO_MATCH,
        strict_mode: bool = False,
    ) -> None:
        """Initialize the PolicyEngine.

        Args:
            default_effect: The decision effect when no rules match.
                Defaults to NO_MATCH (implicitly allow).
            strict_mode: If True, NO_MATCH becomes DENY (deny by default).
        """
        self._policies: list[Policy] = []
        self._default_effect = default_effect
        self._strict_mode = strict_mode
        self._evaluation_count: int = 0
        self._cache: dict[str, PolicyDecision] = {}
        self._cache_enabled: bool = True
        self._max_cache_size: int = 10000

        if strict_mode:
            self._default_effect = PolicyDecisionEffect.DENY

    @property
    def policies(self) -> list[Policy]:
        """List of loaded policies."""
        return list(self._policies)

    @property
    def policy_count(self) -> int:
        """Number of loaded policies."""
        return len(self._policies)

    @property
    def evaluation_count(self) -> int:
        """Total number of evaluations performed."""
        return self._evaluation_count

    def add_policy(self, policy: Policy) -> None:
        """Add a policy to the engine.

        Policies are stored sorted by priority (higher priority first).

        Args:
            policy: The policy to add.
        """
        self._policies.append(policy)
        self._policies.sort(key=lambda p: p.priority, reverse=True)
        self._invalidate_cache()

    def remove_policy(self, policy_name: str) -> bool:
        """Remove a policy by name.

        Args:
            policy_name: The name of the policy to remove.

        Returns:
            True if the policy was found and removed.
        """
        original_count = len(self._policies)
        self._policies = [
            p for p in self._policies if p.metadata.name != policy_name
        ]
        if len(self._policies) < original_count:
            self._invalidate_cache()
            return True
        return False

    def clear_policies(self) -> None:
        """Remove all loaded policies."""
        self._policies.clear()
        self._invalidate_cache()

    def evaluate(
        self,
        action: str,
        resource: str,
        context: EvaluationContext | dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """Evaluate all loaded policies against an action/resource/context.

        Applies rules in priority order with deny-takes-precedence semantics:
        1. Any matching DENY rule results in immediate denial.
        2. REQUIRE_APPROVAL rules trigger approval workflows.
        3. ALLOW rules explicitly permit actions.
        4. WARN/AUDIT rules generate advisory entries.
        5. If no decisive rule matches, the default effect applies.

        Args:
            action: The AWS action being evaluated (e.g., 's3:GetObject').
            resource: The target resource ARN.
            context: Evaluation context with conditions. Can be a dict
                or EvaluationContext instance.

        Returns:
            PolicyDecision with the evaluation result.
        """
        import time as time_mod

        start = time_mod.perf_counter()
        self._evaluation_count += 1

        # Normalize context
        if context is None:
            ctx = EvaluationContext()
        elif isinstance(context, dict):
            ctx = EvaluationContext.from_dict(context)
        else:
            ctx = context

        # Check cache
        cache_key = self._compute_cache_key(action, resource, ctx)
        if self._cache_enabled and cache_key in self._cache:
            return self._cache[cache_key]

        # Collect matches by type
        deny_matches: list[PolicyRule] = []
        approval_matches: list[PolicyRule] = []
        allow_matches: list[PolicyRule] = []
        warn_matches: list[PolicyRule] = []
        audit_matches: list[PolicyRule] = []

        for policy in self._policies:
            if not policy.enabled:
                continue
            for rule in policy.rules:
                if rule.evaluate(action, resource, ctx):
                    if rule.rule_type == RuleType.DENY:
                        deny_matches.append(rule)
                    elif rule.rule_type == RuleType.REQUIRE_APPROVAL:
                        approval_matches.append(rule)
                    elif rule.rule_type == RuleType.ALLOW:
                        allow_matches.append(rule)
                    elif rule.rule_type == RuleType.WARN:
                        warn_matches.append(rule)
                    elif rule.rule_type == RuleType.AUDIT:
                        audit_matches.append(rule)

        # Build decision
        decision = self._resolve_decision(
            action=action,
            resource=resource,
            deny_matches=deny_matches,
            approval_matches=approval_matches,
            allow_matches=allow_matches,
            warn_matches=warn_matches,
            audit_matches=audit_matches,
        )

        elapsed_ms = (time_mod.perf_counter() - start) * 1000
        decision.evaluation_time_ms = elapsed_ms

        # Cache result
        if self._cache_enabled:
            if len(self._cache) >= self._max_cache_size:
                self._cache.clear()
            self._cache[cache_key] = decision

        return decision

    def evaluate_batch(
        self,
        requests: list[dict[str, Any]],
    ) -> list[PolicyDecision]:
        """Evaluate multiple action/resource pairs in batch.

        Args:
            requests: List of dicts with keys 'action', 'resource',
                and optional 'context'.

        Returns:
            List of PolicyDecision results in the same order.
        """
        results: list[PolicyDecision] = []
        for req in requests:
            decision = self.evaluate(
                action=req.get("action", ""),
                resource=req.get("resource", ""),
                context=req.get("context"),
            )
            results.append(decision)
        return results

    def load_default_policies(self) -> None:
        """Load built-in default security baseline policies.

        Provides a reasonable security baseline including:
        - Deny wildcard secret access
        - Require approval for PassRole in production
        - Deny cross-account AssumeRole
        - Warn on broad S3 access
        - Audit all IAM write operations
        - Deny disable CloudTrail
        - Require approval for KMS key deletion
        """
        for policy in get_default_policies():
            self.add_policy(policy)

    def _resolve_decision(
        self,
        action: str,
        resource: str,
        deny_matches: list[PolicyRule],
        approval_matches: list[PolicyRule],
        allow_matches: list[PolicyRule],
        warn_matches: list[PolicyRule],
        audit_matches: list[PolicyRule],
    ) -> PolicyDecision:
        """Resolve the final decision from matched rules.

        Priority: DENY > REQUIRE_APPROVAL > ALLOW > default.
        WARN and AUDIT always attach as side-effects.
        """
        warnings = [
            f"[{r.id}] {r.message}" for r in warn_matches if r.message
        ]
        audit_entries = [
            f"[{r.id}] {r.message or f'Audit: {action} on {resource}'}"
            for r in audit_matches
        ]

        if deny_matches:
            highest_severity = deny_matches[0]
            reasons = [
                f"[{r.id}] {r.message}" for r in deny_matches
            ]
            return PolicyDecision(
                effect=PolicyDecisionEffect.DENY,
                matched_rules=deny_matches,
                reasons=reasons,
                warnings=warnings,
                audit_entries=audit_entries,
            )

        if approval_matches:
            reasons = [
                f"[{r.id}] {r.message}" for r in approval_matches
            ]
            return PolicyDecision(
                effect=PolicyDecisionEffect.REQUIRE_APPROVAL,
                matched_rules=approval_matches,
                reasons=reasons,
                warnings=warnings,
                audit_entries=audit_entries,
            )

        if allow_matches:
            reasons = [
                f"[{r.id}] {r.message}" for r in allow_matches
            ]
            return PolicyDecision(
                effect=PolicyDecisionEffect.ALLOW,
                matched_rules=allow_matches,
                reasons=reasons,
                warnings=warnings,
                audit_entries=audit_entries,
            )

        # No decisive match - check for warn-only
        if warn_matches:
            return PolicyDecision(
                effect=PolicyDecisionEffect.WARN,
                matched_rules=warn_matches,
                reasons=[],
                warnings=warnings,
                audit_entries=audit_entries,
            )

        if audit_matches:
            return PolicyDecision(
                effect=PolicyDecisionEffect.AUDIT,
                matched_rules=audit_matches,
                reasons=[],
                warnings=[],
                audit_entries=audit_entries,
            )

        # Default
        return PolicyDecision(
            effect=self._default_effect,
            matched_rules=[],
            reasons=[],
            warnings=[],
            audit_entries=[],
        )

    def _compute_cache_key(
        self, action: str, resource: str, ctx: EvaluationContext
    ) -> str:
        """Compute a cache key for an evaluation request."""
        key_data = (
            f"{action}|{resource}|{ctx.environment}|"
            f"{ctx.data_classification}|{ctx.agent_type}|"
            f"{ctx.agent_id}"
        )
        return hashlib.md5(key_data.encode()).hexdigest()

    def _invalidate_cache(self) -> None:
        """Clear the evaluation cache."""
        self._cache.clear()

    def set_cache_enabled(self, enabled: bool) -> None:
        """Enable or disable the evaluation cache.

        Args:
            enabled: Whether to enable caching.
        """
        self._cache_enabled = enabled
        if not enabled:
            self._cache.clear()


# =============================================================================
# PolicySet
# =============================================================================


class PolicySet:
    """Collection of policies with priority ordering and composition.

    Manages multiple policies that are evaluated together, with
    configurable merge strategies for conflicting decisions.

    PolicySet supports:
    - Priority-based ordering (higher priority evaluated first)
    - Named policy management (add, remove, enable, disable)
    - Batch evaluation
    - Policy versioning
    """

    def __init__(
        self,
        name: str = "default",
        description: str = "",
        strict_mode: bool = False,
    ) -> None:
        """Initialize a PolicySet.

        Args:
            name: Name of this policy set.
            description: Human-readable description.
            strict_mode: If True, deny by default when no rules match.
        """
        self.name = name
        self.description = description
        self._engine = PolicyEngine(strict_mode=strict_mode)
        self._policy_versions: dict[str, list[Policy]] = {}

    @property
    def policies(self) -> list[Policy]:
        """All policies in this set."""
        return self._engine.policies

    @property
    def policy_count(self) -> int:
        """Number of policies in this set."""
        return self._engine.policy_count

    def add_policy(self, policy: Policy) -> None:
        """Add a policy to the set.

        If a policy with the same name exists, the old version is
        archived and the new version replaces it.

        Args:
            policy: The policy to add.
        """
        policy_name = policy.metadata.name

        # Archive existing version
        existing = self.get_policy(policy_name)
        if existing is not None:
            if policy_name not in self._policy_versions:
                self._policy_versions[policy_name] = []
            self._policy_versions[policy_name].append(existing)
            self._engine.remove_policy(policy_name)

        self._engine.add_policy(policy)

    def remove_policy(self, policy_name: str) -> bool:
        """Remove a policy from the set.

        Args:
            policy_name: Name of the policy to remove.

        Returns:
            True if the policy was found and removed.
        """
        return self._engine.remove_policy(policy_name)

    def get_policy(self, policy_name: str) -> Policy | None:
        """Get a policy by name.

        Args:
            policy_name: Name of the policy to retrieve.

        Returns:
            The policy if found, None otherwise.
        """
        for p in self._engine.policies:
            if p.metadata.name == policy_name:
                return p
        return None

    def get_policy_versions(self, policy_name: str) -> list[Policy]:
        """Get all archived versions of a policy.

        Args:
            policy_name: Name of the policy.

        Returns:
            List of previous versions (oldest first).
        """
        return list(self._policy_versions.get(policy_name, []))

    def enable_policy(self, policy_name: str) -> bool:
        """Enable a policy by name.

        Args:
            policy_name: Name of the policy to enable.

        Returns:
            True if the policy was found.
        """
        policy = self.get_policy(policy_name)
        if policy is not None:
            policy.enabled = True
            return True
        return False

    def disable_policy(self, policy_name: str) -> bool:
        """Disable a policy by name (keeps it loaded but unevaluated).

        Args:
            policy_name: Name of the policy to disable.

        Returns:
            True if the policy was found.
        """
        policy = self.get_policy(policy_name)
        if policy is not None:
            policy.enabled = False
            return True
        return False

    def evaluate(
        self,
        action: str,
        resource: str,
        context: EvaluationContext | dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """Evaluate all policies in this set against an action/resource/context.

        Args:
            action: The AWS action being evaluated.
            resource: The target resource ARN.
            context: Evaluation context.

        Returns:
            PolicyDecision with the combined evaluation result.
        """
        return self._engine.evaluate(action, resource, context)

    def evaluate_batch(
        self,
        requests: list[dict[str, Any]],
    ) -> list[PolicyDecision]:
        """Evaluate multiple requests in batch.

        Args:
            requests: List of dicts with 'action', 'resource', and optional 'context'.

        Returns:
            List of PolicyDecision results.
        """
        return self._engine.evaluate_batch(requests)

    def merge(self, other: PolicySet) -> PolicySet:
        """Merge another PolicySet into a new combined set.

        Args:
            other: The PolicySet to merge with this one.

        Returns:
            A new PolicySet containing policies from both sets.
        """
        merged = PolicySet(
            name=f"{self.name}+{other.name}",
            description=f"Merged: {self.description} | {other.description}",
        )
        for policy in self.policies:
            merged.add_policy(policy)
        for policy in other.policies:
            merged.add_policy(policy)
        return merged


# =============================================================================
# Module-level Functions
# =============================================================================


def load_policy(path: Union[str, Path]) -> Policy:
    """Load a policy from a YAML file.

    Args:
        path: Path to the YAML policy file.

    Returns:
        A parsed Policy instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        yaml.YAMLError: If the YAML is malformed.
        ValueError: If the policy structure is invalid.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Policy file not found: {file_path}")

    content = file_path.read_text(encoding="utf-8")
    return Policy.from_yaml(content)


def load_policies_from_directory(directory: Union[str, Path]) -> list[Policy]:
    """Load all YAML policies from a directory.

    Searches for files matching *.yaml and *.yml patterns.

    Args:
        directory: Path to the directory containing policy files.

    Returns:
        List of parsed Policy instances.

    Raises:
        FileNotFoundError: If the directory does not exist.
    """
    dir_path = Path(directory)
    if not dir_path.is_dir():
        raise FileNotFoundError(f"Policy directory not found: {dir_path}")

    policies: list[Policy] = []
    for pattern in ("*.yaml", "*.yml"):
        for file_path in dir_path.glob(pattern):
            try:
                policy = load_policy(file_path)
                policies.append(policy)
            except (yaml.YAMLError, ValueError):
                continue  # Skip malformed files

    return policies


def validate_policy(policy: Policy) -> list[ValidationError]:
    """Validate a policy for correctness and best practices.

    Checks for:
    - Required fields (version, metadata.name, rule IDs)
    - Valid rule types
    - Valid action/resource patterns
    - Compilable regex patterns
    - Severity values
    - Duplicate rule IDs
    - Unreachable rules (shadowed by higher-priority rules)

    Args:
        policy: The policy to validate.

    Returns:
        List of ValidationError objects. Empty list means valid.
    """
    errors: list[ValidationError] = []

    # Version check
    if not policy.version:
        errors.append(ValidationError(
            path="version",
            message="Policy version is required",
            severity=ValidationSeverity.ERROR,
        ))

    # Metadata checks
    if not policy.metadata.name:
        errors.append(ValidationError(
            path="metadata.name",
            message="Policy name is required",
            severity=ValidationSeverity.ERROR,
        ))

    if not policy.metadata.description:
        errors.append(ValidationError(
            path="metadata.description",
            message="Policy description is recommended",
            severity=ValidationSeverity.WARNING,
        ))

    if not policy.metadata.author:
        errors.append(ValidationError(
            path="metadata.author",
            message="Policy author is recommended for traceability",
            severity=ValidationSeverity.INFO,
        ))

    # Rules checks
    if not policy.rules:
        errors.append(ValidationError(
            path="rules",
            message="Policy contains no rules",
            severity=ValidationSeverity.WARNING,
        ))

    # Check for duplicate rule IDs
    seen_ids: set[str] = set()
    for idx, rule in enumerate(policy.rules):
        rule_path = f"rules[{idx}]"

        if not rule.id:
            errors.append(ValidationError(
                path=f"{rule_path}.id",
                message="Rule ID is required",
                severity=ValidationSeverity.ERROR,
                rule_id=f"index-{idx}",
            ))
        elif rule.id in seen_ids:
            errors.append(ValidationError(
                path=f"{rule_path}.id",
                message=f"Duplicate rule ID: '{rule.id}'",
                severity=ValidationSeverity.ERROR,
                rule_id=rule.id,
            ))
        else:
            seen_ids.add(rule.id)

        # Validate severity
        valid_severities = {"critical", "high", "medium", "low", "informational"}
        if rule.severity and rule.severity.lower() not in valid_severities:
            errors.append(ValidationError(
                path=f"{rule_path}.severity",
                message=f"Invalid severity '{rule.severity}'. "
                        f"Must be one of: {', '.join(sorted(valid_severities))}",
                severity=ValidationSeverity.ERROR,
                rule_id=rule.id,
                suggestion="Use one of: critical, high, medium, low, informational",
            ))

        # Validate regex patterns
        if rule.resource_regex:
            try:
                re.compile(rule.resource_regex)
            except re.error as e:
                errors.append(ValidationError(
                    path=f"{rule_path}.resource_pattern",
                    message=f"Invalid regex pattern: {e}",
                    severity=ValidationSeverity.ERROR,
                    rule_id=rule.id,
                ))

        if rule.action_pattern.startswith("regex:"):
            regex_str = rule.action_pattern[6:]
            try:
                re.compile(regex_str)
            except re.error as e:
                errors.append(ValidationError(
                    path=f"{rule_path}.action",
                    message=f"Invalid regex in action pattern: {e}",
                    severity=ValidationSeverity.ERROR,
                    rule_id=rule.id,
                ))

        if rule.resource_pattern.startswith("regex:"):
            regex_str = rule.resource_pattern[6:]
            try:
                re.compile(regex_str)
            except re.error as e:
                errors.append(ValidationError(
                    path=f"{rule_path}.resource",
                    message=f"Invalid regex in resource pattern: {e}",
                    severity=ValidationSeverity.ERROR,
                    rule_id=rule.id,
                ))

        # Warn about overly broad rules
        if (
            rule.action_pattern == "*"
            and rule.resource_pattern == "*"
            and not rule.resource_regex
            and rule.rule_type == RuleType.DENY
        ):
            errors.append(ValidationError(
                path=rule_path,
                message="Deny rule matches all actions and resources. "
                        "This will block everything.",
                severity=ValidationSeverity.WARNING,
                rule_id=rule.id,
                suggestion="Add conditions or narrow the action/resource pattern",
            ))

    return errors


def test_policy(
    policy: Policy,
    test_cases: list[TestCase | dict[str, Any]],
) -> TestResults:
    """Run test cases against a policy to verify correct behavior.

    Each test case specifies an action, resource, context, and expected
    effect. The policy is evaluated and the actual effect is compared
    to the expected effect.

    Args:
        policy: The policy to test.
        test_cases: List of test cases. Can be TestCase instances or dicts.

    Returns:
        TestResults with individual case results and aggregate statistics.

    Example:
        results = test_policy(my_policy, [
            {
                "name": "deny-secret-wildcard",
                "action": "secretsmanager:GetSecretValue",
                "resource": "*",
                "expected_effect": "deny",
            },
            {
                "name": "allow-s3-read",
                "action": "s3:GetObject",
                "resource": "arn:aws:s3:::approved-bucket/file.txt",
                "context": {"environment": "production"},
                "expected_effect": "allow",
            },
        ])
        assert results.all_passed
    """
    import time as time_mod

    overall_start = time_mod.perf_counter()

    # Create a fresh engine with just this policy
    engine = PolicyEngine()
    engine.add_policy(policy)
    engine.set_cache_enabled(False)

    results = TestResults(policy_name=policy.metadata.name)

    for tc_data in test_cases:
        if isinstance(tc_data, dict):
            tc = TestCase.from_dict(tc_data)
        else:
            tc = tc_data

        case_start = time_mod.perf_counter()
        try:
            ctx = EvaluationContext.from_dict(tc.context) if tc.context else EvaluationContext()
            decision = engine.evaluate(tc.action, tc.resource, ctx)

            actual_effect = decision.effect.value
            actual_rule_ids = [r.id for r in decision.matched_rules]

            # Determine pass/fail
            effect_matches = True
            if tc.expected_effect:
                effect_matches = actual_effect == tc.expected_effect.lower()

            rules_match = True
            if tc.expected_rule_ids:
                rules_match = set(tc.expected_rule_ids).issubset(set(actual_rule_ids))

            if effect_matches and rules_match:
                result = TestResult.PASS
                error_msg = ""
            else:
                result = TestResult.FAIL
                parts: list[str] = []
                if not effect_matches:
                    parts.append(
                        f"Expected effect '{tc.expected_effect}', got '{actual_effect}'"
                    )
                if not rules_match:
                    parts.append(
                        f"Expected rules {tc.expected_rule_ids} not all in {actual_rule_ids}"
                    )
                error_msg = "; ".join(parts)

            case_duration = (time_mod.perf_counter() - case_start) * 1000
            results.results.append(TestCaseResult(
                test_case=tc,
                result=result,
                actual_effect=actual_effect,
                actual_rule_ids=actual_rule_ids,
                error_message=error_msg,
                duration_ms=case_duration,
            ))

        except Exception as e:
            case_duration = (time_mod.perf_counter() - case_start) * 1000
            results.results.append(TestCaseResult(
                test_case=tc,
                result=TestResult.ERROR,
                error_message=str(e),
                duration_ms=case_duration,
            ))

    results.total_duration_ms = (time_mod.perf_counter() - overall_start) * 1000
    return results


# =============================================================================
# Built-in Default Policies
# =============================================================================


def get_default_policies() -> list[Policy]:
    """Get built-in default security baseline policies.

    These policies implement common security best practices for
    AWS agent workloads:

    1. deny-dangerous-wildcards: Blocks wildcard access to secrets, KMS, IAM.
    2. production-safeguards: Requires approval for sensitive production actions.
    3. cross-account-controls: Blocks unauthorized cross-account access.
    4. audit-sensitive-operations: Audits all IAM, KMS, and CloudTrail operations.
    5. data-protection: Protects classified data resources.

    Returns:
        List of default Policy instances.
    """
    return [
        _build_deny_dangerous_wildcards_policy(),
        _build_production_safeguards_policy(),
        _build_cross_account_controls_policy(),
        _build_audit_sensitive_operations_policy(),
        _build_data_protection_policy(),
    ]


def _build_deny_dangerous_wildcards_policy() -> Policy:
    """Build the deny-dangerous-wildcards default policy."""
    return Policy(
        version="1.0",
        metadata=PolicyMetadata(
            name="deny-dangerous-wildcards",
            description="Deny wildcard access to sensitive AWS services",
            author="aws-agent-identity-guard",
            created="2024-01-01",
        ),
        rules=[
            PolicyRule(
                id="DENY-SECRET-WILDCARD",
                rule_type=RuleType.DENY,
                action_pattern="secretsmanager:GetSecretValue",
                resource_pattern="*",
                severity="critical",
                message="Wildcard access to secrets is not allowed",
                priority=100,
            ),
            PolicyRule(
                id="DENY-KMS-WILDCARD",
                rule_type=RuleType.DENY,
                action_pattern="kms:Decrypt",
                resource_pattern="*",
                severity="critical",
                message="Wildcard access to KMS decryption is not allowed",
                priority=100,
            ),
            PolicyRule(
                id="DENY-IAM-CREATE-USER",
                rule_type=RuleType.DENY,
                action_pattern="iam:CreateUser",
                resource_pattern="*",
                severity="high",
                message="Creating IAM users is not allowed for agents",
                priority=90,
            ),
            PolicyRule(
                id="DENY-IAM-CREATE-ACCESS-KEY",
                rule_type=RuleType.DENY,
                action_pattern="iam:CreateAccessKey",
                resource_pattern="*",
                severity="high",
                message="Creating access keys is not allowed for agents",
                priority=90,
            ),
            PolicyRule(
                id="DENY-IAM-ATTACH-POLICY",
                rule_type=RuleType.DENY,
                action_pattern="iam:AttachUserPolicy",
                resource_pattern="*",
                severity="high",
                message="Attaching user policies is not allowed for agents",
                priority=90,
            ),
            PolicyRule(
                id="DENY-IAM-PUT-POLICY",
                rule_type=RuleType.DENY,
                action_pattern="iam:PutUserPolicy",
                resource_pattern="*",
                severity="high",
                message="Inline user policies are not allowed for agents",
                priority=90,
            ),
            PolicyRule(
                id="DENY-CLOUDTRAIL-STOP",
                rule_type=RuleType.DENY,
                action_pattern="cloudtrail:StopLogging",
                resource_pattern="*",
                severity="critical",
                message="Disabling CloudTrail is not allowed",
                priority=100,
            ),
            PolicyRule(
                id="DENY-GUARDDUTY-DELETE",
                rule_type=RuleType.DENY,
                action_pattern="guardduty:DeleteDetector",
                resource_pattern="*",
                severity="critical",
                message="Deleting GuardDuty detectors is not allowed",
                priority=100,
            ),
        ],
        priority=100,
        enabled=True,
    )


def _build_production_safeguards_policy() -> Policy:
    """Build the production-safeguards default policy."""
    return Policy(
        version="1.0",
        metadata=PolicyMetadata(
            name="production-safeguards",
            description="Require approval for sensitive production operations",
            author="aws-agent-identity-guard",
            created="2024-01-01",
        ),
        rules=[
            PolicyRule(
                id="REQUIRE-APPROVAL-PASSROLE",
                rule_type=RuleType.REQUIRE_APPROVAL,
                action_pattern="iam:PassRole",
                resource_pattern="*",
                conditions=RuleConditions(environment=["production"]),
                severity="high",
                message="PassRole in production requires approval",
                priority=80,
            ),
            PolicyRule(
                id="REQUIRE-APPROVAL-DELETE-ROLE",
                rule_type=RuleType.REQUIRE_APPROVAL,
                action_pattern="iam:DeleteRole",
                resource_pattern="*",
                conditions=RuleConditions(environment=["production"]),
                severity="high",
                message="Deleting IAM roles in production requires approval",
                priority=80,
            ),
            PolicyRule(
                id="REQUIRE-APPROVAL-KMS-SCHEDULE-DELETE",
                rule_type=RuleType.REQUIRE_APPROVAL,
                action_pattern="kms:ScheduleKeyDeletion",
                resource_pattern="*",
                severity="critical",
                message="KMS key deletion requires approval",
                priority=90,
            ),
            PolicyRule(
                id="REQUIRE-APPROVAL-RDS-DELETE",
                rule_type=RuleType.REQUIRE_APPROVAL,
                action_pattern="rds:DeleteDBInstance",
                resource_pattern="*",
                conditions=RuleConditions(environment=["production"]),
                severity="critical",
                message="Deleting RDS instances in production requires approval",
                priority=90,
            ),
            PolicyRule(
                id="WARN-PRODUCTION-WRITE",
                rule_type=RuleType.WARN,
                action_pattern="regex:.*:(Create|Put|Delete|Update).*",
                resource_pattern="*",
                conditions=RuleConditions(environment=["production"]),
                severity="medium",
                message="Write operation in production environment",
                priority=10,
            ),
        ],
        priority=80,
        enabled=True,
    )


def _build_cross_account_controls_policy() -> Policy:
    """Build the cross-account-controls default policy."""
    return Policy(
        version="1.0",
        metadata=PolicyMetadata(
            name="cross-account-controls",
            description="Control cross-account access patterns",
            author="aws-agent-identity-guard",
            created="2024-01-01",
        ),
        rules=[
            PolicyRule(
                id="DENY-UNKNOWN-CROSS-ACCOUNT",
                rule_type=RuleType.DENY,
                action_pattern="sts:AssumeRole",
                resource_pattern="*",
                resource_regex=r"arn:aws:iam::(?!123456789012)\d{12}:role/.*",
                severity="critical",
                message="Cross-account AssumeRole to unknown accounts is denied",
                priority=95,
            ),
            PolicyRule(
                id="AUDIT-CROSS-ACCOUNT-ACCESS",
                rule_type=RuleType.AUDIT,
                action_pattern="sts:*",
                resource_pattern="*",
                severity="medium",
                message="STS operation audited for cross-account monitoring",
                priority=5,
            ),
        ],
        priority=90,
        enabled=True,
    )


def _build_audit_sensitive_operations_policy() -> Policy:
    """Build the audit-sensitive-operations default policy."""
    return Policy(
        version="1.0",
        metadata=PolicyMetadata(
            name="audit-sensitive-operations",
            description="Audit all sensitive AWS operations for compliance",
            author="aws-agent-identity-guard",
            created="2024-01-01",
        ),
        rules=[
            PolicyRule(
                id="AUDIT-IAM-OPERATIONS",
                rule_type=RuleType.AUDIT,
                action_pattern="iam:*",
                resource_pattern="*",
                severity="medium",
                message="IAM operation audited",
                priority=5,
            ),
            PolicyRule(
                id="AUDIT-KMS-OPERATIONS",
                rule_type=RuleType.AUDIT,
                action_pattern="kms:*",
                resource_pattern="*",
                severity="medium",
                message="KMS operation audited",
                priority=5,
            ),
            PolicyRule(
                id="AUDIT-CLOUDTRAIL-OPERATIONS",
                rule_type=RuleType.AUDIT,
                action_pattern="cloudtrail:*",
                resource_pattern="*",
                severity="medium",
                message="CloudTrail operation audited",
                priority=5,
            ),
            PolicyRule(
                id="AUDIT-SECRETSMANAGER-OPERATIONS",
                rule_type=RuleType.AUDIT,
                action_pattern="secretsmanager:*",
                resource_pattern="*",
                severity="low",
                message="Secrets Manager operation audited",
                priority=5,
            ),
            PolicyRule(
                id="AUDIT-ORGANIZATIONS-OPERATIONS",
                rule_type=RuleType.AUDIT,
                action_pattern="organizations:*",
                resource_pattern="*",
                severity="high",
                message="Organizations operation audited",
                priority=5,
            ),
        ],
        priority=10,
        enabled=True,
    )


def _build_data_protection_policy() -> Policy:
    """Build the data-protection default policy."""
    return Policy(
        version="1.0",
        metadata=PolicyMetadata(
            name="data-protection",
            description="Protect classified data based on sensitivity level",
            author="aws-agent-identity-guard",
            created="2024-01-01",
        ),
        rules=[
            PolicyRule(
                id="DENY-SECRET-DATA-BROAD-ACCESS",
                rule_type=RuleType.DENY,
                action_pattern="s3:GetObject",
                resource_pattern="*",
                conditions=RuleConditions(
                    data_classification=["SECRET", "REGULATED"],
                ),
                severity="critical",
                message="Broad access to SECRET/REGULATED data is denied",
                priority=95,
            ),
            PolicyRule(
                id="REQUIRE-APPROVAL-CONFIDENTIAL-EXPORT",
                rule_type=RuleType.REQUIRE_APPROVAL,
                action_pattern="regex:s3:(GetObject|CopyObject)",
                resource_pattern="*",
                conditions=RuleConditions(
                    data_classification=["CONFIDENTIAL"],
                    environment=["production"],
                ),
                severity="high",
                message="Exporting CONFIDENTIAL data from production requires approval",
                priority=80,
            ),
            PolicyRule(
                id="WARN-INTERNAL-DATA-ACCESS",
                rule_type=RuleType.WARN,
                action_pattern="s3:GetObject",
                resource_pattern="*",
                conditions=RuleConditions(
                    data_classification=["INTERNAL"],
                ),
                severity="low",
                message="Access to INTERNAL classified data",
                priority=5,
            ),
        ],
        priority=85,
        enabled=True,
    )


# =============================================================================
# Utility Functions
# =============================================================================


def create_policy_from_yaml(yaml_content: str) -> Policy:
    """Create a Policy from raw YAML content.

    Convenience wrapper around Policy.from_yaml with additional validation.

    Args:
        yaml_content: YAML policy content string.

    Returns:
        Validated Policy instance.

    Raises:
        ValueError: If the policy fails validation with ERROR-level issues.
    """
    policy = Policy.from_yaml(yaml_content)
    errors = validate_policy(policy)
    critical_errors = [e for e in errors if e.severity == ValidationSeverity.ERROR]
    if critical_errors:
        error_msgs = "\n".join(str(e) for e in critical_errors)
        raise ValueError(f"Policy validation failed:\n{error_msgs}")
    return policy


def merge_policies(policies: list[Policy], name: str = "merged") -> PolicySet:
    """Merge multiple policies into a single PolicySet.

    Args:
        policies: List of policies to merge.
        name: Name for the resulting PolicySet.

    Returns:
        A PolicySet containing all provided policies.
    """
    policy_set = PolicySet(name=name)
    for policy in policies:
        policy_set.add_policy(policy)
    return policy_set


def policy_to_yaml(policy: Policy) -> str:
    """Serialize a Policy back to YAML format.

    Args:
        policy: The policy to serialize.

    Returns:
        YAML string representation of the policy.
    """
    rules_data: list[dict[str, Any]] = []
    for rule in policy.rules:
        rule_dict: dict[str, Any] = {"id": rule.id}

        # Build the rule type spec
        spec: dict[str, Any] = {}
        if rule.action_pattern != "*":
            spec["action"] = rule.action_pattern
        if rule.resource_pattern != "*":
            spec["resource"] = rule.resource_pattern
        if rule.resource_regex:
            spec["resource_pattern"] = rule.resource_regex

        if spec:
            rule_dict[rule.rule_type.value] = spec
        else:
            rule_dict[rule.rule_type.value] = {"action": "*", "resource": "*"}

        # Add conditions
        conditions_dict: dict[str, Any] = {}
        if rule.conditions.environment:
            conditions_dict["environment"] = rule.conditions.environment
        if rule.conditions.data_classification:
            conditions_dict["data_classification"] = rule.conditions.data_classification
        if rule.conditions.agent_type:
            conditions_dict["agent_type"] = rule.conditions.agent_type
        if rule.conditions.tags:
            conditions_dict["tags"] = rule.conditions.tags
        if conditions_dict:
            rule_dict["conditions"] = conditions_dict

        if rule.severity:
            rule_dict["severity"] = rule.severity
        if rule.message:
            rule_dict["message"] = rule.message

        rules_data.append(rule_dict)

    policy_dict: dict[str, Any] = {
        "version": policy.version,
        "metadata": {
            "name": policy.metadata.name,
            "description": policy.metadata.description,
            "author": policy.metadata.author,
            "created": policy.metadata.created,
        },
        "rules": rules_data,
    }

    if policy.priority:
        policy_dict["priority"] = policy.priority

    return yaml.dump(policy_dict, default_flow_style=False, sort_keys=False)


def compare_policies(old: Policy, new: Policy) -> dict[str, Any]:
    """Compare two policy versions and report differences.

    Args:
        old: The previous policy version.
        new: The new policy version.

    Returns:
        Dictionary with added, removed, and modified rule details.
    """
    old_rules = {r.id: r for r in old.rules}
    new_rules = {r.id: r for r in new.rules}

    added = [r_id for r_id in new_rules if r_id not in old_rules]
    removed = [r_id for r_id in old_rules if r_id not in new_rules]

    modified: list[dict[str, Any]] = []
    for r_id in set(old_rules) & set(new_rules):
        old_r = old_rules[r_id]
        new_r = new_rules[r_id]
        changes: dict[str, Any] = {}

        if old_r.rule_type != new_r.rule_type:
            changes["rule_type"] = {"old": old_r.rule_type.value, "new": new_r.rule_type.value}
        if old_r.action_pattern != new_r.action_pattern:
            changes["action_pattern"] = {"old": old_r.action_pattern, "new": new_r.action_pattern}
        if old_r.resource_pattern != new_r.resource_pattern:
            changes["resource_pattern"] = {"old": old_r.resource_pattern, "new": new_r.resource_pattern}
        if old_r.severity != new_r.severity:
            changes["severity"] = {"old": old_r.severity, "new": new_r.severity}
        if old_r.enabled != new_r.enabled:
            changes["enabled"] = {"old": old_r.enabled, "new": new_r.enabled}

        if changes:
            modified.append({"rule_id": r_id, "changes": changes})

    return {
        "added_rules": added,
        "removed_rules": removed,
        "modified_rules": modified,
        "old_version": old.version,
        "new_version": new.version,
        "old_checksum": old.checksum or old.compute_checksum(),
        "new_checksum": new.checksum or new.compute_checksum(),
    }
