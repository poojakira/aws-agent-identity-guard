"""AWS Agent Identity Guard - Transaction Authorization API.

Production-grade authorization service implementing a policy decision point (PDP)
for AWS agent actions. Evaluates transactions against configurable policy pipelines
with support for fail-closed/fail-open modes, risk scoring, step-up authentication,
and full audit trails.

Architecture:
    - AuthorizationService: Core PDP with pluggable engines
    - RiskEngine: Multi-dimensional risk scoring
    - PolicyEngine: Rule evaluation with priority ordering
    - ApprovalService: Step-up approval workflow management
    - DecisionCache: LRU cache for sub-10ms cached decisions

Performance Target: <10ms for cached authorization decisions.
"""

from __future__ import annotations

import fnmatch
import hashlib
import logging
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, unique
from threading import Lock
from typing import Any, Callable, Optional, Protocol

from .models import (
    AuditEvent,
    ApprovalRequest,
    ApprovalStatus,
    DataClassification,
    Decision,
    Environment,
    Permission,
    PermissionEffect,
    PolicyRule,
    RiskScore,
    SerializableMixin,
)


# =============================================================================
# Module Logger
# =============================================================================

logger = logging.getLogger(__name__)


# =============================================================================
# Utility
# =============================================================================


def _utcnow() -> datetime:
    """Return current UTC time with timezone info."""
    return datetime.now(timezone.utc)


# =============================================================================
# Extended Authorization Models
# =============================================================================


@dataclass
class AuthorizationRequest(SerializableMixin):
    """Extended authorization request capturing full transaction context.

    This extends the base model with additional fields required for
    comprehensive policy evaluation including agent name, environment,
    correlation tracking, and timestamps.

    Attributes:
        agent_id: Unique identifier of the agent.
        agent_name: Human-readable agent name.
        principal: The identity that triggered the agent action.
        tool: The tool or function being invoked by the agent.
        action: The AWS action being performed (e.g., 's3:GetObject').
        resource: The target AWS resource ARN.
        data_classification: Sensitivity level of the data involved.
        context: Additional metadata for policy evaluation.
        risk_context: Pre-computed risk information from upstream systems.
        environment: Deployment environment (dev/staging/production).
        correlation_id: Unique ID for tracing across distributed systems.
        timestamp: When the request was created.
    """

    agent_id: str
    agent_name: str
    principal: str
    tool: str
    action: str
    resource: str
    data_classification: DataClassification = DataClassification.INTERNAL
    context: dict[str, Any] = field(default_factory=dict)
    risk_context: dict[str, Any] = field(default_factory=dict)
    environment: Environment = Environment.PRODUCTION
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=_utcnow)

    @classmethod
    def create(
        cls,
        agent_id: str,
        agent_name: str,
        principal: str,
        action: str,
        resource: str,
        tool: str = "",
        data_classification: DataClassification = DataClassification.INTERNAL,
        context: dict[str, Any] | None = None,
        risk_context: dict[str, Any] | None = None,
        environment: Environment = Environment.PRODUCTION,
        correlation_id: str | None = None,
    ) -> AuthorizationRequest:
        """Factory method for creating an authorization request.

        Args:
            agent_id: Unique agent identifier.
            agent_name: Human-readable agent name.
            principal: Who triggered the agent.
            action: AWS action being requested.
            resource: Target ARN.
            tool: Tool/function being invoked.
            data_classification: Data sensitivity level.
            context: Additional metadata.
            risk_context: Pre-computed risk info.
            environment: Target environment.
            correlation_id: Optional correlation ID (auto-generated if omitted).

        Returns:
            A fully populated AuthorizationRequest instance.
        """
        return cls(
            agent_id=agent_id,
            agent_name=agent_name,
            principal=principal,
            tool=tool,
            action=action,
            resource=resource,
            data_classification=data_classification,
            context=context or {},
            risk_context=risk_context or {},
            environment=environment,
            correlation_id=correlation_id or str(uuid.uuid4()),
            timestamp=_utcnow(),
        )


@dataclass
class AuthorizationDecision(SerializableMixin):
    """Result of an authorization evaluation with full decision context.

    Contains the decision outcome, risk assessment, policy references,
    human-readable explanations, and approval workflow state.

    Attributes:
        decision: The authorization outcome (ALLOW/DENY/STEP_UP/REVIEW).
        risk_score: Numeric risk score (0-100 scale).
        reasons: List of reasons supporting the decision.
        policy: The policy rule that triggered this decision.
        explanation: Human-readable explanation of the decision.
        correlation_id: Correlation ID linking to the original request.
        timestamp: When the decision was made.
        approval_required: Whether human approval is needed.
        approval_id: ID of the approval request (if applicable).
        conditions: Conditions that must be met for an ALLOW decision.
    """

    decision: Decision
    risk_score: int
    reasons: list[str]
    policy: str
    explanation: str
    correlation_id: str
    timestamp: datetime = field(default_factory=_utcnow)
    approval_required: bool = False
    approval_id: Optional[str] = None
    conditions: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate risk_score range."""
        if not (0 <= self.risk_score <= 100):
            raise ValueError(
                f"risk_score must be between 0 and 100, got {self.risk_score}"
            )

    @classmethod
    def allow(
        cls,
        reasons: list[str],
        policy: str = "",
        explanation: str = "Access granted.",
        risk_score: int = 0,
        correlation_id: str = "",
        conditions: list[str] | None = None,
    ) -> AuthorizationDecision:
        """Factory for an ALLOW decision.

        Args:
            reasons: Supporting reasons for the allow.
            policy: Policy reference that permitted the action.
            explanation: Human-readable explanation.
            risk_score: Computed risk score (0-100).
            correlation_id: Correlation ID for tracing.
            conditions: Conditions attached to the allow.

        Returns:
            An AuthorizationDecision with ALLOW outcome.
        """
        return cls(
            decision=Decision.ALLOW,
            risk_score=risk_score,
            reasons=reasons,
            policy=policy,
            explanation=explanation,
            correlation_id=correlation_id or str(uuid.uuid4()),
            timestamp=_utcnow(),
            approval_required=False,
            approval_id=None,
            conditions=conditions or [],
        )

    @classmethod
    def deny(
        cls,
        reasons: list[str],
        policy: str = "",
        explanation: str = "Access denied.",
        risk_score: int = 100,
        correlation_id: str = "",
    ) -> AuthorizationDecision:
        """Factory for a DENY decision.

        Args:
            reasons: Reasons for denial.
            policy: Policy reference that triggered denial.
            explanation: Human-readable explanation of why denied.
            risk_score: Computed risk score (0-100).
            correlation_id: Correlation ID for tracing.

        Returns:
            An AuthorizationDecision with DENY outcome.
        """
        return cls(
            decision=Decision.DENY,
            risk_score=risk_score,
            reasons=reasons,
            policy=policy,
            explanation=explanation,
            correlation_id=correlation_id or str(uuid.uuid4()),
            timestamp=_utcnow(),
            approval_required=False,
            approval_id=None,
            conditions=[],
        )

    @classmethod
    def step_up(
        cls,
        reasons: list[str],
        approval_id: str,
        policy: str = "",
        explanation: str = "Step-up authentication required.",
        risk_score: int = 70,
        correlation_id: str = "",
    ) -> AuthorizationDecision:
        """Factory for a STEP_UP decision requiring elevated authentication.

        Args:
            reasons: Reasons step-up is required.
            approval_id: ID of the generated approval request.
            policy: Policy reference that triggered step-up.
            explanation: Human-readable explanation.
            risk_score: Computed risk score (0-100).
            correlation_id: Correlation ID for tracing.

        Returns:
            An AuthorizationDecision with STEP_UP outcome.
        """
        return cls(
            decision=Decision.STEP_UP,
            risk_score=risk_score,
            reasons=reasons,
            policy=policy,
            explanation=explanation,
            correlation_id=correlation_id or str(uuid.uuid4()),
            timestamp=_utcnow(),
            approval_required=True,
            approval_id=approval_id,
            conditions=[],
        )

    @classmethod
    def review(
        cls,
        reasons: list[str],
        approval_id: str,
        policy: str = "",
        explanation: str = "Human review required.",
        risk_score: int = 60,
        correlation_id: str = "",
    ) -> AuthorizationDecision:
        """Factory for a REVIEW decision requiring human approval.

        Args:
            reasons: Reasons review is needed.
            approval_id: ID of the generated approval request.
            policy: Policy reference that triggered review.
            explanation: Human-readable explanation.
            risk_score: Computed risk score (0-100).
            correlation_id: Correlation ID for tracing.

        Returns:
            An AuthorizationDecision with REVIEW outcome.
        """
        return cls(
            decision=Decision.REVIEW,
            risk_score=risk_score,
            reasons=reasons,
            policy=policy,
            explanation=explanation,
            correlation_id=correlation_id or str(uuid.uuid4()),
            timestamp=_utcnow(),
            approval_required=True,
            approval_id=approval_id,
            conditions=[],
        )

    def format_explanation(self, request: AuthorizationRequest) -> str:
        """Generate a structured human-readable explanation.

        Args:
            request: The original authorization request for context.

        Returns:
            A formatted multi-line explanation string.

        Example output::

            DENIED
            Agent: invoice-agent
            Action: iam:PassRole
            Resource: production-admin-role
            Reason: This action creates a privilege-escalation path.
        """
        lines = [
            self.decision.value,
            f"Agent: {request.agent_id}",
            f"Action: {request.action}",
            f"Resource: {request.resource}",
        ]
        if self.reasons:
            lines.append(f"Reason: {'; '.join(self.reasons)}")
        if self.conditions:
            lines.append(f"Conditions: {'; '.join(self.conditions)}")
        return "\n".join(lines)


# =============================================================================
# Decision Cache (LRU with TTL)
# =============================================================================


class DecisionCache:
    """Thread-safe LRU cache with TTL for authorization decisions.

    Provides sub-millisecond lookups for repeated authorization requests,
    enabling the <10ms performance target for cached decisions.

    Attributes:
        max_size: Maximum number of cached entries.
        ttl_seconds: Time-to-live for cache entries in seconds.
    """

    def __init__(self, max_size: int = 10_000, ttl_seconds: float = 60.0) -> None:
        """Initialize the decision cache.

        Args:
            max_size: Maximum entries before eviction.
            ttl_seconds: Cache entry lifetime in seconds.
        """
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, tuple[AuthorizationDecision, float]] = (
            OrderedDict()
        )
        self._lock = Lock()
        self._hits: int = 0
        self._misses: int = 0

    def _cache_key(self, request: AuthorizationRequest) -> str:
        """Compute a deterministic cache key for a request.

        Args:
            request: The authorization request.

        Returns:
            SHA-256 hash of the relevant request fields.
        """
        key_data = (
            f"{request.agent_id}:{request.action}:{request.resource}"
            f":{request.environment.value if request.environment else 'none'}:{request.data_classification.value}"
            f":{request.tool}:{request.principal}"
        )
        return hashlib.sha256(key_data.encode("utf-8")).hexdigest()

    def get(self, request: AuthorizationRequest) -> Optional[AuthorizationDecision]:
        """Retrieve a cached decision if available and not expired.

        Args:
            request: The authorization request to look up.

        Returns:
            Cached AuthorizationDecision or None if miss/expired.
        """
        key = self._cache_key(request)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None

            decision, cached_at = entry
            if (time.monotonic() - cached_at) > self._ttl_seconds:
                # Expired entry
                del self._cache[key]
                self._misses += 1
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self._hits += 1
            return decision

    def put(self, request: AuthorizationRequest, decision: AuthorizationDecision) -> None:
        """Store a decision in the cache.

        Args:
            request: The authorization request (used as cache key).
            decision: The decision to cache.
        """
        key = self._cache_key(request)
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = (decision, time.monotonic())

            # Evict oldest if over capacity
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

    def invalidate(self, request: AuthorizationRequest) -> None:
        """Remove a specific entry from the cache.

        Args:
            request: The authorization request to invalidate.
        """
        key = self._cache_key(request)
        with self._lock:
            self._cache.pop(key, None)

    def clear(self) -> None:
        """Clear all cached decisions."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    @property
    def hit_rate(self) -> float:
        """Cache hit rate as a percentage (0.0 - 100.0)."""
        total = self._hits + self._misses
        if total == 0:
            return 0.0
        return (self._hits / total) * 100.0

    @property
    def size(self) -> int:
        """Current number of entries in the cache."""
        return len(self._cache)


# =============================================================================
# Engine Protocols
# =============================================================================


class RiskEngine(Protocol):
    """Protocol for risk scoring engines.

    Implementations must compute a risk score for an authorization request,
    returning a normalized integer score (0-100).
    """

    def compute_risk(self, request: AuthorizationRequest) -> int:
        """Compute the risk score for a given authorization request.

        Args:
            request: The authorization request to assess.

        Returns:
            Integer risk score from 0 (no risk) to 100 (maximum risk).
        """
        ...


class PolicyEngine(Protocol):
    """Protocol for policy rule evaluation engines.

    Implementations must evaluate a request against loaded policy rules
    and return matching rules with their effects.
    """

    def evaluate(
        self, request: AuthorizationRequest
    ) -> list[tuple[PolicyRule, PermissionEffect]]:
        """Evaluate the request against all loaded policy rules.

        Args:
            request: The authorization request to evaluate.

        Returns:
            List of (rule, effect) tuples for all matching rules,
            ordered by priority (highest first).
        """
        ...


class ApprovalService(Protocol):
    """Protocol for approval workflow management.

    Implementations must create and manage approval requests
    for step-up and review decisions.
    """

    def create_approval(
        self, request: AuthorizationRequest, reason: str
    ) -> ApprovalRequest:
        """Create a new approval request for a step-up or review action.

        Args:
            request: The authorization request requiring approval.
            reason: Why approval is needed.

        Returns:
            A new ApprovalRequest in PENDING status.
        """
        ...


class AuditLogger(Protocol):
    """Protocol for audit event persistence.

    Implementations must durably record audit events for compliance
    and forensic analysis.
    """

    def log(self, event: AuditEvent) -> None:
        """Persist an audit event.

        Args:
            event: The audit event to record.
        """
        ...


# =============================================================================
# Default Implementations
# =============================================================================


class DefaultRiskEngine:
    """Default risk scoring engine using heuristic analysis.

    Computes risk based on action sensitivity, resource criticality,
    data classification, and environment. Designed as a baseline
    implementation — production deployments should provide a custom
    RiskEngine with ML-based scoring.

    Attributes:
        HIGH_RISK_ACTIONS: Actions that inherently carry elevated risk.
        CRITICAL_RESOURCE_PATTERNS: Resource ARN patterns indicating
            critical infrastructure.
    """

    HIGH_RISK_ACTIONS: set[str] = {
        "iam:PassRole",
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:CreateUser",
        "iam:CreateAccessKey",
        "iam:UpdateAssumeRolePolicy",
        "sts:AssumeRole",
        "lambda:CreateFunction",
        "lambda:UpdateFunctionCode",
        "ec2:RunInstances",
        "s3:DeleteBucket",
        "s3:PutBucketPolicy",
        "kms:ScheduleKeyDeletion",
        "kms:DisableKey",
        "organizations:LeaveOrganization",
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "guardduty:DeleteDetector",
        "config:StopConfigurationRecorder",
    }

    CRITICAL_RESOURCE_PATTERNS: list[str] = [
        "*production*",
        "*prod-*",
        "*-prod",
        "*admin*",
        "*root*",
        "*master*",
        "*security*",
        "*audit*",
        "*compliance*",
    ]

    def compute_risk(self, request: AuthorizationRequest) -> int:
        """Compute risk score using multi-dimensional heuristic analysis.

        Scoring dimensions:
        - Action sensitivity (0-40 points)
        - Resource criticality (0-25 points)
        - Data classification (0-20 points)
        - Environment multiplier (0-15 points)

        Args:
            request: The authorization request to score.

        Returns:
            Integer risk score (0-100).
        """
        score = 0

        # Action sensitivity (0-40)
        if request.action in self.HIGH_RISK_ACTIONS:
            score += 40
        elif request.action.startswith("iam:") or request.action.startswith("sts:"):
            score += 25
        elif any(
            verb in request.action.lower()
            for verb in ["delete", "remove", "disable", "stop"]
        ):
            score += 20
        elif any(
            verb in request.action.lower()
            for verb in ["put", "create", "update", "modify"]
        ):
            score += 10

        # Resource criticality (0-25)
        resource_lower = request.resource.lower()
        if any(
            fnmatch.fnmatch(resource_lower, pattern)
            for pattern in self.CRITICAL_RESOURCE_PATTERNS
        ):
            score += 25
        elif "arn:aws:iam::" in request.resource:
            score += 15

        # Data classification (0-20)
        classification_scores = {
            DataClassification.PUBLIC: 0,
            DataClassification.INTERNAL: 5,
            DataClassification.CONFIDENTIAL: 10,
            DataClassification.SECRET: 15,
            DataClassification.REGULATED: 20,
        }
        score += classification_scores.get(request.data_classification, 5)

        # Environment risk (0-15)
        environment_scores = {
            Environment.DEV: 0,
            Environment.STAGING: 5,
            Environment.PRODUCTION: 15,
        }
        score += environment_scores.get(request.environment, 15) if request.environment else 15

        # Pre-computed risk context boost
        if request.risk_context:
            context_boost = request.risk_context.get("additional_risk", 0)
            score += min(context_boost, 20)  # Cap context boost at 20

        return min(score, 100)


class DefaultPolicyEngine:
    """Default policy evaluation engine using pattern-matching rules.

    Evaluates authorization requests against a set of PolicyRule definitions,
    matching action and resource patterns with glob-style wildcards.
    Rules are evaluated in priority order (highest priority first).

    Attributes:
        rules: Loaded policy rules.
    """

    def __init__(self, rules: list[PolicyRule] | None = None) -> None:
        """Initialize with optional pre-loaded rules.

        Args:
            rules: List of policy rules. If None, uses built-in defaults.
        """
        self._rules: list[PolicyRule] = rules or self._default_rules()

    @property
    def rules(self) -> list[PolicyRule]:
        """Currently loaded policy rules."""
        return self._rules

    def load_rules(self, rules: list[PolicyRule]) -> None:
        """Replace the current rule set with new rules.

        Args:
            rules: New set of policy rules to load.
        """
        self._rules = sorted(rules, key=lambda r: r.priority, reverse=True)

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a single rule and re-sort by priority.

        Args:
            rule: PolicyRule to add.
        """
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    def evaluate(
        self, request: AuthorizationRequest
    ) -> list[tuple[PolicyRule, PermissionEffect]]:
        """Evaluate request against all matching rules in priority order.

        Args:
            request: The authorization request to evaluate.

        Returns:
            List of (rule, effect) tuples for matching rules,
            ordered by descending priority.
        """
        matches: list[tuple[PolicyRule, PermissionEffect]] = []

        for rule in self._rules:
            if not rule.enabled:
                continue

            # Environment filter
            if rule.environments and request.environment and request.environment not in rule.environments:
                continue

            # Action pattern matching
            action_match = any(
                fnmatch.fnmatch(request.action, pattern)
                for pattern in rule.action_patterns
            )
            if not action_match:
                continue

            # Resource pattern matching
            resource_match = any(
                fnmatch.fnmatch(request.resource, pattern)
                for pattern in rule.resource_patterns
            )
            if not resource_match:
                continue

            # Condition evaluation
            if not self._evaluate_conditions(rule.conditions, request):
                continue

            matches.append((rule, rule.effect))

        return matches

    def _evaluate_conditions(
        self, conditions: dict[str, Any], request: AuthorizationRequest
    ) -> bool:
        """Evaluate rule conditions against request context.

        Args:
            conditions: Conditions to evaluate.
            request: The request providing context.

        Returns:
            True if all conditions are satisfied (or no conditions exist).
        """
        if not conditions:
            return True

        for key, expected in conditions.items():
            # Check in request context
            actual = request.context.get(key)
            if actual is None:
                actual = request.risk_context.get(key)

            if actual is None:
                return False

            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False

        return True

    @staticmethod
    def _default_rules() -> list[PolicyRule]:
        """Generate built-in default policy rules.

        Returns:
            List of essential security policy rules.
        """
        rules = [
            # Explicit deny: privilege escalation actions in production
            PolicyRule.create(
                name="deny-privilege-escalation-production",
                action_patterns=[
                    "iam:PassRole",
                    "iam:CreateRole",
                    "iam:AttachRolePolicy",
                    "iam:PutRolePolicy",
                    "iam:UpdateAssumeRolePolicy",
                ],
                resource_patterns=["*"],
                effect=PermissionEffect.DENY,
                environments=[Environment.PRODUCTION],
                description=(
                    "Deny privilege escalation actions in production. "
                    "These actions require out-of-band approval."
                ),
                priority=1000,
            ),
            # Explicit deny: disable security controls
            PolicyRule.create(
                name="deny-disable-security-controls",
                action_patterns=[
                    "cloudtrail:StopLogging",
                    "cloudtrail:DeleteTrail",
                    "guardduty:DeleteDetector",
                    "config:StopConfigurationRecorder",
                ],
                resource_patterns=["*"],
                effect=PermissionEffect.DENY,
                environments=[Environment.PRODUCTION, Environment.STAGING],
                description="Deny actions that disable security monitoring.",
                priority=999,
            ),
            # Explicit deny: destructive KMS operations
            PolicyRule.create(
                name="deny-kms-destructive",
                action_patterns=[
                    "kms:ScheduleKeyDeletion",
                    "kms:DisableKey",
                ],
                resource_patterns=["*"],
                effect=PermissionEffect.DENY,
                environments=[Environment.PRODUCTION],
                description="Deny destructive KMS operations in production.",
                priority=998,
            ),
        ]

        # Sort by priority descending
        rules.sort(key=lambda r: r.priority, reverse=True)
        return rules


class DefaultApprovalService:
    """Default approval service using in-memory storage.

    Suitable for development and testing. Production deployments should
    use a persistent implementation backed by DynamoDB or similar.

    Attributes:
        pending_approvals: Currently pending approval requests.
    """

    def __init__(self) -> None:
        """Initialize with empty approval store."""
        self._approvals: dict[str, ApprovalRequest] = {}
        self._lock = Lock()

    @property
    def pending_approvals(self) -> dict[str, ApprovalRequest]:
        """Currently stored approval requests."""
        return dict(self._approvals)

    def create_approval(
        self, request: AuthorizationRequest, reason: str
    ) -> ApprovalRequest:
        """Create a new approval request.

        Args:
            request: The authorization request needing approval.
            reason: Why approval is required.

        Returns:
            A new ApprovalRequest in PENDING status.
        """
        approval = ApprovalRequest.create(
            agent_id=request.agent_id,
            action=request.action,
            resource=request.resource,
            requestor=request.principal,
        )
        with self._lock:
            self._approvals[approval.request_id] = approval

        logger.info(
            "Approval request created: %s for %s on %s (reason: %s)",
            approval.request_id,
            request.action,
            request.resource,
            reason,
        )
        return approval

    def get_approval(self, approval_id: str) -> Optional[ApprovalRequest]:
        """Retrieve an approval request by ID.

        Args:
            approval_id: The approval request ID.

        Returns:
            The ApprovalRequest or None if not found.
        """
        return self._approvals.get(approval_id)

    def approve(self, approval_id: str, approver: str) -> bool:
        """Approve a pending request.

        Args:
            approval_id: ID of the approval to grant.
            approver: Identity of the approver.

        Returns:
            True if approved, False if not found or not pending.
        """
        with self._lock:
            approval = self._approvals.get(approval_id)
            if approval is None or not approval.is_pending:
                return False
            # Reconstruct with updated status (dataclass with __slots__)
            self._approvals[approval_id] = ApprovalRequest(
                request_id=approval.request_id,
                agent_id=approval.agent_id,
                action=approval.action,
                resource=approval.resource,
                requestor=approval.requestor,
                approver=approver,
                status=ApprovalStatus.APPROVED,
                expiry=approval.expiry,
                created_at=approval.created_at,
            )
            return True

    def deny_approval(self, approval_id: str, approver: str) -> bool:
        """Deny a pending request.

        Args:
            approval_id: ID of the approval to deny.
            approver: Identity of the denier.

        Returns:
            True if denied, False if not found or not pending.
        """
        with self._lock:
            approval = self._approvals.get(approval_id)
            if approval is None or not approval.is_pending:
                return False
            self._approvals[approval_id] = ApprovalRequest(
                request_id=approval.request_id,
                agent_id=approval.agent_id,
                action=approval.action,
                resource=approval.resource,
                requestor=approval.requestor,
                approver=approver,
                status=ApprovalStatus.DENIED,
                expiry=approval.expiry,
                created_at=approval.created_at,
            )
            return True


class DefaultAuditLogger:
    """Default audit logger writing to Python logging and in-memory store.

    Maintains an in-memory event log with hash chain integrity.
    Production deployments should persist to CloudWatch, S3, or
    a dedicated audit store.

    Attributes:
        events: Ordered list of audit events.
    """

    def __init__(self) -> None:
        """Initialize with empty event store."""
        self._events: list[AuditEvent] = []
        self._lock = Lock()

    @property
    def events(self) -> list[AuditEvent]:
        """All recorded audit events (oldest first)."""
        return list(self._events)

    def log(self, event: AuditEvent) -> None:
        """Record an audit event.

        Args:
            event: The audit event to persist.
        """
        with self._lock:
            self._events.append(event)

        logger.info(
            "AUDIT [%s] agent=%s action=%s resource=%s decision=%s correlation=%s",
            event.timestamp.isoformat(),
            event.agent,
            event.action,
            event.resource,
            event.decision.value,
            event.correlation_id,
        )

    def get_by_correlation_id(self, correlation_id: str) -> list[AuditEvent]:
        """Retrieve all events for a given correlation ID.

        Args:
            correlation_id: The correlation ID to search for.

        Returns:
            List of matching audit events.
        """
        return [e for e in self._events if e.correlation_id == correlation_id]

    @property
    def last_hash(self) -> str:
        """Integrity hash of the most recent event, or empty string."""
        if not self._events:
            return ""
        return self._events[-1].integrity_hash


# =============================================================================
# Authorization Configuration
# =============================================================================


@dataclass
class AuthorizationConfig:
    """Configuration for the AuthorizationService.

    Controls fail-open/fail-closed behavior, risk thresholds, caching,
    and per-environment overrides.

    Attributes:
        fail_open_environments: Environments where default is ALLOW (with logging).
        fail_closed_environments: Environments where default is DENY.
        step_up_threshold: Risk score threshold triggering step-up (0-100).
        review_threshold: Risk score threshold triggering review (0-100).
        deny_threshold: Risk score threshold for automatic denial (0-100).
        cache_enabled: Whether to use the decision cache.
        cache_max_size: Maximum cache entries.
        cache_ttl_seconds: Cache entry TTL.
        log_all_decisions: Whether to audit-log all decisions (including ALLOW).
    """

    fail_open_environments: list[Environment] = field(
        default_factory=lambda: [Environment.DEV]
    )
    fail_closed_environments: list[Environment] = field(
        default_factory=lambda: [Environment.STAGING, Environment.PRODUCTION]
    )
    step_up_threshold: int = 60
    review_threshold: int = 50
    deny_threshold: int = 80
    cache_enabled: bool = True
    cache_max_size: int = 10_000
    cache_ttl_seconds: float = 60.0
    log_all_decisions: bool = True

    def __post_init__(self) -> None:
        """Validate threshold ordering."""
        if not (
            self.review_threshold <= self.step_up_threshold <= self.deny_threshold
        ):
            raise ValueError(
                "Thresholds must satisfy: "
                f"review ({self.review_threshold}) <= "
                f"step_up ({self.step_up_threshold}) <= "
                f"deny ({self.deny_threshold})"
            )


# =============================================================================
# AuthorizationService - Core Policy Decision Point
# =============================================================================


class AuthorizationService:
    """Core policy decision point for agent transaction authorization.

    Implements a multi-stage evaluation pipeline:
    1. Cache lookup (for <10ms performance on repeated requests)
    2. Risk scoring via RiskEngine
    3. Explicit deny rule evaluation
    4. Step-up rule evaluation (high-risk actions)
    5. Allow rule evaluation
    6. Default decision (fail-closed or fail-open per environment)

    Every decision is recorded in the audit trail with correlation ID
    for end-to-end traceability.

    Example usage::

        config = AuthorizationConfig()
        service = AuthorizationService(config=config)

        request = AuthorizationRequest.create(
            agent_id="agent-001",
            agent_name="invoice-agent",
            principal="user@example.com",
            action="s3:GetObject",
            resource="arn:aws:s3:::invoices/2024/*",
            environment=Environment.PRODUCTION,
        )

        decision = service.authorize(request)
        print(decision.format_explanation(request))

    Attributes:
        config: Authorization configuration.
        risk_engine: Risk scoring engine.
        policy_engine: Policy rule evaluation engine.
        approval_service: Approval workflow manager.
        audit_logger: Audit event recorder.
        cache: Decision cache for performance.
    """

    def __init__(
        self,
        config: AuthorizationConfig | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        approval_service: ApprovalService | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        """Initialize the AuthorizationService.

        Args:
            config: Authorization configuration. Uses defaults if None.
            risk_engine: Custom risk scoring engine. Uses DefaultRiskEngine if None.
            policy_engine: Custom policy engine. Uses DefaultPolicyEngine if None.
            approval_service: Custom approval service. Uses DefaultApprovalService if None.
            audit_logger: Custom audit logger. Uses DefaultAuditLogger if None.
        """
        self.config = config or AuthorizationConfig()
        self.risk_engine: RiskEngine = risk_engine or DefaultRiskEngine()
        self.policy_engine: PolicyEngine = policy_engine or DefaultPolicyEngine()
        self.approval_service: ApprovalService = (
            approval_service or DefaultApprovalService()
        )
        self.audit_logger: AuditLogger = audit_logger or DefaultAuditLogger()

        # Initialize cache
        self.cache = DecisionCache(
            max_size=self.config.cache_max_size,
            ttl_seconds=self.config.cache_ttl_seconds,
        )

        logger.info(
            "AuthorizationService initialized. "
            "Fail-open: %s, Fail-closed: %s, Cache: %s",
            [e.value for e in self.config.fail_open_environments],
            [e.value for e in self.config.fail_closed_environments],
            self.config.cache_enabled,
        )

    def authorize(self, request: AuthorizationRequest) -> AuthorizationDecision:
        """Authorize an agent transaction.

        Evaluates the request through the full policy pipeline:
        1. Check cache for a prior decision
        2. Compute risk score
        3. Evaluate explicit deny rules (highest priority)
        4. Evaluate step-up rules (high-risk actions)
        5. Evaluate allow rules
        6. Apply default decision based on environment

        Every decision is logged as an AuditEvent with the request's
        correlation_id for end-to-end tracing.

        Args:
            request: The authorization request to evaluate.

        Returns:
            AuthorizationDecision with the outcome, risk score,
            reasons, policy reference, and human-readable explanation.

        Performance:
            Cached decisions return in <1ms. Uncached decisions
            complete in <10ms for typical policy sets.
        """
        start_time = time.monotonic()

        # Step 1: Cache lookup
        if self.config.cache_enabled:
            cached = self.cache.get(request)
            if cached is not None:
                logger.debug(
                    "Cache hit for %s:%s (correlation=%s)",
                    request.agent_id,
                    request.action,
                    getattr(request, 'correlation_id', str(uuid.uuid4())),
                )
                # Update correlation_id and timestamp for the new request
                decision = AuthorizationDecision(
                    decision=cached.decision,
                    risk_score=cached.risk_score,
                    reasons=cached.reasons,
                    policy=cached.policy,
                    explanation=cached.explanation,
                    correlation_id=getattr(request, 'correlation_id', str(uuid.uuid4())),
                    timestamp=_utcnow(),
                    approval_required=cached.approval_required,
                    approval_id=cached.approval_id,
                    conditions=cached.conditions,
                )
                self._emit_audit(request, decision)
                return decision

        # Step 2: Compute risk score
        risk_score = self.risk_engine.compute_risk(request)

        # Step 3: Policy evaluation pipeline
        decision = self._evaluate_pipeline(request, risk_score)

        # Step 4: Cache the decision
        if self.config.cache_enabled:
            self.cache.put(request, decision)

        # Step 5: Audit logging
        self._emit_audit(request, decision)

        elapsed_ms = (time.monotonic() - start_time) * 1000
        logger.info(
            "Authorization decision: %s for %s:%s on %s "
            "(risk=%d, elapsed=%.2fms, correlation=%s)",
            decision.decision.value,
            request.agent_id,
            request.action,
            request.resource,
            decision.risk_score,
            elapsed_ms,
            getattr(request, 'correlation_id', str(uuid.uuid4())),
        )

        return decision

    def _evaluate_pipeline(
        self, request: AuthorizationRequest, risk_score: int
    ) -> AuthorizationDecision:
        """Execute the policy evaluation pipeline.

        Pipeline stages (in order):
        1. Explicit deny rules
        2. Risk-based denial (exceeds deny threshold)
        3. Step-up rules (high risk requiring elevated auth)
        4. Risk-based step-up (exceeds step-up threshold)
        5. Risk-based review (exceeds review threshold)
        6. Explicit allow rules
        7. Default decision (environment-dependent)

        Args:
            request: The authorization request.
            risk_score: Pre-computed risk score (0-100).

        Returns:
            The AuthorizationDecision from the first matching stage.
        """
        # Get policy matches
        policy_matches = self.policy_engine.evaluate(request)

        # Stage 1: Explicit deny rules (highest priority)
        deny_matches = [
            (rule, effect)
            for rule, effect in policy_matches
            if effect == PermissionEffect.DENY
        ]
        if deny_matches:
            rule, _ = deny_matches[0]
            reasons = [rule.description or f"Denied by policy: {rule.name}"]
            explanation = self._build_deny_explanation(request, reasons)
            return AuthorizationDecision.deny(
                reasons=reasons,
                policy=rule.rule_id,
                explanation=explanation,
                risk_score=max(risk_score, 80),
                correlation_id=getattr(request, 'correlation_id', str(uuid.uuid4())),
            )

        # Stage 2: Risk-based automatic denial
        if risk_score >= self.config.deny_threshold:
            reasons = [
                f"Risk score {risk_score} exceeds denial threshold "
                f"{self.config.deny_threshold}."
            ]
            explanation = self._build_deny_explanation(request, reasons)
            return AuthorizationDecision.deny(
                reasons=reasons,
                policy="risk-threshold-deny",
                explanation=explanation,
                risk_score=risk_score,
                correlation_id=getattr(request, 'correlation_id', str(uuid.uuid4())),
            )

        # Stage 3: Step-up rules (CONDITION_DEPENDENT treated as step-up)
        step_up_matches = [
            (rule, effect)
            for rule, effect in policy_matches
            if effect == PermissionEffect.CONDITION_DEPENDENT
        ]
        if step_up_matches:
            rule, _ = step_up_matches[0]
            reasons = [
                rule.description
                or f"Step-up required by policy: {rule.name}"
            ]
            approval = self.approval_service.create_approval(
                request, "; ".join(reasons)
            )
            explanation = self._build_step_up_explanation(request, reasons)
            return AuthorizationDecision.step_up(
                reasons=reasons,
                approval_id=approval.request_id,
                policy=rule.rule_id,
                explanation=explanation,
                risk_score=risk_score,
                correlation_id=getattr(request, 'correlation_id', str(uuid.uuid4())),
            )

        # Stage 4: Risk-based step-up
        if risk_score >= self.config.step_up_threshold:
            reasons = [
                f"Risk score {risk_score} exceeds step-up threshold "
                f"{self.config.step_up_threshold}."
            ]
            approval = self.approval_service.create_approval(
                request, "; ".join(reasons)
            )
            explanation = self._build_step_up_explanation(request, reasons)
            return AuthorizationDecision.step_up(
                reasons=reasons,
                approval_id=approval.request_id,
                policy="risk-threshold-step-up",
                explanation=explanation,
                risk_score=risk_score,
                correlation_id=getattr(request, 'correlation_id', str(uuid.uuid4())),
            )

        # Stage 5: Risk-based review
        if risk_score >= self.config.review_threshold:
            reasons = [
                f"Risk score {risk_score} exceeds review threshold "
                f"{self.config.review_threshold}."
            ]
            approval = self.approval_service.create_approval(
                request, "; ".join(reasons)
            )
            explanation = (
                f"REVIEW REQUIRED\n"
                f"Agent: {request.agent_id}\n"
                f"Action: {request.action}\n"
                f"Resource: {request.resource}\n"
                f"Reason: {'; '.join(reasons)}"
            )
            return AuthorizationDecision.review(
                reasons=reasons,
                approval_id=approval.request_id,
                policy="risk-threshold-review",
                explanation=explanation,
                risk_score=risk_score,
                correlation_id=getattr(request, 'correlation_id', str(uuid.uuid4())),
            )

        # Stage 6: Explicit allow rules
        allow_matches = [
            (rule, effect)
            for rule, effect in policy_matches
            if effect == PermissionEffect.ALLOW
        ]
        if allow_matches:
            rule, _ = allow_matches[0]
            reasons = [f"Allowed by policy: {rule.name}"]
            conditions = self._extract_conditions(rule)
            return AuthorizationDecision.allow(
                reasons=reasons,
                policy=rule.rule_id,
                explanation=f"Access granted per policy '{rule.name}'.",
                risk_score=risk_score,
                correlation_id=getattr(request, 'correlation_id', str(uuid.uuid4())),
                conditions=conditions,
            )

        # Stage 7: Default decision (environment-dependent)
        return self._default_decision(request, risk_score)

    def _default_decision(
        self, request: AuthorizationRequest, risk_score: int
    ) -> AuthorizationDecision:
        """Apply the default decision based on environment configuration.

        - Fail-open environments: ALLOW with logging (for development)
        - Fail-closed environments: DENY (for production safety)

        Args:
            request: The authorization request.
            risk_score: Computed risk score.

        Returns:
            Default AuthorizationDecision for the environment.
        """
        if request.environment and request.environment in self.config.fail_open_environments:
            # Fail-open: allow with logging
            reasons = [
                f"Default ALLOW in {request.environment.value if request.environment else 'unknown'} environment "
                "(no matching policy rule; fail-open mode)."
            ]
            logger.warning(
                "FAIL-OPEN: Allowing %s:%s on %s with no explicit policy match "
                "(environment=%s, correlation=%s)",
                request.agent_id,
                request.action,
                request.resource,
                request.environment.value if request.environment else "unknown",
                getattr(request, 'correlation_id', str(uuid.uuid4())),
            )
            return AuthorizationDecision.allow(
                reasons=reasons,
                policy="default-fail-open",
                explanation=(
                    f"Access granted by default (fail-open mode in "
                    f"{request.environment.value if request.environment else 'unknown'}). No explicit policy matched."
                ),
                risk_score=risk_score,
                correlation_id=getattr(request, 'correlation_id', str(uuid.uuid4())),
                conditions=["audit-logged", "monitor-for-anomalies"],
            )

        # Fail-closed: deny (default for production/staging)
        reasons = [
            f"No explicit allow policy matched. "
            f"Default DENY in {request.environment.value if request.environment else 'production'} environment "
            "(fail-closed mode)."
        ]
        explanation = self._build_deny_explanation(request, reasons)
        return AuthorizationDecision.deny(
            reasons=reasons,
            policy="default-fail-closed",
            explanation=explanation,
            risk_score=max(risk_score, 50),
            correlation_id=getattr(request, 'correlation_id', str(uuid.uuid4())),
        )

    def _build_deny_explanation(
        self, request: AuthorizationRequest, reasons: list[str]
    ) -> str:
        """Build a human-readable DENY explanation.

        Args:
            request: The authorization request.
            reasons: List of denial reasons.

        Returns:
            Formatted multi-line denial explanation.
        """
        return (
            f"DENIED\n"
            f"Agent: {request.agent_id}\n"
            f"Action: {request.action}\n"
            f"Resource: {request.resource}\n"
            f"Reason: {'; '.join(reasons)}"
        )

    def _build_step_up_explanation(
        self, request: AuthorizationRequest, reasons: list[str]
    ) -> str:
        """Build a human-readable STEP_UP explanation.

        Args:
            request: The authorization request.
            reasons: List of reasons requiring step-up.

        Returns:
            Formatted multi-line step-up explanation.
        """
        return (
            f"STEP-UP REQUIRED\n"
            f"Agent: {request.agent_id}\n"
            f"Action: {request.action}\n"
            f"Resource: {request.resource}\n"
            f"Reason: {'; '.join(reasons)}"
        )

    def _extract_conditions(self, rule: PolicyRule) -> list[str]:
        """Extract human-readable conditions from a policy rule.

        Args:
            rule: The policy rule to extract conditions from.

        Returns:
            List of condition strings.
        """
        conditions: list[str] = []
        for key, value in rule.conditions.items():
            if isinstance(value, list):
                conditions.append(f"{key} in [{', '.join(str(v) for v in value)}]")
            else:
                conditions.append(f"{key} = {value}")
        return conditions

    def _emit_audit(
        self, request: AuthorizationRequest, decision: AuthorizationDecision
    ) -> None:
        """Emit an audit event for the authorization decision.

        Args:
            request: The authorization request.
            decision: The resulting authorization decision.
        """
        if not self.config.log_all_decisions and decision.decision == Decision.ALLOW:
            return

        # Get the previous hash for chain integrity
        previous_hash = ""
        if isinstance(self.audit_logger, DefaultAuditLogger):
            previous_hash = self.audit_logger.last_hash

        event = AuditEvent.create(
            who=request.principal,
            agent=request.agent_id,
            action=request.action,
            resource=request.resource,
            decision=decision.decision,
            reason="; ".join(decision.reasons),
            policy_version=decision.policy,
            correlation_id=getattr(request, 'correlation_id', str(uuid.uuid4())),
            previous_hash=previous_hash,
        )
        self.audit_logger.log(event)

    def invalidate_cache(self, request: AuthorizationRequest) -> None:
        """Invalidate a cached decision for a specific request.

        Use this when policies change or when a step-up has been completed.

        Args:
            request: The request whose cached decision should be removed.
        """
        self.cache.invalidate(request)

    def clear_cache(self) -> None:
        """Clear the entire decision cache.

        Use after bulk policy updates or configuration changes.
        """
        self.cache.clear()
        logger.info("Decision cache cleared.")


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Core Service
    "AuthorizationService",
    # Models
    "AuthorizationRequest",
    "AuthorizationDecision",
    # Configuration
    "AuthorizationConfig",
    # Engines & Services
    "RiskEngine",
    "PolicyEngine",
    "ApprovalService",
    "AuditLogger",
    # Default Implementations
    "DefaultRiskEngine",
    "DefaultPolicyEngine",
    "DefaultApprovalService",
    "DefaultAuditLogger",
    # Cache
    "DecisionCache",
]
