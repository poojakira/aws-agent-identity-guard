"""AWS Agent Identity Guard - Human-in-the-Loop Approval System.

Production-grade step-up approval workflow for sensitive agent actions.
Provides identity-bound, time-limited, action-specific, auditable,
and non-replayable approval decisions.

This module implements:
- ApprovalRequest: Rich dataclass capturing full approval context.
- ApprovalDecision: The outcome of an approval action.
- ApprovalPolicy: Role-based policies governing who can approve what.
- ApprovalStore (ABC): Pluggable backend interface for persistence.
- InMemoryApprovalStore: Default in-memory store for development/testing.
- ApprovalService: Orchestrates the full approval lifecycle.
- AuditLog integration: Every approval event is logged with full context.

Example:
    >>> from aws_agent_identity_guard.approval import (
    ...     ApprovalService, ApprovalPolicy, InMemoryApprovalStore
    ... )
    >>> policy = ApprovalPolicy(
    ...     authorized_roles={"security-admin", "team-lead"},
    ...     approval_ttl_seconds=900,
    ... )
    >>> store = InMemoryApprovalStore()
    >>> service = ApprovalService(store=store, policy=policy)
    >>> req = service.request_approval(
    ...     agent_id="agent-001",
    ...     action="s3:DeleteBucket",
    ...     resource="arn:aws:s3:::production-data",
    ...     requestor="automation-pipeline",
    ...     risk_score=0.92,
    ...     reason="Critical data deletion in production",
    ... )
    >>> decision = service.approve(
    ...     request_id=req.request_id,
    ...     approver="admin@corp.com",
    ...     justification="Approved per change request CR-4521",
    ... )
"""

from __future__ import annotations

import logging
import threading
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, unique
from typing import Any, Callable, Optional, Protocol, runtime_checkable

from .models import ApprovalStatus, AuditEvent, Decision

# =============================================================================
# Module Logger
# =============================================================================

logger = logging.getLogger(__name__)


# =============================================================================
# Helper
# =============================================================================


def _utcnow() -> datetime:
    """Return current UTC time with timezone info."""
    return datetime.now(timezone.utc)


# =============================================================================
# Approval Data Models
# =============================================================================


@dataclass
class ApprovalConditions:
    """Scoping conditions that define what an approval authorizes.

    An approval is never a blanket bypass  -  it is scoped to a specific
    action on a specific resource, optionally with additional constraints.
    """

    action: str
    """The exact action approved (e.g., 's3:DeleteBucket')."""

    resource: str
    """The exact resource ARN approved."""

    valid_from: datetime = field(default_factory=_utcnow)
    """Earliest time the approval is valid."""

    valid_until: Optional[datetime] = None
    """Latest time the approval is valid (set from TTL)."""

    max_invocations: int = 1
    """Maximum number of times this approval can be consumed. Default: single-use."""

    additional_constraints: dict[str, Any] = field(default_factory=dict)
    """Extra constraints (IP range, region, etc.)."""

    def is_valid_for(self, action: str, resource: str) -> bool:
        """Check if this approval covers the given action and resource.

        Args:
            action: The action being attempted.
            resource: The resource being accessed.

        Returns:
            True if the conditions match exactly.
        """
        return self.action == action and self.resource == resource


@dataclass
class ApprovalRequest:
    """Full-context approval request for a sensitive agent action.

    Captures the complete context required for an informed approval
    decision, including identity, action, risk, and audit metadata.
    """

    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    """Unique identifier for this approval request (UUID)."""

    agent_id: str = ""
    """The agent whose action requires approval."""

    agent_name: str = ""
    """Human-readable name of the agent."""

    action: str = ""
    """The specific action requiring approval (e.g., 's3:DeleteBucket')."""

    resource: str = ""
    """The target resource ARN."""

    requestor: str = ""
    """Identity of whoever triggered the approval request."""

    risk_score: float = 0.0
    """Composite risk score (0.0 - 1.0) from the risk engine."""

    reason: str = ""
    """Human-readable reason why step-up approval is required."""

    status: ApprovalStatus = ApprovalStatus.PENDING
    """Current workflow state."""

    created_at: datetime = field(default_factory=_utcnow)
    """When the request was created."""

    expires_at: Optional[datetime] = None
    """When the request expires if not actioned."""

    approved_by: Optional[str] = None
    """Identity of the approver (set on approval/denial)."""

    approved_at: Optional[datetime] = None
    """Timestamp of the approval/denial decision."""

    justification: Optional[str] = None
    """Approver's justification for the decision."""

    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    """Correlation ID for tracing across distributed systems."""

    conditions: Optional[ApprovalConditions] = None
    """Scoping conditions for what this approval authorizes."""

    invocation_count: int = 0
    """How many times this approval has been consumed (for non-replayability)."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Additional metadata for extensibility."""

    @property
    def is_expired(self) -> bool:
        """Whether the request has exceeded its TTL."""
        if self.expires_at is None:
            return False
        return _utcnow() > self.expires_at

    @property
    def is_pending(self) -> bool:
        """Whether the request is still awaiting a decision."""
        return self.status == ApprovalStatus.PENDING and not self.is_expired

    @property
    def is_consumable(self) -> bool:
        """Whether this approval can still be consumed (not replayed).

        An approval is consumable only if:
        - Status is APPROVED
        - Not expired
        - Invocation count hasn't exceeded max_invocations in conditions
        """
        if self.status != ApprovalStatus.APPROVED:
            return False
        if self.is_expired:
            return False
        if self.conditions and self.invocation_count >= self.conditions.max_invocations:
            return False
        return True

    def consume(self) -> bool:
        """Consume one use of this approval.

        Returns:
            True if successfully consumed, False if not consumable.
        """
        if not self.is_consumable:
            return False
        self.invocation_count += 1
        return True

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for storage/transport."""
        return {
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "action": self.action,
            "resource": self.resource,
            "requestor": self.requestor,
            "risk_score": self.risk_score,
            "reason": self.reason,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "justification": self.justification,
            "correlation_id": self.correlation_id,
            "invocation_count": self.invocation_count,
            "metadata": self.metadata,
        }


@dataclass
class ApprovalDecision:
    """The outcome of processing an approval request.

    Captures the decision, who made it, and the full audit trail.
    """

    request_id: str
    """The request this decision applies to."""

    status: ApprovalStatus
    """The decision: APPROVED or DENIED."""

    decided_by: str
    """Identity of the decision maker."""

    decided_at: datetime = field(default_factory=_utcnow)
    """When the decision was made."""

    justification: str = ""
    """Reason for the decision."""

    correlation_id: str = ""
    """Correlation ID linking back to the original request."""

    conditions: Optional[ApprovalConditions] = None
    """Scoped conditions (carried from the request)."""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "request_id": self.request_id,
            "status": self.status.value,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at.isoformat(),
            "justification": self.justification,
            "correlation_id": self.correlation_id,
        }


# =============================================================================
# Approval Policy
# =============================================================================


@dataclass
class ApprovalPolicy:
    """Configuration for approval authorization and behavior.

    Defines who can approve, what constraints apply, and how
    escalation works when approvals time out.

    Attributes:
        authorized_roles: Set of roles that can approve requests.
        approval_ttl_seconds: How long an approval request remains valid.
            Default is 900 seconds (15 minutes).
        escalation_ttl_seconds: Time before escalation is triggered if
            no response. Default is 600 seconds (10 minutes).
        escalation_targets: Identities to escalate to if no response.
        allow_self_approval: Whether a requestor can approve their own
            request. Always False for security.
        role_action_mapping: Maps roles to action patterns they can approve.
            If empty, any authorized role can approve any action.
    """

    authorized_roles: set[str] = field(
        default_factory=lambda: {"security-admin", "team-lead"}
    )
    """Roles authorized to approve requests."""

    approval_ttl_seconds: int = 900
    """TTL for approval requests in seconds (default: 15 minutes)."""

    escalation_ttl_seconds: int = 600
    """Seconds before escalation if no response (default: 10 minutes)."""

    escalation_targets: list[str] = field(default_factory=list)
    """Identities to notify on escalation."""

    allow_self_approval: bool = False
    """Whether requestor can approve their own request. Always False."""

    role_action_mapping: dict[str, list[str]] = field(default_factory=dict)
    """Maps roles to action patterns they can approve. Empty = all actions."""

    def can_approve(
        self,
        approver: str,
        approver_roles: set[str],
        request: ApprovalRequest,
    ) -> tuple[bool, str]:
        """Determine whether an approver is authorized for this request.

        Args:
            approver: Identity of the would-be approver.
            approver_roles: Roles held by the approver.
            request: The approval request being evaluated.

        Returns:
            Tuple of (is_authorized, denial_reason).
        """
        # Self-approval check
        if not self.allow_self_approval and approver == request.requestor:
            return False, "Self-approval is not permitted"

        # Role check
        matching_roles = approver_roles & self.authorized_roles
        if not matching_roles:
            return False, (
                f"Approver lacks required roles. Has: {approver_roles}, "
                f"needs one of: {self.authorized_roles}"
            )

        # Action-specific role check
        if self.role_action_mapping:
            action = request.action
            authorized_for_action = False
            for role in matching_roles:
                allowed_patterns = self.role_action_mapping.get(role, [])
                if _action_matches_patterns(action, allowed_patterns):
                    authorized_for_action = True
                    break
            if not authorized_for_action:
                return False, (
                    f"None of approver's roles ({matching_roles}) are "
                    f"authorized for action '{action}'"
                )

        return True, ""

    def should_escalate(self, request: ApprovalRequest) -> bool:
        """Check if a pending request should be escalated.

        Args:
            request: The request to check.

        Returns:
            True if the request has been pending longer than escalation_ttl.
        """
        if request.status != ApprovalStatus.PENDING:
            return False
        elapsed = (_utcnow() - request.created_at).total_seconds()
        return elapsed >= self.escalation_ttl_seconds


def _action_matches_patterns(action: str, patterns: list[str]) -> bool:
    """Check if an action matches any of the given patterns.

    Supports simple glob-style matching with '*' wildcard.

    Args:
        action: The action to match (e.g., 's3:DeleteBucket').
        patterns: List of patterns (e.g., ['s3:*', 'ec2:Terminate*']).

    Returns:
        True if any pattern matches.
    """
    if not patterns:
        return True  # Empty patterns = match all

    import fnmatch

    for pattern in patterns:
        if fnmatch.fnmatch(action, pattern):
            return True
    return False


# =============================================================================
# Approval Store Protocol / ABC
# =============================================================================


class ApprovalStore(ABC):
    """Abstract base class for approval request persistence.

    Implement this interface to plug in custom backends such as
    Redis, DynamoDB, PostgreSQL, or any durable store.

    All implementations must be thread-safe.
    """

    @abstractmethod
    def save(self, request: ApprovalRequest) -> None:
        """Persist an approval request.

        Args:
            request: The approval request to store.

        Raises:
            ApprovalStoreError: If the save operation fails.
        """
        ...

    @abstractmethod
    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        """Retrieve an approval request by ID.

        Args:
            request_id: The unique request identifier.

        Returns:
            The ApprovalRequest if found, None otherwise.
        """
        ...

    @abstractmethod
    def update(self, request: ApprovalRequest) -> None:
        """Update an existing approval request.

        Args:
            request: The updated approval request.

        Raises:
            ApprovalNotFoundError: If the request doesn't exist.
            ApprovalStoreError: If the update operation fails.
        """
        ...

    @abstractmethod
    def list_pending(self, approver: Optional[str] = None) -> list[ApprovalRequest]:
        """List all pending approval requests.

        Args:
            approver: If provided, filter to requests relevant to this approver.

        Returns:
            List of pending approval requests.
        """
        ...

    @abstractmethod
    def list_expired(self) -> list[ApprovalRequest]:
        """List all requests that have exceeded their TTL but are still PENDING.

        Returns:
            List of expired-but-not-yet-updated requests.
        """
        ...

    @abstractmethod
    def delete(self, request_id: str) -> bool:
        """Delete an approval request.

        Args:
            request_id: The request to delete.

        Returns:
            True if deleted, False if not found.
        """
        ...


# =============================================================================
# In-Memory Store Implementation
# =============================================================================


class InMemoryApprovalStore(ApprovalStore):
    """Thread-safe in-memory approval store for development and testing.

    This implementation stores all requests in a dictionary protected
    by a threading lock. Suitable for single-process deployments or
    testing scenarios.

    For production use with multiple workers or distributed systems,
    implement ApprovalStore with Redis, DynamoDB, or similar.
    """

    def __init__(self) -> None:
        """Initialize the in-memory store."""
        self._store: dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()

    def save(self, request: ApprovalRequest) -> None:
        """Persist an approval request in memory.

        Args:
            request: The approval request to store.
        """
        with self._lock:
            self._store[request.request_id] = request
        logger.debug("Stored approval request %s", request.request_id)

    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        """Retrieve an approval request by ID.

        Args:
            request_id: The unique request identifier.

        Returns:
            The ApprovalRequest if found, None otherwise.
        """
        with self._lock:
            return self._store.get(request_id)

    def update(self, request: ApprovalRequest) -> None:
        """Update an existing approval request.

        Args:
            request: The updated approval request.

        Raises:
            ApprovalNotFoundError: If the request doesn't exist.
        """
        with self._lock:
            if request.request_id not in self._store:
                raise ApprovalNotFoundError(
                    f"Request {request.request_id} not found in store"
                )
            self._store[request.request_id] = request
        logger.debug("Updated approval request %s", request.request_id)

    def list_pending(self, approver: Optional[str] = None) -> list[ApprovalRequest]:
        """List all pending approval requests.

        Args:
            approver: Optional filter (currently returns all pending;
                implement role-based filtering in production).

        Returns:
            List of pending approval requests.
        """
        with self._lock:
            results = [
                req
                for req in self._store.values()
                if req.status == ApprovalStatus.PENDING and not req.is_expired
            ]
        return results

    def list_expired(self) -> list[ApprovalRequest]:
        """List requests that are PENDING but past their expiry.

        Returns:
            List of expired approval requests.
        """
        with self._lock:
            return [
                req
                for req in self._store.values()
                if req.status == ApprovalStatus.PENDING and req.is_expired
            ]

    def delete(self, request_id: str) -> bool:
        """Delete an approval request from memory.

        Args:
            request_id: The request to delete.

        Returns:
            True if deleted, False if not found.
        """
        with self._lock:
            if request_id in self._store:
                del self._store[request_id]
                return True
            return False

    @property
    def count(self) -> int:
        """Total number of stored requests."""
        with self._lock:
            return len(self._store)

    def clear(self) -> None:
        """Remove all stored requests (useful for testing)."""
        with self._lock:
            self._store.clear()


# =============================================================================
# Exceptions
# =============================================================================


class ApprovalError(Exception):
    """Base exception for the approval module."""

    pass


class ApprovalNotFoundError(ApprovalError):
    """Raised when an approval request is not found."""

    pass


class ApprovalExpiredError(ApprovalError):
    """Raised when attempting to action an expired request."""

    pass


class ApprovalUnauthorizedError(ApprovalError):
    """Raised when an approver is not authorized."""

    pass


class ApprovalAlreadyDecidedError(ApprovalError):
    """Raised when attempting to action a request that's already decided."""

    pass


class ApprovalStoreError(ApprovalError):
    """Raised when the approval store encounters an error."""

    pass


# =============================================================================
# Audit Log Integration
# =============================================================================


class ApprovalAuditLog:
    """Audit logger for approval events.

    Integrates with the core AuditEvent model to produce tamper-evident
    audit records for every approval lifecycle event.
    """

    def __init__(self, policy_version: str = "1.0.0") -> None:
        """Initialize the audit logger.

        Args:
            policy_version: Version string for the approval policy.
        """
        self._policy_version = policy_version
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()
        self._listeners: list[Callable[[AuditEvent], None]] = []

    def add_listener(self, listener: Callable[[AuditEvent], None]) -> None:
        """Register a listener to be notified of audit events.

        Args:
            listener: Callable that receives AuditEvent instances.
        """
        self._listeners.append(listener)

    def log_request_created(self, request: ApprovalRequest) -> AuditEvent:
        """Log creation of a new approval request.

        Args:
            request: The newly created request.

        Returns:
            The generated AuditEvent.
        """
        return self._emit(
            who=request.requestor,
            agent=request.agent_id,
            action=f"approval:request_created:{request.action}",
            resource=request.resource,
            decision=Decision.STEP_UP,
            reason=(
                f"Approval requested: {request.reason} "
                f"(risk_score={request.risk_score:.2f})"
            ),
            correlation_id=request.correlation_id,
        )

    def log_approved(
        self, request: ApprovalRequest, approver: str, justification: str
    ) -> AuditEvent:
        """Log an approval decision.

        Args:
            request: The approved request.
            approver: Who approved it.
            justification: Why it was approved.

        Returns:
            The generated AuditEvent.
        """
        return self._emit(
            who=approver,
            agent=request.agent_id,
            action=f"approval:approved:{request.action}",
            resource=request.resource,
            decision=Decision.ALLOW,
            reason=f"Approved: {justification}",
            correlation_id=request.correlation_id,
        )

    def log_denied(
        self, request: ApprovalRequest, approver: str, reason: str
    ) -> AuditEvent:
        """Log a denial decision.

        Args:
            request: The denied request.
            approver: Who denied it.
            reason: Why it was denied.

        Returns:
            The generated AuditEvent.
        """
        return self._emit(
            who=approver,
            agent=request.agent_id,
            action=f"approval:denied:{request.action}",
            resource=request.resource,
            decision=Decision.DENY,
            reason=f"Denied: {reason}",
            correlation_id=request.correlation_id,
        )

    def log_expired(self, request: ApprovalRequest) -> AuditEvent:
        """Log expiration of an approval request.

        Args:
            request: The expired request.

        Returns:
            The generated AuditEvent.
        """
        return self._emit(
            who="system",
            agent=request.agent_id,
            action=f"approval:expired:{request.action}",
            resource=request.resource,
            decision=Decision.DENY,
            reason=(
                f"Approval request expired after "
                f"{(request.expires_at - request.created_at).total_seconds():.0f}s"
                if request.expires_at
                else "Approval request expired"
            ),
            correlation_id=request.correlation_id,
        )

    def log_escalated(self, request: ApprovalRequest, targets: list[str]) -> AuditEvent:
        """Log escalation of an approval request.

        Args:
            request: The request being escalated.
            targets: Escalation target identities.

        Returns:
            The generated AuditEvent.
        """
        return self._emit(
            who="system",
            agent=request.agent_id,
            action=f"approval:escalated:{request.action}",
            resource=request.resource,
            decision=Decision.REVIEW,
            reason=f"Escalated to: {', '.join(targets)}",
            correlation_id=request.correlation_id,
        )

    def log_consumed(self, request: ApprovalRequest, consumer: str) -> AuditEvent:
        """Log consumption of an approved request.

        Args:
            request: The consumed approval.
            consumer: Who consumed it.

        Returns:
            The generated AuditEvent.
        """
        return self._emit(
            who=consumer,
            agent=request.agent_id,
            action=f"approval:consumed:{request.action}",
            resource=request.resource,
            decision=Decision.ALLOW,
            reason=(
                f"Approval consumed (invocation {request.invocation_count}"
                f"/{request.conditions.max_invocations if request.conditions else 1})"
            ),
            correlation_id=request.correlation_id,
        )

    @property
    def events(self) -> list[AuditEvent]:
        """All recorded audit events (read-only copy)."""
        with self._lock:
            return list(self._events)

    def _emit(
        self,
        who: str,
        agent: str,
        action: str,
        resource: str,
        decision: Decision,
        reason: str,
        correlation_id: str,
    ) -> AuditEvent:
        """Create, store, and emit an audit event.

        Args:
            who: Principal performing the action.
            agent: Agent identity involved.
            action: Action identifier.
            resource: Target resource.
            decision: Authorization decision.
            reason: Human-readable reason.
            correlation_id: Trace correlation ID.

        Returns:
            The created AuditEvent.
        """
        with self._lock:
            previous_hash = self._events[-1].integrity_hash if self._events else ""

        event = AuditEvent.create(
            who=who,
            agent=agent,
            action=action,
            resource=resource,
            decision=decision,
            reason=reason,
            policy_version=self._policy_version,
            correlation_id=correlation_id,
            previous_hash=previous_hash,
        )

        with self._lock:
            self._events.append(event)

        # Notify listeners
        for listener in self._listeners:
            try:
                listener(event)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Audit listener raised exception: %s", exc, exc_info=True
                )

        logger.info(
            "AUDIT [%s] who=%s agent=%s action=%s resource=%s decision=%s",
            correlation_id[:8],
            who,
            agent,
            action,
            resource,
            decision.value,
        )

        return event


# =============================================================================
# Approver Registry
# =============================================================================


@dataclass
class ApproverIdentity:
    """Registered approver with their roles and contact info."""

    identity: str
    """Unique identifier (email, username, or principal ARN)."""

    roles: set[str] = field(default_factory=set)
    """Roles held by this approver."""

    display_name: str = ""
    """Human-readable display name."""

    contact_channel: str = ""
    """Notification channel (email, Slack, PagerDuty, etc.)."""

    active: bool = True
    """Whether this approver is currently active."""


class ApproverRegistry:
    """Registry of authorized approvers and their roles.

    Provides lookup of approver identities and their associated
    roles for policy enforcement.
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._approvers: dict[str, ApproverIdentity] = {}
        self._lock = threading.Lock()

    def register(self, approver: ApproverIdentity) -> None:
        """Register an approver.

        Args:
            approver: The approver identity to register.
        """
        with self._lock:
            self._approvers[approver.identity] = approver
        logger.debug("Registered approver: %s", approver.identity)

    def unregister(self, identity: str) -> bool:
        """Remove an approver from the registry.

        Args:
            identity: The approver's identity to remove.

        Returns:
            True if removed, False if not found.
        """
        with self._lock:
            if identity in self._approvers:
                del self._approvers[identity]
                return True
            return False

    def get(self, identity: str) -> Optional[ApproverIdentity]:
        """Look up an approver by identity.

        Args:
            identity: The approver's identifier.

        Returns:
            The ApproverIdentity if found and active, None otherwise.
        """
        with self._lock:
            approver = self._approvers.get(identity)
            if approver and approver.active:
                return approver
            return None

    def get_roles(self, identity: str) -> set[str]:
        """Get roles for an approver identity.

        Args:
            identity: The approver's identifier.

        Returns:
            Set of roles, empty if not found.
        """
        approver = self.get(identity)
        return approver.roles if approver else set()

    def list_by_role(self, role: str) -> list[ApproverIdentity]:
        """List all active approvers with a specific role.

        Args:
            role: The role to filter by.

        Returns:
            List of approvers holding the specified role.
        """
        with self._lock:
            return [
                a
                for a in self._approvers.values()
                if a.active and role in a.roles
            ]


# =============================================================================
# Escalation Handler
# =============================================================================


class EscalationHandler:
    """Handles escalation when approval requests are not actioned in time.

    Pluggable notification mechanism  -  override `notify` for custom
    integrations (SNS, PagerDuty, Slack, etc.).
    """

    def __init__(
        self,
        policy: ApprovalPolicy,
        registry: ApproverRegistry,
        audit_log: ApprovalAuditLog,
    ) -> None:
        """Initialize the escalation handler.

        Args:
            policy: The approval policy with escalation configuration.
            registry: The approver registry for resolving targets.
            audit_log: Audit logger for recording escalations.
        """
        self._policy = policy
        self._registry = registry
        self._audit_log = audit_log

    def check_and_escalate(self, request: ApprovalRequest) -> bool:
        """Check if a request needs escalation and handle it.

        Args:
            request: The approval request to evaluate.

        Returns:
            True if escalation was triggered, False otherwise.
        """
        if not self._policy.should_escalate(request):
            return False

        targets = self._resolve_escalation_targets(request)
        if not targets:
            logger.warning(
                "No escalation targets available for request %s",
                request.request_id,
            )
            return False

        self._audit_log.log_escalated(request, targets)
        self.notify(request, targets)
        return True

    def _resolve_escalation_targets(self, request: ApprovalRequest) -> list[str]:
        """Resolve escalation targets from policy and registry.

        Args:
            request: The request needing escalation.

        Returns:
            List of target identities to escalate to.
        """
        targets = list(self._policy.escalation_targets)

        # Also find all security-admins as fallback
        if not targets:
            for role in self._policy.authorized_roles:
                approvers = self._registry.list_by_role(role)
                for approver in approvers:
                    if approver.identity != request.requestor:
                        targets.append(approver.identity)

        return targets

    def notify(self, request: ApprovalRequest, targets: list[str]) -> None:
        """Send escalation notifications.

        Override this method for custom notification integrations.

        Args:
            request: The request being escalated.
            targets: Identities to notify.
        """
        logger.warning(
            "ESCALATION: Request %s (action=%s, resource=%s, risk=%.2f) "
            "has not been actioned. Escalating to: %s",
            request.request_id,
            request.action,
            request.resource,
            request.risk_score,
            ", ".join(targets),
        )


# =============================================================================
# Approval Service
# =============================================================================


class ApprovalService:
    """Orchestrates the human-in-the-loop approval workflow.

    This is the primary entry point for requesting, granting, denying,
    and managing approval requests. It enforces all approval constraints:

    - Identity-bound: Only authorized approvers can approve.
    - Time-limited: Approvals expire after configurable TTL.
    - Action-specific: Approval is for THIS action on THIS resource.
    - Auditable: Every event is logged with full context.
    - Non-replayable: A consumed approval cannot be reused.

    Example:
        >>> store = InMemoryApprovalStore()
        >>> policy = ApprovalPolicy(approval_ttl_seconds=900)
        >>> registry = ApproverRegistry()
        >>> registry.register(ApproverIdentity(
        ...     identity="admin@corp.com",
        ...     roles={"security-admin"},
        ... ))
        >>> service = ApprovalService(
        ...     store=store, policy=policy, registry=registry
        ... )
        >>> req = service.request_approval(
        ...     agent_id="agent-001",
        ...     action="s3:DeleteBucket",
        ...     resource="arn:aws:s3:::prod-data",
        ...     requestor="pipeline-user",
        ...     risk_score=0.85,
        ...     reason="High-risk deletion in production",
        ... )
    """

    def __init__(
        self,
        store: ApprovalStore,
        policy: Optional[ApprovalPolicy] = None,
        registry: Optional[ApproverRegistry] = None,
        audit_log: Optional[ApprovalAuditLog] = None,
        escalation_handler: Optional[EscalationHandler] = None,
        agent_name_resolver: Optional[Callable[[str], str]] = None,
    ) -> None:
        """Initialize the ApprovalService.

        Args:
            store: Backend store for approval requests.
            policy: Approval policy configuration. Uses defaults if None.
            registry: Approver registry. Creates empty one if None.
            audit_log: Audit logger. Creates default one if None.
            escalation_handler: Custom escalation handler. Creates default if None.
            agent_name_resolver: Optional callable to resolve agent_id to name.
        """
        self._store = store
        self._policy = policy or ApprovalPolicy()
        self._registry = registry or ApproverRegistry()
        self._audit_log = audit_log or ApprovalAuditLog()
        self._escalation_handler = escalation_handler or EscalationHandler(
            policy=self._policy,
            registry=self._registry,
            audit_log=self._audit_log,
        )
        self._agent_name_resolver = agent_name_resolver

    @property
    def policy(self) -> ApprovalPolicy:
        """The active approval policy."""
        return self._policy

    @property
    def registry(self) -> ApproverRegistry:
        """The approver registry."""
        return self._registry

    @property
    def audit_log(self) -> ApprovalAuditLog:
        """The audit log."""
        return self._audit_log

    def request_approval(
        self,
        agent_id: str,
        action: str,
        resource: str,
        requestor: str,
        risk_score: float,
        reason: str,
        agent_name: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> ApprovalRequest:
        """Create a new approval request for a sensitive action.

        This initiates the human-in-the-loop workflow. The request will
        remain PENDING until an authorized approver acts on it or it expires.

        Args:
            agent_id: The agent identity requesting the action.
            action: The specific action requiring approval.
            resource: The target resource ARN.
            requestor: Identity of whoever triggered the request.
            risk_score: Risk score from the risk engine (0.0-1.0).
            reason: Human-readable explanation of why approval is needed.
            agent_name: Optional human-readable agent name.
            metadata: Optional additional metadata.

        Returns:
            The created ApprovalRequest in PENDING status.

        Raises:
            ValueError: If risk_score is out of range.
        """
        if not (0.0 <= risk_score <= 1.0):
            raise ValueError(f"risk_score must be between 0.0 and 1.0, got {risk_score}")

        # Resolve agent name
        resolved_name = agent_name or ""
        if not resolved_name and self._agent_name_resolver:
            try:
                resolved_name = self._agent_name_resolver(agent_id)
            except Exception:  # noqa: BLE001
                resolved_name = agent_id

        now = _utcnow()
        expires_at = now + timedelta(seconds=self._policy.approval_ttl_seconds)

        request = ApprovalRequest(
            request_id=str(uuid.uuid4()),
            agent_id=agent_id,
            agent_name=resolved_name,
            action=action,
            resource=resource,
            requestor=requestor,
            risk_score=risk_score,
            reason=reason,
            status=ApprovalStatus.PENDING,
            created_at=now,
            expires_at=expires_at,
            correlation_id=str(uuid.uuid4()),
            conditions=ApprovalConditions(
                action=action,
                resource=resource,
                valid_from=now,
                valid_until=expires_at,
                max_invocations=1,
            ),
            metadata=metadata or {},
        )

        self._store.save(request)
        self._audit_log.log_request_created(request)

        logger.info(
            "Approval request created: id=%s agent=%s action=%s resource=%s risk=%.2f",
            request.request_id,
            agent_id,
            action,
            resource,
            risk_score,
        )

        return request

    def approve(
        self,
        request_id: str,
        approver: str,
        justification: str,
    ) -> ApprovalDecision:
        """Approve a pending request.

        Enforces all approval constraints:
        - Request must exist and be PENDING
        - Request must not be expired
        - Approver must be authorized (role-based)
        - Approver cannot self-approve

        Args:
            request_id: The request to approve.
            approver: Identity of the approver.
            justification: Reason for approving.

        Returns:
            ApprovalDecision with status APPROVED.

        Raises:
            ApprovalNotFoundError: If request doesn't exist.
            ApprovalExpiredError: If request has expired.
            ApprovalAlreadyDecidedError: If request is not PENDING.
            ApprovalUnauthorizedError: If approver lacks authorization.
        """
        request = self._get_and_validate(request_id, approver)

        # Apply the approval
        now = _utcnow()
        request.status = ApprovalStatus.APPROVED
        request.approved_by = approver
        request.approved_at = now
        request.justification = justification

        # Update expiry on conditions to match from-now
        if request.conditions:
            request.conditions.valid_from = now
            request.conditions.valid_until = request.expires_at

        self._store.update(request)
        self._audit_log.log_approved(request, approver, justification)

        logger.info(
            "Approval GRANTED: id=%s approver=%s action=%s resource=%s",
            request_id,
            approver,
            request.action,
            request.resource,
        )

        return ApprovalDecision(
            request_id=request_id,
            status=ApprovalStatus.APPROVED,
            decided_by=approver,
            decided_at=now,
            justification=justification,
            correlation_id=request.correlation_id,
            conditions=request.conditions,
        )

    def deny(
        self,
        request_id: str,
        approver: str,
        reason: str,
    ) -> ApprovalDecision:
        """Deny a pending request.

        Args:
            request_id: The request to deny.
            approver: Identity of the denier.
            reason: Reason for denial.

        Returns:
            ApprovalDecision with status DENIED.

        Raises:
            ApprovalNotFoundError: If request doesn't exist.
            ApprovalExpiredError: If request has expired.
            ApprovalAlreadyDecidedError: If request is not PENDING.
            ApprovalUnauthorizedError: If approver lacks authorization.
        """
        request = self._get_and_validate(request_id, approver)

        # Apply the denial
        now = _utcnow()
        request.status = ApprovalStatus.DENIED
        request.approved_by = approver
        request.approved_at = now
        request.justification = reason

        self._store.update(request)
        self._audit_log.log_denied(request, approver, reason)

        logger.info(
            "Approval DENIED: id=%s approver=%s action=%s resource=%s reason=%s",
            request_id,
            approver,
            request.action,
            request.resource,
            reason,
        )

        return ApprovalDecision(
            request_id=request_id,
            status=ApprovalStatus.DENIED,
            decided_by=approver,
            decided_at=now,
            justification=reason,
            correlation_id=request.correlation_id,
        )

    def check_approval(self, request_id: str) -> ApprovalStatus:
        """Check the current status of an approval request.

        Also handles lazy expiration  -  if the request is found to be
        expired, updates its status.

        Args:
            request_id: The request to check.

        Returns:
            Current ApprovalStatus.

        Raises:
            ApprovalNotFoundError: If request doesn't exist.
        """
        request = self._store.get(request_id)
        if request is None:
            raise ApprovalNotFoundError(f"Approval request {request_id} not found")

        # Lazy expiration
        if request.status == ApprovalStatus.PENDING and request.is_expired:
            request.status = ApprovalStatus.EXPIRED
            self._store.update(request)
            self._audit_log.log_expired(request)
            logger.info("Approval request %s expired (lazy check)", request_id)

        return request.status

    def list_pending(self, approver: Optional[str] = None) -> list[ApprovalRequest]:
        """List all pending approval requests.

        Args:
            approver: If provided, filter to requests this approver
                is authorized to action.

        Returns:
            List of pending ApprovalRequest objects.
        """
        pending = self._store.list_pending(approver)

        # Check escalation for each pending request
        for request in pending:
            self._escalation_handler.check_and_escalate(request)

        return pending

    def expire_stale(self) -> int:
        """Expire all stale (past-TTL) pending requests.

        Scans for requests that have exceeded their TTL and transitions
        them to EXPIRED status. Each expiration is audit-logged.

        Returns:
            Number of requests expired.
        """
        expired_requests = self._store.list_expired()
        count = 0

        for request in expired_requests:
            request.status = ApprovalStatus.EXPIRED
            self._store.update(request)
            self._audit_log.log_expired(request)
            count += 1
            logger.info(
                "Expired stale approval request: id=%s action=%s resource=%s",
                request.request_id,
                request.action,
                request.resource,
            )

        if count > 0:
            logger.info("Expired %d stale approval requests", count)

        return count

    def consume_approval(
        self,
        request_id: str,
        action: str,
        resource: str,
        consumer: str,
    ) -> bool:
        """Consume an approved request (marks it as used).

        Enforces non-replayability: once consumed up to max_invocations,
        the approval cannot be reused.

        Args:
            request_id: The approval to consume.
            action: The action being performed (must match).
            resource: The resource being accessed (must match).
            consumer: Identity of who is consuming the approval.

        Returns:
            True if successfully consumed, False otherwise.

        Raises:
            ApprovalNotFoundError: If request doesn't exist.
        """
        request = self._store.get(request_id)
        if request is None:
            raise ApprovalNotFoundError(f"Approval request {request_id} not found")

        # Validate conditions match
        if request.conditions and not request.conditions.is_valid_for(action, resource):
            logger.warning(
                "Approval consumption rejected: conditions don't match. "
                "Expected action=%s resource=%s, got action=%s resource=%s",
                request.conditions.action,
                request.conditions.resource,
                action,
                resource,
            )
            return False

        # Try to consume
        if not request.consume():
            logger.warning(
                "Approval consumption rejected: request %s is not consumable "
                "(status=%s, expired=%s, invocations=%d)",
                request_id,
                request.status.value,
                request.is_expired,
                request.invocation_count,
            )
            return False

        self._store.update(request)
        self._audit_log.log_consumed(request, consumer)

        logger.info(
            "Approval consumed: id=%s consumer=%s invocation=%d",
            request_id,
            consumer,
            request.invocation_count,
        )

        return True

    def cancel(self, request_id: str, cancelled_by: str) -> bool:
        """Cancel a pending approval request.

        Args:
            request_id: The request to cancel.
            cancelled_by: Identity of who is cancelling.

        Returns:
            True if cancelled, False if not in a cancellable state.

        Raises:
            ApprovalNotFoundError: If request doesn't exist.
        """
        request = self._store.get(request_id)
        if request is None:
            raise ApprovalNotFoundError(f"Approval request {request_id} not found")

        if request.status != ApprovalStatus.PENDING:
            return False

        request.status = ApprovalStatus.CANCELLED
        request.approved_by = cancelled_by
        request.approved_at = _utcnow()
        request.justification = "Cancelled"

        self._store.update(request)

        logger.info(
            "Approval request cancelled: id=%s by=%s",
            request_id,
            cancelled_by,
        )

        return True

    def _get_and_validate(
        self, request_id: str, approver: str
    ) -> ApprovalRequest:
        """Retrieve a request and validate it can be actioned.

        Args:
            request_id: The request ID.
            approver: The identity attempting to action the request.

        Returns:
            The validated ApprovalRequest.

        Raises:
            ApprovalNotFoundError: If request doesn't exist.
            ApprovalExpiredError: If request has expired.
            ApprovalAlreadyDecidedError: If request is not PENDING.
            ApprovalUnauthorizedError: If approver lacks authorization.
        """
        request = self._store.get(request_id)
        if request is None:
            raise ApprovalNotFoundError(f"Approval request {request_id} not found")

        # Check if already decided
        if request.status != ApprovalStatus.PENDING:
            raise ApprovalAlreadyDecidedError(
                f"Request {request_id} is already {request.status.value}"
            )

        # Check expiration
        if request.is_expired:
            request.status = ApprovalStatus.EXPIRED
            self._store.update(request)
            self._audit_log.log_expired(request)
            raise ApprovalExpiredError(
                f"Request {request_id} has expired "
                f"(expired at {request.expires_at})"
            )

        # Authorization check
        approver_roles = self._registry.get_roles(approver)
        authorized, denial_reason = self._policy.can_approve(
            approver=approver,
            approver_roles=approver_roles,
            request=request,
        )
        if not authorized:
            raise ApprovalUnauthorizedError(
                f"Approver '{approver}' is not authorized: {denial_reason}"
            )

        return request


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Core classes
    "ApprovalService",
    "ApprovalRequest",
    "ApprovalDecision",
    "ApprovalConditions",
    "ApprovalPolicy",
    # Store interface and implementation
    "ApprovalStore",
    "InMemoryApprovalStore",
    # Approver management
    "ApproverIdentity",
    "ApproverRegistry",
    # Escalation
    "EscalationHandler",
    # Audit
    "ApprovalAuditLog",
    # Exceptions
    "ApprovalError",
    "ApprovalNotFoundError",
    "ApprovalExpiredError",
    "ApprovalUnauthorizedError",
    "ApprovalAlreadyDecidedError",
    "ApprovalStoreError",
]
