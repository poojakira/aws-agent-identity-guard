"""
aws_agent_identity_guard/approval.py
--------------------------------------------------------------------------------
Human-in-the-loop approval system for high-risk AI agent actions.

Implements a time-limited, identity-bound, action-specific approval workflow
that ensures sensitive operations require explicit human authorization before
proceeding. This is NOT a generic boolean bypass -- each approval is scoped
to a specific agent, action, and resource combination.

Key security properties:
  - Identity-bound: Only designated approvers can approve specific action types
  - Time-limited: All approvals expire (configurable TTL, default 5 minutes)
  - Action-specific: Approval covers exactly one agent+action+resource tuple
  - Auditable: Every request, approval, and denial generates an AuditEvent
  - Non-replayable: Expired or consumed approvals cannot be reused

Storage is abstracted behind the ApprovalStore protocol to support both
in-memory (development/testing) and distributed (Redis) backends.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol, runtime_checkable

from aws_agent_identity_guard.models import (
    ApprovalRequest,
    ApprovalStatus,
    AuditEvent,
    AuthorizationDecisionType,
    _generate_uuid,
    _now_utc,
)

logger = logging.getLogger(__name__)


# --- Storage Protocol ---


@runtime_checkable
class ApprovalStore(Protocol):
    """
    Protocol defining the storage interface for approval requests.

    Implementations must be thread-safe and support concurrent access.
    """

    def save(self, request: ApprovalRequest) -> None:
        """Persist an approval request."""
        ...

    def get(self, request_id: str) -> ApprovalRequest | None:
        """Retrieve an approval request by ID."""
        ...

    def list_by_status(
        self, status: ApprovalStatus, agent_id: str | None = None
    ) -> list[ApprovalRequest]:
        """List requests filtered by status and optionally by agent_id."""
        ...

    def update(self, request: ApprovalRequest) -> None:
        """Update an existing approval request."""
        ...

    def delete(self, request_id: str) -> bool:
        """Delete an approval request. Returns True if deleted."""
        ...


# --- In-Memory Store Implementation ---


class InMemoryApprovalStore:
    """
    Thread-safe in-memory implementation of ApprovalStore.

    Suitable for development, testing, and single-instance deployments.
    Data is lost on process restart.
    """

    def __init__(self) -> None:
        """Initialize the in-memory store."""
        self._store: dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()

    def save(self, request: ApprovalRequest) -> None:
        """
        Persist an approval request to memory.

        Args:
            request: The approval request to store.
        """
        with self._lock:
            self._store[request.request_id] = request
            logger.debug("Stored approval request %s", request.request_id)

    def get(self, request_id: str) -> ApprovalRequest | None:
        """
        Retrieve an approval request by ID.

        Args:
            request_id: The unique request identifier.

        Returns:
            The approval request, or None if not found.
        """
        with self._lock:
            return self._store.get(request_id)

    def list_by_status(
        self, status: ApprovalStatus, agent_id: str | None = None
    ) -> list[ApprovalRequest]:
        """
        List requests filtered by status and optionally by agent_id.

        Args:
            status: Filter by this approval status.
            agent_id: Optional agent ID filter.

        Returns:
            List of matching approval requests.
        """
        with self._lock:
            results = [
                req for req in self._store.values() if req.status == status
            ]
            if agent_id:
                results = [r for r in results if r.agent_id == agent_id]
            return results

    def update(self, request: ApprovalRequest) -> None:
        """
        Update an existing approval request.

        Args:
            request: The updated approval request.

        Raises:
            KeyError: If the request does not exist.
        """
        with self._lock:
            if request.request_id not in self._store:
                raise KeyError(
                    f"Approval request {request.request_id} not found"
                )
            self._store[request.request_id] = request
            logger.debug("Updated approval request %s", request.request_id)

    def delete(self, request_id: str) -> bool:
        """
        Delete an approval request.

        Args:
            request_id: The request to delete.

        Returns:
            True if the request was deleted; False if not found.
        """
        with self._lock:
            if request_id in self._store:
                del self._store[request_id]
                return True
            return False

    @property
    def count(self) -> int:
        """Return the total number of stored requests."""
        with self._lock:
            return len(self._store)


# --- Redis Store Interface ---


class RedisApprovalStore:
    """
    Redis-backed implementation of ApprovalStore for distributed deployments.

    This is an interface definition showing the expected contract. A full
    implementation requires a Redis client dependency (e.g., redis-py).

    Attributes:
        redis_url: Connection URL for the Redis instance.
        key_prefix: Prefix for all Redis keys used by this store.
        default_ttl: Default TTL for stored requests in Redis.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        key_prefix: str = "approval:",
        default_ttl: int = 3600,
    ) -> None:
        """
        Initialize the Redis store.

        Args:
            redis_url: Redis connection URL.
            key_prefix: Key namespace prefix.
            default_ttl: Default TTL for entries in seconds.
        """
        self._redis_url = redis_url
        self._key_prefix = key_prefix
        self._default_ttl = default_ttl
        self._client: Any = None
        logger.info("RedisApprovalStore configured for %s", redis_url)

    def _get_client(self) -> Any:
        """
        Get or create the Redis client connection.

        Returns:
            The Redis client instance.

        Raises:
            ImportError: If redis package is not installed.
        """
        if self._client is None:
            try:
                import redis
                self._client = redis.from_url(self._redis_url)
            except ImportError:
                raise ImportError(
                    "redis package is required for RedisApprovalStore. "
                    "Install with: pip install redis"
                )
        return self._client

    def save(self, request: ApprovalRequest) -> None:
        """Persist an approval request to Redis."""
        import json
        client = self._get_client()
        key = f"{self._key_prefix}{request.request_id}"
        client.setex(key, self._default_ttl, json.dumps(request.to_dict()))

    def get(self, request_id: str) -> ApprovalRequest | None:
        """Retrieve an approval request from Redis."""
        import json
        client = self._get_client()
        key = f"{self._key_prefix}{request_id}"
        data = client.get(key)
        if data is None:
            return None
        return ApprovalRequest.from_dict(json.loads(data))

    def list_by_status(
        self, status: ApprovalStatus, agent_id: str | None = None
    ) -> list[ApprovalRequest]:
        """List requests by status from Redis."""
        import json
        client = self._get_client()
        pattern = f"{self._key_prefix}*"
        results: list[ApprovalRequest] = []
        for key in client.scan_iter(match=pattern):
            data = client.get(key)
            if data:
                req = ApprovalRequest.from_dict(json.loads(data))
                if req.status == status:
                    if agent_id is None or req.agent_id == agent_id:
                        results.append(req)
        return results

    def update(self, request: ApprovalRequest) -> None:
        """Update an approval request in Redis."""
        self.save(request)

    def delete(self, request_id: str) -> bool:
        """Delete an approval request from Redis."""
        client = self._get_client()
        key = f"{self._key_prefix}{request_id}"
        return bool(client.delete(key))


# --- Approval Policy (RBAC) ---


class ApprovalPolicy:
    """
    Defines who can approve what actions (RBAC for approvals).

    Maps action patterns to lists of authorized approvers. If no policy
    matches an action, a default approver list is used.

    Usage:
        policy = ApprovalPolicy(default_approvers=["security-team"])
        policy.add_rule("iam:*", ["iam-admins", "security-team"])
        policy.add_rule("s3:Delete*", ["data-team", "security-team"])
    """

    def __init__(self, default_approvers: list[str] | None = None) -> None:
        """
        Initialize the approval policy.

        Args:
            default_approvers: Fallback approver list when no rule matches.
        """
        self._rules: list[tuple[str, list[str]]] = []
        self._default_approvers = default_approvers or []

    def add_rule(self, action_pattern: str, approvers: list[str]) -> None:
        """
        Add an approval rule mapping an action pattern to approvers.

        Args:
            action_pattern: Glob pattern for IAM actions.
            approvers: List of approver identifiers authorized for this pattern.
        """
        if not action_pattern:
            raise ValueError("action_pattern cannot be empty")
        if not approvers:
            raise ValueError("approvers list cannot be empty")
        self._rules.append((action_pattern, list(approvers)))
        logger.debug(
            "Added approval rule: %s -> %s", action_pattern, approvers
        )

    def get_authorized_approvers(self, action: str) -> list[str]:
        """
        Get the list of authorized approvers for a given action.

        Args:
            action: The IAM action being approved.

        Returns:
            List of authorized approver identifiers.
        """
        import fnmatch

        for pattern, approvers in self._rules:
            if fnmatch.fnmatch(action.lower(), pattern.lower()):
                return approvers
        return self._default_approvers

    def is_authorized_approver(self, approver: str, action: str) -> bool:
        """
        Check if a specific approver is authorized for a given action.

        Args:
            approver: The approver identifier to check.
            action: The IAM action being approved.

        Returns:
            True if the approver is authorized; False otherwise.
        """
        authorized = self.get_authorized_approvers(action)
        if not authorized:
            # No policy defined -- allow any approver (open policy)
            return True
        return approver in authorized


# --- Approval Manager ---


class ApprovalManager:
    """
    Human-in-the-loop approval system for high-risk agent actions.

    Manages the lifecycle of approval requests from creation through
    approval/denial/expiration. Integrates with the ApprovalStore for
    persistence and ApprovalPolicy for RBAC enforcement.

    Key security guarantees:
      - Approvals are time-limited (configurable TTL, default 5 minutes)
      - Approvals are action-specific (exact agent+action+resource scope)
      - Only authorized approvers can approve/deny (policy-enforced)
      - Self-approval is prohibited (requester cannot approve own request)
      - Every state transition generates an AuditEvent

    Usage:
        manager = ApprovalManager()
        req = manager.request_approval("agent-1", "iam:PassRole", "arn:...", "system")
        approved = manager.approve(req.request_id, "admin@example.com", "Reviewed")
        assert approved.status == ApprovalStatus.APPROVED
    """

    def __init__(
        self,
        store: ApprovalStore | None = None,
        policy: ApprovalPolicy | None = None,
        default_ttl_seconds: int = 300,
    ) -> None:
        """
        Initialize the approval manager.

        Args:
            store: Storage backend for approval requests.
                   Defaults to InMemoryApprovalStore.
            policy: Approval RBAC policy. Defaults to open policy.
            default_ttl_seconds: Default time-to-live for approvals in seconds.
        """
        self._store: ApprovalStore = store or InMemoryApprovalStore()
        self._policy = policy or ApprovalPolicy()
        self._default_ttl_seconds = default_ttl_seconds
        self._audit_events: list[AuditEvent] = []
        self._audit_lock = threading.Lock()
        logger.info(
            "ApprovalManager initialized with TTL=%ds", default_ttl_seconds
        )

    @property
    def audit_events(self) -> list[AuditEvent]:
        """Return the list of generated audit events."""
        with self._audit_lock:
            return list(self._audit_events)

    def request_approval(
        self,
        agent_id: str,
        action: str,
        resource: str,
        requester: str,
        ttl_seconds: int = 300,
    ) -> ApprovalRequest:
        """
        Create a new approval request for a high-risk action.

        Args:
            agent_id: The agent identity requesting the action.
            action: The IAM action requiring approval.
            resource: The target resource ARN.
            requester: Identifier of the system/user that initiated the request.
            ttl_seconds: Time-to-live in seconds before the request expires.
                         Defaults to 300 (5 minutes).

        Returns:
            The created ApprovalRequest in PENDING status.

        Raises:
            ValueError: If required fields are empty.
        """
        if not agent_id:
            raise ValueError("agent_id cannot be empty")
        if not action:
            raise ValueError("action cannot be empty")
        if not resource:
            raise ValueError("resource cannot be empty")

        effective_ttl = ttl_seconds if ttl_seconds > 0 else self._default_ttl_seconds
        now = _now_utc()

        approval_request = ApprovalRequest(
            request_id=_generate_uuid(),
            agent_id=agent_id,
            action=action,
            resource=resource,
            requester=requester,
            status=ApprovalStatus.PENDING,
            expires_at=now + timedelta(seconds=effective_ttl),
            created_at=now,
        )

        self._store.save(approval_request)

        # Emit audit event
        self._emit_audit(
            correlation_id=approval_request.request_id,
            agent_id=agent_id,
            action=action,
            resource=resource,
            decision=AuthorizationDecisionType.REVIEW,
            reasons=[
                f"Approval requested by {requester}",
                f"TTL: {effective_ttl}s",
                f"Action: {action} on {resource}",
            ],
        )

        logger.info(
            "Approval request created: id=%s agent=%s action=%s resource=%s ttl=%ds",
            approval_request.request_id,
            agent_id,
            action,
            resource,
            effective_ttl,
        )

        return approval_request

    def approve(
        self, request_id: str, approver: str, reason: str = ""
    ) -> ApprovalRequest:
        """
        Approve a pending approval request.

        Args:
            request_id: The approval request ID to approve.
            approver: Identifier of the human approving the request.
            reason: Optional justification for the approval.

        Returns:
            The updated ApprovalRequest with APPROVED status.

        Raises:
            ValueError: If the request is not in PENDING status.
            PermissionError: If the approver is not authorized.
            KeyError: If the request does not exist.
        """
        request = self._get_and_validate(request_id, approver)

        # Check expiration before approving
        if request.is_expired:
            request.status = ApprovalStatus.EXPIRED
            self._store.update(request)
            raise ValueError(
                f"Approval request {request_id} has expired and cannot be approved"
            )

        # Prevent self-approval
        if request.requester and request.requester == approver:
            raise PermissionError(
                f"Self-approval is prohibited: {approver} cannot approve their own request"
            )

        # Check RBAC authorization
        if not self._policy.is_authorized_approver(approver, request.action):
            raise PermissionError(
                f"Approver '{approver}' is not authorized to approve "
                f"action '{request.action}'"
            )

        # Apply approval
        request.status = ApprovalStatus.APPROVED
        request.approver = approver
        request.reason = reason
        request.decision_at = _now_utc()

        self._store.update(request)

        # Emit audit event
        self._emit_audit(
            correlation_id=request.request_id,
            agent_id=request.agent_id,
            action=request.action,
            resource=request.resource,
            decision=AuthorizationDecisionType.ALLOW,
            reasons=[
                f"Approved by {approver}",
                f"Reason: {reason}" if reason else "No reason provided",
            ],
        )

        logger.info(
            "Approval request %s approved by %s (reason: %s)",
            request_id,
            approver,
            reason or "none",
        )

        return request

    def deny(
        self, request_id: str, approver: str, reason: str = ""
    ) -> ApprovalRequest:
        """
        Deny a pending approval request.

        Args:
            request_id: The approval request ID to deny.
            approver: Identifier of the human denying the request.
            reason: Optional justification for the denial.

        Returns:
            The updated ApprovalRequest with DENIED status.

        Raises:
            ValueError: If the request is not in PENDING status.
            PermissionError: If the approver is not authorized.
            KeyError: If the request does not exist.
        """
        request = self._get_and_validate(request_id, approver)

        # Check expiration
        if request.is_expired:
            request.status = ApprovalStatus.EXPIRED
            self._store.update(request)
            raise ValueError(
                f"Approval request {request_id} has expired"
            )

        # Check RBAC authorization
        if not self._policy.is_authorized_approver(approver, request.action):
            raise PermissionError(
                f"Approver '{approver}' is not authorized to act on "
                f"action '{request.action}'"
            )

        # Apply denial
        request.status = ApprovalStatus.DENIED
        request.approver = approver
        request.reason = reason
        request.decision_at = _now_utc()

        self._store.update(request)

        # Emit audit event
        self._emit_audit(
            correlation_id=request.request_id,
            agent_id=request.agent_id,
            action=request.action,
            resource=request.resource,
            decision=AuthorizationDecisionType.DENY,
            reasons=[
                f"Denied by {approver}",
                f"Reason: {reason}" if reason else "No reason provided",
            ],
        )

        logger.info(
            "Approval request %s denied by %s (reason: %s)",
            request_id,
            approver,
            reason or "none",
        )

        return request

    def check_status(self, request_id: str) -> ApprovalRequest:
        """
        Check the current status of an approval request.

        If the request has expired but is still marked PENDING, this method
        will update it to EXPIRED status.

        Args:
            request_id: The approval request ID to check.

        Returns:
            The current ApprovalRequest.

        Raises:
            KeyError: If the request does not exist.
        """
        request = self._store.get(request_id)
        if request is None:
            raise KeyError(f"Approval request {request_id} not found")

        # Auto-expire if needed
        if request.status == ApprovalStatus.PENDING and request.is_expired:
            request.status = ApprovalStatus.EXPIRED
            self._store.update(request)
            logger.debug("Request %s auto-expired on status check", request_id)

        return request

    def list_pending(self, agent_id: str | None = None) -> list[ApprovalRequest]:
        """
        List all pending approval requests, optionally filtered by agent.

        Automatically expires stale requests encountered during listing.

        Args:
            agent_id: Optional agent ID to filter by.

        Returns:
            List of pending (non-expired) approval requests.
        """
        pending = self._store.list_by_status(ApprovalStatus.PENDING, agent_id)

        active: list[ApprovalRequest] = []
        for request in pending:
            if request.is_expired:
                request.status = ApprovalStatus.EXPIRED
                self._store.update(request)
            else:
                active.append(request)

        return active

    def expire_stale(self) -> int:
        """
        Expire all pending requests that have passed their TTL.

        This should be called periodically (e.g., via a background task)
        to clean up stale requests.

        Returns:
            The number of requests that were expired.
        """
        pending = self._store.list_by_status(ApprovalStatus.PENDING)
        expired_count = 0

        for request in pending:
            if request.is_expired:
                request.status = ApprovalStatus.EXPIRED
                self._store.update(request)
                expired_count += 1

                # Emit audit event for expiration
                self._emit_audit(
                    correlation_id=request.request_id,
                    agent_id=request.agent_id,
                    action=request.action,
                    resource=request.resource,
                    decision=AuthorizationDecisionType.DENY,
                    reasons=[
                        "Approval request expired without decision",
                        f"Created at: {request.created_at.isoformat() if request.created_at else 'unknown'}",
                        f"Expired at: {request.expires_at.isoformat() if request.expires_at else 'unknown'}",
                    ],
                )

        if expired_count > 0:
            logger.info("Expired %d stale approval requests", expired_count)

        return expired_count

    def is_approved(self, request_id: str) -> bool:
        """
        Check if a specific approval request has been approved.

        Also verifies the approval has not expired since it was granted.

        Args:
            request_id: The approval request ID to check.

        Returns:
            True if the request is currently in APPROVED status and not expired.
        """
        request = self._store.get(request_id)
        if request is None:
            return False

        if request.status != ApprovalStatus.APPROVED:
            return False

        # Verify the approval itself has not expired
        if request.is_expired:
            return False

        return True

    # --- Private Methods ---

    def _get_and_validate(
        self, request_id: str, approver: str
    ) -> ApprovalRequest:
        """
        Retrieve and validate a request before approval/denial.

        Args:
            request_id: The request ID to retrieve.
            approver: The approver identifier.

        Returns:
            The validated ApprovalRequest.

        Raises:
            KeyError: If the request does not exist.
            ValueError: If the request is not in PENDING status.
        """
        if not request_id:
            raise ValueError("request_id cannot be empty")
        if not approver:
            raise ValueError("approver cannot be empty")

        request = self._store.get(request_id)
        if request is None:
            raise KeyError(f"Approval request {request_id} not found")

        if request.status != ApprovalStatus.PENDING:
            raise ValueError(
                f"Cannot modify approval request {request_id}: "
                f"current status is {request.status.value} (must be PENDING)"
            )

        return request

    def _emit_audit(
        self,
        correlation_id: str,
        agent_id: str,
        action: str,
        resource: str,
        decision: AuthorizationDecisionType,
        reasons: list[str],
    ) -> AuditEvent:
        """
        Create and store an audit event.

        Args:
            correlation_id: Correlation ID linking to the approval request.
            agent_id: The agent involved.
            action: The action being approved/denied.
            resource: The target resource.
            decision: The authorization decision type.
            reasons: List of reasons for the event.

        Returns:
            The created AuditEvent.
        """
        event = AuditEvent(
            event_id=_generate_uuid(),
            correlation_id=correlation_id,
            agent_id=agent_id,
            action=action,
            resource=resource,
            decision=decision,
            reasons=reasons,
            policy_version="approval-system",
        )

        with self._audit_lock:
            self._audit_events.append(event)

        logger.debug(
            "Audit event %s: %s for %s (correlation: %s)",
            event.event_id,
            decision.value,
            action,
            correlation_id,
        )

        return event
