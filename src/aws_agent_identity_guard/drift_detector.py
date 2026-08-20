"""AWS Agent Identity Guard - Permission Drift Detection Engine.

Production-grade module for detecting and reporting permission drift in agent
identities. Monitors changes in effective permissions over time, compares
baselines against current state, and generates alerts when drift is detected.

Key capabilities:
- Baseline capture: snapshot all effective permissions at a point in time
- Drift detection: compare current state against baseline
- Continuous monitoring: async generator for real-time drift events
- Alerting: webhook, SNS, and log-based notifications
- Baseline persistence: in-memory with protocol for external storage backends
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, unique
from typing import Any, AsyncGenerator, Protocol, runtime_checkable

from .models import (
    Agent,
    EffectivePermission,
    Permission,
    PermissionEffect,
    PermissionSource,
    Severity,
    SerializableMixin,
    _utcnow,
)


logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Actions considered dangerous when added (trigger HIGH severity)
_DANGEROUS_ACTIONS: frozenset[str] = frozenset({
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "lambda:AddPermission",
    "ec2:RunInstances",
    "s3:PutBucketPolicy",
    "s3:DeleteBucket",
    "kms:Decrypt",
    "kms:CreateGrant",
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "organizations:*",
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "guardduty:DeleteDetector",
    "config:StopConfigurationRecorder",
})

# Default monitoring interval in seconds
_DEFAULT_MONITOR_INTERVAL: float = 60.0

# Maximum baselines retained in memory
_DEFAULT_MAX_BASELINES: int = 100


# =============================================================================
# Enumerations
# =============================================================================


@unique
class DriftType(str, Enum):
    """Types of permission drift that can be detected."""

    PERMISSION_ADDED = "PERMISSION_ADDED"
    PERMISSION_REMOVED = "PERMISSION_REMOVED"
    POLICY_CHANGED = "POLICY_CHANGED"
    BOUNDARY_CHANGED = "BOUNDARY_CHANGED"
    SCP_CHANGED = "SCP_CHANGED"


@unique
class DriftSeverity(str, Enum):
    """Severity classification for drift events."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@unique
class AlertChannel(str, Enum):
    """Supported alerting channels."""

    WEBHOOK = "WEBHOOK"
    SNS = "SNS"
    LOG = "LOG"


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class PermissionTuple(SerializableMixin):
    """A single action+resource pair representing one effective permission.

    Used as the atomic unit for set-based permission comparison.
    """

    action: str
    resource: str

    def __hash__(self) -> int:
        return hash((self.action, self.resource))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PermissionTuple):
            return NotImplemented
        return self.action == other.action and self.resource == other.resource

    def __repr__(self) -> str:
        return f"PermissionTuple(action={self.action!r}, resource={self.resource!r})"


@dataclass
class PermissionBaseline(SerializableMixin):
    """Snapshot of all effective permissions at a specific point in time.

    Captures the complete permission state of an agent for later comparison.
    The policies_hash provides a fast-path check for detecting any changes
    without full set comparison.

    Attributes:
        baseline_id: Unique identifier for this baseline snapshot.
        agent_id: The agent whose permissions are captured.
        captured_at: UTC timestamp when the baseline was taken.
        permissions: Complete set of action+resource permission tuples.
        policies_hash: SHA-256 hash of the serialized policy configuration.
        metadata: Additional context about the baseline capture.
    """

    baseline_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    captured_at: datetime = field(default_factory=_utcnow)
    permissions: set[PermissionTuple] = field(default_factory=set)
    policies_hash: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Compute policies_hash if not provided."""
        if not self.policies_hash and self.permissions:
            self.policies_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute a deterministic hash of the permission set."""
        sorted_perms = sorted(
            (p.action, p.resource) for p in self.permissions
        )
        content = json.dumps(sorted_perms, sort_keys=True)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @property
    def permission_count(self) -> int:
        """Number of effective permissions in this baseline."""
        return len(self.permissions)

    def contains_action(self, action: str) -> bool:
        """Check if any permission in the baseline grants the given action."""
        return any(p.action == action for p in self.permissions)


@dataclass
class DriftEvent(SerializableMixin):
    """A single detected permission drift event.

    Represents one atomic change between baseline and current state,
    with risk assessment and full context for investigation.

    Attributes:
        event_id: Unique event identifier.
        agent_id: The agent affected by the drift.
        drift_type: Classification of the drift (added, removed, changed).
        permission: The specific permission that changed.
        detected_at: UTC timestamp when drift was detected.
        baseline_ref: Reference to the baseline this was compared against.
        current_snapshot: The current permission state at detection time.
        severity: Risk severity of this drift event.
        risk_delta: Change in overall risk score caused by this drift.
        description: Human-readable description of the drift.
        source_policy: The policy that caused the change, if identifiable.
    """

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    drift_type: DriftType = DriftType.PERMISSION_ADDED
    permission: PermissionTuple | None = None
    detected_at: datetime = field(default_factory=_utcnow)
    baseline_ref: str = ""
    current_snapshot: str = ""
    severity: DriftSeverity = DriftSeverity.MEDIUM
    risk_delta: float = 0.0
    description: str = ""
    source_policy: str = ""

    def __post_init__(self) -> None:
        """Validate risk_delta range."""
        if not (-1.0 <= self.risk_delta <= 1.0):
            raise ValueError(
                f"risk_delta must be between -1.0 and 1.0, got {self.risk_delta}"
            )

    @property
    def is_high_severity(self) -> bool:
        """Whether this event is HIGH or CRITICAL severity."""
        return self.severity in (DriftSeverity.CRITICAL, DriftSeverity.HIGH)

    def to_alert_payload(self) -> dict[str, Any]:
        """Serialize to a payload suitable for alerting systems."""
        return {
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "drift_type": self.drift_type.value,
            "permission": {
                "action": self.permission.action,
                "resource": self.permission.resource,
            } if self.permission else None,
            "detected_at": self.detected_at.isoformat(),
            "severity": self.severity.value,
            "risk_delta": self.risk_delta,
            "description": self.description,
        }


@dataclass
class DriftReport(SerializableMixin):
    """Summary report of all permission changes between two snapshots.

    Provides a comprehensive view of drift with risk assessment,
    categorized events, and actionable recommendations.

    Attributes:
        report_id: Unique report identifier.
        agent_id: The agent assessed.
        generated_at: When the report was generated.
        baseline_snapshot: Reference baseline used for comparison.
        current_snapshot: Current state snapshot identifier.
        events: All drift events detected.
        total_added: Count of permissions added.
        total_removed: Count of permissions removed.
        net_risk_delta: Aggregate risk score change.
        highest_severity: Worst severity among all events.
        recommendations: Actionable remediation recommendations.
        summary: Human-readable summary of the drift.
    """

    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    generated_at: datetime = field(default_factory=_utcnow)
    baseline_snapshot: str = ""
    current_snapshot: str = ""
    events: list[DriftEvent] = field(default_factory=list)
    total_added: int = 0
    total_removed: int = 0
    net_risk_delta: float = 0.0
    highest_severity: DriftSeverity = DriftSeverity.INFORMATIONAL
    recommendations: list[str] = field(default_factory=list)
    summary: str = ""

    def __post_init__(self) -> None:
        """Compute derived fields from events if present."""
        if self.events and not self.summary:
            self._compute_summary()

    def _compute_summary(self) -> None:
        """Compute summary statistics from drift events."""
        self.total_added = sum(
            1 for e in self.events if e.drift_type == DriftType.PERMISSION_ADDED
        )
        self.total_removed = sum(
            1 for e in self.events if e.drift_type == DriftType.PERMISSION_REMOVED
        )
        self.net_risk_delta = sum(e.risk_delta for e in self.events)

        severity_order = [
            DriftSeverity.INFORMATIONAL,
            DriftSeverity.LOW,
            DriftSeverity.MEDIUM,
            DriftSeverity.HIGH,
            DriftSeverity.CRITICAL,
        ]
        if self.events:
            self.highest_severity = max(
                (e.severity for e in self.events),
                key=lambda s: severity_order.index(s),
            )

        self.summary = (
            f"Drift report for agent {self.agent_id}: "
            f"{self.total_added} permissions added, "
            f"{self.total_removed} permissions removed, "
            f"net risk delta: {self.net_risk_delta:+.3f}, "
            f"highest severity: {self.highest_severity.value}"
        )

    @property
    def has_critical_drift(self) -> bool:
        """Whether any CRITICAL drift was detected."""
        return any(e.severity == DriftSeverity.CRITICAL for e in self.events)

    @property
    def has_high_drift(self) -> bool:
        """Whether any HIGH or CRITICAL drift was detected."""
        return any(e.is_high_severity for e in self.events)

    @property
    def event_count(self) -> int:
        """Total number of drift events."""
        return len(self.events)


# =============================================================================
# Alerting Interface
# =============================================================================


@dataclass
class AlertConfig:
    """Configuration for a single alert destination.

    Attributes:
        channel: The alerting channel type.
        endpoint: Channel-specific endpoint (URL, ARN, or logger name).
        min_severity: Minimum severity to trigger this alert.
        enabled: Whether this alert destination is active.
        headers: Additional headers for webhook calls.
        metadata: Additional channel-specific configuration.
    """

    channel: AlertChannel
    endpoint: str
    min_severity: DriftSeverity = DriftSeverity.MEDIUM
    enabled: bool = True
    headers: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class AlertDispatcher:
    """Dispatches drift alerts to configured channels.

    Supports webhook (HTTP POST), SNS (publish), and structured logging.
    Each destination can filter by minimum severity.
    """

    def __init__(self, configs: list[AlertConfig] | None = None) -> None:
        """Initialize the alert dispatcher.

        Args:
            configs: List of alert destination configurations.
        """
        self._configs: list[AlertConfig] = configs or []
        self._sent_count: int = 0
        self._failed_count: int = 0

    @property
    def sent_count(self) -> int:
        """Number of alerts successfully dispatched."""
        return self._sent_count

    @property
    def failed_count(self) -> int:
        """Number of alerts that failed to dispatch."""
        return self._failed_count

    def add_config(self, config: AlertConfig) -> None:
        """Add an alert destination configuration.

        Args:
            config: The alert configuration to add.
        """
        self._configs.append(config)

    def remove_config(self, channel: AlertChannel, endpoint: str) -> bool:
        """Remove an alert destination by channel and endpoint.

        Args:
            channel: The channel type to remove.
            endpoint: The specific endpoint to remove.

        Returns:
            True if a configuration was removed, False otherwise.
        """
        original_count = len(self._configs)
        self._configs = [
            c for c in self._configs
            if not (c.channel == channel and c.endpoint == endpoint)
        ]
        return len(self._configs) < original_count

    async def dispatch(self, event: DriftEvent) -> list[str]:
        """Dispatch a drift event to all applicable alert destinations.

        Filters destinations by minimum severity and enabled status.

        Args:
            event: The drift event to alert on.

        Returns:
            List of channel descriptions that received the alert.
        """
        severity_order = [
            DriftSeverity.INFORMATIONAL,
            DriftSeverity.LOW,
            DriftSeverity.MEDIUM,
            DriftSeverity.HIGH,
            DriftSeverity.CRITICAL,
        ]
        event_severity_idx = severity_order.index(event.severity)
        dispatched: list[str] = []

        for config in self._configs:
            if not config.enabled:
                continue
            min_idx = severity_order.index(config.min_severity)
            if event_severity_idx < min_idx:
                continue

            try:
                await self._send_alert(config, event)
                self._sent_count += 1
                dispatched.append(f"{config.channel.value}:{config.endpoint}")
            except Exception as exc:
                self._failed_count += 1
                logger.error(
                    "Failed to dispatch alert to %s:%s: %s",
                    config.channel.value,
                    config.endpoint,
                    exc,
                )

        return dispatched

    async def _send_alert(self, config: AlertConfig, event: DriftEvent) -> None:
        """Send an alert to a specific destination.

        Args:
            config: The destination configuration.
            event: The drift event to send.
        """
        payload = event.to_alert_payload()

        if config.channel == AlertChannel.LOG:
            log_level = logging.WARNING if event.is_high_severity else logging.INFO
            logging.getLogger(config.endpoint or "drift_alerts").log(
                log_level,
                "Drift alert: %s",
                json.dumps(payload, default=str),
            )

        elif config.channel == AlertChannel.WEBHOOK:
            # In production, use aiohttp or httpx for async HTTP
            # This logs the intent for environments without HTTP client
            logger.info(
                "Webhook alert to %s: %s",
                config.endpoint,
                json.dumps(payload, default=str),
            )
            # Placeholder for actual HTTP POST:
            # async with aiohttp.ClientSession() as session:
            #     await session.post(
            #         config.endpoint,
            #         json=payload,
            #         headers=config.headers,
            #     )

        elif config.channel == AlertChannel.SNS:
            # In production, use aioboto3 for async SNS publish
            logger.info(
                "SNS alert to %s: %s",
                config.endpoint,
                json.dumps(payload, default=str),
            )
            # Placeholder for actual SNS publish:
            # async with aioboto3.client("sns") as sns:
            #     await sns.publish(
            #         TopicArn=config.endpoint,
            #         Message=json.dumps(payload, default=str),
            #         Subject=f"Drift Alert: {event.drift_type.value}",
            #     )


# =============================================================================
# Baseline Storage Protocol & In-Memory Implementation
# =============================================================================


@runtime_checkable
class BaselineStore(Protocol):
    """Protocol for baseline persistence backends.

    Implementations can store baselines in DynamoDB, S3, local files,
    or any other storage system. The in-memory implementation serves
    as the default and as a reference implementation.
    """

    def save(self, baseline: PermissionBaseline) -> None:
        """Persist a baseline snapshot.

        Args:
            baseline: The baseline to store.
        """
        ...

    def load(self, baseline_id: str) -> PermissionBaseline | None:
        """Load a baseline by its identifier.

        Args:
            baseline_id: The unique baseline identifier.

        Returns:
            The baseline if found, None otherwise.
        """
        ...

    def load_latest(self, agent_id: str) -> PermissionBaseline | None:
        """Load the most recent baseline for an agent.

        Args:
            agent_id: The agent whose latest baseline to retrieve.

        Returns:
            The most recent baseline if any exist, None otherwise.
        """
        ...

    def list_baselines(self, agent_id: str) -> list[PermissionBaseline]:
        """List all baselines for an agent, ordered by capture time descending.

        Args:
            agent_id: The agent whose baselines to list.

        Returns:
            List of baselines, newest first.
        """
        ...

    def delete(self, baseline_id: str) -> bool:
        """Delete a baseline by its identifier.

        Args:
            baseline_id: The baseline to delete.

        Returns:
            True if deleted, False if not found.
        """
        ...


class InMemoryBaselineStore:
    """In-memory baseline storage with bounded capacity.

    Implements the BaselineStore protocol using a dictionary with
    LRU-style eviction when max capacity is reached.

    Attributes:
        max_baselines: Maximum number of baselines to retain.
    """

    def __init__(self, max_baselines: int = _DEFAULT_MAX_BASELINES) -> None:
        """Initialize the in-memory store.

        Args:
            max_baselines: Maximum baselines to retain before eviction.
        """
        self._store: dict[str, PermissionBaseline] = {}
        self._order: deque[str] = deque()
        self.max_baselines = max_baselines

    @property
    def count(self) -> int:
        """Number of baselines currently stored."""
        return len(self._store)

    def save(self, baseline: PermissionBaseline) -> None:
        """Persist a baseline snapshot in memory.

        Evicts the oldest baseline if capacity is exceeded.

        Args:
            baseline: The baseline to store.
        """
        if baseline.baseline_id in self._store:
            # Update existing - no capacity change
            self._store[baseline.baseline_id] = baseline
            return

        # Evict oldest if at capacity
        while len(self._store) >= self.max_baselines and self._order:
            oldest_id = self._order.popleft()
            self._store.pop(oldest_id, None)

        self._store[baseline.baseline_id] = baseline
        self._order.append(baseline.baseline_id)

    def load(self, baseline_id: str) -> PermissionBaseline | None:
        """Load a baseline by its identifier.

        Args:
            baseline_id: The unique baseline identifier.

        Returns:
            The baseline if found, None otherwise.
        """
        return self._store.get(baseline_id)

    def load_latest(self, agent_id: str) -> PermissionBaseline | None:
        """Load the most recent baseline for an agent.

        Args:
            agent_id: The agent whose latest baseline to retrieve.

        Returns:
            The most recent baseline if any exist, None otherwise.
        """
        agent_baselines = [
            b for b in self._store.values() if b.agent_id == agent_id
        ]
        if not agent_baselines:
            return None
        return max(agent_baselines, key=lambda b: b.captured_at)

    def list_baselines(self, agent_id: str) -> list[PermissionBaseline]:
        """List all baselines for an agent, newest first.

        Args:
            agent_id: The agent whose baselines to list.

        Returns:
            List of baselines, ordered by captured_at descending.
        """
        agent_baselines = [
            b for b in self._store.values() if b.agent_id == agent_id
        ]
        return sorted(agent_baselines, key=lambda b: b.captured_at, reverse=True)

    def delete(self, baseline_id: str) -> bool:
        """Delete a baseline by its identifier.

        Args:
            baseline_id: The baseline to delete.

        Returns:
            True if deleted, False if not found.
        """
        if baseline_id in self._store:
            del self._store[baseline_id]
            try:
                self._order.remove(baseline_id)
            except ValueError:
                pass
            return True
        return False

    def clear(self) -> None:
        """Remove all stored baselines."""
        self._store.clear()
        self._order.clear()


# =============================================================================
# Permission Resolution Helper
# =============================================================================


def _extract_permissions_from_agent(agent: Agent) -> set[PermissionTuple]:
    """Extract effective permission tuples from an agent's policy configuration.

    Parses the agent's identity policies to build a set of all allowed
    action+resource combinations. This is a simplified extraction that
    handles standard IAM policy document structure.

    Args:
        agent: The agent to extract permissions from.

    Returns:
        Set of PermissionTuple representing all effective permissions.
    """
    permissions: set[PermissionTuple] = set()

    for policy_doc in agent.identity_policies:
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            effect = statement.get("Effect", "")
            if effect != "Allow":
                continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = statement.get("Resource", ["*"])
            if isinstance(resources, str):
                resources = [resources]

            for action in actions:
                for resource in resources:
                    permissions.add(PermissionTuple(action=action, resource=resource))

    return permissions


def _compute_policies_hash(agent: Agent) -> str:
    """Compute a deterministic hash of the agent's full policy configuration.

    Includes identity policies, permission boundaries, and trust policy.

    Args:
        agent: The agent whose policies to hash.

    Returns:
        SHA-256 hex digest of the policy configuration.
    """
    policy_data = {
        "identity_policies": agent.identity_policies,
        "permission_boundaries": agent.permission_boundaries,
        "trust_policy": agent.trust_policy,
    }
    content = json.dumps(policy_data, sort_keys=True, default=str)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _classify_severity(
    drift_type: DriftType,
    permission: PermissionTuple | None,
) -> DriftSeverity:
    """Classify the severity of a drift event based on type and permission.

    Rules:
    - Adding dangerous permissions -> CRITICAL
    - Adding any permission -> HIGH
    - Policy/boundary/SCP changes -> MEDIUM
    - Removing permissions -> LOW

    Args:
        drift_type: The type of drift detected.
        permission: The specific permission involved.

    Returns:
        The computed severity level.
    """
    if drift_type == DriftType.PERMISSION_ADDED:
        if permission and permission.action in _DANGEROUS_ACTIONS:
            return DriftSeverity.CRITICAL
        return DriftSeverity.HIGH

    if drift_type == DriftType.PERMISSION_REMOVED:
        return DriftSeverity.LOW

    if drift_type in (DriftType.BOUNDARY_CHANGED, DriftType.SCP_CHANGED):
        return DriftSeverity.HIGH

    # POLICY_CHANGED
    return DriftSeverity.MEDIUM


def _compute_risk_delta(
    drift_type: DriftType,
    permission: PermissionTuple | None,
) -> float:
    """Compute the risk score delta for a drift event.

    Positive values indicate increased risk, negative indicates reduced risk.

    Args:
        drift_type: The type of drift.
        permission: The specific permission involved.

    Returns:
        Risk delta between -1.0 and 1.0.
    """
    if drift_type == DriftType.PERMISSION_ADDED:
        if permission and permission.action in _DANGEROUS_ACTIONS:
            return 0.8
        return 0.3

    if drift_type == DriftType.PERMISSION_REMOVED:
        if permission and permission.action in _DANGEROUS_ACTIONS:
            return -0.5
        return -0.1

    if drift_type == DriftType.BOUNDARY_CHANGED:
        return 0.4

    if drift_type == DriftType.SCP_CHANGED:
        return 0.5

    # POLICY_CHANGED
    return 0.2


# =============================================================================
# Drift Detector
# =============================================================================


class DriftDetector:
    """Core permission drift detection engine.

    Captures permission baselines, detects drift between baseline and current
    state, generates reports, and supports continuous async monitoring with
    integrated alerting.

    Example usage::

        detector = DriftDetector()
        baseline = detector.capture_baseline(agent)

        # Later, check for drift
        events = detector.detect_drift(agent, baseline)
        for event in events:
            print(f"Drift detected: {event.drift_type.value} - {event.description}")

        # Continuous monitoring
        async for event in detector.monitor(agent, interval=30.0):
            handle_drift_event(event)
    """

    def __init__(
        self,
        store: BaselineStore | None = None,
        alert_dispatcher: AlertDispatcher | None = None,
    ) -> None:
        """Initialize the drift detector.

        Args:
            store: Baseline persistence backend. Defaults to in-memory store.
            alert_dispatcher: Alert dispatcher for notifications.
                Defaults to a log-only dispatcher.
        """
        self._store: BaselineStore = store or InMemoryBaselineStore()
        self._alert_dispatcher = alert_dispatcher or AlertDispatcher(
            configs=[AlertConfig(
                channel=AlertChannel.LOG,
                endpoint="aws_agent_identity_guard.drift",
                min_severity=DriftSeverity.MEDIUM,
            )]
        )
        self._monitoring: bool = False

    @property
    def store(self) -> BaselineStore:
        """The baseline storage backend."""
        return self._store

    @property
    def alert_dispatcher(self) -> AlertDispatcher:
        """The alert dispatcher instance."""
        return self._alert_dispatcher

    def capture_baseline(self, agent: Agent) -> PermissionBaseline:
        """Capture a permission baseline snapshot for an agent.

        Extracts all effective permissions from the agent's current policy
        configuration and stores them as a baseline for future comparison.

        Args:
            agent: The agent to capture a baseline for.

        Returns:
            The captured PermissionBaseline with all current permissions.
        """
        permissions = _extract_permissions_from_agent(agent)
        policies_hash = _compute_policies_hash(agent)

        baseline = PermissionBaseline(
            baseline_id=str(uuid.uuid4()),
            agent_id=agent.agent_id,
            captured_at=_utcnow(),
            permissions=permissions,
            policies_hash=policies_hash,
            metadata={
                "agent_name": agent.name,
                "environment": agent.environment.value,
                "iam_role_arn": agent.iam_role_arn,
                "permission_count": len(permissions),
                "workload_type": agent.workload_type.value,
            },
        )

        self._store.save(baseline)
        logger.info(
            "Captured baseline %s for agent %s with %d permissions",
            baseline.baseline_id,
            agent.agent_id,
            len(permissions),
        )
        return baseline

    def detect_drift(
        self,
        agent: Agent,
        baseline: PermissionBaseline,
    ) -> list[DriftEvent]:
        """Detect permission drift between baseline and agent's current state.

        Compares the agent's current effective permissions against the provided
        baseline and generates drift events for all differences.

        Args:
            agent: The agent to check for drift.
            baseline: The reference baseline to compare against.

        Returns:
            List of DriftEvent objects describing all detected changes.
        """
        current_permissions = _extract_permissions_from_agent(agent)
        current_hash = _compute_policies_hash(agent)
        current_snapshot_id = str(uuid.uuid4())

        events: list[DriftEvent] = []

        # Detect added permissions
        added = current_permissions - baseline.permissions
        for perm in added:
            drift_type = DriftType.PERMISSION_ADDED
            severity = _classify_severity(drift_type, perm)
            risk_delta = _compute_risk_delta(drift_type, perm)

            events.append(DriftEvent(
                event_id=str(uuid.uuid4()),
                agent_id=agent.agent_id,
                drift_type=drift_type,
                permission=perm,
                detected_at=_utcnow(),
                baseline_ref=baseline.baseline_id,
                current_snapshot=current_snapshot_id,
                severity=severity,
                risk_delta=risk_delta,
                description=(
                    f"Permission added: {perm.action} on {perm.resource}"
                ),
            ))

        # Detect removed permissions
        removed = baseline.permissions - current_permissions
        for perm in removed:
            drift_type = DriftType.PERMISSION_REMOVED
            severity = _classify_severity(drift_type, perm)
            risk_delta = _compute_risk_delta(drift_type, perm)

            events.append(DriftEvent(
                event_id=str(uuid.uuid4()),
                agent_id=agent.agent_id,
                drift_type=drift_type,
                permission=perm,
                detected_at=_utcnow(),
                baseline_ref=baseline.baseline_id,
                current_snapshot=current_snapshot_id,
                severity=severity,
                risk_delta=risk_delta,
                description=(
                    f"Permission removed: {perm.action} on {perm.resource}"
                ),
            ))

        # Detect policy-level changes even if effective permissions are the same
        if current_hash != baseline.policies_hash and not added and not removed:
            events.append(DriftEvent(
                event_id=str(uuid.uuid4()),
                agent_id=agent.agent_id,
                drift_type=DriftType.POLICY_CHANGED,
                permission=None,
                detected_at=_utcnow(),
                baseline_ref=baseline.baseline_id,
                current_snapshot=current_snapshot_id,
                severity=DriftSeverity.MEDIUM,
                risk_delta=_compute_risk_delta(DriftType.POLICY_CHANGED, None),
                description=(
                    "Policy configuration changed without effective permission change"
                ),
            ))

        # Detect boundary changes
        baseline_boundaries = baseline.metadata.get("permission_boundaries", [])
        current_boundaries = agent.permission_boundaries
        if sorted(baseline_boundaries) != sorted(current_boundaries):
            events.append(DriftEvent(
                event_id=str(uuid.uuid4()),
                agent_id=agent.agent_id,
                drift_type=DriftType.BOUNDARY_CHANGED,
                permission=None,
                detected_at=_utcnow(),
                baseline_ref=baseline.baseline_id,
                current_snapshot=current_snapshot_id,
                severity=_classify_severity(DriftType.BOUNDARY_CHANGED, None),
                risk_delta=_compute_risk_delta(DriftType.BOUNDARY_CHANGED, None),
                description=(
                    f"Permission boundary changed: "
                    f"{baseline_boundaries} -> {current_boundaries}"
                ),
            ))

        if events:
            logger.warning(
                "Detected %d drift events for agent %s",
                len(events),
                agent.agent_id,
            )
        else:
            logger.debug(
                "No drift detected for agent %s against baseline %s",
                agent.agent_id,
                baseline.baseline_id,
            )

        return events

    def compare_snapshots(
        self,
        old: PermissionBaseline,
        new: PermissionBaseline,
    ) -> DriftReport:
        """Compare two permission snapshots and generate a drift report.

        Performs a full comparison between two baselines, regardless of
        whether they belong to the same agent.

        Args:
            old: The older/reference baseline.
            new: The newer/current baseline.

        Returns:
            A DriftReport summarizing all differences with risk assessment.
        """
        events: list[DriftEvent] = []
        snapshot_id = str(uuid.uuid4())

        # Added permissions
        added = new.permissions - old.permissions
        for perm in added:
            drift_type = DriftType.PERMISSION_ADDED
            events.append(DriftEvent(
                event_id=str(uuid.uuid4()),
                agent_id=new.agent_id,
                drift_type=drift_type,
                permission=perm,
                detected_at=_utcnow(),
                baseline_ref=old.baseline_id,
                current_snapshot=snapshot_id,
                severity=_classify_severity(drift_type, perm),
                risk_delta=_compute_risk_delta(drift_type, perm),
                description=f"Permission added: {perm.action} on {perm.resource}",
            ))

        # Removed permissions
        removed = old.permissions - new.permissions
        for perm in removed:
            drift_type = DriftType.PERMISSION_REMOVED
            events.append(DriftEvent(
                event_id=str(uuid.uuid4()),
                agent_id=new.agent_id,
                drift_type=drift_type,
                permission=perm,
                detected_at=_utcnow(),
                baseline_ref=old.baseline_id,
                current_snapshot=snapshot_id,
                severity=_classify_severity(drift_type, perm),
                risk_delta=_compute_risk_delta(drift_type, perm),
                description=f"Permission removed: {perm.action} on {perm.resource}",
            ))

        # Policy hash change detection
        if old.policies_hash != new.policies_hash and not added and not removed:
            events.append(DriftEvent(
                event_id=str(uuid.uuid4()),
                agent_id=new.agent_id,
                drift_type=DriftType.POLICY_CHANGED,
                permission=None,
                detected_at=_utcnow(),
                baseline_ref=old.baseline_id,
                current_snapshot=snapshot_id,
                severity=DriftSeverity.MEDIUM,
                risk_delta=_compute_risk_delta(DriftType.POLICY_CHANGED, None),
                description="Policy configuration changed",
            ))

        # Build recommendations
        recommendations: list[str] = []
        if added:
            dangerous_added = [
                p for p in added if p.action in _DANGEROUS_ACTIONS
            ]
            if dangerous_added:
                recommendations.append(
                    f"URGENT: {len(dangerous_added)} dangerous permission(s) added. "
                    f"Review and remediate immediately: "
                    f"{', '.join(p.action for p in dangerous_added[:5])}"
                )
            recommendations.append(
                f"Review {len(added)} added permission(s) against least-privilege principle."
            )
        if removed:
            recommendations.append(
                f"{len(removed)} permission(s) removed. Verify no functionality is broken."
            )

        report = DriftReport(
            report_id=str(uuid.uuid4()),
            agent_id=new.agent_id,
            generated_at=_utcnow(),
            baseline_snapshot=old.baseline_id,
            current_snapshot=snapshot_id,
            events=events,
            recommendations=recommendations,
        )
        # Trigger summary computation
        report._compute_summary()

        logger.info(
            "Generated drift report %s: %d events, severity=%s",
            report.report_id,
            report.event_count,
            report.highest_severity.value,
        )
        return report

    async def monitor(
        self,
        agent: Agent,
        interval: float = _DEFAULT_MONITOR_INTERVAL,
    ) -> AsyncGenerator[DriftEvent, None]:
        """Continuously monitor an agent for permission drift.

        Async generator that periodically checks for drift against the
        most recent baseline and yields drift events as they are detected.
        Automatically updates the baseline after each check cycle.

        Args:
            agent: The agent to monitor.
            interval: Seconds between drift checks. Defaults to 60.

        Yields:
            DriftEvent objects as drift is detected.

        Example::

            async for event in detector.monitor(agent, interval=30.0):
                await handle_event(event)
        """
        self._monitoring = True
        baseline = self._store.load_latest(agent.agent_id)

        if baseline is None:
            baseline = self.capture_baseline(agent)
            logger.info(
                "No existing baseline found for agent %s, created initial baseline %s",
                agent.agent_id,
                baseline.baseline_id,
            )

        logger.info(
            "Starting drift monitoring for agent %s with interval %.1fs",
            agent.agent_id,
            interval,
        )

        try:
            while self._monitoring:
                await asyncio.sleep(interval)

                events = self.detect_drift(agent, baseline)

                for event in events:
                    # Dispatch alerts for significant events
                    if event.is_high_severity:
                        await self._alert_dispatcher.dispatch(event)
                    yield event

                # Update baseline if drift was detected to avoid repeat alerts
                if events:
                    baseline = self.capture_baseline(agent)
                    logger.info(
                        "Updated baseline to %s after detecting %d drift events",
                        baseline.baseline_id,
                        len(events),
                    )

        except asyncio.CancelledError:
            logger.info(
                "Drift monitoring cancelled for agent %s",
                agent.agent_id,
            )
            raise
        finally:
            self._monitoring = False

    def stop_monitoring(self) -> None:
        """Signal the monitoring loop to stop after the current cycle."""
        self._monitoring = False
        logger.info("Drift monitoring stop requested")

    @property
    def is_monitoring(self) -> bool:
        """Whether the monitor is currently active."""
        return self._monitoring
