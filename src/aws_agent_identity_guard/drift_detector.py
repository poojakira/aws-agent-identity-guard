"""
aws_agent_identity_guard/drift_detector.py
---------------------------------------------------------------------------
Permission-Drift Detection Module.

Monitors AI agent permissions over time, detecting when effective permissions
change from an established baseline. Identifies new attack paths introduced
by permission additions and generates risk-scored alerts.

Security philosophy:
  - Permissions that change without a corresponding change request are suspect.
  - New permissions should be evaluated for attack path implications.
  - Drift detection must be continuous and automated.
  - Baselines represent the approved security posture; any deviation is drift.
"""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

from aws_agent_identity_guard.models import (
    AttackPath,
    AttackStep,
    DriftEvent,
    EffectiveEffect,
    EffectivePermission,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AlertLevel(str, Enum):
    """Alert severity level for drift detection."""

    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AlertSeverity(str, Enum):
    """Severity classification for drift alerts."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass
class DriftReport:
    """
    Complete report of detected permission drift for an agent.

    Attributes:
        agent_id: The agent whose permissions drifted.
        timestamp: When the drift was detected.
        baseline_snapshot_id: Identifier of the baseline snapshot used.
        current_snapshot_id: Identifier of the current snapshot.
        new_permissions: Permissions that were added since the baseline.
        removed_permissions: Permissions that were removed since the baseline.
        modified_permissions: Permissions with changed conditions or effect.
        new_attack_paths: Attack paths enabled by the new permissions.
        drift_risk_score: Overall risk score for this drift (0-100).
        alert_level: Recommended alert level based on risk assessment.
    """

    agent_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    baseline_snapshot_id: str = ""
    current_snapshot_id: str = ""
    new_permissions: list[EffectivePermission] = field(default_factory=list)
    removed_permissions: list[EffectivePermission] = field(default_factory=list)
    modified_permissions: list[EffectivePermission] = field(default_factory=list)
    new_attack_paths: list[AttackPath] = field(default_factory=list)
    drift_risk_score: int = 0
    alert_level: AlertLevel = AlertLevel.INFO

    def __post_init__(self) -> None:
        """Validate drift report fields."""
        if not self.agent_id:
            raise ValueError("agent_id cannot be empty")
        if not (0 <= self.drift_risk_score <= 100):
            raise ValueError(
                f"drift_risk_score must be between 0 and 100, got {self.drift_risk_score}"
            )
        if isinstance(self.alert_level, str):
            self.alert_level = AlertLevel(self.alert_level)

    @property
    def has_drift(self) -> bool:
        """Check if any drift was detected."""
        return bool(
            self.new_permissions or self.removed_permissions or self.modified_permissions
        )

    @property
    def total_changes(self) -> int:
        """Total number of permission changes detected."""
        return (
            len(self.new_permissions)
            + len(self.removed_permissions)
            + len(self.modified_permissions)
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "agent_id": self.agent_id,
            "timestamp": self.timestamp.isoformat(),
            "baseline_snapshot_id": self.baseline_snapshot_id,
            "current_snapshot_id": self.current_snapshot_id,
            "new_permissions": [p.to_dict() for p in self.new_permissions],
            "removed_permissions": [p.to_dict() for p in self.removed_permissions],
            "modified_permissions": [p.to_dict() for p in self.modified_permissions],
            "new_attack_paths": [ap.to_dict() for ap in self.new_attack_paths],
            "drift_risk_score": self.drift_risk_score,
            "alert_level": self.alert_level.value,
            "has_drift": self.has_drift,
            "total_changes": self.total_changes,
        }


@dataclass
class Alert:
    """
    An alert generated from drift detection.

    Attributes:
        alert_id: Unique identifier for this alert.
        agent_id: The agent that triggered the alert.
        severity: How severe this alert is.
        message: Human-readable alert message.
        drift_report: The drift report that triggered this alert.
        acknowledged: Whether the alert has been acknowledged.
        created_at: When the alert was created.
    """

    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    severity: AlertSeverity = AlertSeverity.MEDIUM
    message: str = ""
    drift_report: DriftReport | None = None
    acknowledged: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Validate alert fields."""
        if not self.alert_id:
            self.alert_id = str(uuid.uuid4())
        if isinstance(self.severity, str):
            self.severity = AlertSeverity(self.severity)

    def acknowledge(self) -> None:
        """Mark this alert as acknowledged."""
        self.acknowledged = True

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "alert_id": self.alert_id,
            "agent_id": self.agent_id,
            "severity": self.severity.value,
            "message": self.message,
            "drift_report": self.drift_report.to_dict() if self.drift_report else None,
            "acknowledged": self.acknowledged,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class BaselineSnapshot:
    """
    A captured snapshot of an agent's permissions used as comparison baseline.

    Attributes:
        snapshot_id: Unique identifier for this snapshot.
        agent_id: The agent this baseline belongs to.
        permissions: The effective permissions at baseline time.
        captured_at: When this snapshot was captured.
        description: Optional human-readable description.
    """

    snapshot_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    permissions: list[EffectivePermission] = field(default_factory=list)
    captured_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "snapshot_id": self.snapshot_id,
            "agent_id": self.agent_id,
            "permissions": [p.to_dict() for p in self.permissions],
            "captured_at": self.captured_at.isoformat(),
            "description": self.description,
        }


# ---------------------------------------------------------------------------
# BaselineStore Protocol and InMemory Implementation
# ---------------------------------------------------------------------------


class BaselineStore(Protocol):
    """
    Protocol for storing and retrieving permission baselines.

    Implementations may use in-memory storage, DynamoDB, S3, or other
    persistence mechanisms.
    """

    def save_baseline(self, snapshot: BaselineSnapshot) -> None:
        """Save a baseline snapshot."""
        ...

    def get_latest_baseline(self, agent_id: str) -> BaselineSnapshot | None:
        """Get the most recent baseline for an agent."""
        ...

    def get_all_baselines(self, agent_id: str) -> list[BaselineSnapshot]:
        """Get all baselines for an agent, ordered by capture time."""
        ...


class InMemoryBaselineStore:
    """
    In-memory implementation of BaselineStore for development and testing.

    Thread-safe storage of baseline snapshots. Not suitable for production
    use where persistence across restarts is required.
    """

    def __init__(self) -> None:
        """Initialize the in-memory store."""
        self._baselines: dict[str, list[BaselineSnapshot]] = {}
        self._lock = threading.Lock()
        logger.info("InMemoryBaselineStore initialized")

    def save_baseline(self, snapshot: BaselineSnapshot) -> None:
        """
        Save a baseline snapshot to in-memory storage.

        Args:
            snapshot: The baseline snapshot to save.
        """
        with self._lock:
            if snapshot.agent_id not in self._baselines:
                self._baselines[snapshot.agent_id] = []
            self._baselines[snapshot.agent_id].append(snapshot)
            logger.debug(
                "Saved baseline %s for agent %s (%d permissions)",
                snapshot.snapshot_id,
                snapshot.agent_id,
                len(snapshot.permissions),
            )

    def get_latest_baseline(self, agent_id: str) -> BaselineSnapshot | None:
        """
        Get the most recent baseline for an agent.

        Args:
            agent_id: The agent identifier.

        Returns:
            The latest BaselineSnapshot or None if no baseline exists.
        """
        with self._lock:
            baselines = self._baselines.get(agent_id, [])
            if not baselines:
                return None
            return max(baselines, key=lambda b: b.captured_at)

    def get_all_baselines(self, agent_id: str) -> list[BaselineSnapshot]:
        """
        Get all baselines for an agent, ordered by capture time.

        Args:
            agent_id: The agent identifier.

        Returns:
            List of BaselineSnapshot ordered oldest to newest.
        """
        with self._lock:
            baselines = self._baselines.get(agent_id, [])
            return sorted(baselines, key=lambda b: b.captured_at)


# ---------------------------------------------------------------------------
# Dangerous permission patterns for attack path detection
# ---------------------------------------------------------------------------

_ESCALATION_PERMISSIONS = {
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicy",
    "iam:CreatePolicyVersion",
    "iam:UpdateAssumeRolePolicy",
    "iam:AddUserToGroup",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "sts:AssumeRole",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "lambda:AddPermission",
    "cloudformation:CreateStack",
    "cloudformation:UpdateStack",
}

_EXFILTRATION_PERMISSIONS = {
    "s3:GetObject",
    "s3:ListBucket",
    "dynamodb:Scan",
    "dynamodb:Query",
    "rds:CopyDBSnapshot",
    "rds:CopyDBClusterSnapshot",
    "ec2:CreateSnapshot",
    "ec2:CopySnapshot",
    "ec2:ModifySnapshotAttribute",
    "redshift:CopyClusterSnapshot",
}

_PERSISTENCE_PERMISSIONS = {
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "lambda:CreateFunction",
    "lambda:CreateEventSourceMapping",
    "events:PutRule",
    "events:PutTargets",
    "ec2:RunInstances",
    "ecs:CreateService",
    "eks:CreateNodegroup",
}

_ANTI_FORENSICS_PERMISSIONS = {
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "logs:DeleteLogGroup",
    "logs:DeleteLogStream",
    "config:StopConfigurationRecorder",
    "guardduty:DeleteDetector",
    "securityhub:DisableSecurityHub",
}



# ---------------------------------------------------------------------------
# Drift Detector
# ---------------------------------------------------------------------------


class DriftDetector:
    """
    Detects and analyzes permission drift for AI agents.

    Compares current effective permissions against an established baseline
    to identify additions, removals, and modifications. Assesses risk and
    identifies new attack paths introduced by permission changes.

    Usage:
        detector = DriftDetector()
        detector.set_baseline("agent-123", current_permissions)
        # ... time passes, permissions change ...
        report = detector.detect_drift("agent-123", new_permissions)
        if report.alert_level == AlertLevel.CRITICAL:
            alert = detector.alert_on_drift("agent-123", report)
    """

    def __init__(self, baseline_store: BaselineStore | None = None) -> None:
        """
        Initialize the drift detector.

        Args:
            baseline_store: Storage backend for baselines. If None, uses
                InMemoryBaselineStore.
        """
        self._store: BaselineStore = baseline_store or InMemoryBaselineStore()
        self._drift_history: dict[str, list[DriftEvent]] = {}
        self._alerts: list[Alert] = []
        self._lock = threading.Lock()
        self._monitoring_active: dict[str, bool] = {}
        logger.info("DriftDetector initialized")

    def set_baseline(
        self,
        agent_id: str,
        permissions: list[EffectivePermission],
        description: str = "",
    ) -> None:
        """
        Set a new permission baseline for an agent.

        The baseline represents the approved security posture. All future
        drift detection will compare against this baseline.

        Args:
            agent_id: The agent identifier.
            permissions: The effective permissions to use as baseline.
            description: Optional description of why this baseline was set.

        Raises:
            ValueError: If agent_id is empty.
        """
        if not agent_id:
            raise ValueError("agent_id cannot be empty")

        snapshot = BaselineSnapshot(
            agent_id=agent_id,
            permissions=list(permissions),
            description=description or f"Baseline set at {datetime.now(timezone.utc).isoformat()}",
        )
        self._store.save_baseline(snapshot)

        logger.info(
            "Baseline set for agent '%s': snapshot=%s, permissions=%d",
            agent_id,
            snapshot.snapshot_id,
            len(permissions),
        )

    def detect_drift(
        self,
        agent_id: str,
        current_permissions: list[EffectivePermission],
    ) -> DriftReport:
        """
        Detect permission drift from baseline for the given agent.

        Compares the current effective permissions against the stored baseline
        and generates a comprehensive drift report with risk assessment.

        Args:
            agent_id: The agent identifier.
            current_permissions: The agent's current effective permissions.

        Returns:
            DriftReport with all detected changes and risk assessment.

        Raises:
            ValueError: If agent_id is empty or no baseline exists.
        """
        if not agent_id:
            raise ValueError("agent_id cannot be empty")

        baseline = self._store.get_latest_baseline(agent_id)
        if baseline is None:
            raise ValueError(
                f"No baseline exists for agent '{agent_id}'. "
                f"Call set_baseline() first to establish a baseline."
            )

        logger.info(
            "Detecting drift for agent '%s' against baseline %s",
            agent_id,
            baseline.snapshot_id,
        )

        new_perms, removed_perms, modified_perms = self._compare_permissions(
            baseline.permissions, current_permissions
        )

        risk_score = self._assess_drift_risk(new_perms, removed_perms)
        attack_paths = self._detect_new_attack_paths(new_perms)
        alert_level = self._determine_alert_level(risk_score, attack_paths)

        current_snapshot_id = str(uuid.uuid4())

        report = DriftReport(
            agent_id=agent_id,
            baseline_snapshot_id=baseline.snapshot_id,
            current_snapshot_id=current_snapshot_id,
            new_permissions=new_perms,
            removed_permissions=removed_perms,
            modified_permissions=modified_perms,
            new_attack_paths=attack_paths,
            drift_risk_score=risk_score,
            alert_level=alert_level,
        )

        # Record drift event in history
        if report.has_drift:
            drift_event = DriftEvent(
                agent_id=agent_id,
                previous_permissions=baseline.permissions,
                current_permissions=current_permissions,
                new_permissions=new_perms,
                removed_permissions=removed_perms,
                new_attack_paths=attack_paths,
            )
            with self._lock:
                if agent_id not in self._drift_history:
                    self._drift_history[agent_id] = []
                self._drift_history[agent_id].append(drift_event)

        logger.info(
            "Drift detection complete for agent '%s': "
            "new=%d, removed=%d, modified=%d, risk=%d, level=%s",
            agent_id,
            len(new_perms),
            len(removed_perms),
            len(modified_perms),
            risk_score,
            alert_level.value,
        )

        return report

    def _compare_permissions(
        self,
        baseline: list[EffectivePermission],
        current: list[EffectivePermission],
    ) -> tuple[list[EffectivePermission], list[EffectivePermission], list[EffectivePermission]]:
        """
        Compare baseline and current permissions to find differences.

        Uses action+resource as the identity key for each permission.

        Args:
            baseline: The baseline permission set.
            current: The current permission set.

        Returns:
            Tuple of (new_permissions, removed_permissions, modified_permissions).
        """
        baseline_map: dict[tuple[str, str], EffectivePermission] = {}
        for perm in baseline:
            key = (perm.action, perm.resource)
            baseline_map[key] = perm

        current_map: dict[tuple[str, str], EffectivePermission] = {}
        for perm in current:
            key = (perm.action, perm.resource)
            current_map[key] = perm

        baseline_keys = set(baseline_map.keys())
        current_keys = set(current_map.keys())

        new_keys = current_keys - baseline_keys
        new_permissions = [current_map[k] for k in new_keys]

        removed_keys = baseline_keys - current_keys
        removed_permissions = [baseline_map[k] for k in removed_keys]

        modified_permissions: list[EffectivePermission] = []
        common_keys = baseline_keys & current_keys
        for key in common_keys:
            base_perm = baseline_map[key]
            curr_perm = current_map[key]
            if (
                base_perm.effective_effect != curr_perm.effective_effect
                or base_perm.conditions_required != curr_perm.conditions_required
            ):
                modified_permissions.append(curr_perm)

        return new_permissions, removed_permissions, modified_permissions

    def _assess_drift_risk(
        self,
        new_permissions: list[EffectivePermission],
        removed_permissions: list[EffectivePermission],
    ) -> int:
        """
        Assess the risk score of the detected drift.

        Scores 0-100 based on the nature of added permissions.

        Args:
            new_permissions: Permissions that were added.
            removed_permissions: Permissions that were removed.

        Returns:
            Risk score from 0 (no risk) to 100 (maximum risk).
        """
        if not new_permissions and not removed_permissions:
            return 0

        score = 0.0

        for perm in new_permissions:
            action = perm.action

            if action == "*" or action.endswith(":*"):
                score += 30
                continue

            if action in _ESCALATION_PERMISSIONS:
                score += 20
            elif action in _ANTI_FORENSICS_PERMISSIONS:
                score += 25
            elif action in _PERSISTENCE_PERMISSIONS:
                score += 15
            elif action in _EXFILTRATION_PERMISSIONS:
                score += 10
            else:
                if any(
                    keyword in action.lower()
                    for keyword in ["delete", "create", "put", "update", "modify"]
                ):
                    score += 5
                else:
                    score += 2

            if perm.resource == "*":
                score += 5

        # Removal of deny rules increases risk
        for perm in removed_permissions:
            if perm.effective_effect == EffectiveEffect.DENIED:
                score += 10

        return max(0, min(100, int(score)))

    def _detect_new_attack_paths(
        self,
        new_permissions: list[EffectivePermission],
    ) -> list[AttackPath]:
        """
        Detect new attack paths enabled by newly added permissions.

        Args:
            new_permissions: Permissions that were newly added.

        Returns:
            List of detected AttackPath objects.
        """
        attack_paths: list[AttackPath] = []
        new_actions = {p.action for p in new_permissions}

        escalation_actions = new_actions & _ESCALATION_PERMISSIONS
        if escalation_actions:
            steps = [
                AttackStep(
                    action=action,
                    resource="*",
                    description=f"Use '{action}' to escalate privileges",
                    privilege_gained="Elevated IAM access",
                )
                for action in sorted(escalation_actions)
            ]
            attack_paths.append(
                AttackPath(
                    steps=steps,
                    likelihood=0.7,
                    impact=0.9,
                    description=(
                        f"Privilege escalation via newly granted IAM permissions: "
                        f"{', '.join(sorted(escalation_actions))}"
                    ),
                )
            )

        exfil_actions = new_actions & _EXFILTRATION_PERMISSIONS
        if exfil_actions:
            steps = [
                AttackStep(
                    action=action,
                    resource="*",
                    description=f"Use '{action}' to access or copy data",
                    privilege_gained="Data access",
                )
                for action in sorted(exfil_actions)
            ]
            attack_paths.append(
                AttackPath(
                    steps=steps,
                    likelihood=0.6,
                    impact=0.7,
                    description=(
                        f"Data exfiltration via newly granted data access: "
                        f"{', '.join(sorted(exfil_actions))}"
                    ),
                )
            )

        persistence_actions = new_actions & _PERSISTENCE_PERMISSIONS
        if persistence_actions:
            steps = [
                AttackStep(
                    action=action,
                    resource="*",
                    description=f"Use '{action}' to establish persistence",
                    privilege_gained="Persistent access",
                )
                for action in sorted(persistence_actions)
            ]
            attack_paths.append(
                AttackPath(
                    steps=steps,
                    likelihood=0.5,
                    impact=0.8,
                    description=(
                        f"Persistence establishment via: "
                        f"{', '.join(sorted(persistence_actions))}"
                    ),
                )
            )

        anti_forensics_actions = new_actions & _ANTI_FORENSICS_PERMISSIONS
        if anti_forensics_actions:
            steps = [
                AttackStep(
                    action=action,
                    resource="*",
                    description=f"Use '{action}' to cover tracks",
                    privilege_gained="Logging/monitoring evasion",
                )
                for action in sorted(anti_forensics_actions)
            ]
            attack_paths.append(
                AttackPath(
                    steps=steps,
                    likelihood=0.4,
                    impact=0.95,
                    description=(
                        f"Anti-forensics capability via: "
                        f"{', '.join(sorted(anti_forensics_actions))}"
                    ),
                )
            )

        # Combined escalation + persistence is especially dangerous
        if escalation_actions and persistence_actions:
            combined_steps = [
                AttackStep(
                    action=sorted(escalation_actions)[0],
                    resource="*",
                    description="Escalate privileges via IAM manipulation",
                    privilege_gained="Admin-level access",
                ),
                AttackStep(
                    action=sorted(persistence_actions)[0],
                    resource="*",
                    description="Establish persistent backdoor access",
                    privilege_gained="Persistent admin access",
                ),
            ]
            attack_paths.append(
                AttackPath(
                    steps=combined_steps,
                    likelihood=0.8,
                    impact=0.95,
                    description=(
                        "Combined escalation and persistence: agent can escalate "
                        "privileges and then establish persistent backdoor access"
                    ),
                )
            )

        logger.debug("Detected %d new attack paths", len(attack_paths))
        return attack_paths

    def get_drift_history(self, agent_id: str) -> list[DriftEvent]:
        """
        Get the full drift history for an agent.

        Args:
            agent_id: The agent identifier.

        Returns:
            List of DriftEvent objects in chronological order.
        """
        with self._lock:
            history = self._drift_history.get(agent_id, [])
            return sorted(history, key=lambda e: e.timestamp)

    def alert_on_drift(
        self,
        agent_id: str,
        drift_report: DriftReport,
    ) -> Alert:
        """
        Generate an alert based on a drift report.

        Creates a structured alert with appropriate severity based on the
        drift risk score and attack paths detected.

        Args:
            agent_id: The agent that triggered the drift.
            drift_report: The drift report to alert on.

        Returns:
            Alert object with full context.
        """
        severity_map = {
            AlertLevel.INFO: AlertSeverity.LOW,
            AlertLevel.WARNING: AlertSeverity.MEDIUM,
            AlertLevel.CRITICAL: AlertSeverity.CRITICAL,
        }
        severity = severity_map.get(drift_report.alert_level, AlertSeverity.MEDIUM)

        if drift_report.new_attack_paths:
            if severity == AlertSeverity.LOW:
                severity = AlertSeverity.MEDIUM
            elif severity == AlertSeverity.MEDIUM:
                severity = AlertSeverity.HIGH

        message_parts = [
            f"Permission drift detected for agent '{agent_id}'.",
            f"Risk score: {drift_report.drift_risk_score}/100.",
        ]
        if drift_report.new_permissions:
            new_actions = [p.action for p in drift_report.new_permissions[:5]]
            message_parts.append(
                f"New permissions ({len(drift_report.new_permissions)}): "
                f"{', '.join(new_actions)}"
            )
        if drift_report.removed_permissions:
            message_parts.append(
                f"Removed permissions: {len(drift_report.removed_permissions)}"
            )
        if drift_report.new_attack_paths:
            message_parts.append(
                f"New attack paths detected: {len(drift_report.new_attack_paths)}"
            )

        message = " ".join(message_parts)

        alert = Alert(
            agent_id=agent_id,
            severity=severity,
            message=message,
            drift_report=drift_report,
        )

        with self._lock:
            self._alerts.append(alert)

        logger.warning(
            "Alert generated for agent '%s': severity=%s, message=%s",
            agent_id,
            severity.value,
            message,
        )

        return alert

    def start_monitoring(self, agent_id: str) -> None:
        """
        Mark an agent for continuous monitoring.

        Enables periodic drift checks for the given agent. Actual scheduling
        should be handled by an external scheduler (e.g., AWS EventBridge,
        cron, or threading timer).

        Args:
            agent_id: The agent to monitor.
        """
        with self._lock:
            self._monitoring_active[agent_id] = True
        logger.info("Continuous monitoring started for agent '%s'", agent_id)

    def stop_monitoring(self, agent_id: str) -> None:
        """
        Stop continuous monitoring for an agent.

        Args:
            agent_id: The agent to stop monitoring.
        """
        with self._lock:
            self._monitoring_active[agent_id] = False
        logger.info("Continuous monitoring stopped for agent '%s'", agent_id)

    def is_monitoring(self, agent_id: str) -> bool:
        """
        Check if an agent is currently being monitored.

        Args:
            agent_id: The agent to check.

        Returns:
            True if continuous monitoring is active for this agent.
        """
        with self._lock:
            return self._monitoring_active.get(agent_id, False)

    def get_unacknowledged_alerts(self, agent_id: str | None = None) -> list[Alert]:
        """
        Get all unacknowledged alerts, optionally filtered by agent.

        Args:
            agent_id: Optional filter by agent. If None, returns all.

        Returns:
            List of unacknowledged Alert objects.
        """
        with self._lock:
            alerts = [a for a in self._alerts if not a.acknowledged]
            if agent_id:
                alerts = [a for a in alerts if a.agent_id == agent_id]
            return alerts

    # -----------------------------------------------------------------------
    # Private Helpers
    # -----------------------------------------------------------------------

    def _determine_alert_level(
        self, risk_score: int, attack_paths: list[AttackPath]
    ) -> AlertLevel:
        """Determine the appropriate alert level based on risk and attack paths."""
        if risk_score >= 70 or any(ap.composite_score >= 60 for ap in attack_paths):
            return AlertLevel.CRITICAL
        if risk_score >= 40 or attack_paths:
            return AlertLevel.WARNING
        return AlertLevel.INFO
