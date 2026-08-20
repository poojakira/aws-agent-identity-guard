"""AWS Agent Identity Guard - Runtime Behavior Analysis Engine.

Production-grade module for analyzing agent runtime behavior against declared
capabilities. Detects anomalies by comparing observed actions to learned
behavioral baselines, identifying deviations that may indicate compromise,
misconfiguration, or policy violations.

Key capabilities:
- Activity recording: bounded buffer for agent action history
- Behavior baseline: learned normal patterns for each agent
- Anomaly detection: multi-dimensional deviation analysis
- Behavior reporting: comprehensive reports with timelines and risk indicators
"""

from __future__ import annotations

import logging
import statistics
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, unique
from typing import Any, Sequence

from .models import (
    Agent,
    Severity,
    SerializableMixin,
    _utcnow,
)


logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Default maximum activity records per agent
_DEFAULT_MAX_BUFFER_SIZE: int = 10_000

# Default time window for behavior analysis (hours)
_DEFAULT_ANALYSIS_WINDOW_HOURS: int = 24

# Threshold multipliers for anomaly detection
_VOLUME_ANOMALY_STDDEV_MULTIPLIER: float = 3.0
_SEQUENCE_MIN_OCCURRENCES: int = 3
_DEVIATION_HIGH_THRESHOLD: float = 0.7
_DEVIATION_CRITICAL_THRESHOLD: float = 0.9

# Default normal operating hours (UTC)
_DEFAULT_NORMAL_HOURS_START: int = 6
_DEFAULT_NORMAL_HOURS_END: int = 22


# =============================================================================
# Enumerations
# =============================================================================


@unique
class AnomalyType(str, Enum):
    """Types of behavioral anomalies that can be detected."""

    UNEXPECTED_TOOL = "UNEXPECTED_TOOL"
    UNEXPECTED_SERVICE = "UNEXPECTED_SERVICE"
    ABNORMAL_RESOURCE = "ABNORMAL_RESOURCE"
    PRIVILEGE_JUMP = "PRIVILEGE_JUMP"
    UNUSUAL_SEQUENCE = "UNUSUAL_SEQUENCE"
    TIME_ANOMALY = "TIME_ANOMALY"
    VOLUME_ANOMALY = "VOLUME_ANOMALY"
    NEW_DESTINATION = "NEW_DESTINATION"


@unique
class RiskLevel(str, Enum):
    """Risk level indicators for behavior reports."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NORMAL = "NORMAL"


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class ActivityRecord(SerializableMixin):
    """A single recorded agent activity event.

    Represents one action taken by an agent, with full context for
    later behavioral analysis.

    Attributes:
        record_id: Unique identifier for this activity record.
        agent_id: The agent that performed the action.
        action: The AWS action performed (e.g., 's3:GetObject').
        resource: The resource acted upon (ARN or identifier).
        timestamp: When the action occurred (UTC).
        context: Additional context about the action.
    """

    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    action: str = ""
    resource: str = ""
    timestamp: datetime = field(default_factory=_utcnow)
    context: dict[str, Any] = field(default_factory=dict)

    @property
    def service(self) -> str:
        """Extract the AWS service prefix from the action."""
        if ":" in self.action:
            return self.action.split(":")[0]
        return self.action

    @property
    def hour(self) -> int:
        """Extract the hour (UTC) from the timestamp."""
        return self.timestamp.hour

    @property
    def tool(self) -> str:
        """Extract the tool name from context, if available."""
        return self.context.get("tool", "")

    @property
    def destination(self) -> str:
        """Extract external destination from context, if available."""
        return self.context.get("destination", "")


@dataclass
class BehaviorBaseline(SerializableMixin):
    """Learned normal behavior pattern for an agent.

    Built from historical activity data, represents what 'normal'
    looks like for a specific agent. Used as the reference for
    anomaly detection.

    Attributes:
        agent_id: The agent this baseline describes.
        created_at: When the baseline was established.
        updated_at: When the baseline was last updated.
        normal_actions: Set of actions the agent normally performs.
        normal_resources: Set of resources the agent normally accesses.
        normal_services: Set of AWS services the agent normally uses.
        normal_tools: Set of tools the agent normally uses.
        normal_destinations: Set of external endpoints normally accessed.
        normal_hours: Tuple of (start_hour, end_hour) in UTC for normal operation.
        normal_volume: Expected actions per hour (mean, stddev).
        action_sequences: Common action sequences (ordered pairs/tuples).
        observation_period_days: How many days of data the baseline covers.
        total_observations: Total number of activity records used to build this.
    """

    agent_id: str = ""
    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)
    normal_actions: set[str] = field(default_factory=set)
    normal_resources: set[str] = field(default_factory=set)
    normal_services: set[str] = field(default_factory=set)
    normal_tools: set[str] = field(default_factory=set)
    normal_destinations: set[str] = field(default_factory=set)
    normal_hours: tuple[int, int] = (_DEFAULT_NORMAL_HOURS_START, _DEFAULT_NORMAL_HOURS_END)
    normal_volume: tuple[float, float] = (0.0, 0.0)  # (mean, stddev)
    action_sequences: list[tuple[str, ...]] = field(default_factory=list)
    observation_period_days: int = 0
    total_observations: int = 0

    def is_normal_hour(self, hour: int) -> bool:
        """Check if the given hour falls within normal operating hours.

        Args:
            hour: Hour in UTC (0-23).

        Returns:
            True if within normal hours, False otherwise.
        """
        start, end = self.normal_hours
        if start <= end:
            return start <= hour <= end
        # Wraps around midnight
        return hour >= start or hour <= end

    def is_normal_volume(self, count: int, window_hours: float = 1.0) -> bool:
        """Check if the action count is within normal volume range.

        Uses mean + N standard deviations as the threshold.

        Args:
            count: Number of actions observed.
            window_hours: Time window in hours the count covers.

        Returns:
            True if within normal range, False otherwise.
        """
        mean, stddev = self.normal_volume
        if stddev == 0:
            # No variance data, use 2x mean as threshold
            return count <= max(mean * 2, 10)
        hourly_rate = count / max(window_hours, 0.01)
        threshold = mean + (_VOLUME_ANOMALY_STDDEV_MULTIPLIER * stddev)
        return hourly_rate <= threshold


@dataclass
class BehaviorAnomaly(SerializableMixin):
    """A single detected behavioral anomaly.

    Represents a deviation from the agent's established behavior baseline.

    Attributes:
        anomaly_id: Unique anomaly identifier.
        agent_id: The agent exhibiting the anomaly.
        anomaly_type: Classification of the anomaly.
        action: The action that triggered the anomaly.
        resource: The resource involved.
        timestamp: When the anomalous action occurred.
        deviation_score: How far from normal (0.0 = normal, 1.0 = extreme).
        description: Human-readable description of the anomaly.
        evidence: Supporting data for the anomaly detection.
    """

    anomaly_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    anomaly_type: AnomalyType = AnomalyType.UNEXPECTED_SERVICE
    action: str = ""
    resource: str = ""
    timestamp: datetime = field(default_factory=_utcnow)
    deviation_score: float = 0.0
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate deviation_score range."""
        if not (0.0 <= self.deviation_score <= 1.0):
            raise ValueError(
                f"deviation_score must be between 0.0 and 1.0, got {self.deviation_score}"
            )

    @property
    def severity(self) -> Severity:
        """Map deviation score to a severity level."""
        if self.deviation_score >= _DEVIATION_CRITICAL_THRESHOLD:
            return Severity.CRITICAL
        if self.deviation_score >= _DEVIATION_HIGH_THRESHOLD:
            return Severity.HIGH
        if self.deviation_score >= 0.4:
            return Severity.MEDIUM
        return Severity.LOW

    @property
    def is_high_severity(self) -> bool:
        """Whether this anomaly is HIGH or CRITICAL severity."""
        return self.severity in (Severity.CRITICAL, Severity.HIGH)


@dataclass
class RiskIndicator(SerializableMixin):
    """A risk signal derived from behavior analysis.

    Attributes:
        indicator: Short identifier for the risk signal.
        level: Risk level classification.
        description: Human-readable explanation.
        contributing_anomalies: Anomaly IDs that contribute to this indicator.
    """

    indicator: str = ""
    level: RiskLevel = RiskLevel.NORMAL
    description: str = ""
    contributing_anomalies: list[str] = field(default_factory=list)


@dataclass
class BehaviorReport(SerializableMixin):
    """Comprehensive behavior analysis report for an agent.

    Summarizes observed behavior within a time window, detected anomalies,
    risk indicators, and a timeline of significant events.

    Attributes:
        report_id: Unique report identifier.
        agent_id: The agent analyzed.
        generated_at: When the report was generated.
        time_window_start: Start of the analysis window.
        time_window_end: End of the analysis window.
        total_activities: Total actions recorded in the window.
        unique_actions: Count of distinct actions performed.
        unique_resources: Count of distinct resources accessed.
        anomalies: All detected anomalies in the window.
        risk_indicators: Derived risk signals.
        risk_level: Overall risk level for the agent.
        timeline: Key events in chronological order.
        summary: Human-readable summary.
    """

    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    generated_at: datetime = field(default_factory=_utcnow)
    time_window_start: datetime = field(default_factory=_utcnow)
    time_window_end: datetime = field(default_factory=_utcnow)
    total_activities: int = 0
    unique_actions: int = 0
    unique_resources: int = 0
    anomalies: list[BehaviorAnomaly] = field(default_factory=list)
    risk_indicators: list[RiskIndicator] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.NORMAL
    timeline: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""

    @property
    def anomaly_count(self) -> int:
        """Total number of anomalies detected."""
        return len(self.anomalies)

    @property
    def has_critical_anomalies(self) -> bool:
        """Whether any CRITICAL anomalies were detected."""
        return any(
            a.deviation_score >= _DEVIATION_CRITICAL_THRESHOLD
            for a in self.anomalies
        )

    @property
    def has_high_anomalies(self) -> bool:
        """Whether any HIGH or CRITICAL anomalies were detected."""
        return any(a.is_high_severity for a in self.anomalies)


# =============================================================================
# Activity Buffer
# =============================================================================


class ActivityBuffer:
    """Bounded circular buffer for agent activity records.

    Maintains per-agent activity histories with configurable maximum size.
    When the buffer for an agent is full, the oldest records are evicted.

    Attributes:
        max_size: Maximum records per agent.
    """

    def __init__(self, max_size: int = _DEFAULT_MAX_BUFFER_SIZE) -> None:
        """Initialize the activity buffer.

        Args:
            max_size: Maximum number of records to retain per agent.
        """
        self.max_size = max_size
        self._buffers: dict[str, deque[ActivityRecord]] = defaultdict(
            lambda: deque(maxlen=max_size)
        )
        self._total_recorded: int = 0

    @property
    def total_recorded(self) -> int:
        """Total number of records ever added across all agents."""
        return self._total_recorded

    def record(self, activity: ActivityRecord) -> None:
        """Add an activity record to the buffer.

        If the agent's buffer is full, the oldest record is evicted.

        Args:
            activity: The activity record to store.
        """
        self._buffers[activity.agent_id].append(activity)
        self._total_recorded += 1

    def get_activities(
        self,
        agent_id: str,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[ActivityRecord]:
        """Retrieve activity records for an agent within a time range.

        Args:
            agent_id: The agent whose activities to retrieve.
            since: Start of time range (inclusive). None means no lower bound.
            until: End of time range (inclusive). None means no upper bound.

        Returns:
            List of matching activity records, ordered by timestamp.
        """
        buffer = self._buffers.get(agent_id)
        if not buffer:
            return []

        records = list(buffer)

        if since:
            records = [r for r in records if r.timestamp >= since]
        if until:
            records = [r for r in records if r.timestamp <= until]

        return sorted(records, key=lambda r: r.timestamp)

    def get_recent(
        self,
        agent_id: str,
        count: int = 100,
    ) -> list[ActivityRecord]:
        """Get the most recent N activities for an agent.

        Args:
            agent_id: The agent whose activities to retrieve.
            count: Maximum number of records to return.

        Returns:
            List of most recent records, ordered newest first.
        """
        buffer = self._buffers.get(agent_id)
        if not buffer:
            return []
        records = list(buffer)[-count:]
        records.reverse()
        return records

    def count(self, agent_id: str) -> int:
        """Get the number of stored records for an agent.

        Args:
            agent_id: The agent to count records for.

        Returns:
            Number of records currently in the buffer.
        """
        return len(self._buffers.get(agent_id, deque()))

    def clear(self, agent_id: str | None = None) -> None:
        """Clear activity records.

        Args:
            agent_id: If provided, clear only this agent's buffer.
                If None, clear all buffers.
        """
        if agent_id:
            self._buffers.pop(agent_id, None)
        else:
            self._buffers.clear()

    @property
    def tracked_agents(self) -> list[str]:
        """List of agent IDs with recorded activity."""
        return list(self._buffers.keys())


# =============================================================================
# Behavior Analyzer
# =============================================================================


class BehaviorAnalyzer:
    """Runtime behavior analysis engine for agent workloads.

    Records agent activities, builds behavioral baselines from observation,
    and detects anomalies by comparing current behavior against established
    patterns. Supports multi-dimensional anomaly detection including
    tool usage, service access, resource patterns, timing, volume, and
    action sequences.

    Example usage::

        analyzer = BehaviorAnalyzer(max_buffer_size=5000)

        # Record activities as they occur
        analyzer.record_activity(
            agent_id="agent-123",
            action="s3:GetObject",
            resource="arn:aws:s3:::my-bucket/data.csv",
            timestamp=datetime.now(timezone.utc),
            context={"tool": "data-reader", "destination": ""},
        )

        # Build baseline from observation
        analyzer.build_baseline("agent-123", observation_days=7)

        # Detect anomalies
        anomalies = analyzer.detect_anomalies("agent-123")
        for anomaly in anomalies:
            print(f"{anomaly.anomaly_type.value}: {anomaly.description}")

        # Generate comprehensive report
        report = analyzer.analyze_behavior("agent-123", time_window_hours=24)
    """

    def __init__(
        self,
        max_buffer_size: int = _DEFAULT_MAX_BUFFER_SIZE,
        declared_capabilities: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        """Initialize the behavior analyzer.

        Args:
            max_buffer_size: Maximum activity records per agent.
            declared_capabilities: Pre-configured declared capabilities per agent.
                Maps agent_id -> {"tools": [...], "services": [...], "resources": [...]}.
        """
        self._buffer = ActivityBuffer(max_size=max_buffer_size)
        self._baselines: dict[str, BehaviorBaseline] = {}
        self._declared_capabilities: dict[str, dict[str, Any]] = (
            declared_capabilities or {}
        )

    @property
    def buffer(self) -> ActivityBuffer:
        """The underlying activity buffer."""
        return self._buffer

    @property
    def baselines(self) -> dict[str, BehaviorBaseline]:
        """Mapping of agent_id to their behavior baselines."""
        return dict(self._baselines)

    def set_declared_capabilities(
        self,
        agent_id: str,
        tools: list[str] | None = None,
        services: list[str] | None = None,
        resources: list[str] | None = None,
    ) -> None:
        """Set the declared capabilities for an agent.

        These are the tools, services, and resources the agent is
        expected/allowed to use based on its manifest or configuration.

        Args:
            agent_id: The agent to configure.
            tools: List of tool names the agent is declared to use.
            services: List of AWS services the agent is declared to access.
            resources: List of resource patterns the agent is declared to access.
        """
        self._declared_capabilities[agent_id] = {
            "tools": set(tools or []),
            "services": set(services or []),
            "resources": set(resources or []),
        }

    def record_activity(
        self,
        agent_id: str,
        action: str,
        resource: str,
        timestamp: datetime | None = None,
        context: dict[str, Any] | None = None,
    ) -> ActivityRecord:
        """Record a single agent activity event.

        Args:
            agent_id: The agent that performed the action.
            action: The AWS action performed (e.g., 's3:GetObject').
            resource: The resource acted upon (ARN or identifier).
            timestamp: When the action occurred. Defaults to current UTC time.
            context: Additional context. May include 'tool', 'destination',
                'source_ip', 'session_id', etc.

        Returns:
            The created ActivityRecord.
        """
        record = ActivityRecord(
            record_id=str(uuid.uuid4()),
            agent_id=agent_id,
            action=action,
            resource=resource,
            timestamp=timestamp or _utcnow(),
            context=context or {},
        )
        self._buffer.record(record)
        logger.debug(
            "Recorded activity for agent %s: %s on %s",
            agent_id,
            action,
            resource,
        )
        return record

    def build_baseline(
        self,
        agent_id: str,
        observation_days: int = 7,
    ) -> BehaviorBaseline:
        """Build a behavior baseline from recorded activity history.

        Analyzes all recorded activities within the observation window
        to establish what 'normal' looks like for this agent.

        Args:
            agent_id: The agent to build a baseline for.
            observation_days: Number of days of history to analyze.

        Returns:
            The computed BehaviorBaseline.
        """
        since = _utcnow() - timedelta(days=observation_days)
        activities = self._buffer.get_activities(agent_id, since=since)

        if not activities:
            logger.warning(
                "No activities found for agent %s in the last %d days",
                agent_id,
                observation_days,
            )
            baseline = BehaviorBaseline(
                agent_id=agent_id,
                observation_period_days=observation_days,
                total_observations=0,
            )
            self._baselines[agent_id] = baseline
            return baseline

        # Extract normal patterns
        normal_actions: set[str] = set()
        normal_resources: set[str] = set()
        normal_services: set[str] = set()
        normal_tools: set[str] = set()
        normal_destinations: set[str] = set()
        hours_seen: list[int] = []
        hourly_counts: dict[str, int] = defaultdict(int)

        for activity in activities:
            normal_actions.add(activity.action)
            normal_resources.add(activity.resource)
            normal_services.add(activity.service)
            if activity.tool:
                normal_tools.add(activity.tool)
            if activity.destination:
                normal_destinations.add(activity.destination)
            hours_seen.append(activity.hour)

            # Track hourly volume
            hour_key = activity.timestamp.strftime("%Y-%m-%d-%H")
            hourly_counts[hour_key] += 1

        # Compute normal operating hours
        if hours_seen:
            hour_min = min(hours_seen)
            hour_max = max(hours_seen)
            # Add 1-hour buffer on each side
            normal_hours_start = max(0, hour_min - 1)
            normal_hours_end = min(23, hour_max + 1)
        else:
            normal_hours_start = _DEFAULT_NORMAL_HOURS_START
            normal_hours_end = _DEFAULT_NORMAL_HOURS_END

        # Compute volume statistics
        if hourly_counts:
            volumes = list(hourly_counts.values())
            mean_volume = statistics.mean(volumes)
            stddev_volume = (
                statistics.stdev(volumes) if len(volumes) > 1 else 0.0
            )
        else:
            mean_volume = 0.0
            stddev_volume = 0.0

        # Extract common action sequences (bigrams)
        action_sequences: list[tuple[str, ...]] = []
        sequence_counts: dict[tuple[str, ...], int] = defaultdict(int)
        for i in range(len(activities) - 1):
            pair = (activities[i].action, activities[i + 1].action)
            sequence_counts[pair] += 1

        # Keep sequences that appear at least N times
        action_sequences = [
            seq for seq, count in sequence_counts.items()
            if count >= _SEQUENCE_MIN_OCCURRENCES
        ]

        baseline = BehaviorBaseline(
            agent_id=agent_id,
            created_at=_utcnow(),
            updated_at=_utcnow(),
            normal_actions=normal_actions,
            normal_resources=normal_resources,
            normal_services=normal_services,
            normal_tools=normal_tools,
            normal_destinations=normal_destinations,
            normal_hours=(normal_hours_start, normal_hours_end),
            normal_volume=(mean_volume, stddev_volume),
            action_sequences=action_sequences,
            observation_period_days=observation_days,
            total_observations=len(activities),
        )

        self._baselines[agent_id] = baseline
        logger.info(
            "Built behavior baseline for agent %s: %d observations, "
            "%d actions, %d resources, %d services",
            agent_id,
            len(activities),
            len(normal_actions),
            len(normal_resources),
            len(normal_services),
        )
        return baseline

    def detect_anomalies(
        self,
        agent_id: str,
        time_window_hours: int = _DEFAULT_ANALYSIS_WINDOW_HOURS,
    ) -> list[BehaviorAnomaly]:
        """Detect behavioral anomalies for an agent.

        Compares recent activities against the established baseline and
        declared capabilities to identify deviations.

        Args:
            agent_id: The agent to analyze.
            time_window_hours: How many hours of recent activity to check.

        Returns:
            List of detected BehaviorAnomaly objects.
        """
        baseline = self._baselines.get(agent_id)
        if not baseline:
            logger.warning(
                "No baseline for agent %s, building from available data",
                agent_id,
            )
            baseline = self.build_baseline(agent_id)

        since = _utcnow() - timedelta(hours=time_window_hours)
        activities = self._buffer.get_activities(agent_id, since=since)

        if not activities:
            return []

        anomalies: list[BehaviorAnomaly] = []
        declared = self._declared_capabilities.get(agent_id, {})
        declared_tools = declared.get("tools", set())
        declared_services = declared.get("services", set())
        declared_resources = declared.get("resources", set())

        # --- UNEXPECTED_TOOL detection ---
        for activity in activities:
            if activity.tool and declared_tools and activity.tool not in declared_tools:
                anomalies.append(BehaviorAnomaly(
                    anomaly_id=str(uuid.uuid4()),
                    agent_id=agent_id,
                    anomaly_type=AnomalyType.UNEXPECTED_TOOL,
                    action=activity.action,
                    resource=activity.resource,
                    timestamp=activity.timestamp,
                    deviation_score=0.8,
                    description=(
                        f"Agent used undeclared tool '{activity.tool}'. "
                        f"Declared tools: {sorted(declared_tools)}"
                    ),
                    evidence={
                        "tool_used": activity.tool,
                        "declared_tools": sorted(declared_tools),
                        "record_id": activity.record_id,
                    },
                ))

        # --- UNEXPECTED_SERVICE detection ---
        for activity in activities:
            service = activity.service
            if declared_services and service not in declared_services:
                anomalies.append(BehaviorAnomaly(
                    anomaly_id=str(uuid.uuid4()),
                    agent_id=agent_id,
                    anomaly_type=AnomalyType.UNEXPECTED_SERVICE,
                    action=activity.action,
                    resource=activity.resource,
                    timestamp=activity.timestamp,
                    deviation_score=0.75,
                    description=(
                        f"Agent accessed undeclared service '{service}'. "
                        f"Declared services: {sorted(declared_services)}"
                    ),
                    evidence={
                        "service_accessed": service,
                        "declared_services": sorted(declared_services),
                        "record_id": activity.record_id,
                    },
                ))

        # --- ABNORMAL_RESOURCE detection ---
        for activity in activities:
            if (
                baseline.normal_resources
                and activity.resource not in baseline.normal_resources
            ):
                # Check declared resources as allowlist
                if declared_resources and activity.resource not in declared_resources:
                    anomalies.append(BehaviorAnomaly(
                        anomaly_id=str(uuid.uuid4()),
                        agent_id=agent_id,
                        anomaly_type=AnomalyType.ABNORMAL_RESOURCE,
                        action=activity.action,
                        resource=activity.resource,
                        timestamp=activity.timestamp,
                        deviation_score=0.6,
                        description=(
                            f"Agent accessed resource '{activity.resource}' "
                            f"not seen in baseline ({baseline.total_observations} "
                            f"observations over {baseline.observation_period_days} days)"
                        ),
                        evidence={
                            "resource": activity.resource,
                            "baseline_resource_count": len(baseline.normal_resources),
                            "record_id": activity.record_id,
                        },
                    ))

        # --- PRIVILEGE_JUMP detection ---
        anomalies.extend(self._detect_privilege_jumps(agent_id, activities, baseline))

        # --- UNUSUAL_SEQUENCE detection ---
        anomalies.extend(self._detect_unusual_sequences(agent_id, activities, baseline))

        # --- TIME_ANOMALY detection ---
        for activity in activities:
            if not baseline.is_normal_hour(activity.hour):
                anomalies.append(BehaviorAnomaly(
                    anomaly_id=str(uuid.uuid4()),
                    agent_id=agent_id,
                    anomaly_type=AnomalyType.TIME_ANOMALY,
                    action=activity.action,
                    resource=activity.resource,
                    timestamp=activity.timestamp,
                    deviation_score=0.5,
                    description=(
                        f"Action at {activity.hour}:00 UTC outside normal hours "
                        f"({baseline.normal_hours[0]}:00-{baseline.normal_hours[1]}:00 UTC)"
                    ),
                    evidence={
                        "action_hour": activity.hour,
                        "normal_hours": baseline.normal_hours,
                        "record_id": activity.record_id,
                    },
                ))

        # --- VOLUME_ANOMALY detection ---
        volume_anomaly = self._detect_volume_anomaly(
            agent_id, activities, baseline, time_window_hours
        )
        if volume_anomaly:
            anomalies.append(volume_anomaly)

        # --- NEW_DESTINATION detection ---
        for activity in activities:
            destination = activity.destination
            if (
                destination
                and baseline.normal_destinations
                and destination not in baseline.normal_destinations
            ):
                anomalies.append(BehaviorAnomaly(
                    anomaly_id=str(uuid.uuid4()),
                    agent_id=agent_id,
                    anomaly_type=AnomalyType.NEW_DESTINATION,
                    action=activity.action,
                    resource=activity.resource,
                    timestamp=activity.timestamp,
                    deviation_score=0.7,
                    description=(
                        f"Agent accessed new external destination '{destination}' "
                        f"not seen in baseline"
                    ),
                    evidence={
                        "destination": destination,
                        "known_destinations": sorted(baseline.normal_destinations),
                        "record_id": activity.record_id,
                    },
                ))

        # Deduplicate by (anomaly_type, action, resource) keeping highest score
        anomalies = self._deduplicate_anomalies(anomalies)

        if anomalies:
            logger.warning(
                "Detected %d anomalies for agent %s in the last %d hours",
                len(anomalies),
                agent_id,
                time_window_hours,
            )

        return anomalies

    def analyze_behavior(
        self,
        agent_id: str,
        time_window_hours: int = _DEFAULT_ANALYSIS_WINDOW_HOURS,
    ) -> BehaviorReport:
        """Generate a comprehensive behavior analysis report.

        Combines activity statistics, anomaly detection, risk indicators,
        and a timeline into a single report.

        Args:
            agent_id: The agent to analyze.
            time_window_hours: Hours of history to include in the report.

        Returns:
            A BehaviorReport with full analysis results.
        """
        now = _utcnow()
        window_start = now - timedelta(hours=time_window_hours)

        activities = self._buffer.get_activities(
            agent_id, since=window_start, until=now
        )
        anomalies = self.detect_anomalies(agent_id, time_window_hours)

        # Compute activity statistics
        unique_actions = set(a.action for a in activities)
        unique_resources = set(a.resource for a in activities)

        # Compute risk indicators
        risk_indicators = self._compute_risk_indicators(agent_id, anomalies, activities)

        # Determine overall risk level
        risk_level = self._compute_overall_risk(anomalies, risk_indicators)

        # Build timeline of significant events
        timeline = self._build_timeline(activities, anomalies)

        # Generate summary
        summary = (
            f"Behavior report for agent {agent_id}: "
            f"{len(activities)} activities in {time_window_hours}h window, "
            f"{len(unique_actions)} unique actions, "
            f"{len(anomalies)} anomalies detected, "
            f"risk level: {risk_level.value}"
        )

        report = BehaviorReport(
            report_id=str(uuid.uuid4()),
            agent_id=agent_id,
            generated_at=now,
            time_window_start=window_start,
            time_window_end=now,
            total_activities=len(activities),
            unique_actions=len(unique_actions),
            unique_resources=len(unique_resources),
            anomalies=anomalies,
            risk_indicators=risk_indicators,
            risk_level=risk_level,
            timeline=timeline,
            summary=summary,
        )

        logger.info(
            "Generated behavior report %s for agent %s: risk=%s, anomalies=%d",
            report.report_id,
            agent_id,
            risk_level.value,
            len(anomalies),
        )
        return report

    # =========================================================================
    # Private Detection Methods
    # =========================================================================

    def _detect_privilege_jumps(
        self,
        agent_id: str,
        activities: list[ActivityRecord],
        baseline: BehaviorBaseline,
    ) -> list[BehaviorAnomaly]:
        """Detect sudden escalation in permission usage.

        Identifies when an agent starts using significantly more privileged
        actions than its normal pattern.

        Args:
            agent_id: The agent being analyzed.
            activities: Recent activity records.
            baseline: The behavior baseline.

        Returns:
            List of PRIVILEGE_JUMP anomalies.
        """
        anomalies: list[BehaviorAnomaly] = []

        # Define privileged action prefixes (IAM, STS, Organizations, etc.)
        privileged_prefixes = {
            "iam:", "sts:", "organizations:", "kms:", "secretsmanager:",
            "cloudtrail:", "guardduty:", "config:", "access-analyzer:",
        }

        # Count privileged actions in baseline vs current
        baseline_privileged = {
            a for a in baseline.normal_actions
            if any(a.lower().startswith(p) for p in privileged_prefixes)
        }

        current_privileged_actions: set[str] = set()
        for activity in activities:
            if any(activity.action.lower().startswith(p) for p in privileged_prefixes):
                current_privileged_actions.add(activity.action)

        # New privileged actions not in baseline
        new_privileged = current_privileged_actions - baseline_privileged
        if new_privileged:
            # Higher score for more new privileged actions
            score = min(0.5 + (len(new_privileged) * 0.1), 1.0)
            anomalies.append(BehaviorAnomaly(
                anomaly_id=str(uuid.uuid4()),
                agent_id=agent_id,
                anomaly_type=AnomalyType.PRIVILEGE_JUMP,
                action=sorted(new_privileged)[0],
                resource="*",
                timestamp=_utcnow(),
                deviation_score=score,
                description=(
                    f"Agent using {len(new_privileged)} new privileged action(s) "
                    f"not in baseline: {sorted(new_privileged)[:5]}"
                ),
                evidence={
                    "new_privileged_actions": sorted(new_privileged),
                    "baseline_privileged_count": len(baseline_privileged),
                    "current_privileged_count": len(current_privileged_actions),
                },
            ))

        return anomalies

    def _detect_unusual_sequences(
        self,
        agent_id: str,
        activities: list[ActivityRecord],
        baseline: BehaviorBaseline,
    ) -> list[BehaviorAnomaly]:
        """Detect unusual action sequences.

        Identifies action pairs that were never observed in the baseline period.

        Args:
            agent_id: The agent being analyzed.
            activities: Recent activity records.
            baseline: The behavior baseline.

        Returns:
            List of UNUSUAL_SEQUENCE anomalies.
        """
        anomalies: list[BehaviorAnomaly] = []

        if not baseline.action_sequences or len(activities) < 2:
            return anomalies

        known_sequences = set(baseline.action_sequences)

        for i in range(len(activities) - 1):
            pair = (activities[i].action, activities[i + 1].action)
            if pair not in known_sequences:
                # Only flag if both actions are individually known (sequence is novel)
                if (
                    activities[i].action in baseline.normal_actions
                    and activities[i + 1].action in baseline.normal_actions
                ):
                    anomalies.append(BehaviorAnomaly(
                        anomaly_id=str(uuid.uuid4()),
                        agent_id=agent_id,
                        anomaly_type=AnomalyType.UNUSUAL_SEQUENCE,
                        action=f"{pair[0]} -> {pair[1]}",
                        resource=activities[i + 1].resource,
                        timestamp=activities[i + 1].timestamp,
                        deviation_score=0.55,
                        description=(
                            f"Unusual action sequence: '{pair[0]}' followed by "
                            f"'{pair[1]}' not seen in {baseline.total_observations} "
                            f"baseline observations"
                        ),
                        evidence={
                            "sequence": list(pair),
                            "known_sequence_count": len(known_sequences),
                        },
                    ))

        return anomalies

    def _detect_volume_anomaly(
        self,
        agent_id: str,
        activities: list[ActivityRecord],
        baseline: BehaviorBaseline,
        time_window_hours: int,
    ) -> BehaviorAnomaly | None:
        """Detect abnormal activity volume.

        Checks if the number of actions in the time window exceeds
        the expected volume based on baseline statistics.

        Args:
            agent_id: The agent being analyzed.
            activities: Recent activity records.
            baseline: The behavior baseline.
            time_window_hours: The time window being analyzed.

        Returns:
            A VOLUME_ANOMALY if detected, None otherwise.
        """
        if not activities or baseline.normal_volume == (0.0, 0.0):
            return None

        count = len(activities)
        window_hours = max(time_window_hours, 1)

        if not baseline.is_normal_volume(count, window_hours):
            mean, stddev = baseline.normal_volume
            hourly_rate = count / window_hours
            if stddev > 0:
                z_score = (hourly_rate - mean) / stddev
                score = min(0.5 + (z_score / 10.0), 1.0)
            else:
                score = 0.7

            return BehaviorAnomaly(
                anomaly_id=str(uuid.uuid4()),
                agent_id=agent_id,
                anomaly_type=AnomalyType.VOLUME_ANOMALY,
                action="*",
                resource="*",
                timestamp=_utcnow(),
                deviation_score=max(0.0, min(score, 1.0)),
                description=(
                    f"Abnormal activity volume: {count} actions in "
                    f"{time_window_hours}h ({hourly_rate:.1f}/h) vs "
                    f"baseline mean {mean:.1f}/h (stddev {stddev:.1f})"
                ),
                evidence={
                    "observed_count": count,
                    "window_hours": time_window_hours,
                    "hourly_rate": hourly_rate,
                    "baseline_mean": mean,
                    "baseline_stddev": stddev,
                },
            )

        return None

    def _deduplicate_anomalies(
        self,
        anomalies: list[BehaviorAnomaly],
    ) -> list[BehaviorAnomaly]:
        """Deduplicate anomalies, keeping the highest deviation score.

        Groups by (anomaly_type, action, resource) and retains only
        the most severe instance of each.

        Args:
            anomalies: Raw list of detected anomalies.

        Returns:
            Deduplicated list with highest-severity representatives.
        """
        best: dict[tuple[str, str, str], BehaviorAnomaly] = {}

        for anomaly in anomalies:
            key = (anomaly.anomaly_type.value, anomaly.action, anomaly.resource)
            existing = best.get(key)
            if existing is None or anomaly.deviation_score > existing.deviation_score:
                best[key] = anomaly

        return sorted(
            best.values(),
            key=lambda a: a.deviation_score,
            reverse=True,
        )

    def _compute_risk_indicators(
        self,
        agent_id: str,
        anomalies: list[BehaviorAnomaly],
        activities: list[ActivityRecord],
    ) -> list[RiskIndicator]:
        """Derive risk indicators from anomalies and activity patterns.

        Args:
            agent_id: The agent being assessed.
            anomalies: Detected anomalies.
            activities: Recent activity records.

        Returns:
            List of RiskIndicator objects.
        """
        indicators: list[RiskIndicator] = []

        # Privilege escalation indicator
        priv_anomalies = [
            a for a in anomalies if a.anomaly_type == AnomalyType.PRIVILEGE_JUMP
        ]
        if priv_anomalies:
            max_score = max(a.deviation_score for a in priv_anomalies)
            level = (
                RiskLevel.CRITICAL if max_score >= _DEVIATION_CRITICAL_THRESHOLD
                else RiskLevel.HIGH if max_score >= _DEVIATION_HIGH_THRESHOLD
                else RiskLevel.MEDIUM
            )
            indicators.append(RiskIndicator(
                indicator="privilege_escalation_risk",
                level=level,
                description=(
                    f"Agent showing privilege escalation behavior with "
                    f"{len(priv_anomalies)} related anomaly(ies)"
                ),
                contributing_anomalies=[a.anomaly_id for a in priv_anomalies],
            ))

        # Data exfiltration indicator
        dest_anomalies = [
            a for a in anomalies if a.anomaly_type == AnomalyType.NEW_DESTINATION
        ]
        volume_anomalies = [
            a for a in anomalies if a.anomaly_type == AnomalyType.VOLUME_ANOMALY
        ]
        if dest_anomalies and volume_anomalies:
            indicators.append(RiskIndicator(
                indicator="data_exfiltration_risk",
                level=RiskLevel.HIGH,
                description=(
                    "New destinations combined with abnormal volume suggests "
                    "potential data exfiltration"
                ),
                contributing_anomalies=(
                    [a.anomaly_id for a in dest_anomalies]
                    + [a.anomaly_id for a in volume_anomalies]
                ),
            ))

        # Unauthorized access indicator
        tool_anomalies = [
            a for a in anomalies if a.anomaly_type == AnomalyType.UNEXPECTED_TOOL
        ]
        service_anomalies = [
            a for a in anomalies if a.anomaly_type == AnomalyType.UNEXPECTED_SERVICE
        ]
        if tool_anomalies or service_anomalies:
            combined = tool_anomalies + service_anomalies
            max_score = max(a.deviation_score for a in combined)
            level = (
                RiskLevel.HIGH if max_score >= _DEVIATION_HIGH_THRESHOLD
                else RiskLevel.MEDIUM
            )
            indicators.append(RiskIndicator(
                indicator="unauthorized_access_risk",
                level=level,
                description=(
                    f"Agent using undeclared tools or services "
                    f"({len(tool_anomalies)} tool, {len(service_anomalies)} service anomalies)"
                ),
                contributing_anomalies=[a.anomaly_id for a in combined],
            ))

        # Off-hours activity indicator
        time_anomalies = [
            a for a in anomalies if a.anomaly_type == AnomalyType.TIME_ANOMALY
        ]
        if time_anomalies:
            indicators.append(RiskIndicator(
                indicator="off_hours_activity",
                level=RiskLevel.MEDIUM,
                description=(
                    f"Agent active outside normal hours "
                    f"({len(time_anomalies)} time anomaly events)"
                ),
                contributing_anomalies=[a.anomaly_id for a in time_anomalies],
            ))

        return indicators

    def _compute_overall_risk(
        self,
        anomalies: list[BehaviorAnomaly],
        indicators: list[RiskIndicator],
    ) -> RiskLevel:
        """Compute the overall risk level from anomalies and indicators.

        Args:
            anomalies: All detected anomalies.
            indicators: Derived risk indicators.

        Returns:
            The overall RiskLevel for the agent.
        """
        if not anomalies:
            return RiskLevel.NORMAL

        # Check indicator levels first
        indicator_levels = [i.level for i in indicators]
        if RiskLevel.CRITICAL in indicator_levels:
            return RiskLevel.CRITICAL
        if RiskLevel.HIGH in indicator_levels:
            return RiskLevel.HIGH

        # Fall back to anomaly scores
        max_score = max(a.deviation_score for a in anomalies)
        if max_score >= _DEVIATION_CRITICAL_THRESHOLD:
            return RiskLevel.CRITICAL
        if max_score >= _DEVIATION_HIGH_THRESHOLD:
            return RiskLevel.HIGH
        if max_score >= 0.4:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _build_timeline(
        self,
        activities: list[ActivityRecord],
        anomalies: list[BehaviorAnomaly],
    ) -> list[dict[str, Any]]:
        """Build a chronological timeline of significant events.

        Merges activities and anomalies into a unified timeline,
        highlighting anomalous events.

        Args:
            activities: Activity records in the window.
            anomalies: Detected anomalies.

        Returns:
            List of timeline entries ordered by timestamp.
        """
        timeline: list[dict[str, Any]] = []

        # Create a set of anomalous timestamps for cross-reference
        anomaly_timestamps = {a.timestamp for a in anomalies}
        anomaly_actions = {(a.action, a.resource) for a in anomalies}

        # Add activity entries (sample to avoid excessive timeline length)
        max_timeline_entries = 50
        step = max(1, len(activities) // max_timeline_entries)

        for i in range(0, len(activities), step):
            activity = activities[i]
            is_anomalous = (
                activity.timestamp in anomaly_timestamps
                or (activity.action, activity.resource) in anomaly_actions
            )
            timeline.append({
                "timestamp": activity.timestamp.isoformat(),
                "type": "activity",
                "action": activity.action,
                "resource": activity.resource,
                "anomalous": is_anomalous,
            })

        # Add anomaly entries
        for anomaly in anomalies:
            timeline.append({
                "timestamp": anomaly.timestamp.isoformat(),
                "type": "anomaly",
                "anomaly_type": anomaly.anomaly_type.value,
                "action": anomaly.action,
                "deviation_score": anomaly.deviation_score,
                "description": anomaly.description,
            })

        # Sort by timestamp
        timeline.sort(key=lambda e: e["timestamp"])
        return timeline
