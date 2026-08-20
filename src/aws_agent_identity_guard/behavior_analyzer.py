"""
aws_agent_identity_guard/behavior_analyzer.py
---------------------------------------------------------------------------
Runtime-vs-Declared Behavior Analysis Module.

Records and analyzes AI agent runtime behavior to detect deviations from
declared capabilities. Identifies unexpected tools, services, resources,
privilege jumps, and unusual action sequences that may indicate compromise
or misconfiguration.

Security philosophy:
  - What an agent declares it will do and what it actually does must match.
  - Runtime behavior creates an empirical baseline for anomaly detection.
  - Sudden changes in behavior patterns are high-confidence indicators of
    compromise or policy violation.
  - Sequence analysis catches multi-step attack patterns invisible to
    per-action checks.
"""

from __future__ import annotations

import logging
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aws_agent_identity_guard.models import AgentIdentity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AnomalyType(str, Enum):
    """Classification of behavior anomalies."""

    UNEXPECTED_TOOL = "UNEXPECTED_TOOL"
    UNEXPECTED_SERVICE = "UNEXPECTED_SERVICE"
    ABNORMAL_RESOURCE = "ABNORMAL_RESOURCE"
    PRIVILEGE_JUMP = "PRIVILEGE_JUMP"
    UNUSUAL_SEQUENCE = "UNUSUAL_SEQUENCE"


class AnomalySeverity(str, Enum):
    """Severity of a detected behavioral anomaly."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass
class ActionRecord:
    """
    A single recorded runtime action performed by an agent.

    Attributes:
        agent_id: The agent that performed this action.
        action: The IAM action or tool invocation.
        resource: The target resource ARN.
        timestamp: When the action was performed.
        success: Whether the action succeeded.
        context: Additional context (IP, session, tool name, etc.).
    """

    agent_id: str
    action: str
    resource: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    success: bool = True
    context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate action record."""
        if not self.agent_id:
            raise ValueError("agent_id cannot be empty")
        if not self.action:
            raise ValueError("action cannot be empty")

    @property
    def service(self) -> str:
        """Extract the service name from the action."""
        if ":" in self.action:
            return self.action.split(":")[0]
        return "unknown"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "agent_id": self.agent_id,
            "action": self.action,
            "resource": self.resource,
            "timestamp": self.timestamp.isoformat(),
            "success": self.success,
            "context": self.context,
            "service": self.service,
        }


@dataclass
class BehaviorAnomaly:
    """
    A detected deviation from expected agent behavior.

    Attributes:
        anomaly_type: Classification of the anomaly.
        description: Human-readable description of what was observed.
        severity: How severe this anomaly is.
        evidence: List of evidence items supporting this anomaly detection.
        timestamp: When this anomaly was detected.
    """

    anomaly_type: AnomalyType
    description: str
    severity: AnomalySeverity
    evidence: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "anomaly_type": self.anomaly_type.value,
            "description": self.description,
            "severity": self.severity.value,
            "evidence": list(self.evidence),
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class BehaviorBaseline:
    """
    Established behavioral baseline for an agent over a time window.

    Attributes:
        agent_id: The agent this baseline describes.
        normal_services: Services the agent normally accesses.
        normal_resources: Resource patterns the agent normally targets.
        normal_action_patterns: Common action sequences (bigrams).
        established_at: When this baseline was computed.
        action_count: Total actions in the baseline period.
        time_window_hours: How many hours of data this baseline covers.
    """

    agent_id: str
    normal_services: set[str] = field(default_factory=set)
    normal_resources: set[str] = field(default_factory=set)
    normal_action_patterns: list[tuple[str, str]] = field(default_factory=list)
    established_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    action_count: int = 0
    time_window_hours: int = 168  # 7 days default

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "agent_id": self.agent_id,
            "normal_services": sorted(self.normal_services),
            "normal_resources": sorted(self.normal_resources),
            "normal_action_patterns": [
                list(pair) for pair in self.normal_action_patterns
            ],
            "established_at": self.established_at.isoformat(),
            "action_count": self.action_count,
            "time_window_hours": self.time_window_hours,
        }


@dataclass
class BehaviorReport:
    """
    Complete behavior analysis report for an agent.

    Attributes:
        agent_id: The agent analyzed.
        time_window: Time window of the analysis in hours.
        total_actions: Total actions recorded in the window.
        unique_services: Number of unique services accessed.
        unique_resources: Number of unique resources targeted.
        anomalies: List of detected behavioral anomalies.
        risk_adjustment: Risk adjustment score based on behavior (-50 to +50).
    """

    agent_id: str
    time_window: int = 24
    total_actions: int = 0
    unique_services: int = 0
    unique_resources: int = 0
    anomalies: list[BehaviorAnomaly] = field(default_factory=list)
    risk_adjustment: int = 0

    def __post_init__(self) -> None:
        """Validate behavior report."""
        if not self.agent_id:
            raise ValueError("agent_id cannot be empty")
        if not (-50 <= self.risk_adjustment <= 50):
            raise ValueError(
                f"risk_adjustment must be between -50 and 50, got {self.risk_adjustment}"
            )

    @property
    def has_anomalies(self) -> bool:
        """Check if any anomalies were detected."""
        return len(self.anomalies) > 0

    @property
    def critical_anomalies(self) -> list[BehaviorAnomaly]:
        """Get only CRITICAL severity anomalies."""
        return [a for a in self.anomalies if a.severity == AnomalySeverity.CRITICAL]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "agent_id": self.agent_id,
            "time_window": self.time_window,
            "total_actions": self.total_actions,
            "unique_services": self.unique_services,
            "unique_resources": self.unique_resources,
            "anomalies": [a.to_dict() for a in self.anomalies],
            "risk_adjustment": self.risk_adjustment,
            "has_anomalies": self.has_anomalies,
            "critical_count": len(self.critical_anomalies),
        }


@dataclass
class BehaviorDrift:
    """
    Summary of behavioral drift from baseline.

    Attributes:
        new_services: Services accessed that are not in the baseline.
        new_resources: Resources targeted that are not in the baseline.
        frequency_changes: Actions with significant frequency changes.
        time_pattern_changes: Changes in timing patterns.
    """

    new_services: list[str] = field(default_factory=list)
    new_resources: list[str] = field(default_factory=list)
    frequency_changes: dict[str, float] = field(default_factory=dict)
    time_pattern_changes: dict[str, str] = field(default_factory=dict)

    @property
    def has_drift(self) -> bool:
        """Check if any behavioral drift was detected."""
        return bool(
            self.new_services
            or self.new_resources
            or self.frequency_changes
            or self.time_pattern_changes
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "new_services": list(self.new_services),
            "new_resources": list(self.new_resources),
            "frequency_changes": dict(self.frequency_changes),
            "time_pattern_changes": dict(self.time_pattern_changes),
            "has_drift": self.has_drift,
        }



# ---------------------------------------------------------------------------
# Privilege escalation indicators
# ---------------------------------------------------------------------------

_PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicy",
    "iam:CreatePolicyVersion",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:AddUserToGroup",
    "sts:AssumeRole",
    "sts:AssumeRoleWithSAML",
    "sts:AssumeRoleWithWebIdentity",
}

_HIGH_PRIVILEGE_ACTIONS = {
    "iam:CreateUser",
    "iam:DeleteUser",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "ec2:RunInstances",
    "cloudformation:CreateStack",
    "cloudformation:UpdateStack",
}


# ---------------------------------------------------------------------------
# Behavior Analyzer
# ---------------------------------------------------------------------------


class BehaviorAnalyzer:
    """
    Records and analyzes AI agent runtime behavior for anomaly detection.

    Maintains a record of all actions performed by agents, builds behavioral
    baselines, and detects deviations that may indicate compromise, abuse,
    or misconfiguration.

    Usage:
        analyzer = BehaviorAnalyzer()
        analyzer.record_action("agent-1", "s3:GetObject", "arn:aws:s3:::bucket/key")
        report = analyzer.analyze("agent-1")
        if report.has_anomalies:
            investigate(report)
    """

    def __init__(self, agent_registry: dict[str, AgentIdentity] | None = None) -> None:
        """
        Initialize the behavior analyzer.

        Args:
            agent_registry: Optional mapping of agent_id to AgentIdentity.
                Used to look up declared capabilities for comparison.
        """
        self._actions: dict[str, list[ActionRecord]] = defaultdict(list)
        self._baselines: dict[str, BehaviorBaseline] = {}
        self._agent_registry: dict[str, AgentIdentity] = agent_registry or {}
        self._lock = threading.Lock()
        logger.info("BehaviorAnalyzer initialized")

    def register_agent(self, agent: AgentIdentity) -> None:
        """
        Register an agent identity for behavior analysis.

        Args:
            agent: The agent identity to register.
        """
        with self._lock:
            self._agent_registry[agent.agent_id] = agent
        logger.debug("Registered agent '%s' for behavior analysis", agent.name)

    def record_action(
        self,
        agent_id: str,
        action: str,
        resource: str,
        timestamp: datetime | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """
        Record a runtime action performed by an agent.

        Args:
            agent_id: The agent that performed the action.
            action: The IAM action or tool invocation string.
            resource: The target resource ARN or identifier.
            timestamp: When the action occurred. Defaults to now.
            context: Additional context (tool name, IP, session, etc.).

        Raises:
            ValueError: If agent_id or action is empty.
        """
        if not agent_id:
            raise ValueError("agent_id cannot be empty")
        if not action:
            raise ValueError("action cannot be empty")

        record = ActionRecord(
            agent_id=agent_id,
            action=action,
            resource=resource or "*",
            timestamp=timestamp or datetime.now(timezone.utc),
            context=context or {},
        )

        with self._lock:
            self._actions[agent_id].append(record)

        logger.debug(
            "Recorded action for agent '%s': %s on %s",
            agent_id,
            action,
            resource,
        )

    def analyze(self, agent_id: str, time_window_hours: int = 24) -> BehaviorReport:
        """
        Analyze recorded behavior for an agent and detect anomalies.

        Examines all actions within the specified time window against the
        agent's declared capabilities and behavioral baseline.

        Args:
            agent_id: The agent to analyze.
            time_window_hours: How many hours back to analyze.

        Returns:
            BehaviorReport with anomalies and statistics.

        Raises:
            ValueError: If agent_id is empty.
        """
        if not agent_id:
            raise ValueError("agent_id cannot be empty")

        logger.info(
            "Analyzing behavior for agent '%s' over %d hour window",
            agent_id,
            time_window_hours,
        )

        # Get actions within time window
        cutoff = datetime.now(timezone.utc) - timedelta(hours=time_window_hours)
        with self._lock:
            all_actions = self._actions.get(agent_id, [])
            recent_actions = [a for a in all_actions if a.timestamp >= cutoff]

        if not recent_actions:
            logger.info("No actions recorded for agent '%s' in the time window", agent_id)
            return BehaviorReport(
                agent_id=agent_id,
                time_window=time_window_hours,
            )

        # Get agent identity if registered
        agent = self._agent_registry.get(agent_id)

        # Run all anomaly detection methods
        anomalies: list[BehaviorAnomaly] = []

        if agent:
            anomalies.extend(self._detect_unexpected_tools(agent, recent_actions))
            anomalies.extend(self._detect_unexpected_services(agent, recent_actions))
            anomalies.extend(self._detect_abnormal_resources(agent, recent_actions))

        anomalies.extend(self._detect_privilege_jumps(agent, recent_actions))
        anomalies.extend(self._detect_unusual_sequences(agent, recent_actions))

        # Compute statistics
        unique_services = {a.service for a in recent_actions}
        unique_resources = {a.resource for a in recent_actions}

        # Calculate risk adjustment based on anomalies
        risk_adjustment = self._calculate_risk_adjustment(anomalies)

        report = BehaviorReport(
            agent_id=agent_id,
            time_window=time_window_hours,
            total_actions=len(recent_actions),
            unique_services=len(unique_services),
            unique_resources=len(unique_resources),
            anomalies=anomalies,
            risk_adjustment=risk_adjustment,
        )

        logger.info(
            "Behavior analysis complete for agent '%s': "
            "%d actions, %d services, %d anomalies, risk_adj=%d",
            agent_id,
            report.total_actions,
            report.unique_services,
            len(anomalies),
            risk_adjustment,
        )

        return report

    def _detect_unexpected_tools(
        self,
        agent: AgentIdentity,
        recorded_actions: list[ActionRecord],
    ) -> list[BehaviorAnomaly]:
        """
        Detect use of tools not declared in the agent's capabilities.

        Args:
            agent: The agent identity with declared capabilities.
            recorded_actions: Actions recorded in the analysis window.

        Returns:
            List of anomalies for unexpected tool usage.
        """
        anomalies: list[BehaviorAnomaly] = []

        # Extract declared tool names from context of capabilities
        declared_tools: set[str] = set()
        for cap in agent.declared_capabilities:
            # Capability names often imply the tool (e.g., "invoke-lambda")
            declared_tools.add(cap)

        # Check action contexts for tool references
        for action_record in recorded_actions:
            tool_name = action_record.context.get("tool", "")
            if tool_name and tool_name not in declared_tools:
                anomalies.append(
                    BehaviorAnomaly(
                        anomaly_type=AnomalyType.UNEXPECTED_TOOL,
                        description=(
                            f"Agent '{agent.name}' used tool '{tool_name}' which is "
                            f"not in its declared capabilities. "
                            f"Action: {action_record.action}"
                        ),
                        severity=AnomalySeverity.MEDIUM,
                        evidence=[
                            f"Tool: {tool_name}",
                            f"Action: {action_record.action}",
                            f"Resource: {action_record.resource}",
                            f"Timestamp: {action_record.timestamp.isoformat()}",
                        ],
                        timestamp=action_record.timestamp,
                    )
                )

        return anomalies

    def _detect_unexpected_services(
        self,
        agent: AgentIdentity,
        recorded_actions: list[ActionRecord],
    ) -> list[BehaviorAnomaly]:
        """
        Detect access to AWS services not implied by declared capabilities.

        Args:
            agent: The agent identity with declared capabilities.
            recorded_actions: Actions recorded in the analysis window.

        Returns:
            List of anomalies for unexpected service usage.
        """
        anomalies: list[BehaviorAnomaly] = []

        # Derive expected services from declared capabilities
        expected_services = self._derive_expected_services(agent)

        # Find services actually accessed
        accessed_services: dict[str, list[ActionRecord]] = defaultdict(list)
        for record in recorded_actions:
            accessed_services[record.service].append(record)

        # Detect unexpected service usage
        for service, service_actions in accessed_services.items():
            if service not in expected_services and service != "unknown":
                severity = AnomalySeverity.MEDIUM
                # Elevate for sensitive services
                sensitive_services = {"iam", "sts", "organizations", "cloudtrail", "kms"}
                if service in sensitive_services:
                    severity = AnomalySeverity.HIGH

                sample_actions = [a.action for a in service_actions[:5]]
                anomalies.append(
                    BehaviorAnomaly(
                        anomaly_type=AnomalyType.UNEXPECTED_SERVICE,
                        description=(
                            f"Agent '{agent.name}' accessed service '{service}' which "
                            f"is not expected based on declared capabilities. "
                            f"{len(service_actions)} action(s) recorded."
                        ),
                        severity=severity,
                        evidence=[
                            f"Service: {service}",
                            f"Action count: {len(service_actions)}",
                            f"Sample actions: {', '.join(sample_actions)}",
                            f"Declared capabilities: {', '.join(agent.declared_capabilities)}",
                        ],
                        timestamp=service_actions[0].timestamp,
                    )
                )

        return anomalies

    def _detect_abnormal_resources(
        self,
        agent: AgentIdentity,
        recorded_actions: list[ActionRecord],
    ) -> list[BehaviorAnomaly]:
        """
        Detect access to resources outside the agent's normal scope.

        Args:
            agent: The agent identity with declared capabilities.
            recorded_actions: Actions recorded in the analysis window.

        Returns:
            List of anomalies for abnormal resource access.
        """
        anomalies: list[BehaviorAnomaly] = []

        # Check against baseline if available
        baseline = self._baselines.get(agent.agent_id)
        if not baseline:
            return anomalies

        for record in recorded_actions:
            if record.resource == "*":
                continue

            if record.resource not in baseline.normal_resources:
                # Check if it matches any pattern in normal resources
                is_expected = False
                for normal_resource in baseline.normal_resources:
                    if self._resource_matches_pattern(record.resource, normal_resource):
                        is_expected = True
                        break

                if not is_expected:
                    anomalies.append(
                        BehaviorAnomaly(
                            anomaly_type=AnomalyType.ABNORMAL_RESOURCE,
                            description=(
                                f"Agent '{agent.name}' accessed resource "
                                f"'{record.resource}' which is outside its established "
                                f"behavioral baseline."
                            ),
                            severity=AnomalySeverity.MEDIUM,
                            evidence=[
                                f"Resource: {record.resource}",
                                f"Action: {record.action}",
                                f"Timestamp: {record.timestamp.isoformat()}",
                                f"Baseline resources: {len(baseline.normal_resources)}",
                            ],
                            timestamp=record.timestamp,
                        )
                    )

        return anomalies

    def _detect_privilege_jumps(
        self,
        agent: AgentIdentity | None,
        recorded_actions: list[ActionRecord],
    ) -> list[BehaviorAnomaly]:
        """
        Detect sudden jumps in privilege level of actions.

        Identifies when an agent transitions from low-privilege actions
        (read, list) to high-privilege actions (create, delete, modify IAM)
        without gradual escalation.

        Args:
            agent: The agent identity (may be None).
            recorded_actions: Actions recorded in the analysis window.

        Returns:
            List of anomalies for privilege jumps.
        """
        anomalies: list[BehaviorAnomaly] = []

        if len(recorded_actions) < 2:
            return anomalies

        # Sort actions by timestamp
        sorted_actions = sorted(recorded_actions, key=lambda a: a.timestamp)

        # Look for transitions from low to high privilege
        for i in range(1, len(sorted_actions)):
            prev_action = sorted_actions[i - 1]
            curr_action = sorted_actions[i]

            prev_level = self._action_privilege_level(prev_action.action)
            curr_level = self._action_privilege_level(curr_action.action)

            # Detect jump of 2+ levels
            if curr_level - prev_level >= 2:
                agent_name = agent.name if agent else curr_action.agent_id
                severity = AnomalySeverity.HIGH
                if curr_action.action in _PRIVILEGE_ESCALATION_ACTIONS:
                    severity = AnomalySeverity.CRITICAL

                anomalies.append(
                    BehaviorAnomaly(
                        anomaly_type=AnomalyType.PRIVILEGE_JUMP,
                        description=(
                            f"Agent '{agent_name}' jumped from low-privilege action "
                            f"'{prev_action.action}' to high-privilege action "
                            f"'{curr_action.action}' within "
                            f"{(curr_action.timestamp - prev_action.timestamp).seconds}s."
                        ),
                        severity=severity,
                        evidence=[
                            f"Previous: {prev_action.action} (level {prev_level})",
                            f"Current: {curr_action.action} (level {curr_level})",
                            f"Time gap: {(curr_action.timestamp - prev_action.timestamp).seconds}s",
                            f"Resource: {curr_action.resource}",
                        ],
                        timestamp=curr_action.timestamp,
                    )
                )

        return anomalies

    def _detect_unusual_sequences(
        self,
        agent: AgentIdentity | None,
        recorded_actions: list[ActionRecord],
    ) -> list[BehaviorAnomaly]:
        """
        Detect unusual action sequences that may indicate attack patterns.

        Looks for known attack sequence patterns (reconnaissance followed by
        exploitation, data access followed by exfiltration, etc.).

        Args:
            agent: The agent identity (may be None).
            recorded_actions: Actions recorded in the analysis window.

        Returns:
            List of anomalies for unusual sequences.
        """
        anomalies: list[BehaviorAnomaly] = []

        if len(recorded_actions) < 3:
            return anomalies

        sorted_actions = sorted(recorded_actions, key=lambda a: a.timestamp)
        action_sequence = [a.action for a in sorted_actions]

        # Define known attack patterns as sequences
        attack_patterns: list[dict[str, Any]] = [
            {
                "name": "Reconnaissance then Escalation",
                "indicators": (
                    {"iam:ListRoles", "iam:ListPolicies", "iam:GetRole"},
                    {"iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:CreateRole"},
                ),
                "severity": AnomalySeverity.CRITICAL,
            },
            {
                "name": "Credential Harvesting",
                "indicators": (
                    {"secretsmanager:ListSecrets", "ssm:DescribeParameters"},
                    {"secretsmanager:GetSecretValue", "ssm:GetParameter"},
                ),
                "severity": AnomalySeverity.HIGH,
            },
            {
                "name": "Data Staging for Exfiltration",
                "indicators": (
                    {"s3:ListBucket", "dynamodb:Scan"},
                    {"s3:PutObject", "s3:CopyObject"},
                ),
                "severity": AnomalySeverity.HIGH,
            },
            {
                "name": "Security Control Disablement",
                "indicators": (
                    {"cloudtrail:DescribeTrails", "guardduty:ListDetectors"},
                    {"cloudtrail:StopLogging", "guardduty:DeleteDetector"},
                ),
                "severity": AnomalySeverity.CRITICAL,
            },
        ]

        for pattern in attack_patterns:
            recon_indicators, exploit_indicators = pattern["indicators"]
            recon_found = recon_indicators & set(action_sequence)
            exploit_found = exploit_indicators & set(action_sequence)

            if recon_found and exploit_found:
                # Verify ordering: recon before exploit
                first_recon_idx = min(
                    action_sequence.index(a) for a in recon_found
                )
                last_exploit_idx = max(
                    action_sequence.index(a) for a in exploit_found
                )

                if first_recon_idx < last_exploit_idx:
                    agent_name = agent.name if agent else sorted_actions[0].agent_id
                    anomalies.append(
                        BehaviorAnomaly(
                            anomaly_type=AnomalyType.UNUSUAL_SEQUENCE,
                            description=(
                                f"Agent '{agent_name}' exhibited pattern "
                                f"'{pattern['name']}': reconnaissance actions "
                                f"followed by exploitation actions."
                            ),
                            severity=pattern["severity"],
                            evidence=[
                                f"Pattern: {pattern['name']}",
                                f"Recon actions: {', '.join(sorted(recon_found))}",
                                f"Exploit actions: {', '.join(sorted(exploit_found))}",
                                f"Sequence length: {len(action_sequence)} actions",
                            ],
                            timestamp=sorted_actions[last_exploit_idx].timestamp,
                        )
                    )

        # Also check against baseline patterns if available
        baseline = self._baselines.get(
            agent.agent_id if agent else (sorted_actions[0].agent_id if sorted_actions else "")
        )
        if baseline and baseline.normal_action_patterns:
            current_bigrams = set()
            for i in range(len(action_sequence) - 1):
                current_bigrams.add((action_sequence[i], action_sequence[i + 1]))

            normal_bigrams = set(baseline.normal_action_patterns)
            novel_bigrams = current_bigrams - normal_bigrams

            # Only flag if a significant portion is novel
            if len(novel_bigrams) > len(current_bigrams) * 0.5 and len(novel_bigrams) > 3:
                agent_name = agent.name if agent else sorted_actions[0].agent_id
                sample_novel = list(novel_bigrams)[:5]
                anomalies.append(
                    BehaviorAnomaly(
                        anomaly_type=AnomalyType.UNUSUAL_SEQUENCE,
                        description=(
                            f"Agent '{agent_name}' is executing action sequences "
                            f"significantly different from its behavioral baseline. "
                            f"{len(novel_bigrams)} novel action pairs detected."
                        ),
                        severity=AnomalySeverity.MEDIUM,
                        evidence=[
                            f"Novel pairs: {len(novel_bigrams)}",
                            f"Total pairs: {len(current_bigrams)}",
                            f"Sample: {sample_novel}",
                        ],
                    )
                )

        return anomalies

    def _build_behavior_baseline(
        self,
        agent_id: str,
        time_window_hours: int = 168,
    ) -> BehaviorBaseline:
        """
        Build a behavioral baseline from recorded actions.

        Analyzes historical actions to establish what is normal for this agent.

        Args:
            agent_id: The agent to build a baseline for.
            time_window_hours: How many hours of history to use (default 7 days).

        Returns:
            BehaviorBaseline representing normal behavior.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=time_window_hours)

        with self._lock:
            all_actions = self._actions.get(agent_id, [])
            window_actions = [a for a in all_actions if a.timestamp >= cutoff]

        if not window_actions:
            logger.warning(
                "No actions found for agent '%s' in %d hour window for baseline",
                agent_id,
                time_window_hours,
            )
            return BehaviorBaseline(
                agent_id=agent_id,
                time_window_hours=time_window_hours,
            )

        # Compute normal services
        normal_services = {a.service for a in window_actions}

        # Compute normal resources
        normal_resources = {a.resource for a in window_actions}

        # Compute normal action patterns (bigrams)
        sorted_actions = sorted(window_actions, key=lambda a: a.timestamp)
        action_bigrams: list[tuple[str, str]] = []
        for i in range(len(sorted_actions) - 1):
            bigram = (sorted_actions[i].action, sorted_actions[i + 1].action)
            action_bigrams.append(bigram)

        # Keep only frequently occurring bigrams
        bigram_counts = Counter(action_bigrams)
        frequent_bigrams = [
            bigram for bigram, count in bigram_counts.items()
            if count >= 2
        ]

        baseline = BehaviorBaseline(
            agent_id=agent_id,
            normal_services=normal_services,
            normal_resources=normal_resources,
            normal_action_patterns=frequent_bigrams,
            action_count=len(window_actions),
            time_window_hours=time_window_hours,
        )

        # Store the baseline
        with self._lock:
            self._baselines[agent_id] = baseline

        logger.info(
            "Built behavior baseline for agent '%s': "
            "%d services, %d resources, %d patterns from %d actions",
            agent_id,
            len(normal_services),
            len(normal_resources),
            len(frequent_bigrams),
            len(window_actions),
        )

        return baseline

    def compare_to_baseline(self, agent_id: str, time_window_hours: int = 24) -> BehaviorDrift:
        """
        Compare current behavior to established baseline.

        Args:
            agent_id: The agent to compare.
            time_window_hours: Recent window to compare against baseline.

        Returns:
            BehaviorDrift showing deviations from baseline.
        """
        baseline = self._baselines.get(agent_id)
        if not baseline:
            # Build baseline first if not available
            baseline = self._build_behavior_baseline(agent_id)

        # Get recent actions
        cutoff = datetime.now(timezone.utc) - timedelta(hours=time_window_hours)
        with self._lock:
            all_actions = self._actions.get(agent_id, [])
            recent_actions = [a for a in all_actions if a.timestamp >= cutoff]

        if not recent_actions:
            return BehaviorDrift()

        # Detect new services
        current_services = {a.service for a in recent_actions}
        new_services = sorted(current_services - baseline.normal_services)

        # Detect new resources
        current_resources = {a.resource for a in recent_actions}
        new_resources = sorted(current_resources - baseline.normal_resources)

        # Detect frequency changes
        current_action_counts = Counter(a.action for a in recent_actions)
        baseline_action_counts = Counter(
            a.action for a in self._actions.get(agent_id, [])
            if a.timestamp < cutoff
        )

        frequency_changes: dict[str, float] = {}
        for action, count in current_action_counts.items():
            baseline_count = baseline_action_counts.get(action, 0)
            if baseline_count > 0:
                ratio = count / baseline_count
                if ratio > 3.0 or ratio < 0.1:
                    frequency_changes[action] = round(ratio, 2)
            elif count > 5:
                frequency_changes[action] = float("inf")

        # Detect time pattern changes
        time_pattern_changes: dict[str, str] = {}
        current_hours = Counter(a.timestamp.hour for a in recent_actions)
        peak_hour = current_hours.most_common(1)[0][0] if current_hours else 0

        baseline_hours = Counter(
            a.timestamp.hour for a in self._actions.get(agent_id, [])
            if a.timestamp < cutoff
        )
        baseline_peak = baseline_hours.most_common(1)[0][0] if baseline_hours else 0

        if abs(peak_hour - baseline_peak) > 6:
            time_pattern_changes["peak_hour_shift"] = (
                f"Baseline peak: {baseline_peak}:00, Current peak: {peak_hour}:00"
            )

        drift = BehaviorDrift(
            new_services=new_services,
            new_resources=new_resources[:50],  # Cap for readability
            frequency_changes=frequency_changes,
            time_pattern_changes=time_pattern_changes,
        )

        logger.info(
            "Behavior drift comparison for agent '%s': "
            "new_services=%d, new_resources=%d, freq_changes=%d",
            agent_id,
            len(new_services),
            len(new_resources),
            len(frequency_changes),
        )

        return drift

    # -----------------------------------------------------------------------
    # Private Helpers
    # -----------------------------------------------------------------------

    def _derive_expected_services(self, agent: AgentIdentity) -> set[str]:
        """Derive expected AWS services from declared capabilities."""
        # Map capability names to expected services
        capability_service_hints: dict[str, set[str]] = {
            "read-s3": {"s3"},
            "write-s3": {"s3"},
            "read-s3-invoices": {"s3"},
            "read-dynamodb": {"dynamodb"},
            "write-dynamodb": {"dynamodb"},
            "invoke-lambda": {"lambda"},
            "invoke-bedrock": {"bedrock"},
            "read-secrets": {"secretsmanager"},
            "read-ssm-parameters": {"ssm"},
            "send-sqs": {"sqs"},
            "receive-sqs": {"sqs"},
            "publish-sns": {"sns"},
            "read-cloudwatch-logs": {"logs"},
            "write-cloudwatch-logs": {"logs"},
            "read-kinesis": {"kinesis"},
            "write-kinesis": {"kinesis"},
            "execute-step-functions": {"states"},
            "read-rds": {"rds-data"},
            "kms-decrypt": {"kms"},
            "kms-encrypt": {"kms"},
        }

        expected: set[str] = {"sts", "logs"}  # Always expected: identity + logging
        for cap in agent.declared_capabilities:
            if cap in capability_service_hints:
                expected.update(capability_service_hints[cap])

        return expected

    def _action_privilege_level(self, action: str) -> int:
        """
        Assign a numeric privilege level to an action.

        Levels:
            0 - Read/List/Describe/Get
            1 - Write/Put/Send/Publish
            2 - Create/Update/Modify
            3 - Delete/Terminate/Destroy
            4 - IAM/STS/Security modifications

        Args:
            action: The IAM action string.

        Returns:
            Integer privilege level 0-4.
        """
        if action in _PRIVILEGE_ESCALATION_ACTIONS:
            return 4
        if action in _HIGH_PRIVILEGE_ACTIONS:
            return 3

        action_lower = action.lower()
        if any(kw in action_lower for kw in ["delete", "terminate", "remove", "destroy"]):
            return 3
        if any(kw in action_lower for kw in ["create", "update", "modify", "attach"]):
            return 2
        if any(kw in action_lower for kw in ["put", "send", "publish", "write", "invoke"]):
            return 1
        # Default: read-level
        return 0

    def _resource_matches_pattern(self, resource: str, pattern: str) -> bool:
        """Check if a resource ARN matches a baseline resource pattern."""
        if pattern == "*":
            return True
        if resource == pattern:
            return True

        # Simple prefix matching for ARN patterns
        # e.g., arn:aws:s3:::my-bucket/* matches arn:aws:s3:::my-bucket/file.txt
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            if resource.startswith(prefix):
                return True

        # Match if same service and account, just different resource name
        resource_parts = resource.split(":")
        pattern_parts = pattern.split(":")
        return (
            len(resource_parts) >= 5
            and len(pattern_parts) >= 5
            and resource_parts[:5] == pattern_parts[:5]
        )

    def _calculate_risk_adjustment(self, anomalies: list[BehaviorAnomaly]) -> int:
        """
        Calculate risk adjustment score based on detected anomalies.

        Returns a value from -50 (reduce risk, very clean behavior) to
        +50 (increase risk, highly anomalous behavior).

        Args:
            anomalies: List of detected anomalies.

        Returns:
            Integer risk adjustment from -50 to +50.
        """
        if not anomalies:
            return -10  # Clean behavior reduces risk slightly

        severity_scores = {
            AnomalySeverity.LOW: 3,
            AnomalySeverity.MEDIUM: 8,
            AnomalySeverity.HIGH: 15,
            AnomalySeverity.CRITICAL: 25,
        }

        total = sum(
            severity_scores.get(a.severity, 5)
            for a in anomalies
        )

        return max(-50, min(50, total))
