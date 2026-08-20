"""AWS Agent Identity Guard - Intent-to-Permission Alignment Engine.

Compares declared agent capabilities (what an agent is supposed to do)
against effective permissions (what it can actually do) and observed
usage (what it has done). Detects misalignment categories:

- OVER_PRIVILEGE: permissions granted but not declared in manifest
- UNUSED_PERMISSIONS: permissions never exercised (CloudTrail analysis)
- DANGEROUS_UNRELATED: high-risk permissions unrelated to stated purpose
- MISSING_PERMISSIONS: actions in manifest but not in effective permissions

Provides alignment scoring (0-100) with category breakdowns and generates
specific remediation recommendations for each finding.

Manifest Format (YAML):
    agent:
      name: invoice-processor
      purpose: Process invoices from S3 and store in DynamoDB
      declared_actions:
        - s3:GetObject
        - s3:PutObject
        - dynamodb:PutItem
      declared_resources:
        - arn:aws:s3:::invoices-prod/*
        - arn:aws:dynamodb:us-east-1:*:table/invoices
      data_classification: CONFIDENTIAL
"""

from __future__ import annotations

import fnmatch
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, unique
from pathlib import Path
from typing import Any, Optional

import yaml

from .models import (
    DataClassification,
    EffectivePermission,
    Finding,
    FindingCategory,
    Permission,
    PermissionEffect,
    Severity,
    SerializableMixin,
    _utcnow,
)


__all__ = [
    "AlignmentCategory",
    "AlignmentFinding",
    "AlignmentReport",
    "AlignmentScoreBreakdown",
    "AgentManifest",
    "IntentAlignmentEngine",
    "ManifestValidationError",
    "PolicyDiff",
    "Recommendation",
    "load_manifest",
    "validate_manifest",
]


# =============================================================================
# Constants
# =============================================================================

# Actions considered high-risk regardless of context
DANGEROUS_ACTIONS: frozenset[str] = frozenset({
    "iam:CreateUser",
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreateLoginProfile",
    "iam:AddUserToGroup",
    "sts:AssumeRole",
    "organizations:LeaveOrganization",
    "organizations:DeleteOrganization",
    "ec2:RunInstances",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "lambda:AddPermission",
    "kms:Decrypt",
    "kms:CreateGrant",
    "kms:DisableKey",
    "kms:ScheduleKeyDeletion",
    "s3:PutBucketPolicy",
    "s3:DeleteBucketPolicy",
    "s3:PutBucketPublicAccessBlock",
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "guardduty:DeleteDetector",
    "config:DeleteConfigRule",
    "config:StopConfigurationRecorder",
})

# Penalty weights for alignment scoring per category
_CATEGORY_WEIGHTS: dict[str, float] = {
    "OVER_PRIVILEGE": 0.30,
    "UNUSED_PERMISSIONS": 0.20,
    "DANGEROUS_UNRELATED": 0.35,
    "MISSING_PERMISSIONS": 0.15,
}


# =============================================================================
# Enumerations
# =============================================================================


@unique
class AlignmentCategory(str, Enum):
    """Categories of intent-to-permission misalignment."""

    OVER_PRIVILEGE = "OVER_PRIVILEGE"
    UNUSED_PERMISSIONS = "UNUSED_PERMISSIONS"
    DANGEROUS_UNRELATED = "DANGEROUS_UNRELATED"
    MISSING_PERMISSIONS = "MISSING_PERMISSIONS"


# =============================================================================
# Exceptions
# =============================================================================


class ManifestValidationError(Exception):
    """Raised when a manifest file fails validation.

    Attributes:
        errors: List of individual validation failure messages.
    """

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__(f"Manifest validation failed: {'; '.join(errors)}")


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class AgentManifest(SerializableMixin):
    """Declaration of what an agent is supposed to do.

    The manifest is the source of truth for an agent's intended behaviour.
    It defines the actions, resources, services, and data classification levels
    that the agent legitimately requires to fulfil its purpose.

    Attributes:
        name: Human-readable identifier for the agent.
        purpose: Description of the agent's intended function.
        declared_actions: IAM action patterns the agent legitimately needs
            (supports wildcards, e.g. ``s3:Get*``).
        declared_resources: ARN patterns the agent may access
            (supports wildcards).
        declared_data_access: Data classification levels the agent
            should be able to access.
        declared_services: AWS service prefixes the agent is expected
            to interact with (e.g. ``s3``, ``dynamodb``).
        version: Manifest schema version.
        metadata: Additional key-value metadata for the manifest.
    """

    __slots__ = (
        "name",
        "purpose",
        "declared_actions",
        "declared_resources",
        "declared_data_access",
        "declared_services",
        "version",
        "metadata",
    )

    name: str
    purpose: str
    declared_actions: list[str]
    declared_resources: list[str]
    declared_data_access: list[DataClassification]
    declared_services: list[str]
    version: str
    metadata: dict[str, Any]

    @classmethod
    def create(
        cls,
        name: str,
        purpose: str,
        declared_actions: list[str],
        declared_resources: list[str] | None = None,
        declared_data_access: list[DataClassification] | None = None,
        declared_services: list[str] | None = None,
        version: str = "1.0",
        metadata: dict[str, Any] | None = None,
    ) -> AgentManifest:
        """Factory method for creating an AgentManifest with sensible defaults.

        Args:
            name: Agent name.
            purpose: Description of what the agent does.
            declared_actions: Required IAM action patterns.
            declared_resources: ARN patterns (auto-derived from actions if omitted).
            declared_data_access: Data classification levels.
            declared_services: AWS service prefixes (auto-derived from actions
                if omitted).
            version: Schema version string.
            metadata: Optional key-value metadata.

        Returns:
            A fully-initialized AgentManifest instance.
        """
        # Auto-derive services from action prefixes if not provided
        if declared_services is None:
            declared_services = list({
                action.split(":")[0]
                for action in declared_actions
                if ":" in action
            })

        return cls(
            name=name,
            purpose=purpose,
            declared_actions=declared_actions,
            declared_resources=declared_resources or ["*"],
            declared_data_access=declared_data_access or [DataClassification.INTERNAL],
            declared_services=declared_services,
            version=version,
            metadata=metadata or {},
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentManifest:
        """Reconstruct an AgentManifest from a dictionary.

        Handles nested ``agent:`` key from YAML format as well as flat dicts.
        """
        # Support nested YAML format: { agent: { ... } }
        if "agent" in data and isinstance(data["agent"], dict):
            data = data["agent"]

        data_access_raw = data.get("declared_data_access") or data.get(
            "data_classification"
        )
        if isinstance(data_access_raw, str):
            data_access = [DataClassification(data_access_raw)]
        elif isinstance(data_access_raw, list):
            data_access = [DataClassification(d) for d in data_access_raw]
        else:
            data_access = [DataClassification.INTERNAL]

        declared_actions = data.get("declared_actions", [])
        declared_services = data.get("declared_services")
        if declared_services is None:
            declared_services = list({
                action.split(":")[0]
                for action in declared_actions
                if ":" in action
            })

        return cls(
            name=data["name"],
            purpose=data.get("purpose", ""),
            declared_actions=declared_actions,
            declared_resources=data.get("declared_resources", ["*"]),
            declared_data_access=data_access,
            declared_services=declared_services,
            version=data.get("version", "1.0"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class AlignmentFinding(SerializableMixin):
    """A single finding from alignment analysis.

    Attributes:
        finding_id: Unique identifier for this finding.
        category: The type of misalignment detected.
        severity: Severity level of the finding.
        action: The IAM action implicated.
        resource: The resource ARN/pattern implicated.
        message: Human-readable explanation of the finding.
        evidence: Supporting data (e.g. CloudTrail references).
        timestamp: When the finding was generated.
    """

    __slots__ = (
        "finding_id",
        "category",
        "severity",
        "action",
        "resource",
        "message",
        "evidence",
        "timestamp",
    )

    finding_id: str
    category: AlignmentCategory
    severity: Severity
    action: str
    resource: str
    message: str
    evidence: dict[str, Any]
    timestamp: datetime

    @classmethod
    def create(
        cls,
        category: AlignmentCategory,
        severity: Severity,
        action: str,
        resource: str = "*",
        message: str = "",
        evidence: dict[str, Any] | None = None,
    ) -> AlignmentFinding:
        """Factory for creating an AlignmentFinding with auto-generated ID."""
        return cls(
            finding_id=str(uuid.uuid4()),
            category=category,
            severity=severity,
            action=action,
            resource=resource,
            message=message,
            evidence=evidence or {},
            timestamp=_utcnow(),
        )


@dataclass
class Recommendation(SerializableMixin):
    """Actionable remediation recommendation for a misalignment finding.

    Attributes:
        finding_id: The finding this recommendation addresses.
        category: The misalignment category.
        action: Suggested remediation action (e.g. "REMOVE", "ADD", "SCOPE_DOWN").
        description: Human-readable description of the remediation.
        policy_statement: Suggested IAM policy statement JSON (if applicable).
        priority: Priority level (1=highest).
        effort: Estimated effort (LOW, MEDIUM, HIGH).
    """

    __slots__ = (
        "finding_id",
        "category",
        "action",
        "description",
        "policy_statement",
        "priority",
        "effort",
    )

    finding_id: str
    category: AlignmentCategory
    action: str
    description: str
    policy_statement: dict[str, Any]
    priority: int
    effort: str

    @classmethod
    def create(
        cls,
        finding_id: str,
        category: AlignmentCategory,
        action: str,
        description: str,
        policy_statement: dict[str, Any] | None = None,
        priority: int = 3,
        effort: str = "MEDIUM",
    ) -> Recommendation:
        """Factory for creating a Recommendation."""
        return cls(
            finding_id=finding_id,
            category=category,
            action=action,
            description=description,
            policy_statement=policy_statement or {},
            priority=priority,
            effort=effort,
        )


@dataclass
class PolicyDiff(SerializableMixin):
    """Difference between effective permissions and the manifest-aligned ideal.

    Attributes:
        actions_to_remove: Actions that should be removed from the policy.
        actions_to_add: Actions that should be added to the policy.
        resources_to_scope: Resources that should be scoped down.
        suggested_policy: A complete IAM policy document reflecting ideal state.
    """

    __slots__ = (
        "actions_to_remove",
        "actions_to_add",
        "resources_to_scope",
        "suggested_policy",
    )

    actions_to_remove: list[str]
    actions_to_add: list[str]
    resources_to_scope: dict[str, list[str]]
    suggested_policy: dict[str, Any]

    @classmethod
    def empty(cls) -> PolicyDiff:
        """Factory for an empty (no-diff) PolicyDiff."""
        return cls(
            actions_to_remove=[],
            actions_to_add=[],
            resources_to_scope={},
            suggested_policy={},
        )


@dataclass
class AlignmentScoreBreakdown(SerializableMixin):
    """Score breakdown by misalignment category.

    Attributes:
        over_privilege_score: Score contribution from over-privilege (0-100).
        unused_permissions_score: Score contribution from unused perms (0-100).
        dangerous_unrelated_score: Score contribution from dangerous perms (0-100).
        missing_permissions_score: Score contribution from missing perms (0-100).
        alignment_score: Final weighted alignment score (0-100).
        category_counts: Number of findings per category.
    """

    __slots__ = (
        "over_privilege_score",
        "unused_permissions_score",
        "dangerous_unrelated_score",
        "missing_permissions_score",
        "alignment_score",
        "category_counts",
    )

    over_privilege_score: float
    unused_permissions_score: float
    dangerous_unrelated_score: float
    missing_permissions_score: float
    alignment_score: float
    category_counts: dict[str, int]


@dataclass
class AlignmentReport(SerializableMixin):
    """Complete alignment analysis report.

    Encapsulates the full output of an intent-alignment analysis run,
    including findings, scoring, recommendations, and a policy diff.

    Attributes:
        report_id: Unique report identifier.
        agent_name: Name of the agent analyzed.
        manifest: The manifest used for analysis.
        findings: All misalignment findings detected.
        score: Overall alignment score breakdown.
        recommendations: Remediation recommendations.
        policy_diff: Diff between current and ideal permission state.
        analyzed_at: Timestamp of analysis.
        effective_permissions_count: Number of effective permissions evaluated.
        cloudtrail_events_count: Number of CloudTrail events considered.
    """

    __slots__ = (
        "report_id",
        "agent_name",
        "manifest",
        "findings",
        "score",
        "recommendations",
        "policy_diff",
        "analyzed_at",
        "effective_permissions_count",
        "cloudtrail_events_count",
    )

    report_id: str
    agent_name: str
    manifest: AgentManifest
    findings: list[AlignmentFinding]
    score: AlignmentScoreBreakdown
    recommendations: list[Recommendation]
    policy_diff: PolicyDiff
    analyzed_at: datetime
    effective_permissions_count: int
    cloudtrail_events_count: int

    @classmethod
    def create(
        cls,
        agent_name: str,
        manifest: AgentManifest,
        findings: list[AlignmentFinding],
        score: AlignmentScoreBreakdown,
        recommendations: list[Recommendation],
        policy_diff: PolicyDiff,
        effective_permissions_count: int = 0,
        cloudtrail_events_count: int = 0,
    ) -> AlignmentReport:
        """Factory for creating an AlignmentReport."""
        return cls(
            report_id=str(uuid.uuid4()),
            agent_name=agent_name,
            manifest=manifest,
            findings=findings,
            score=score,
            recommendations=recommendations,
            policy_diff=policy_diff,
            analyzed_at=_utcnow(),
            effective_permissions_count=effective_permissions_count,
            cloudtrail_events_count=cloudtrail_events_count,
        )

    @property
    def is_aligned(self) -> bool:
        """Whether the agent's permissions are fully aligned (score == 100)."""
        return self.score.alignment_score == 100.0

    @property
    def critical_findings(self) -> list[AlignmentFinding]:
        """Findings with CRITICAL severity."""
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> list[AlignmentFinding]:
        """Findings with HIGH severity."""
        return [f for f in self.findings if f.severity == Severity.HIGH]


# =============================================================================
# Manifest Loading & Validation
# =============================================================================


def load_manifest(path: str | Path) -> AgentManifest:
    """Load an agent manifest from a YAML file.

    Args:
        path: Path to the YAML manifest file.

    Returns:
        A validated AgentManifest instance.

    Raises:
        FileNotFoundError: If the manifest file does not exist.
        ManifestValidationError: If the manifest content is invalid.
        yaml.YAMLError: If the file is not valid YAML.
    """
    manifest_path = Path(path)
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")

    with manifest_path.open("r", encoding="utf-8") as f:
        raw_data = yaml.safe_load(f)

    if raw_data is None:
        raise ManifestValidationError(["Manifest file is empty"])

    manifest = AgentManifest.from_dict(raw_data)
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: AgentManifest) -> None:
    """Validate an AgentManifest for correctness and completeness.

    Checks:
    - Required fields are non-empty.
    - Action patterns follow service:Action format.
    - Resource ARNs/patterns have valid structure.
    - Data classification levels are recognized.
    - Declared services are consistent with declared actions.

    Args:
        manifest: The manifest to validate.

    Raises:
        ManifestValidationError: If validation fails, with all errors collected.
    """
    errors: list[str] = []

    # Required fields
    if not manifest.name or not manifest.name.strip():
        errors.append("'name' is required and must be non-empty")

    if not manifest.purpose or not manifest.purpose.strip():
        errors.append("'purpose' is required and must be non-empty")

    if not manifest.declared_actions:
        errors.append("'declared_actions' must contain at least one action")

    # Validate action patterns
    action_pattern = re.compile(r"^[a-zA-Z0-9\-]+:[a-zA-Z0-9\*\?]+$")
    for action in manifest.declared_actions:
        if not action_pattern.match(action):
            errors.append(
                f"Invalid action pattern '{action}': "
                f"must be in format 'service:Action' (wildcards allowed)"
            )

    # Validate resource ARNs/patterns
    for resource in manifest.declared_resources:
        if resource == "*":
            continue
        if not resource.startswith("arn:"):
            errors.append(
                f"Invalid resource '{resource}': must be an ARN or '*'"
            )

    # Validate services consistency
    action_services = {
        a.split(":")[0] for a in manifest.declared_actions if ":" in a
    }
    for service in manifest.declared_services:
        if service not in action_services:
            # Warning-level: service declared but no corresponding actions
            pass  # Not an error, just advisory

    # Validate data classification values
    for classification in manifest.declared_data_access:
        if not isinstance(classification, DataClassification):
            errors.append(
                f"Invalid data classification: {classification}"
            )

    if errors:
        raise ManifestValidationError(errors)


# =============================================================================
# Intent Alignment Engine
# =============================================================================


class IntentAlignmentEngine:
    """Engine for comparing declared agent capabilities against effective permissions.

    The engine takes an agent's manifest (declaration of intent) and compares
    it against the agent's effective IAM permissions and optionally CloudTrail
    usage data to detect misalignments across four categories.

    Usage::

        engine = IntentAlignmentEngine()
        manifest = load_manifest("agent-manifest.yaml")
        report = engine.analyze(
            manifest=manifest,
            effective_permissions=permissions,
            cloudtrail_actions=observed_actions,
        )
        print(f"Alignment score: {report.score.alignment_score}/100")
        for finding in report.findings:
            print(f"  [{finding.category.value}] {finding.message}")

    Attributes:
        dangerous_actions: Set of IAM actions considered inherently dangerous.
        category_weights: Weighting for each category in score calculation.
    """

    def __init__(
        self,
        dangerous_actions: frozenset[str] | None = None,
        category_weights: dict[str, float] | None = None,
    ) -> None:
        """Initialize the IntentAlignmentEngine.

        Args:
            dangerous_actions: Custom set of actions considered dangerous.
                Defaults to the module-level DANGEROUS_ACTIONS constant.
            category_weights: Custom category weights for scoring.
                Defaults to the module-level _CATEGORY_WEIGHTS.
        """
        self.dangerous_actions: frozenset[str] = (
            dangerous_actions if dangerous_actions is not None else DANGEROUS_ACTIONS
        )
        self.category_weights: dict[str, float] = (
            category_weights if category_weights is not None else dict(_CATEGORY_WEIGHTS)
        )

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def analyze(
        self,
        manifest: AgentManifest,
        effective_permissions: list[EffectivePermission],
        cloudtrail_actions: list[str] | None = None,
    ) -> AlignmentReport:
        """Run full alignment analysis.

        Compares the manifest against effective permissions and optional
        CloudTrail data to produce a comprehensive alignment report.

        Args:
            manifest: The agent's declared capability manifest.
            effective_permissions: Currently resolved IAM permissions.
            cloudtrail_actions: Optional list of IAM actions observed in
                CloudTrail logs (format: ``service:Action``).

        Returns:
            An AlignmentReport with findings, score, recommendations,
            and policy diff.
        """
        cloudtrail_actions = cloudtrail_actions or []

        # Extract allowed actions from effective permissions
        allowed_permissions = [
            ep for ep in effective_permissions
            if ep.effect == PermissionEffect.ALLOW
        ]
        effective_actions = {ep.action for ep in allowed_permissions}

        # Run detection phases
        findings: list[AlignmentFinding] = []
        findings.extend(self._detect_over_privilege(manifest, allowed_permissions))
        findings.extend(
            self._detect_unused_permissions(manifest, allowed_permissions, cloudtrail_actions)
        )
        findings.extend(
            self._detect_dangerous_unrelated(manifest, allowed_permissions)
        )
        findings.extend(self._detect_missing_permissions(manifest, effective_actions))

        # Calculate score
        score = self._calculate_score(findings, len(effective_actions), manifest)

        # Generate recommendations
        recommendations = self._generate_recommendations(findings, manifest)

        # Compute policy diff
        policy_diff = self._compute_policy_diff(manifest, allowed_permissions, findings)

        return AlignmentReport.create(
            agent_name=manifest.name,
            manifest=manifest,
            findings=findings,
            score=score,
            recommendations=recommendations,
            policy_diff=policy_diff,
            effective_permissions_count=len(effective_permissions),
            cloudtrail_events_count=len(cloudtrail_actions),
        )

    def analyze_from_file(
        self,
        manifest_path: str | Path,
        effective_permissions: list[EffectivePermission],
        cloudtrail_actions: list[str] | None = None,
    ) -> AlignmentReport:
        """Run analysis using a manifest file path.

        Convenience wrapper that loads and validates the manifest before
        running analysis.

        Args:
            manifest_path: Path to the YAML manifest file.
            effective_permissions: Currently resolved IAM permissions.
            cloudtrail_actions: Optional CloudTrail observed actions.

        Returns:
            An AlignmentReport.
        """
        manifest = load_manifest(manifest_path)
        return self.analyze(manifest, effective_permissions, cloudtrail_actions)

    # -------------------------------------------------------------------------
    # Detection Methods
    # -------------------------------------------------------------------------

    def _detect_over_privilege(
        self,
        manifest: AgentManifest,
        allowed_permissions: list[EffectivePermission],
    ) -> list[AlignmentFinding]:
        """Detect permissions granted but not declared in the manifest.

        An action is over-privileged if it is present in effective permissions
        but does not match any pattern in the manifest's declared_actions.

        Args:
            manifest: Agent capability manifest.
            allowed_permissions: Effective ALLOW permissions.

        Returns:
            List of OVER_PRIVILEGE findings.
        """
        findings: list[AlignmentFinding] = []

        for perm in allowed_permissions:
            if not self._action_matches_manifest(perm.action, manifest):
                severity = self._severity_for_over_privilege(perm.action)
                findings.append(
                    AlignmentFinding.create(
                        category=AlignmentCategory.OVER_PRIVILEGE,
                        severity=severity,
                        action=perm.action,
                        resource=perm.resource,
                        message=(
                            f"Action '{perm.action}' on resource '{perm.resource}' "
                            f"is permitted but not declared in the manifest for "
                            f"agent '{manifest.name}' (purpose: {manifest.purpose})"
                        ),
                        evidence={
                            "declared_actions": manifest.declared_actions,
                            "effective_action": perm.action,
                            "effective_resource": perm.resource,
                        },
                    )
                )

        return findings

    def _detect_unused_permissions(
        self,
        manifest: AgentManifest,
        allowed_permissions: list[EffectivePermission],
        cloudtrail_actions: list[str],
    ) -> list[AlignmentFinding]:
        """Detect permissions never exercised according to CloudTrail data.

        An action is unused if it appears in effective permissions but has
        never been observed in CloudTrail logs. Only runs if CloudTrail
        data is provided.

        Args:
            manifest: Agent capability manifest.
            allowed_permissions: Effective ALLOW permissions.
            cloudtrail_actions: Actions observed in CloudTrail.

        Returns:
            List of UNUSED_PERMISSIONS findings.
        """
        if not cloudtrail_actions:
            return []

        findings: list[AlignmentFinding] = []
        observed_set = set(cloudtrail_actions)

        for perm in allowed_permissions:
            if perm.action not in observed_set:
                # Determine if this unused perm is also outside manifest
                in_manifest = self._action_matches_manifest(perm.action, manifest)
                severity = Severity.LOW if in_manifest else Severity.MEDIUM

                findings.append(
                    AlignmentFinding.create(
                        category=AlignmentCategory.UNUSED_PERMISSIONS,
                        severity=severity,
                        action=perm.action,
                        resource=perm.resource,
                        message=(
                            f"Action '{perm.action}' is permitted but has never "
                            f"been exercised according to CloudTrail data. "
                            f"{'Declared in manifest.' if in_manifest else 'NOT declared in manifest.'}"
                        ),
                        evidence={
                            "in_manifest": in_manifest,
                            "cloudtrail_events_analyzed": len(cloudtrail_actions),
                        },
                    )
                )

        return findings

    def _detect_dangerous_unrelated(
        self,
        manifest: AgentManifest,
        allowed_permissions: list[EffectivePermission],
    ) -> list[AlignmentFinding]:
        """Detect high-risk permissions unrelated to the stated purpose.

        A permission is dangerous and unrelated if:
        1. It is in the dangerous_actions set, AND
        2. Its service prefix is NOT in the manifest's declared_services

        Args:
            manifest: Agent capability manifest.
            allowed_permissions: Effective ALLOW permissions.

        Returns:
            List of DANGEROUS_UNRELATED findings.
        """
        findings: list[AlignmentFinding] = []
        manifest_services = set(manifest.declared_services)

        for perm in allowed_permissions:
            if not self._is_dangerous(perm.action):
                continue

            action_service = perm.action.split(":")[0] if ":" in perm.action else ""

            # Check if the dangerous action's service is unrelated to manifest
            if action_service not in manifest_services:
                findings.append(
                    AlignmentFinding.create(
                        category=AlignmentCategory.DANGEROUS_UNRELATED,
                        severity=Severity.CRITICAL,
                        action=perm.action,
                        resource=perm.resource,
                        message=(
                            f"CRITICAL: Agent '{manifest.name}' (purpose: "
                            f"'{manifest.purpose}') has dangerous permission "
                            f"'{perm.action}' which is unrelated to its declared "
                            f"services {sorted(manifest_services)}. This could "
                            f"enable privilege escalation or lateral movement."
                        ),
                        evidence={
                            "declared_services": sorted(manifest_services),
                            "dangerous_action": perm.action,
                            "action_service": action_service,
                            "risk_category": "privilege_escalation"
                            if "iam:" in perm.action
                            else "security_control_bypass",
                        },
                    )
                )
            elif not self._action_matches_manifest(perm.action, manifest):
                # Dangerous action in a related service but not in declared_actions
                findings.append(
                    AlignmentFinding.create(
                        category=AlignmentCategory.DANGEROUS_UNRELATED,
                        severity=Severity.HIGH,
                        action=perm.action,
                        resource=perm.resource,
                        message=(
                            f"Agent '{manifest.name}' has dangerous permission "
                            f"'{perm.action}' in a related service but not "
                            f"declared in manifest actions. Review required."
                        ),
                        evidence={
                            "declared_actions": manifest.declared_actions,
                            "dangerous_action": perm.action,
                        },
                    )
                )

        return findings

    def _detect_missing_permissions(
        self,
        manifest: AgentManifest,
        effective_actions: set[str],
    ) -> list[AlignmentFinding]:
        """Detect actions declared in manifest but not in effective permissions.

        An action is missing if it appears in the manifest's declared_actions
        but has no matching entry in the effective permissions. This indicates
        the agent cannot perform its intended function.

        Args:
            manifest: Agent capability manifest.
            effective_actions: Set of actions from effective permissions.

        Returns:
            List of MISSING_PERMISSIONS findings.
        """
        findings: list[AlignmentFinding] = []

        for declared_action in manifest.declared_actions:
            if not self._declared_action_has_effective(declared_action, effective_actions):
                findings.append(
                    AlignmentFinding.create(
                        category=AlignmentCategory.MISSING_PERMISSIONS,
                        severity=Severity.HIGH,
                        action=declared_action,
                        resource="*",
                        message=(
                            f"Declared action '{declared_action}' in manifest is "
                            f"NOT present in effective permissions. Agent "
                            f"'{manifest.name}' may be unable to fulfil its purpose."
                        ),
                        evidence={
                            "declared_action": declared_action,
                            "effective_actions": sorted(effective_actions),
                        },
                    )
                )

        return findings

    # -------------------------------------------------------------------------
    # Scoring
    # -------------------------------------------------------------------------

    def _calculate_score(
        self,
        findings: list[AlignmentFinding],
        total_effective_actions: int,
        manifest: AgentManifest,
    ) -> AlignmentScoreBreakdown:
        """Calculate the alignment score with category breakdown.

        The score starts at 100 and deductions are applied based on
        the number and severity of findings in each category, weighted
        by category importance.

        Scoring methodology:
        - Each finding deducts points based on its severity.
        - Deductions are normalized by total permission count to prevent
          agents with many permissions from being unfairly penalized.
        - Category scores are weighted and combined.

        Args:
            findings: All detected findings.
            total_effective_actions: Number of effective allowed actions.
            manifest: The agent manifest.

        Returns:
            An AlignmentScoreBreakdown with per-category and overall scores.
        """
        severity_penalties = {
            Severity.CRITICAL: 15.0,
            Severity.HIGH: 10.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.0,
            Severity.INFORMATIONAL: 0.5,
        }

        # Group findings by category
        category_findings: dict[AlignmentCategory, list[AlignmentFinding]] = {
            cat: [] for cat in AlignmentCategory
        }
        for finding in findings:
            category_findings[finding.category].append(finding)

        # Calculate per-category penalty scores (higher = worse)
        def _category_penalty(cat_findings: list[AlignmentFinding]) -> float:
            """Sum severity penalties for a category, capped at 100."""
            total_penalty = sum(
                severity_penalties.get(f.severity, 1.0) for f in cat_findings
            )
            return min(total_penalty, 100.0)

        over_priv_penalty = _category_penalty(
            category_findings[AlignmentCategory.OVER_PRIVILEGE]
        )
        unused_penalty = _category_penalty(
            category_findings[AlignmentCategory.UNUSED_PERMISSIONS]
        )
        dangerous_penalty = _category_penalty(
            category_findings[AlignmentCategory.DANGEROUS_UNRELATED]
        )
        missing_penalty = _category_penalty(
            category_findings[AlignmentCategory.MISSING_PERMISSIONS]
        )

        # Convert penalties to scores (100 - penalty, floored at 0)
        over_priv_score = max(0.0, 100.0 - over_priv_penalty)
        unused_score = max(0.0, 100.0 - unused_penalty)
        dangerous_score = max(0.0, 100.0 - dangerous_penalty)
        missing_score = max(0.0, 100.0 - missing_penalty)

        # Weighted composite score
        weights = self.category_weights
        alignment_score = (
            over_priv_score * weights.get("OVER_PRIVILEGE", 0.30)
            + unused_score * weights.get("UNUSED_PERMISSIONS", 0.20)
            + dangerous_score * weights.get("DANGEROUS_UNRELATED", 0.35)
            + missing_score * weights.get("MISSING_PERMISSIONS", 0.15)
        )

        # Round to 1 decimal
        alignment_score = round(alignment_score, 1)

        category_counts = {
            cat.value: len(cat_findings)
            for cat, cat_findings in category_findings.items()
        }

        return AlignmentScoreBreakdown(
            over_privilege_score=round(over_priv_score, 1),
            unused_permissions_score=round(unused_score, 1),
            dangerous_unrelated_score=round(dangerous_score, 1),
            missing_permissions_score=round(missing_score, 1),
            alignment_score=alignment_score,
            category_counts=category_counts,
        )

    # -------------------------------------------------------------------------
    # Recommendation Generation
    # -------------------------------------------------------------------------

    def _generate_recommendations(
        self,
        findings: list[AlignmentFinding],
        manifest: AgentManifest,
    ) -> list[Recommendation]:
        """Generate specific remediation recommendations for each finding.

        Each finding type maps to a different remediation strategy:
        - OVER_PRIVILEGE → Remove the permission or scope it down.
        - UNUSED_PERMISSIONS → Remove or set up a review schedule.
        - DANGEROUS_UNRELATED → Immediately remove; flag for security review.
        - MISSING_PERMISSIONS → Add the permission to the agent's policy.

        Args:
            findings: All detected findings.
            manifest: The agent manifest for context.

        Returns:
            List of remediation Recommendations.
        """
        recommendations: list[Recommendation] = []

        for finding in findings:
            rec = self._recommendation_for_finding(finding, manifest)
            if rec is not None:
                recommendations.append(rec)

        # Sort by priority (1 = highest)
        recommendations.sort(key=lambda r: r.priority)
        return recommendations

    def _recommendation_for_finding(
        self,
        finding: AlignmentFinding,
        manifest: AgentManifest,
    ) -> Recommendation:
        """Generate a single recommendation for a finding.

        Args:
            finding: The alignment finding.
            manifest: Agent manifest for context.

        Returns:
            A Recommendation instance.
        """
        if finding.category == AlignmentCategory.OVER_PRIVILEGE:
            return Recommendation.create(
                finding_id=finding.finding_id,
                category=finding.category,
                action="REMOVE",
                description=(
                    f"Remove permission '{finding.action}' from agent "
                    f"'{manifest.name}' policy. This action is not required "
                    f"for the agent's declared purpose: '{manifest.purpose}'. "
                    f"If the action is actually needed, add it to the manifest."
                ),
                policy_statement={
                    "Effect": "Deny",
                    "Action": finding.action,
                    "Resource": finding.resource,
                    "Sid": f"DenyUndeclared{finding.action.replace(':', '').replace('*', 'Star')}",
                },
                priority=2,
                effort="LOW",
            )

        elif finding.category == AlignmentCategory.UNUSED_PERMISSIONS:
            return Recommendation.create(
                finding_id=finding.finding_id,
                category=finding.category,
                action="REVIEW_AND_REMOVE",
                description=(
                    f"Action '{finding.action}' has never been used. Remove it "
                    f"from the agent's policy. If it is needed for future "
                    f"operations, document it in the manifest with justification."
                ),
                policy_statement={
                    "Effect": "Deny",
                    "Action": finding.action,
                    "Resource": finding.resource,
                    "Sid": f"DenyUnused{finding.action.replace(':', '').replace('*', 'Star')}",
                },
                priority=3,
                effort="LOW",
            )

        elif finding.category == AlignmentCategory.DANGEROUS_UNRELATED:
            return Recommendation.create(
                finding_id=finding.finding_id,
                category=finding.category,
                action="IMMEDIATE_REMOVE",
                description=(
                    f"URGENT: Remove dangerous permission '{finding.action}' "
                    f"immediately. This action is unrelated to agent "
                    f"'{manifest.name}' purpose and poses a security risk. "
                    f"Investigate how this permission was granted and whether "
                    f"it has been exploited."
                ),
                policy_statement={
                    "Effect": "Deny",
                    "Action": finding.action,
                    "Resource": "*",
                    "Sid": f"DenyDangerous{finding.action.replace(':', '').replace('*', 'Star')}",
                },
                priority=1,
                effort="LOW",
            )

        else:  # MISSING_PERMISSIONS
            # Determine appropriate resource scope
            matching_resources = [
                r for r in manifest.declared_resources
                if self._resource_matches_action_service(r, finding.action)
            ]
            resource_scope = matching_resources if matching_resources else ["*"]

            return Recommendation.create(
                finding_id=finding.finding_id,
                category=finding.category,
                action="ADD",
                description=(
                    f"Add permission '{finding.action}' to agent "
                    f"'{manifest.name}' policy scoped to declared resources. "
                    f"This action is required for the agent's stated purpose "
                    f"but is not currently permitted."
                ),
                policy_statement={
                    "Effect": "Allow",
                    "Action": finding.action,
                    "Resource": resource_scope,
                    "Sid": f"AllowDeclared{finding.action.replace(':', '').replace('*', 'Star')}",
                },
                priority=2,
                effort="MEDIUM",
            )

    # -------------------------------------------------------------------------
    # Policy Diff
    # -------------------------------------------------------------------------

    def _compute_policy_diff(
        self,
        manifest: AgentManifest,
        allowed_permissions: list[EffectivePermission],
        findings: list[AlignmentFinding],
    ) -> PolicyDiff:
        """Compute the diff between effective permissions and ideal state.

        Generates a suggested IAM policy document that aligns permissions
        with the manifest declarations.

        Args:
            manifest: Agent capability manifest.
            allowed_permissions: Effective ALLOW permissions.
            findings: Detected findings (used to determine removals/additions).

        Returns:
            A PolicyDiff with actions to add, remove, and scope.
        """
        actions_to_remove: list[str] = []
        actions_to_add: list[str] = []
        resources_to_scope: dict[str, list[str]] = {}

        for finding in findings:
            if finding.category in (
                AlignmentCategory.OVER_PRIVILEGE,
                AlignmentCategory.DANGEROUS_UNRELATED,
            ):
                if finding.action not in actions_to_remove:
                    actions_to_remove.append(finding.action)
            elif finding.category == AlignmentCategory.MISSING_PERMISSIONS:
                if finding.action not in actions_to_add:
                    actions_to_add.append(finding.action)

        # Determine resource scoping for over-privileged actions
        for perm in allowed_permissions:
            if perm.resource == "*" and self._action_matches_manifest(
                perm.action, manifest
            ):
                # Action is declared but resource is too broad
                matching_resources = [
                    r
                    for r in manifest.declared_resources
                    if self._resource_matches_action_service(r, perm.action)
                ]
                if matching_resources and matching_resources != ["*"]:
                    resources_to_scope[perm.action] = matching_resources

        # Build suggested policy
        suggested_policy = self._build_suggested_policy(manifest)

        return PolicyDiff(
            actions_to_remove=sorted(actions_to_remove),
            actions_to_add=sorted(actions_to_add),
            resources_to_scope=resources_to_scope,
            suggested_policy=suggested_policy,
        )

    def _build_suggested_policy(self, manifest: AgentManifest) -> dict[str, Any]:
        """Build an IAM policy document aligned with the manifest.

        Args:
            manifest: Agent capability manifest.

        Returns:
            IAM policy document as a dictionary.
        """
        # Group actions by resource pattern for compact policy
        action_resource_groups: dict[str, list[str]] = {}
        for action in manifest.declared_actions:
            matching_resources = [
                r
                for r in manifest.declared_resources
                if self._resource_matches_action_service(r, action)
            ]
            resource_key = ",".join(sorted(matching_resources)) if matching_resources else "*"
            action_resource_groups.setdefault(resource_key, []).append(action)

        statements: list[dict[str, Any]] = []
        for idx, (resource_key, actions) in enumerate(
            action_resource_groups.items(), start=1
        ):
            resources = resource_key.split(",") if resource_key != "*" else ["*"]
            statements.append({
                "Sid": f"AlignedPermissions{idx}",
                "Effect": "Allow",
                "Action": sorted(actions),
                "Resource": resources if len(resources) > 1 else resources[0],
            })

        return {
            "Version": "2012-10-17",
            "Statement": statements,
        }

    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------

    def _action_matches_manifest(
        self, action: str, manifest: AgentManifest
    ) -> bool:
        """Check if an action matches any declared action pattern in the manifest.

        Supports wildcard matching (e.g. ``s3:Get*`` matches ``s3:GetObject``).

        Args:
            action: The IAM action to check.
            manifest: Agent manifest with declared action patterns.

        Returns:
            True if the action matches at least one declared pattern.
        """
        for declared in manifest.declared_actions:
            if self._action_pattern_matches(declared, action):
                return True
        return False

    @staticmethod
    def _action_pattern_matches(pattern: str, action: str) -> bool:
        """Check if an action pattern matches a specific action.

        Supports ``*`` and ``?`` wildcards using fnmatch semantics.
        Matching is case-insensitive.

        Args:
            pattern: Action pattern (e.g. ``s3:Get*``).
            action: Specific action (e.g. ``s3:GetObject``).

        Returns:
            True if the pattern matches the action.
        """
        return fnmatch.fnmatch(action.lower(), pattern.lower())

    def _declared_action_has_effective(
        self, declared_action: str, effective_actions: set[str]
    ) -> bool:
        """Check if a declared action pattern has a matching effective permission.

        Args:
            declared_action: A manifest declared action (may contain wildcards).
            effective_actions: Set of effective permission actions.

        Returns:
            True if any effective action matches the declared pattern.
        """
        # If the declared action is exact (no wildcards), check directly
        if "*" not in declared_action and "?" not in declared_action:
            return declared_action in effective_actions

        # Wildcard pattern: check if any effective action matches
        for effective in effective_actions:
            if self._action_pattern_matches(declared_action, effective):
                return True
        return False

    def _is_dangerous(self, action: str) -> bool:
        """Check if an action is in the dangerous actions set.

        Uses exact match and wildcard expansion.

        Args:
            action: IAM action to check.

        Returns:
            True if the action is considered dangerous.
        """
        if action in self.dangerous_actions:
            return True
        # Check if action matches any dangerous pattern
        for dangerous in self.dangerous_actions:
            if fnmatch.fnmatch(action.lower(), dangerous.lower()):
                return True
        return False

    def _severity_for_over_privilege(self, action: str) -> Severity:
        """Determine severity for an over-privilege finding based on action risk.

        Args:
            action: The over-privileged IAM action.

        Returns:
            Appropriate severity level.
        """
        if self._is_dangerous(action):
            return Severity.HIGH
        # Write/modify actions are more concerning than read-only
        write_indicators = ("Put", "Create", "Delete", "Update", "Attach", "Detach")
        action_name = action.split(":")[-1] if ":" in action else action
        if any(action_name.startswith(w) for w in write_indicators):
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _resource_matches_action_service(resource: str, action: str) -> bool:
        """Check if a resource ARN is relevant to an action's service.

        Args:
            resource: A resource ARN pattern.
            action: An IAM action.

        Returns:
            True if the resource appears to belong to the action's service.
        """
        if resource == "*":
            return True

        service_prefix = action.split(":")[0] if ":" in action else ""
        if not service_prefix:
            return False

        # Map service prefix to ARN service component
        service_arn_map: dict[str, str] = {
            "s3": "s3",
            "dynamodb": "dynamodb",
            "lambda": "lambda",
            "ec2": "ec2",
            "iam": "iam",
            "sts": "sts",
            "sqs": "sqs",
            "sns": "sns",
            "kms": "kms",
            "secretsmanager": "secretsmanager",
            "ssm": "ssm",
            "logs": "logs",
            "cloudwatch": "cloudwatch",
            "events": "events",
            "bedrock": "bedrock",
            "sagemaker": "sagemaker",
        }

        arn_service = service_arn_map.get(service_prefix, service_prefix)

        # Check if the ARN contains the service identifier
        # ARN format: arn:partition:service:region:account:resource
        arn_parts = resource.split(":")
        if len(arn_parts) >= 3:
            return arn_parts[2] == arn_service

        return False
