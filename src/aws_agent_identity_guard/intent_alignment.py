"""
aws_agent_identity_guard/intent_alignment.py
---------------------------------------------------------------------------
AI Intent-to-Permission Alignment Module.

Analyzes the alignment between an agent's declared intent (capabilities) and
its actual effective permissions in AWS IAM. Detects over-privilege,
unused permissions, dangerous unrelated access, and missing required
permissions. Generates least-privilege IAM policies.

Security philosophy:
  - Agents should only have permissions directly required by their declared
    purpose and capabilities.
  - Any permission not traceable to a declared capability is suspect.
  - Dangerous permissions (IAM write, STS assume-role to admin, KMS decrypt
    on broad key sets) require explicit justification.
  - The alignment score quantifies how closely actual permissions match intent.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from aws_agent_identity_guard.models import (
    AgentIdentity,
    EffectiveEffect,
    EffectivePermission,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class FindingType(str, Enum):
    """Classification of an alignment finding."""

    OVER_PRIVILEGE = "OVER_PRIVILEGE"
    UNUSED = "UNUSED"
    DANGEROUS = "DANGEROUS"
    MISSING = "MISSING"


class Severity(str, Enum):
    """Severity classification for alignment findings."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass
class AlignmentFinding:
    """
    A single finding from the intent-to-permission alignment analysis.

    Attributes:
        finding_type: Category of the finding (over-privilege, unused, etc.).
        permission: The IAM permission (action:resource) related to this finding.
        reason: Human-readable explanation of why this is a finding.
        severity: How severe this finding is from a security standpoint.
        recommendation: Actionable recommendation to resolve the finding.
    """

    finding_type: FindingType
    permission: str
    reason: str
    severity: Severity
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "finding_type": self.finding_type.value,
            "permission": self.permission,
            "reason": self.reason,
            "severity": self.severity.value,
            "recommendation": self.recommendation,
        }


@dataclass
class AlignmentReport:
    """
    Complete report from analyzing intent-to-permission alignment.

    Attributes:
        agent_id: The agent that was analyzed.
        over_privileged: Permissions beyond what the agent's capabilities require.
        unused: Permissions that have not been exercised within the analysis window.
        dangerous_unrelated: Dangerous permissions with no capability justification.
        missing_required: Permissions the agent's capabilities require but lacks.
        alignment_score: Score from 0 (fully misaligned) to 100 (perfect alignment).
        recommended_policy: A least-privilege IAM policy JSON matching declared intent.
        analyzed_at: Timestamp of the analysis.
    """

    agent_id: str
    over_privileged: list[AlignmentFinding] = field(default_factory=list)
    unused: list[AlignmentFinding] = field(default_factory=list)
    dangerous_unrelated: list[AlignmentFinding] = field(default_factory=list)
    missing_required: list[AlignmentFinding] = field(default_factory=list)
    alignment_score: int = 100
    recommended_policy: dict[str, Any] = field(default_factory=dict)
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Validate alignment score bounds."""
        if not (0 <= self.alignment_score <= 100):
            raise ValueError(
                f"alignment_score must be between 0 and 100, got {self.alignment_score}"
            )

    @property
    def total_findings(self) -> int:
        """Total number of findings across all categories."""
        return (
            len(self.over_privileged)
            + len(self.unused)
            + len(self.dangerous_unrelated)
            + len(self.missing_required)
        )

    @property
    def has_critical(self) -> bool:
        """Check if any finding is CRITICAL severity."""
        all_findings = (
            self.over_privileged + self.unused + self.dangerous_unrelated + self.missing_required
        )
        return any(f.severity == Severity.CRITICAL for f in all_findings)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "agent_id": self.agent_id,
            "over_privileged": [f.to_dict() for f in self.over_privileged],
            "unused": [f.to_dict() for f in self.unused],
            "dangerous_unrelated": [f.to_dict() for f in self.dangerous_unrelated],
            "missing_required": [f.to_dict() for f in self.missing_required],
            "alignment_score": self.alignment_score,
            "recommended_policy": self.recommended_policy,
            "analyzed_at": self.analyzed_at.isoformat(),
            "total_findings": self.total_findings,
            "has_critical": self.has_critical,
        }


# ---------------------------------------------------------------------------
# Capability-to-Permission Mapping
# ---------------------------------------------------------------------------

CAPABILITY_PERMISSION_MAP: dict[str, list[dict[str, str]]] = {
    "read-s3-invoices": [
        {"action": "s3:GetObject", "resource": "arn:aws:s3:::*-invoices/*"},
        {"action": "s3:ListBucket", "resource": "arn:aws:s3:::*-invoices"},
    ],
    "read-s3": [
        {"action": "s3:GetObject", "resource": "arn:aws:s3:::*"},
        {"action": "s3:ListBucket", "resource": "arn:aws:s3:::*"},
        {"action": "s3:ListAllMyBuckets", "resource": "*"},
    ],
    "write-s3": [
        {"action": "s3:PutObject", "resource": "arn:aws:s3:::*"},
        {"action": "s3:DeleteObject", "resource": "arn:aws:s3:::*"},
    ],
    "read-dynamodb": [
        {"action": "dynamodb:GetItem", "resource": "arn:aws:dynamodb:*:*:table/*"},
        {"action": "dynamodb:Query", "resource": "arn:aws:dynamodb:*:*:table/*"},
        {"action": "dynamodb:Scan", "resource": "arn:aws:dynamodb:*:*:table/*"},
        {"action": "dynamodb:BatchGetItem", "resource": "arn:aws:dynamodb:*:*:table/*"},
    ],
    "write-dynamodb": [
        {"action": "dynamodb:PutItem", "resource": "arn:aws:dynamodb:*:*:table/*"},
        {"action": "dynamodb:UpdateItem", "resource": "arn:aws:dynamodb:*:*:table/*"},
        {"action": "dynamodb:DeleteItem", "resource": "arn:aws:dynamodb:*:*:table/*"},
        {"action": "dynamodb:BatchWriteItem", "resource": "arn:aws:dynamodb:*:*:table/*"},
    ],
    "invoke-lambda": [
        {"action": "lambda:InvokeFunction", "resource": "arn:aws:lambda:*:*:function:*"},
    ],
    "invoke-bedrock": [
        {"action": "bedrock:InvokeModel", "resource": "arn:aws:bedrock:*:*:*"},
        {"action": "bedrock:InvokeModelWithResponseStream", "resource": "arn:aws:bedrock:*:*:*"},
    ],
    "read-secrets": [
        {
            "action": "secretsmanager:GetSecretValue",
            "resource": "arn:aws:secretsmanager:*:*:secret:*",
        },
        {
            "action": "secretsmanager:DescribeSecret",
            "resource": "arn:aws:secretsmanager:*:*:secret:*",
        },
    ],
    "read-ssm-parameters": [
        {"action": "ssm:GetParameter", "resource": "arn:aws:ssm:*:*:parameter/*"},
        {"action": "ssm:GetParameters", "resource": "arn:aws:ssm:*:*:parameter/*"},
        {"action": "ssm:GetParametersByPath", "resource": "arn:aws:ssm:*:*:parameter/*"},
    ],
    "send-sqs": [
        {"action": "sqs:SendMessage", "resource": "arn:aws:sqs:*:*:*"},
        {"action": "sqs:SendMessageBatch", "resource": "arn:aws:sqs:*:*:*"},
    ],
    "receive-sqs": [
        {"action": "sqs:ReceiveMessage", "resource": "arn:aws:sqs:*:*:*"},
        {"action": "sqs:DeleteMessage", "resource": "arn:aws:sqs:*:*:*"},
        {"action": "sqs:ChangeMessageVisibility", "resource": "arn:aws:sqs:*:*:*"},
    ],
    "publish-sns": [
        {"action": "sns:Publish", "resource": "arn:aws:sns:*:*:*"},
    ],
    "read-cloudwatch-logs": [
        {"action": "logs:GetLogEvents", "resource": "arn:aws:logs:*:*:log-group:*"},
        {"action": "logs:FilterLogEvents", "resource": "arn:aws:logs:*:*:log-group:*"},
        {"action": "logs:DescribeLogGroups", "resource": "*"},
    ],
    "write-cloudwatch-logs": [
        {"action": "logs:CreateLogStream", "resource": "arn:aws:logs:*:*:log-group:*"},
        {"action": "logs:PutLogEvents", "resource": "arn:aws:logs:*:*:log-group:*"},
    ],
    "read-kinesis": [
        {"action": "kinesis:GetRecords", "resource": "arn:aws:kinesis:*:*:stream/*"},
        {"action": "kinesis:GetShardIterator", "resource": "arn:aws:kinesis:*:*:stream/*"},
        {"action": "kinesis:DescribeStream", "resource": "arn:aws:kinesis:*:*:stream/*"},
    ],
    "write-kinesis": [
        {"action": "kinesis:PutRecord", "resource": "arn:aws:kinesis:*:*:stream/*"},
        {"action": "kinesis:PutRecords", "resource": "arn:aws:kinesis:*:*:stream/*"},
    ],
    "execute-step-functions": [
        {"action": "states:StartExecution", "resource": "arn:aws:states:*:*:stateMachine:*"},
        {"action": "states:DescribeExecution", "resource": "arn:aws:states:*:*:execution:*:*"},
    ],
    "read-rds": [
        {"action": "rds-data:ExecuteStatement", "resource": "arn:aws:rds:*:*:cluster:*"},
        {"action": "rds-data:BatchExecuteStatement", "resource": "arn:aws:rds:*:*:cluster:*"},
    ],
    "kms-decrypt": [
        {"action": "kms:Decrypt", "resource": "arn:aws:kms:*:*:key/*"},
    ],
    "kms-encrypt": [
        {"action": "kms:Encrypt", "resource": "arn:aws:kms:*:*:key/*"},
        {"action": "kms:GenerateDataKey", "resource": "arn:aws:kms:*:*:key/*"},
    ],
}


# ---------------------------------------------------------------------------
# Dangerous Permissions Map
# ---------------------------------------------------------------------------

DANGEROUS_PERMISSIONS_MAP: dict[str, list[str]] = {
    "iam_write": [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:CreatePolicy",
        "iam:DeletePolicy",
        "iam:CreatePolicyVersion",
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:CreateAccessKey",
        "iam:UpdateAssumeRolePolicy",
        "iam:AddUserToGroup",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
    ],
    "sts_escalation": [
        "sts:AssumeRole",
        "sts:AssumeRoleWithSAML",
        "sts:AssumeRoleWithWebIdentity",
        "sts:GetFederationToken",
    ],
    "data_exfiltration": [
        "s3:GetObject",
        "s3:ListBucket",
        "dynamodb:Scan",
        "rds:CopyDBSnapshot",
        "rds:CopyDBClusterSnapshot",
        "redshift:CopyClusterSnapshot",
        "ec2:CreateSnapshot",
        "ec2:CopySnapshot",
        "ec2:ModifySnapshotAttribute",
    ],
    "infrastructure_destruction": [
        "ec2:TerminateInstances",
        "rds:DeleteDBInstance",
        "rds:DeleteDBCluster",
        "dynamodb:DeleteTable",
        "s3:DeleteBucket",
        "lambda:DeleteFunction",
        "cloudformation:DeleteStack",
        "ecs:DeleteCluster",
        "eks:DeleteCluster",
    ],
    "network_manipulation": [
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:CreateSecurityGroup",
        "ec2:ModifyVpcAttribute",
        "ec2:CreateVpcPeeringConnection",
        "ec2:AcceptVpcPeeringConnection",
        "ec2:CreateRoute",
        "ec2:ReplaceRoute",
    ],
    "encryption_key_management": [
        "kms:CreateKey",
        "kms:ScheduleKeyDeletion",
        "kms:DisableKey",
        "kms:PutKeyPolicy",
        "kms:CreateGrant",
        "kms:RetireGrant",
    ],
    "logging_tampering": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail",
        "logs:DeleteLogGroup",
        "logs:DeleteLogStream",
        "config:StopConfigurationRecorder",
        "config:DeleteConfigurationRecorder",
    ],
    "secrets_and_credentials": [
        "secretsmanager:DeleteSecret",
        "secretsmanager:PutSecretValue",
        "secretsmanager:UpdateSecret",
        "ssm:DeleteParameter",
        "ssm:PutParameter",
    ],
    "organization_level": [
        "organizations:LeaveOrganization",
        "organizations:RemoveAccountFromOrganization",
        "organizations:CreateAccount",
        "organizations:InviteAccountToOrganization",
    ],
}

# Flatten for quick lookups
_ALL_DANGEROUS_PERMISSIONS: set[str] = set()
for _category_perms in DANGEROUS_PERMISSIONS_MAP.values():
    _ALL_DANGEROUS_PERMISSIONS.update(_category_perms)


def _get_danger_category(action: str) -> str | None:
    """Return the danger category for a given IAM action, or None if not dangerous."""
    for category, actions in DANGEROUS_PERMISSIONS_MAP.items():
        if action in actions:
            return category
    return None


def _severity_for_danger_category(category: str) -> Severity:
    """Map danger category to finding severity."""
    critical_categories = {
        "iam_write",
        "sts_escalation",
        "logging_tampering",
        "organization_level",
    }
    high_categories = {
        "infrastructure_destruction",
        "encryption_key_management",
        "secrets_and_credentials",
    }
    if category in critical_categories:
        return Severity.CRITICAL
    if category in high_categories:
        return Severity.HIGH
    return Severity.MEDIUM


# ---------------------------------------------------------------------------
# Intent Alignment Analyzer
# ---------------------------------------------------------------------------


class IntentAlignmentAnalyzer:
    """
    Analyzes alignment between an agent's declared intent and effective permissions.

    Compares what an agent is declared to do (its capabilities) against what it
    is actually permitted to do (its IAM effective permissions). Identifies
    misalignment in both directions: over-privilege and missing permissions.

    Usage:
        analyzer = IntentAlignmentAnalyzer()
        report = analyzer.analyze(agent, effective_permissions)
        if report.has_critical:
            alert_security_team(report)
    """

    def __init__(
        self,
        capability_map: dict[str, list[dict[str, str]]] | None = None,
        dangerous_permissions: dict[str, list[str]] | None = None,
    ) -> None:
        """
        Initialize the analyzer with optional custom mappings.

        Args:
            capability_map: Custom capability-to-permission mapping. If None,
                uses the built-in CAPABILITY_PERMISSION_MAP.
            dangerous_permissions: Custom dangerous permissions map. If None,
                uses the built-in DANGEROUS_PERMISSIONS_MAP.
        """
        self._capability_map = capability_map or CAPABILITY_PERMISSION_MAP
        self._dangerous_map = dangerous_permissions or DANGEROUS_PERMISSIONS_MAP
        self._all_dangerous: set[str] = set()
        for perms in self._dangerous_map.values():
            self._all_dangerous.update(perms)
        logger.info(
            "IntentAlignmentAnalyzer initialized with %d capability mappings, "
            "%d dangerous permission categories",
            len(self._capability_map),
            len(self._dangerous_map),
        )

    def analyze(
        self,
        agent: AgentIdentity,
        effective_permissions: list[EffectivePermission],
    ) -> AlignmentReport:
        """
        Perform full intent-to-permission alignment analysis.

        Evaluates the agent's declared capabilities against its effective
        permissions to detect over-privilege, unused access, dangerous
        unrelated permissions, and missing required permissions.

        Args:
            agent: The agent identity to analyze.
            effective_permissions: The agent's resolved effective permissions.

        Returns:
            AlignmentReport with all findings and an alignment score.

        Raises:
            ValueError: If agent or permissions are invalid.
        """
        if not agent:
            raise ValueError("agent cannot be None")
        if not agent.agent_id:
            raise ValueError("agent must have a valid agent_id")

        logger.info(
            "Starting alignment analysis for agent '%s' (%s) with %d effective permissions",
            agent.name,
            agent.agent_id,
            len(effective_permissions),
        )

        # Filter to only ALLOWED permissions for analysis
        allowed_permissions = [
            p for p in effective_permissions if p.effective_effect == EffectiveEffect.ALLOWED
        ]

        declared_capabilities = agent.declared_capabilities

        # Run all detection methods
        over_privileged = self._detect_over_privilege(declared_capabilities, allowed_permissions)
        unused = self._detect_unused_permissions(agent, allowed_permissions, usage_data=None)
        dangerous = self._detect_dangerous_unrelated(agent, allowed_permissions)
        missing = self._detect_missing_permissions(declared_capabilities, allowed_permissions)

        # Calculate alignment score
        alignment_score = self._calculate_alignment_score(
            allowed_permissions, over_privileged, unused, dangerous, missing
        )

        # Generate recommended minimal policy
        recommended_policy = self.generate_minimal_policy(agent)

        report = AlignmentReport(
            agent_id=agent.agent_id,
            over_privileged=over_privileged,
            unused=unused,
            dangerous_unrelated=dangerous,
            missing_required=missing,
            alignment_score=alignment_score,
            recommended_policy=recommended_policy,
        )

        logger.info(
            "Alignment analysis complete for agent '%s': score=%d, "
            "findings=%d (over=%d, unused=%d, dangerous=%d, missing=%d)",
            agent.name,
            alignment_score,
            report.total_findings,
            len(over_privileged),
            len(unused),
            len(dangerous),
            len(missing),
        )

        return report

    def _detect_over_privilege(
        self,
        declared_capabilities: list[str],
        effective_permissions: list[EffectivePermission],
    ) -> list[AlignmentFinding]:
        """
        Detect permissions that exceed what declared capabilities require.

        Identifies permissions the agent holds that cannot be traced back to
        any declared capability. These represent unnecessary privilege that
        should be removed.

        Args:
            declared_capabilities: List of high-level capability identifiers.
            effective_permissions: The agent's effective ALLOWED permissions.

        Returns:
            List of over-privilege findings.
        """
        findings: list[AlignmentFinding] = []

        # Build the set of actions justified by declared capabilities
        justified_actions: set[str] = set()
        for capability in declared_capabilities:
            if capability in self._capability_map:
                for perm_spec in self._capability_map[capability]:
                    justified_actions.add(perm_spec["action"])

        # Check each effective permission
        for perm in effective_permissions:
            action = perm.action

            # Skip wildcard actions in this check (handled by dangerous detection)
            if action == "*":
                continue

            # Check if the action matches any justified action
            if not self._action_is_justified(action, justified_actions):
                severity = Severity.MEDIUM
                # Elevate severity for write/delete actions
                if any(
                    keyword in action.lower()
                    for keyword in ["put", "create", "delete", "update", "modify"]
                ):
                    severity = Severity.HIGH

                findings.append(
                    AlignmentFinding(
                        finding_type=FindingType.OVER_PRIVILEGE,
                        permission=f"{action} on {perm.resource}",
                        reason=(
                            f"Permission '{action}' is not required by any declared "
                            f"capability. No capability mapping justifies this access."
                        ),
                        severity=severity,
                        recommendation=(
                            f"Remove '{action}' from the agent's policy or add a "
                            f"declared capability that justifies this permission."
                        ),
                    )
                )

        logger.debug(
            "Over-privilege detection found %d findings from %d permissions",
            len(findings),
            len(effective_permissions),
        )
        return findings

    def _detect_unused_permissions(
        self,
        agent: AgentIdentity,
        effective_permissions: list[EffectivePermission],
        usage_data: dict[str, datetime] | None,
    ) -> list[AlignmentFinding]:
        """
        Detect permissions that have not been exercised.

        Uses usage data (from CloudTrail or similar) to identify permissions
        that the agent holds but has never or recently used. Without usage data,
        falls back to heuristic analysis based on capability declarations.

        Args:
            agent: The agent identity being analyzed.
            effective_permissions: The agent's effective ALLOWED permissions.
            usage_data: Optional dict mapping action strings to last-used timestamps.
                If None, heuristic detection is used instead.

        Returns:
            List of unused permission findings.
        """
        findings: list[AlignmentFinding] = []

        if usage_data is not None:
            # Exact detection using usage data
            now = datetime.now(timezone.utc)
            for perm in effective_permissions:
                last_used = usage_data.get(perm.action)
                if last_used is None:
                    findings.append(
                        AlignmentFinding(
                            finding_type=FindingType.UNUSED,
                            permission=f"{perm.action} on {perm.resource}",
                            reason=(
                                f"Permission '{perm.action}' has never been used by "
                                f"agent '{agent.name}' according to usage records."
                            ),
                            severity=Severity.MEDIUM,
                            recommendation=(
                                f"Remove '{perm.action}' if the agent does not need it. "
                                f"If it is needed for disaster recovery, document the "
                                f"justification."
                            ),
                        )
                    )
                else:
                    days_unused = (now - last_used).days
                    if days_unused > 90:
                        findings.append(
                            AlignmentFinding(
                                finding_type=FindingType.UNUSED,
                                permission=f"{perm.action} on {perm.resource}",
                                reason=(
                                    f"Permission '{perm.action}' has not been used in "
                                    f"{days_unused} days (last used: "
                                    f"{last_used.isoformat()})."
                                ),
                                severity=Severity.LOW,
                                recommendation=(
                                    f"Review whether '{perm.action}' is still needed. "
                                    f"Consider removing after confirming with the agent owner."
                                ),
                            )
                        )
        else:
            # Heuristic: permissions not mapped to any capability
            basic_actions = {
                "sts:GetCallerIdentity",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:CreateLogGroup",
            }
            declared_actions: set[str] = set()
            for capability in agent.declared_capabilities:
                if capability in self._capability_map:
                    for perm_spec in self._capability_map[capability]:
                        declared_actions.add(perm_spec["action"])

            for perm in effective_permissions:
                if (
                    perm.action not in declared_actions
                    and perm.action not in basic_actions
                    and perm.action != "*"
                ):
                    findings.append(
                        AlignmentFinding(
                            finding_type=FindingType.UNUSED,
                            permission=f"{perm.action} on {perm.resource}",
                            reason=(
                                f"Permission '{perm.action}' is not mapped to any "
                                f"declared capability and may be unused. No usage data "
                                f"available for definitive determination."
                            ),
                            severity=Severity.LOW,
                            recommendation=(
                                f"Enable CloudTrail analysis to confirm whether "
                                f"'{perm.action}' is actively used. Remove if unused."
                            ),
                        )
                    )

        logger.debug("Unused permission detection found %d findings", len(findings))
        return findings

    def _detect_dangerous_unrelated(
        self,
        agent: AgentIdentity,
        effective_permissions: list[EffectivePermission],
    ) -> list[AlignmentFinding]:
        """
        Detect dangerous permissions that have no relation to agent capabilities.

        Flags permissions from the dangerous permissions map that cannot be
        justified by the agent's declared purpose or capabilities.

        Args:
            agent: The agent identity being analyzed.
            effective_permissions: The agent's effective ALLOWED permissions.

        Returns:
            List of dangerous unrelated permission findings.
        """
        findings: list[AlignmentFinding] = []

        # Build justified actions from capabilities
        justified_actions: set[str] = set()
        for capability in agent.declared_capabilities:
            if capability in self._capability_map:
                for perm_spec in self._capability_map[capability]:
                    justified_actions.add(perm_spec["action"])

        for perm in effective_permissions:
            action = perm.action

            # Handle wildcard actions (extremely dangerous)
            if action == "*" or action.endswith(":*"):
                service = action.split(":")[0] if ":" in action else "ALL"
                findings.append(
                    AlignmentFinding(
                        finding_type=FindingType.DANGEROUS,
                        permission=f"{action} on {perm.resource}",
                        reason=(
                            f"Wildcard permission '{action}' grants unrestricted "
                            f"access to service '{service}'. This violates least-privilege "
                            f"and is extremely dangerous for an AI agent."
                        ),
                        severity=Severity.CRITICAL,
                        recommendation=(
                            f"Replace wildcard '{action}' with specific actions required "
                            f"by the agent's declared capabilities. No AI agent should "
                            f"have wildcard service access."
                        ),
                    )
                )
                continue

            # Check against dangerous permissions
            danger_category = _get_danger_category(action)
            if danger_category and action not in justified_actions:
                severity = _severity_for_danger_category(danger_category)
                findings.append(
                    AlignmentFinding(
                        finding_type=FindingType.DANGEROUS,
                        permission=f"{action} on {perm.resource}",
                        reason=(
                            f"Permission '{action}' is categorized as dangerous "
                            f"(category: {danger_category}) and is not justified by "
                            f"any declared capability of agent '{agent.name}'. "
                            f"Purpose: '{agent.purpose}'."
                        ),
                        severity=severity,
                        recommendation=(
                            f"Remove '{action}' immediately unless there is documented "
                            f"justification. If required, add an explicit capability "
                            f"declaration and security review approval."
                        ),
                    )
                )

        logger.debug("Dangerous unrelated detection found %d findings", len(findings))
        return findings

    def _detect_missing_permissions(
        self,
        declared_capabilities: list[str],
        effective_permissions: list[EffectivePermission],
    ) -> list[AlignmentFinding]:
        """
        Detect permissions that declared capabilities require but are missing.

        Identifies gaps where the agent's capabilities imply it needs certain
        permissions, but those permissions are not present in the effective set.

        Args:
            declared_capabilities: List of high-level capability identifiers.
            effective_permissions: The agent's effective ALLOWED permissions.

        Returns:
            List of missing permission findings.
        """
        findings: list[AlignmentFinding] = []

        # Build the set of actions the agent actually has
        actual_actions: set[str] = {p.action for p in effective_permissions}

        # Check each declared capability
        for capability in declared_capabilities:
            if capability not in self._capability_map:
                logger.warning(
                    "Capability '%s' has no mapping in CAPABILITY_PERMISSION_MAP. "
                    "Cannot verify required permissions.",
                    capability,
                )
                continue

            required_permissions = self._capability_map[capability]
            for perm_spec in required_permissions:
                required_action = perm_spec["action"]
                if not self._has_permission(required_action, actual_actions):
                    findings.append(
                        AlignmentFinding(
                            finding_type=FindingType.MISSING,
                            permission=f"{required_action} on {perm_spec['resource']}",
                            reason=(
                                f"Capability '{capability}' requires permission "
                                f"'{required_action}' but it is not present in the "
                                f"agent's effective permissions."
                            ),
                            severity=Severity.HIGH,
                            recommendation=(
                                f"Add '{required_action}' to the agent's IAM policy "
                                f"scoped to resource '{perm_spec['resource']}' to "
                                f"fulfill the '{capability}' capability."
                            ),
                        )
                    )

        logger.debug("Missing permission detection found %d findings", len(findings))
        return findings

    def generate_minimal_policy(self, agent: AgentIdentity) -> dict[str, Any]:
        """
        Generate a least-privilege IAM policy matching the agent's declared intent.

        Creates an IAM policy document containing only the permissions required
        by the agent's declared capabilities, scoped to the narrowest resources.

        Args:
            agent: The agent identity to generate a policy for.

        Returns:
            IAM policy document as a dictionary (JSON-serializable).
        """
        statements: list[dict[str, Any]] = []

        # Group permissions by service for cleaner policy structure
        service_actions: dict[str, list[dict[str, str]]] = {}

        for capability in agent.declared_capabilities:
            if capability not in self._capability_map:
                logger.warning(
                    "Cannot map capability '%s' to IAM actions for policy generation",
                    capability,
                )
                continue

            for perm_spec in self._capability_map[capability]:
                action = perm_spec["action"]
                resource = perm_spec["resource"]
                service = action.split(":")[0] if ":" in action else "unknown"

                if service not in service_actions:
                    service_actions[service] = []
                service_actions[service].append({"action": action, "resource": resource})

        # Build statements grouped by service
        for service, perms in sorted(service_actions.items()):
            resource_to_actions: dict[str, list[str]] = {}
            for perm in perms:
                resource = perm["resource"]
                if resource not in resource_to_actions:
                    resource_to_actions[resource] = []
                if perm["action"] not in resource_to_actions[resource]:
                    resource_to_actions[resource].append(perm["action"])

            for resource, actions in resource_to_actions.items():
                sid = f"Agent{agent.agent_id[:8].replace('-', '')}_{service}"
                statements.append(
                    {
                        "Sid": sid,
                        "Effect": "Allow",
                        "Action": sorted(set(actions)),
                        "Resource": resource,
                    }
                )

        # Always include basic operational permissions
        statements.append(
            {
                "Sid": "BasicOperational",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "sts:GetCallerIdentity",
                ],
                "Resource": "*",
            }
        )

        # Add deny statement for dangerous permissions as a guardrail
        statements.append(
            {
                "Sid": "DenyDangerousActions",
                "Effect": "Deny",
                "Action": sorted(self._all_dangerous),
                "Resource": "*",
            }
        )

        policy = {
            "Version": "2012-10-17",
            "Statement": statements,
        }

        logger.info(
            "Generated minimal policy for agent '%s' with %d statements",
            agent.name,
            len(statements),
        )
        return policy

    # -----------------------------------------------------------------------
    # Private Helper Methods
    # -----------------------------------------------------------------------

    def _action_is_justified(self, action: str, justified_actions: set[str]) -> bool:
        """Check if an action is covered by the justified actions set."""
        if action in justified_actions:
            return True

        # Check for service-level wildcards in justified set
        service = action.split(":")[0] if ":" in action else ""
        if f"{service}:*" in justified_actions:
            return True

        return "*" in justified_actions

    def _has_permission(self, required_action: str, actual_actions: set[str]) -> bool:
        """Check if the required action is available in actual actions."""
        if required_action in actual_actions:
            return True

        if "*" in actual_actions:
            return True

        service = required_action.split(":")[0] if ":" in required_action else ""
        return f"{service}:*" in actual_actions

    def _calculate_alignment_score(
        self,
        effective_permissions: list[EffectivePermission],
        over_privileged: list[AlignmentFinding],
        unused: list[AlignmentFinding],
        dangerous: list[AlignmentFinding],
        missing: list[AlignmentFinding],
    ) -> int:
        """
        Calculate an alignment score from 0 to 100.

        The score starts at 100 and is reduced by findings weighted by severity.

        Args:
            effective_permissions: Total effective permissions.
            over_privileged: Over-privilege findings.
            unused: Unused permission findings.
            dangerous: Dangerous unrelated findings.
            missing: Missing permission findings.

        Returns:
            Integer score from 0 to 100.
        """
        if not effective_permissions:
            if missing:
                return max(0, 100 - len(missing) * 15)
            return 100

        score = 100.0

        severity_weights = {
            Severity.LOW: 2,
            Severity.MEDIUM: 5,
            Severity.HIGH: 10,
            Severity.CRITICAL: 20,
        }

        all_findings = over_privileged + unused + dangerous + missing
        for finding in all_findings:
            weight = severity_weights.get(finding.severity, 5)
            score -= weight

        # Dangerous findings get extra penalty
        score -= len(dangerous) * 5

        return max(0, min(100, int(score)))
