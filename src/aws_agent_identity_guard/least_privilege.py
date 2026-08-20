"""AWS Agent Identity Guard - Least-Privilege Recommendation Engine.

Production-grade engine for analyzing agent permissions and generating
actionable, policy-level least-privilege recommendations. This module goes
beyond flagging wildcards  -  it produces concrete replacement policies,
scoped resource ARNs, and unified diffs showing exactly what changes to make.

Key capabilities:
- Wildcard action -> specific action replacement with common usage patterns
- Resource '*' -> scoped ARN recommendations based on agent manifest/context
- Missing condition key detection and injection
- Cross-account restriction recommendations
- Full IAM policy document generation with unified diff output

Usage:
    from aws_agent_identity_guard.least_privilege import LeastPrivilegeEngine

    engine = LeastPrivilegeEngine()
    report = engine.analyze(agent)
    print(report.summary)
    print(report.policy_diff.unified_diff_text)
"""

from __future__ import annotations

import copy
import difflib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, unique
from typing import Any, Optional

from .models import (
    Agent,
    Environment,
    Finding,
    FindingCategory,
    Permission,
    PermissionEffect,
    PermissionSource,
    Severity,
    SerializableMixin,
)


# =============================================================================
# Enumerations
# =============================================================================


@unique
class EffortLevel(str, Enum):
    """Estimated implementation effort for a recommendation."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@unique
class ScopingStrategy(str, Enum):
    """Strategies for narrowing permissions to least privilege."""

    WILDCARD_TO_SPECIFIC_ACTIONS = "WILDCARD_TO_SPECIFIC_ACTIONS"
    RESOURCE_STAR_TO_SPECIFIC_ARNS = "RESOURCE_STAR_TO_SPECIFIC_ARNS"
    ADD_CONDITION_KEYS = "ADD_CONDITION_KEYS"
    RESTRICT_CROSS_ACCOUNT = "RESTRICT_CROSS_ACCOUNT"
    SPLIT_COMBINED_STATEMENT = "SPLIT_COMBINED_STATEMENT"
    REMOVE_UNUSED_ACTIONS = "REMOVE_UNUSED_ACTIONS"


# =============================================================================
# Common Replacement Maps
# =============================================================================

# Maps wildcard service permissions to commonly-needed specific actions.
# These represent safe defaults for agent workloads; real deployments should
# refine further using CloudTrail access advisor data.
WILDCARD_ACTION_REPLACEMENTS: dict[str, list[str]] = {
    "s3:*": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket",
    ],
    "iam:*": [
        "iam:GetRole",
        "iam:GetPolicy",
        "iam:ListRoles",
        "iam:ListPolicies",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
    ],
    "lambda:*": [
        "lambda:InvokeFunction",
        "lambda:GetFunction",
        "lambda:ListFunctions",
    ],
    "dynamodb:*": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
    ],
    "secretsmanager:*": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
    ],
    "sqs:*": [
        "sqs:SendMessage",
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
    ],
    "sns:*": [
        "sns:Publish",
        "sns:Subscribe",
        "sns:GetTopicAttributes",
    ],
    "logs:*": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
    ],
    "ec2:*": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
    ],
    "kms:*": [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "kms:DescribeKey",
    ],
    "sts:*": [
        "sts:AssumeRole",
        "sts:GetCallerIdentity",
    ],
    "bedrock:*": [
        "bedrock:InvokeModel",
        "bedrock:ListFoundationModels",
        "bedrock:GetFoundationModel",
    ],
}

# Default condition keys recommended per service for tighter scoping.
RECOMMENDED_CONDITIONS: dict[str, dict[str, Any]] = {
    "s3": {
        "StringEquals": {
            "aws:RequestedRegion": "${aws:Region}",
        },
        "Bool": {
            "aws:SecureTransport": "true",
        },
    },
    "kms": {
        "StringEquals": {
            "kms:ViaService": "s3.${aws:Region}.amazonaws.com",
        },
    },
    "sts": {
        "StringEquals": {
            "sts:ExternalId": "${ExternalId}",
        },
    },
    "secretsmanager": {
        "StringEquals": {
            "aws:ResourceTag/Environment": "${Environment}",
        },
    },
}

# Risk reduction weights for different scoping strategies.
STRATEGY_RISK_REDUCTION: dict[ScopingStrategy, float] = {
    ScopingStrategy.WILDCARD_TO_SPECIFIC_ACTIONS: 0.35,
    ScopingStrategy.RESOURCE_STAR_TO_SPECIFIC_ARNS: 0.30,
    ScopingStrategy.ADD_CONDITION_KEYS: 0.15,
    ScopingStrategy.RESTRICT_CROSS_ACCOUNT: 0.20,
    ScopingStrategy.SPLIT_COMBINED_STATEMENT: 0.10,
    ScopingStrategy.REMOVE_UNUSED_ACTIONS: 0.25,
}


# =============================================================================
# Helper Functions
# =============================================================================


def _utcnow() -> datetime:
    """Return current UTC time with timezone info."""
    return datetime.now(timezone.utc)


def _generate_id() -> str:
    """Generate a unique identifier."""
    return str(uuid.uuid4())


def _extract_service_prefix(action: str) -> str:
    """Extract the AWS service prefix from an action string.

    Args:
        action: IAM action like 's3:GetObject' or 's3:*'.

    Returns:
        Service prefix (e.g., 's3').
    """
    if ":" in action:
        return action.split(":")[0].lower()
    return action.lower()


def _is_wildcard_action(action: str) -> bool:
    """Check if an action contains a wildcard.

    Args:
        action: IAM action string.

    Returns:
        True if the action is '*' or ends with ':*'.
    """
    return action == "*" or action.endswith(":*")


def _is_wildcard_resource(resource: str) -> bool:
    """Check if a resource is a wildcard (unrestricted).

    Args:
        resource: IAM resource ARN or pattern.

    Returns:
        True if the resource grants unrestricted access.
    """
    return resource == "*"


def _format_policy_json(policy: dict[str, Any]) -> str:
    """Format a policy document as pretty-printed JSON.

    Args:
        policy: IAM policy document dict.

    Returns:
        Formatted JSON string with 2-space indentation.
    """
    return json.dumps(policy, indent=2, sort_keys=False, default=str)


def _generate_unified_diff(before: str, after: str, context_lines: int = 3) -> str:
    """Generate a unified diff between two text blocks.

    Args:
        before: Original text content.
        after: Modified text content.
        context_lines: Number of context lines around changes.

    Returns:
        Unified diff string suitable for display.
    """
    before_lines = before.splitlines(keepends=True)
    after_lines = after.splitlines(keepends=True)

    diff = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile="current_policy.json",
        tofile="recommended_policy.json",
        lineterm="",
        n=context_lines,
    )
    return "".join(diff)


def _infer_resource_arn_from_agent(
    agent: Agent, service: str, action: str
) -> str:
    """Infer a scoped resource ARN from agent context.

    Uses the agent's tags, purpose, environment, and existing policy
    patterns to construct a reasonable scoped ARN.

    Args:
        agent: The Agent to derive context from.
        service: AWS service name (e.g., 's3').
        action: The specific action being scoped.

    Returns:
        A scoped resource ARN string.
    """
    account_id = _extract_account_from_role_arn(agent.iam_role_arn)
    region = _extract_region_from_tags(agent.tags)
    agent_name = agent.name.lower().replace(" ", "-")
    env = agent.environment.value

    # Service-specific ARN patterns
    arn_templates: dict[str, str] = {
        "s3": f"arn:aws:s3:::{agent_name}-{env}/*",
        "dynamodb": f"arn:aws:dynamodb:{region}:{account_id}:table/{agent_name}-*",
        "lambda": f"arn:aws:lambda:{region}:{account_id}:function:{agent_name}-*",
        "secretsmanager": (
            f"arn:aws:secretsmanager:{region}:{account_id}:"
            f"secret:{env}/{agent_name}/*"
        ),
        "sqs": f"arn:aws:sqs:{region}:{account_id}:{agent_name}-*",
        "sns": f"arn:aws:sns:{region}:{account_id}:{agent_name}-*",
        "kms": f"arn:aws:kms:{region}:{account_id}:key/*",
        "logs": (
            f"arn:aws:logs:{region}:{account_id}:"
            f"log-group:/aws/{agent_name}/*"
        ),
        "iam": f"arn:aws:iam::{account_id}:role/{agent_name}-*",
        "sts": f"arn:aws:iam::{account_id}:role/{agent_name}-*",
        "bedrock": f"arn:aws:bedrock:{region}:{account_id}:*",
    }

    return arn_templates.get(
        service,
        f"arn:aws:{service}:{region}:{account_id}:*",
    )


def _extract_account_from_role_arn(role_arn: str) -> str:
    """Extract the AWS account ID from a role ARN.

    Args:
        role_arn: IAM role ARN string.

    Returns:
        12-digit account ID or placeholder.
    """
    # ARN format: arn:aws:iam::123456789012:role/name
    parts = role_arn.split(":")
    if len(parts) >= 5 and parts[4]:
        return parts[4]
    return "123456789012"


def _extract_region_from_tags(tags: dict[str, str]) -> str:
    """Extract region from agent tags or return default.

    Args:
        tags: Agent tag dictionary.

    Returns:
        AWS region string.
    """
    return tags.get("region", tags.get("aws:region", "us-east-1"))


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class CurrentPermission(SerializableMixin):
    """Represents the current (overly-broad) permission to be replaced.

    Attributes:
        action: The IAM action pattern (may contain wildcards).
        resource: The IAM resource ARN pattern (may be '*').
        effect: Whether this is ALLOW or DENY.
        conditions: Any existing condition keys on the statement.
    """

    action: str
    resource: str
    effect: str = "Allow"
    conditions: dict[str, Any] = field(default_factory=dict)


@dataclass
class RecommendedPermission(SerializableMixin):
    """Represents the recommended scoped permission.

    Attributes:
        actions: List of specific IAM actions to replace the wildcard.
        resource: Scoped resource ARN.
        effect: Permission effect (typically 'Allow').
        conditions: Recommended condition keys for additional scoping.
    """

    actions: list[str]
    resource: str
    effect: str = "Allow"
    conditions: dict[str, Any] = field(default_factory=dict)


@dataclass
class Recommendation(SerializableMixin):
    """A single least-privilege recommendation with actionable detail.

    Each recommendation provides the current overly-broad permission,
    the recommended scoped replacement, rationale, effort estimate,
    and the actual IAM policy statement JSON ready to deploy.

    Attributes:
        recommendation_id: Unique identifier for this recommendation.
        finding_reference: ID of the finding that triggered this recommendation.
        current_permission: The overly-broad permission being replaced.
        recommended_permission: The scoped replacement permission.
        rationale: Human-readable explanation of why this change is needed.
        risk_reduction: Estimated reduction in risk score (0.0-1.0).
        effort: Implementation effort level (LOW/MEDIUM/HIGH).
        policy_statement: The actual IAM JSON statement to use as replacement.
        strategy: The scoping strategy applied.
        priority: Priority rank (lower = more important).
    """

    recommendation_id: str
    finding_reference: str
    current_permission: CurrentPermission
    recommended_permission: RecommendedPermission
    rationale: str
    risk_reduction: float
    effort: EffortLevel
    policy_statement: dict[str, Any]
    strategy: ScopingStrategy = ScopingStrategy.WILDCARD_TO_SPECIFIC_ACTIONS
    priority: int = 0

    def __post_init__(self) -> None:
        """Validate risk_reduction range."""
        if not (0.0 <= self.risk_reduction <= 1.0):
            raise ValueError(
                f"risk_reduction must be between 0.0 and 1.0, "
                f"got {self.risk_reduction}"
            )


@dataclass
class PolicyDiff(SerializableMixin):
    """Diff between current and recommended IAM policy documents.

    Provides both structured change sets and human-readable unified diff
    output for review workflows.

    Attributes:
        statements_to_remove: Policy statements that should be deleted.
        statements_to_add: New policy statements to add.
        statements_to_modify: Statements with changes (before/after pairs).
        unified_diff_text: Human-readable unified diff string.
        before_policy: Complete original policy document.
        after_policy: Complete recommended policy document.
        change_count: Total number of statement-level changes.
    """

    statements_to_remove: list[dict[str, Any]]
    statements_to_add: list[dict[str, Any]]
    statements_to_modify: list[dict[str, Any]]
    unified_diff_text: str
    before_policy: dict[str, Any]
    after_policy: dict[str, Any]
    change_count: int = 0

    def __post_init__(self) -> None:
        """Compute change_count if not set."""
        if self.change_count == 0:
            self.change_count = (
                len(self.statements_to_remove)
                + len(self.statements_to_add)
                + len(self.statements_to_modify)
            )

    @property
    def has_changes(self) -> bool:
        """Whether any policy changes are recommended."""
        return self.change_count > 0


@dataclass
class LeastPrivilegeReport(SerializableMixin):
    """Complete least-privilege analysis report for an agent.

    Contains the full analysis results including risk scoring,
    ranked recommendations, policy diffs, and executive summary.

    Attributes:
        agent_id: The agent that was analyzed.
        current_risk_score: Risk score under current permissions.
        projected_risk_score: Estimated risk score after applying all recommendations.
        recommendations: Actionable recommendations ranked by risk_reduction.
        policy_diff: Unified diff between current and recommended policies.
        summary: Executive summary of the analysis findings.
        analyzed_at: Timestamp of analysis.
        strategies_applied: Which scoping strategies were used.
        total_permissions_before: Count of permission grants before.
        total_permissions_after: Estimated count after applying recommendations.
    """

    agent_id: str
    current_risk_score: float
    projected_risk_score: float
    recommendations: list[Recommendation]
    policy_diff: PolicyDiff
    summary: str
    analyzed_at: datetime = field(default_factory=_utcnow)
    strategies_applied: list[ScopingStrategy] = field(default_factory=list)
    total_permissions_before: int = 0
    total_permissions_after: int = 0

    def __post_init__(self) -> None:
        """Sort recommendations by risk_reduction descending."""
        self.recommendations.sort(key=lambda r: r.risk_reduction, reverse=True)

    @property
    def risk_reduction_percentage(self) -> float:
        """Percentage reduction in risk score if all recommendations applied."""
        if self.current_risk_score == 0.0:
            return 0.0
        reduction = self.current_risk_score - self.projected_risk_score
        return (reduction / self.current_risk_score) * 100.0

    @property
    def high_priority_count(self) -> int:
        """Number of recommendations with risk_reduction > 0.25."""
        return sum(1 for r in self.recommendations if r.risk_reduction > 0.25)


# =============================================================================
# Least-Privilege Engine
# =============================================================================


class LeastPrivilegeEngine:
    """Engine for analyzing agent permissions and generating least-privilege recommendations.

    The engine examines an agent's IAM policies, identifies overly-broad permissions,
    and produces concrete, deployable replacement policies with full unified diffs.

    This is NOT a simple wildcard detector. It generates:
    - Specific action lists to replace wildcards (e.g., 's3:*' -> 's3:GetObject, s3:PutObject')
    - Scoped resource ARNs derived from agent context
    - Condition keys for additional access restrictions
    - Complete IAM policy statement JSON ready for deployment
    - Unified diffs for human review and approval workflows

    Example:
        >>> engine = LeastPrivilegeEngine()
        >>> report = engine.analyze(agent)
        >>> for rec in report.recommendations:
        ...     print(f"{rec.rationale}")
        ...     print(json.dumps(rec.policy_statement, indent=2))
        >>> print(report.policy_diff.unified_diff_text)
    """

    def __init__(
        self,
        custom_replacements: dict[str, list[str]] | None = None,
        custom_conditions: dict[str, dict[str, Any]] | None = None,
        cloudtrail_actions: dict[str, list[str]] | None = None,
    ) -> None:
        """Initialize the LeastPrivilegeEngine.

        Args:
            custom_replacements: Additional or override action replacement maps.
                Keys are wildcard patterns (e.g., 'glue:*'), values are
                lists of specific actions.
            custom_conditions: Additional or override condition key recommendations.
                Keys are service prefixes, values are IAM condition blocks.
            cloudtrail_actions: Observed actions from CloudTrail per agent.
                Keys are agent_ids, values are lists of actions actually used.
        """
        self._replacements = {**WILDCARD_ACTION_REPLACEMENTS}
        if custom_replacements:
            self._replacements.update(custom_replacements)

        self._conditions = {**RECOMMENDED_CONDITIONS}
        if custom_conditions:
            self._conditions.update(custom_conditions)

        self._cloudtrail_actions: dict[str, list[str]] = cloudtrail_actions or {}

    def analyze(self, agent: Agent) -> LeastPrivilegeReport:
        """Perform a complete least-privilege analysis of an agent's permissions.

        Examines all identity policies attached to the agent, identifies
        overly-broad permissions, and generates ranked recommendations
        with concrete replacement policies.

        Args:
            agent: The Agent to analyze.

        Returns:
            LeastPrivilegeReport with ranked recommendations, policy diff,
            and executive summary.
        """
        recommendations: list[Recommendation] = []
        strategies_applied: set[ScopingStrategy] = set()
        total_permissions_before = 0

        # Analyze each identity policy
        for policy_doc in agent.identity_policies:
            statements = policy_doc.get("Statement", [])
            for statement in statements:
                if statement.get("Effect") != "Allow":
                    continue

                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                resources = statement.get("Resource", [])
                if isinstance(resources, str):
                    resources = [resources]

                conditions = statement.get("Condition", {})
                total_permissions_before += len(actions) * len(resources)

                # Analyze each action-resource combination
                for action in actions:
                    for resource in resources:
                        recs = self._analyze_permission(
                            agent=agent,
                            action=action,
                            resource=resource,
                            conditions=conditions,
                        )
                        for rec in recs:
                            recommendations.append(rec)
                            strategies_applied.add(rec.strategy)

        # Compute risk scores
        current_risk = self._compute_risk_score(agent, recommendations)
        projected_risk = self._compute_projected_risk(current_risk, recommendations)

        # Generate scoped policy and diff
        recommended_policy = self.generate_scoped_policy(agent)
        current_policy = self._build_current_policy(agent)
        policy_diff = self.generate_policy_diff(current_policy, recommended_policy)

        # Count effective permissions after
        total_permissions_after = self._count_permissions(recommended_policy)

        # Build summary
        summary = self._build_summary(
            agent=agent,
            recommendations=recommendations,
            current_risk=current_risk,
            projected_risk=projected_risk,
            strategies_applied=strategies_applied,
        )

        return LeastPrivilegeReport(
            agent_id=agent.agent_id,
            current_risk_score=current_risk,
            projected_risk_score=projected_risk,
            recommendations=recommendations,
            policy_diff=policy_diff,
            summary=summary,
            analyzed_at=_utcnow(),
            strategies_applied=list(strategies_applied),
            total_permissions_before=total_permissions_before,
            total_permissions_after=total_permissions_after,
        )

    def recommend(self, finding: Finding) -> list[Recommendation]:
        """Generate recommendations from a security finding.

        Converts a Finding (e.g., from the scanner) into actionable
        least-privilege recommendations with concrete policy replacements.

        Args:
            finding: A security finding to generate recommendations for.

        Returns:
            List of Recommendation objects with specific remediation steps.
        """
        recommendations: list[Recommendation] = []

        if finding.category == FindingCategory.EXCESSIVE_PERMISSIONS:
            recommendations.extend(
                self._recommend_for_excessive_permissions(finding)
            )
        elif finding.category == FindingCategory.PRIVILEGE_ESCALATION:
            recommendations.extend(
                self._recommend_for_privilege_escalation(finding)
            )
        elif finding.category == FindingCategory.DATA_EXPOSURE:
            recommendations.extend(
                self._recommend_for_data_exposure(finding)
            )
        elif finding.category == FindingCategory.LATERAL_MOVEMENT:
            recommendations.extend(
                self._recommend_for_lateral_movement(finding)
            )
        elif finding.category in (
            FindingCategory.POLICY_VIOLATION,
            FindingCategory.COMPLIANCE,
            FindingCategory.CONFIGURATION,
        ):
            recommendations.extend(
                self._recommend_for_policy_violation(finding)
            )
        else:
            # Generic recommendation for other finding categories
            recommendations.extend(
                self._recommend_generic(finding)
            )

        return recommendations

    def generate_policy_diff(
        self,
        current_policy: dict[str, Any],
        recommended_policy: dict[str, Any],
    ) -> PolicyDiff:
        """Generate a detailed diff between current and recommended policies.

        Produces both structured change sets (statements to add/remove/modify)
        and a human-readable unified diff for review workflows.

        Args:
            current_policy: The current IAM policy document.
            recommended_policy: The recommended least-privilege policy document.

        Returns:
            PolicyDiff with structured changes and unified diff text.
        """
        current_statements = current_policy.get("Statement", [])
        recommended_statements = recommended_policy.get("Statement", [])

        statements_to_remove: list[dict[str, Any]] = []
        statements_to_add: list[dict[str, Any]] = []
        statements_to_modify: list[dict[str, Any]] = []

        # Index statements by a signature for comparison
        current_sigs = {
            self._statement_signature(s): s for s in current_statements
        }
        recommended_sigs = {
            self._statement_signature(s): s for s in recommended_statements
        }

        # Find removed statements
        for sig, stmt in current_sigs.items():
            if sig not in recommended_sigs:
                # Check if it was modified (same Sid but different content)
                current_sid = stmt.get("Sid", "")
                modified = False
                if current_sid:
                    for rec_stmt in recommended_statements:
                        if rec_stmt.get("Sid") == current_sid:
                            statements_to_modify.append({
                                "before": stmt,
                                "after": rec_stmt,
                                "sid": current_sid,
                            })
                            modified = True
                            break
                if not modified:
                    statements_to_remove.append(stmt)

        # Find added statements
        for sig, stmt in recommended_sigs.items():
            if sig not in current_sigs:
                # Skip if already captured as a modification
                stmt_sid = stmt.get("Sid", "")
                is_modification = any(
                    m.get("sid") == stmt_sid and stmt_sid
                    for m in statements_to_modify
                )
                if not is_modification:
                    statements_to_add.append(stmt)

        # Generate unified diff text
        before_text = _format_policy_json(current_policy)
        after_text = _format_policy_json(recommended_policy)
        unified_diff_text = _generate_unified_diff(before_text, after_text)

        return PolicyDiff(
            statements_to_remove=statements_to_remove,
            statements_to_add=statements_to_add,
            statements_to_modify=statements_to_modify,
            unified_diff_text=unified_diff_text,
            before_policy=current_policy,
            after_policy=recommended_policy,
        )

    def generate_scoped_policy(self, agent: Agent) -> dict[str, Any]:
        """Generate a complete least-privilege IAM policy document for an agent.

        Examines the agent's current policies and produces a replacement policy
        with all wildcards resolved to specific actions and resources.

        Args:
            agent: The Agent to generate a scoped policy for.

        Returns:
            Complete IAM policy document dict ready for deployment.
        """
        scoped_statements: list[dict[str, Any]] = []
        statement_counter = 0

        for policy_doc in agent.identity_policies:
            statements = policy_doc.get("Statement", [])
            for statement in statements:
                effect = statement.get("Effect", "Allow")

                # Pass through Deny statements unchanged
                if effect == "Deny":
                    scoped_statements.append(copy.deepcopy(statement))
                    continue

                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                resources = statement.get("Resource", [])
                if isinstance(resources, str):
                    resources = [resources]

                conditions = statement.get("Condition", {})
                sid = statement.get("Sid", "")

                # Process each action and scope it
                scoped_actions: list[str] = []
                scoped_resources: list[str] = []
                scoped_conditions: dict[str, Any] = copy.deepcopy(conditions)

                for action in actions:
                    if _is_wildcard_action(action):
                        # Replace wildcard with specific actions
                        replacements = self._get_replacement_actions(
                            action, agent
                        )
                        scoped_actions.extend(replacements)
                    else:
                        scoped_actions.append(action)

                for resource in resources:
                    if _is_wildcard_resource(resource):
                        # Infer scoped resources per service
                        services = set(
                            _extract_service_prefix(a) for a in scoped_actions
                        )
                        for service in services:
                            scoped_resource = _infer_resource_arn_from_agent(
                                agent, service, scoped_actions[0]
                            )
                            if scoped_resource not in scoped_resources:
                                scoped_resources.append(scoped_resource)
                    else:
                        scoped_resources.append(resource)

                # Add recommended conditions if none exist
                if not scoped_conditions:
                    services = set(
                        _extract_service_prefix(a) for a in scoped_actions
                    )
                    for service in services:
                        if service in self._conditions:
                            scoped_conditions.update(self._conditions[service])

                # Deduplicate actions
                scoped_actions = sorted(set(scoped_actions))

                # Build the scoped statement
                statement_counter += 1
                scoped_stmt: dict[str, Any] = {
                    "Sid": sid or f"LeastPrivilege{statement_counter:03d}",
                    "Effect": "Allow",
                    "Action": scoped_actions if len(scoped_actions) > 1 else scoped_actions[0],
                    "Resource": (
                        scoped_resources
                        if len(scoped_resources) > 1
                        else scoped_resources[0]
                        if scoped_resources
                        else "*"
                    ),
                }

                if scoped_conditions:
                    scoped_stmt["Condition"] = scoped_conditions

                scoped_statements.append(scoped_stmt)

        return {
            "Version": "2012-10-17",
            "Statement": scoped_statements,
        }

    # =========================================================================
    # Private Analysis Methods
    # =========================================================================

    def _analyze_permission(
        self,
        agent: Agent,
        action: str,
        resource: str,
        conditions: dict[str, Any],
    ) -> list[Recommendation]:
        """Analyze a single permission and generate recommendations.

        Args:
            agent: Agent being analyzed.
            action: IAM action (may be wildcard).
            resource: IAM resource ARN (may be '*').
            conditions: Existing condition keys.

        Returns:
            List of recommendations for this permission.
        """
        recommendations: list[Recommendation] = []

        # Strategy 1: Wildcard action -> specific actions
        if _is_wildcard_action(action):
            rec = self._recommend_wildcard_to_specific(
                agent=agent,
                action=action,
                resource=resource,
                conditions=conditions,
            )
            if rec:
                recommendations.append(rec)

        # Strategy 2: Wildcard resource -> specific ARNs
        if _is_wildcard_resource(resource) and not _is_wildcard_action(action):
            rec = self._recommend_resource_scoping(
                agent=agent,
                action=action,
                resource=resource,
                conditions=conditions,
            )
            if rec:
                recommendations.append(rec)

        # Strategy 3: Missing conditions -> add condition keys
        if not conditions:
            service = _extract_service_prefix(action)
            if service in self._conditions:
                rec = self._recommend_add_conditions(
                    agent=agent,
                    action=action,
                    resource=resource,
                    service=service,
                )
                if rec:
                    recommendations.append(rec)

        # Strategy 4: Cross-account detection
        if self._is_cross_account_access(agent, resource):
            rec = self._recommend_restrict_cross_account(
                agent=agent,
                action=action,
                resource=resource,
            )
            if rec:
                recommendations.append(rec)

        return recommendations

    def _recommend_wildcard_to_specific(
        self,
        agent: Agent,
        action: str,
        resource: str,
        conditions: dict[str, Any],
    ) -> Optional[Recommendation]:
        """Generate recommendation to replace wildcard action with specific actions.

        Args:
            agent: Agent being analyzed.
            action: Wildcard action (e.g., 's3:*').
            resource: Resource ARN.
            conditions: Existing conditions.

        Returns:
            Recommendation or None if no replacement available.
        """
        replacement_actions = self._get_replacement_actions(action, agent)
        if not replacement_actions:
            return None

        service = _extract_service_prefix(action)
        scoped_resource = resource
        if _is_wildcard_resource(resource):
            scoped_resource = _infer_resource_arn_from_agent(
                agent, service, replacement_actions[0]
            )

        # Build the replacement policy statement
        policy_statement: dict[str, Any] = {
            "Effect": "Allow",
            "Action": replacement_actions,
            "Resource": scoped_resource,
        }

        # Add conditions
        recommended_conditions = copy.deepcopy(conditions)
        if service in self._conditions and not conditions:
            recommended_conditions = self._conditions[service]

        if recommended_conditions:
            policy_statement["Condition"] = recommended_conditions

        # Build human-readable recommendation
        actions_str = ", ".join(replacement_actions[:3])
        if len(replacement_actions) > 3:
            actions_str += f" (+{len(replacement_actions) - 3} more)"

        rationale = (
            f"Replace {action} with {actions_str} on {scoped_resource}. "
            f"Wildcard actions grant {self._count_actions_in_service(service)} "
            f"permissions when only {len(replacement_actions)} are needed. "
            f"This reduces the blast radius from full {service} access to "
            f"only the operations the agent requires."
        )

        risk_reduction = STRATEGY_RISK_REDUCTION[
            ScopingStrategy.WILDCARD_TO_SPECIFIC_ACTIONS
        ]
        # Higher reduction for production environments
        if agent.is_production:
            risk_reduction = min(1.0, risk_reduction * 1.5)

        return Recommendation(
            recommendation_id=_generate_id(),
            finding_reference=f"wildcard-action-{service}",
            current_permission=CurrentPermission(
                action=action,
                resource=resource,
                effect="Allow",
                conditions=conditions,
            ),
            recommended_permission=RecommendedPermission(
                actions=replacement_actions,
                resource=scoped_resource,
                effect="Allow",
                conditions=recommended_conditions,
            ),
            rationale=rationale,
            risk_reduction=risk_reduction,
            effort=EffortLevel.LOW if len(replacement_actions) <= 5 else EffortLevel.MEDIUM,
            policy_statement=policy_statement,
            strategy=ScopingStrategy.WILDCARD_TO_SPECIFIC_ACTIONS,
            priority=1,
        )

    def _recommend_resource_scoping(
        self,
        agent: Agent,
        action: str,
        resource: str,
        conditions: dict[str, Any],
    ) -> Optional[Recommendation]:
        """Generate recommendation to replace wildcard resource with scoped ARN.

        Args:
            agent: Agent being analyzed.
            action: Specific IAM action.
            resource: Wildcard resource ('*').
            conditions: Existing conditions.

        Returns:
            Recommendation or None.
        """
        service = _extract_service_prefix(action)
        scoped_resource = _infer_resource_arn_from_agent(agent, service, action)

        policy_statement: dict[str, Any] = {
            "Effect": "Allow",
            "Action": action,
            "Resource": scoped_resource,
        }

        if conditions:
            policy_statement["Condition"] = conditions

        rationale = (
            f"Scope resource from '*' (all resources) to '{scoped_resource}'. "
            f"The action '{action}' should only operate on resources "
            f"belonging to agent '{agent.name}' in the '{agent.environment.value}' "
            f"environment. Unrestricted resource access allows the agent to "
            f"affect any resource in the account."
        )

        risk_reduction = STRATEGY_RISK_REDUCTION[
            ScopingStrategy.RESOURCE_STAR_TO_SPECIFIC_ARNS
        ]

        return Recommendation(
            recommendation_id=_generate_id(),
            finding_reference=f"wildcard-resource-{service}-{action.split(':')[-1]}",
            current_permission=CurrentPermission(
                action=action,
                resource=resource,
                effect="Allow",
                conditions=conditions,
            ),
            recommended_permission=RecommendedPermission(
                actions=[action],
                resource=scoped_resource,
                effect="Allow",
                conditions=conditions,
            ),
            rationale=rationale,
            risk_reduction=risk_reduction,
            effort=EffortLevel.MEDIUM,
            policy_statement=policy_statement,
            strategy=ScopingStrategy.RESOURCE_STAR_TO_SPECIFIC_ARNS,
            priority=2,
        )

    def _recommend_add_conditions(
        self,
        agent: Agent,
        action: str,
        resource: str,
        service: str,
    ) -> Optional[Recommendation]:
        """Generate recommendation to add condition keys for additional scoping.

        Args:
            agent: Agent being analyzed.
            action: IAM action.
            resource: IAM resource.
            service: AWS service prefix.

        Returns:
            Recommendation or None.
        """
        recommended_conditions = self._conditions.get(service, {})
        if not recommended_conditions:
            return None

        # Substitute placeholders with agent context
        resolved_conditions = self._resolve_condition_placeholders(
            recommended_conditions, agent
        )

        policy_statement: dict[str, Any] = {
            "Effect": "Allow",
            "Action": action,
            "Resource": resource,
            "Condition": resolved_conditions,
        }

        condition_desc = ", ".join(
            f"{op}: {list(keys.keys())}"
            for op, keys in resolved_conditions.items()
        )

        rationale = (
            f"Add condition keys to '{action}' on '{resource}': {condition_desc}. "
            f"Conditions provide defense-in-depth by restricting when permissions "
            f"can be exercised, even if the action and resource are correct. "
            f"For example, requiring secure transport prevents credential theft "
            f"via network interception."
        )

        return Recommendation(
            recommendation_id=_generate_id(),
            finding_reference=f"missing-conditions-{service}",
            current_permission=CurrentPermission(
                action=action,
                resource=resource,
                effect="Allow",
                conditions={},
            ),
            recommended_permission=RecommendedPermission(
                actions=[action],
                resource=resource,
                effect="Allow",
                conditions=resolved_conditions,
            ),
            rationale=rationale,
            risk_reduction=STRATEGY_RISK_REDUCTION[ScopingStrategy.ADD_CONDITION_KEYS],
            effort=EffortLevel.LOW,
            policy_statement=policy_statement,
            strategy=ScopingStrategy.ADD_CONDITION_KEYS,
            priority=3,
        )

    def _recommend_restrict_cross_account(
        self,
        agent: Agent,
        action: str,
        resource: str,
    ) -> Optional[Recommendation]:
        """Generate recommendation to restrict cross-account access.

        Args:
            agent: Agent being analyzed.
            action: IAM action.
            resource: Resource that may be in another account.

        Returns:
            Recommendation or None.
        """
        own_account = _extract_account_from_role_arn(agent.iam_role_arn)

        conditions: dict[str, Any] = {
            "StringEquals": {
                "aws:ResourceAccount": own_account,
            },
        }

        policy_statement: dict[str, Any] = {
            "Effect": "Allow",
            "Action": action,
            "Resource": resource,
            "Condition": conditions,
        }

        rationale = (
            f"Restrict '{action}' to resources in account '{own_account}'. "
            f"Cross-account access without explicit account restrictions "
            f"could allow the agent to access resources in other AWS accounts, "
            f"enabling lateral movement across account boundaries."
        )

        return Recommendation(
            recommendation_id=_generate_id(),
            finding_reference=f"cross-account-{_extract_service_prefix(action)}",
            current_permission=CurrentPermission(
                action=action,
                resource=resource,
                effect="Allow",
                conditions={},
            ),
            recommended_permission=RecommendedPermission(
                actions=[action],
                resource=resource,
                effect="Allow",
                conditions=conditions,
            ),
            rationale=rationale,
            risk_reduction=STRATEGY_RISK_REDUCTION[
                ScopingStrategy.RESTRICT_CROSS_ACCOUNT
            ],
            effort=EffortLevel.LOW,
            policy_statement=policy_statement,
            strategy=ScopingStrategy.RESTRICT_CROSS_ACCOUNT,
            priority=2,
        )

    # =========================================================================
    # Finding-Based Recommendation Methods
    # =========================================================================

    def _recommend_for_excessive_permissions(
        self, finding: Finding
    ) -> list[Recommendation]:
        """Generate recommendations for excessive permission findings.

        Args:
            finding: An EXCESSIVE_PERMISSIONS finding.

        Returns:
            List of recommendations.
        """
        recommendations: list[Recommendation] = []

        for resource_arn in finding.affected_resources:
            # Try to extract the service and action from the finding message
            service = self._extract_service_from_resource(resource_arn)
            wildcard_action = f"{service}:*" if service else "*"

            if wildcard_action in self._replacements:
                replacement_actions = self._replacements[wildcard_action]
                policy_statement: dict[str, Any] = {
                    "Effect": "Allow",
                    "Action": replacement_actions,
                    "Resource": resource_arn if resource_arn != "*" else f"arn:aws:{service}:*:*:*",
                }

                actions_str = ", ".join(replacement_actions[:3])
                rationale = (
                    f"Replace broad {service} permissions with specific actions: "
                    f"{actions_str}. Finding: {finding.message}"
                )

                recommendations.append(
                    Recommendation(
                        recommendation_id=_generate_id(),
                        finding_reference=finding.rule_id,
                        current_permission=CurrentPermission(
                            action=wildcard_action,
                            resource=resource_arn,
                        ),
                        recommended_permission=RecommendedPermission(
                            actions=replacement_actions,
                            resource=resource_arn,
                        ),
                        rationale=rationale,
                        risk_reduction=min(0.5, finding.risk_score * 0.6),
                        effort=EffortLevel.MEDIUM,
                        policy_statement=policy_statement,
                        strategy=ScopingStrategy.WILDCARD_TO_SPECIFIC_ACTIONS,
                        priority=1,
                    )
                )

        return recommendations

    def _recommend_for_privilege_escalation(
        self, finding: Finding
    ) -> list[Recommendation]:
        """Generate recommendations for privilege escalation findings.

        Args:
            finding: A PRIVILEGE_ESCALATION finding.

        Returns:
            List of recommendations.
        """
        recommendations: list[Recommendation] = []

        # Privilege escalation often involves IAM mutations
        dangerous_iam_actions = [
            "iam:CreateRole",
            "iam:AttachRolePolicy",
            "iam:PutRolePolicy",
            "iam:CreateUser",
            "iam:AttachUserPolicy",
            "iam:CreateAccessKey",
            "iam:UpdateAssumeRolePolicy",
        ]

        safe_iam_actions = [
            "iam:GetRole",
            "iam:GetPolicy",
            "iam:ListRoles",
            "iam:ListPolicies",
            "iam:GetRolePolicy",
            "iam:ListAttachedRolePolicies",
        ]

        # Create explicit deny for dangerous actions
        deny_statement: dict[str, Any] = {
            "Effect": "Deny",
            "Action": dangerous_iam_actions,
            "Resource": "*",
        }

        allow_statement: dict[str, Any] = {
            "Effect": "Allow",
            "Action": safe_iam_actions,
            "Resource": "*",
        }

        rationale = (
            f"Remove privilege escalation path by explicitly denying "
            f"IAM mutation actions ({', '.join(dangerous_iam_actions[:3])}, ...) "
            f"and allowing only read-only IAM access. "
            f"Finding: {finding.message}"
        )

        recommendations.append(
            Recommendation(
                recommendation_id=_generate_id(),
                finding_reference=finding.rule_id,
                current_permission=CurrentPermission(
                    action="iam:*",
                    resource="*",
                ),
                recommended_permission=RecommendedPermission(
                    actions=safe_iam_actions,
                    resource="*",
                    conditions={},
                ),
                rationale=rationale,
                risk_reduction=min(0.7, finding.risk_score * 0.8),
                effort=EffortLevel.MEDIUM,
                policy_statement=allow_statement,
                strategy=ScopingStrategy.WILDCARD_TO_SPECIFIC_ACTIONS,
                priority=0,
            )
        )

        return recommendations

    def _recommend_for_data_exposure(
        self, finding: Finding
    ) -> list[Recommendation]:
        """Generate recommendations for data exposure findings.

        Args:
            finding: A DATA_EXPOSURE finding.

        Returns:
            List of recommendations.
        """
        recommendations: list[Recommendation] = []

        # Add encryption and secure transport conditions
        conditions: dict[str, Any] = {
            "Bool": {
                "aws:SecureTransport": "true",
            },
            "StringEquals": {
                "s3:x-amz-server-side-encryption": "aws:kms",
            },
        }

        for resource_arn in finding.affected_resources:
            service = self._extract_service_from_resource(resource_arn)
            actions = self._replacements.get(
                f"{service}:*", [f"{service}:GetObject"]
            )

            # Only data-read actions
            read_actions = [a for a in actions if "Get" in a or "Read" in a or "Describe" in a]
            if not read_actions:
                read_actions = actions[:2]

            policy_statement: dict[str, Any] = {
                "Effect": "Allow",
                "Action": read_actions,
                "Resource": resource_arn,
                "Condition": conditions,
            }

            rationale = (
                f"Restrict data access to read-only with encryption and "
                f"secure transport conditions on '{resource_arn}'. "
                f"This prevents data exfiltration via unencrypted channels "
                f"and limits operations to non-destructive reads. "
                f"Finding: {finding.message}"
            )

            recommendations.append(
                Recommendation(
                    recommendation_id=_generate_id(),
                    finding_reference=finding.rule_id,
                    current_permission=CurrentPermission(
                        action=f"{service}:*",
                        resource=resource_arn,
                    ),
                    recommended_permission=RecommendedPermission(
                        actions=read_actions,
                        resource=resource_arn,
                        conditions=conditions,
                    ),
                    rationale=rationale,
                    risk_reduction=min(0.5, finding.risk_score * 0.7),
                    effort=EffortLevel.LOW,
                    policy_statement=policy_statement,
                    strategy=ScopingStrategy.ADD_CONDITION_KEYS,
                    priority=1,
                )
            )

        return recommendations

    def _recommend_for_lateral_movement(
        self, finding: Finding
    ) -> list[Recommendation]:
        """Generate recommendations for lateral movement findings.

        Args:
            finding: A LATERAL_MOVEMENT finding.

        Returns:
            List of recommendations.
        """
        recommendations: list[Recommendation] = []

        # Restrict AssumeRole to specific target roles
        conditions: dict[str, Any] = {
            "StringEquals": {
                "sts:ExternalId": "required-external-id",
                "aws:PrincipalOrgID": "o-organization-id",
            },
        }

        policy_statement: dict[str, Any] = {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::*:role/specific-target-role",
            "Condition": conditions,
        }

        rationale = (
            f"Restrict lateral movement by limiting sts:AssumeRole to specific "
            f"target roles with external ID and organization restrictions. "
            f"Unrestricted AssumeRole allows the agent to pivot to any role "
            f"in any account. Finding: {finding.message}"
        )

        recommendations.append(
            Recommendation(
                recommendation_id=_generate_id(),
                finding_reference=finding.rule_id,
                current_permission=CurrentPermission(
                    action="sts:AssumeRole",
                    resource="*",
                ),
                recommended_permission=RecommendedPermission(
                    actions=["sts:AssumeRole"],
                    resource="arn:aws:iam::*:role/specific-target-role",
                    conditions=conditions,
                ),
                rationale=rationale,
                risk_reduction=min(0.6, finding.risk_score * 0.75),
                effort=EffortLevel.MEDIUM,
                policy_statement=policy_statement,
                strategy=ScopingStrategy.RESTRICT_CROSS_ACCOUNT,
                priority=1,
            )
        )

        return recommendations

    def _recommend_for_policy_violation(
        self, finding: Finding
    ) -> list[Recommendation]:
        """Generate recommendations for policy violation findings.

        Args:
            finding: A POLICY_VIOLATION, COMPLIANCE, or CONFIGURATION finding.

        Returns:
            List of recommendations.
        """
        recommendations: list[Recommendation] = []

        # Generic: tighten based on affected resources
        for resource_arn in finding.affected_resources:
            service = self._extract_service_from_resource(resource_arn)
            replacement_actions = self._replacements.get(
                f"{service}:*",
                [f"{service}:Get*", f"{service}:List*", f"{service}:Describe*"],
            )

            policy_statement: dict[str, Any] = {
                "Effect": "Allow",
                "Action": replacement_actions,
                "Resource": resource_arn,
            }

            rationale = (
                f"Address policy violation by restricting '{service}' actions "
                f"to known-safe operations on '{resource_arn}'. "
                f"Finding: {finding.message}"
            )

            recommendations.append(
                Recommendation(
                    recommendation_id=_generate_id(),
                    finding_reference=finding.rule_id,
                    current_permission=CurrentPermission(
                        action=f"{service}:*",
                        resource=resource_arn,
                    ),
                    recommended_permission=RecommendedPermission(
                        actions=replacement_actions,
                        resource=resource_arn,
                    ),
                    rationale=rationale,
                    risk_reduction=min(0.4, finding.risk_score * 0.5),
                    effort=EffortLevel.MEDIUM,
                    policy_statement=policy_statement,
                    strategy=ScopingStrategy.WILDCARD_TO_SPECIFIC_ACTIONS,
                    priority=2,
                )
            )

        return recommendations

    def _recommend_generic(self, finding: Finding) -> list[Recommendation]:
        """Generate generic recommendations for uncategorized findings.

        Args:
            finding: Any finding without a specialized handler.

        Returns:
            List of recommendations.
        """
        recommendations: list[Recommendation] = []

        if finding.affected_resources:
            for resource_arn in finding.affected_resources:
                service = self._extract_service_from_resource(resource_arn)
                policy_statement: dict[str, Any] = {
                    "Effect": "Allow",
                    "Action": f"{service}:Get*",
                    "Resource": resource_arn,
                }

                rationale = (
                    f"Restrict access to read-only operations on "
                    f"'{resource_arn}' pending detailed access analysis. "
                    f"Finding: {finding.message}"
                )

                recommendations.append(
                    Recommendation(
                        recommendation_id=_generate_id(),
                        finding_reference=finding.rule_id,
                        current_permission=CurrentPermission(
                            action=f"{service}:*",
                            resource=resource_arn,
                        ),
                        recommended_permission=RecommendedPermission(
                            actions=[f"{service}:Get*"],
                            resource=resource_arn,
                        ),
                        rationale=rationale,
                        risk_reduction=min(0.3, finding.risk_score * 0.4),
                        effort=EffortLevel.LOW,
                        policy_statement=policy_statement,
                        strategy=ScopingStrategy.WILDCARD_TO_SPECIFIC_ACTIONS,
                        priority=3,
                    )
                )

        return recommendations

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _get_replacement_actions(
        self, wildcard_action: str, agent: Agent
    ) -> list[str]:
        """Get replacement actions for a wildcard, using CloudTrail data if available.

        Prefers CloudTrail-observed actions over the static replacement map
        when available for the given agent.

        Args:
            wildcard_action: The wildcard action to replace (e.g., 's3:*').
            agent: The agent being analyzed.

        Returns:
            List of specific actions to use as replacements.
        """
        service = _extract_service_prefix(wildcard_action)

        # Prefer CloudTrail-observed actions for this agent
        if agent.agent_id in self._cloudtrail_actions:
            observed = [
                a
                for a in self._cloudtrail_actions[agent.agent_id]
                if _extract_service_prefix(a) == service
            ]
            if observed:
                return sorted(set(observed))

        # Fall back to static replacement map
        if wildcard_action in self._replacements:
            return self._replacements[wildcard_action]

        # For fully wildcard '*', return a conservative set
        if wildcard_action == "*":
            return [
                "s3:GetObject",
                "s3:PutObject",
                "logs:PutLogEvents",
                "logs:CreateLogStream",
            ]

        # Unknown service wildcard: return read-only pattern
        return [
            f"{service}:Get*",
            f"{service}:List*",
            f"{service}:Describe*",
        ]

    def _compute_risk_score(
        self, agent: Agent, recommendations: list[Recommendation]
    ) -> float:
        """Compute the current risk score for an agent's permissions.

        Factors in:
        - Number of wildcard actions
        - Number of wildcard resources
        - Missing condition keys
        - Production environment multiplier
        - Data classification sensitivity

        Args:
            agent: Agent being analyzed.
            recommendations: Generated recommendations (indicates issues found).

        Returns:
            Risk score between 0.0 and 1.0.
        """
        base_score = 0.0

        # Each recommendation indicates a security gap
        for rec in recommendations:
            weight = 0.1  # Base weight per recommendation

            if rec.strategy == ScopingStrategy.WILDCARD_TO_SPECIFIC_ACTIONS:
                weight = 0.15
            elif rec.strategy == ScopingStrategy.RESOURCE_STAR_TO_SPECIFIC_ARNS:
                weight = 0.12
            elif rec.strategy == ScopingStrategy.RESTRICT_CROSS_ACCOUNT:
                weight = 0.13
            elif rec.strategy == ScopingStrategy.ADD_CONDITION_KEYS:
                weight = 0.08

            base_score += weight

        # Environment multiplier
        if agent.is_production:
            base_score *= 1.5

        # Data classification multiplier
        classification_multipliers = {
            "PUBLIC": 1.0,
            "INTERNAL": 1.1,
            "CONFIDENTIAL": 1.3,
            "SECRET": 1.5,
            "REGULATED": 1.6,
        }
        multiplier = classification_multipliers.get(
            agent.data_classification.value, 1.0
        )
        base_score *= multiplier

        # Cap at 1.0
        return min(1.0, base_score)

    def _compute_projected_risk(
        self,
        current_risk: float,
        recommendations: list[Recommendation],
    ) -> float:
        """Compute the projected risk score after applying all recommendations.

        Args:
            current_risk: Current risk score.
            recommendations: Recommendations to apply.

        Returns:
            Projected risk score between 0.0 and 1.0.
        """
        total_reduction = sum(r.risk_reduction for r in recommendations)
        # Diminishing returns: can't reduce below 5% of original
        projected = current_risk * max(0.05, 1.0 - total_reduction)
        return max(0.0, min(1.0, projected))

    def _build_current_policy(self, agent: Agent) -> dict[str, Any]:
        """Build a consolidated current policy document from agent's policies.

        Args:
            agent: Agent whose policies to consolidate.

        Returns:
            Consolidated IAM policy document.
        """
        all_statements: list[dict[str, Any]] = []
        for policy_doc in agent.identity_policies:
            statements = policy_doc.get("Statement", [])
            all_statements.extend(statements)

        return {
            "Version": "2012-10-17",
            "Statement": all_statements,
        }

    def _count_permissions(self, policy: dict[str, Any]) -> int:
        """Count the total number of action-resource pairs in a policy.

        Args:
            policy: IAM policy document.

        Returns:
            Count of permission grants.
        """
        count = 0
        for statement in policy.get("Statement", []):
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            count += len(actions) * len(resources)
        return count

    def _count_actions_in_service(self, service: str) -> int:
        """Estimate the number of IAM actions available for a service.

        Args:
            service: AWS service prefix (e.g., 's3').

        Returns:
            Estimated number of actions.
        """
        # Approximate counts for common services
        service_action_counts: dict[str, int] = {
            "s3": 120,
            "iam": 180,
            "ec2": 450,
            "lambda": 50,
            "dynamodb": 40,
            "secretsmanager": 20,
            "sqs": 25,
            "sns": 30,
            "kms": 35,
            "sts": 10,
            "logs": 30,
            "bedrock": 25,
        }
        return service_action_counts.get(service, 50)

    def _is_cross_account_access(self, agent: Agent, resource: str) -> bool:
        """Determine if a resource ARN indicates cross-account access.

        Args:
            agent: Agent to compare account with.
            resource: Resource ARN to check.

        Returns:
            True if the resource is in a different account or unrestricted.
        """
        if resource == "*":
            return True

        agent_account = _extract_account_from_role_arn(agent.iam_role_arn)
        resource_parts = resource.split(":")
        if len(resource_parts) >= 5:
            resource_account = resource_parts[4]
            if resource_account and resource_account != agent_account:
                return True
            # Empty account field in ARN (e.g., S3) is not cross-account
            if not resource_account:
                return False

        return False

    def _extract_service_from_resource(self, resource_arn: str) -> str:
        """Extract service name from a resource ARN.

        Args:
            resource_arn: AWS resource ARN.

        Returns:
            Service prefix (e.g., 's3').
        """
        if resource_arn == "*":
            return "unknown"
        parts = resource_arn.split(":")
        if len(parts) >= 3:
            return parts[2]
        return "unknown"

    def _resolve_condition_placeholders(
        self,
        conditions: dict[str, Any],
        agent: Agent,
    ) -> dict[str, Any]:
        """Resolve placeholder values in condition templates with agent context.

        Args:
            conditions: Condition template with ${placeholder} values.
            agent: Agent to derive values from.

        Returns:
            Conditions with placeholders resolved where possible.
        """
        resolved = copy.deepcopy(conditions)
        replacements = {
            "${Environment}": agent.environment.value,
            "${aws:Region}": _extract_region_from_tags(agent.tags),
            "${ExternalId}": agent.tags.get("external_id", agent.agent_id[:8]),
        }

        def _resolve_value(value: Any) -> Any:
            if isinstance(value, str):
                for placeholder, replacement in replacements.items():
                    value = value.replace(placeholder, replacement)
                return value
            if isinstance(value, dict):
                return {k: _resolve_value(v) for k, v in value.items()}
            if isinstance(value, list):
                return [_resolve_value(item) for item in value]
            return value

        return _resolve_value(resolved)

    def _statement_signature(self, statement: dict[str, Any]) -> str:
        """Generate a unique signature for a policy statement for comparison.

        Args:
            statement: IAM policy statement dict.

        Returns:
            A string signature for the statement.
        """
        # Normalize actions and resources to sorted lists
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        resources = statement.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        sig_data = {
            "effect": statement.get("Effect", "Allow"),
            "actions": sorted(actions),
            "resources": sorted(resources),
            "condition": json.dumps(
                statement.get("Condition", {}), sort_keys=True
            ),
        }
        return json.dumps(sig_data, sort_keys=True)

    def _build_summary(
        self,
        agent: Agent,
        recommendations: list[Recommendation],
        current_risk: float,
        projected_risk: float,
        strategies_applied: set[ScopingStrategy],
    ) -> str:
        """Build a human-readable executive summary.

        Args:
            agent: Analyzed agent.
            recommendations: Generated recommendations.
            current_risk: Current risk score.
            projected_risk: Projected risk after remediation.
            strategies_applied: Set of strategies used.

        Returns:
            Executive summary string.
        """
        risk_reduction_pct = (
            ((current_risk - projected_risk) / current_risk * 100.0)
            if current_risk > 0
            else 0.0
        )

        high_priority = sum(1 for r in recommendations if r.risk_reduction > 0.25)
        low_effort = sum(1 for r in recommendations if r.effort == EffortLevel.LOW)

        strategy_names = [s.value.replace("_", " ").title() for s in strategies_applied]

        summary_parts = [
            f"Least-Privilege Analysis for agent '{agent.name}' "
            f"(ID: {agent.agent_id[:8]}...)",
            f"",
            f"Environment: {agent.environment.value} | "
            f"Data Classification: {agent.data_classification.value}",
            f"Current Risk Score: {current_risk:.2f} | "
            f"Projected Risk Score: {projected_risk:.2f} "
            f"({risk_reduction_pct:.0f}% reduction)",
            f"",
            f"Total Recommendations: {len(recommendations)}",
            f"  High Priority (>25% risk reduction): {high_priority}",
            f"  Low Effort (quick wins): {low_effort}",
            f"",
            f"Strategies Applied: {', '.join(strategy_names) if strategy_names else 'None'}",
        ]

        if recommendations:
            summary_parts.append("")
            summary_parts.append("Top Recommendations:")
            for i, rec in enumerate(
                sorted(recommendations, key=lambda r: r.risk_reduction, reverse=True)[:5],
                1,
            ):
                summary_parts.append(
                    f"  {i}. [{rec.effort.value}] {rec.rationale[:100]}..."
                    if len(rec.rationale) > 100
                    else f"  {i}. [{rec.effort.value}] {rec.rationale}"
                )

        return "\n".join(summary_parts)


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Enums
    "EffortLevel",
    "ScopingStrategy",
    # Data Classes
    "CurrentPermission",
    "RecommendedPermission",
    "Recommendation",
    "PolicyDiff",
    "LeastPrivilegeReport",
    # Engine
    "LeastPrivilegeEngine",
    # Constants
    "WILDCARD_ACTION_REPLACEMENTS",
    "RECOMMENDED_CONDITIONS",
    "STRATEGY_RISK_REDUCTION",
]
