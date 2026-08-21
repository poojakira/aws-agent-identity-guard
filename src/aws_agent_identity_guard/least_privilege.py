"""
aws_agent_identity_guard/least_privilege.py
--------------------------------------------------------------------------------
Least-privilege recommendation engine for AWS Agent Identity Guard.

Analyzes effective permissions and usage patterns to generate actionable
recommendations that reduce privilege scope to the minimum required.
Produces concrete policy JSON diffs, Terraform HCL, and CloudFormation
YAML remediation code.

Design principles:
  - Recommendations are specific and actionable, not generic warnings
  - Every wildcard is replaced with explicit, narrowly-scoped alternatives
  - Risk reduction is quantified for prioritization
  - IaC output is production-ready and copy-pasteable
  - All operations are side-effect-free (read-only analysis)
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aws_agent_identity_guard.models import (
        AgentIdentity,
        EffectivePermission,
    )

logger = logging.getLogger(__name__)


# --- Constants: AWS service action catalogs for narrowing wildcards ---

_SERVICE_ACTION_CATALOG: dict[str, dict[str, list[str]]] = {
    "s3": {
        "read_only": [
            "s3:GetObject",
            "s3:GetObjectVersion",
            "s3:GetBucketLocation",
            "s3:ListBucket",
            "s3:ListBucketVersions",
        ],
        "write": [
            "s3:PutObject",
            "s3:DeleteObject",
            "s3:PutObjectAcl",
        ],
        "admin": [
            "s3:CreateBucket",
            "s3:DeleteBucket",
            "s3:PutBucketPolicy",
            "s3:PutBucketAcl",
            "s3:PutEncryptionConfiguration",
        ],
    },
    "dynamodb": {
        "read_only": [
            "dynamodb:GetItem",
            "dynamodb:BatchGetItem",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:DescribeTable",
        ],
        "write": [
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:DeleteItem",
            "dynamodb:BatchWriteItem",
        ],
        "admin": [
            "dynamodb:CreateTable",
            "dynamodb:DeleteTable",
            "dynamodb:UpdateTable",
            "dynamodb:CreateGlobalTable",
        ],
    },
    "lambda": {
        "read_only": [
            "lambda:GetFunction",
            "lambda:ListFunctions",
            "lambda:GetFunctionConfiguration",
        ],
        "invoke": [
            "lambda:InvokeFunction",
            "lambda:InvokeAsync",
        ],
        "admin": [
            "lambda:CreateFunction",
            "lambda:DeleteFunction",
            "lambda:UpdateFunctionCode",
            "lambda:UpdateFunctionConfiguration",
            "lambda:AddPermission",
        ],
    },
    "iam": {
        "read_only": [
            "iam:GetRole",
            "iam:GetPolicy",
            "iam:ListRoles",
            "iam:ListPolicies",
            "iam:GetRolePolicy",
        ],
        "write": [
            "iam:PutRolePolicy",
            "iam:AttachRolePolicy",
            "iam:DetachRolePolicy",
            "iam:CreateRole",
        ],
        "admin": [
            "iam:CreateUser",
            "iam:DeleteRole",
            "iam:CreatePolicy",
            "iam:DeletePolicy",
            "iam:PassRole",
        ],
    },
    "bedrock": {
        "read_only": [
            "bedrock:GetFoundationModel",
            "bedrock:ListFoundationModels",
            "bedrock:GetModelInvocationLoggingConfiguration",
        ],
        "invoke": [
            "bedrock:InvokeModel",
            "bedrock:InvokeModelWithResponseStream",
        ],
        "admin": [
            "bedrock:CreateModelCustomizationJob",
            "bedrock:DeleteCustomModel",
            "bedrock:PutModelInvocationLoggingConfiguration",
        ],
    },
    "sagemaker": {
        "read_only": [
            "sagemaker:DescribeEndpoint",
            "sagemaker:ListEndpoints",
            "sagemaker:DescribeModel",
        ],
        "invoke": [
            "sagemaker:InvokeEndpoint",
            "sagemaker:InvokeEndpointAsync",
        ],
        "admin": [
            "sagemaker:CreateEndpoint",
            "sagemaker:DeleteEndpoint",
            "sagemaker:CreateModel",
            "sagemaker:DeleteModel",
        ],
    },
    "secretsmanager": {
        "read_only": [
            "secretsmanager:GetSecretValue",
            "secretsmanager:DescribeSecret",
            "secretsmanager:ListSecrets",
        ],
        "write": [
            "secretsmanager:PutSecretValue",
            "secretsmanager:UpdateSecret",
        ],
        "admin": [
            "secretsmanager:CreateSecret",
            "secretsmanager:DeleteSecret",
            "secretsmanager:RotateSecret",
        ],
    },
    "kms": {
        "read_only": [
            "kms:DescribeKey",
            "kms:GetKeyPolicy",
            "kms:ListKeys",
        ],
        "encrypt_decrypt": [
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:GenerateDataKey",
        ],
        "admin": [
            "kms:CreateKey",
            "kms:ScheduleKeyDeletion",
            "kms:PutKeyPolicy",
            "kms:CreateGrant",
        ],
    },
    "sts": {
        "read_only": [
            "sts:GetCallerIdentity",
            "sts:GetAccessKeyInfo",
        ],
        "assume": [
            "sts:AssumeRole",
            "sts:AssumeRoleWithSAML",
            "sts:AssumeRoleWithWebIdentity",
        ],
        "admin": [
            "sts:GetFederationToken",
            "sts:GetSessionToken",
        ],
    },
}

_CONDITION_KEY_SUGGESTIONS: dict[str, dict[str, Any]] = {
    "s3": {
        "aws:SourceVpc": {"StringEquals": {"aws:SourceVpc": "vpc-REPLACE_ME"}},
        "s3:prefix": {"StringLike": {"s3:prefix": "specific-prefix/*"}},
        "aws:RequestedRegion": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
    },
    "dynamodb": {
        "dynamodb:LeadingKeys": {
            "ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["partition-key-value"]}
        },
        "aws:SourceVpc": {"StringEquals": {"aws:SourceVpc": "vpc-REPLACE_ME"}},
    },
    "iam": {
        "iam:PassedToService": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}},
        "aws:RequestedRegion": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
    },
    "lambda": {
        "aws:ResourceTag/Environment": {
            "StringEquals": {"aws:ResourceTag/Environment": "production"}
        },
    },
    "kms": {
        "kms:ViaService": {"StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com"}},
        "kms:EncryptionContext": {"StringEquals": {"kms:EncryptionContext:department": "finance"}},
    },
    "bedrock": {
        "aws:RequestedRegion": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
    },
    "secretsmanager": {
        "secretsmanager:ResourceTag/Environment": {
            "StringEquals": {"secretsmanager:ResourceTag/Environment": "production"}
        },
    },
}


# --- Data Classes ---


@dataclass
class Replacement:
    """
    A specific permission replacement mapping.

    Maps an overly-broad action/resource pair to a narrowly-scoped set.

    Attributes:
        original_action: The broad action being replaced (e.g., 's3:*').
        replacement_actions: Specific actions to replace it with.
        original_resource: The broad resource ARN being replaced.
        replacement_resource: A specific resource ARN.
        conditions_to_add: IAM conditions to further restrict access.
    """

    original_action: str
    replacement_actions: list[str] = field(default_factory=list)
    original_resource: str = "*"
    replacement_resource: str = "*"
    conditions_to_add: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "original_action": self.original_action,
            "replacement_actions": list(self.replacement_actions),
            "original_resource": self.original_resource,
            "replacement_resource": self.replacement_resource,
            "conditions_to_add": dict(self.conditions_to_add),
        }


@dataclass
class Recommendation:
    """
    A single least-privilege recommendation with remediation code.

    Attributes:
        finding_id: Unique identifier for this finding.
        current_permission: The current overly-broad permission string.
        recommended_permission: The recommended narrower permission string.
        reason: Human-readable explanation of why this change is recommended.
        risk_reduction: Estimated risk reduction (0-100 scale).
        iac_snippet: Infrastructure-as-code remediation snippet.
    """

    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    current_permission: str = ""
    recommended_permission: str = ""
    reason: str = ""
    risk_reduction: int = 0
    iac_snippet: str = ""

    def __post_init__(self) -> None:
        """Validate recommendation fields."""
        if not (0 <= self.risk_reduction <= 100):
            raise ValueError(f"risk_reduction must be between 0 and 100, got {self.risk_reduction}")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "finding_id": self.finding_id,
            "current_permission": self.current_permission,
            "recommended_permission": self.recommended_permission,
            "reason": self.reason,
            "risk_reduction": self.risk_reduction,
            "iac_snippet": self.iac_snippet,
        }


@dataclass
class PolicyDiff:
    """
    Structured diff between current and recommended policies.

    Attributes:
        additions: Policy statements to add.
        removals: Policy statements to remove.
        modifications: Policy statements to modify (before/after pairs).
        net_risk_change: Net change in risk score (negative means reduction).
        human_summary: Plain-language summary of all changes.
    """

    additions: list[dict[str, Any]] = field(default_factory=list)
    removals: list[dict[str, Any]] = field(default_factory=list)
    modifications: list[dict[str, Any]] = field(default_factory=list)
    net_risk_change: int = 0
    human_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "additions": self.additions,
            "removals": self.removals,
            "modifications": self.modifications,
            "net_risk_change": self.net_risk_change,
            "human_summary": self.human_summary,
        }


# --- Utility Functions ---


def _extract_service_from_action(action: str) -> str:
    """
    Extract the AWS service prefix from an IAM action string.

    Args:
        action: IAM action (e.g., 's3:GetObject' or 's3:*').

    Returns:
        The service name (e.g., 's3'), or empty string if unparseable.
    """
    if ":" in action:
        return action.split(":")[0].lower()
    return ""


def _is_wildcard_action(action: str) -> bool:
    """
    Determine if the action uses wildcards.

    Args:
        action: IAM action string.

    Returns:
        True if the action contains '*' or '?'.
    """
    return "*" in action or "?" in action


def _is_wildcard_resource(resource: str) -> bool:
    """
    Determine if the resource is a wildcard.

    Args:
        resource: IAM resource ARN or wildcard.

    Returns:
        True if the resource is '*' or contains broad wildcards.
    """
    return resource == "*" or resource == "arn:aws:*:*:*:*"


def _calculate_risk_reduction(action: str, resource: str) -> int:
    """
    Calculate estimated risk reduction for narrowing a permission.

    Uses heuristics based on the action/resource breadth.

    Args:
        action: The current action string.
        resource: The current resource string.

    Returns:
        Risk reduction estimate (0-100).
    """
    score = 0

    # Wildcard action on any service is high risk
    if action == "*":
        score += 50
    elif action.endswith(":*"):
        score += 35
    elif "*" in action:
        score += 20

    # Wildcard resource compounds the risk
    if resource == "*":
        score += 40
    elif resource.endswith("*") and resource.count("/") < 2:
        score += 20

    # Service-specific risk amplifiers
    service = _extract_service_from_action(action)
    high_risk_services = {"iam", "sts", "organizations", "kms", "cloudtrail"}
    if service in high_risk_services:
        score = min(100, score + 15)

    return min(100, score)


# --- Main Engine ---


class LeastPrivilegeRecommender:
    """
    Generates actionable least-privilege recommendations for AI agents.

    Analyzes effective permissions and usage patterns to identify overly-broad
    permissions and produce specific, narrowly-scoped replacements with
    concrete policy JSON diffs and IaC remediation code.

    Usage:
        recommender = LeastPrivilegeRecommender()
        recommendations = recommender.recommend(agent, effective_perms, usage_data)
        diff = recommender.generate_policy_diff(current_policy, recommendations)
        terraform_code = recommender.generate_iac_code(recommendations, format='terraform')
    """

    def __init__(
        self,
        service_catalog: dict[str, dict[str, list[str]]] | None = None,
        condition_catalog: dict[str, dict[str, Any]] | None = None,
        default_region: str = "us-east-1",
        account_id: str = "123456789012",
    ) -> None:
        """
        Initialize the least-privilege recommender.

        Args:
            service_catalog: Custom service action catalog. Uses built-in if None.
            condition_catalog: Custom condition key suggestions. Uses built-in if None.
            default_region: Default AWS region for ARN construction.
            account_id: Default AWS account ID for ARN construction.
        """
        self._service_catalog = service_catalog or _SERVICE_ACTION_CATALOG
        self._condition_catalog = condition_catalog or _CONDITION_KEY_SUGGESTIONS
        self._default_region = default_region
        self._account_id = account_id
        logger.info(
            "LeastPrivilegeRecommender initialized with %d service catalogs",
            len(self._service_catalog),
        )

    def recommend(
        self,
        agent: AgentIdentity,
        effective_permissions: list[EffectivePermission],
        usage_data: dict[str, Any] | None = None,
    ) -> list[Recommendation]:
        """
        Generate least-privilege recommendations for an agent.

        Analyzes each effective permission for overly-broad access and
        produces specific replacement recommendations.

        Args:
            agent: The agent identity to analyze.
            effective_permissions: List of the agent's effective permissions.
            usage_data: Optional usage/access pattern data for more precise
                narrowing. Expected structure:
                {
                    "accessed_resources": ["arn:aws:s3:::bucket/key", ...],
                    "used_actions": ["s3:GetObject", ...],
                    "access_patterns": {"service": {"actions": [...], "resources": [...]}}
                }

        Returns:
            List of Recommendation objects, sorted by risk_reduction descending.
        """
        if not effective_permissions:
            logger.info("No effective permissions to analyze for agent %s", agent.agent_id)
            return []

        usage_data = usage_data or {}
        recommendations: list[Recommendation] = []

        for perm in effective_permissions:
            try:
                perm_recommendations = self._analyze_permission(agent, perm, usage_data)
                recommendations.extend(perm_recommendations)
            except Exception as exc:
                logger.error(
                    "Error analyzing permission %s:%s for agent %s: %s",
                    perm.action,
                    perm.resource,
                    agent.agent_id,
                    exc,
                )

        # Sort by risk reduction (highest first) for prioritization
        recommendations.sort(key=lambda r: r.risk_reduction, reverse=True)

        logger.info(
            "Generated %d recommendations for agent %s (top risk_reduction: %d)",
            len(recommendations),
            agent.agent_id,
            recommendations[0].risk_reduction if recommendations else 0,
        )

        return recommendations

    def _analyze_permission(
        self,
        agent: AgentIdentity,
        perm: EffectivePermission,
        usage_data: dict[str, Any],
    ) -> list[Recommendation]:
        """
        Analyze a single permission and generate recommendations.

        Args:
            agent: The agent identity being analyzed.
            perm: The effective permission to analyze.
            usage_data: Usage pattern data.

        Returns:
            List of recommendations for this permission.
        """
        recommendations: list[Recommendation] = []

        action = perm.action
        resource = perm.resource

        # Check for wildcard actions
        if _is_wildcard_action(action):
            replacements = self._generate_specific_replacements(perm)
            for replacement in replacements:
                risk_reduction = _calculate_risk_reduction(action, resource)
                recommended_str = ", ".join(replacement.replacement_actions)
                rec_resource = replacement.replacement_resource

                iac_snippet = self._generate_single_iac_snippet(
                    replacement.replacement_actions,
                    rec_resource,
                    replacement.conditions_to_add,
                    format_type="terraform",
                )

                rec = Recommendation(
                    current_permission=f"{action} on {resource}",
                    recommended_permission=f"{recommended_str} on {rec_resource}",
                    reason=(
                        f"Wildcard action '{action}' grants excessive privileges. "
                        f"Replace with specific actions: {recommended_str}. "
                        f"Scope resource to: {rec_resource}"
                    ),
                    risk_reduction=risk_reduction,
                    iac_snippet=iac_snippet,
                )
                recommendations.append(rec)

        # Check for wildcard resources (even with specific actions)
        elif _is_wildcard_resource(resource):
            narrowed_resource = self._narrow_wildcard_resources(perm, usage_data)
            if narrowed_resource != resource:
                risk_reduction = _calculate_risk_reduction(action, resource)
                conditions = self._add_condition_keys(perm)

                iac_snippet = self._generate_single_iac_snippet(
                    [action],
                    narrowed_resource,
                    conditions,
                    format_type="terraform",
                )

                rec = Recommendation(
                    current_permission=f"{action} on {resource}",
                    recommended_permission=f"{action} on {narrowed_resource}",
                    reason=(
                        f"Resource wildcard '*' allows access to all resources. "
                        f"Narrow to specific resource: {narrowed_resource}. "
                        f"Add conditions for defense-in-depth."
                    ),
                    risk_reduction=risk_reduction,
                    iac_snippet=iac_snippet,
                )
                recommendations.append(rec)

        # Check for missing condition keys on sensitive actions
        elif self._is_sensitive_action(action) and not perm.conditions_required:
            conditions = self._add_condition_keys(perm)
            if conditions:
                iac_snippet = self._generate_single_iac_snippet(
                    [action],
                    resource,
                    conditions,
                    format_type="terraform",
                )

                rec = Recommendation(
                    current_permission=f"{action} on {resource}",
                    recommended_permission=f"{action} on {resource} with conditions",
                    reason=(
                        f"Sensitive action '{action}' lacks condition keys. "
                        f"Add conditions to restrict: {json.dumps(conditions, indent=2)}"
                    ),
                    risk_reduction=min(25, _calculate_risk_reduction(action, resource) + 10),
                    iac_snippet=iac_snippet,
                )
                recommendations.append(rec)

        return recommendations

    def _generate_specific_replacements(
        self,
        permission: EffectivePermission,
    ) -> list[Replacement]:
        """
        Generate specific action/resource replacements for a broad permission.

        For wildcard actions like 's3:*', generates replacements using the
        service action catalog, splitting into read/write/admin tiers.

        Args:
            permission: The effective permission with wildcards.

        Returns:
            List of Replacement objects with specific actions/resources.
        """
        action = permission.action
        resource = permission.resource
        service = _extract_service_from_action(action)

        replacements: list[Replacement] = []

        if service in self._service_catalog:
            catalog = self._service_catalog[service]

            # Default: recommend read-only tier
            read_actions = catalog.get("read_only", [])
            if read_actions:
                narrowed_resource = self._construct_narrowed_resource(service, resource)
                conditions = self._add_condition_keys(permission)

                replacements.append(
                    Replacement(
                        original_action=action,
                        replacement_actions=read_actions,
                        original_resource=resource,
                        replacement_resource=narrowed_resource,
                        conditions_to_add=conditions,
                    )
                )

            # If there are invoke/write actions, add them as separate replacements
            invoke_actions = catalog.get("invoke", [])
            if invoke_actions:
                narrowed_resource = self._construct_narrowed_resource(service, resource)
                replacements.append(
                    Replacement(
                        original_action=action,
                        replacement_actions=invoke_actions,
                        original_resource=resource,
                        replacement_resource=narrowed_resource,
                        conditions_to_add={},
                    )
                )

        elif action == "*":
            # Full wildcard: no service prefix, recommend explicit deny pattern
            replacements.append(
                Replacement(
                    original_action="*",
                    replacement_actions=["<specify-needed-actions>"],
                    original_resource="*",
                    replacement_resource="<specify-resource-arn>",
                    conditions_to_add={
                        "StringEquals": {"aws:RequestedRegion": self._default_region}
                    },
                )
            )
        else:
            # Unknown service: return generic narrowing
            replacements.append(
                Replacement(
                    original_action=action,
                    replacement_actions=[action.replace("*", "<specific-action>")],
                    original_resource=resource,
                    replacement_resource=resource if resource != "*" else "<specific-arn>",
                    conditions_to_add={},
                )
            )

        return replacements

    def _narrow_wildcard_resources(
        self,
        permission: EffectivePermission,
        usage_patterns: dict[str, Any],
    ) -> str:
        """
        Replace a wildcard resource with a specific ARN based on usage.

        Uses access pattern data to determine the most specific resource
        scope that covers observed usage.

        Args:
            permission: The permission with a wildcard resource.
            usage_patterns: Observed usage patterns with accessed_resources.

        Returns:
            A specific ARN string (or narrowed wildcard pattern).
        """
        action = permission.action
        service = _extract_service_from_action(action)
        resource = permission.resource

        # Check if usage data provides accessed resources
        accessed_resources = usage_patterns.get("accessed_resources", [])
        access_patterns = usage_patterns.get("access_patterns", {})

        # Try to find resources for this specific service
        service_patterns = access_patterns.get(service, {})
        service_resources = service_patterns.get("resources", [])

        # Merge resource lists
        relevant_resources = []
        for res in accessed_resources + service_resources:
            is_match = (service and f":{service}:" in res.lower()) or (
                service and res.startswith(f"arn:aws:{service}:")
            )
            if is_match:
                relevant_resources.append(res)

        if relevant_resources:
            # Find common prefix among accessed resources
            common_prefix = self._find_common_arn_prefix(relevant_resources)
            if common_prefix and common_prefix != "*":
                return f"{common_prefix}*"

        # Fallback: construct a reasonable resource scope from service
        return self._construct_narrowed_resource(service, resource)

    def _narrow_wildcard_actions(
        self,
        permission: EffectivePermission,
        service: str,
    ) -> list[str]:
        """
        Replace a wildcard action with specific actions from the catalog.

        Args:
            permission: The permission with a wildcard action.
            service: The AWS service name.

        Returns:
            List of specific action strings.
        """
        if service in self._service_catalog:
            catalog = self._service_catalog[service]
            # Default to read_only tier as safest replacement
            actions = catalog.get("read_only", [])
            if actions:
                return actions

        # If no catalog entry, return a placeholder
        return [f"{service}:<specify-action>"]

    def _add_condition_keys(
        self,
        permission: EffectivePermission,
    ) -> dict[str, Any]:
        """
        Suggest IAM condition keys to further restrict a permission.

        Selects appropriate conditions based on the service and action type.

        Args:
            permission: The permission to add conditions to.

        Returns:
            Dictionary of suggested IAM conditions.
        """
        action = permission.action
        service = _extract_service_from_action(action)

        conditions: dict[str, Any] = {}

        if service in self._condition_catalog:
            service_conditions = self._condition_catalog[service]
            # Select the most impactful condition for this service
            for _key, condition_block in service_conditions.items():
                conditions.update(condition_block)
                break  # Take the first (most impactful) suggestion

        # Always suggest source VPC restriction for production
        if not conditions:
            conditions = {"StringEquals": {"aws:SourceVpc": "vpc-REPLACE_WITH_YOUR_VPC_ID"}}

        return conditions

    def generate_policy_diff(
        self,
        current_policy: dict[str, Any],
        recommendations: list[Recommendation],
    ) -> PolicyDiff:
        """
        Generate a structured policy diff from recommendations.

        Produces additions, removals, and modifications with a human-readable
        summary of all changes.

        Args:
            current_policy: The current IAM policy document (JSON structure).
            recommendations: List of recommendations to apply.

        Returns:
            A PolicyDiff with complete before/after details.
        """
        if not recommendations:
            return PolicyDiff(
                human_summary="No changes recommended. Policy is already well-scoped."
            )

        additions: list[dict[str, Any]] = []
        removals: list[dict[str, Any]] = []
        modifications: list[dict[str, Any]] = []
        total_risk_reduction = 0

        for rec in recommendations:
            total_risk_reduction += rec.risk_reduction

            # Parse current permission
            current_parts = rec.current_permission.split(" on ")
            current_action = current_parts[0] if current_parts else rec.current_permission
            current_resource = current_parts[1] if len(current_parts) > 1 else "*"

            # Parse recommended permission
            rec_parts = rec.recommended_permission.split(" on ")
            rec_actions_str = rec_parts[0] if rec_parts else rec.recommended_permission
            rec_resource = rec_parts[1] if len(rec_parts) > 1 else "*"
            rec_actions = [a.strip() for a in rec_actions_str.split(",")]

            # Build the removal statement
            removal_statement = {
                "Effect": "Allow",
                "Action": current_action,
                "Resource": current_resource,
            }
            removals.append(removal_statement)

            # Build the addition statement
            addition_statement: dict[str, Any] = {
                "Effect": "Allow",
                "Action": rec_actions if len(rec_actions) > 1 else rec_actions[0],
                "Resource": rec_resource,
            }

            # Add conditions if referenced in the recommendation
            if "with conditions" in rec.recommended_permission.lower():
                # Extract conditions from reason (they are JSON-embedded)
                addition_statement["Condition"] = {
                    "StringEquals": {"aws:SourceVpc": "vpc-REPLACE_WITH_YOUR_VPC_ID"}
                }

            additions.append(addition_statement)

            # Build modification record (before/after pair)
            modifications.append(
                {
                    "finding_id": rec.finding_id,
                    "before": removal_statement,
                    "after": addition_statement,
                    "reason": rec.reason,
                    "risk_reduction": rec.risk_reduction,
                }
            )

        # Compute net risk change (negative = improvement)
        net_risk_change = -min(100, total_risk_reduction)

        # Build human-readable summary
        summary_parts = [
            f"Policy diff contains {len(modifications)} change(s):",
            f"  - {len(removals)} statement(s) to remove (overly broad)",
            f"  - {len(additions)} statement(s) to add (narrowly scoped)",
            f"  - Net risk change: {net_risk_change} (lower is better)",
            "",
            "Top changes:",
        ]
        for mod in modifications[:5]:
            summary_parts.append(f"  [{mod['risk_reduction']}% reduction] {mod['reason'][:80]}")

        human_summary = "\n".join(summary_parts)

        return PolicyDiff(
            additions=additions,
            removals=removals,
            modifications=modifications,
            net_risk_change=net_risk_change,
            human_summary=human_summary,
        )

    def generate_iac_code(
        self,
        recommendations: list[Recommendation],
        format: str = "terraform",  # noqa: A002
    ) -> str:
        """
        Generate infrastructure-as-code remediation from recommendations.

        Produces production-ready Terraform HCL or CloudFormation YAML.

        Args:
            recommendations: List of recommendations to convert to IaC.
            format: Output format - 'terraform' or 'cloudformation'.

        Returns:
            Complete IaC code string ready for deployment.

        Raises:
            ValueError: If format is not 'terraform' or 'cloudformation'.
        """
        if format not in ("terraform", "cloudformation"):
            raise ValueError(f"Unsupported format: {format}. Use 'terraform' or 'cloudformation'.")

        if not recommendations:
            return "# No recommendations to generate IaC for."

        if format == "terraform":
            return self._generate_terraform(recommendations)
        else:
            return self._generate_cloudformation(recommendations)

    # --- Private Helper Methods ---

    def _is_sensitive_action(self, action: str) -> bool:
        """
        Determine if an action is sensitive and warrants conditions.

        Args:
            action: IAM action string.

        Returns:
            True if the action is considered sensitive.
        """
        sensitive_prefixes = [
            "iam:",
            "sts:AssumeRole",
            "kms:Decrypt",
            "kms:CreateGrant",
            "secretsmanager:GetSecretValue",
            "lambda:UpdateFunctionCode",
            "s3:DeleteObject",
            "s3:PutBucketPolicy",
            "dynamodb:DeleteTable",
            "organizations:",
            "cloudtrail:StopLogging",
            "cloudtrail:DeleteTrail",
        ]
        action_lower = action.lower()
        return any(action_lower.startswith(prefix.lower()) for prefix in sensitive_prefixes)

    def _construct_narrowed_resource(self, service: str, current_resource: str) -> str:
        """
        Construct a narrowed resource ARN based on service conventions.

        Args:
            service: AWS service name.
            current_resource: Current resource string.

        Returns:
            A more specific ARN pattern.
        """
        resource_templates: dict[str, str] = {
            "s3": "arn:aws:s3:::BUCKET_NAME/*",
            "dynamodb": (
                f"arn:aws:dynamodb:{self._default_region}:{self._account_id}" f":table/TABLE_NAME"
            ),
            "lambda": (
                f"arn:aws:lambda:{self._default_region}:{self._account_id}"
                f":function:FUNCTION_NAME"
            ),
            "iam": f"arn:aws:iam::{self._account_id}:role/ROLE_NAME",
            "kms": (f"arn:aws:kms:{self._default_region}:{self._account_id}" f":key/KEY_ID"),
            "secretsmanager": (
                f"arn:aws:secretsmanager:{self._default_region}:{self._account_id}"
                f":secret:SECRET_NAME"
            ),
            "bedrock": (f"arn:aws:bedrock:{self._default_region}::foundation-model/*"),
            "sagemaker": (
                f"arn:aws:sagemaker:{self._default_region}:{self._account_id}"
                f":endpoint/ENDPOINT_NAME"
            ),
            "sts": f"arn:aws:iam::{self._account_id}:role/ROLE_NAME",
        }

        if service in resource_templates:
            return resource_templates[service]

        # Generic fallback
        return f"arn:aws:{service}:{self._default_region}:{self._account_id}:RESOURCE_ID"

    def _find_common_arn_prefix(self, arns: list[str]) -> str:
        """
        Find the longest common prefix among a list of ARN strings.

        Args:
            arns: List of ARN strings.

        Returns:
            The longest common prefix, or empty string if none.
        """
        if not arns:
            return ""
        if len(arns) == 1:
            # Return up to the last path separator
            last_sep = arns[0].rfind("/")
            if last_sep > 0:
                return arns[0][: last_sep + 1]
            return arns[0]

        prefix = arns[0]
        for arn in arns[1:]:
            while not arn.startswith(prefix):
                prefix = prefix[:-1]
                if not prefix:
                    return ""

        # Ensure prefix ends at a path boundary
        last_sep = prefix.rfind("/")
        if last_sep > 0:
            return prefix[: last_sep + 1]
        last_colon = prefix.rfind(":")
        if last_colon > 0:
            return prefix[: last_colon + 1]

        return prefix

    def _generate_single_iac_snippet(
        self,
        actions: list[str],
        resource: str,
        conditions: dict[str, Any],
        format_type: str = "terraform",
    ) -> str:
        """
        Generate a single IaC snippet for one recommendation.

        Args:
            actions: List of IAM actions.
            resource: Resource ARN.
            conditions: IAM conditions to include.
            format_type: 'terraform' or 'cloudformation'.

        Returns:
            IaC code snippet string.
        """
        if format_type == "terraform":
            return self._snippet_terraform(actions, resource, conditions)
        else:
            return self._snippet_cloudformation(actions, resource, conditions)

    def _snippet_terraform(
        self,
        actions: list[str],
        resource: str,
        conditions: dict[str, Any],
    ) -> str:
        """Generate a Terraform HCL statement snippet."""
        actions_hcl = ", ".join(f'"{a}"' for a in actions)
        lines = [
            "  statement {",
            '    effect = "Allow"',
            f"    actions = [{actions_hcl}]",
            f'    resources = ["{resource}"]',
        ]

        if conditions:
            for operator, kv_pairs in conditions.items():
                lines.append("")
                lines.append("    condition {")
                lines.append(f'      test     = "{operator}"')
                if isinstance(kv_pairs, dict):
                    for var_name, var_val in kv_pairs.items():
                        lines.append(f'      variable = "{var_name}"')
                        if isinstance(var_val, list):
                            vals = ", ".join(f'"{v}"' for v in var_val)
                            lines.append(f"      values   = [{vals}]")
                        else:
                            lines.append(f'      values   = ["{var_val}"]')
                        break  # One variable per condition block
                lines.append("    }")

        lines.append("  }")
        return "\n".join(lines)

    def _snippet_cloudformation(
        self,
        actions: list[str],
        resource: str,
        conditions: dict[str, Any],
    ) -> str:
        """Generate a CloudFormation YAML statement snippet."""
        actions_yaml = "\n".join(f"            - {a}" for a in actions)
        lines = [
            "        - Effect: Allow",
            "          Action:",
            actions_yaml,
            "          Resource:",
            f"            - {resource}",
        ]

        if conditions:
            lines.append("          Condition:")
            for operator, kv_pairs in conditions.items():
                lines.append(f"            {operator}:")
                if isinstance(kv_pairs, dict):
                    for var_name, var_val in kv_pairs.items():
                        if isinstance(var_val, list):
                            lines.append(f"              {var_name}:")
                            for v in var_val:
                                lines.append(f"                - {v}")
                        else:
                            lines.append(f"              {var_name}: {var_val}")

        return "\n".join(lines)

    def _generate_terraform(self, recommendations: list[Recommendation]) -> str:
        """
        Generate complete Terraform HCL for all recommendations.

        Args:
            recommendations: List of recommendations.

        Returns:
            Complete Terraform code string.
        """
        lines = [
            "# Terraform remediation generated by AWS Agent Identity Guard",
            "# Apply these changes to enforce least-privilege for AI agent roles.",
            "#",
            "# IMPORTANT: Review and customize resource ARNs and condition values",
            "# before applying to your environment.",
            "",
            'data "aws_caller_identity" "current" {}',
            'data "aws_region" "current" {}',
            "",
            'resource "aws_iam_policy" "agent_least_privilege" {',
            '  name        = "agent-identity-guard-least-privilege"',
            '  description = "Least-privilege policy generated by AWS Agent Identity Guard"',
            "",
            "  policy = jsonencode({",
            '    Version = "2012-10-17"',
            "    Statement = [",
        ]

        for _i, rec in enumerate(recommendations):
            # Parse recommended permission
            rec_parts = rec.recommended_permission.split(" on ")
            rec_actions_str = rec_parts[0] if rec_parts else ""
            rec_resource = rec_parts[1] if len(rec_parts) > 1 else "*"
            rec_actions = [a.strip() for a in rec_actions_str.split(",") if a.strip()]

            if not rec_actions:
                continue

            actions_json = json.dumps(rec_actions)
            lines.append("      {")
            lines.append('        Effect   = "Allow"')
            lines.append(f"        Action   = {actions_json}")
            lines.append(f'        Resource = "{rec_resource}"')
            lines.append("      },")

        lines.extend(
            [
                "    ]",
                "  })",
                "}",
                "",
                "# Attach to the agent role:",
                '# resource "aws_iam_role_policy_attachment" "agent_policy" {',
                "#   role       = aws_iam_role.agent_role.name",
                "#   policy_arn = aws_iam_policy.agent_least_privilege.arn",
                "# }",
            ]
        )

        return "\n".join(lines)

    def _generate_cloudformation(self, recommendations: list[Recommendation]) -> str:
        """
        Generate complete CloudFormation YAML for all recommendations.

        Args:
            recommendations: List of recommendations.

        Returns:
            Complete CloudFormation YAML string.
        """
        lines = [
            "# CloudFormation remediation generated by AWS Agent Identity Guard",
            "# Apply these changes to enforce least-privilege for AI agent roles.",
            "#",
            "# IMPORTANT: Review and customize resource ARNs and condition values",
            "# before applying to your environment.",
            "",
            "AWSTemplateFormatVersion: '2010-09-09'",
            "Description: Least-privilege policy for AI agent roles",
            "",
            "Resources:",
            "  AgentLeastPrivilegePolicy:",
            "    Type: AWS::IAM::ManagedPolicy",
            "    Properties:",
            "      ManagedPolicyName: agent-identity-guard-least-privilege",
            "      Description: Least-privilege policy generated by AWS Agent Identity Guard",
            "      PolicyDocument:",
            "        Version: '2012-10-17'",
            "        Statement:",
        ]

        for rec in recommendations:
            # Parse recommended permission
            rec_parts = rec.recommended_permission.split(" on ")
            rec_actions_str = rec_parts[0] if rec_parts else ""
            rec_resource = rec_parts[1] if len(rec_parts) > 1 else "*"
            rec_actions = [a.strip() for a in rec_actions_str.split(",") if a.strip()]

            if not rec_actions:
                continue

            lines.append("          - Effect: Allow")
            lines.append("            Action:")
            for action in rec_actions:
                lines.append(f"              - {action}")
            lines.append("            Resource:")
            lines.append(f"              - {rec_resource}")

        lines.extend(
            [
                "",
                "  # Attach to agent role:",
                "  # AgentRole:",
                "  #   Type: AWS::IAM::Role",
                "  #   Properties:",
                "  #     ManagedPolicyArns:",
                "  #       - !Ref AgentLeastPrivilegePolicy",
            ]
        )

        return "\n".join(lines)
