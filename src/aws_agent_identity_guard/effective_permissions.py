"""AWS Agent Identity Guard - Effective Permission Analysis Engine.

Production-grade engine for resolving effective permissions across all IAM
policy layers. Implements the complete AWS authorization logic including:

- Identity policies (inline + managed)
- Resource policies
- Permission boundaries
- Service Control Policies (SCPs)
- Session policies

Follows AWS's documented evaluation logic where explicit deny always wins,
and both SCPs and permission boundaries must allow for an effective allow.

References:
    - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, unique
from typing import Any, Optional, Protocol

from .models import (
    Agent,
    EffectivePermission,
    Permission,
    PermissionEffect,
    PermissionSource,
)


logger = logging.getLogger(__name__)


# =============================================================================
# Constants & Known Service Actions
# =============================================================================

# Subset of well-known AWS service action prefixes for wildcard expansion
_KNOWN_SERVICE_ACTIONS: dict[str, list[str]] = {
    "s3": [
        "GetObject", "PutObject", "DeleteObject", "ListBucket",
        "ListAllMyBuckets", "GetBucketPolicy", "PutBucketPolicy",
        "GetBucketAcl", "PutBucketAcl", "GetObjectAcl", "PutObjectAcl",
        "CreateBucket", "DeleteBucket", "GetBucketLocation",
        "GetBucketVersioning", "PutBucketVersioning", "ListObjectVersions",
        "GetObjectVersion", "DeleteObjectVersion", "RestoreObject",
        "GetBucketEncryption", "PutBucketEncryption",
    ],
    "iam": [
        "CreateRole", "DeleteRole", "AttachRolePolicy", "DetachRolePolicy",
        "PutRolePolicy", "DeleteRolePolicy", "CreatePolicy", "DeletePolicy",
        "CreateUser", "DeleteUser", "AttachUserPolicy", "DetachUserPolicy",
        "PutUserPolicy", "DeleteUserPolicy", "CreateAccessKey", "DeleteAccessKey",
        "ListRoles", "ListUsers", "ListPolicies", "GetRole", "GetUser",
        "GetPolicy", "GetRolePolicy", "GetUserPolicy", "PassRole",
        "CreateServiceLinkedRole", "UpdateAssumeRolePolicy",
        "SimulatePrincipalPolicy", "SimulateCustomPolicy",
    ],
    "sts": [
        "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity",
        "GetCallerIdentity", "GetSessionToken", "GetFederationToken",
        "DecodeAuthorizationMessage",
    ],
    "ec2": [
        "RunInstances", "TerminateInstances", "StartInstances", "StopInstances",
        "DescribeInstances", "DescribeSecurityGroups", "CreateSecurityGroup",
        "DeleteSecurityGroup", "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress", "DescribeVpcs", "CreateVpc", "DeleteVpc",
        "DescribeSubnets", "CreateSubnet", "DeleteSubnet",
    ],
    "lambda": [
        "CreateFunction", "DeleteFunction", "InvokeFunction", "UpdateFunctionCode",
        "UpdateFunctionConfiguration", "GetFunction", "ListFunctions",
        "AddPermission", "RemovePermission", "GetPolicy",
        "CreateEventSourceMapping", "DeleteEventSourceMapping",
    ],
    "dynamodb": [
        "GetItem", "PutItem", "DeleteItem", "UpdateItem", "Query", "Scan",
        "CreateTable", "DeleteTable", "DescribeTable", "ListTables",
        "BatchGetItem", "BatchWriteItem", "UpdateTable",
    ],
    "kms": [
        "Encrypt", "Decrypt", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext",
        "CreateKey", "DeleteKey", "ScheduleKeyDeletion", "CancelKeyDeletion",
        "DescribeKey", "ListKeys", "CreateAlias", "DeleteAlias",
        "CreateGrant", "RevokeGrant", "RetireGrant",
    ],
    "secretsmanager": [
        "GetSecretValue", "CreateSecret", "DeleteSecret", "UpdateSecret",
        "PutSecretValue", "DescribeSecret", "ListSecrets",
        "RotateSecret", "RestoreSecret",
    ],
    "bedrock": [
        "InvokeModel", "InvokeModelWithResponseStream", "ListFoundationModels",
        "GetFoundationModel", "CreateModelCustomizationJob",
        "GetModelCustomizationJob", "ListModelCustomizationJobs",
        "CreateAgent", "DeleteAgent", "GetAgent", "ListAgents",
        "InvokeAgent", "PrepareAgent",
    ],
    "sagemaker": [
        "CreateEndpoint", "DeleteEndpoint", "InvokeEndpoint",
        "CreateModel", "DeleteModel", "DescribeModel",
        "CreateTrainingJob", "DescribeTrainingJob", "StopTrainingJob",
        "CreateNotebookInstance", "DeleteNotebookInstance",
    ],
}


# =============================================================================
# Data Types for Policy Evaluation
# =============================================================================


@dataclass(slots=True)
class Statement:
    """Parsed IAM policy statement.

    Represents a single statement from an IAM policy document with all
    fields normalized for evaluation.
    """

    sid: str
    effect: PermissionEffect
    actions: list[str]
    not_actions: list[str]
    resources: list[str]
    not_resources: list[str]
    principals: list[str]
    not_principals: list[str]
    conditions: dict[str, dict[str, Any]]
    source_policy: str

    @property
    def is_allow(self) -> bool:
        """Whether this statement grants access."""
        return self.effect == PermissionEffect.ALLOW

    @property
    def is_deny(self) -> bool:
        """Whether this statement explicitly denies access."""
        return self.effect == PermissionEffect.DENY

    @property
    def uses_not_action(self) -> bool:
        """Whether this statement uses NotAction."""
        return bool(self.not_actions)

    @property
    def uses_not_resource(self) -> bool:
        """Whether this statement uses NotResource."""
        return bool(self.not_resources)


@dataclass(slots=True)
class PolicyLayer:
    """A named collection of policy statements from a specific source.

    Groups statements from one policy source for layered evaluation.
    """

    name: str
    source: PermissionSource
    statements: list[Statement]
    policy_arn: str = ""


@dataclass(slots=True)
class EvaluationContext:
    """Context for policy evaluation including request-time variables.

    Provides the runtime context needed for condition evaluation,
    including source IP, time, tags, and custom context values.
    """

    action: str
    resource: str
    principal_arn: str
    account_id: str = ""
    source_ip: str = ""
    current_time: str = ""
    secure_transport: bool = True
    tags: dict[str, str] = field(default_factory=dict)
    request_context: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PermissionReport:
    """Structured report of all effective permissions for an agent.

    Provides a comprehensive view of what an agent can and cannot do,
    with full provenance for each permission determination.
    """

    agent_id: str
    agent_name: str
    iam_role_arn: str
    evaluated_at: datetime
    effective_permissions: list[EffectivePermission]
    summary: dict[str, int]
    findings: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report to a dictionary."""
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "iam_role_arn": self.iam_role_arn,
            "evaluated_at": self.evaluated_at.isoformat(),
            "effective_permissions": [
                ep.to_dict() for ep in self.effective_permissions
            ],
            "summary": self.summary,
            "findings": self.findings,
        }


# =============================================================================
# Exceptions
# =============================================================================


class PolicyEvaluationError(Exception):
    """Raised when policy evaluation encounters an unrecoverable error."""

    pass


class PolicyParseError(Exception):
    """Raised when a policy document cannot be parsed."""

    pass


class SimulationError(Exception):
    """Raised when IAM policy simulation fails."""

    pass


# =============================================================================
# Policy Parsing Utilities
# =============================================================================


def parse_policy_document(
    doc: dict[str, Any],
    source_policy: str = "unknown",
) -> list[Statement]:
    """Parse an IAM policy document into a list of Statement objects.

    Handles both single-statement and multi-statement policy documents.
    Normalizes all fields to lists for consistent evaluation.

    Args:
        doc: IAM policy document as a dictionary.
        source_policy: Name/ARN of the source policy for provenance.

    Returns:
        List of parsed Statement objects.

    Raises:
        PolicyParseError: If the document structure is invalid.
    """
    if not isinstance(doc, dict):
        raise PolicyParseError(
            f"Policy document must be a dict, got {type(doc).__name__}"
        )

    statements_raw = doc.get("Statement", [])
    if isinstance(statements_raw, dict):
        statements_raw = [statements_raw]

    if not isinstance(statements_raw, list):
        raise PolicyParseError(
            f"Statement must be a list or dict, got {type(statements_raw).__name__}"
        )

    parsed: list[Statement] = []
    for idx, stmt in enumerate(statements_raw):
        if not isinstance(stmt, dict):
            raise PolicyParseError(
                f"Statement at index {idx} must be a dict, got {type(stmt).__name__}"
            )

        effect_str = stmt.get("Effect", "")
        if effect_str not in ("Allow", "Deny"):
            raise PolicyParseError(
                f"Statement at index {idx} has invalid Effect: '{effect_str}'"
            )

        effect = (
            PermissionEffect.ALLOW if effect_str == "Allow" else PermissionEffect.DENY
        )

        parsed.append(
            Statement(
                sid=stmt.get("Sid", f"stmt_{idx}"),
                effect=effect,
                actions=_normalize_to_list(stmt.get("Action", [])),
                not_actions=_normalize_to_list(stmt.get("NotAction", [])),
                resources=_normalize_to_list(stmt.get("Resource", [])),
                not_resources=_normalize_to_list(stmt.get("NotResource", [])),
                principals=_normalize_principals(stmt.get("Principal", [])),
                not_principals=_normalize_principals(stmt.get("NotPrincipal", [])),
                conditions=stmt.get("Condition", {}),
                source_policy=source_policy,
            )
        )

    return parsed


def expand_wildcards(action: str) -> list[str]:
    """Expand a wildcard action pattern into known matching actions.

    Uses the built-in service action catalog to expand patterns like
    's3:Get*' into specific actions. Returns the original pattern if
    the service is not in the catalog.

    Args:
        action: Action string, potentially with wildcards (e.g., 's3:Get*').

    Returns:
        List of matching concrete actions, or the original pattern if
        no expansion is possible.

    Examples:
        >>> expand_wildcards("s3:Get*")
        ['s3:GetObject', 's3:GetBucketPolicy', ...]
        >>> expand_wildcards("s3:GetObject")
        ['s3:GetObject']
        >>> expand_wildcards("*")
        ['*']
    """
    if action == "*":
        return ["*"]

    if ":" not in action:
        return [action]

    service, action_pattern = action.split(":", 1)
    service_lower = service.lower()

    if service_lower not in _KNOWN_SERVICE_ACTIONS:
        # Unknown service - return as-is, cannot expand
        return [action]

    known_actions = _KNOWN_SERVICE_ACTIONS[service_lower]

    if "*" not in action_pattern and "?" not in action_pattern:
        # No wildcard - return exact match
        return [action]

    # Use fnmatch for glob-style matching
    matched = [
        f"{service}:{a}"
        for a in known_actions
        if fnmatch.fnmatchcase(a, action_pattern)
        or fnmatch.fnmatchcase(a.lower(), action_pattern.lower())
    ]

    return matched if matched else [action]


def match_resource(pattern: str, resource_arn: str) -> bool:
    """Match a resource ARN pattern against a specific resource ARN.

    Supports IAM-style wildcards (* and ?) in the pattern.
    Also handles the special '*' (all resources) pattern.

    Args:
        pattern: Resource ARN pattern, possibly with wildcards.
        resource_arn: The concrete resource ARN to match against.

    Returns:
        True if the resource matches the pattern.

    Examples:
        >>> match_resource("arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket/key.txt")
        True
        >>> match_resource("arn:aws:s3:::*", "arn:aws:s3:::any-bucket")
        True
        >>> match_resource("*", "arn:aws:anything:::anything")
        True
    """
    if pattern == "*":
        return True

    if resource_arn == "*":
        return True

    # Convert IAM wildcard pattern to regex
    regex_pattern = _arn_pattern_to_regex(pattern)
    try:
        return bool(re.fullmatch(regex_pattern, resource_arn, re.IGNORECASE))
    except re.error:
        logger.warning(f"Invalid regex generated from pattern: {pattern}")
        return False


def evaluate_conditions(
    conditions: dict[str, dict[str, Any]],
    context: dict[str, Any],
) -> bool:
    """Evaluate IAM condition block against a request context.

    Supports the following condition operators:
    - StringEquals / StringNotEquals
    - StringLike / StringNotLike
    - ArnEquals / ArnNotEquals
    - ArnLike / ArnNotLike
    - IpAddress / NotIpAddress
    - NumericEquals / NumericNotEquals / NumericLessThan / NumericGreaterThan
    - DateEquals / DateNotEquals / DateLessThan / DateGreaterThan
    - Bool
    - Null
    - StringEqualsIgnoreCase

    All condition operators are ANDed together. Multiple values within
    a single condition key are ORed.

    Args:
        conditions: IAM Condition block from a policy statement.
        context: Request context providing values for condition keys.

    Returns:
        True if all conditions are satisfied, False otherwise.
    """
    if not conditions:
        return True

    for operator, condition_block in conditions.items():
        if not isinstance(condition_block, dict):
            logger.warning(f"Invalid condition block for operator {operator}")
            return False

        # Handle IfExists suffix
        if_exists = operator.endswith("IfExists")
        base_operator = operator.replace("IfExists", "") if if_exists else operator

        # Handle ForAllValues / ForAnyValue prefixes
        quantifier = None
        if base_operator.startswith("ForAllValues:"):
            quantifier = "ForAllValues"
            base_operator = base_operator[len("ForAllValues:"):]
        elif base_operator.startswith("ForAnyValue:"):
            quantifier = "ForAnyValue"
            base_operator = base_operator[len("ForAnyValue:"):]

        for condition_key, condition_values in condition_block.items():
            context_value = context.get(condition_key)

            # IfExists: skip if key not present in context
            if context_value is None:
                if if_exists:
                    continue
                # Null operator checks for key presence
                if base_operator == "Null":
                    if not _evaluate_null(condition_values, context_value):
                        return False
                    continue
                # Key not present and not IfExists -> condition fails
                return False

            # Normalize condition values to list
            if not isinstance(condition_values, list):
                condition_values = [condition_values]

            # Normalize context values for set operators
            context_values_list = (
                context_value
                if isinstance(context_value, list)
                else [context_value]
            )

            if quantifier == "ForAllValues":
                # Every context value must match at least one condition value
                for cv in context_values_list:
                    if not any(
                        _evaluate_single_condition(base_operator, cond_v, cv)
                        for cond_v in condition_values
                    ):
                        return False
            elif quantifier == "ForAnyValue":
                # At least one context value must match at least one condition value
                found = False
                for cv in context_values_list:
                    if any(
                        _evaluate_single_condition(base_operator, cond_v, cv)
                        for cond_v in condition_values
                    ):
                        found = True
                        break
                if not found:
                    return False
            else:
                # Standard: any condition value must match the context value
                matched = any(
                    _evaluate_single_condition(base_operator, cond_v, context_value)
                    for cond_v in condition_values
                )
                if not matched:
                    return False

    return True


# =============================================================================
# Internal Condition Evaluation Helpers
# =============================================================================


def _evaluate_single_condition(
    operator: str, condition_value: Any, context_value: Any
) -> bool:
    """Evaluate a single condition operator against a value pair."""
    evaluators = {
        "StringEquals": _eval_string_equals,
        "StringNotEquals": lambda cv, ctx: not _eval_string_equals(cv, ctx),
        "StringEqualsIgnoreCase": _eval_string_equals_ignore_case,
        "StringNotEqualsIgnoreCase": lambda cv, ctx: not _eval_string_equals_ignore_case(cv, ctx),
        "StringLike": _eval_string_like,
        "StringNotLike": lambda cv, ctx: not _eval_string_like(cv, ctx),
        "ArnEquals": _eval_arn_equals,
        "ArnNotEquals": lambda cv, ctx: not _eval_arn_equals(cv, ctx),
        "ArnLike": _eval_arn_like,
        "ArnNotLike": lambda cv, ctx: not _eval_arn_like(cv, ctx),
        "IpAddress": _eval_ip_address,
        "NotIpAddress": lambda cv, ctx: not _eval_ip_address(cv, ctx),
        "NumericEquals": _eval_numeric_equals,
        "NumericNotEquals": lambda cv, ctx: not _eval_numeric_equals(cv, ctx),
        "NumericLessThan": _eval_numeric_less_than,
        "NumericLessThanEquals": _eval_numeric_less_than_equals,
        "NumericGreaterThan": _eval_numeric_greater_than,
        "NumericGreaterThanEquals": _eval_numeric_greater_than_equals,
        "DateEquals": _eval_date_equals,
        "DateNotEquals": lambda cv, ctx: not _eval_date_equals(cv, ctx),
        "DateLessThan": _eval_date_less_than,
        "DateGreaterThan": _eval_date_greater_than,
        "DateLessThanEquals": _eval_date_less_than_equals,
        "DateGreaterThanEquals": _eval_date_greater_than_equals,
        "Bool": _eval_bool,
        "Null": _evaluate_null,
    }

    evaluator = evaluators.get(operator)
    if evaluator is None:
        logger.warning(f"Unknown condition operator: {operator}")
        return False

    try:
        return evaluator(condition_value, context_value)
    except (ValueError, TypeError) as e:
        logger.debug(
            f"Condition evaluation error for {operator}: {e}"
        )
        return False


def _eval_string_equals(condition_value: Any, context_value: Any) -> bool:
    return str(condition_value) == str(context_value)


def _eval_string_equals_ignore_case(condition_value: Any, context_value: Any) -> bool:
    return str(condition_value).lower() == str(context_value).lower()


def _eval_string_like(condition_value: Any, context_value: Any) -> bool:
    """Glob-style matching with * and ? wildcards."""
    pattern = str(condition_value)
    value = str(context_value)
    return fnmatch.fnmatchcase(value, pattern)


def _eval_arn_equals(condition_value: Any, context_value: Any) -> bool:
    return str(condition_value) == str(context_value)


def _eval_arn_like(condition_value: Any, context_value: Any) -> bool:
    """ARN matching with wildcards in individual ARN segments."""
    pattern = str(condition_value)
    value = str(context_value)
    regex_pattern = _arn_pattern_to_regex(pattern)
    try:
        return bool(re.fullmatch(regex_pattern, value, re.IGNORECASE))
    except re.error:
        return False


def _eval_ip_address(condition_value: Any, context_value: Any) -> bool:
    """Check if an IP address falls within a CIDR range."""
    try:
        network = ipaddress.ip_network(str(condition_value), strict=False)
        address = ipaddress.ip_address(str(context_value))
        return address in network
    except ValueError:
        return False


def _eval_numeric_equals(condition_value: Any, context_value: Any) -> bool:
    return float(condition_value) == float(context_value)


def _eval_numeric_less_than(condition_value: Any, context_value: Any) -> bool:
    return float(context_value) < float(condition_value)


def _eval_numeric_less_than_equals(condition_value: Any, context_value: Any) -> bool:
    return float(context_value) <= float(condition_value)


def _eval_numeric_greater_than(condition_value: Any, context_value: Any) -> bool:
    return float(context_value) > float(condition_value)


def _eval_numeric_greater_than_equals(condition_value: Any, context_value: Any) -> bool:
    return float(context_value) >= float(condition_value)


def _eval_date_equals(condition_value: Any, context_value: Any) -> bool:
    d1 = _parse_datetime(condition_value)
    d2 = _parse_datetime(context_value)
    return d1 == d2 if d1 and d2 else False


def _eval_date_less_than(condition_value: Any, context_value: Any) -> bool:
    d_threshold = _parse_datetime(condition_value)
    d_context = _parse_datetime(context_value)
    return d_context < d_threshold if d_threshold and d_context else False


def _eval_date_greater_than(condition_value: Any, context_value: Any) -> bool:
    d_threshold = _parse_datetime(condition_value)
    d_context = _parse_datetime(context_value)
    return d_context > d_threshold if d_threshold and d_context else False


def _eval_date_less_than_equals(condition_value: Any, context_value: Any) -> bool:
    d_threshold = _parse_datetime(condition_value)
    d_context = _parse_datetime(context_value)
    return d_context <= d_threshold if d_threshold and d_context else False


def _eval_date_greater_than_equals(condition_value: Any, context_value: Any) -> bool:
    d_threshold = _parse_datetime(condition_value)
    d_context = _parse_datetime(context_value)
    return d_context >= d_threshold if d_threshold and d_context else False


def _eval_bool(condition_value: Any, context_value: Any) -> bool:
    cv = str(condition_value).lower() in ("true", "1")
    ctx = str(context_value).lower() in ("true", "1")
    return cv == ctx


def _evaluate_null(condition_value: Any, context_value: Any) -> bool:
    """Null condition: checks if key exists (true) or doesn't (false)."""
    expected_null = str(condition_value).lower() in ("true", "1")
    is_null = context_value is None
    return expected_null == is_null


def _parse_datetime(value: Any) -> Optional[datetime]:
    """Parse a datetime value from various formats."""
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        pass
    # Try epoch seconds
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (ValueError, TypeError):
        return None


# =============================================================================
# Internal Helper Functions
# =============================================================================


def _normalize_to_list(value: Any) -> list[str]:
    """Normalize a string or list to a list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _normalize_principals(value: Any) -> list[str]:
    """Normalize Principal/NotPrincipal field to a list of strings."""
    if value == "*":
        return ["*"]
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        # {"AWS": "arn:...", "Service": "s3.amazonaws.com"}
        principals: list[str] = []
        for principal_type, principal_values in value.items():
            if isinstance(principal_values, str):
                principals.append(principal_values)
            elif isinstance(principal_values, list):
                principals.extend(str(v) for v in principal_values)
        return principals
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _arn_pattern_to_regex(pattern: str) -> str:
    """Convert an ARN wildcard pattern to a regex pattern.

    Handles * (match anything) and ? (match single char) wildcards
    while escaping all other regex metacharacters.
    """
    # Escape everything except our wildcards
    parts = re.split(r"(\*|\?)", pattern)
    regex_parts = []
    for part in parts:
        if part == "*":
            regex_parts.append(".*")
        elif part == "?":
            regex_parts.append(".")
        else:
            regex_parts.append(re.escape(part))
    return "".join(regex_parts)


def _utcnow() -> datetime:
    """Return current UTC time with timezone info."""
    return datetime.now(timezone.utc)


def _action_matches(action_pattern: str, target_action: str) -> bool:
    """Check if an action pattern matches a target action.

    Supports wildcards (* and ?) in the pattern.

    Args:
        action_pattern: Pattern from a policy statement (e.g., 's3:Get*').
        target_action: The action to check (e.g., 's3:GetObject').

    Returns:
        True if the pattern matches the action.
    """
    if action_pattern == "*":
        return True
    return fnmatch.fnmatchcase(
        target_action.lower(), action_pattern.lower()
    )


def _statement_matches_action(stmt: Statement, action: str) -> bool:
    """Determine if a statement applies to the given action.

    Handles both Action and NotAction fields.
    """
    if stmt.uses_not_action:
        # NotAction: matches everything EXCEPT the listed actions
        for not_action in stmt.not_actions:
            if _action_matches(not_action, action):
                return False
        return True
    else:
        # Action: matches only the listed actions
        for stmt_action in stmt.actions:
            if _action_matches(stmt_action, action):
                return True
        return False


def _statement_matches_resource(stmt: Statement, resource: str) -> bool:
    """Determine if a statement applies to the given resource.

    Handles both Resource and NotResource fields.
    """
    if stmt.uses_not_resource:
        # NotResource: matches everything EXCEPT the listed resources
        for not_resource in stmt.not_resources:
            if match_resource(not_resource, resource):
                return False
        return True
    else:
        # Resource: matches only the listed resources
        for stmt_resource in stmt.resources:
            if match_resource(stmt_resource, resource):
                return True
        return False


def _extract_account_from_arn(arn: str) -> str:
    """Extract the account ID from an ARN.

    Args:
        arn: An AWS ARN string.

    Returns:
        The account ID, or empty string if not parseable.
    """
    parts = arn.split(":")
    if len(parts) >= 5:
        return parts[4]
    return ""


# =============================================================================
# Principal Matching
# =============================================================================


def match_principal(
    statement_principals: list[str],
    request_principal: str,
    account_id: str = "",
) -> bool:
    """Match a request principal against a statement's principal list.

    Handles:
    - Wildcard "*" (matches everyone)
    - Exact ARN matches
    - Account-level matches (just account ID)
    - Service principals (e.g., 'lambda.amazonaws.com')

    Args:
        statement_principals: Principals from the policy statement.
        request_principal: The ARN of the requesting principal.
        account_id: The account ID of the requesting principal.

    Returns:
        True if the principal matches.
    """
    if not statement_principals:
        return True  # No principal restriction

    for principal in statement_principals:
        if principal == "*":
            return True
        if principal == request_principal:
            return True
        # Account-level match
        if account_id and principal == account_id:
            return True
        # Root account match
        if principal.endswith(":root") and account_id:
            principal_account = _extract_account_from_arn(principal)
            if principal_account == account_id:
                return True
        # Wildcard ARN matching
        if "*" in principal or "?" in principal:
            if match_resource(principal, request_principal):
                return True

    return False


# =============================================================================
# IAM Policy Simulation (Optional boto3 Integration)
# =============================================================================


class IAMSimulator:
    """Optional integration with AWS IAM SimulatePrincipalPolicy.

    Provides a way to validate local evaluation against the AWS
    authoritative evaluation engine. Requires boto3 and appropriate
    IAM permissions.
    """

    def __init__(self, boto3_client: Any = None, region: str = "us-east-1") -> None:
        """Initialize the IAM simulator.

        Args:
            boto3_client: Pre-configured boto3 IAM client. If None,
                will attempt to create one using boto3.
            region: AWS region for the IAM client.
        """
        self._client = boto3_client
        self._region = region

    def _get_client(self) -> Any:
        """Lazily initialize the IAM client."""
        if self._client is None:
            try:
                import boto3  # type: ignore[import-untyped]
                self._client = boto3.client("iam", region_name=self._region)
            except ImportError:
                raise SimulationError(
                    "boto3 is required for IAM simulation. "
                    "Install it with: pip install boto3"
                )
            except Exception as e:
                raise SimulationError(
                    f"Failed to create IAM client: {e}"
                )
        return self._client

    def simulate_principal_policy(
        self,
        principal_arn: str,
        actions: list[str],
        resource_arns: list[str] | None = None,
        context_entries: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Simulate policy evaluation using AWS IAM.

        Calls iam:SimulatePrincipalPolicy to get the authoritative
        evaluation result from AWS.

        Args:
            principal_arn: ARN of the principal to simulate for.
            actions: List of actions to evaluate.
            resource_arns: Optional resource ARNs to evaluate against.
            context_entries: Optional context entries for condition evaluation.

        Returns:
            List of evaluation results from AWS.

        Raises:
            SimulationError: If the simulation call fails.
        """
        client = self._get_client()

        kwargs: dict[str, Any] = {
            "PolicySourceArn": principal_arn,
            "ActionNames": actions,
        }

        if resource_arns:
            kwargs["ResourceArns"] = resource_arns

        if context_entries:
            kwargs["ContextEntries"] = context_entries

        try:
            results: list[dict[str, Any]] = []
            paginator = client.get_paginator("simulate_principal_policy")
            for page in paginator.paginate(**kwargs):
                results.extend(page.get("EvaluationResults", []))
            return results
        except Exception as e:
            raise SimulationError(
                f"IAM simulation failed for {principal_arn}: {e}"
            )

    def simulate_and_compare(
        self,
        principal_arn: str,
        action: str,
        resource: str,
        local_result: PermissionEffect,
    ) -> dict[str, Any]:
        """Simulate and compare against local evaluation.

        Args:
            principal_arn: ARN of the principal.
            action: The action to evaluate.
            resource: The resource ARN.
            local_result: The locally computed permission effect.

        Returns:
            Comparison result with both local and AWS evaluations.
        """
        try:
            aws_results = self.simulate_principal_policy(
                principal_arn=principal_arn,
                actions=[action],
                resource_arns=[resource] if resource != "*" else None,
            )

            aws_decision = "UNKNOWN"
            if aws_results:
                aws_decision = aws_results[0].get("EvalDecision", "UNKNOWN")

            # Map AWS decision to our effect
            aws_effect_map = {
                "allowed": PermissionEffect.ALLOW,
                "explicitDeny": PermissionEffect.DENY,
                "implicitDeny": PermissionEffect.DENY,
            }
            aws_effect = aws_effect_map.get(aws_decision, PermissionEffect.DENY)

            return {
                "action": action,
                "resource": resource,
                "local_result": local_result.value,
                "aws_result": aws_decision,
                "match": local_result == aws_effect,
                "aws_raw": aws_results[0] if aws_results else None,
            }
        except SimulationError as e:
            return {
                "action": action,
                "resource": resource,
                "local_result": local_result.value,
                "aws_result": "ERROR",
                "match": None,
                "error": str(e),
            }


# =============================================================================
# Effective Permission Analyzer
# =============================================================================


class EffectivePermissionAnalyzer:
    """Resolves effective permissions for an Agent by layering all policy types.

    Implements the complete AWS authorization evaluation logic:
    1. If there's an explicit deny in ANY policy -> DENY
    2. If SCP doesn't allow -> DENY (implicit)
    3. If Permission Boundary doesn't allow -> DENY (implicit)
    4. If Session Policy is present and doesn't allow -> DENY (implicit)
    5. If Identity Policy OR Resource Policy allows -> ALLOW
    6. Otherwise -> DENY (implicit)

    Usage:
        analyzer = EffectivePermissionAnalyzer(agent)
        analyzer.add_identity_policies(policies)
        analyzer.add_scps(scp_policies)
        result = analyzer.evaluate(action="s3:GetObject", resource="arn:aws:s3:::bucket/key")
    """

    def __init__(self, agent: Agent) -> None:
        """Initialize the analyzer for a specific agent.

        Args:
            agent: The Agent whose permissions to analyze.
        """
        self._agent = agent
        self._identity_layers: list[PolicyLayer] = []
        self._resource_layers: list[PolicyLayer] = []
        self._boundary_layers: list[PolicyLayer] = []
        self._scp_layers: list[PolicyLayer] = []
        self._session_layers: list[PolicyLayer] = []
        self._simulator: Optional[IAMSimulator] = None

        # Auto-load identity policies from agent
        self._load_agent_policies()

    @property
    def agent(self) -> Agent:
        """The agent being analyzed."""
        return self._agent

    def _load_agent_policies(self) -> None:
        """Load policies from the agent's identity_policies field."""
        for idx, policy_doc in enumerate(self._agent.identity_policies):
            policy_name = policy_doc.get(
                "PolicyName", f"agent_identity_policy_{idx}"
            )
            try:
                # Handle both raw documents and wrapped policy docs
                doc = policy_doc.get("PolicyDocument", policy_doc)
                statements = parse_policy_document(doc, source_policy=policy_name)
                self._identity_layers.append(
                    PolicyLayer(
                        name=policy_name,
                        source=PermissionSource.IDENTITY_POLICY,
                        statements=statements,
                    )
                )
            except PolicyParseError as e:
                logger.warning(
                    f"Failed to parse agent identity policy {policy_name}: {e}"
                )

    def add_identity_policies(
        self,
        policies: list[dict[str, Any]],
        source_name: str = "managed_policy",
    ) -> None:
        """Add identity policies (inline or managed) for evaluation.

        Args:
            policies: List of IAM policy documents.
            source_name: Base name for the policy source.
        """
        for idx, doc in enumerate(policies):
            name = f"{source_name}_{idx}"
            try:
                statements = parse_policy_document(doc, source_policy=name)
                self._identity_layers.append(
                    PolicyLayer(
                        name=name,
                        source=PermissionSource.IDENTITY_POLICY,
                        statements=statements,
                    )
                )
            except PolicyParseError as e:
                logger.warning(f"Failed to parse identity policy {name}: {e}")

    def add_resource_policies(
        self,
        policies: list[dict[str, Any]],
        resource_arns: list[str] | None = None,
    ) -> None:
        """Add resource-based policies for evaluation.

        Args:
            policies: List of resource policy documents.
            resource_arns: Associated resource ARNs for context.
        """
        for idx, doc in enumerate(policies):
            arn = resource_arns[idx] if resource_arns and idx < len(resource_arns) else ""
            name = f"resource_policy_{idx}"
            try:
                statements = parse_policy_document(doc, source_policy=name)
                self._resource_layers.append(
                    PolicyLayer(
                        name=name,
                        source=PermissionSource.RESOURCE_POLICY,
                        statements=statements,
                        policy_arn=arn,
                    )
                )
            except PolicyParseError as e:
                logger.warning(f"Failed to parse resource policy {name}: {e}")

    def add_permission_boundaries(
        self,
        policies: list[dict[str, Any]],
    ) -> None:
        """Add permission boundary policies for evaluation.

        Args:
            policies: List of permission boundary policy documents.
        """
        for idx, doc in enumerate(policies):
            name = f"permission_boundary_{idx}"
            try:
                statements = parse_policy_document(doc, source_policy=name)
                self._boundary_layers.append(
                    PolicyLayer(
                        name=name,
                        source=PermissionSource.PERMISSION_BOUNDARY,
                        statements=statements,
                    )
                )
            except PolicyParseError as e:
                logger.warning(f"Failed to parse permission boundary {name}: {e}")

    def add_scps(self, policies: list[dict[str, Any]]) -> None:
        """Add Service Control Policies for evaluation.

        Args:
            policies: List of SCP policy documents.
        """
        for idx, doc in enumerate(policies):
            name = f"scp_{idx}"
            try:
                statements = parse_policy_document(doc, source_policy=name)
                self._scp_layers.append(
                    PolicyLayer(
                        name=name,
                        source=PermissionSource.SCP,
                        statements=statements,
                    )
                )
            except PolicyParseError as e:
                logger.warning(f"Failed to parse SCP {name}: {e}")

    def add_session_policies(self, policies: list[dict[str, Any]]) -> None:
        """Add session policies for evaluation.

        Args:
            policies: List of session policy documents.
        """
        for idx, doc in enumerate(policies):
            name = f"session_policy_{idx}"
            try:
                statements = parse_policy_document(doc, source_policy=name)
                self._session_layers.append(
                    PolicyLayer(
                        name=name,
                        source=PermissionSource.SESSION_POLICY,
                        statements=statements,
                    )
                )
            except PolicyParseError as e:
                logger.warning(f"Failed to parse session policy {name}: {e}")

    def set_simulator(self, simulator: IAMSimulator) -> None:
        """Set an IAM simulator for cross-validation.

        Args:
            simulator: Configured IAMSimulator instance.
        """
        self._simulator = simulator

    def evaluate(
        self,
        action: str,
        resource: str,
        context: EvaluationContext | None = None,
    ) -> EffectivePermission:
        """Evaluate the effective permission for an action+resource pair.

        Follows the AWS evaluation logic:
        1. Check for explicit deny across ALL layers -> DENY
        2. Check SCPs (if present) allow the action -> DENY if not
        3. Check Permission Boundaries allow the action -> DENY if not
        4. Check Session Policies (if present) allow the action -> DENY if not
        5. Check Identity Policies or Resource Policies allow -> ALLOW
        6. Otherwise -> implicit DENY

        Args:
            action: The AWS action to evaluate (e.g., 's3:GetObject').
            resource: The resource ARN to evaluate against.
            context: Optional evaluation context for condition evaluation.

        Returns:
            EffectivePermission with the determination and full provenance.
        """
        eval_context = context or EvaluationContext(
            action=action,
            resource=resource,
            principal_arn=self._agent.iam_role_arn,
        )
        context_dict = self._build_context_dict(eval_context)

        contributing_policies: list[Permission] = []
        evaluation_path: list[str] = []
        conditions_required: dict[str, Any] = {}

        # Step 1: Check for explicit deny in ANY layer
        all_layers = (
            self._identity_layers
            + self._resource_layers
            + self._boundary_layers
            + self._scp_layers
            + self._session_layers
        )

        for layer in all_layers:
            deny_result = self._check_explicit_deny(
                layer, action, resource, context_dict
            )
            if deny_result is not None:
                evaluation_path.append(
                    f"EXPLICIT_DENY in {layer.name} ({layer.source.value})"
                )
                contributing_policies.append(deny_result)
                return EffectivePermission.create(
                    action=action,
                    resource=resource,
                    effect=PermissionEffect.DENY,
                    contributing_policies=contributing_policies,
                    evaluation_path=evaluation_path,
                )

        evaluation_path.append("No explicit deny found in any layer")

        # Step 2: Check SCPs (must allow if present)
        if self._scp_layers:
            scp_allows = self._check_layers_allow(
                self._scp_layers, action, resource, context_dict
            )
            if not scp_allows:
                evaluation_path.append("SCP does not allow action (implicit deny)")
                return EffectivePermission.create(
                    action=action,
                    resource=resource,
                    effect=PermissionEffect.DENY,
                    contributing_policies=contributing_policies,
                    evaluation_path=evaluation_path,
                )
            evaluation_path.append("SCP allows action")

        # Step 3: Check Permission Boundaries (must allow if present)
        if self._boundary_layers:
            boundary_allows = self._check_layers_allow(
                self._boundary_layers, action, resource, context_dict
            )
            if not boundary_allows:
                evaluation_path.append(
                    "Permission boundary does not allow action (implicit deny)"
                )
                return EffectivePermission.create(
                    action=action,
                    resource=resource,
                    effect=PermissionEffect.DENY,
                    contributing_policies=contributing_policies,
                    evaluation_path=evaluation_path,
                )
            evaluation_path.append("Permission boundary allows action")

        # Step 4: Check Session Policies (must allow if present)
        if self._session_layers:
            session_allows = self._check_layers_allow(
                self._session_layers, action, resource, context_dict
            )
            if not session_allows:
                evaluation_path.append(
                    "Session policy does not allow action (implicit deny)"
                )
                return EffectivePermission.create(
                    action=action,
                    resource=resource,
                    effect=PermissionEffect.DENY,
                    contributing_policies=contributing_policies,
                    evaluation_path=evaluation_path,
                )
            evaluation_path.append("Session policy allows action")

        # Step 5: Check Identity Policies and Resource Policies for allow
        identity_allow = self._find_allow_permission(
            self._identity_layers, action, resource, context_dict
        )
        resource_allow = self._find_allow_permission(
            self._resource_layers, action, resource, context_dict
        )

        if identity_allow is not None:
            contributing_policies.append(identity_allow)
            evaluation_path.append(
                f"Identity policy allows action: {identity_allow.source.value}"
            )
            # Check for condition dependencies
            conds = self._find_conditions(
                self._identity_layers, action, resource
            )
            if conds:
                conditions_required = conds

            return EffectivePermission.create(
                action=action,
                resource=resource,
                effect=PermissionEffect.ALLOW,
                contributing_policies=contributing_policies,
                evaluation_path=evaluation_path,
                conditions_required=conditions_required,
            )

        if resource_allow is not None:
            contributing_policies.append(resource_allow)
            evaluation_path.append(
                f"Resource policy allows action: {resource_allow.source.value}"
            )
            conds = self._find_conditions(
                self._resource_layers, action, resource
            )
            if conds:
                conditions_required = conds

            return EffectivePermission.create(
                action=action,
                resource=resource,
                effect=PermissionEffect.ALLOW,
                contributing_policies=contributing_policies,
                evaluation_path=evaluation_path,
                conditions_required=conditions_required,
            )

        # Step 5b: Check if there are conditions that might allow
        all_identity_resource = self._identity_layers + self._resource_layers
        condition_dependent = self._check_condition_dependent(
            all_identity_resource, action, resource
        )
        if condition_dependent:
            evaluation_path.append(
                "Action may be allowed depending on conditions"
            )
            return EffectivePermission.create(
                action=action,
                resource=resource,
                effect=PermissionEffect.CONDITION_DEPENDENT,
                contributing_policies=contributing_policies,
                evaluation_path=evaluation_path,
                conditions_required=condition_dependent,
            )

        # Step 6: Implicit deny
        evaluation_path.append("No policy grants access (implicit deny)")
        return EffectivePermission.create(
            action=action,
            resource=resource,
            effect=PermissionEffect.DENY,
            contributing_policies=contributing_policies,
            evaluation_path=evaluation_path,
        )

    def evaluate_batch(
        self,
        action_resource_pairs: list[tuple[str, str]],
        context: EvaluationContext | None = None,
    ) -> list[EffectivePermission]:
        """Evaluate multiple action+resource pairs efficiently.

        Args:
            action_resource_pairs: List of (action, resource) tuples.
            context: Optional shared evaluation context.

        Returns:
            List of EffectivePermission results in the same order.
        """
        results: list[EffectivePermission] = []
        for action, resource in action_resource_pairs:
            ctx = EvaluationContext(
                action=action,
                resource=resource,
                principal_arn=self._agent.iam_role_arn,
            ) if context is None else context
            results.append(self.evaluate(action, resource, ctx))
        return results

    def _build_context_dict(self, context: EvaluationContext) -> dict[str, Any]:
        """Build a flat context dictionary for condition evaluation."""
        ctx: dict[str, Any] = {
            "aws:PrincipalArn": context.principal_arn,
            "aws:SourceIp": context.source_ip,
            "aws:SecureTransport": str(context.secure_transport).lower(),
        }
        if context.current_time:
            ctx["aws:CurrentTime"] = context.current_time
        else:
            ctx["aws:CurrentTime"] = _utcnow().isoformat()

        if context.account_id:
            ctx["aws:PrincipalAccount"] = context.account_id

        # Add resource tags
        for key, value in context.tags.items():
            ctx[f"aws:ResourceTag/{key}"] = value

        # Add any custom context
        ctx.update(context.request_context)

        return ctx

    def _check_explicit_deny(
        self,
        layer: PolicyLayer,
        action: str,
        resource: str,
        context_dict: dict[str, Any],
    ) -> Optional[Permission]:
        """Check if a layer has an explicit deny for the action+resource.

        Returns a Permission object if denied, None otherwise.
        """
        for stmt in layer.statements:
            if not stmt.is_deny:
                continue
            if not _statement_matches_action(stmt, action):
                continue
            if not _statement_matches_resource(stmt, resource):
                continue
            # Evaluate conditions
            if stmt.conditions and not evaluate_conditions(
                stmt.conditions, context_dict
            ):
                continue
            # Explicit deny found
            return Permission.deny(
                action=action,
                resource=resource,
                source=layer.source,
                conditions=stmt.conditions,
            )
        return None

    def _check_layers_allow(
        self,
        layers: list[PolicyLayer],
        action: str,
        resource: str,
        context_dict: dict[str, Any],
    ) -> bool:
        """Check if any statement in the layers allows the action+resource.

        Used for SCPs, boundaries, and session policies where at least
        one allow is needed.
        """
        for layer in layers:
            for stmt in layer.statements:
                if not stmt.is_allow:
                    continue
                if not _statement_matches_action(stmt, action):
                    continue
                if not _statement_matches_resource(stmt, resource):
                    continue
                if stmt.conditions and not evaluate_conditions(
                    stmt.conditions, context_dict
                ):
                    continue
                return True
        return False

    def _find_allow_permission(
        self,
        layers: list[PolicyLayer],
        action: str,
        resource: str,
        context_dict: dict[str, Any],
    ) -> Optional[Permission]:
        """Find an allow permission in the layers.

        Returns the first matching Permission or None.
        """
        for layer in layers:
            for stmt in layer.statements:
                if not stmt.is_allow:
                    continue
                if not _statement_matches_action(stmt, action):
                    continue
                if not _statement_matches_resource(stmt, resource):
                    continue
                if stmt.conditions and not evaluate_conditions(
                    stmt.conditions, context_dict
                ):
                    continue
                return Permission.allow(
                    action=action,
                    resource=resource,
                    source=layer.source,
                    conditions=stmt.conditions,
                )
        return None

    def _find_conditions(
        self,
        layers: list[PolicyLayer],
        action: str,
        resource: str,
    ) -> dict[str, Any]:
        """Collect all conditions from matching allow statements."""
        all_conditions: dict[str, Any] = {}
        for layer in layers:
            for stmt in layer.statements:
                if not stmt.is_allow:
                    continue
                if not _statement_matches_action(stmt, action):
                    continue
                if not _statement_matches_resource(stmt, resource):
                    continue
                if stmt.conditions:
                    all_conditions.update(stmt.conditions)
        return all_conditions

    def _check_condition_dependent(
        self,
        layers: list[PolicyLayer],
        action: str,
        resource: str,
    ) -> dict[str, Any]:
        """Check if there are allow statements with unsatisfied conditions.

        Returns the conditions that would need to be met for access.
        """
        for layer in layers:
            for stmt in layer.statements:
                if not stmt.is_allow:
                    continue
                if not _statement_matches_action(stmt, action):
                    continue
                if not _statement_matches_resource(stmt, resource):
                    continue
                if stmt.conditions:
                    return stmt.conditions
        return {}


# =============================================================================
# Permission Resolver
# =============================================================================


class PermissionResolver:
    """High-level resolver that combines all policy layers and produces
    EffectivePermission objects with full provenance.

    Orchestrates the EffectivePermissionAnalyzer with additional
    cross-account resolution and comprehensive reporting.

    Usage:
        resolver = PermissionResolver(agent)
        resolver.load_identity_policies(inline_policies, managed_policies)
        resolver.load_resource_policies(bucket_policies)
        resolver.load_scps(org_scps)
        resolver.load_permission_boundaries(boundary_docs)

        result = resolver.resolve("s3:GetObject", "arn:aws:s3:::bucket/key")
        report = resolver.generate_report(actions_to_check)
    """

    def __init__(
        self,
        agent: Agent,
        account_id: str = "",
        simulator: Optional[IAMSimulator] = None,
    ) -> None:
        """Initialize the resolver.

        Args:
            agent: The Agent to resolve permissions for.
            account_id: The AWS account ID for cross-account checks.
            simulator: Optional IAM simulator for AWS cross-validation.
        """
        self._agent = agent
        self._account_id = account_id or _extract_account_from_arn(agent.iam_role_arn)
        self._analyzer = EffectivePermissionAnalyzer(agent)
        self._simulator = simulator

        if simulator:
            self._analyzer.set_simulator(simulator)

        self._resolved_cache: dict[tuple[str, str], EffectivePermission] = {}

    @property
    def agent(self) -> Agent:
        """The agent being resolved."""
        return self._agent

    @property
    def account_id(self) -> str:
        """The resolved account ID."""
        return self._account_id

    def load_identity_policies(
        self,
        inline_policies: list[dict[str, Any]] | None = None,
        managed_policies: list[dict[str, Any]] | None = None,
    ) -> None:
        """Load identity policies (inline and managed).

        Args:
            inline_policies: List of inline policy documents.
            managed_policies: List of managed policy documents.
        """
        if inline_policies:
            self._analyzer.add_identity_policies(
                inline_policies, source_name="inline_policy"
            )
        if managed_policies:
            self._analyzer.add_identity_policies(
                managed_policies, source_name="managed_policy"
            )

    def load_resource_policies(
        self,
        policies: list[dict[str, Any]],
        resource_arns: list[str] | None = None,
    ) -> None:
        """Load resource-based policies.

        Args:
            policies: List of resource policy documents.
            resource_arns: Associated resource ARNs.
        """
        self._analyzer.add_resource_policies(policies, resource_arns)

    def load_scps(self, policies: list[dict[str, Any]]) -> None:
        """Load Service Control Policies.

        Args:
            policies: List of SCP documents.
        """
        self._analyzer.add_scps(policies)

    def load_permission_boundaries(
        self, policies: list[dict[str, Any]]
    ) -> None:
        """Load permission boundary policies.

        Args:
            policies: List of permission boundary documents.
        """
        self._analyzer.add_permission_boundaries(policies)

    def load_session_policies(self, policies: list[dict[str, Any]]) -> None:
        """Load session policies.

        Args:
            policies: List of session policy documents.
        """
        self._analyzer.add_session_policies(policies)

    def resolve(
        self,
        action: str,
        resource: str,
        context: EvaluationContext | None = None,
        use_cache: bool = True,
    ) -> EffectivePermission:
        """Resolve the effective permission for an action+resource pair.

        Args:
            action: AWS action to evaluate.
            resource: Resource ARN to evaluate against.
            context: Optional evaluation context.
            use_cache: Whether to use cached results.

        Returns:
            EffectivePermission with full provenance.
        """
        cache_key = (action, resource)

        if use_cache and cache_key in self._resolved_cache:
            return self._resolved_cache[cache_key]

        result = self._analyzer.evaluate(action, resource, context)
        self._resolved_cache[cache_key] = result
        return result

    def resolve_batch(
        self,
        action_resource_pairs: list[tuple[str, str]],
        context: EvaluationContext | None = None,
    ) -> list[EffectivePermission]:
        """Resolve multiple action+resource pairs.

        Args:
            action_resource_pairs: List of (action, resource) tuples.
            context: Optional shared evaluation context.

        Returns:
            List of EffectivePermission results.
        """
        return [
            self.resolve(action, resource, context)
            for action, resource in action_resource_pairs
        ]

    def resolve_cross_account(
        self,
        action: str,
        resource: str,
        resource_account_id: str,
        resource_policy: dict[str, Any] | None = None,
    ) -> EffectivePermission:
        """Resolve a cross-account permission request.

        Cross-account access requires BOTH:
        1. The identity policy in the source account allows the action
        2. The resource policy in the target account allows the principal

        Args:
            action: AWS action to evaluate.
            resource: Resource ARN in the target account.
            resource_account_id: Account ID of the resource owner.
            resource_policy: Resource policy from the target account.

        Returns:
            EffectivePermission with cross-account evaluation path.
        """
        evaluation_path: list[str] = []
        contributing_policies: list[Permission] = []

        is_cross_account = resource_account_id != self._account_id
        evaluation_path.append(
            f"Cross-account: source={self._account_id}, target={resource_account_id}"
            if is_cross_account
            else f"Same-account: {self._account_id}"
        )

        # For same-account, use standard evaluation
        if not is_cross_account:
            return self.resolve(action, resource)

        # Cross-account: check identity policy allows
        identity_result = self._analyzer.evaluate(action, resource)

        if identity_result.effect == PermissionEffect.DENY:
            evaluation_path.append("Identity policy denies (or does not allow)")
            return EffectivePermission.create(
                action=action,
                resource=resource,
                effect=PermissionEffect.DENY,
                contributing_policies=identity_result.contributing_policies,
                evaluation_path=evaluation_path
                + identity_result.evaluation_path,
            )

        # Cross-account: check resource policy allows the principal
        if resource_policy:
            resource_allows = self._evaluate_resource_policy_for_principal(
                resource_policy, action, resource
            )
            if not resource_allows:
                evaluation_path.append(
                    "Resource policy does not allow cross-account principal"
                )
                return EffectivePermission.create(
                    action=action,
                    resource=resource,
                    effect=PermissionEffect.DENY,
                    contributing_policies=contributing_policies,
                    evaluation_path=evaluation_path,
                )
            evaluation_path.append("Resource policy allows cross-account access")
        else:
            evaluation_path.append(
                "No resource policy provided - cannot confirm cross-account access"
            )
            return EffectivePermission.create(
                action=action,
                resource=resource,
                effect=PermissionEffect.CONDITION_DEPENDENT,
                contributing_policies=contributing_policies,
                evaluation_path=evaluation_path,
                conditions_required={
                    "cross_account": "Resource policy required for cross-account access"
                },
            )

        # Both sides allow
        evaluation_path.append("Cross-account access ALLOWED")
        return EffectivePermission.create(
            action=action,
            resource=resource,
            effect=PermissionEffect.ALLOW,
            contributing_policies=identity_result.contributing_policies,
            evaluation_path=evaluation_path,
        )

    def _evaluate_resource_policy_for_principal(
        self,
        policy_doc: dict[str, Any],
        action: str,
        resource: str,
    ) -> bool:
        """Check if a resource policy allows our principal.

        Args:
            policy_doc: The resource policy document.
            action: The action to check.
            resource: The resource ARN.

        Returns:
            True if the policy allows the principal.
        """
        try:
            statements = parse_policy_document(policy_doc, "resource_policy")
        except PolicyParseError:
            return False

        principal_arn = self._agent.iam_role_arn
        for stmt in statements:
            if not stmt.is_allow:
                continue
            if not _statement_matches_action(stmt, action):
                continue
            if not _statement_matches_resource(stmt, resource):
                continue
            # Check principal matching
            if stmt.principals:
                if not match_principal(
                    stmt.principals, principal_arn, self._account_id
                ):
                    continue
            return True
        return False

    def clear_cache(self) -> None:
        """Clear the resolution cache."""
        self._resolved_cache.clear()

    def generate_report(
        self,
        actions_to_check: list[tuple[str, str]] | None = None,
        include_wildcards: bool = False,
    ) -> PermissionReport:
        """Generate a comprehensive permission report for the agent.

        Args:
            actions_to_check: Specific (action, resource) pairs to evaluate.
                If None, evaluates all actions found in loaded policies.
            include_wildcards: Whether to expand wildcards in the report.

        Returns:
            PermissionReport with all effective permissions and summary.
        """
        if actions_to_check is None:
            actions_to_check = self._discover_actions_from_policies()

        if include_wildcards:
            expanded_pairs: list[tuple[str, str]] = []
            for action, resource in actions_to_check:
                expanded_actions = expand_wildcards(action)
                for exp_action in expanded_actions:
                    expanded_pairs.append((exp_action, resource))
            actions_to_check = expanded_pairs

        effective_permissions: list[EffectivePermission] = []
        for action, resource in actions_to_check:
            result = self.resolve(action, resource)
            effective_permissions.append(result)

        # Build summary
        summary = {
            "total_evaluated": len(effective_permissions),
            "allowed": sum(
                1 for ep in effective_permissions
                if ep.effect == PermissionEffect.ALLOW
            ),
            "denied": sum(
                1 for ep in effective_permissions
                if ep.effect == PermissionEffect.DENY
            ),
            "condition_dependent": sum(
                1 for ep in effective_permissions
                if ep.effect == PermissionEffect.CONDITION_DEPENDENT
            ),
        }

        # Generate findings
        findings = self._generate_findings(effective_permissions)

        return PermissionReport(
            agent_id=self._agent.agent_id,
            agent_name=self._agent.name,
            iam_role_arn=self._agent.iam_role_arn,
            evaluated_at=_utcnow(),
            effective_permissions=effective_permissions,
            summary=summary,
            findings=findings,
        )

    def _discover_actions_from_policies(self) -> list[tuple[str, str]]:
        """Extract all action+resource pairs from loaded policies."""
        pairs: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        all_layers = (
            self._analyzer._identity_layers
            + self._analyzer._resource_layers
            + self._analyzer._boundary_layers
            + self._analyzer._scp_layers
            + self._analyzer._session_layers
        )

        for layer in all_layers:
            for stmt in layer.statements:
                actions = stmt.actions if stmt.actions else ["*"]
                resources = stmt.resources if stmt.resources else ["*"]

                for action in actions:
                    for resource in resources:
                        key = (action, resource)
                        if key not in seen:
                            seen.add(key)
                            pairs.append(key)

        return pairs

    def _generate_findings(
        self, permissions: list[EffectivePermission]
    ) -> list[str]:
        """Generate security findings from effective permissions.

        Args:
            permissions: The evaluated effective permissions.

        Returns:
            List of finding descriptions.
        """
        findings: list[str] = []

        # Check for overly permissive actions
        for ep in permissions:
            if ep.effect != PermissionEffect.ALLOW:
                continue

            # Flag wildcard actions
            if ep.action == "*" or ep.action.endswith(":*"):
                findings.append(
                    f"EXCESSIVE_PERMISSIONS: Wildcard action '{ep.action}' "
                    f"allowed on resource '{ep.resource}'"
                )

            # Flag wildcard resources
            if ep.resource == "*":
                findings.append(
                    f"EXCESSIVE_PERMISSIONS: Action '{ep.action}' allowed "
                    f"on all resources (*)"
                )

            # Flag sensitive actions
            sensitive_actions = {
                "iam:CreateUser", "iam:CreateRole", "iam:AttachRolePolicy",
                "iam:PutRolePolicy", "iam:PassRole", "iam:CreateAccessKey",
                "sts:AssumeRole", "kms:Decrypt", "kms:CreateGrant",
                "secretsmanager:GetSecretValue",
                "lambda:CreateFunction", "lambda:UpdateFunctionCode",
            }
            if ep.action in sensitive_actions:
                findings.append(
                    f"PRIVILEGE_ESCALATION_RISK: Sensitive action '{ep.action}' "
                    f"is allowed on '{ep.resource}'"
                )

            # Flag actions without conditions
            if not ep.conditions_required and ep.action != "*":
                if any(
                    ep.action.startswith(prefix)
                    for prefix in ("iam:", "sts:", "kms:")
                ):
                    findings.append(
                        f"MISSING_CONDITIONS: Security-sensitive action "
                        f"'{ep.action}' has no conditions restricting access"
                    )

        return findings


# =============================================================================
# Report Generation
# =============================================================================


def generate_permission_report(
    agent: Agent,
    identity_policies: list[dict[str, Any]] | None = None,
    resource_policies: list[dict[str, Any]] | None = None,
    scps: list[dict[str, Any]] | None = None,
    permission_boundaries: list[dict[str, Any]] | None = None,
    session_policies: list[dict[str, Any]] | None = None,
    actions_to_check: list[tuple[str, str]] | None = None,
    account_id: str = "",
) -> PermissionReport:
    """Convenience function to generate a full permission report.

    Creates a PermissionResolver, loads all policies, and generates
    a comprehensive report.

    Args:
        agent: The Agent to analyze.
        identity_policies: Optional additional identity policies.
        resource_policies: Optional resource-based policies.
        scps: Optional Service Control Policies.
        permission_boundaries: Optional permission boundary policies.
        session_policies: Optional session policies.
        actions_to_check: Specific action+resource pairs to evaluate.
        account_id: AWS account ID for cross-account checks.

    Returns:
        PermissionReport with full analysis results.
    """
    resolver = PermissionResolver(agent, account_id=account_id)

    if identity_policies:
        resolver.load_identity_policies(managed_policies=identity_policies)
    if resource_policies:
        resolver.load_resource_policies(resource_policies)
    if scps:
        resolver.load_scps(scps)
    if permission_boundaries:
        resolver.load_permission_boundaries(permission_boundaries)
    if session_policies:
        resolver.load_session_policies(session_policies)

    return resolver.generate_report(actions_to_check)


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Core Classes
    "EffectivePermissionAnalyzer",
    "PermissionResolver",
    "IAMSimulator",
    # Data Types
    "Statement",
    "PolicyLayer",
    "EvaluationContext",
    "PermissionReport",
    # Utility Functions
    "parse_policy_document",
    "expand_wildcards",
    "match_resource",
    "evaluate_conditions",
    "match_principal",
    "generate_permission_report",
    # Exceptions
    "PolicyEvaluationError",
    "PolicyParseError",
    "SimulationError",
]
