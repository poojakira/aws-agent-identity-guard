"""
aws_agent_identity_guard/effective_permissions.py
────────────────────────────────────────────────────────────────────────────────
Effective Permission Analysis Engine.

Implements the full AWS IAM policy evaluation logic to determine effective
permissions for an AI agent identity. This engine resolves permissions across
all five policy layers:

  1. Identity-based policies (attached to the role)
  2. Resource-based policies (on the target resource)
  3. Permission boundaries (ceiling on identity policies)
  4. Service Control Policies (organizational ceiling)
  5. Session policies (further restriction for assumed roles)

Evaluation order (per AWS documentation):
  • Explicit DENY in any policy layer → DENIED (no override)
  • Then check if an ALLOW exists in identity or resource policies
  • Permission boundaries intersect with identity policy allows
  • SCPs intersect at the organizational unit level
  • Session policies intersect for assumed-role sessions
  • If no explicit ALLOW found → implicit DENY

References:
  https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
"""

from __future__ import annotations

import fnmatch
import logging
from typing import Any

from .models import (
    AgentIdentity,
    EffectiveEffect,
    EffectivePermission,
    Permission,
    PermissionEffect,
    PolicyDocument,
    PolicySource,
)

logger = logging.getLogger(__name__)


# ─── Wildcard and ARN Matching ────────────────────────────────────────────────


def _action_matches(pattern: str, action: str) -> bool:
    """
    Check if an IAM action pattern matches a specific action.

    Supports wildcards:
      - '*' matches everything
      - 's3:*' matches all S3 actions
      - 's3:Get*' matches s3:GetObject, s3:GetBucketPolicy, etc.

    Comparison is case-insensitive per IAM semantics.

    Args:
        pattern: The action pattern (may contain wildcards).
        action: The specific action to check.

    Returns:
        True if the pattern matches the action.
    """
    pattern_lower = pattern.lower()
    action_lower = action.lower()

    if pattern_lower == "*":
        return True

    # Convert IAM wildcard pattern to fnmatch pattern
    # IAM uses '*' as multi-char wildcard and '?' as single-char wildcard
    # fnmatch uses the same convention, so direct match works
    return fnmatch.fnmatch(action_lower, pattern_lower)


def _resource_matches(pattern: str, resource: str) -> bool:
    """
    Check if a resource ARN pattern matches a specific resource ARN.

    Handles:
      - '*' matches all resources
      - Wildcards within ARN components
      - Case-sensitive matching (ARNs are case-sensitive)

    Args:
        pattern: The resource ARN pattern (may contain wildcards).
        resource: The specific resource ARN to check.

    Returns:
        True if the pattern matches the resource.
    """
    if pattern == "*":
        return True
    if resource == "*":
        return True

    # Use fnmatch for wildcard matching within the ARN
    # ARNs are case-sensitive (unlike actions)
    return fnmatch.fnmatch(resource, pattern)


def _condition_applies(conditions: dict[str, Any], context: dict[str, Any]) -> bool | None:
    """
    Evaluate IAM condition block against request context.

    Returns:
        True if all conditions are satisfied.
        False if any condition is explicitly not satisfied.
        None if conditions cannot be evaluated (missing context keys).
    """
    if not conditions:
        return True

    for operator, condition_block in conditions.items():
        op_lower = operator.lower()

        # Handle IfExists variants
        if_exists = op_lower.endswith("ifexists")
        base_op = op_lower.replace("ifexists", "") if if_exists else op_lower

        for condition_key, condition_values in condition_block.items():
            # Normalize condition values to list
            if isinstance(condition_values, str):
                condition_values = [condition_values]
            elif not isinstance(condition_values, list):
                condition_values = [str(condition_values)]

            # Get the context value for this condition key
            context_value = context.get(condition_key)

            if context_value is None:
                if if_exists:
                    # IfExists: condition is satisfied if key is missing
                    continue
                # Cannot evaluate  --  return None (CONDITIONAL)
                return None

            # Evaluate based on operator
            context_str = str(context_value)

            if base_op == "stringequals":
                if context_str not in condition_values:
                    return False
            elif base_op == "stringnotequals":
                if context_str in condition_values:
                    return False
            elif base_op == "stringlike":
                matched = any(fnmatch.fnmatch(context_str, v) for v in condition_values)
                if not matched:
                    return False
            elif base_op == "stringnotlike":
                matched = any(fnmatch.fnmatch(context_str, v) for v in condition_values)
                if matched:
                    return False
            elif base_op == "arnlike":
                matched = any(fnmatch.fnmatch(context_str, v) for v in condition_values)
                if not matched:
                    return False
            elif base_op == "arnnotlike":
                matched = any(fnmatch.fnmatch(context_str, v) for v in condition_values)
                if matched:
                    return False
            elif base_op == "arnequals":
                if context_str not in condition_values:
                    return False
            elif base_op == "ipaddress":
                # Simplified IP matching  --  production would use ipaddress module
                if context_str not in condition_values:
                    return None  # Cannot fully evaluate without CIDR logic
            elif base_op == "bool":
                bool_str = str(context_value).lower()
                if bool_str not in [v.lower() for v in condition_values]:
                    return False
            elif base_op in (
                "numericequals",
                "numericlessthan",
                "numericgreaterthan",
                "numericlessthanequals",
                "numericgreaterthanequals",
            ):
                try:
                    ctx_num = float(context_str)
                    for val_str in condition_values:
                        val_num = float(val_str)
                        # Map operator to comparison function
                        numeric_checks = {
                            "numericequals": ctx_num != val_num,
                            "numericlessthan": ctx_num >= val_num,
                            "numericgreaterthan": ctx_num <= val_num,
                            "numericlessthanequals": ctx_num > val_num,
                            "numericgreaterthanequals": ctx_num < val_num,
                        }
                        if numeric_checks.get(base_op, False):
                            return False
                except (ValueError, TypeError):
                    return None
            elif base_op == "null":
                # Null condition checks key existence
                for val in condition_values:
                    expect_null = val.lower() == "true"
                    is_null = context_value is None
                    if expect_null != is_null:
                        return False
            else:
                # Unknown operator  --  cannot evaluate
                logger.warning("Unknown condition operator: %s", operator)
                return None

    return True


# ─── Effective Permission Analyzer ────────────────────────────────────────────


class EffectivePermissionAnalyzer:
    """
    Analyzes effective permissions for an AI agent by evaluating all IAM policy layers.

    Implements the canonical AWS IAM policy evaluation logic:
      1. Gather all applicable policies across all layers
      2. Check for explicit denies (any layer can deny)
      3. Check for allows in identity and resource policies
      4. Intersect with permission boundaries
      5. Intersect with SCPs
      6. Intersect with session policies
      7. Produce ALLOWED/DENIED/CONDITIONAL classification with reasoning

    Usage:
        analyzer = EffectivePermissionAnalyzer()
        effective = analyzer.analyze(
            agent=agent_identity,
            identity_policies=[policy_doc, ...],
            resource_policies=[...],
            permission_boundaries=[...],
            scps=[...],
            session_policies=[...]
        )
    """

    def __init__(self) -> None:
        """Initialize the analyzer."""
        self._evaluation_count: int = 0

    def analyze(
        self,
        agent: AgentIdentity,
        identity_policies: list[PolicyDocument] | None = None,
        resource_policies: list[PolicyDocument] | None = None,
        permission_boundaries: list[PolicyDocument] | None = None,
        scps: list[PolicyDocument] | None = None,
        session_policies: list[PolicyDocument] | None = None,
    ) -> list[EffectivePermission]:
        """
        Perform full effective permission analysis across all policy layers.

        Implements the AWS IAM policy evaluation algorithm:
          1. Extract permissions from all policy documents
          2. Apply explicit deny (any deny in any layer → DENIED)
          3. Identity policies provide the base allow set
          4. Permission boundaries intersect (ceiling) the allowed set
          5. SCPs intersect at the org level
          6. Session policies intersect if present
          7. Resource policies can grant cross-account access independently

        Args:
            agent: The agent identity to analyze.
            identity_policies: Policies attached to the agent's IAM role.
            resource_policies: Policies on the target resources.
            permission_boundaries: IAM permission boundaries applied to the role.
            scps: Service Control Policies from AWS Organizations.
            session_policies: Session policies for assumed role sessions.

        Returns:
            List of EffectivePermission objects with full reasoning.
        """
        identity_policies = identity_policies or []
        resource_policies = resource_policies or []
        permission_boundaries = permission_boundaries or []
        scps = scps or []
        session_policies = session_policies or []

        logger.info(
            "Analyzing effective permissions for agent '%s' (role: %s)",
            agent.name,
            agent.iam_role_arn,
        )

        # Step 1: Extract all permissions from all policy layers
        all_permissions: list[Permission] = []

        for policy in identity_policies:
            for statement in policy.statements:
                perms = self._evaluate_statement(statement, PolicySource.IDENTITY_POLICY)
                all_permissions.extend(perms)

        for policy in resource_policies:
            for statement in policy.statements:
                perms = self._evaluate_statement(statement, PolicySource.RESOURCE_POLICY)
                all_permissions.extend(perms)

        for policy in permission_boundaries:
            for statement in policy.statements:
                perms = self._evaluate_statement(statement, PolicySource.PERMISSION_BOUNDARY)
                all_permissions.extend(perms)

        for policy in scps:
            for statement in policy.statements:
                perms = self._evaluate_statement(statement, PolicySource.SCP)
                all_permissions.extend(perms)

        for policy in session_policies:
            for statement in policy.statements:
                perms = self._evaluate_statement(statement, PolicySource.SESSION_POLICY)
                all_permissions.extend(perms)

        logger.debug("Extracted %d total permissions across all layers", len(all_permissions))

        # Step 2: Apply permission boundaries (intersect with identity allows)
        identity_allows = [
            p
            for p in all_permissions
            if p.source == PolicySource.IDENTITY_POLICY and p.effect == PermissionEffect.ALLOW
        ]

        if permission_boundaries:
            identity_allows = self._apply_permission_boundaries(
                identity_allows, permission_boundaries
            )

        # Step 3: Apply SCPs (intersect at org level)
        if scps:
            identity_allows = self._apply_scps(identity_allows, scps)

        # Step 4: Apply session policies (further restriction)
        if session_policies:
            identity_allows = self._apply_session_policies(identity_allows, session_policies)

        # Step 5: Resolve conflicts and produce effective permissions
        effective_permissions = self._resolve_conflicts(all_permissions, identity_allows)

        self._evaluation_count += 1
        logger.info(
            "Effective permission analysis complete: %d permissions resolved",
            len(effective_permissions),
        )

        return effective_permissions

    def _evaluate_statement(
        self, statement: dict[str, Any], policy_type: PolicySource
    ) -> list[Permission]:
        """
        Extract Permission objects from a single IAM policy statement.

        Handles both 'Action'/'NotAction' and 'Resource'/'NotResource' variants.
        Expands multiple actions and resources into individual Permission objects.

        Args:
            statement: A single IAM policy statement dictionary.
            policy_type: The policy layer this statement belongs to.

        Returns:
            List of Permission objects extracted from this statement.
        """
        permissions: list[Permission] = []

        # Determine effect
        effect_str = statement.get("Effect", "").upper()
        if effect_str not in ("ALLOW", "DENY"):
            logger.warning("Invalid Effect in statement: %s", effect_str)
            return permissions

        effect = PermissionEffect(effect_str)

        # Get actions (Action or NotAction)
        actions = statement.get("Action", statement.get("NotAction", []))
        if isinstance(actions, str):
            actions = [actions]

        # Get resources (Resource or NotResource)
        resources = statement.get("Resource", statement.get("NotResource", ["*"]))
        if isinstance(resources, str):
            resources = [resources]

        # Get conditions
        conditions = statement.get("Condition", {})

        # Expand into individual permissions
        for action in actions:
            for resource in resources:
                perm = Permission(
                    action=action,
                    resource=resource,
                    effect=effect,
                    conditions=conditions,
                    source=policy_type,
                )
                permissions.append(perm)

        return permissions

    def _apply_permission_boundaries(
        self,
        permissions: list[Permission],
        boundaries: list[PolicyDocument],
    ) -> list[Permission]:
        """
        Apply permission boundaries as an intersection ceiling.

        Permission boundaries restrict the maximum permissions that identity
        policies can grant. An action is only allowed if BOTH the identity
        policy AND the permission boundary allow it.

        Args:
            permissions: The currently allowed permissions from identity policies.
            boundaries: Permission boundary policy documents.

        Returns:
            Filtered list of permissions that survive the boundary intersection.
        """
        if not boundaries:
            return permissions

        # Extract all allowed actions/resources from boundaries
        boundary_allows: list[Permission] = []
        for boundary in boundaries:
            for statement in boundary.statements:
                perms = self._evaluate_statement(statement, PolicySource.PERMISSION_BOUNDARY)
                boundary_allows.extend(p for p in perms if p.effect == PermissionEffect.ALLOW)

        # Intersect: keep only permissions that match something in the boundary
        surviving: list[Permission] = []
        for perm in permissions:
            if self._is_covered_by(perm, boundary_allows):
                surviving.append(perm)
            else:
                logger.debug(
                    "Permission %s on %s filtered by permission boundary",
                    perm.action,
                    perm.resource,
                )

        return surviving

    def _apply_scps(
        self,
        permissions: list[Permission],
        scps: list[PolicyDocument],
    ) -> list[Permission]:
        """
        Apply Service Control Policies as an organizational ceiling.

        SCPs restrict the maximum permissions available to accounts in an OU.
        If an SCP does not explicitly allow an action, it is implicitly denied
        at the organizational level.

        Args:
            permissions: The currently allowed permissions.
            scps: Service Control Policy documents.

        Returns:
            Filtered list of permissions that survive SCP intersection.
        """
        if not scps:
            return permissions

        # Extract all allowed actions from SCPs
        scp_allows: list[Permission] = []
        for scp in scps:
            for statement in scp.statements:
                perms = self._evaluate_statement(statement, PolicySource.SCP)
                scp_allows.extend(p for p in perms if p.effect == PermissionEffect.ALLOW)

        # If no SCP allows exist, this means FullAWSAccess is not present  --  deny all
        if not scp_allows:
            logger.warning("No SCP allows found  --  all permissions will be denied")
            return []

        # Intersect: keep only permissions covered by SCP allows
        surviving: list[Permission] = []
        for perm in permissions:
            if self._is_covered_by(perm, scp_allows):
                surviving.append(perm)
            else:
                logger.debug(
                    "Permission %s on %s filtered by SCP",
                    perm.action,
                    perm.resource,
                )

        return surviving

    def _apply_session_policies(
        self,
        permissions: list[Permission],
        session_policies: list[PolicyDocument],
    ) -> list[Permission]:
        """
        Apply session policies as a further restriction on assumed-role sessions.

        Session policies (passed during AssumeRole) further restrict the
        effective permissions for that session. They intersect with the
        identity policy allows.

        Args:
            permissions: The currently allowed permissions.
            session_policies: Session policy documents.

        Returns:
            Filtered list of permissions that survive session policy intersection.
        """
        if not session_policies:
            return permissions

        # Extract all allowed actions from session policies
        session_allows: list[Permission] = []
        for policy in session_policies:
            for statement in policy.statements:
                perms = self._evaluate_statement(statement, PolicySource.SESSION_POLICY)
                session_allows.extend(p for p in perms if p.effect == PermissionEffect.ALLOW)

        # Intersect
        surviving: list[Permission] = []
        for perm in permissions:
            if self._is_covered_by(perm, session_allows):
                surviving.append(perm)
            else:
                logger.debug(
                    "Permission %s on %s filtered by session policy",
                    perm.action,
                    perm.resource,
                )

        return surviving

    def _resolve_conflicts(
        self,
        all_permissions: list[Permission],
        surviving_allows: list[Permission],
    ) -> list[EffectivePermission]:
        """
        Resolve permission conflicts and produce final effective permissions.

        Applies the core IAM evaluation logic:
          1. Explicit deny in ANY layer → DENIED
          2. Surviving allows after boundary/SCP/session intersection → ALLOWED or CONDITIONAL
          3. No allow → implicit DENIED

        Args:
            all_permissions: All permissions from all policy layers.
            surviving_allows: Allows that survived all intersection filters.

        Returns:
            List of EffectivePermission with full classification and reasoning.
        """
        effective: list[EffectivePermission] = []

        # Collect all unique action-resource pairs from allows
        seen: set[tuple[str, str]] = set()

        for perm in surviving_allows:
            key = (perm.action, perm.resource)
            if key in seen:
                continue
            seen.add(key)

            # Check for explicit deny across ALL policies
            if self._check_explicit_deny(perm.action, perm.resource, all_permissions):
                effective.append(
                    EffectivePermission(
                        action=perm.action,
                        resource=perm.resource,
                        effective_effect=EffectiveEffect.DENIED,
                        contributing_policies=self._get_contributing_policies(
                            perm.action, perm.resource, all_permissions
                        ),
                        conditions_required=[],
                        evaluation_reason=(
                            f"Explicit DENY found for {perm.action} on {perm.resource}. "
                            "Explicit deny overrides all allows per IAM evaluation logic."
                        ),
                    )
                )
            elif self._check_condition_dependency(perm):
                effective.append(
                    EffectivePermission(
                        action=perm.action,
                        resource=perm.resource,
                        effective_effect=EffectiveEffect.CONDITIONAL,
                        contributing_policies=self._get_contributing_policies(
                            perm.action, perm.resource, all_permissions
                        ),
                        conditions_required=[perm.conditions] if perm.conditions else [],
                        evaluation_reason=(
                            f"Access to {perm.action} on {perm.resource} is conditional. "
                            f"Conditions must be satisfied at request time: {perm.conditions}"
                        ),
                    )
                )
            else:
                effective.append(
                    EffectivePermission(
                        action=perm.action,
                        resource=perm.resource,
                        effective_effect=EffectiveEffect.ALLOWED,
                        contributing_policies=self._get_contributing_policies(
                            perm.action, perm.resource, all_permissions
                        ),
                        conditions_required=[],
                        evaluation_reason=(
                            f"Access to {perm.action} on {perm.resource} is allowed. "
                            "Identity policy grants access, no explicit deny found, "
                            "and permission survives boundary/SCP/session intersection."
                        ),
                    )
                )

        # Also report explicit denies that don't overlap with allows
        for perm in all_permissions:
            if perm.effect == PermissionEffect.DENY:
                key = (perm.action, perm.resource)
                if key not in seen:
                    seen.add(key)
                    effective.append(
                        EffectivePermission(
                            action=perm.action,
                            resource=perm.resource,
                            effective_effect=EffectiveEffect.DENIED,
                            contributing_policies=[perm.source.value],
                            conditions_required=[],
                            evaluation_reason=(
                                f"Explicit DENY for {perm.action} on {perm.resource} "
                                f"from {perm.source.value}."
                            ),
                        )
                    )

        return effective

    def _check_explicit_deny(
        self, action: str, resource: str, all_permissions: list[Permission]
    ) -> bool:
        """
        Check if there is an explicit DENY for the given action-resource pair.

        An explicit deny in ANY policy layer immediately denies the request,
        regardless of any allows elsewhere.

        Args:
            action: The IAM action to check.
            resource: The resource ARN to check.
            all_permissions: All permissions from all policy layers.

        Returns:
            True if an explicit deny exists that covers this action-resource.
        """
        for perm in all_permissions:
            if perm.effect != PermissionEffect.DENY:
                continue
            if _action_matches(perm.action, action) and _resource_matches(perm.resource, resource):
                # Check if the deny has conditions  --  if so, it may not always apply
                if not perm.conditions:
                    return True
                # Deny with conditions: still counts as explicit deny
                # (conditions on deny make it conditional, but we flag it as denied
                # for safety  --  the deny may or may not fire depending on context)
                return True

        return False

    def _check_condition_dependency(self, permission: Permission) -> bool:
        """
        Check if a permission has conditions that make it context-dependent.

        Permissions with conditions are classified as CONDITIONAL because their
        effective access depends on request-time context values.

        Args:
            permission: The permission to check.

        Returns:
            True if the permission has non-empty conditions.
        """
        return bool(permission.conditions)

    def _is_covered_by(self, permission: Permission, covering_set: list[Permission]) -> bool:
        """
        Check if a permission is covered by at least one permission in a set.

        Used for intersection logic: a permission from an identity policy is
        "covered" by a boundary/SCP if the boundary/SCP allows the same action
        on the same (or broader) resource.

        Args:
            permission: The permission to check coverage for.
            covering_set: The set of permissions that might cover it.

        Returns:
            True if at least one permission in the covering set matches.
        """
        for cover in covering_set:
            if _action_matches(cover.action, permission.action) and _resource_matches(
                cover.resource, permission.resource
            ):
                return True
        return False

    def _get_contributing_policies(
        self, action: str, resource: str, all_permissions: list[Permission]
    ) -> list[str]:
        """
        Get the list of policy sources that contribute to an action-resource evaluation.

        Args:
            action: The IAM action.
            resource: The resource ARN.
            all_permissions: All permissions from all layers.

        Returns:
            List of unique policy source identifiers that match.
        """
        sources: set[str] = set()
        for perm in all_permissions:
            if _action_matches(perm.action, action) and _resource_matches(perm.resource, resource):
                sources.add(perm.source.value)
        return sorted(sources)

    def simulate_access(
        self,
        agent: AgentIdentity,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
        identity_policies: list[PolicyDocument] | None = None,
        resource_policies: list[PolicyDocument] | None = None,
        permission_boundaries: list[PolicyDocument] | None = None,
        scps: list[PolicyDocument] | None = None,
        session_policies: list[PolicyDocument] | None = None,
    ) -> EffectivePermission:
        """
        Simulate access for a specific action-resource-context combination.

        Like IAM policy simulator, determines the effective permission for a
        single access request, evaluating conditions against the provided context.

        Args:
            agent: The agent identity making the request.
            action: The specific IAM action to simulate.
            resource: The target resource ARN.
            context: Request context for condition evaluation (keys → values).
            identity_policies: Identity policies to evaluate.
            resource_policies: Resource policies to evaluate.
            permission_boundaries: Permission boundaries to evaluate.
            scps: SCPs to evaluate.
            session_policies: Session policies to evaluate.

        Returns:
            EffectivePermission with the simulation result and full reasoning.
        """
        context = context or {}
        identity_policies = identity_policies or []
        resource_policies = resource_policies or []
        permission_boundaries = permission_boundaries or []
        scps = scps or []
        session_policies = session_policies or []

        logger.info(
            "Simulating access: agent=%s, action=%s, resource=%s",
            agent.agent_id,
            action,
            resource,
        )

        reasons: list[str] = []

        # Step 1: Collect all deny statements that match
        all_denies: list[Permission] = []
        all_allows: list[Permission] = []

        for source_policies, source_type in [
            (identity_policies, PolicySource.IDENTITY_POLICY),
            (resource_policies, PolicySource.RESOURCE_POLICY),
            (permission_boundaries, PolicySource.PERMISSION_BOUNDARY),
            (scps, PolicySource.SCP),
            (session_policies, PolicySource.SESSION_POLICY),
        ]:
            for policy in source_policies:
                for statement in policy.statements:
                    perms = self._evaluate_statement(statement, source_type)
                    for perm in perms:
                        if not _action_matches(perm.action, action):
                            continue
                        if not _resource_matches(perm.resource, resource):
                            continue
                        if perm.effect == PermissionEffect.DENY:
                            all_denies.append(perm)
                        else:
                            all_allows.append(perm)

        # Step 2: Check explicit denies (with condition evaluation)
        for deny in all_denies:
            cond_result = _condition_applies(deny.conditions, context)
            if cond_result is True:
                reasons.append(
                    f"Explicit DENY from {deny.source.value} "
                    f"(action={deny.action}, resource={deny.resource})"
                )
                return EffectivePermission(
                    action=action,
                    resource=resource,
                    effective_effect=EffectiveEffect.DENIED,
                    contributing_policies=[deny.source.value],
                    conditions_required=[],
                    evaluation_reason=(
                        f"Explicitly denied by {deny.source.value}. "
                        f"Deny conditions satisfied with provided context."
                    ),
                )
            elif cond_result is None:
                # Deny has conditions we can't evaluate  --  flag as conditional
                reasons.append(
                    f"Conditional DENY from {deny.source.value}  --  "
                    f"conditions could not be fully evaluated"
                )

        # Step 3: Check allows  --  must pass through all intersection layers
        identity_allows = [p for p in all_allows if p.source == PolicySource.IDENTITY_POLICY]
        resource_allows = [p for p in all_allows if p.source == PolicySource.RESOURCE_POLICY]
        boundary_allows = [p for p in all_allows if p.source == PolicySource.PERMISSION_BOUNDARY]
        scp_allows_list = [p for p in all_allows if p.source == PolicySource.SCP]
        session_allows = [p for p in all_allows if p.source == PolicySource.SESSION_POLICY]

        # Check if identity policy allows (with conditions)
        identity_granted = False
        conditional_on_identity = False
        for allow in identity_allows:
            cond_result = _condition_applies(allow.conditions, context)
            if cond_result is True:
                identity_granted = True
                reasons.append(f"Identity policy allows {action} on {resource}")
                break
            elif cond_result is None:
                conditional_on_identity = True

        # Check resource policy allows (can independently grant same-account)
        resource_granted = False
        for allow in resource_allows:
            cond_result = _condition_applies(allow.conditions, context)
            if cond_result is True:
                resource_granted = True
                reasons.append(f"Resource policy allows {action} on {resource}")
                break

        if not identity_granted and not resource_granted:
            if conditional_on_identity:
                return EffectivePermission(
                    action=action,
                    resource=resource,
                    effective_effect=EffectiveEffect.CONDITIONAL,
                    contributing_policies=[PolicySource.IDENTITY_POLICY.value],
                    conditions_required=[p.conditions for p in identity_allows if p.conditions],
                    evaluation_reason=(
                        f"Access to {action} on {resource} depends on conditions "
                        f"that could not be evaluated with the provided context."
                    ),
                )
            return EffectivePermission(
                action=action,
                resource=resource,
                effective_effect=EffectiveEffect.DENIED,
                contributing_policies=[],
                conditions_required=[],
                evaluation_reason=(
                    f"Implicit deny: no identity or resource policy allows "
                    f"{action} on {resource}."
                ),
            )

        # Step 4: Check permission boundary intersection (if identity-granted)
        if identity_granted and permission_boundaries and not boundary_allows:
            return EffectivePermission(
                action=action,
                resource=resource,
                effective_effect=EffectiveEffect.DENIED,
                contributing_policies=[PolicySource.PERMISSION_BOUNDARY.value],
                conditions_required=[],
                evaluation_reason=(
                    f"Permission boundary does not allow {action} on {resource}. "
                    f"Permission boundaries restrict the maximum identity permissions."
                ),
            )

        # Step 5: Check SCP intersection
        if identity_granted and scps and not scp_allows_list:
            return EffectivePermission(
                action=action,
                resource=resource,
                effective_effect=EffectiveEffect.DENIED,
                contributing_policies=[PolicySource.SCP.value],
                conditions_required=[],
                evaluation_reason=(
                    f"SCP does not allow {action} on {resource}. "
                    f"Service Control Policies restrict the maximum account permissions."
                ),
            )

        # Step 6: Check session policy intersection
        if identity_granted and session_policies and not session_allows:
            return EffectivePermission(
                action=action,
                resource=resource,
                effective_effect=EffectiveEffect.DENIED,
                contributing_policies=[PolicySource.SESSION_POLICY.value],
                conditions_required=[],
                evaluation_reason=(
                    f"Session policy does not allow {action} on {resource}. "
                    f"Session policies restrict the maximum session permissions."
                ),
            )

        # If we got here with conditional deny warnings, mark as conditional
        if reasons and any("Conditional DENY" in r for r in reasons):
            return EffectivePermission(
                action=action,
                resource=resource,
                effective_effect=EffectiveEffect.CONDITIONAL,
                contributing_policies=sorted({p.source.value for p in all_allows + all_denies}),
                conditions_required=[p.conditions for p in all_denies if p.conditions],
                evaluation_reason=(
                    f"Access to {action} on {resource} is allowed by policy but a "
                    f"conditional deny exists that may apply depending on context."
                ),
            )

        # Fully allowed
        contributing = sorted({p.source.value for p in all_allows})
        return EffectivePermission(
            action=action,
            resource=resource,
            effective_effect=EffectiveEffect.ALLOWED,
            contributing_policies=contributing,
            conditions_required=[],
            evaluation_reason=(
                f"Access to {action} on {resource} is ALLOWED. "
                f"Granted by: {', '.join(contributing)}. "
                f"No explicit deny, passes all intersection layers."
            ),
        )

    def get_unused_permissions(
        self,
        agent: AgentIdentity,
        cloudtrail_events: list[dict[str, Any]],
        effective_permissions: list[EffectivePermission] | None = None,
        identity_policies: list[PolicyDocument] | None = None,
    ) -> list[EffectivePermission]:
        """
        Identify permissions granted but never used, based on CloudTrail data.

        Compares the agent's effective allowed permissions against actual API
        calls recorded in CloudTrail. Permissions that are allowed but have
        no corresponding CloudTrail event are flagged as unused.

        This supports least-privilege refinement by identifying permissions
        that can be safely removed.

        Args:
            agent: The agent identity to analyze.
            cloudtrail_events: List of CloudTrail event records (dicts with
                'eventSource', 'eventName', 'resources' keys).
            effective_permissions: Pre-computed effective permissions (optional).
                If not provided, identity_policies must be supplied.
            identity_policies: Policies to analyze if effective_permissions
                not pre-computed.

        Returns:
            List of EffectivePermission objects that are ALLOWED but unused.
        """
        if effective_permissions is None:
            if identity_policies is None:
                logger.warning(
                    "Cannot determine unused permissions without effective_permissions "
                    "or identity_policies"
                )
                return []
            effective_permissions = self.analyze(agent, identity_policies=identity_policies)

        # Extract used actions from CloudTrail
        used_actions: set[str] = set()
        used_action_resources: set[tuple[str, str]] = set()

        for event in cloudtrail_events:
            # CloudTrail format: eventSource = "s3.amazonaws.com", eventName = "GetObject"
            event_source = event.get("eventSource", "")
            event_name = event.get("eventName", "")

            # Convert CloudTrail format to IAM action format
            # e.g., "s3.amazonaws.com" + "GetObject" → "s3:GetObject"
            service = event_source.replace(".amazonaws.com", "").split(".")[0]
            iam_action = f"{service}:{event_name}"
            used_actions.add(iam_action.lower())

            # Track resource usage if available
            resources = event.get("resources", [])
            for resource in resources:
                arn = resource.get("ARN", resource.get("arn", ""))
                if arn:
                    used_action_resources.add((iam_action.lower(), arn))

        # Find unused: allowed permissions not seen in CloudTrail
        unused: list[EffectivePermission] = []

        for perm in effective_permissions:
            if perm.effective_effect != EffectiveEffect.ALLOWED:
                continue

            # Check if this specific action was ever used
            action_lower = perm.action.lower()

            # Handle wildcards in the permission  --  can't definitively say unused
            if "*" in perm.action:
                # For wildcard permissions, check if ANY matching action was used
                any_used = any(_action_matches(perm.action, used_act) for used_act in used_actions)
                if not any_used:
                    unused.append(
                        EffectivePermission(
                            action=perm.action,
                            resource=perm.resource,
                            effective_effect=perm.effective_effect,
                            contributing_policies=perm.contributing_policies,
                            conditions_required=perm.conditions_required,
                            evaluation_reason=(
                                f"Wildcard permission {perm.action} on {perm.resource}  --  "
                                f"no matching actions found in CloudTrail events."
                            ),
                        )
                    )
            else:
                if action_lower not in used_actions:
                    unused.append(
                        EffectivePermission(
                            action=perm.action,
                            resource=perm.resource,
                            effective_effect=perm.effective_effect,
                            contributing_policies=perm.contributing_policies,
                            conditions_required=perm.conditions_required,
                            evaluation_reason=(
                                f"Permission {perm.action} on {perm.resource} is granted "
                                f"but was never used in the analyzed CloudTrail period."
                            ),
                        )
                    )

        logger.info(
            "Found %d unused permissions out of %d allowed for agent '%s'",
            len(unused),
            sum(1 for p in effective_permissions if p.effective_effect == EffectiveEffect.ALLOWED),
            agent.name,
        )

        return unused
