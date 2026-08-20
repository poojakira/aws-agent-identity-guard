"""
aws_agent_identity_guard/risk_engine.py
────────────────────────────────────────────────────────────────────────────────
Multidimensional risk scoring engine for AI agent authorization decisions.

Evaluates agent identities and transaction requests across six risk dimensions:
  • Privilege level — dangerous IAM actions (iam:*, sts:AssumeRole, PassRole)
  • Sensitivity — data classification and access to secrets/KMS
  • Blast radius — wildcard resources, cross-account, service breadth
  • Data exposure — S3 public access, DynamoDB scan, logs access
  • Persistence — ability to create roles, policies, users, backdoors
  • Lateral movement — lambda invoke, assume-role chains, SSM sessions

Each dimension produces an independent 0-100 score. An environment multiplier
(production=1.5, staging=1.2, development=0.8) is applied to the weighted
composite to produce the final overall risk score.

Risk thresholds:
  LOW      = 0-25
  MEDIUM   = 26-50
  HIGH     = 51-75
  CRITICAL = 76-100
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from aws_agent_identity_guard.models import (
    AgentIdentity,
    AttackPath,
    DataClassification,
    EffectivePermission,
    Environment,
    RiskScore,
    TransactionRequest,
)

logger = logging.getLogger(__name__)


# ─── Risk Level Classification ────────────────────────────────────────────────


class RiskLevel(str, Enum):
    """Categorical risk level derived from the overall numeric score."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def classify_risk(score: float) -> RiskLevel:
    """
    Classify a numeric risk score into a categorical level.

    Args:
        score: Numeric risk score (0-100).

    Returns:
        The corresponding RiskLevel enum value.
    """
    if score <= 25:
        return RiskLevel.LOW
    elif score <= 50:
        return RiskLevel.MEDIUM
    elif score <= 75:
        return RiskLevel.HIGH
    else:
        return RiskLevel.CRITICAL


# ─── Default Configuration ────────────────────────────────────────────────────


@dataclass
class RiskWeights:
    """
    Configurable weights for each risk dimension.

    Weights are relative and will be normalized to sum to 1.0 internally.
    Higher weight means that dimension has more influence on the overall score.

    Attributes:
        privilege: Weight for privilege-level risk.
        sensitivity: Weight for data sensitivity risk.
        blast_radius: Weight for blast radius risk.
        data_exposure: Weight for data exposure risk.
        persistence: Weight for persistence risk.
        lateral_movement: Weight for lateral movement risk.
    """

    privilege: float = 0.25
    sensitivity: float = 0.20
    blast_radius: float = 0.20
    data_exposure: float = 0.15
    persistence: float = 0.10
    lateral_movement: float = 0.10

    def normalized(self) -> dict[str, float]:
        """Return weights normalized to sum to 1.0."""
        total = (
            self.privilege
            + self.sensitivity
            + self.blast_radius
            + self.data_exposure
            + self.persistence
            + self.lateral_movement
        )
        if total == 0:
            raise ValueError("Total weight cannot be zero")
        return {
            "privilege": self.privilege / total,
            "sensitivity": self.sensitivity / total,
            "blast_radius": self.blast_radius / total,
            "data_exposure": self.data_exposure / total,
            "persistence": self.persistence / total,
            "lateral_movement": self.lateral_movement / total,
        }


# ─── Dangerous Action Catalogs ───────────────────────────────────────────────

# Actions that grant God-mode or near-God-mode privilege
_CRITICAL_PRIVILEGE_ACTIONS: set[str] = {
    "iam:*",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:CreateRole",
    "iam:CreateUser",
    "iam:UpdateAssumeRolePolicy",
    "iam:PassRole",
    "sts:AssumeRole",
    "sts:AssumeRoleWithSAML",
    "sts:AssumeRoleWithWebIdentity",
    "organizations:*",
}

# Actions that are high-privilege but not admin-equivalent
_HIGH_PRIVILEGE_ACTIONS: set[str] = {
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:DeletePolicy",
    "iam:DeleteRolePolicy",
    "iam:DetachRolePolicy",
    "sts:GetFederationToken",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "lambda:UpdateFunctionConfiguration",
    "lambda:InvokeFunction",
    "ec2:RunInstances",
    "cloudformation:CreateStack",
    "cloudformation:UpdateStack",
}

# Actions involving secrets/sensitive data access
_SENSITIVITY_ACTIONS: set[str] = {
    "secretsmanager:GetSecretValue",
    "secretsmanager:ListSecrets",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
    "kms:Decrypt",
    "kms:GenerateDataKey",
    "kms:CreateGrant",
    "kms:ReEncrypt*",
}

# Actions that expose data
_DATA_EXPOSURE_ACTIONS: set[str] = {
    "s3:GetObject",
    "s3:ListBucket",
    "s3:GetBucketPolicy",
    "s3:PutBucketPolicy",
    "s3:PutBucketAcl",
    "s3:PutObjectAcl",
    "dynamodb:Scan",
    "dynamodb:Query",
    "dynamodb:GetItem",
    "dynamodb:BatchGetItem",
    "logs:GetLogEvents",
    "logs:FilterLogEvents",
    "logs:StartQuery",
    "rds:DownloadDBLogFilePortion",
    "athena:StartQueryExecution",
    "glue:GetTable",
    "glue:GetTables",
    "glue:GetDatabase",
}

# Actions enabling persistence / backdoor creation
_PERSISTENCE_ACTIONS: set[str] = {
    "iam:CreateRole",
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:UpdateAssumeRolePolicy",
    "lambda:CreateFunction",
    "lambda:AddPermission",
    "events:PutRule",
    "events:PutTargets",
    "cloudwatch:PutMetricAlarm",
    "sns:CreateTopic",
    "sns:Subscribe",
    "sqs:CreateQueue",
}

# Actions enabling lateral movement
_LATERAL_MOVEMENT_ACTIONS: set[str] = {
    "lambda:InvokeFunction",
    "lambda:InvokeAsync",
    "sts:AssumeRole",
    "ssm:StartSession",
    "ssm:SendCommand",
    "ec2:RunInstances",
    "ecs:RunTask",
    "ecs:StartTask",
    "eks:DescribeCluster",
    "bedrock:InvokeModel",
    "bedrock:InvokeAgent",
    "sagemaker:InvokeEndpoint",
    "stepfunctions:StartExecution",
}


# ─── Risk Engine ──────────────────────────────────────────────────────────────


class RiskEngine:
    """
    Multidimensional risk scoring engine for AI agent identities and transactions.

    Evaluates agent permissions across six independent risk dimensions, applies
    environment-based multipliers, and produces a composite RiskScore object
    suitable for authorization decisions.

    Usage:
        engine = RiskEngine()
        risk = engine.score_agent(agent, effective_permissions, attack_paths)
        level = classify_risk(risk.overall)

    Args:
        weights: Optional RiskWeights to customize dimension importance.
    """

    def __init__(self, weights: RiskWeights | None = None) -> None:
        """
        Initialize the risk engine with configurable weights.

        Args:
            weights: Custom risk dimension weights. Defaults to balanced weighting.
        """
        self._weights = weights or RiskWeights()
        logger.info(
            "RiskEngine initialized with weights: %s",
            self._weights.normalized(),
        )

    @property
    def weights(self) -> RiskWeights:
        """Return current risk weights configuration."""
        return self._weights

    @weights.setter
    def weights(self, value: RiskWeights) -> None:
        """Update risk weights configuration."""
        self._weights = value
        logger.info("RiskEngine weights updated: %s", self._weights.normalized())

    def score_agent(
        self,
        agent: AgentIdentity,
        effective_permissions: list[EffectivePermission],
        attack_paths: list[AttackPath],
        behavior_data: dict[str, Any] | None = None,
    ) -> RiskScore:
        """
        Compute comprehensive risk score for an agent identity.

        Evaluates the agent's effective permissions against all six risk dimensions,
        applies the environment multiplier, and optionally incorporates behavioral
        anomaly signals.

        Args:
            agent: The agent identity to assess.
            effective_permissions: Resolved permissions after full policy evaluation.
            attack_paths: Known attack paths available to this agent.
            behavior_data: Optional behavioral analytics (anomaly scores, access patterns).

        Returns:
            A fully populated RiskScore with per-dimension and composite scores.

        Raises:
            ValueError: If agent is None or permissions list is invalid.
        """
        if agent is None:
            raise ValueError("agent cannot be None")
        if effective_permissions is None:
            raise ValueError("effective_permissions cannot be None")

        logger.debug(
            "Scoring agent '%s' (%s) with %d permissions, %d attack paths",
            agent.name,
            agent.agent_id,
            len(effective_permissions),
            len(attack_paths),
        )

        try:
            # Extract allowed actions for scoring
            allowed_permissions = self._filter_allowed(effective_permissions)

            # Compute individual dimension scores
            privilege_score = self._score_privilege(allowed_permissions)
            sensitivity_score = self._score_sensitivity(agent, allowed_permissions)
            blast_radius_score = self._score_blast_radius(allowed_permissions)
            data_exposure_score = self._score_data_exposure(allowed_permissions)
            persistence_score = self._score_persistence(allowed_permissions)
            lateral_movement_score = self._score_lateral_movement(
                allowed_permissions, attack_paths
            )

            # Environment multiplier
            env_factor = self._environment_factor(agent)

            # Behavioral adjustment
            behavior_modifier = self._behavior_modifier(behavior_data)

            # Compute weighted overall
            scores = {
                "privilege": privilege_score,
                "sensitivity": sensitivity_score,
                "blast_radius": blast_radius_score,
                "data_exposure": data_exposure_score,
                "persistence": persistence_score,
                "lateral_movement": lateral_movement_score,
            }
            overall = self._compute_overall(scores, env_factor, behavior_modifier)

            risk_score = RiskScore(
                overall=overall,
                privilege=float(privilege_score),
                sensitivity=float(sensitivity_score),
                blast_radius=float(blast_radius_score),
                data_exposure=float(data_exposure_score),
                persistence=float(persistence_score),
                lateral_movement=float(lateral_movement_score),
                environment_factor=env_factor,
                transaction_context={
                    "agent_id": agent.agent_id,
                    "agent_name": agent.name,
                    "environment": agent.environment.value,
                    "risk_level": classify_risk(overall).value,
                    "attack_path_count": len(attack_paths),
                    "permission_count": len(effective_permissions),
                },
            )

            logger.info(
                "Agent '%s' risk score: overall=%.1f (%s), "
                "privilege=%d, sensitivity=%d, blast_radius=%d, "
                "data_exposure=%d, persistence=%d, lateral_movement=%d, "
                "env_factor=%.2f",
                agent.name,
                overall,
                classify_risk(overall).value,
                privilege_score,
                sensitivity_score,
                blast_radius_score,
                data_exposure_score,
                persistence_score,
                lateral_movement_score,
                env_factor,
            )

            return risk_score

        except Exception as exc:
            logger.error(
                "Error scoring agent '%s': %s",
                agent.name if agent else "unknown",
                str(exc),
                exc_info=True,
            )
            raise

    def score_transaction(
        self,
        transaction: TransactionRequest,
        agent: AgentIdentity,
        effective_permissions: list[EffectivePermission],
    ) -> RiskScore:
        """
        Compute risk score for a specific transaction request.

        Focuses scoring on the particular action/resource being requested,
        rather than the full permission set. Useful for real-time authorization.

        Args:
            transaction: The specific action being requested.
            agent: The agent identity making the request.
            effective_permissions: Agent's resolved permissions.

        Returns:
            A RiskScore focused on the transaction's risk characteristics.

        Raises:
            ValueError: If transaction or agent is None.
        """
        if transaction is None:
            raise ValueError("transaction cannot be None")
        if agent is None:
            raise ValueError("agent cannot be None")

        logger.debug(
            "Scoring transaction: agent='%s', action='%s', resource='%s'",
            agent.name,
            transaction.action,
            transaction.resource,
        )

        try:
            # Create a synthetic single-permission list for the transaction
            transaction_permission = EffectivePermission(
                action=transaction.action,
                resource=transaction.resource,
                effective_effect="ALLOWED",
                contributing_policies=[],
                conditions_required=[],
                evaluation_reason="Transaction request evaluation",
            )
            single_perm = [transaction_permission]

            # Score dimensions against the single transaction action
            privilege_score = self._score_privilege(single_perm)
            sensitivity_score = self._score_sensitivity(agent, single_perm)
            blast_radius_score = self._score_blast_radius(single_perm)
            data_exposure_score = self._score_data_exposure(single_perm)
            persistence_score = self._score_persistence(single_perm)
            lateral_movement_score = self._score_lateral_movement(single_perm, [])

            # Data classification boost
            classification_boost = self._data_classification_boost(
                transaction.data_classification
            )
            sensitivity_score = min(100, sensitivity_score + classification_boost)

            env_factor = self._environment_factor(agent)

            scores = {
                "privilege": privilege_score,
                "sensitivity": sensitivity_score,
                "blast_radius": blast_radius_score,
                "data_exposure": data_exposure_score,
                "persistence": persistence_score,
                "lateral_movement": lateral_movement_score,
            }
            overall = self._compute_overall(scores, env_factor)

            risk_score = RiskScore(
                overall=overall,
                privilege=float(privilege_score),
                sensitivity=float(sensitivity_score),
                blast_radius=float(blast_radius_score),
                data_exposure=float(data_exposure_score),
                persistence=float(persistence_score),
                lateral_movement=float(lateral_movement_score),
                environment_factor=env_factor,
                transaction_context={
                    "request_id": transaction.request_id,
                    "agent_id": transaction.agent_id,
                    "action": transaction.action,
                    "resource": transaction.resource,
                    "tool": transaction.tool,
                    "risk_level": classify_risk(overall).value,
                    "data_classification": transaction.data_classification.value,
                },
            )

            logger.info(
                "Transaction '%s' -> '%s' risk: overall=%.1f (%s)",
                transaction.action,
                transaction.resource,
                overall,
                classify_risk(overall).value,
            )

            return risk_score

        except Exception as exc:
            logger.error(
                "Error scoring transaction '%s': %s",
                transaction.request_id if transaction else "unknown",
                str(exc),
                exc_info=True,
            )
            raise

    # ─── Dimension Scoring Methods ────────────────────────────────────────────

    def _score_privilege(self, permissions: list[EffectivePermission]) -> int:
        """
        Score privilege level risk based on dangerous IAM actions.

        Evaluates the presence of god-mode actions (iam:*, sts:AssumeRole),
        policy-manipulation actions, and high-privilege compute actions.

        Args:
            permissions: List of allowed effective permissions.

        Returns:
            Risk score from 0 (no privilege risk) to 100 (maximum privilege risk).
        """
        if not permissions:
            return 0

        score = 0
        actions = self._extract_actions(permissions)

        # Check for wildcard admin
        if "*" in actions or "iam:*" in actions:
            return 100

        # Critical privilege actions (weighted heavily)
        critical_matches = actions & _CRITICAL_PRIVILEGE_ACTIONS
        score += min(70, len(critical_matches) * 40)

        # High privilege actions
        high_matches = actions & _HIGH_PRIVILEGE_ACTIONS
        score += min(30, len(high_matches) * 8)

        # Wildcard service actions (e.g., s3:*, ec2:*)
        wildcard_service_actions = {a for a in actions if a.endswith(":*")}
        score += min(20, len(wildcard_service_actions) * 10)

        # Action patterns with case-insensitive matching for common escalation
        for action in actions:
            action_lower = action.lower()
            if "passrole" in action_lower:
                score += 15
            elif "assumerolewith" in action_lower:
                score += 12
            elif "createpolicyversion" in action_lower:
                score += 20

        return min(100, score)

    def _score_sensitivity(
        self, agent: AgentIdentity, permissions: list[EffectivePermission]
    ) -> int:
        """
        Score data sensitivity risk based on classification and secret access.

        Considers the agent's declared data classification level, access to
        secrets managers, KMS decryption capabilities, and parameter stores.

        Args:
            agent: The agent identity with data classification metadata.
            permissions: List of allowed effective permissions.

        Returns:
            Risk score from 0 (no sensitivity risk) to 100 (maximum sensitivity risk).
        """
        if not permissions:
            return 0

        score = 0
        actions = self._extract_actions(permissions)

        # Base score from agent's data classification
        classification_scores = {
            DataClassification.PUBLIC: 0,
            DataClassification.INTERNAL: 10,
            DataClassification.CONFIDENTIAL: 30,
            DataClassification.SECRET: 50,
            DataClassification.REGULATED: 60,
        }
        score += classification_scores.get(agent.data_classification, 10)

        # Sensitivity action access
        sensitivity_matches = actions & _SENSITIVITY_ACTIONS
        score += min(40, len(sensitivity_matches) * 10)

        # KMS key access patterns
        kms_actions = {a for a in actions if a.startswith("kms:")}
        if kms_actions:
            score += min(15, len(kms_actions) * 5)

        # Access to secrets on wildcard resources
        for perm in permissions:
            if perm.action in _SENSITIVITY_ACTIONS and perm.resource == "*":
                score += 10
                break

        return min(100, score)

    def _score_blast_radius(self, permissions: list[EffectivePermission]) -> int:
        """
        Score blast radius based on scope of potential damage.

        Evaluates wildcard resource patterns, cross-account access indicators,
        number of distinct services accessible, and breadth of write actions.

        Args:
            permissions: List of allowed effective permissions.

        Returns:
            Risk score from 0 (minimal blast radius) to 100 (maximum blast radius).
        """
        if not permissions:
            return 0

        score = 0

        # Count wildcard resources
        wildcard_resources = sum(1 for p in permissions if p.resource == "*")
        score += min(40, wildcard_resources * 5)

        # Count distinct services
        services = set()
        for perm in permissions:
            parts = perm.action.split(":")
            if len(parts) >= 2:
                services.add(parts[0])
        service_count = len(services)
        if service_count > 10:
            score += 30
        elif service_count > 5:
            score += 20
        elif service_count > 3:
            score += 10

        # Cross-account indicators (resources with different account IDs)
        cross_account_resources = sum(
            1
            for p in permissions
            if "::" in p.resource and self._is_cross_account_resource(p.resource)
        )
        score += min(20, cross_account_resources * 10)

        # Write/modify actions breadth
        write_actions = sum(
            1
            for p in permissions
            if any(
                verb in p.action.lower()
                for verb in [
                    "put",
                    "create",
                    "delete",
                    "update",
                    "modify",
                    "attach",
                    "detach",
                    "remove",
                ]
            )
        )
        score += min(20, write_actions * 2)

        return min(100, score)

    def _score_data_exposure(self, permissions: list[EffectivePermission]) -> int:
        """
        Score data exposure risk from S3 public access, DynamoDB scans, and logs.

        Evaluates actions that could expose large volumes of data, enable
        public sharing, or allow bulk data extraction.

        Args:
            permissions: List of allowed effective permissions.

        Returns:
            Risk score from 0 (no data exposure risk) to 100 (maximum exposure risk).
        """
        if not permissions:
            return 0

        score = 0
        actions = self._extract_actions(permissions)

        # Direct data exposure actions
        exposure_matches = actions & _DATA_EXPOSURE_ACTIONS
        score += min(40, len(exposure_matches) * 7)

        # S3 public access risk
        s3_public_actions = {
            "s3:PutBucketPolicy",
            "s3:PutBucketAcl",
            "s3:PutObjectAcl",
            "s3:PutBucketPublicAccessBlock",
        }
        public_matches = actions & s3_public_actions
        score += min(30, len(public_matches) * 15)

        # Bulk data operations
        bulk_actions = {"dynamodb:Scan", "athena:StartQueryExecution", "s3:ListBucket"}
        bulk_matches = actions & bulk_actions
        score += min(20, len(bulk_matches) * 10)

        # Access to logs (potential credential/data leakage)
        log_actions = {a for a in actions if a.startswith("logs:")}
        score += min(15, len(log_actions) * 5)

        # Wildcard S3 access
        for perm in permissions:
            if perm.action.startswith("s3:") and perm.resource == "*":
                score += 15
                break

        return min(100, score)

    def _score_persistence(self, permissions: list[EffectivePermission]) -> int:
        """
        Score persistence risk from ability to create backdoors.

        Evaluates actions that enable creating new IAM entities, modifying
        trust policies, establishing event-driven triggers, or installing
        persistent compute.

        Args:
            permissions: List of allowed effective permissions.

        Returns:
            Risk score from 0 (no persistence risk) to 100 (maximum persistence risk).
        """
        if not permissions:
            return 0

        score = 0
        actions = self._extract_actions(permissions)

        # Persistence-enabling actions
        persistence_matches = actions & _PERSISTENCE_ACTIONS
        score += min(60, len(persistence_matches) * 10)

        # Particularly dangerous: trust policy modification
        if "iam:UpdateAssumeRolePolicy" in actions:
            score += 25

        # Access key creation (direct credential backdoor)
        if "iam:CreateAccessKey" in actions:
            score += 20

        # Event-based persistence (CloudWatch Events, Lambda triggers)
        event_actions = {a for a in actions if a.startswith("events:") or a.startswith("scheduler:")}
        if event_actions:
            score += min(15, len(event_actions) * 5)

        return min(100, score)

    def _score_lateral_movement(
        self,
        permissions: list[EffectivePermission],
        attack_paths: list[AttackPath],
    ) -> int:
        """
        Score lateral movement risk from role chaining, Lambda invocation, and SSM.

        Evaluates the ability to pivot to other services, accounts, or compute
        environments. Incorporates known attack paths for path-based scoring.

        Args:
            permissions: List of allowed effective permissions.
            attack_paths: Known attack paths for this agent.

        Returns:
            Risk score from 0 (no lateral movement risk) to 100 (maximum risk).
        """
        if not permissions:
            return 0

        score = 0
        actions = self._extract_actions(permissions)

        # Lateral movement actions
        lateral_matches = actions & _LATERAL_MOVEMENT_ACTIONS
        score += min(50, len(lateral_matches) * 10)

        # Role assumption chains
        assume_actions = {a for a in actions if "AssumeRole" in a}
        score += min(20, len(assume_actions) * 10)

        # SSM access (direct instance access)
        ssm_actions = {a for a in actions if a.startswith("ssm:")}
        if ssm_actions:
            score += min(15, len(ssm_actions) * 5)

        # Attack path bonus: more paths = higher lateral movement risk
        if attack_paths:
            path_bonus = min(25, len(attack_paths) * 5)
            # Weight by average composite score of paths
            avg_composite = sum(p.composite_score for p in attack_paths) / len(attack_paths)
            path_bonus = int(path_bonus * (avg_composite / 100.0)) if avg_composite > 0 else path_bonus
            score += path_bonus

        return min(100, score)

    # ─── Environment and Composite Scoring ────────────────────────────────────

    def _environment_factor(self, agent: AgentIdentity) -> float:
        """
        Compute environment-based risk multiplier.

        Production environments receive a higher multiplier because the same
        permission set poses greater real-world risk in production than in
        development.

        Args:
            agent: The agent identity with environment metadata.

        Returns:
            Multiplier float: production=1.5, staging=1.2, development=0.8.
        """
        environment_multipliers = {
            Environment.PRODUCTION: 1.5,
            Environment.STAGING: 1.2,
            Environment.DEVELOPMENT: 0.8,
        }
        factor = environment_multipliers.get(agent.environment, 1.0)
        logger.debug(
            "Environment factor for '%s' (%s): %.2f",
            agent.name,
            agent.environment.value,
            factor,
        )
        return factor

    def _compute_overall(
        self,
        scores: dict[str, int],
        environment_factor: float,
        behavior_modifier: float = 1.0,
    ) -> float:
        """
        Compute weighted composite risk score with environment multiplier.

        Applies normalized weights to dimension scores, multiplies by the
        environment factor, and clamps the result to [0, 100].

        Args:
            scores: Dictionary of dimension name -> score (0-100).
            environment_factor: Environment-based multiplier.
            behavior_modifier: Optional behavioral anomaly multiplier.

        Returns:
            Final composite score clamped to 0-100.
        """
        normalized_weights = self._weights.normalized()

        weighted_sum = 0.0
        for dimension, weight in normalized_weights.items():
            dimension_score = scores.get(dimension, 0)
            weighted_sum += dimension_score * weight

        # Apply environment factor and behavior modifier
        overall = weighted_sum * environment_factor * behavior_modifier

        # Clamp to valid range
        overall = max(0.0, min(100.0, overall))

        logger.debug(
            "Composite score: weighted_sum=%.2f, env_factor=%.2f, "
            "behavior_mod=%.2f, final=%.2f",
            weighted_sum,
            environment_factor,
            behavior_modifier,
            overall,
        )

        return round(overall, 1)

    # ─── Helper Methods ───────────────────────────────────────────────────────

    def _filter_allowed(
        self, permissions: list[EffectivePermission]
    ) -> list[EffectivePermission]:
        """
        Filter to only ALLOWED and CONDITIONAL permissions for risk scoring.

        DENIED permissions do not contribute to risk because they cannot be exercised.

        Args:
            permissions: All effective permissions.

        Returns:
            Subset of permissions that are ALLOWED or CONDITIONAL.
        """
        from aws_agent_identity_guard.models import EffectiveEffect

        return [
            p
            for p in permissions
            if p.effective_effect in (EffectiveEffect.ALLOWED, EffectiveEffect.CONDITIONAL)
        ]

    def _extract_actions(self, permissions: list[EffectivePermission]) -> set[str]:
        """
        Extract unique action strings from a list of effective permissions.

        Args:
            permissions: List of effective permissions.

        Returns:
            Set of unique action strings.
        """
        return {p.action for p in permissions}

    def _is_cross_account_resource(self, resource: str) -> bool:
        """
        Heuristic check for cross-account resource ARNs.

        Examines the account-id field (position 4) in an ARN to detect
        resources that belong to a different account.

        Args:
            resource: A resource ARN string.

        Returns:
            True if the resource appears to be cross-account.
        """
        if not resource.startswith("arn:"):
            return False
        parts = resource.split(":")
        if len(parts) >= 5:
            account_id = parts[4]
            # Wildcard or empty account_id suggests cross-account potential
            return account_id == "*" or account_id == ""
        return False

    def _behavior_modifier(self, behavior_data: dict[str, Any] | None) -> float:
        """
        Compute behavioral anomaly modifier from analytics data.

        Incorporates signals like unusual access times, velocity anomalies,
        geographic anomalies, and deviation from baseline patterns.

        Args:
            behavior_data: Optional dictionary with behavioral signals.

        Returns:
            Modifier float (1.0 = normal, >1.0 = elevated risk from anomalies).
        """
        if not behavior_data:
            return 1.0

        modifier = 1.0

        # Anomaly score (0.0-1.0 where 1.0 is highly anomalous)
        anomaly_score = behavior_data.get("anomaly_score", 0.0)
        if anomaly_score > 0.8:
            modifier += 0.3
        elif anomaly_score > 0.5:
            modifier += 0.15

        # Velocity anomaly (unusual request rate)
        velocity_anomaly = behavior_data.get("velocity_anomaly", False)
        if velocity_anomaly:
            modifier += 0.1

        # Off-hours access
        off_hours = behavior_data.get("off_hours_access", False)
        if off_hours:
            modifier += 0.1

        # New action pattern (never seen before from this agent)
        new_action = behavior_data.get("new_action_pattern", False)
        if new_action:
            modifier += 0.2

        return min(1.5, modifier)  # Cap at 1.5x

    def _data_classification_boost(self, classification: DataClassification) -> int:
        """
        Compute additional sensitivity score boost based on data classification.

        Args:
            classification: The data classification level of the transaction.

        Returns:
            Additional score to add to sensitivity dimension.
        """
        boosts = {
            DataClassification.PUBLIC: 0,
            DataClassification.INTERNAL: 5,
            DataClassification.CONFIDENTIAL: 15,
            DataClassification.SECRET: 30,
            DataClassification.REGULATED: 35,
        }
        return boosts.get(classification, 0)
