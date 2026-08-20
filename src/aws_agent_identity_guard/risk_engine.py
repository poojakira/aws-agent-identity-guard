"""AWS Agent Identity Guard - Multidimensional Risk Scoring Engine.

Production-grade risk engine that replaces simplistic severity-only findings
with multidimensional scoring across privilege, sensitivity, blast radius,
data exposure, persistence, lateral movement, environment, and transaction context.

The engine supports:
- Configurable risk profiles (strict/standard/permissive)
- Non-linear composite score calculation with toxic combination detection
- Risk scoring for permissions, agents, transactions, attack paths, and drift events
- Weighted dimension combination with risk multipliers

Architecture:
    RiskEngine orchestrates scoring via dimension calculators and a composite
    aggregator. Risk profiles configure thresholds and weights per environment.
    The risk factors catalog maps AWS action patterns to base risk scores.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum, unique
from typing import Any, Optional

from .models import (
    Agent,
    AttackPath,
    AuthorizationRequest,
    DataClassification,
    DriftEvent,
    Environment,
    RiskScore,
    Severity,
)


# =============================================================================
# Risk Level Enumeration
# =============================================================================


@unique
class RiskLevel(str, Enum):
    """Risk classification levels for composite scores."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# =============================================================================
# Risk Calculation Result
# =============================================================================


@dataclass
class RiskCalculation:
    """Result of a multidimensional risk calculation.

    Encapsulates dimension scores, weights, multipliers, composite score,
    risk level classification, and human-readable explanation.

    Attributes:
        dimension_scores: Mapping of dimension name to score (0-100).
        weights: Mapping of dimension name to weight used in calculation.
        multipliers: List of applied risk multipliers with descriptions.
        composite_score: Final aggregated risk score (0-100).
        risk_level: Classification derived from composite score and profile thresholds.
        explanation: Human-readable breakdown of the risk assessment.
    """

    dimension_scores: dict[str, float]
    weights: dict[str, float]
    multipliers: list[dict[str, Any]]
    composite_score: float
    risk_level: RiskLevel
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON compatibility."""
        return {
            "dimension_scores": self.dimension_scores,
            "weights": self.weights,
            "multipliers": self.multipliers,
            "composite_score": self.composite_score,
            "risk_level": self.risk_level.value,
            "explanation": self.explanation,
        }

    def to_risk_score(self) -> RiskScore:
        """Convert to the canonical RiskScore model (0.0-1.0 scale).

        Maps the 0-100 dimension scores to 0.0-1.0 range expected by RiskScore.
        """
        return RiskScore(
            privilege_score=self.dimension_scores.get("privilege_score", 0.0) / 100.0,
            sensitivity_score=self.dimension_scores.get("sensitivity_score", 0.0) / 100.0,
            blast_radius=self.dimension_scores.get("blast_radius", 0.0) / 100.0,
            data_exposure=self.dimension_scores.get("data_exposure", 0.0) / 100.0,
            persistence_risk=self.dimension_scores.get("persistence_risk", 0.0) / 100.0,
            lateral_movement=self.dimension_scores.get("lateral_movement", 0.0) / 100.0,
            environment_risk=self.dimension_scores.get("environment_risk", 0.0) / 100.0,
            transaction_context_risk=self.dimension_scores.get("transaction_context_risk", 0.0) / 100.0,
            composite_score=min(self.composite_score / 100.0, 1.0),
            calculation_details={
                "weights": self.weights,
                "multipliers": self.multipliers,
                "risk_level": self.risk_level.value,
                "explanation": self.explanation,
            },
        )

    @property
    def is_actionable(self) -> bool:
        """Whether this risk level requires action (MEDIUM or above)."""
        return self.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM)

    @property
    def severity(self) -> Severity:
        """Map risk level to Severity enum for compatibility with findings."""
        mapping = {
            RiskLevel.CRITICAL: Severity.CRITICAL,
            RiskLevel.HIGH: Severity.HIGH,
            RiskLevel.MEDIUM: Severity.MEDIUM,
            RiskLevel.LOW: Severity.LOW,
            RiskLevel.INFO: Severity.INFORMATIONAL,
        }
        return mapping[self.risk_level]


# =============================================================================
# Risk Profile Configuration
# =============================================================================


@dataclass
class RiskThresholds:
    """Score thresholds for risk level classification.

    Attributes:
        critical: Score at or above this is CRITICAL.
        high: Score at or above this is HIGH.
        medium: Score at or above this is MEDIUM.
        low: Score at or above this is LOW.
        Below low threshold is INFO.
    """

    critical: float = 85.0
    high: float = 65.0
    medium: float = 40.0
    low: float = 20.0


@dataclass
class RiskProfile:
    """Configurable risk profile controlling weights, thresholds, and multipliers.

    Attributes:
        name: Profile identifier (strict, standard, permissive).
        description: Human-readable description of the profile's purpose.
        weights: Dimension weights for composite score calculation.
        thresholds: Score thresholds for risk level classification.
        toxic_combination_multiplier: Base multiplier for toxic combinations.
        nonlinear_exponent: Exponent for non-linear scaling of high scores.
    """

    name: str
    description: str
    weights: dict[str, float]
    thresholds: RiskThresholds
    toxic_combination_multiplier: float = 1.5
    nonlinear_exponent: float = 1.3

    def classify(self, score: float) -> RiskLevel:
        """Classify a composite score into a risk level.

        Args:
            score: Composite risk score (0-100).

        Returns:
            The corresponding RiskLevel.
        """
        if score >= self.thresholds.critical:
            return RiskLevel.CRITICAL
        if score >= self.thresholds.high:
            return RiskLevel.HIGH
        if score >= self.thresholds.medium:
            return RiskLevel.MEDIUM
        if score >= self.thresholds.low:
            return RiskLevel.LOW
        return RiskLevel.INFO


# =============================================================================
# Default Risk Profiles
# =============================================================================


_DEFAULT_WEIGHTS: dict[str, float] = {
    "privilege_score": 0.25,
    "sensitivity_score": 0.15,
    "blast_radius": 0.15,
    "data_exposure": 0.12,
    "persistence_risk": 0.10,
    "lateral_movement": 0.10,
    "environment_risk": 0.08,
    "transaction_context_risk": 0.05,
}


STRICT_PROFILE = RiskProfile(
    name="strict",
    description="Production environments: lower thresholds, aggressive detection.",
    weights={
        "privilege_score": 0.22,
        "sensitivity_score": 0.16,
        "blast_radius": 0.16,
        "data_exposure": 0.14,
        "persistence_risk": 0.10,
        "lateral_movement": 0.10,
        "environment_risk": 0.07,
        "transaction_context_risk": 0.05,
    },
    thresholds=RiskThresholds(critical=70.0, high=50.0, medium=30.0, low=15.0),
    toxic_combination_multiplier=1.8,
    nonlinear_exponent=1.4,
)

STANDARD_PROFILE = RiskProfile(
    name="standard",
    description="Balanced risk assessment for staging and general workloads.",
    weights=_DEFAULT_WEIGHTS.copy(),
    thresholds=RiskThresholds(critical=85.0, high=65.0, medium=40.0, low=20.0),
    toxic_combination_multiplier=1.5,
    nonlinear_exponent=1.3,
)

PERMISSIVE_PROFILE = RiskProfile(
    name="permissive",
    description="Development environments: higher thresholds, fewer alerts.",
    weights={
        "privilege_score": 0.28,
        "sensitivity_score": 0.12,
        "blast_radius": 0.12,
        "data_exposure": 0.10,
        "persistence_risk": 0.10,
        "lateral_movement": 0.10,
        "environment_risk": 0.08,
        "transaction_context_risk": 0.10,
    },
    thresholds=RiskThresholds(critical=92.0, high=75.0, medium=50.0, low=25.0),
    toxic_combination_multiplier=1.3,
    nonlinear_exponent=1.2,
)

PROFILES: dict[str, RiskProfile] = {
    "strict": STRICT_PROFILE,
    "standard": STANDARD_PROFILE,
    "permissive": PERMISSIVE_PROFILE,
}


# =============================================================================
# Risk Factors Catalog
# =============================================================================


@dataclass
class RiskFactor:
    """A cataloged risk factor mapping an action pattern to base risk scores.

    Attributes:
        pattern: Regex pattern matching AWS action strings.
        base_privilege: Base privilege score for matching actions.
        base_persistence: Base persistence risk for matching actions.
        base_lateral_movement: Base lateral movement risk.
        base_data_exposure: Base data exposure risk.
        base_blast_radius: Base blast radius score.
        description: Human-readable description of why this action is risky.
        tags: Categorization tags (e.g., 'admin', 'destructive', 'read-only').
    """

    pattern: str
    base_privilege: float
    base_persistence: float = 0.0
    base_lateral_movement: float = 0.0
    base_data_exposure: float = 0.0
    base_blast_radius: float = 0.0
    description: str = ""
    tags: list[str] = field(default_factory=list)

    def matches(self, action: str) -> bool:
        """Check if an AWS action string matches this risk factor pattern.

        Args:
            action: AWS action string (e.g., 'iam:CreateRole').

        Returns:
            True if the action matches the pattern.
        """
        return bool(re.match(self.pattern, action, re.IGNORECASE))


# Comprehensive catalog of AWS action risk factors
RISK_FACTORS_CATALOG: list[RiskFactor] = [
    # --- IAM Admin Actions (highest privilege) ---
    RiskFactor(
        pattern=r"iam:(Create|Attach|Put)(Role|User|Group)Policy",
        base_privilege=95.0,
        base_persistence=85.0,
        base_lateral_movement=70.0,
        base_blast_radius=80.0,
        description="Attach or create IAM policies - enables privilege escalation.",
        tags=["admin", "privilege-escalation", "persistence"],
    ),
    RiskFactor(
        pattern=r"iam:CreateRole",
        base_privilege=90.0,
        base_persistence=90.0,
        base_lateral_movement=75.0,
        base_blast_radius=70.0,
        description="Create new IAM roles - persistence and lateral movement vector.",
        tags=["admin", "persistence", "lateral-movement"],
    ),
    RiskFactor(
        pattern=r"iam:PassRole",
        base_privilege=85.0,
        base_persistence=50.0,
        base_lateral_movement=80.0,
        base_blast_radius=60.0,
        description="Pass role to service - enables delegation and lateral movement.",
        tags=["admin", "lateral-movement"],
    ),
    RiskFactor(
        pattern=r"iam:CreateAccessKey",
        base_privilege=85.0,
        base_persistence=95.0,
        base_lateral_movement=60.0,
        base_data_exposure=40.0,
        base_blast_radius=50.0,
        description="Create long-lived access keys - major persistence vector.",
        tags=["admin", "persistence", "credential"],
    ),
    RiskFactor(
        pattern=r"iam:UpdateAssumeRolePolicy",
        base_privilege=90.0,
        base_persistence=80.0,
        base_lateral_movement=90.0,
        base_blast_radius=75.0,
        description="Modify trust policy - cross-account lateral movement.",
        tags=["admin", "lateral-movement", "trust"],
    ),
    RiskFactor(
        pattern=r"iam:CreateUser",
        base_privilege=80.0,
        base_persistence=85.0,
        base_lateral_movement=50.0,
        base_blast_radius=40.0,
        description="Create IAM users - persistence mechanism.",
        tags=["admin", "persistence"],
    ),
    RiskFactor(
        pattern=r"iam:Delete.*",
        base_privilege=80.0,
        base_blast_radius=70.0,
        description="Delete IAM resources - destructive and potentially disruptive.",
        tags=["admin", "destructive"],
    ),
    RiskFactor(
        pattern=r"iam:Put(User|Role)PermissionsBoundary",
        base_privilege=75.0,
        base_blast_radius=60.0,
        description="Modify permission boundaries - weaken security guardrails.",
        tags=["admin", "boundary"],
    ),
    RiskFactor(
        pattern=r"iam:(Get|List).*",
        base_privilege=15.0,
        base_data_exposure=20.0,
        description="Read IAM configuration - reconnaissance activity.",
        tags=["read-only", "reconnaissance"],
    ),
    # --- STS Actions ---
    RiskFactor(
        pattern=r"sts:AssumeRole",
        base_privilege=70.0,
        base_lateral_movement=85.0,
        base_blast_radius=50.0,
        description="Assume another role - primary lateral movement mechanism.",
        tags=["lateral-movement", "session"],
    ),
    RiskFactor(
        pattern=r"sts:GetFederationToken",
        base_privilege=65.0,
        base_persistence=50.0,
        base_lateral_movement=40.0,
        description="Get federation token - creates temporary persistent access.",
        tags=["persistence", "session"],
    ),
    # --- Lambda Actions ---
    RiskFactor(
        pattern=r"lambda:CreateFunction",
        base_privilege=75.0,
        base_persistence=70.0,
        base_lateral_movement=65.0,
        base_blast_radius=55.0,
        description="Create Lambda function - code execution with role assumption.",
        tags=["compute", "persistence", "lateral-movement"],
    ),
    RiskFactor(
        pattern=r"lambda:UpdateFunctionCode",
        base_privilege=70.0,
        base_persistence=60.0,
        base_lateral_movement=50.0,
        description="Update Lambda code - inject code running with function's role.",
        tags=["compute", "persistence"],
    ),
    RiskFactor(
        pattern=r"lambda:AddPermission",
        base_privilege=65.0,
        base_lateral_movement=55.0,
        base_blast_radius=45.0,
        description="Add Lambda resource policy - enable cross-account invocation.",
        tags=["compute", "lateral-movement"],
    ),
    RiskFactor(
        pattern=r"lambda:(Invoke|InvokeFunction)",
        base_privilege=40.0,
        base_blast_radius=30.0,
        description="Invoke Lambda function - execute code in target context.",
        tags=["compute", "execution"],
    ),
    # --- S3 Data Actions ---
    RiskFactor(
        pattern=r"s3:PutBucketPolicy",
        base_privilege=80.0,
        base_data_exposure=85.0,
        base_blast_radius=75.0,
        description="Modify bucket policy - expose data publicly or cross-account.",
        tags=["data", "exposure", "destructive"],
    ),
    RiskFactor(
        pattern=r"s3:DeleteBucket",
        base_privilege=75.0,
        base_blast_radius=90.0,
        base_data_exposure=50.0,
        description="Delete S3 bucket - destructive data loss.",
        tags=["data", "destructive"],
    ),
    RiskFactor(
        pattern=r"s3:PutObject",
        base_privilege=35.0,
        base_data_exposure=30.0,
        description="Write objects to S3 - data modification capability.",
        tags=["data", "write"],
    ),
    RiskFactor(
        pattern=r"s3:GetObject",
        base_privilege=20.0,
        base_data_exposure=45.0,
        description="Read S3 objects - potential data exfiltration.",
        tags=["data", "read", "exfiltration"],
    ),
    RiskFactor(
        pattern=r"s3:(List|Get).*",
        base_privilege=10.0,
        base_data_exposure=15.0,
        description="List/Get S3 metadata - reconnaissance.",
        tags=["data", "read-only", "reconnaissance"],
    ),
    # --- EC2/Networking ---
    RiskFactor(
        pattern=r"ec2:RunInstances",
        base_privilege=70.0,
        base_persistence=65.0,
        base_blast_radius=60.0,
        description="Launch EC2 instances - compute with assumed roles.",
        tags=["compute", "persistence"],
    ),
    RiskFactor(
        pattern=r"ec2:(AuthorizeSecurityGroupIngress|AuthorizeSecurityGroupEgress)",
        base_privilege=65.0,
        base_blast_radius=70.0,
        description="Modify security groups - open network access.",
        tags=["network", "exposure"],
    ),
    RiskFactor(
        pattern=r"ec2:CreateVpcPeeringConnection",
        base_privilege=60.0,
        base_lateral_movement=70.0,
        base_blast_radius=65.0,
        description="Create VPC peering - lateral network movement.",
        tags=["network", "lateral-movement"],
    ),
    # --- KMS Actions ---
    RiskFactor(
        pattern=r"kms:Decrypt",
        base_privilege=50.0,
        base_data_exposure=75.0,
        description="Decrypt data - access to encrypted sensitive content.",
        tags=["crypto", "data-access"],
    ),
    RiskFactor(
        pattern=r"kms:(ScheduleKeyDeletion|DisableKey)",
        base_privilege=85.0,
        base_blast_radius=90.0,
        description="Disable/delete KMS keys - cryptographic denial of service.",
        tags=["crypto", "destructive"],
    ),
    RiskFactor(
        pattern=r"kms:CreateGrant",
        base_privilege=60.0,
        base_lateral_movement=50.0,
        base_persistence=45.0,
        description="Create KMS grant - delegate decryption to other principals.",
        tags=["crypto", "delegation"],
    ),
    # --- Organizations / Cross-Account ---
    RiskFactor(
        pattern=r"organizations:.*",
        base_privilege=90.0,
        base_blast_radius=95.0,
        base_lateral_movement=80.0,
        description="Organization-level actions - maximum blast radius.",
        tags=["admin", "org-level"],
    ),
    # --- Secrets Manager / SSM ---
    RiskFactor(
        pattern=r"secretsmanager:GetSecretValue",
        base_privilege=50.0,
        base_data_exposure=85.0,
        description="Retrieve secrets - access to credentials and sensitive config.",
        tags=["data", "credential", "sensitive"],
    ),
    RiskFactor(
        pattern=r"ssm:GetParameter.*",
        base_privilege=30.0,
        base_data_exposure=55.0,
        description="Read SSM parameters - may contain secrets.",
        tags=["data", "credential"],
    ),
    # --- CloudTrail / Logging ---
    RiskFactor(
        pattern=r"cloudtrail:(StopLogging|DeleteTrail|UpdateTrail)",
        base_privilege=90.0,
        base_blast_radius=85.0,
        description="Disable/modify audit logging - cover tracks.",
        tags=["defense-evasion", "destructive"],
    ),
    # --- Catch-all patterns ---
    RiskFactor(
        pattern=r".*:Create.*",
        base_privilege=40.0,
        base_persistence=30.0,
        base_blast_radius=25.0,
        description="Generic create action - moderate resource creation risk.",
        tags=["create"],
    ),
    RiskFactor(
        pattern=r".*:Delete.*",
        base_privilege=50.0,
        base_blast_radius=50.0,
        description="Generic delete action - destructive capability.",
        tags=["destructive"],
    ),
    RiskFactor(
        pattern=r".*:(List|Get|Describe).*",
        base_privilege=10.0,
        base_data_exposure=10.0,
        description="Generic read action - low risk reconnaissance.",
        tags=["read-only"],
    ),
]


# =============================================================================
# Toxic Combination Definitions
# =============================================================================


@dataclass
class ToxicCombination:
    """Definition of a toxic combination of actions that amplifies risk.

    When multiple actions from a toxic combination are present together,
    the combined risk exceeds the sum of individual risks.

    Attributes:
        name: Identifier for this toxic combination.
        description: Why this combination is dangerous.
        action_patterns: Regex patterns that must all be present.
        multiplier: Risk multiplier when the combination is detected.
        affected_dimensions: Which dimensions are amplified.
    """

    name: str
    description: str
    action_patterns: list[str]
    multiplier: float
    affected_dimensions: list[str]

    def matches(self, actions: list[str]) -> bool:
        """Check if a set of actions triggers this toxic combination.

        Args:
            actions: List of AWS action strings to evaluate.

        Returns:
            True if all patterns in the combination have at least one match.
        """
        for pattern in self.action_patterns:
            if not any(re.match(pattern, action, re.IGNORECASE) for action in actions):
                return False
        return True


TOXIC_COMBINATIONS: list[ToxicCombination] = [
    ToxicCombination(
        name="passrole_create_function",
        description="PassRole + CreateFunction enables arbitrary code execution as any passable role.",
        action_patterns=[r"iam:PassRole", r"lambda:CreateFunction"],
        multiplier=2.0,
        affected_dimensions=["privilege_score", "lateral_movement", "persistence_risk"],
    ),
    ToxicCombination(
        name="passrole_run_instances",
        description="PassRole + RunInstances enables launching EC2 with elevated roles.",
        action_patterns=[r"iam:PassRole", r"ec2:RunInstances"],
        multiplier=1.8,
        affected_dimensions=["privilege_score", "lateral_movement", "persistence_risk"],
    ),
    ToxicCombination(
        name="create_role_attach_policy",
        description="CreateRole + AttachRolePolicy enables creating admin-equivalent roles.",
        action_patterns=[r"iam:CreateRole", r"iam:Attach(Role|User|Group)Policy"],
        multiplier=2.2,
        affected_dimensions=["privilege_score", "persistence_risk", "blast_radius"],
    ),
    ToxicCombination(
        name="assume_role_create_key",
        description="AssumeRole + CreateAccessKey enables persistent access via assumed identity.",
        action_patterns=[r"sts:AssumeRole", r"iam:CreateAccessKey"],
        multiplier=1.9,
        affected_dimensions=["persistence_risk", "lateral_movement"],
    ),
    ToxicCombination(
        name="update_trust_assume_role",
        description="UpdateAssumeRolePolicy + AssumeRole enables cross-account takeover.",
        action_patterns=[r"iam:UpdateAssumeRolePolicy", r"sts:AssumeRole"],
        multiplier=2.1,
        affected_dimensions=["lateral_movement", "blast_radius", "privilege_score"],
    ),
    ToxicCombination(
        name="get_secret_exfil",
        description="GetSecretValue + S3 write enables secret exfiltration.",
        action_patterns=[r"secretsmanager:GetSecretValue", r"s3:PutObject"],
        multiplier=1.7,
        affected_dimensions=["data_exposure", "blast_radius"],
    ),
    ToxicCombination(
        name="disable_logging_destructive",
        description="StopLogging + destructive actions enables undetected destruction.",
        action_patterns=[r"cloudtrail:(StopLogging|DeleteTrail)", r".*:Delete.*"],
        multiplier=2.3,
        affected_dimensions=["blast_radius", "privilege_score"],
    ),
    ToxicCombination(
        name="kms_disable_s3_access",
        description="DisableKey + S3 access enables ransomware-style denial of access.",
        action_patterns=[r"kms:(ScheduleKeyDeletion|DisableKey)", r"s3:(GetObject|PutObject)"],
        multiplier=2.0,
        affected_dimensions=["blast_radius", "data_exposure"],
    ),
    ToxicCombination(
        name="create_user_attach_admin",
        description="CreateUser + AttachUserPolicy enables creating shadow admin accounts.",
        action_patterns=[r"iam:CreateUser", r"iam:Attach(User|Role)Policy"],
        multiplier=2.0,
        affected_dimensions=["privilege_score", "persistence_risk", "blast_radius"],
    ),
    ToxicCombination(
        name="vpc_peering_lateral",
        description="VPC peering + security group modification enables network lateral movement.",
        action_patterns=[r"ec2:CreateVpcPeeringConnection", r"ec2:AuthorizeSecurityGroup.*"],
        multiplier=1.6,
        affected_dimensions=["lateral_movement", "blast_radius"],
    ),
]


# =============================================================================
# Resource Sensitivity Mapping
# =============================================================================


_RESOURCE_SENSITIVITY_PATTERNS: list[tuple[str, float]] = [
    # Production / critical infrastructure
    (r".*:prod(uction)?[:/\-].*", 90.0),
    (r".*arn:aws:iam::\d+:root.*", 100.0),
    (r".*arn:aws:organizations::.*", 95.0),
    # Secrets and credentials
    (r".*arn:aws:secretsmanager:.*", 85.0),
    (r".*arn:aws:kms:.*", 80.0),
    (r".*arn:aws:ssm:.*:parameter/.*secret.*", 80.0),
    (r".*arn:aws:ssm:.*:parameter/.*password.*", 80.0),
    # Data stores
    (r".*arn:aws:s3:::.*-confidential.*", 85.0),
    (r".*arn:aws:s3:::.*-sensitive.*", 80.0),
    (r".*arn:aws:rds:.*", 70.0),
    (r".*arn:aws:dynamodb:.*", 60.0),
    (r".*arn:aws:s3:::.*", 40.0),
    # IAM
    (r".*arn:aws:iam:.*:role/Admin.*", 90.0),
    (r".*arn:aws:iam:.*:role/.*", 60.0),
    (r".*arn:aws:iam:.*:user/.*", 55.0),
    (r".*arn:aws:iam:.*:policy/.*", 50.0),
    # Compute
    (r".*arn:aws:lambda:.*", 45.0),
    (r".*arn:aws:ec2:.*", 40.0),
    (r".*arn:aws:ecs:.*", 40.0),
    # Logging / monitoring
    (r".*arn:aws:cloudtrail:.*", 75.0),
    (r".*arn:aws:logs:.*", 35.0),
    # Wildcard resource
    (r"^\*$", 85.0),
    # Default fallback
    (r".*", 20.0),
]


def _score_resource_sensitivity(resource: str) -> float:
    """Score resource sensitivity based on ARN pattern matching.

    Args:
        resource: AWS resource ARN or wildcard.

    Returns:
        Sensitivity score 0-100.
    """
    for pattern, score in _RESOURCE_SENSITIVITY_PATTERNS:
        if re.match(pattern, resource, re.IGNORECASE):
            return score
    return 20.0


# =============================================================================
# Data Classification to Score Mapping
# =============================================================================


_DATA_CLASSIFICATION_SCORES: dict[DataClassification, float] = {
    DataClassification.PUBLIC: 10.0,
    DataClassification.INTERNAL: 30.0,
    DataClassification.CONFIDENTIAL: 60.0,
    DataClassification.SECRET: 85.0,
    DataClassification.REGULATED: 95.0,
}


# =============================================================================
# Environment Risk Scores
# =============================================================================


_ENVIRONMENT_RISK_SCORES: dict[Environment, float] = {
    Environment.DEV: 20.0,
    Environment.STAGING: 50.0,
    Environment.PRODUCTION: 90.0,
}


# =============================================================================
# Main Risk Engine
# =============================================================================


class RiskEngine:
    """Multidimensional risk scoring engine for AWS agent identity analysis.

    Replaces simplistic severity-only findings with comprehensive scoring
    across eight risk dimensions, applying non-linear scaling, configurable
    weights, and toxic combination multipliers.

    Usage:
        engine = RiskEngine(profile="strict")
        result = engine.score_permission("iam:PassRole", "*", context={...})
        print(result.composite_score, result.risk_level)

    Attributes:
        profile: The active risk profile controlling weights and thresholds.
        risk_factors: The catalog of action-to-risk mappings.
        toxic_combinations: Detected toxic combination patterns.
    """

    def __init__(
        self,
        profile: str | RiskProfile = "standard",
        custom_weights: dict[str, float] | None = None,
        custom_thresholds: RiskThresholds | None = None,
        risk_factors: list[RiskFactor] | None = None,
        toxic_combinations: list[ToxicCombination] | None = None,
    ) -> None:
        """Initialize the risk engine with a risk profile.

        Args:
            profile: Profile name ('strict', 'standard', 'permissive') or RiskProfile instance.
            custom_weights: Override default dimension weights.
            custom_thresholds: Override default risk thresholds.
            risk_factors: Custom risk factors catalog (defaults to built-in).
            toxic_combinations: Custom toxic combinations (defaults to built-in).

        Raises:
            ValueError: If profile name is not recognized.
        """
        if isinstance(profile, str):
            if profile not in PROFILES:
                raise ValueError(
                    f"Unknown profile '{profile}'. Available: {list(PROFILES.keys())}"
                )
            self._profile = PROFILES[profile]
        else:
            self._profile = profile

        # Apply custom overrides
        if custom_weights:
            self._profile.weights.update(custom_weights)
        if custom_thresholds:
            self._profile.thresholds = custom_thresholds

        self._risk_factors = risk_factors if risk_factors is not None else RISK_FACTORS_CATALOG
        self._toxic_combinations = (
            toxic_combinations if toxic_combinations is not None else TOXIC_COMBINATIONS
        )

    @property
    def profile(self) -> RiskProfile:
        """The active risk profile."""
        return self._profile

    @property
    def risk_factors(self) -> list[RiskFactor]:
        """The risk factors catalog."""
        return self._risk_factors

    @property
    def toxic_combinations(self) -> list[ToxicCombination]:
        """The toxic combination definitions."""
        return self._toxic_combinations

    # -------------------------------------------------------------------------
    # Public Scoring Methods
    # -------------------------------------------------------------------------

    def score_permission(
        self,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> RiskCalculation:
        """Score an individual permission (action + resource pair).

        Evaluates a single AWS permission against the risk factors catalog,
        resource sensitivity, and any provided context.

        Args:
            action: AWS action string (e.g., 'iam:CreateRole').
            resource: AWS resource ARN or wildcard.
            context: Optional context dict with keys:
                - environment: Environment enum or string
                - data_classification: DataClassification enum or string
                - related_actions: list of other actions in the same policy
                - transaction_id: correlation identifier

        Returns:
            RiskCalculation with dimension scores and composite result.
        """
        context = context or {}
        dimensions = self._calculate_permission_dimensions(action, resource, context)
        multipliers = self._detect_toxic_combinations_for_actions(
            [action] + context.get("related_actions", [])
        )
        return self._compute_composite(dimensions, multipliers, context)

    def score_agent(self, agent: Agent) -> RiskCalculation:
        """Score an agent's overall risk posture.

        Evaluates the agent's entire permission set, environment,
        data classification, and configuration to produce an
        aggregate risk assessment.

        Args:
            agent: Agent instance with identity policies and metadata.

        Returns:
            RiskCalculation representing the agent's aggregate risk posture.
        """
        # Collect all actions from identity policies
        all_actions = self._extract_actions_from_policies(agent.identity_policies)
        all_resources = self._extract_resources_from_policies(agent.identity_policies)

        # Score each action and aggregate
        dimension_scores: dict[str, float] = {
            "privilege_score": 0.0,
            "sensitivity_score": 0.0,
            "blast_radius": 0.0,
            "data_exposure": 0.0,
            "persistence_risk": 0.0,
            "lateral_movement": 0.0,
            "environment_risk": 0.0,
            "transaction_context_risk": 0.0,
        }

        if all_actions:
            # Take the maximum risk across all actions for each dimension
            for action in all_actions:
                factor_scores = self._get_factor_scores(action)
                dimension_scores["privilege_score"] = max(
                    dimension_scores["privilege_score"], factor_scores.get("privilege_score", 0.0)
                )
                dimension_scores["persistence_risk"] = max(
                    dimension_scores["persistence_risk"], factor_scores.get("persistence_risk", 0.0)
                )
                dimension_scores["lateral_movement"] = max(
                    dimension_scores["lateral_movement"], factor_scores.get("lateral_movement", 0.0)
                )
                dimension_scores["data_exposure"] = max(
                    dimension_scores["data_exposure"], factor_scores.get("data_exposure", 0.0)
                )
                dimension_scores["blast_radius"] = max(
                    dimension_scores["blast_radius"], factor_scores.get("blast_radius", 0.0)
                )

        # Resource sensitivity from all resources
        if all_resources:
            max_sensitivity = max(_score_resource_sensitivity(r) for r in all_resources)
            dimension_scores["sensitivity_score"] = max_sensitivity
        else:
            dimension_scores["sensitivity_score"] = _DATA_CLASSIFICATION_SCORES.get(
                agent.data_classification, 30.0
            )

        # Environment risk
        dimension_scores["environment_risk"] = _ENVIRONMENT_RISK_SCORES.get(
            agent.environment, 50.0
        )

        # Blast radius boost for wildcard resources
        if "*" in all_resources:
            dimension_scores["blast_radius"] = max(dimension_scores["blast_radius"], 85.0)

        # Boost for number of permissions (more permissions = larger blast radius)
        permission_count_factor = min(len(all_actions) / 50.0, 1.0) * 30.0
        dimension_scores["blast_radius"] = min(
            100.0, dimension_scores["blast_radius"] + permission_count_factor
        )

        # Transaction context is not applicable for static agent scoring
        dimension_scores["transaction_context_risk"] = 0.0

        # Detect toxic combinations
        multipliers = self._detect_toxic_combinations_for_actions(all_actions)

        context = {
            "environment": agent.environment,
            "data_classification": agent.data_classification,
            "agent_id": agent.agent_id,
            "scoring_type": "agent_posture",
        }
        return self._compute_composite(dimension_scores, multipliers, context)

    def score_transaction(self, auth_request: AuthorizationRequest) -> RiskCalculation:
        """Score a real-time authorization transaction.

        Evaluates the risk of a specific action being performed right now,
        considering the full transaction context including who, what, where,
        and the current risk posture.

        Args:
            auth_request: AuthorizationRequest with agent, action, resource, and context.

        Returns:
            RiskCalculation for the transaction with real-time context scoring.
        """
        context: dict[str, Any] = {
            "environment": auth_request.context.get("environment"),
            "data_classification": auth_request.data_classification,
            "related_actions": auth_request.risk_context.get("related_actions", []),
            "scoring_type": "transaction",
            "agent_id": auth_request.agent_id,
            "principal": auth_request.principal,
        }

        # Calculate base dimensions from the action
        dimensions = self._calculate_permission_dimensions(
            auth_request.action, auth_request.resource, context
        )

        # Transaction context risk based on risk_context signals
        transaction_risk = self._calculate_transaction_context_risk(auth_request)
        dimensions["transaction_context_risk"] = transaction_risk

        # Data classification override for sensitivity
        classification_score = _DATA_CLASSIFICATION_SCORES.get(
            auth_request.data_classification, 30.0
        )
        dimensions["sensitivity_score"] = max(
            dimensions["sensitivity_score"], classification_score
        )

        # Detect toxic combinations with related actions
        all_actions = [auth_request.action] + auth_request.risk_context.get("related_actions", [])
        multipliers = self._detect_toxic_combinations_for_actions(all_actions)

        return self._compute_composite(dimensions, multipliers, context)

    def score_attack_path(self, path: AttackPath) -> RiskCalculation:
        """Score an attack path based on its steps, likelihood, and impact.

        Evaluates a multi-step attack chain considering the cumulative risk
        of each step, the overall likelihood, and target impact.

        Args:
            path: AttackPath with steps, likelihood, and impact assessments.

        Returns:
            RiskCalculation reflecting the attack path's composite risk.
        """
        if not path.steps:
            return self._zero_calculation("No steps in attack path.")

        # Collect all actions in the path
        step_actions = [step.action for step in path.steps]

        # Score each step and take the maximum per dimension
        dimensions: dict[str, float] = {
            "privilege_score": 0.0,
            "sensitivity_score": 0.0,
            "blast_radius": 0.0,
            "data_exposure": 0.0,
            "persistence_risk": 0.0,
            "lateral_movement": 0.0,
            "environment_risk": 50.0,  # Default to medium without context
            "transaction_context_risk": 0.0,
        }

        for step in path.steps:
            factor_scores = self._get_factor_scores(step.action)
            resource_sensitivity = _score_resource_sensitivity(step.resource)

            dimensions["privilege_score"] = max(
                dimensions["privilege_score"], factor_scores.get("privilege_score", 0.0)
            )
            dimensions["sensitivity_score"] = max(
                dimensions["sensitivity_score"], resource_sensitivity
            )
            dimensions["persistence_risk"] = max(
                dimensions["persistence_risk"], factor_scores.get("persistence_risk", 0.0)
            )
            dimensions["lateral_movement"] = max(
                dimensions["lateral_movement"], factor_scores.get("lateral_movement", 0.0)
            )
            dimensions["data_exposure"] = max(
                dimensions["data_exposure"], factor_scores.get("data_exposure", 0.0)
            )
            dimensions["blast_radius"] = max(
                dimensions["blast_radius"], factor_scores.get("blast_radius", 0.0)
            )

        # Multi-step chains inherently have higher lateral movement and blast radius
        step_count_boost = min(len(path.steps) * 10.0, 40.0)
        dimensions["lateral_movement"] = min(
            100.0, dimensions["lateral_movement"] + step_count_boost
        )
        dimensions["blast_radius"] = min(
            100.0, dimensions["blast_radius"] + step_count_boost * 0.5
        )

        # Apply likelihood and impact as scaling factors
        likelihood_factor = path.likelihood
        impact_factor = path.impact

        # Scale dimensions by likelihood (an unlikely path is less risky)
        for dim in dimensions:
            dimensions[dim] = dimensions[dim] * (0.5 + 0.5 * likelihood_factor)

        # Boost by impact
        impact_boost = impact_factor * 20.0
        dimensions["blast_radius"] = min(100.0, dimensions["blast_radius"] + impact_boost)

        # Detect toxic combinations across path steps
        multipliers = self._detect_toxic_combinations_for_actions(step_actions)

        context: dict[str, Any] = {
            "scoring_type": "attack_path",
            "source": path.source_node,
            "target": path.target,
            "step_count": len(path.steps),
            "likelihood": path.likelihood,
            "impact": path.impact,
        }
        return self._compute_composite(dimensions, multipliers, context)

    def score_drift(self, drift_event: DriftEvent) -> RiskCalculation:
        """Score a permission drift event based on what changed.

        Evaluates the risk implications of permissions being added or
        removed from an agent's baseline.

        Args:
            drift_event: DriftEvent with added and removed permissions.

        Returns:
            RiskCalculation reflecting the drift's risk.
        """
        if not drift_event.has_drift:
            return self._zero_calculation("No drift detected.")

        dimensions: dict[str, float] = {
            "privilege_score": 0.0,
            "sensitivity_score": 0.0,
            "blast_radius": 0.0,
            "data_exposure": 0.0,
            "persistence_risk": 0.0,
            "lateral_movement": 0.0,
            "environment_risk": 50.0,
            "transaction_context_risk": 0.0,
        }

        # Added permissions are the primary risk vector
        for permission in drift_event.permissions_added:
            factor_scores = self._get_factor_scores(permission)
            dimensions["privilege_score"] = max(
                dimensions["privilege_score"], factor_scores.get("privilege_score", 0.0)
            )
            dimensions["persistence_risk"] = max(
                dimensions["persistence_risk"], factor_scores.get("persistence_risk", 0.0)
            )
            dimensions["lateral_movement"] = max(
                dimensions["lateral_movement"], factor_scores.get("lateral_movement", 0.0)
            )
            dimensions["data_exposure"] = max(
                dimensions["data_exposure"], factor_scores.get("data_exposure", 0.0)
            )
            dimensions["blast_radius"] = max(
                dimensions["blast_radius"], factor_scores.get("blast_radius", 0.0)
            )

        # More permissions added = higher blast radius
        added_count_factor = min(len(drift_event.permissions_added) / 20.0, 1.0) * 40.0
        dimensions["blast_radius"] = min(100.0, dimensions["blast_radius"] + added_count_factor)

        # Removed permissions can also indicate risk (removing boundaries)
        for permission in drift_event.permissions_removed:
            # Removing deny rules or boundaries is suspicious
            if any(
                keyword in permission.lower()
                for keyword in ["deny", "boundary", "condition"]
            ):
                dimensions["privilege_score"] = min(
                    100.0, dimensions["privilege_score"] + 20.0
                )

        # Drift itself is a persistence concern
        dimensions["persistence_risk"] = max(dimensions["persistence_risk"], 40.0)

        # Sensitivity based on what was added
        if drift_event.permissions_added:
            max_sensitivity = max(
                _score_resource_sensitivity(p) for p in drift_event.permissions_added
            )
            dimensions["sensitivity_score"] = max(
                dimensions["sensitivity_score"], max_sensitivity * 0.6
            )

        # Detect toxic combinations in newly added permissions
        multipliers = self._detect_toxic_combinations_for_actions(
            drift_event.permissions_added
        )

        context: dict[str, Any] = {
            "scoring_type": "drift",
            "agent_id": drift_event.agent_id,
            "permissions_added_count": len(drift_event.permissions_added),
            "permissions_removed_count": len(drift_event.permissions_removed),
        }
        return self._compute_composite(dimensions, multipliers, context)

    # -------------------------------------------------------------------------
    # Internal Calculation Methods
    # -------------------------------------------------------------------------

    def _calculate_permission_dimensions(
        self,
        action: str,
        resource: str,
        context: dict[str, Any],
    ) -> dict[str, float]:
        """Calculate dimension scores for a single permission.

        Args:
            action: AWS action string.
            resource: AWS resource ARN or wildcard.
            context: Additional context for scoring.

        Returns:
            Dictionary of dimension name to score (0-100).
        """
        factor_scores = self._get_factor_scores(action)

        dimensions: dict[str, float] = {
            "privilege_score": factor_scores.get("privilege_score", 20.0),
            "sensitivity_score": _score_resource_sensitivity(resource),
            "blast_radius": factor_scores.get("blast_radius", 20.0),
            "data_exposure": factor_scores.get("data_exposure", 10.0),
            "persistence_risk": factor_scores.get("persistence_risk", 10.0),
            "lateral_movement": factor_scores.get("lateral_movement", 10.0),
            "environment_risk": 50.0,  # Default medium
            "transaction_context_risk": 0.0,
        }

        # Wildcard resource boosts blast radius and sensitivity
        if resource == "*":
            dimensions["blast_radius"] = max(dimensions["blast_radius"], 85.0)
            dimensions["sensitivity_score"] = max(dimensions["sensitivity_score"], 70.0)

        # Environment context
        env = context.get("environment")
        if env:
            if isinstance(env, str):
                try:
                    env = Environment(env)
                except ValueError:
                    env = None
            if isinstance(env, Environment):
                dimensions["environment_risk"] = _ENVIRONMENT_RISK_SCORES[env]

        # Data classification context
        data_class = context.get("data_classification")
        if data_class:
            if isinstance(data_class, str):
                try:
                    data_class = DataClassification(data_class)
                except ValueError:
                    data_class = None
            if isinstance(data_class, DataClassification):
                classification_score = _DATA_CLASSIFICATION_SCORES[data_class]
                dimensions["sensitivity_score"] = max(
                    dimensions["sensitivity_score"], classification_score
                )
                dimensions["data_exposure"] = max(
                    dimensions["data_exposure"], classification_score * 0.7
                )

        return dimensions

    def _calculate_transaction_context_risk(
        self, auth_request: AuthorizationRequest
    ) -> float:
        """Calculate transaction-specific context risk.

        Factors in real-time signals like unusual timing, frequency,
        and behavioral anomalies from the risk_context.

        Args:
            auth_request: The authorization request with risk context.

        Returns:
            Transaction context risk score (0-100).
        """
        risk_context = auth_request.risk_context
        score = 0.0

        # Frequency anomaly (too many requests in short time)
        request_rate = risk_context.get("request_rate_per_minute", 0)
        if request_rate > 100:
            score += 40.0
        elif request_rate > 50:
            score += 25.0
        elif request_rate > 20:
            score += 10.0

        # First-time action
        if risk_context.get("first_time_action", False):
            score += 25.0

        # Unusual source IP or region
        if risk_context.get("unusual_source", False):
            score += 30.0

        # Time-based risk (outside business hours)
        if risk_context.get("outside_business_hours", False):
            score += 15.0

        # Elevated recent failure rate
        failure_rate = risk_context.get("recent_failure_rate", 0.0)
        if failure_rate > 0.5:
            score += 20.0
        elif failure_rate > 0.2:
            score += 10.0

        # Anomaly score from external detection
        anomaly_score = risk_context.get("anomaly_score", 0.0)
        score += anomaly_score * 30.0

        return min(score, 100.0)

    def _get_factor_scores(self, action: str) -> dict[str, float]:
        """Look up risk factor scores for an action from the catalog.

        Returns the first matching factor's base scores. Actions are
        matched against patterns in priority order (most specific first).

        Args:
            action: AWS action string to look up.

        Returns:
            Dictionary of base scores from the matching risk factor.
        """
        for factor in self._risk_factors:
            if factor.matches(action):
                return {
                    "privilege_score": factor.base_privilege,
                    "persistence_risk": factor.base_persistence,
                    "lateral_movement": factor.base_lateral_movement,
                    "data_exposure": factor.base_data_exposure,
                    "blast_radius": factor.base_blast_radius,
                }
        # No matching factor - return conservative defaults
        return {
            "privilege_score": 20.0,
            "persistence_risk": 10.0,
            "lateral_movement": 10.0,
            "data_exposure": 10.0,
            "blast_radius": 15.0,
        }

    def _detect_toxic_combinations_for_actions(
        self, actions: list[str]
    ) -> list[dict[str, Any]]:
        """Detect toxic combinations present in a set of actions.

        Args:
            actions: List of AWS action strings to check.

        Returns:
            List of triggered toxic combination descriptors.
        """
        triggered: list[dict[str, Any]] = []
        for combo in self._toxic_combinations:
            if combo.matches(actions):
                triggered.append({
                    "name": combo.name,
                    "description": combo.description,
                    "multiplier": combo.multiplier,
                    "affected_dimensions": combo.affected_dimensions,
                })
        return triggered

    def _compute_composite(
        self,
        dimensions: dict[str, float],
        multipliers: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> RiskCalculation:
        """Compute the composite risk score from dimensions and multipliers.

        Applies:
        1. Weighted combination of dimension scores
        2. Non-linear scaling for high-privilege + high-environment scenarios
        3. Toxic combination multipliers
        4. Clamping to 0-100 range

        Args:
            dimensions: Dimension name to score (0-100) mapping.
            multipliers: Triggered toxic combination descriptors.
            context: Scoring context for explanation generation.

        Returns:
            Complete RiskCalculation.
        """
        weights = self._profile.weights

        # Ensure all dimensions have values
        for dim in weights:
            if dim not in dimensions:
                dimensions[dim] = 0.0

        # --- Step 1: Weighted linear combination ---
        weighted_sum = sum(
            dimensions.get(dim, 0.0) * weight
            for dim, weight in weights.items()
        )

        # --- Step 2: Non-linear scaling ---
        # When privilege is very high AND environment is production, amplify risk
        privilege = dimensions.get("privilege_score", 0.0)
        env_risk = dimensions.get("environment_risk", 0.0)

        nonlinear_boost = 0.0
        if privilege >= 80.0 and env_risk >= 80.0:
            # Both are high - apply exponential boost
            excess = ((privilege - 70.0) / 30.0) * ((env_risk - 70.0) / 30.0)
            nonlinear_boost = excess * 25.0 * self._profile.nonlinear_exponent

        # Also boost when any single dimension is critically high
        max_dimension = max(dimensions.values()) if dimensions else 0.0
        if max_dimension >= 90.0:
            critical_boost = ((max_dimension - 85.0) / 15.0) ** self._profile.nonlinear_exponent * 10.0
            nonlinear_boost = max(nonlinear_boost, critical_boost)

        composite = weighted_sum + nonlinear_boost

        # --- Step 3: Toxic combination multipliers ---
        applied_multiplier = 1.0
        for mult_info in multipliers:
            # Apply the multiplier proportionally based on affected dimensions
            affected_dims = mult_info.get("affected_dimensions", [])
            if affected_dims:
                affected_avg = sum(
                    dimensions.get(d, 0.0) for d in affected_dims
                ) / len(affected_dims)
                # Scale multiplier by how high the affected dimensions already are
                effective_multiplier = 1.0 + (mult_info["multiplier"] - 1.0) * (
                    affected_avg / 100.0
                )
                applied_multiplier = max(applied_multiplier, effective_multiplier)

        composite *= applied_multiplier

        # --- Step 4: Clamp ---
        composite = max(0.0, min(100.0, composite))

        # --- Classification ---
        risk_level = self._profile.classify(composite)

        # --- Explanation ---
        explanation = self._generate_explanation(
            dimensions, multipliers, composite, risk_level, context
        )

        return RiskCalculation(
            dimension_scores=dimensions,
            weights=weights,
            multipliers=multipliers,
            composite_score=round(composite, 2),
            risk_level=risk_level,
            explanation=explanation,
        )

    def _generate_explanation(
        self,
        dimensions: dict[str, float],
        multipliers: list[dict[str, Any]],
        composite: float,
        risk_level: RiskLevel,
        context: dict[str, Any],
    ) -> str:
        """Generate a human-readable explanation of the risk calculation.

        Args:
            dimensions: Scored dimensions.
            multipliers: Triggered multipliers.
            composite: Final composite score.
            risk_level: Classified risk level.
            context: Scoring context.

        Returns:
            Multi-line explanation string.
        """
        lines: list[str] = []
        scoring_type = context.get("scoring_type", "permission")
        lines.append(f"Risk Assessment ({scoring_type}): {risk_level.value} ({composite:.1f}/100)")
        lines.append("")

        # Top contributing dimensions
        sorted_dims = sorted(dimensions.items(), key=lambda x: x[1], reverse=True)
        top_dims = [d for d in sorted_dims if d[1] > 0][:5]
        if top_dims:
            lines.append("Top risk dimensions:")
            for dim_name, dim_score in top_dims:
                label = dim_name.replace("_", " ").title()
                lines.append(f"  - {label}: {dim_score:.0f}/100")

        # Toxic combinations
        if multipliers:
            lines.append("")
            lines.append("Toxic combinations detected:")
            for mult in multipliers:
                lines.append(f"  - {mult['name']}: {mult['description']} (x{mult['multiplier']:.1f})")

        # Non-linear factors
        privilege = dimensions.get("privilege_score", 0.0)
        env_risk = dimensions.get("environment_risk", 0.0)
        if privilege >= 80.0 and env_risk >= 80.0:
            lines.append("")
            lines.append(
                "⚠ Non-linear amplification: high privilege in production environment."
            )

        return "\n".join(lines)

    def _zero_calculation(self, reason: str) -> RiskCalculation:
        """Return a zero-risk calculation with an explanation.

        Args:
            reason: Why the risk is zero.

        Returns:
            RiskCalculation with all zeros and INFO level.
        """
        zero_dimensions = {
            "privilege_score": 0.0,
            "sensitivity_score": 0.0,
            "blast_radius": 0.0,
            "data_exposure": 0.0,
            "persistence_risk": 0.0,
            "lateral_movement": 0.0,
            "environment_risk": 0.0,
            "transaction_context_risk": 0.0,
        }
        return RiskCalculation(
            dimension_scores=zero_dimensions,
            weights=self._profile.weights,
            multipliers=[],
            composite_score=0.0,
            risk_level=RiskLevel.INFO,
            explanation=f"Risk Assessment: INFO (0.0/100)\n\n{reason}",
        )

    # -------------------------------------------------------------------------
    # Policy Extraction Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _extract_actions_from_policies(policies: list[dict[str, Any]]) -> list[str]:
        """Extract all action strings from IAM policy documents.

        Args:
            policies: List of IAM policy document dictionaries.

        Returns:
            Deduplicated list of action strings.
        """
        actions: set[str] = set()
        for policy in policies:
            statements = policy.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for statement in statements:
                if statement.get("Effect", "").upper() == "ALLOW":
                    stmt_actions = statement.get("Action", [])
                    if isinstance(stmt_actions, str):
                        stmt_actions = [stmt_actions]
                    actions.update(stmt_actions)
        return sorted(actions)

    @staticmethod
    def _extract_resources_from_policies(policies: list[dict[str, Any]]) -> list[str]:
        """Extract all resource ARNs from IAM policy documents.

        Args:
            policies: List of IAM policy document dictionaries.

        Returns:
            Deduplicated list of resource ARN strings.
        """
        resources: set[str] = set()
        for policy in policies:
            statements = policy.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for statement in statements:
                if statement.get("Effect", "").upper() == "ALLOW":
                    stmt_resources = statement.get("Resource", [])
                    if isinstance(stmt_resources, str):
                        stmt_resources = [stmt_resources]
                    resources.update(stmt_resources)
        return sorted(resources)


# =============================================================================
# Convenience Functions
# =============================================================================


def create_engine(
    environment: Environment | None = None,
    profile: str | None = None,
) -> RiskEngine:
    """Create a RiskEngine with appropriate profile for the environment.

    If no explicit profile is given, selects based on environment:
    - PRODUCTION -> strict
    - STAGING -> standard
    - DEV -> permissive

    Args:
        environment: Target environment for profile selection.
        profile: Explicit profile name override.

    Returns:
        Configured RiskEngine instance.
    """
    if profile:
        return RiskEngine(profile=profile)

    if environment:
        env_profile_map = {
            Environment.PRODUCTION: "strict",
            Environment.STAGING: "standard",
            Environment.DEV: "permissive",
        }
        return RiskEngine(profile=env_profile_map.get(environment, "standard"))

    return RiskEngine(profile="standard")


def quick_score(action: str, resource: str = "*", environment: str = "production") -> RiskCalculation:
    """Quick one-shot risk scoring for a single action.

    Convenience function for rapid risk assessment without engine setup.

    Args:
        action: AWS action string (e.g., 'iam:PassRole').
        resource: AWS resource ARN or wildcard. Defaults to '*'.
        environment: Environment string. Defaults to 'production'.

    Returns:
        RiskCalculation for the action.
    """
    try:
        env = Environment(environment)
    except ValueError:
        env = Environment.PRODUCTION

    engine = create_engine(environment=env)
    return engine.score_permission(action, resource, context={"environment": env})


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Core classes
    "RiskEngine",
    "RiskCalculation",
    "RiskLevel",
    "RiskProfile",
    "RiskThresholds",
    "RiskFactor",
    "ToxicCombination",
    # Profiles
    "STRICT_PROFILE",
    "STANDARD_PROFILE",
    "PERMISSIVE_PROFILE",
    "PROFILES",
    # Catalogs
    "RISK_FACTORS_CATALOG",
    "TOXIC_COMBINATIONS",
    # Convenience
    "create_engine",
    "quick_score",
]
