"""AWS Agent Identity Guard - Core Domain Models.

Production-grade data models for agent identity management, authorization,
risk scoring, audit, and compliance in AWS environments.

This module defines the canonical representations for:
- Agent identities and their associated IAM constructs
- Permission evaluation across policy layers
- Authorization request/decision lifecycle
- Risk scoring with multi-dimensional analysis
- Policy-as-code rule definitions
- Audit trail with cryptographic integrity
- Approval workflows
- Attack path analysis
- Permission drift detection
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, unique
from typing import Any, Optional


# =============================================================================
# Enumerations
# =============================================================================


@unique
class DataClassification(str, Enum):
    """Data sensitivity classification levels."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    REGULATED = "REGULATED"

    def __gt__(self, other: DataClassification) -> bool:
        order = list(DataClassification)
        return order.index(self) > order.index(other)

    def __ge__(self, other: DataClassification) -> bool:
        order = list(DataClassification)
        return order.index(self) >= order.index(other)


@unique
class Environment(str, Enum):
    """Deployment environment tiers."""

    DEV = "dev"
    STAGING = "staging"
    PRODUCTION = "production"


@unique
class WorkloadType(str, Enum):
    """AWS workload types that can host agent identities."""

    BEDROCK_AGENT = "BEDROCK_AGENT"
    LAMBDA = "LAMBDA"
    ECS = "ECS"
    EKS = "EKS"
    SAGEMAKER = "SAGEMAKER"
    CUSTOM = "CUSTOM"


@unique
class Decision(str, Enum):
    """Authorization decision outcomes."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    STEP_UP = "STEP_UP"
    REVIEW = "REVIEW"


@unique
class Severity(str, Enum):
    """Finding severity levels aligned with AWS Security Hub."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@unique
class ApprovalStatus(str, Enum):
    """Approval workflow states."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


@unique
class PermissionEffect(str, Enum):
    """IAM permission effect types."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    CONDITION_DEPENDENT = "CONDITION_DEPENDENT"


@unique
class PermissionSource(str, Enum):
    """Source of a permission grant or denial."""

    IDENTITY_POLICY = "identity_policy"
    RESOURCE_POLICY = "resource_policy"
    SCP = "scp"
    PERMISSION_BOUNDARY = "permission_boundary"
    SESSION_POLICY = "session_policy"


@unique
class AgentStatus(str, Enum):
    """Agent lifecycle status."""

    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    SUSPENDED = "SUSPENDED"
    DECOMMISSIONED = "DECOMMISSIONED"


@unique
class FindingCategory(str, Enum):
    """Categories for security findings."""

    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    EXCESSIVE_PERMISSIONS = "EXCESSIVE_PERMISSIONS"
    DATA_EXPOSURE = "DATA_EXPOSURE"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PERSISTENCE = "PERSISTENCE"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    DRIFT = "DRIFT"
    COMPLIANCE = "COMPLIANCE"
    CONFIGURATION = "CONFIGURATION"


# =============================================================================
# Helper Mixins
# =============================================================================


class SerializableMixin:
    """Mixin providing consistent serialization for dataclasses."""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the instance to a dictionary.

        Handles datetime, Enum, and nested dataclass serialization.
        """
        return _serialize(asdict(self))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Any:
        """Deserialize a dictionary into an instance.

        Subclasses with complex fields should override this method
        for proper type reconstruction.
        """
        return cls(**data)


def _serialize(obj: Any) -> Any:
    """Recursively serialize objects for JSON compatibility."""
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialize(item) for item in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    return obj


def _utcnow() -> datetime:
    """Return current UTC time with timezone info."""
    return datetime.now(timezone.utc)


# =============================================================================
# Core Models
# =============================================================================


@dataclass
class Permission(SerializableMixin):
    """A single permission statement from an IAM policy layer.

    Represents one action/resource/effect tuple as evaluated from
    a specific policy source.
    """

    __slots__ = ("action", "resource", "effect", "conditions", "source")

    action: str
    resource: str
    effect: PermissionEffect
    conditions: dict[str, Any]
    source: PermissionSource

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Permission:
        """Reconstruct a Permission from a dictionary."""
        return cls(
            action=data["action"],
            resource=data["resource"],
            effect=PermissionEffect(data["effect"]),
            conditions=data.get("conditions", {}),
            source=PermissionSource(data["source"]),
        )

    @classmethod
    def allow(
        cls,
        action: str,
        resource: str,
        source: PermissionSource,
        conditions: dict[str, Any] | None = None,
    ) -> Permission:
        """Factory for an ALLOW permission."""
        return cls(
            action=action,
            resource=resource,
            effect=PermissionEffect.ALLOW,
            conditions=conditions or {},
            source=source,
        )

    @classmethod
    def deny(
        cls,
        action: str,
        resource: str,
        source: PermissionSource,
        conditions: dict[str, Any] | None = None,
    ) -> Permission:
        """Factory for a DENY permission."""
        return cls(
            action=action,
            resource=resource,
            effect=PermissionEffect.DENY,
            conditions=conditions or {},
            source=source,
        )


@dataclass
class EffectivePermission(SerializableMixin):
    """Resolved permission after evaluating all IAM policy layers.

    This is the final determination of whether an action on a resource
    is allowed or denied, considering identity policies, resource policies,
    SCPs, permission boundaries, and session policies.
    """

    __slots__ = (
        "action",
        "resource",
        "effect",
        "contributing_policies",
        "evaluation_path",
        "conditions_required",
        "resolved_at",
    )

    action: str
    resource: str
    effect: PermissionEffect
    contributing_policies: list[Permission]
    evaluation_path: list[str]
    conditions_required: dict[str, Any]
    resolved_at: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EffectivePermission:
        """Reconstruct an EffectivePermission from a dictionary."""
        return cls(
            action=data["action"],
            resource=data["resource"],
            effect=PermissionEffect(data["effect"]),
            contributing_policies=[
                Permission.from_dict(p) for p in data.get("contributing_policies", [])
            ],
            evaluation_path=data.get("evaluation_path", []),
            conditions_required=data.get("conditions_required", {}),
            resolved_at=datetime.fromisoformat(data["resolved_at"])
            if isinstance(data.get("resolved_at"), str)
            else data.get("resolved_at", _utcnow()),
        )

    @classmethod
    def create(
        cls,
        action: str,
        resource: str,
        effect: PermissionEffect,
        contributing_policies: list[Permission] | None = None,
        evaluation_path: list[str] | None = None,
        conditions_required: dict[str, Any] | None = None,
    ) -> EffectivePermission:
        """Factory method for creating an EffectivePermission."""
        return cls(
            action=action,
            resource=resource,
            effect=effect,
            contributing_policies=contributing_policies or [],
            evaluation_path=evaluation_path or [],
            conditions_required=conditions_required or {},
            resolved_at=_utcnow(),
        )


@dataclass
class RiskScore(SerializableMixin):
    """Multi-dimensional risk assessment for an agent action.

    Each dimension is scored 0.0-1.0. The composite_score is a weighted
    aggregate considering all risk dimensions and context.
    """

    __slots__ = (
        "privilege_score",
        "sensitivity_score",
        "blast_radius",
        "data_exposure",
        "persistence_risk",
        "lateral_movement",
        "environment_risk",
        "transaction_context_risk",
        "composite_score",
        "calculation_details",
    )

    privilege_score: float
    sensitivity_score: float
    blast_radius: float
    data_exposure: float
    persistence_risk: float
    lateral_movement: float
    environment_risk: float
    transaction_context_risk: float
    composite_score: float
    calculation_details: dict[str, Any]

    def __post_init__(self) -> None:
        """Validate score ranges."""
        score_fields = [
            "privilege_score",
            "sensitivity_score",
            "blast_radius",
            "data_exposure",
            "persistence_risk",
            "lateral_movement",
            "environment_risk",
            "transaction_context_risk",
            "composite_score",
        ]
        for field_name in score_fields:
            value = getattr(self, field_name)
            if not (0.0 <= value <= 1.0):
                raise ValueError(
                    f"{field_name} must be between 0.0 and 1.0, got {value}"
                )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RiskScore:
        """Reconstruct a RiskScore from a dictionary."""
        return cls(
            privilege_score=float(data["privilege_score"]),
            sensitivity_score=float(data["sensitivity_score"]),
            blast_radius=float(data["blast_radius"]),
            data_exposure=float(data["data_exposure"]),
            persistence_risk=float(data["persistence_risk"]),
            lateral_movement=float(data["lateral_movement"]),
            environment_risk=float(data["environment_risk"]),
            transaction_context_risk=float(data["transaction_context_risk"]),
            composite_score=float(data["composite_score"]),
            calculation_details=data.get("calculation_details", {}),
        )

    @classmethod
    def zero(cls) -> RiskScore:
        """Factory for a zero-risk score (baseline)."""
        return cls(
            privilege_score=0.0,
            sensitivity_score=0.0,
            blast_radius=0.0,
            data_exposure=0.0,
            persistence_risk=0.0,
            lateral_movement=0.0,
            environment_risk=0.0,
            transaction_context_risk=0.0,
            composite_score=0.0,
            calculation_details={"method": "zero_baseline"},
        )

    @property
    def is_high_risk(self) -> bool:
        """Whether the composite score exceeds the high-risk threshold."""
        return self.composite_score >= 0.7

    @property
    def is_critical(self) -> bool:
        """Whether the composite score exceeds the critical threshold."""
        return self.composite_score >= 0.9


@dataclass
class AttackStep(SerializableMixin):
    """A single step in an attack path."""

    __slots__ = ("action", "resource", "technique", "prerequisites", "description")

    action: str
    resource: str
    technique: str
    prerequisites: list[str]
    description: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackStep:
        """Reconstruct an AttackStep from a dictionary."""
        return cls(
            action=data["action"],
            resource=data["resource"],
            technique=data.get("technique", ""),
            prerequisites=data.get("prerequisites", []),
            description=data.get("description", ""),
        )


@dataclass
class AttackPath(SerializableMixin):
    """A potential attack path from a source to a target.

    Models multi-step privilege escalation or lateral movement
    chains that an agent could exploit.
    """

    __slots__ = (
        "source_node",
        "steps",
        "target",
        "likelihood",
        "impact",
        "description",
    )

    source_node: str
    steps: list[AttackStep]
    target: str
    likelihood: float
    impact: float
    description: str

    def __post_init__(self) -> None:
        """Validate likelihood and impact ranges."""
        if not (0.0 <= self.likelihood <= 1.0):
            raise ValueError(
                f"likelihood must be between 0.0 and 1.0, got {self.likelihood}"
            )
        if not (0.0 <= self.impact <= 1.0):
            raise ValueError(f"impact must be between 0.0 and 1.0, got {self.impact}")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackPath:
        """Reconstruct an AttackPath from a dictionary."""
        return cls(
            source_node=data["source_node"],
            steps=[AttackStep.from_dict(s) for s in data.get("steps", [])],
            target=data["target"],
            likelihood=float(data["likelihood"]),
            impact=float(data["impact"]),
            description=data.get("description", ""),
        )

    @property
    def risk_rating(self) -> float:
        """Combined risk rating (likelihood * impact)."""
        return self.likelihood * self.impact


@dataclass
class Finding(SerializableMixin):
    """Security finding produced by analysis rules.

    Represents a detected issue, policy violation, or risk condition
    with actionable remediation guidance and compliance context.
    """

    __slots__ = (
        "rule_id",
        "severity",
        "category",
        "message",
        "remediation",
        "attack_chain",
        "risk_score",
        "affected_resources",
        "compliance_mappings",
    )

    rule_id: str
    severity: Severity
    category: FindingCategory
    message: str
    remediation: str
    attack_chain: list[AttackStep]
    risk_score: float
    affected_resources: list[str]
    compliance_mappings: dict[str, list[str]]

    def __post_init__(self) -> None:
        """Validate risk_score range."""
        if not (0.0 <= self.risk_score <= 1.0):
            raise ValueError(
                f"risk_score must be between 0.0 and 1.0, got {self.risk_score}"
            )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Reconstruct a Finding from a dictionary."""
        return cls(
            rule_id=data["rule_id"],
            severity=Severity(data["severity"]),
            category=FindingCategory(data["category"]),
            message=data["message"],
            remediation=data.get("remediation", ""),
            attack_chain=[
                AttackStep.from_dict(s) for s in data.get("attack_chain", [])
            ],
            risk_score=float(data.get("risk_score", 0.0)),
            affected_resources=data.get("affected_resources", []),
            compliance_mappings=data.get("compliance_mappings", {}),
        )

    @classmethod
    def create(
        cls,
        rule_id: str,
        severity: Severity,
        category: FindingCategory,
        message: str,
        remediation: str = "",
        affected_resources: list[str] | None = None,
        compliance_mappings: dict[str, list[str]] | None = None,
        risk_score: float = 0.0,
    ) -> Finding:
        """Factory method with sensible defaults."""
        return cls(
            rule_id=rule_id,
            severity=severity,
            category=category,
            message=message,
            remediation=remediation,
            attack_chain=[],
            risk_score=risk_score,
            affected_resources=affected_resources or [],
            compliance_mappings=compliance_mappings or {},
        )


@dataclass
class Agent(SerializableMixin):
    """Core agent identity representation.

    Encapsulates all identity, permission, and metadata attributes
    for an AWS agent workload, including its IAM configuration and
    operational context.
    """

    __slots__ = (
        "agent_id",
        "name",
        "owner",
        "environment",
        "purpose",
        "workload_type",
        "iam_role_arn",
        "trust_policy",
        "identity_policies",
        "permission_boundaries",
        "data_classification",
        "tags",
        "created_at",
        "last_activity",
        "status",
    )

    agent_id: str
    name: str
    owner: str
    environment: Environment
    purpose: str
    workload_type: WorkloadType
    iam_role_arn: str
    trust_policy: dict[str, Any]
    identity_policies: list[dict[str, Any]]
    permission_boundaries: list[str]
    data_classification: DataClassification
    tags: dict[str, str]
    created_at: datetime
    last_activity: Optional[datetime]
    status: AgentStatus

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Agent:
        """Reconstruct an Agent from a dictionary."""
        return cls(
            agent_id=data["agent_id"],
            name=data["name"],
            owner=data["owner"],
            environment=Environment(data["environment"]),
            purpose=data.get("purpose", ""),
            workload_type=WorkloadType(data["workload_type"]),
            iam_role_arn=data["iam_role_arn"],
            trust_policy=data.get("trust_policy", {}),
            identity_policies=data.get("identity_policies", []),
            permission_boundaries=data.get("permission_boundaries", []),
            data_classification=DataClassification(data["data_classification"]),
            tags=data.get("tags", {}),
            created_at=datetime.fromisoformat(data["created_at"])
            if isinstance(data.get("created_at"), str)
            else data.get("created_at", _utcnow()),
            last_activity=datetime.fromisoformat(data["last_activity"])
            if isinstance(data.get("last_activity"), str)
            else data.get("last_activity"),
            status=AgentStatus(data.get("status", "ACTIVE")),
        )

    @classmethod
    def create(
        cls,
        name: str,
        owner: str,
        environment: Environment,
        workload_type: WorkloadType,
        iam_role_arn: str,
        purpose: str = "",
        data_classification: DataClassification = DataClassification.INTERNAL,
        tags: dict[str, str] | None = None,
    ) -> Agent:
        """Factory method for creating a new Agent with generated ID and timestamps."""
        return cls(
            agent_id=str(uuid.uuid4()),
            name=name,
            owner=owner,
            environment=environment,
            purpose=purpose,
            workload_type=workload_type,
            iam_role_arn=iam_role_arn,
            trust_policy={},
            identity_policies=[],
            permission_boundaries=[],
            data_classification=data_classification,
            tags=tags or {},
            created_at=_utcnow(),
            last_activity=None,
            status=AgentStatus.ACTIVE,
        )

    @property
    def is_production(self) -> bool:
        """Whether this agent operates in a production environment."""
        return self.environment == Environment.PRODUCTION

    @property
    def is_active(self) -> bool:
        """Whether the agent is currently active."""
        return self.status == AgentStatus.ACTIVE


# =============================================================================
# Authorization Models
# =============================================================================


@dataclass
class AuthorizationRequest(SerializableMixin):
    """Request to authorize an agent action.

    Captures the full context needed for policy evaluation,
    including the agent identity, requested action, target resource,
    and ambient risk context.
    """

    __slots__ = (
        "agent_id",
        "principal",
        "tool",
        "action",
        "resource",
        "data_classification",
        "context",
        "risk_context",
        "environment",
    )

    agent_id: str
    principal: str
    tool: str
    action: str
    resource: str
    data_classification: DataClassification
    context: dict[str, Any]
    risk_context: dict[str, Any]
    environment: Optional[Environment]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthorizationRequest:
        """Reconstruct an AuthorizationRequest from a dictionary."""
        env = None
        if "environment" in data and data["environment"]:
            try:
                env = Environment(data["environment"])
            except (ValueError, KeyError):
                env = None
        return cls(
            agent_id=data["agent_id"],
            principal=data["principal"],
            tool=data.get("tool", ""),
            action=data["action"],
            resource=data["resource"],
            data_classification=DataClassification(data["data_classification"]),
            context=data.get("context", {}),
            risk_context=data.get("risk_context", {}),
            environment=env,
        )

    @classmethod
    def create(
        cls,
        agent_id: str,
        principal: str,
        action: str,
        resource: str,
        tool: str = "",
        data_classification: DataClassification = DataClassification.INTERNAL,
        context: dict[str, Any] | None = None,
        risk_context: dict[str, Any] | None = None,
        environment: Optional[Environment] = None,
    ) -> AuthorizationRequest:
        """Factory method with defaults for optional fields."""
        return cls(
            agent_id=agent_id,
            principal=principal,
            tool=tool,
            action=action,
            resource=resource,
            data_classification=data_classification,
            context=context or {},
            risk_context=risk_context or {},
            environment=environment,
        )


@dataclass
class AuthorizationDecision(SerializableMixin):
    """Result of an authorization evaluation.

    Contains the decision, supporting rationale, risk assessment,
    and audit correlation information.
    """

    __slots__ = (
        "decision",
        "risk_score",
        "reasons",
        "policy_ref",
        "explanation",
        "correlation_id",
        "timestamp",
    )

    decision: Decision
    risk_score: float
    reasons: list[str]
    policy_ref: str
    explanation: str
    correlation_id: str
    timestamp: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthorizationDecision:
        """Reconstruct an AuthorizationDecision from a dictionary."""
        return cls(
            decision=Decision(data["decision"]),
            risk_score=float(data.get("risk_score", 0.0)),
            reasons=data.get("reasons", []),
            policy_ref=data.get("policy_ref", ""),
            explanation=data.get("explanation", ""),
            correlation_id=data.get("correlation_id", ""),
            timestamp=datetime.fromisoformat(data["timestamp"])
            if isinstance(data.get("timestamp"), str)
            else data.get("timestamp", _utcnow()),
        )

    @classmethod
    def allow(
        cls,
        reasons: list[str] | None = None,
        policy_ref: str = "",
        explanation: str = "Access granted",
        risk_score: float = 0.0,
    ) -> AuthorizationDecision:
        """Factory for an ALLOW decision."""
        return cls(
            decision=Decision.ALLOW,
            risk_score=risk_score,
            reasons=reasons or [],
            policy_ref=policy_ref,
            explanation=explanation,
            correlation_id=str(uuid.uuid4()),
            timestamp=_utcnow(),
        )

    @classmethod
    def deny(
        cls,
        reasons: list[str],
        policy_ref: str = "",
        explanation: str = "Access denied",
        risk_score: float = 1.0,
    ) -> AuthorizationDecision:
        """Factory for a DENY decision."""
        return cls(
            decision=Decision.DENY,
            risk_score=risk_score,
            reasons=reasons,
            policy_ref=policy_ref,
            explanation=explanation,
            correlation_id=str(uuid.uuid4()),
            timestamp=_utcnow(),
        )

    @classmethod
    def step_up(
        cls,
        reasons: list[str],
        policy_ref: str = "",
        explanation: str = "Additional verification required",
        risk_score: float = 0.5,
    ) -> AuthorizationDecision:
        """Factory for a STEP_UP decision requiring elevated auth."""
        return cls(
            decision=Decision.STEP_UP,
            risk_score=risk_score,
            reasons=reasons,
            policy_ref=policy_ref,
            explanation=explanation,
            correlation_id=str(uuid.uuid4()),
            timestamp=_utcnow(),
        )

    @classmethod
    def review(
        cls,
        reasons: list[str],
        policy_ref: str = "",
        explanation: str = "Human review required",
        risk_score: float = 0.6,
    ) -> AuthorizationDecision:
        """Factory for a REVIEW decision requiring human approval."""
        return cls(
            decision=Decision.REVIEW,
            risk_score=risk_score,
            reasons=reasons,
            policy_ref=policy_ref,
            explanation=explanation,
            correlation_id=str(uuid.uuid4()),
            timestamp=_utcnow(),
        )


# =============================================================================
# Policy-as-Code Models
# =============================================================================


@dataclass
class PolicyRule(SerializableMixin):
    """Policy-as-code rule definition.

    Defines an authorization rule with action patterns, resource patterns,
    effect, conditions, and applicable environments. Supports glob-style
    matching for actions and resources.
    """

    __slots__ = (
        "rule_id",
        "name",
        "description",
        "action_patterns",
        "resource_patterns",
        "effect",
        "conditions",
        "environments",
        "priority",
        "enabled",
    )

    rule_id: str
    name: str
    description: str
    action_patterns: list[str]
    resource_patterns: list[str]
    effect: PermissionEffect
    conditions: dict[str, Any]
    environments: list[Environment]
    priority: int
    enabled: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyRule:
        """Reconstruct a PolicyRule from a dictionary."""
        return cls(
            rule_id=data["rule_id"],
            name=data.get("name", ""),
            description=data.get("description", ""),
            action_patterns=data.get("action_patterns", []),
            resource_patterns=data.get("resource_patterns", []),
            effect=PermissionEffect(data["effect"]),
            conditions=data.get("conditions", {}),
            environments=[Environment(e) for e in data.get("environments", [])],
            priority=int(data.get("priority", 0)),
            enabled=data.get("enabled", True),
        )

    @classmethod
    def create(
        cls,
        name: str,
        action_patterns: list[str],
        resource_patterns: list[str],
        effect: PermissionEffect,
        environments: list[Environment] | None = None,
        conditions: dict[str, Any] | None = None,
        description: str = "",
        priority: int = 0,
    ) -> PolicyRule:
        """Factory method for creating a new policy rule."""
        return cls(
            rule_id=str(uuid.uuid4()),
            name=name,
            description=description,
            action_patterns=action_patterns,
            resource_patterns=resource_patterns,
            effect=effect,
            conditions=conditions or {},
            environments=environments or list(Environment),
            priority=priority,
            enabled=True,
        )


# =============================================================================
# Audit and Compliance Models
# =============================================================================


@dataclass
class AuditEvent(SerializableMixin):
    """Immutable audit trail entry with cryptographic integrity.

    Records who performed what action, on which resource, with what
    decision, and maintains a hash chain for tamper detection.
    """

    __slots__ = (
        "who",
        "agent",
        "action",
        "resource",
        "decision",
        "reason",
        "policy_version",
        "timestamp",
        "correlation_id",
        "integrity_hash",
    )

    who: str
    agent: str
    action: str
    resource: str
    decision: Decision
    reason: str
    policy_version: str
    timestamp: datetime
    correlation_id: str
    integrity_hash: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEvent:
        """Reconstruct an AuditEvent from a dictionary."""
        return cls(
            who=data["who"],
            agent=data["agent"],
            action=data["action"],
            resource=data["resource"],
            decision=Decision(data["decision"]),
            reason=data.get("reason", ""),
            policy_version=data.get("policy_version", ""),
            timestamp=datetime.fromisoformat(data["timestamp"])
            if isinstance(data.get("timestamp"), str)
            else data.get("timestamp", _utcnow()),
            correlation_id=data.get("correlation_id", ""),
            integrity_hash=data.get("integrity_hash", ""),
        )

    @classmethod
    def create(
        cls,
        who: str,
        agent: str,
        action: str,
        resource: str,
        decision: Decision,
        reason: str = "",
        policy_version: str = "",
        correlation_id: str | None = None,
        previous_hash: str = "",
    ) -> AuditEvent:
        """Factory method that computes the integrity hash automatically.

        Args:
            who: The principal performing the action.
            agent: The agent identity involved.
            action: The action being performed.
            resource: The target resource.
            decision: The authorization decision.
            reason: Human-readable reason for the decision.
            policy_version: Version of the policy that was evaluated.
            correlation_id: Optional correlation ID (generated if not provided).
            previous_hash: Hash of the previous audit event for chaining.
        """
        ts = _utcnow()
        cid = correlation_id or str(uuid.uuid4())

        # Compute integrity hash over event content + previous hash
        hash_input = json.dumps(
            {
                "who": who,
                "agent": agent,
                "action": action,
                "resource": resource,
                "decision": decision.value,
                "reason": reason,
                "policy_version": policy_version,
                "timestamp": ts.isoformat(),
                "correlation_id": cid,
                "previous_hash": previous_hash,
            },
            sort_keys=True,
        )
        integrity_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

        return cls(
            who=who,
            agent=agent,
            action=action,
            resource=resource,
            decision=decision,
            reason=reason,
            policy_version=policy_version,
            timestamp=ts,
            correlation_id=cid,
            integrity_hash=integrity_hash,
        )

    def verify_integrity(self, previous_hash: str = "") -> bool:
        """Verify the integrity hash of this event.

        Args:
            previous_hash: The hash of the previous event in the chain.

        Returns:
            True if the hash matches, False if tampered.
        """
        hash_input = json.dumps(
            {
                "who": self.who,
                "agent": self.agent,
                "action": self.action,
                "resource": self.resource,
                "decision": self.decision.value,
                "reason": self.reason,
                "policy_version": self.policy_version,
                "timestamp": self.timestamp.isoformat(),
                "correlation_id": self.correlation_id,
                "previous_hash": previous_hash,
            },
            sort_keys=True,
        )
        expected = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
        return self.integrity_hash == expected


# =============================================================================
# Approval Workflow Models
# =============================================================================


@dataclass
class ApprovalRequest(SerializableMixin):
    """Request for human approval of a sensitive agent action.

    Used when policy evaluation determines that a human must
    approve before an action can proceed.
    """

    __slots__ = (
        "request_id",
        "agent_id",
        "action",
        "resource",
        "requestor",
        "approver",
        "status",
        "expiry",
        "created_at",
    )

    request_id: str
    agent_id: str
    action: str
    resource: str
    requestor: str
    approver: str
    status: ApprovalStatus
    expiry: datetime
    created_at: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApprovalRequest:
        """Reconstruct an ApprovalRequest from a dictionary."""
        return cls(
            request_id=data["request_id"],
            agent_id=data["agent_id"],
            action=data["action"],
            resource=data["resource"],
            requestor=data["requestor"],
            approver=data.get("approver", ""),
            status=ApprovalStatus(data.get("status", "PENDING")),
            expiry=datetime.fromisoformat(data["expiry"])
            if isinstance(data.get("expiry"), str)
            else data.get("expiry", _utcnow()),
            created_at=datetime.fromisoformat(data["created_at"])
            if isinstance(data.get("created_at"), str)
            else data.get("created_at", _utcnow()),
        )

    @classmethod
    def create(
        cls,
        agent_id: str,
        action: str,
        resource: str,
        requestor: str,
        approver: str = "",
        expiry: datetime | None = None,
    ) -> ApprovalRequest:
        """Factory for a new pending approval request.

        Args:
            agent_id: The agent requesting approval.
            action: The action requiring approval.
            resource: The target resource.
            requestor: Who initiated the request.
            approver: Designated approver (can be assigned later).
            expiry: When the request expires. Defaults to 1 hour from now.
        """
        from datetime import timedelta

        now = _utcnow()
        return cls(
            request_id=str(uuid.uuid4()),
            agent_id=agent_id,
            action=action,
            resource=resource,
            requestor=requestor,
            approver=approver,
            status=ApprovalStatus.PENDING,
            expiry=expiry or (now + timedelta(hours=1)),
            created_at=now,
        )

    @property
    def is_expired(self) -> bool:
        """Whether the approval request has expired."""
        return _utcnow() > self.expiry

    @property
    def is_pending(self) -> bool:
        """Whether the approval is still pending."""
        return self.status == ApprovalStatus.PENDING and not self.is_expired


# =============================================================================
# Drift Detection Models
# =============================================================================


@dataclass
class DriftEvent(SerializableMixin):
    """Permission drift detection event.

    Captures changes between the expected baseline permissions and
    the current state, enabling detection of unauthorized modifications.
    """

    __slots__ = (
        "agent_id",
        "permissions_added",
        "permissions_removed",
        "detected_at",
        "baseline_snapshot",
        "current_snapshot",
    )

    agent_id: str
    permissions_added: list[str]
    permissions_removed: list[str]
    detected_at: datetime
    baseline_snapshot: dict[str, Any]
    current_snapshot: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DriftEvent:
        """Reconstruct a DriftEvent from a dictionary."""
        return cls(
            agent_id=data["agent_id"],
            permissions_added=data.get("permissions_added", []),
            permissions_removed=data.get("permissions_removed", []),
            detected_at=datetime.fromisoformat(data["detected_at"])
            if isinstance(data.get("detected_at"), str)
            else data.get("detected_at", _utcnow()),
            baseline_snapshot=data.get("baseline_snapshot", {}),
            current_snapshot=data.get("current_snapshot", {}),
        )

    @classmethod
    def create(
        cls,
        agent_id: str,
        permissions_added: list[str] | None = None,
        permissions_removed: list[str] | None = None,
        baseline_snapshot: dict[str, Any] | None = None,
        current_snapshot: dict[str, Any] | None = None,
    ) -> DriftEvent:
        """Factory for creating a drift event at current time."""
        return cls(
            agent_id=agent_id,
            permissions_added=permissions_added or [],
            permissions_removed=permissions_removed or [],
            detected_at=_utcnow(),
            baseline_snapshot=baseline_snapshot or {},
            current_snapshot=current_snapshot or {},
        )

    @property
    def has_drift(self) -> bool:
        """Whether any permission changes were detected."""
        return bool(self.permissions_added or self.permissions_removed)

    @property
    def drift_summary(self) -> str:
        """Human-readable summary of the drift."""
        parts = []
        if self.permissions_added:
            parts.append(f"+{len(self.permissions_added)} added")
        if self.permissions_removed:
            parts.append(f"-{len(self.permissions_removed)} removed")
        return ", ".join(parts) if parts else "no drift"


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Enums
    "DataClassification",
    "Environment",
    "WorkloadType",
    "Decision",
    "Severity",
    "ApprovalStatus",
    "PermissionEffect",
    "PermissionSource",
    "AgentStatus",
    "FindingCategory",
    # Core Models
    "Agent",
    "Permission",
    "EffectivePermission",
    "Finding",
    "AuthorizationRequest",
    "AuthorizationDecision",
    "RiskScore",
    "PolicyRule",
    "AuditEvent",
    "ApprovalRequest",
    "AttackStep",
    "AttackPath",
    "DriftEvent",
    # Utilities
    "SerializableMixin",
]
