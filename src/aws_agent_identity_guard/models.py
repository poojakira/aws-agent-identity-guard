"""
aws_agent_identity_guard/models.py
────────────────────────────────────────────────────────────────────────────────
Core data models for the AWS Agent Identity Guard system.

Defines the canonical representations of agent identities, permissions,
authorization decisions, risk scores, audit events, and drift detection
structures. All models use dataclasses with full type hints, enum-based
classification, __post_init__ validation, and JSON serialization.

Design principles:
  • Immutable-by-default where feasible (frozen dataclasses for value objects)
  • Explicit enum types to prevent stringly-typed bugs
  • Full round-trip serialization (to_dict / from_dict)
  • Defensive validation at construction time
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ─── Enums ────────────────────────────────────────────────────────────────────


class AgentType(str, Enum):
    """Classification of the AI agent's execution environment."""

    BEDROCK = "BEDROCK"
    LAMBDA = "LAMBDA"
    ECS = "ECS"
    EKS = "EKS"
    SAGEMAKER = "SAGEMAKER"
    CUSTOM = "CUSTOM"


class Environment(str, Enum):
    """Deployment environment classification."""

    DEVELOPMENT = "DEVELOPMENT"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"


class DataClassification(str, Enum):
    """Data sensitivity classification following enterprise standards."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"  # noqa: S105
    REGULATED = "REGULATED"


class PermissionEffect(str, Enum):
    """IAM statement effect."""

    ALLOW = "ALLOW"
    DENY = "DENY"


class EffectiveEffect(str, Enum):
    """Result of full IAM policy evaluation across all policy layers."""

    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    CONDITIONAL = "CONDITIONAL"


class PolicySource(str, Enum):
    """Origin type of a permission statement."""

    IDENTITY_POLICY = "IDENTITY_POLICY"
    RESOURCE_POLICY = "RESOURCE_POLICY"
    PERMISSION_BOUNDARY = "PERMISSION_BOUNDARY"
    SCP = "SCP"
    SESSION_POLICY = "SESSION_POLICY"


class AuthorizationDecisionType(str, Enum):
    """Outcome of a runtime authorization evaluation."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    STEP_UP = "STEP_UP"
    REVIEW = "REVIEW"


class ApprovalStatus(str, Enum):
    """Lifecycle state of an approval request."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


# ─── Utility Functions ────────────────────────────────────────────────────────


def _now_utc() -> datetime:
    """Return current UTC timestamp."""
    return datetime.now(timezone.utc)


def _generate_uuid() -> str:
    """Generate a new UUID4 string."""
    return str(uuid.uuid4())


def _serialize_datetime(dt: datetime | None) -> str | None:
    """Serialize datetime to ISO 8601 string."""
    if dt is None:
        return None
    return dt.isoformat()


def _deserialize_datetime(value: str | None) -> datetime | None:
    """Deserialize ISO 8601 string to datetime."""
    if value is None:
        return None
    return datetime.fromisoformat(value)


def _validate_range(value: float | int, min_val: float, max_val: float, field_name: str) -> None:
    """Validate a numeric value is within bounds."""
    if not (min_val <= value <= max_val):
        raise ValueError(f"{field_name} must be between {min_val} and {max_val}, got {value}")


def _validate_arn(arn: str | None, field_name: str) -> None:
    """Validate an ARN has the correct basic format (if provided)."""
    if arn is None:
        return
    if not arn.startswith("arn:"):
        raise ValueError(f"{field_name} must be a valid ARN starting with 'arn:', got '{arn}'")


# ─── Core Data Models ─────────────────────────────────────────────────────────


@dataclass
class AgentIdentity:
    """
    Canonical representation of an AI agent's identity within AWS.

    Encapsulates the agent's classification, ownership, environment context,
    IAM binding, data sensitivity, and declared capabilities. This is the
    central entity that all authorization and audit decisions reference.

    Attributes:
        agent_id: Unique identifier for this agent identity.
        name: Human-readable name of the agent.
        agent_type: Execution environment classification.
        owner: Team or individual responsible for the agent.
        environment: Deployment environment (dev/staging/prod).
        purpose: Description of the agent's intended function.
        description: Extended description or notes.
        workload_identity: Optional workload identity (e.g., IRSA, pod identity).
        iam_role_arn: The IAM role ARN bound to this agent.
        data_classification: Highest data sensitivity this agent handles.
        declared_capabilities: List of capability strings the agent is authorized for.
        tags: Arbitrary metadata tags.
        created_at: Timestamp when this identity was created.
        updated_at: Timestamp of last modification.
    """

    agent_id: str = field(default_factory=_generate_uuid)
    name: str = ""
    agent_type: AgentType = AgentType.CUSTOM
    owner: str = ""
    environment: Environment = Environment.DEVELOPMENT
    purpose: str = ""
    description: str = ""
    workload_identity: str | None = None
    iam_role_arn: str | None = None
    data_classification: DataClassification = DataClassification.INTERNAL
    declared_capabilities: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=_now_utc)
    updated_at: datetime = field(default_factory=_now_utc)

    def __post_init__(self) -> None:
        """Validate fields at construction time."""
        if not self.agent_id:
            raise ValueError("agent_id cannot be empty")
        if not self.name:
            raise ValueError("name cannot be empty")
        if isinstance(self.agent_type, str):
            self.agent_type = AgentType(self.agent_type)
        if isinstance(self.environment, str):
            self.environment = Environment(self.environment)
        if isinstance(self.data_classification, str):
            self.data_classification = DataClassification(self.data_classification)
        _validate_arn(self.iam_role_arn, "iam_role_arn")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "agent_type": self.agent_type.value,
            "owner": self.owner,
            "environment": self.environment.value,
            "purpose": self.purpose,
            "description": self.description,
            "workload_identity": self.workload_identity,
            "iam_role_arn": self.iam_role_arn,
            "data_classification": self.data_classification.value,
            "declared_capabilities": list(self.declared_capabilities),
            "tags": dict(self.tags),
            "created_at": _serialize_datetime(self.created_at),
            "updated_at": _serialize_datetime(self.updated_at),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentIdentity:
        """Deserialize from a dictionary."""
        return cls(
            agent_id=data.get("agent_id", _generate_uuid()),
            name=data["name"],
            agent_type=AgentType(data.get("agent_type", "CUSTOM")),
            owner=data.get("owner", ""),
            environment=Environment(data.get("environment", "DEVELOPMENT")),
            purpose=data.get("purpose", ""),
            description=data.get("description", ""),
            workload_identity=data.get("workload_identity"),
            iam_role_arn=data.get("iam_role_arn"),
            data_classification=DataClassification(data.get("data_classification", "INTERNAL")),
            declared_capabilities=data.get("declared_capabilities", []),
            tags=data.get("tags", {}),
            created_at=_deserialize_datetime(data.get("created_at")) or _now_utc(),
            updated_at=_deserialize_datetime(data.get("updated_at")) or _now_utc(),
        )


@dataclass(frozen=True)
class Permission:
    """
    A single permission statement extracted from an IAM policy.

    Represents one action-resource-effect triple with optional conditions
    and policy source tracking for audit purposes.

    Attributes:
        action: The IAM action (e.g., 's3:GetObject').
        resource: The resource ARN pattern.
        effect: ALLOW or DENY.
        conditions: IAM condition block (operator -> key -> values).
        source: Which policy layer this permission originates from.
    """

    action: str
    resource: str
    effect: PermissionEffect
    conditions: dict[str, Any] = field(default_factory=dict)
    source: PolicySource = PolicySource.IDENTITY_POLICY

    def __post_init__(self) -> None:
        """Validate permission fields."""
        if not self.action:
            raise ValueError("action cannot be empty")
        if not self.resource:
            raise ValueError("resource cannot be empty")
        if isinstance(self.effect, str):
            object.__setattr__(self, "effect", PermissionEffect(self.effect))
        if isinstance(self.source, str):
            object.__setattr__(self, "source", PolicySource(self.source))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "action": self.action,
            "resource": self.resource,
            "effect": self.effect.value,
            "conditions": self.conditions,
            "source": self.source.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Permission:
        """Deserialize from a dictionary."""
        return cls(
            action=data["action"],
            resource=data["resource"],
            effect=PermissionEffect(data["effect"]),
            conditions=data.get("conditions", {}),
            source=PolicySource(data.get("source", "IDENTITY_POLICY")),
        )


@dataclass(frozen=True)
class EffectivePermission:
    """
    The resolved permission after evaluating all policy layers.

    Represents the final determination of whether an action on a resource
    is ALLOWED, DENIED, or CONDITIONAL (dependent on runtime conditions).

    Attributes:
        action: The IAM action evaluated.
        resource: The resource ARN evaluated.
        effective_effect: Final determination (ALLOWED/DENIED/CONDITIONAL).
        contributing_policies: List of policy ARNs/names that contributed.
        conditions_required: Conditions that must be met for access (if CONDITIONAL).
        evaluation_reason: Human-readable explanation of the evaluation logic.
    """

    action: str
    resource: str
    effective_effect: EffectiveEffect
    contributing_policies: list[str] = field(default_factory=list)
    conditions_required: list[dict[str, Any]] = field(default_factory=list)
    evaluation_reason: str = ""

    def __post_init__(self) -> None:
        """Validate effective permission fields."""
        if not self.action:
            raise ValueError("action cannot be empty")
        if not self.resource:
            raise ValueError("resource cannot be empty")
        if isinstance(self.effective_effect, str):
            object.__setattr__(self, "effective_effect", EffectiveEffect(self.effective_effect))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "action": self.action,
            "resource": self.resource,
            "effective_effect": self.effective_effect.value,
            "contributing_policies": list(self.contributing_policies),
            "conditions_required": list(self.conditions_required),
            "evaluation_reason": self.evaluation_reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EffectivePermission:
        """Deserialize from a dictionary."""
        return cls(
            action=data["action"],
            resource=data["resource"],
            effective_effect=EffectiveEffect(data["effective_effect"]),
            contributing_policies=data.get("contributing_policies", []),
            conditions_required=data.get("conditions_required", []),
            evaluation_reason=data.get("evaluation_reason", ""),
        )


@dataclass
class PolicyDocument:
    """
    Representation of an IAM policy document with metadata.

    Attributes:
        policy_type: The layer this policy belongs to (identity, resource, etc.).
        arn: The policy ARN (if applicable).
        name: Human-readable policy name.
        statements: List of IAM statement dictionaries.
    """

    policy_type: PolicySource
    arn: str | None = None
    name: str = ""
    statements: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate policy document."""
        if isinstance(self.policy_type, str):
            self.policy_type = PolicySource(self.policy_type)
        if not self.statements:
            logger.warning("PolicyDocument '%s' has no statements", self.name or self.arn)
        _validate_arn(self.arn, "arn")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "policy_type": self.policy_type.value,
            "arn": self.arn,
            "name": self.name,
            "statements": self.statements,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyDocument:
        """Deserialize from a dictionary."""
        return cls(
            policy_type=PolicySource(data["policy_type"]),
            arn=data.get("arn"),
            name=data.get("name", ""),
            statements=data.get("statements", []),
        )


@dataclass
class AgentCapability:
    """
    Declares a specific capability an agent is authorized to exercise.

    Used for capability-based access control beyond IAM  --  tracks what services,
    data stores, and external endpoints an agent may interact with.

    Attributes:
        service: AWS service name (e.g., 's3', 'bedrock').
        api_action: Specific API action (e.g., 'GetObject').
        resource_scope: Resource ARN pattern this capability covers.
        data_stores: List of data stores accessed (bucket names, table names, etc.).
        external_endpoints: List of external URLs/endpoints the agent may call.
        secrets: List of secret ARNs or parameter paths required.
    """

    service: str
    api_action: str
    resource_scope: str = "*"
    data_stores: list[str] = field(default_factory=list)
    external_endpoints: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate capability fields."""
        if not self.service:
            raise ValueError("service cannot be empty")
        if not self.api_action:
            raise ValueError("api_action cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "service": self.service,
            "api_action": self.api_action,
            "resource_scope": self.resource_scope,
            "data_stores": list(self.data_stores),
            "external_endpoints": list(self.external_endpoints),
            "secrets": list(self.secrets),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentCapability:
        """Deserialize from a dictionary."""
        return cls(
            service=data["service"],
            api_action=data["api_action"],
            resource_scope=data.get("resource_scope", "*"),
            data_stores=data.get("data_stores", []),
            external_endpoints=data.get("external_endpoints", []),
            secrets=data.get("secrets", []),
        )


@dataclass
class RiskScore:
    """
    Multi-dimensional risk assessment for an authorization decision.

    Each dimension scores 0-100, where 0 is no risk and 100 is maximum risk.
    The environment_factor is a multiplier (e.g., 1.0 for dev, 2.5 for prod).

    Attributes:
        overall: Composite risk score (0-100).
        privilege: Risk from privilege level of the action (0-100).
        sensitivity: Risk from data sensitivity involved (0-100).
        blast_radius: Potential scope of damage (0-100).
        data_exposure: Risk of data leakage (0-100).
        persistence: Risk of establishing persistent access (0-100).
        lateral_movement: Risk of moving to other systems (0-100).
        environment_factor: Multiplier based on deployment environment.
        transaction_context: Additional context from the triggering transaction.
    """

    overall: float = 0.0
    privilege: float = 0.0
    sensitivity: float = 0.0
    blast_radius: float = 0.0
    data_exposure: float = 0.0
    persistence: float = 0.0
    lateral_movement: float = 0.0
    environment_factor: float = 1.0
    transaction_context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate all score dimensions are within bounds."""
        _validate_range(self.overall, 0, 100, "overall")
        _validate_range(self.privilege, 0, 100, "privilege")
        _validate_range(self.sensitivity, 0, 100, "sensitivity")
        _validate_range(self.blast_radius, 0, 100, "blast_radius")
        _validate_range(self.data_exposure, 0, 100, "data_exposure")
        _validate_range(self.persistence, 0, 100, "persistence")
        _validate_range(self.lateral_movement, 0, 100, "lateral_movement")
        if self.environment_factor < 0:
            raise ValueError(
                f"environment_factor must be non-negative, got {self.environment_factor}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "overall": self.overall,
            "privilege": self.privilege,
            "sensitivity": self.sensitivity,
            "blast_radius": self.blast_radius,
            "data_exposure": self.data_exposure,
            "persistence": self.persistence,
            "lateral_movement": self.lateral_movement,
            "environment_factor": self.environment_factor,
            "transaction_context": self.transaction_context,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RiskScore:
        """Deserialize from a dictionary."""
        return cls(
            overall=data.get("overall", 0.0),
            privilege=data.get("privilege", 0.0),
            sensitivity=data.get("sensitivity", 0.0),
            blast_radius=data.get("blast_radius", 0.0),
            data_exposure=data.get("data_exposure", 0.0),
            persistence=data.get("persistence", 0.0),
            lateral_movement=data.get("lateral_movement", 0.0),
            environment_factor=data.get("environment_factor", 1.0),
            transaction_context=data.get("transaction_context", {}),
        )


@dataclass
class AuthorizationDecision:
    """
    The outcome of evaluating a transaction request against policy.

    Records what was decided, why, and the associated risk assessment.

    Attributes:
        decision: The authorization outcome (ALLOW/DENY/STEP_UP/REVIEW).
        risk_score: Full risk assessment that informed this decision.
        reasons: List of human-readable reasons for the decision.
        policy_matched: Identifier of the policy rule that drove the decision.
        timestamp: When this decision was made.
        correlation_id: Request correlation ID for tracing.
        explanation: Detailed explanation suitable for audit logs.
    """

    decision: AuthorizationDecisionType
    risk_score: RiskScore = field(default_factory=RiskScore)
    reasons: list[str] = field(default_factory=list)
    policy_matched: str = ""
    timestamp: datetime = field(default_factory=_now_utc)
    correlation_id: str = field(default_factory=_generate_uuid)
    explanation: str = ""

    def __post_init__(self) -> None:
        """Validate authorization decision."""
        if isinstance(self.decision, str):
            self.decision = AuthorizationDecisionType(self.decision)
        if not self.correlation_id:
            self.correlation_id = _generate_uuid()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "decision": self.decision.value,
            "risk_score": self.risk_score.to_dict(),
            "reasons": list(self.reasons),
            "policy_matched": self.policy_matched,
            "timestamp": _serialize_datetime(self.timestamp),
            "correlation_id": self.correlation_id,
            "explanation": self.explanation,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthorizationDecision:
        """Deserialize from a dictionary."""
        return cls(
            decision=AuthorizationDecisionType(data["decision"]),
            risk_score=RiskScore.from_dict(data.get("risk_score", {})),
            reasons=data.get("reasons", []),
            policy_matched=data.get("policy_matched", ""),
            timestamp=_deserialize_datetime(data.get("timestamp")) or _now_utc(),
            correlation_id=data.get("correlation_id", _generate_uuid()),
            explanation=data.get("explanation", ""),
        )


@dataclass
class TransactionRequest:
    """
    An agent's request to perform an action, submitted for authorization.

    Attributes:
        agent_id: The agent identity making this request.
        principal: The IAM principal (role ARN) executing the action.
        tool: The tool or function being invoked.
        action: The IAM action requested.
        resource: The target resource ARN.
        data_classification: Sensitivity level of data involved.
        context: Additional runtime context (IP, session, etc.).
        request_id: Unique identifier for this request.
        timestamp: When the request was submitted.
    """

    agent_id: str
    principal: str
    tool: str
    action: str
    resource: str
    data_classification: DataClassification = DataClassification.INTERNAL
    context: dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=_generate_uuid)
    timestamp: datetime = field(default_factory=_now_utc)

    def __post_init__(self) -> None:
        """Validate transaction request."""
        if not self.agent_id:
            raise ValueError("agent_id cannot be empty")
        if not self.action:
            raise ValueError("action cannot be empty")
        if not self.resource:
            raise ValueError("resource cannot be empty")
        if isinstance(self.data_classification, str):
            self.data_classification = DataClassification(self.data_classification)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "agent_id": self.agent_id,
            "principal": self.principal,
            "tool": self.tool,
            "action": self.action,
            "resource": self.resource,
            "data_classification": self.data_classification.value,
            "context": self.context,
            "request_id": self.request_id,
            "timestamp": _serialize_datetime(self.timestamp),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TransactionRequest:
        """Deserialize from a dictionary."""
        return cls(
            agent_id=data["agent_id"],
            principal=data.get("principal", ""),
            tool=data.get("tool", ""),
            action=data["action"],
            resource=data["resource"],
            data_classification=DataClassification(data.get("data_classification", "INTERNAL")),
            context=data.get("context", {}),
            request_id=data.get("request_id", _generate_uuid()),
            timestamp=_deserialize_datetime(data.get("timestamp")) or _now_utc(),
        )


@dataclass
class AuditEvent:
    """
    Immutable audit record for every authorization decision.

    Includes an integrity hash for tamper detection.

    Attributes:
        event_id: Unique identifier for this audit event.
        correlation_id: Links to the original request.
        agent_id: The agent that triggered this event.
        principal: The IAM principal involved.
        action: The action that was requested.
        resource: The target resource.
        decision: The authorization outcome.
        reasons: Why this decision was made.
        policy_version: Version identifier of the policy set used.
        timestamp: When this event was recorded.
        integrity_hash: SHA-256 hash of event content for tamper detection.
    """

    event_id: str = field(default_factory=_generate_uuid)
    correlation_id: str = ""
    agent_id: str = ""
    principal: str = ""
    action: str = ""
    resource: str = ""
    decision: AuthorizationDecisionType = AuthorizationDecisionType.DENY
    reasons: list[str] = field(default_factory=list)
    policy_version: str = ""
    timestamp: datetime = field(default_factory=_now_utc)
    integrity_hash: str = ""

    def __post_init__(self) -> None:
        """Validate and compute integrity hash if not provided."""
        if isinstance(self.decision, str):
            self.decision = AuthorizationDecisionType(self.decision)
        if not self.integrity_hash:
            self.integrity_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute SHA-256 integrity hash over event fields."""
        content = (
            f"{self.event_id}|{self.correlation_id}|{self.agent_id}|"
            f"{self.principal}|{self.action}|{self.resource}|"
            f"{self.decision.value}|{','.join(self.reasons)}|"
            f"{self.policy_version}|{_serialize_datetime(self.timestamp)}"
        )
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify the integrity hash matches the event content."""
        return self.integrity_hash == self._compute_hash()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "event_id": self.event_id,
            "correlation_id": self.correlation_id,
            "agent_id": self.agent_id,
            "principal": self.principal,
            "action": self.action,
            "resource": self.resource,
            "decision": self.decision.value,
            "reasons": list(self.reasons),
            "policy_version": self.policy_version,
            "timestamp": _serialize_datetime(self.timestamp),
            "integrity_hash": self.integrity_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEvent:
        """Deserialize from a dictionary."""
        return cls(
            event_id=data.get("event_id", _generate_uuid()),
            correlation_id=data.get("correlation_id", ""),
            agent_id=data.get("agent_id", ""),
            principal=data.get("principal", ""),
            action=data.get("action", ""),
            resource=data.get("resource", ""),
            decision=AuthorizationDecisionType(data.get("decision", "DENY")),
            reasons=data.get("reasons", []),
            policy_version=data.get("policy_version", ""),
            timestamp=_deserialize_datetime(data.get("timestamp")) or _now_utc(),
            integrity_hash=data.get("integrity_hash", ""),
        )


@dataclass(frozen=True)
class AttackStep:
    """
    A single step in an attack path representing privilege escalation.

    Attributes:
        action: The IAM action used in this step.
        resource: The target resource of this step.
        description: Human-readable explanation of what this step achieves.
        privilege_gained: Description of the privilege obtained.
    """

    action: str
    resource: str
    description: str = ""
    privilege_gained: str = ""

    def __post_init__(self) -> None:
        """Validate attack step."""
        if not self.action:
            raise ValueError("action cannot be empty")
        if not self.resource:
            raise ValueError("resource cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "action": self.action,
            "resource": self.resource,
            "description": self.description,
            "privilege_gained": self.privilege_gained,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackStep:
        """Deserialize from a dictionary."""
        return cls(
            action=data["action"],
            resource=data["resource"],
            description=data.get("description", ""),
            privilege_gained=data.get("privilege_gained", ""),
        )


@dataclass
class AttackPath:
    """
    A sequence of attack steps representing a privilege escalation path.

    Attributes:
        steps: Ordered list of attack steps.
        likelihood: Probability of exploitation (0.0 to 1.0).
        impact: Severity of successful exploitation (0.0 to 1.0).
        composite_score: Combined risk score (likelihood * impact * 100).
        description: Summary of the full attack path.
    """

    steps: list[AttackStep] = field(default_factory=list)
    likelihood: float = 0.0
    impact: float = 0.0
    composite_score: float = 0.0
    description: str = ""

    def __post_init__(self) -> None:
        """Validate attack path scores."""
        _validate_range(self.likelihood, 0.0, 1.0, "likelihood")
        _validate_range(self.impact, 0.0, 1.0, "impact")
        if self.composite_score == 0.0 and self.steps:
            self.composite_score = round(self.likelihood * self.impact * 100, 2)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "steps": [step.to_dict() for step in self.steps],
            "likelihood": self.likelihood,
            "impact": self.impact,
            "composite_score": self.composite_score,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackPath:
        """Deserialize from a dictionary."""
        return cls(
            steps=[AttackStep.from_dict(s) for s in data.get("steps", [])],
            likelihood=data.get("likelihood", 0.0),
            impact=data.get("impact", 0.0),
            composite_score=data.get("composite_score", 0.0),
            description=data.get("description", ""),
        )


@dataclass
class DriftEvent:
    """
    Records a detected change in an agent's effective permissions.

    Used for continuous monitoring and alerting on permission drift.

    Attributes:
        agent_id: The agent whose permissions changed.
        timestamp: When the drift was detected.
        previous_permissions: Permissions before the change.
        current_permissions: Permissions after the change.
        new_permissions: Permissions that were added.
        removed_permissions: Permissions that were removed.
        new_attack_paths: Any new attack paths introduced by the drift.
    """

    agent_id: str
    timestamp: datetime = field(default_factory=_now_utc)
    previous_permissions: list[EffectivePermission] = field(default_factory=list)
    current_permissions: list[EffectivePermission] = field(default_factory=list)
    new_permissions: list[EffectivePermission] = field(default_factory=list)
    removed_permissions: list[EffectivePermission] = field(default_factory=list)
    new_attack_paths: list[AttackPath] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate drift event."""
        if not self.agent_id:
            raise ValueError("agent_id cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "agent_id": self.agent_id,
            "timestamp": _serialize_datetime(self.timestamp),
            "previous_permissions": [p.to_dict() for p in self.previous_permissions],
            "current_permissions": [p.to_dict() for p in self.current_permissions],
            "new_permissions": [p.to_dict() for p in self.new_permissions],
            "removed_permissions": [p.to_dict() for p in self.removed_permissions],
            "new_attack_paths": [ap.to_dict() for ap in self.new_attack_paths],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DriftEvent:
        """Deserialize from a dictionary."""
        return cls(
            agent_id=data["agent_id"],
            timestamp=_deserialize_datetime(data.get("timestamp")) or _now_utc(),
            previous_permissions=[
                EffectivePermission.from_dict(p) for p in data.get("previous_permissions", [])
            ],
            current_permissions=[
                EffectivePermission.from_dict(p) for p in data.get("current_permissions", [])
            ],
            new_permissions=[
                EffectivePermission.from_dict(p) for p in data.get("new_permissions", [])
            ],
            removed_permissions=[
                EffectivePermission.from_dict(p) for p in data.get("removed_permissions", [])
            ],
            new_attack_paths=[AttackPath.from_dict(ap) for ap in data.get("new_attack_paths", [])],
        )


@dataclass
class ApprovalRequest:
    """
    A request for human approval of a high-risk agent action.

    Used when the authorization engine decides STEP_UP or REVIEW.

    Attributes:
        request_id: Unique identifier for this approval request.
        agent_id: The agent requesting approval.
        action: The IAM action requiring approval.
        resource: The target resource.
        requester: Who/what initiated the request.
        approver: Who is designated to approve.
        status: Current lifecycle state.
        expires_at: When this request expires if not acted upon.
        created_at: When the request was created.
        decision_at: When the approval/denial decision was made.
        reason: Justification or explanation for the request/decision.
    """

    request_id: str = field(default_factory=_generate_uuid)
    agent_id: str = ""
    action: str = ""
    resource: str = ""
    requester: str = ""
    approver: str = ""
    status: ApprovalStatus = ApprovalStatus.PENDING
    expires_at: datetime | None = None
    created_at: datetime = field(default_factory=_now_utc)
    decision_at: datetime | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        """Validate approval request."""
        if not self.request_id:
            self.request_id = _generate_uuid()
        if isinstance(self.status, str):
            self.status = ApprovalStatus(self.status)
        if not self.agent_id:
            raise ValueError("agent_id cannot be empty")

    @property
    def is_expired(self) -> bool:
        """Check if this request has expired."""
        if self.expires_at is None:
            return False
        return _now_utc() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "action": self.action,
            "resource": self.resource,
            "requester": self.requester,
            "approver": self.approver,
            "status": self.status.value,
            "expires_at": _serialize_datetime(self.expires_at),
            "created_at": _serialize_datetime(self.created_at),
            "decision_at": _serialize_datetime(self.decision_at),
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApprovalRequest:
        """Deserialize from a dictionary."""
        return cls(
            request_id=data.get("request_id", _generate_uuid()),
            agent_id=data["agent_id"],
            action=data.get("action", ""),
            resource=data.get("resource", ""),
            requester=data.get("requester", ""),
            approver=data.get("approver", ""),
            status=ApprovalStatus(data.get("status", "PENDING")),
            expires_at=_deserialize_datetime(data.get("expires_at")),
            created_at=_deserialize_datetime(data.get("created_at")) or _now_utc(),
            decision_at=_deserialize_datetime(data.get("decision_at")),
            reason=data.get("reason", ""),
        )
