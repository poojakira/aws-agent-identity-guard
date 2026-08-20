"""AWS Agent Identity Guard - Capability Inventory and Graph Module.

Provides comprehensive enumeration and graph-based analysis of agent
capabilities within AWS environments. Automatically discovers accessible
services, resources, roles, data stores, and network endpoints from
IAM policies (static analysis) and optionally from live AWS APIs.

Key components:
- CapabilityInventory: Enumerates everything an agent can access
- CapabilityGraph: Directed graph representation of access relationships
- Graph operations: Path finding, blast radius, lateral movement analysis
- Serialization: DOT format and JSON export for visualization

Usage:
    from aws_agent_identity_guard.capability_inventory import (
        CapabilityInventory,
        CapabilityGraph,
    )

    inventory = CapabilityInventory.from_agent(agent)
    graph = inventory.build_graph()
    radius = graph.blast_radius(agent.agent_id)
"""

from __future__ import annotations

import fnmatch
import json
import re
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, unique
from typing import Any, Iterator, Optional, Protocol, runtime_checkable

from .models import (
    Agent,
    Permission,
    PermissionEffect,
    PermissionSource,
    DataClassification,
    Environment,
    SerializableMixin,
)


# =============================================================================
# Enumerations
# =============================================================================


@unique
class NodeType(str, Enum):
    """Types of nodes in the capability graph."""

    AGENT = "AGENT"
    SERVICE = "SERVICE"
    RESOURCE = "RESOURCE"
    ROLE = "ROLE"
    SECRET = "SECRET"
    ENDPOINT = "ENDPOINT"
    KMS_KEY = "KMS_KEY"
    DATA_STORE = "DATA_STORE"


@unique
class EdgeType(str, Enum):
    """Types of relationships between nodes in the capability graph."""

    CAN_ACCESS = "can_access"
    CAN_ASSUME = "can_assume"
    CAN_INVOKE = "can_invoke"
    CAN_READ = "can_read"
    CAN_WRITE = "can_write"
    CAN_DELETE = "can_delete"


@unique
class RiskLevel(str, Enum):
    """Risk classification for graph edges."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@unique
class ResourceCategory(str, Enum):
    """Categories for discovered resources."""

    COMPUTE = "COMPUTE"
    STORAGE = "STORAGE"
    DATABASE = "DATABASE"
    NETWORKING = "NETWORKING"
    SECURITY = "SECURITY"
    ANALYTICS = "ANALYTICS"
    AI_ML = "AI_ML"
    MANAGEMENT = "MANAGEMENT"


# =============================================================================
# Node and Edge Dataclasses
# =============================================================================


@dataclass(slots=True)
class GraphNode:
    """A node in the capability graph.

    Represents an entity (agent, service, resource, role, etc.)
    with associated metadata for visualization and analysis.
    """

    node_id: str
    node_type: NodeType
    label: str
    arn: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    resource_category: Optional[ResourceCategory] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize node to dictionary."""
        result: dict[str, Any] = {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "label": self.label,
            "arn": self.arn,
            "metadata": self.metadata,
        }
        if self.resource_category:
            result["resource_category"] = self.resource_category.value
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GraphNode:
        """Reconstruct a GraphNode from a dictionary."""
        return cls(
            node_id=data["node_id"],
            node_type=NodeType(data["node_type"]),
            label=data["label"],
            arn=data.get("arn", ""),
            metadata=data.get("metadata", {}),
            resource_category=ResourceCategory(data["resource_category"])
            if data.get("resource_category")
            else None,
        )

    @property
    def is_data_store(self) -> bool:
        """Whether this node represents a data store."""
        return self.resource_category in (
            ResourceCategory.STORAGE,
            ResourceCategory.DATABASE,
        ) or self.node_type == NodeType.DATA_STORE

    @property
    def is_role(self) -> bool:
        """Whether this node represents an IAM role."""
        return self.node_type == NodeType.ROLE

    def dot_attributes(self) -> str:
        """Generate DOT format attributes for this node."""
        shapes = {
            NodeType.AGENT: "doubleoctagon",
            NodeType.SERVICE: "box",
            NodeType.RESOURCE: "ellipse",
            NodeType.ROLE: "hexagon",
            NodeType.SECRET: "diamond",
            NodeType.ENDPOINT: "trapezium",
            NodeType.KMS_KEY: "pentagon",
            NodeType.DATA_STORE: "cylinder",
        }
        colors = {
            NodeType.AGENT: "#4a90d9",
            NodeType.SERVICE: "#7cb342",
            NodeType.RESOURCE: "#ffa726",
            NodeType.ROLE: "#ab47bc",
            NodeType.SECRET: "#e53935",
            NodeType.ENDPOINT: "#00acc1",
            NodeType.KMS_KEY: "#8d6e63",
            NodeType.DATA_STORE: "#5c6bc0",
        }
        shape = shapes.get(self.node_type, "ellipse")
        color = colors.get(self.node_type, "#000000")
        escaped_label = self.label.replace('"', '\\"')
        return f'shape={shape}, style=filled, fillcolor="{color}", fontcolor=white, label="{escaped_label}"'


@dataclass(slots=True)
class GraphEdge:
    """A directed edge in the capability graph.

    Represents an access relationship between two nodes with
    full provenance and risk metadata.
    """

    edge_id: str
    source_id: str
    target_id: str
    edge_type: EdgeType
    permission_source: PermissionSource
    conditions: dict[str, Any] = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    actions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize edge to dictionary."""
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "permission_source": self.permission_source.value,
            "conditions": self.conditions,
            "risk_level": self.risk_level.value,
            "actions": self.actions,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GraphEdge:
        """Reconstruct a GraphEdge from a dictionary."""
        return cls(
            edge_id=data["edge_id"],
            source_id=data["source_id"],
            target_id=data["target_id"],
            edge_type=EdgeType(data["edge_type"]),
            permission_source=PermissionSource(data["permission_source"]),
            conditions=data.get("conditions", {}),
            risk_level=RiskLevel(data.get("risk_level", "MEDIUM")),
            actions=data.get("actions", []),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def create(
        cls,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        permission_source: PermissionSource,
        conditions: dict[str, Any] | None = None,
        risk_level: RiskLevel = RiskLevel.MEDIUM,
        actions: list[str] | None = None,
    ) -> GraphEdge:
        """Factory method for creating a new edge with generated ID."""
        return cls(
            edge_id=str(uuid.uuid4()),
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            permission_source=permission_source,
            conditions=conditions or {},
            risk_level=risk_level,
            actions=actions or [],
        )

    def dot_attributes(self) -> str:
        """Generate DOT format attributes for this edge."""
        colors = {
            RiskLevel.CRITICAL: "#e53935",
            RiskLevel.HIGH: "#ff7043",
            RiskLevel.MEDIUM: "#ffa726",
            RiskLevel.LOW: "#66bb6a",
            RiskLevel.INFORMATIONAL: "#90a4ae",
        }
        styles = {
            EdgeType.CAN_ACCESS: "solid",
            EdgeType.CAN_ASSUME: "bold",
            EdgeType.CAN_INVOKE: "dashed",
            EdgeType.CAN_READ: "solid",
            EdgeType.CAN_WRITE: "solid",
            EdgeType.CAN_DELETE: "dotted",
        }
        color = colors.get(self.risk_level, "#000000")
        style = styles.get(self.edge_type, "solid")
        escaped_label = self.edge_type.value.replace('"', '\\"')
        return f'color="{color}", style={style}, label="{escaped_label}"'


# =============================================================================
# Discovery Protocol
# =============================================================================


@runtime_checkable
class DiscoverySource(Protocol):
    """Protocol for pluggable discovery sources.

    Implementations can discover capabilities from IAM policies,
    live AWS APIs, or other sources.
    """

    def discover_services(self, agent: Agent) -> list[DiscoveredService]:
        """Discover accessible AWS services for the agent."""
        ...

    def discover_resources(self, agent: Agent) -> list[DiscoveredResource]:
        """Discover accessible resources for the agent."""
        ...

    def discover_roles(self, agent: Agent) -> list[DiscoveredRole]:
        """Discover assumable roles for the agent."""
        ...


# =============================================================================
# Discovery Result Types
# =============================================================================


@dataclass(slots=True)
class DiscoveredService:
    """A discovered AWS service the agent can access."""

    service_name: str
    actions: list[str]
    permission_source: PermissionSource
    conditions: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "service_name": self.service_name,
            "actions": self.actions,
            "permission_source": self.permission_source.value,
            "conditions": self.conditions,
        }


@dataclass(slots=True)
class DiscoveredResource:
    """A discovered resource the agent can access."""

    arn: str
    service: str
    resource_type: str
    actions: list[str]
    permission_source: PermissionSource
    risk_level: RiskLevel = RiskLevel.MEDIUM
    category: Optional[ResourceCategory] = None
    conditions: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        result: dict[str, Any] = {
            "arn": self.arn,
            "service": self.service,
            "resource_type": self.resource_type,
            "actions": self.actions,
            "permission_source": self.permission_source.value,
            "risk_level": self.risk_level.value,
            "conditions": self.conditions,
            "metadata": self.metadata,
        }
        if self.category:
            result["category"] = self.category.value
        return result


@dataclass(slots=True)
class DiscoveredRole:
    """A discovered IAM role the agent can assume."""

    role_arn: str
    role_name: str
    trust_policy: dict[str, Any] = field(default_factory=dict)
    attached_policies: list[str] = field(default_factory=list)
    conditions: dict[str, Any] = field(default_factory=dict)
    is_cross_account: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "role_arn": self.role_arn,
            "role_name": self.role_name,
            "trust_policy": self.trust_policy,
            "attached_policies": self.attached_policies,
            "conditions": self.conditions,
            "is_cross_account": self.is_cross_account,
        }


@dataclass(slots=True)
class DiscoveredEndpoint:
    """A discovered external endpoint the agent can reach."""

    endpoint_url: str
    endpoint_type: str  # api_gateway, vpc_endpoint, internet
    service: str = ""
    protocol: str = "https"
    port: int = 443
    vpc_id: str = ""
    security_groups: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "endpoint_url": self.endpoint_url,
            "endpoint_type": self.endpoint_type,
            "service": self.service,
            "protocol": self.protocol,
            "port": self.port,
            "vpc_id": self.vpc_id,
            "security_groups": self.security_groups,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class DiscoveredSecret:
    """A discovered secret the agent can access."""

    secret_arn: str
    secret_name: str
    actions: list[str] = field(default_factory=list)
    kms_key_id: str = ""
    rotation_enabled: bool = False
    last_accessed: Optional[datetime] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        result: dict[str, Any] = {
            "secret_arn": self.secret_arn,
            "secret_name": self.secret_name,
            "actions": self.actions,
            "kms_key_id": self.kms_key_id,
            "rotation_enabled": self.rotation_enabled,
        }
        if self.last_accessed:
            result["last_accessed"] = self.last_accessed.isoformat()
        return result


@dataclass(slots=True)
class DiscoveredKMSKey:
    """A discovered KMS key the agent can use."""

    key_arn: str
    key_id: str
    alias: str = ""
    actions: list[str] = field(default_factory=list)
    key_policy_grants_access: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "key_arn": self.key_arn,
            "key_id": self.key_id,
            "alias": self.alias,
            "actions": self.actions,
            "key_policy_grants_access": self.key_policy_grants_access,
        }


@dataclass(slots=True)
class NetworkScope:
    """Network-level access scope for the agent."""

    vpc_ids: list[str] = field(default_factory=list)
    subnet_ids: list[str] = field(default_factory=list)
    security_group_ids: list[str] = field(default_factory=list)
    has_internet_access: bool = False
    vpc_endpoints: list[str] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    nat_gateway_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "vpc_ids": self.vpc_ids,
            "subnet_ids": self.subnet_ids,
            "security_group_ids": self.security_group_ids,
            "has_internet_access": self.has_internet_access,
            "vpc_endpoints": self.vpc_endpoints,
            "allowed_cidrs": self.allowed_cidrs,
            "nat_gateway_ids": self.nat_gateway_ids,
        }


# =============================================================================
# IAM Policy Parser (Static Discovery)
# =============================================================================


# Mapping of AWS service prefixes to resource categories
_SERVICE_CATEGORY_MAP: dict[str, ResourceCategory] = {
    "s3": ResourceCategory.STORAGE,
    "dynamodb": ResourceCategory.DATABASE,
    "rds": ResourceCategory.DATABASE,
    "redshift": ResourceCategory.DATABASE,
    "elasticache": ResourceCategory.DATABASE,
    "lambda": ResourceCategory.COMPUTE,
    "ecs": ResourceCategory.COMPUTE,
    "eks": ResourceCategory.COMPUTE,
    "ec2": ResourceCategory.COMPUTE,
    "sagemaker": ResourceCategory.AI_ML,
    "bedrock": ResourceCategory.AI_ML,
    "states": ResourceCategory.COMPUTE,
    "secretsmanager": ResourceCategory.SECURITY,
    "kms": ResourceCategory.SECURITY,
    "iam": ResourceCategory.SECURITY,
    "sts": ResourceCategory.SECURITY,
    "vpc": ResourceCategory.NETWORKING,
    "apigateway": ResourceCategory.NETWORKING,
    "execute-api": ResourceCategory.NETWORKING,
    "sns": ResourceCategory.MANAGEMENT,
    "sqs": ResourceCategory.MANAGEMENT,
    "cloudwatch": ResourceCategory.MANAGEMENT,
    "logs": ResourceCategory.MANAGEMENT,
    "kinesis": ResourceCategory.ANALYTICS,
    "athena": ResourceCategory.ANALYTICS,
    "glue": ResourceCategory.ANALYTICS,
}

# Actions that indicate data read capability
_READ_ACTIONS: set[str] = {
    "Get*", "Describe*", "List*", "Read*", "Select*", "Query*", "Scan*",
    "BatchGet*", "Head*",
}

# Actions that indicate data write capability
_WRITE_ACTIONS: set[str] = {
    "Put*", "Create*", "Update*", "Write*", "Upload*", "BatchWrite*",
    "Insert*", "Modify*", "Set*",
}

# Actions that indicate delete capability
_DELETE_ACTIONS: set[str] = {
    "Delete*", "Remove*", "Terminate*", "Destroy*", "Purge*",
}

# High-risk action patterns
_HIGH_RISK_PATTERNS: list[str] = [
    "iam:*",
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "sts:AssumeRole",
    "kms:Decrypt",
    "kms:*",
    "secretsmanager:GetSecretValue",
    "s3:DeleteBucket",
    "dynamodb:DeleteTable",
    "rds:DeleteDBInstance",
    "lambda:UpdateFunctionCode",
    "ec2:RunInstances",
]


def _classify_risk(action: str, resource: str) -> RiskLevel:
    """Classify the risk level of an action on a resource.

    Args:
        action: The IAM action (e.g., 's3:GetObject').
        resource: The resource ARN or pattern.

    Returns:
        The assessed risk level.
    """
    # Wildcard on all resources is always critical
    if action == "*" and resource == "*":
        return RiskLevel.CRITICAL

    # Check against high-risk patterns
    for pattern in _HIGH_RISK_PATTERNS:
        if fnmatch.fnmatch(action.lower(), pattern.lower()):
            return RiskLevel.HIGH

    # Admin-level actions
    if action.endswith(":*"):
        return RiskLevel.HIGH

    # Delete actions
    action_part = action.split(":")[-1] if ":" in action else action
    for pattern in _DELETE_ACTIONS:
        if fnmatch.fnmatch(action_part, pattern):
            return RiskLevel.HIGH

    # Write actions
    for pattern in _WRITE_ACTIONS:
        if fnmatch.fnmatch(action_part, pattern):
            return RiskLevel.MEDIUM

    # Read actions
    for pattern in _READ_ACTIONS:
        if fnmatch.fnmatch(action_part, pattern):
            return RiskLevel.LOW

    return RiskLevel.MEDIUM


def _determine_edge_type(action: str) -> EdgeType:
    """Determine the edge type from an IAM action.

    Args:
        action: The IAM action string.

    Returns:
        The appropriate edge type for the graph.
    """
    if "AssumeRole" in action:
        return EdgeType.CAN_ASSUME

    action_part = action.split(":")[-1] if ":" in action else action

    # Check invoke patterns
    invoke_patterns = {"Invoke*", "Execute*", "Start*", "Run*"}
    for pattern in invoke_patterns:
        if fnmatch.fnmatch(action_part, pattern):
            return EdgeType.CAN_INVOKE

    # Check delete patterns
    for pattern in _DELETE_ACTIONS:
        if fnmatch.fnmatch(action_part, pattern):
            return EdgeType.CAN_DELETE

    # Check write patterns
    for pattern in _WRITE_ACTIONS:
        if fnmatch.fnmatch(action_part, pattern):
            return EdgeType.CAN_WRITE

    # Check read patterns
    for pattern in _READ_ACTIONS:
        if fnmatch.fnmatch(action_part, pattern):
            return EdgeType.CAN_READ

    return EdgeType.CAN_ACCESS


def _extract_service_from_action(action: str) -> str:
    """Extract the AWS service prefix from an action string.

    Args:
        action: IAM action like 's3:GetObject' or '*'.

    Returns:
        The service prefix, or '*' for wildcard actions.
    """
    if ":" in action:
        return action.split(":")[0]
    return "*"


def _extract_service_from_arn(arn: str) -> str:
    """Extract the AWS service from an ARN.

    Args:
        arn: An AWS ARN like 'arn:aws:s3:::my-bucket'.

    Returns:
        The service name, or empty string if not a valid ARN.
    """
    # ARN format: arn:partition:service:region:account:resource
    parts = arn.split(":")
    if len(parts) >= 3 and parts[0] == "arn":
        return parts[2]
    return ""


def _is_data_store_service(service: str) -> bool:
    """Check if a service is a data store service."""
    return service in ("s3", "dynamodb", "rds", "redshift", "elasticache", "efs")


def _is_tool_service(service: str) -> bool:
    """Check if a service is a tool/compute service."""
    return service in ("lambda", "states", "bedrock")


def _is_secret_service(service: str) -> bool:
    """Check if a service manages secrets."""
    return service in ("secretsmanager", "ssm")


class IAMPolicyDiscovery:
    """Static discovery source that analyzes IAM policy documents.

    Parses IAM policy JSON to enumerate accessible services, resources,
    and roles without making any AWS API calls.
    """

    def __init__(self) -> None:
        """Initialize the IAM policy discovery source."""
        self._parsed_statements: list[dict[str, Any]] = []

    def discover_services(self, agent: Agent) -> list[DiscoveredService]:
        """Discover accessible AWS services from IAM policies.

        Analyzes all identity policies attached to the agent and
        groups allowed actions by service.

        Args:
            agent: The agent whose policies to analyze.

        Returns:
            List of discovered services with their allowed actions.
        """
        service_actions: dict[str, list[str]] = defaultdict(list)
        service_conditions: dict[str, dict[str, Any]] = defaultdict(dict)

        for policy_doc in agent.identity_policies:
            statements = self._extract_statements(policy_doc)
            for stmt in statements:
                if stmt.get("Effect", "").upper() != "ALLOW":
                    continue
                actions = self._normalize_list(stmt.get("Action", []))
                conditions = stmt.get("Condition", {})
                for action in actions:
                    service = _extract_service_from_action(action)
                    if service != "*":
                        service_actions[service].append(action)
                        if conditions:
                            service_conditions[service].update(conditions)
                    else:
                        # Wildcard action applies to all services
                        service_actions["*"].append("*")

        discovered: list[DiscoveredService] = []
        for service, actions in sorted(service_actions.items()):
            discovered.append(
                DiscoveredService(
                    service_name=service,
                    actions=sorted(set(actions)),
                    permission_source=PermissionSource.IDENTITY_POLICY,
                    conditions=service_conditions.get(service, {}),
                )
            )
        return discovered

    def discover_resources(self, agent: Agent) -> list[DiscoveredResource]:
        """Discover accessible resources from IAM policies.

        Extracts resource ARNs from policy statements and categorizes
        them by service and resource type.

        Args:
            agent: The agent whose policies to analyze.

        Returns:
            List of discovered resources with access details.
        """
        discovered: list[DiscoveredResource] = []
        seen_arns: set[str] = set()

        for policy_doc in agent.identity_policies:
            statements = self._extract_statements(policy_doc)
            for stmt in statements:
                if stmt.get("Effect", "").upper() != "ALLOW":
                    continue

                actions = self._normalize_list(stmt.get("Action", []))
                resources = self._normalize_list(stmt.get("Resource", []))
                conditions = stmt.get("Condition", {})

                for resource_arn in resources:
                    if resource_arn in seen_arns:
                        continue
                    seen_arns.add(resource_arn)

                    service = _extract_service_from_arn(resource_arn)
                    if not service and resource_arn != "*":
                        continue

                    resource_type = self._infer_resource_type(resource_arn, service)
                    category = _SERVICE_CATEGORY_MAP.get(service)

                    # Determine risk from most dangerous action
                    max_risk = RiskLevel.INFORMATIONAL
                    for action in actions:
                        risk = _classify_risk(action, resource_arn)
                        if list(RiskLevel).index(risk) < list(RiskLevel).index(max_risk):
                            max_risk = risk

                    discovered.append(
                        DiscoveredResource(
                            arn=resource_arn,
                            service=service or "*",
                            resource_type=resource_type,
                            actions=sorted(actions),
                            permission_source=PermissionSource.IDENTITY_POLICY,
                            risk_level=max_risk,
                            category=category,
                            conditions=conditions,
                        )
                    )

        return discovered

    def discover_roles(self, agent: Agent) -> list[DiscoveredRole]:
        """Discover IAM roles the agent can assume.

        Looks for sts:AssumeRole actions in policies and extracts
        role ARNs from the resource field.

        Args:
            agent: The agent whose policies to analyze.

        Returns:
            List of discoverable assumable roles.
        """
        discovered: list[DiscoveredRole] = []
        seen_roles: set[str] = set()

        for policy_doc in agent.identity_policies:
            statements = self._extract_statements(policy_doc)
            for stmt in statements:
                if stmt.get("Effect", "").upper() != "ALLOW":
                    continue

                actions = self._normalize_list(stmt.get("Action", []))
                assume_actions = [
                    a for a in actions
                    if "AssumeRole" in a or a == "sts:*" or a == "*"
                ]
                if not assume_actions:
                    continue

                resources = self._normalize_list(stmt.get("Resource", []))
                conditions = stmt.get("Condition", {})

                for resource_arn in resources:
                    if resource_arn in seen_roles:
                        continue
                    if ":role/" not in resource_arn and resource_arn != "*":
                        continue
                    seen_roles.add(resource_arn)

                    role_name = resource_arn.split("/")[-1] if "/" in resource_arn else resource_arn
                    # Cross-account if the ARN account differs
                    is_cross_account = self._is_cross_account(
                        resource_arn, agent.iam_role_arn
                    )

                    discovered.append(
                        DiscoveredRole(
                            role_arn=resource_arn,
                            role_name=role_name,
                            conditions=conditions,
                            is_cross_account=is_cross_account,
                        )
                    )

        return discovered

    def discover_secrets(self, agent: Agent) -> list[DiscoveredSecret]:
        """Discover secrets the agent can access.

        Looks for secretsmanager and ssm parameter store actions.

        Args:
            agent: The agent whose policies to analyze.

        Returns:
            List of accessible secrets.
        """
        discovered: list[DiscoveredSecret] = []
        seen: set[str] = set()

        for policy_doc in agent.identity_policies:
            statements = self._extract_statements(policy_doc)
            for stmt in statements:
                if stmt.get("Effect", "").upper() != "ALLOW":
                    continue

                actions = self._normalize_list(stmt.get("Action", []))
                secret_actions = [
                    a for a in actions
                    if _extract_service_from_action(a) in ("secretsmanager", "ssm", "*")
                ]
                if not secret_actions:
                    continue

                resources = self._normalize_list(stmt.get("Resource", []))
                for resource_arn in resources:
                    if resource_arn in seen:
                        continue
                    service = _extract_service_from_arn(resource_arn)
                    if service not in ("secretsmanager", "ssm") and resource_arn != "*":
                        continue
                    seen.add(resource_arn)

                    secret_name = resource_arn.split(":")[-1] if resource_arn != "*" else "*"
                    discovered.append(
                        DiscoveredSecret(
                            secret_arn=resource_arn,
                            secret_name=secret_name,
                            actions=sorted(secret_actions),
                        )
                    )

        return discovered

    def discover_kms_keys(self, agent: Agent) -> list[DiscoveredKMSKey]:
        """Discover KMS keys the agent can use.

        Args:
            agent: The agent whose policies to analyze.

        Returns:
            List of accessible KMS keys.
        """
        discovered: list[DiscoveredKMSKey] = []
        seen: set[str] = set()

        for policy_doc in agent.identity_policies:
            statements = self._extract_statements(policy_doc)
            for stmt in statements:
                if stmt.get("Effect", "").upper() != "ALLOW":
                    continue

                actions = self._normalize_list(stmt.get("Action", []))
                kms_actions = [
                    a for a in actions
                    if _extract_service_from_action(a) in ("kms", "*")
                ]
                if not kms_actions:
                    continue

                resources = self._normalize_list(stmt.get("Resource", []))
                for resource_arn in resources:
                    if resource_arn in seen:
                        continue
                    service = _extract_service_from_arn(resource_arn)
                    if service != "kms" and resource_arn != "*":
                        continue
                    seen.add(resource_arn)

                    key_id = resource_arn.split("/")[-1] if "/" in resource_arn else resource_arn
                    discovered.append(
                        DiscoveredKMSKey(
                            key_arn=resource_arn,
                            key_id=key_id,
                            actions=sorted(kms_actions),
                        )
                    )

        return discovered

    def discover_endpoints(self, agent: Agent) -> list[DiscoveredEndpoint]:
        """Discover external endpoints from API Gateway and VPC configurations.

        Args:
            agent: The agent whose policies to analyze.

        Returns:
            List of discoverable endpoints.
        """
        discovered: list[DiscoveredEndpoint] = []
        seen: set[str] = set()

        for policy_doc in agent.identity_policies:
            statements = self._extract_statements(policy_doc)
            for stmt in statements:
                if stmt.get("Effect", "").upper() != "ALLOW":
                    continue

                actions = self._normalize_list(stmt.get("Action", []))
                endpoint_actions = [
                    a for a in actions
                    if _extract_service_from_action(a) in (
                        "execute-api", "apigateway", "*"
                    )
                ]
                if not endpoint_actions:
                    continue

                resources = self._normalize_list(stmt.get("Resource", []))
                for resource_arn in resources:
                    if resource_arn in seen:
                        continue
                    seen.add(resource_arn)

                    # Extract API Gateway endpoint info from ARN
                    endpoint_url = self._arn_to_endpoint(resource_arn)
                    if endpoint_url:
                        discovered.append(
                            DiscoveredEndpoint(
                                endpoint_url=endpoint_url,
                                endpoint_type="api_gateway",
                                service="apigateway",
                            )
                        )

        return discovered

    def _extract_statements(self, policy_doc: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract statements from a policy document.

        Handles both full policy documents (with Version/Statement)
        and statement lists directly.
        """
        if "Statement" in policy_doc:
            statements = policy_doc["Statement"]
        elif "Version" in policy_doc:
            statements = policy_doc.get("Statement", [])
        else:
            # Assume it's a single statement
            statements = [policy_doc]

        if isinstance(statements, dict):
            statements = [statements]
        return statements

    def _normalize_list(self, value: Any) -> list[str]:
        """Normalize a policy value to a list of strings."""
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return value
        return []

    def _infer_resource_type(self, arn: str, service: str) -> str:
        """Infer the resource type from an ARN.

        Args:
            arn: The resource ARN.
            service: The extracted service name.

        Returns:
            A human-readable resource type string.
        """
        if arn == "*":
            return "wildcard"

        parts = arn.split(":")
        if len(parts) >= 6:
            resource_part = ":".join(parts[5:])
            if "/" in resource_part:
                return resource_part.split("/")[0]
            return resource_part

        return "unknown"

    def _is_cross_account(self, role_arn: str, agent_arn: str) -> bool:
        """Determine if a role is in a different account than the agent."""
        role_parts = role_arn.split(":")
        agent_parts = agent_arn.split(":")
        if len(role_parts) >= 5 and len(agent_parts) >= 5:
            return role_parts[4] != agent_parts[4]
        return False

    def _arn_to_endpoint(self, arn: str) -> str:
        """Convert an API Gateway ARN to an endpoint URL.

        Args:
            arn: The API Gateway resource ARN.

        Returns:
            The inferred endpoint URL, or empty string.
        """
        # arn:aws:execute-api:region:account:api-id/stage/method/resource
        parts = arn.split(":")
        if len(parts) >= 6 and "execute-api" in arn:
            region = parts[3] if len(parts) > 3 else "us-east-1"
            resource = parts[5] if len(parts) > 5 else ""
            api_id = resource.split("/")[0] if "/" in resource else resource
            if api_id and api_id != "*":
                return f"https://{api_id}.execute-api.{region}.amazonaws.com"
        return ""


# =============================================================================
# Capability Graph
# =============================================================================


class CapabilityGraph:
    """Directed graph representing agent capabilities and access relationships.

    Provides graph operations for security analysis including path finding,
    blast radius computation, lateral movement detection, and data access
    scope analysis.

    The graph uses adjacency lists for efficient traversal and supports
    serialization to DOT format and JSON for visualization tools.
    """

    def __init__(self) -> None:
        """Initialize an empty capability graph."""
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}
        self._adjacency: dict[str, list[str]] = defaultdict(list)  # node_id -> [edge_ids]
        self._reverse_adjacency: dict[str, list[str]] = defaultdict(list)  # node_id -> [edge_ids incoming]

    @property
    def nodes(self) -> dict[str, GraphNode]:
        """All nodes in the graph."""
        return self._nodes

    @property
    def edges(self) -> dict[str, GraphEdge]:
        """All edges in the graph."""
        return self._edges

    @property
    def node_count(self) -> int:
        """Total number of nodes."""
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        """Total number of edges."""
        return len(self._edges)

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the graph.

        If a node with the same ID already exists, it will be updated.

        Args:
            node: The graph node to add.
        """
        self._nodes[node.node_id] = node
        if node.node_id not in self._adjacency:
            self._adjacency[node.node_id] = []
        if node.node_id not in self._reverse_adjacency:
            self._reverse_adjacency[node.node_id] = []

    def add_edge(self, edge: GraphEdge) -> None:
        """Add a directed edge to the graph.

        Both source and target nodes must exist in the graph.

        Args:
            edge: The graph edge to add.

        Raises:
            ValueError: If source or target node does not exist.
        """
        if edge.source_id not in self._nodes:
            raise ValueError(f"Source node '{edge.source_id}' not found in graph")
        if edge.target_id not in self._nodes:
            raise ValueError(f"Target node '{edge.target_id}' not found in graph")

        self._edges[edge.edge_id] = edge
        self._adjacency[edge.source_id].append(edge.edge_id)
        self._reverse_adjacency[edge.target_id].append(edge.edge_id)

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get a node by ID.

        Args:
            node_id: The node identifier.

        Returns:
            The node if found, None otherwise.
        """
        return self._nodes.get(node_id)

    def get_outgoing_edges(self, node_id: str) -> list[GraphEdge]:
        """Get all outgoing edges from a node.

        Args:
            node_id: The source node identifier.

        Returns:
            List of edges originating from the node.
        """
        edge_ids = self._adjacency.get(node_id, [])
        return [self._edges[eid] for eid in edge_ids if eid in self._edges]

    def get_incoming_edges(self, node_id: str) -> list[GraphEdge]:
        """Get all incoming edges to a node.

        Args:
            node_id: The target node identifier.

        Returns:
            List of edges pointing to the node.
        """
        edge_ids = self._reverse_adjacency.get(node_id, [])
        return [self._edges[eid] for eid in edge_ids if eid in self._edges]

    def get_neighbors(self, node_id: str) -> list[GraphNode]:
        """Get all direct neighbors (targets of outgoing edges).

        Args:
            node_id: The source node identifier.

        Returns:
            List of directly reachable nodes.
        """
        edges = self.get_outgoing_edges(node_id)
        neighbor_ids = {e.target_id for e in edges}
        return [self._nodes[nid] for nid in neighbor_ids if nid in self._nodes]

    def nodes_by_type(self, node_type: NodeType) -> list[GraphNode]:
        """Get all nodes of a specific type.

        Args:
            node_type: The type of nodes to retrieve.

        Returns:
            List of nodes matching the type.
        """
        return [n for n in self._nodes.values() if n.node_type == node_type]

    # -------------------------------------------------------------------------
    # Graph Operations
    # -------------------------------------------------------------------------

    def find_paths(
        self,
        source: str,
        target: str,
        max_depth: int = 10,
    ) -> list[list[str]]:
        """Find all paths from source to target node.

        Uses depth-limited DFS to enumerate paths between two nodes.
        Avoids cycles by tracking visited nodes per path.

        Args:
            source: Source node ID.
            target: Target node ID.
            max_depth: Maximum path length to consider.

        Returns:
            List of paths, where each path is a list of node IDs.

        Raises:
            ValueError: If source or target node does not exist.
        """
        if source not in self._nodes:
            raise ValueError(f"Source node '{source}' not found in graph")
        if target not in self._nodes:
            raise ValueError(f"Target node '{target}' not found in graph")

        paths: list[list[str]] = []
        self._dfs_paths(source, target, [source], set(), max_depth, paths)
        return paths

    def _dfs_paths(
        self,
        current: str,
        target: str,
        path: list[str],
        visited: set[str],
        max_depth: int,
        results: list[list[str]],
    ) -> None:
        """Recursive DFS helper for path finding."""
        if current == target and len(path) > 1:
            results.append(list(path))
            return

        if len(path) > max_depth:
            return

        visited.add(current)
        for edge in self.get_outgoing_edges(current):
            next_node = edge.target_id
            if next_node not in visited:
                path.append(next_node)
                self._dfs_paths(next_node, target, path, visited, max_depth, results)
                path.pop()
        visited.discard(current)

    def blast_radius(self, agent_node_id: str) -> set[str]:
        """Compute the blast radius: all resources reachable from an agent.

        Performs BFS from the agent node to find all transitively
        reachable nodes, representing the maximum impact scope if
        the agent is compromised.

        Args:
            agent_node_id: The agent's node ID in the graph.

        Returns:
            Set of all reachable node IDs (excluding the agent itself).

        Raises:
            ValueError: If the agent node does not exist.
        """
        if agent_node_id not in self._nodes:
            raise ValueError(f"Agent node '{agent_node_id}' not found in graph")

        reachable: set[str] = set()
        queue: deque[str] = deque([agent_node_id])
        visited: set[str] = {agent_node_id}

        while queue:
            current = queue.popleft()
            for edge in self.get_outgoing_edges(current):
                next_node = edge.target_id
                if next_node not in visited:
                    visited.add(next_node)
                    reachable.add(next_node)
                    queue.append(next_node)

        return reachable

    def lateral_movement_paths(self, agent_node_id: str) -> list[list[str]]:
        """Find lateral movement paths from an agent to other roles/agents.

        Identifies paths that lead to role assumption or access to
        other agent identities, representing privilege escalation
        or lateral movement opportunities.

        Args:
            agent_node_id: The agent's node ID in the graph.

        Returns:
            List of paths leading to role or agent nodes.

        Raises:
            ValueError: If the agent node does not exist.
        """
        if agent_node_id not in self._nodes:
            raise ValueError(f"Agent node '{agent_node_id}' not found in graph")

        lateral_targets = [
            n.node_id for n in self._nodes.values()
            if n.node_type in (NodeType.ROLE, NodeType.AGENT)
            and n.node_id != agent_node_id
        ]

        all_paths: list[list[str]] = []
        for target in lateral_targets:
            paths = self.find_paths(agent_node_id, target, max_depth=5)
            all_paths.extend(paths)

        return all_paths

    def data_access_scope(self, agent_node_id: str) -> set[str]:
        """Find all data stores reachable from an agent.

        Filters the blast radius to only include data store nodes
        (S3 buckets, DynamoDB tables, RDS instances, etc.).

        Args:
            agent_node_id: The agent's node ID in the graph.

        Returns:
            Set of reachable data store node IDs.

        Raises:
            ValueError: If the agent node does not exist.
        """
        reachable = self.blast_radius(agent_node_id)
        return {
            node_id for node_id in reachable
            if node_id in self._nodes and self._nodes[node_id].is_data_store
        }

    # -------------------------------------------------------------------------
    # Serialization
    # -------------------------------------------------------------------------

    def to_json(self) -> str:
        """Serialize the graph to a JSON string.

        Returns:
            JSON string representation of the full graph.
        """
        return json.dumps(self.to_dict(), indent=2, default=str)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the graph to a dictionary.

        Returns:
            Dictionary with nodes and edges lists.
        """
        return {
            "nodes": [node.to_dict() for node in self._nodes.values()],
            "edges": [edge.to_dict() for edge in self._edges.values()],
            "metadata": {
                "node_count": self.node_count,
                "edge_count": self.edge_count,
                "node_types": dict(self._count_node_types()),
                "edge_types": dict(self._count_edge_types()),
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CapabilityGraph:
        """Reconstruct a graph from a dictionary.

        Args:
            data: Dictionary with 'nodes' and 'edges' keys.

        Returns:
            Reconstructed CapabilityGraph instance.
        """
        graph = cls()
        for node_data in data.get("nodes", []):
            graph.add_node(GraphNode.from_dict(node_data))
        for edge_data in data.get("edges", []):
            graph.add_edge(GraphEdge.from_dict(edge_data))
        return graph

    @classmethod
    def from_json(cls, json_str: str) -> CapabilityGraph:
        """Reconstruct a graph from a JSON string.

        Args:
            json_str: JSON string representation.

        Returns:
            Reconstructed CapabilityGraph instance.
        """
        return cls.from_dict(json.loads(json_str))

    def to_dot(self, title: str = "CapabilityGraph") -> str:
        """Serialize the graph to DOT format for Graphviz visualization.

        Args:
            title: The graph title for the DOT output.

        Returns:
            DOT format string suitable for Graphviz rendering.
        """
        lines: list[str] = []
        safe_title = title.replace('"', '\\"')
        lines.append(f'digraph "{safe_title}" {{')
        lines.append("    rankdir=LR;")
        lines.append('    node [fontname="Helvetica", fontsize=10];')
        lines.append('    edge [fontname="Helvetica", fontsize=8];')
        lines.append("")

        # Group nodes by type using subgraphs
        nodes_by_type: dict[NodeType, list[GraphNode]] = defaultdict(list)
        for node in self._nodes.values():
            nodes_by_type[node.node_type].append(node)

        for node_type, nodes in nodes_by_type.items():
            lines.append(f"    subgraph cluster_{node_type.value.lower()} {{")
            lines.append(f'        label="{node_type.value}";')
            lines.append("        style=dashed;")
            for node in nodes:
                safe_id = self._dot_safe_id(node.node_id)
                lines.append(f"        {safe_id} [{node.dot_attributes()}];")
            lines.append("    }")
            lines.append("")

        # Edges
        for edge in self._edges.values():
            source_id = self._dot_safe_id(edge.source_id)
            target_id = self._dot_safe_id(edge.target_id)
            lines.append(f"    {source_id} -> {target_id} [{edge.dot_attributes()}];")

        lines.append("}")
        return "\n".join(lines)

    def _dot_safe_id(self, node_id: str) -> str:
        """Convert a node ID to a DOT-safe identifier."""
        # Replace non-alphanumeric characters with underscores
        safe = re.sub(r"[^a-zA-Z0-9_]", "_", node_id)
        # Ensure it doesn't start with a digit
        if safe and safe[0].isdigit():
            safe = f"n_{safe}"
        return safe

    def _count_node_types(self) -> dict[str, int]:
        """Count nodes by type."""
        counts: dict[str, int] = defaultdict(int)
        for node in self._nodes.values():
            counts[node.node_type.value] += 1
        return dict(counts)

    def _count_edge_types(self) -> dict[str, int]:
        """Count edges by type."""
        counts: dict[str, int] = defaultdict(int)
        for edge in self._edges.values():
            counts[edge.edge_type.value] += 1
        return dict(counts)


# =============================================================================
# Capability Inventory
# =============================================================================


class CapabilityInventory:
    """Comprehensive enumeration of an agent's accessible capabilities.

    Automatically discovers and catalogs all AWS services, resources,
    tools, data stores, roles, secrets, endpoints, KMS keys, and
    network scope accessible to an agent based on IAM policies and
    optionally from live AWS API discovery.

    The inventory can be used to:
    - Generate security reports
    - Build capability graphs for analysis
    - Assess blast radius and lateral movement risk
    - Audit compliance with least-privilege principles

    Example:
        >>> agent = Agent.create(name="my-agent", ...)
        >>> inventory = CapabilityInventory.from_agent(agent)
        >>> report = inventory.generate_report()
        >>> graph = inventory.build_graph()
        >>> blast = graph.blast_radius(agent.agent_id)
    """

    def __init__(
        self,
        agent: Agent,
        services: list[DiscoveredService] | None = None,
        resources: list[DiscoveredResource] | None = None,
        roles: list[DiscoveredRole] | None = None,
        secrets: list[DiscoveredSecret] | None = None,
        kms_keys: list[DiscoveredKMSKey] | None = None,
        endpoints: list[DiscoveredEndpoint] | None = None,
        network_scope: NetworkScope | None = None,
    ) -> None:
        """Initialize a capability inventory.

        Args:
            agent: The agent this inventory describes.
            services: Discovered AWS services.
            resources: Discovered accessible resources.
            roles: Discovered assumable roles.
            secrets: Discovered accessible secrets.
            kms_keys: Discovered KMS keys.
            endpoints: Discovered external endpoints.
            network_scope: Network access scope.
        """
        self._agent = agent
        self._services: list[DiscoveredService] = services or []
        self._resources: list[DiscoveredResource] = resources or []
        self._roles: list[DiscoveredRole] = roles or []
        self._secrets: list[DiscoveredSecret] = secrets or []
        self._kms_keys: list[DiscoveredKMSKey] = kms_keys or []
        self._endpoints: list[DiscoveredEndpoint] = endpoints or []
        self._network_scope: NetworkScope = network_scope or NetworkScope()
        self._discovered_at: datetime = datetime.now(timezone.utc)

    @property
    def agent(self) -> Agent:
        """The agent this inventory describes."""
        return self._agent

    @property
    def services(self) -> list[DiscoveredService]:
        """Discovered AWS services."""
        return self._services

    @property
    def resources(self) -> list[DiscoveredResource]:
        """Discovered accessible resources."""
        return self._resources

    @property
    def roles(self) -> list[DiscoveredRole]:
        """Discovered assumable roles."""
        return self._roles

    @property
    def secrets(self) -> list[DiscoveredSecret]:
        """Discovered accessible secrets."""
        return self._secrets

    @property
    def kms_keys(self) -> list[DiscoveredKMSKey]:
        """Discovered KMS keys."""
        return self._kms_keys

    @property
    def endpoints(self) -> list[DiscoveredEndpoint]:
        """Discovered external endpoints."""
        return self._endpoints

    @property
    def network_scope(self) -> NetworkScope:
        """Network access scope."""
        return self._network_scope

    @property
    def tools(self) -> list[DiscoveredResource]:
        """Lambda functions, Step Functions, and Bedrock agents."""
        return [
            r for r in self._resources
            if r.service in ("lambda", "states", "bedrock")
        ]

    @property
    def data_stores(self) -> list[DiscoveredResource]:
        """S3 buckets, DynamoDB tables, RDS instances, and other data stores."""
        return [
            r for r in self._resources
            if _is_data_store_service(r.service)
        ]

    @property
    def actions_by_service(self) -> dict[str, list[str]]:
        """All actions grouped by AWS service."""
        grouped: dict[str, list[str]] = defaultdict(list)
        for svc in self._services:
            grouped[svc.service_name].extend(svc.actions)
        # Deduplicate
        return {k: sorted(set(v)) for k, v in grouped.items()}

    @classmethod
    def from_agent(
        cls,
        agent: Agent,
        discovery_sources: list[Any] | None = None,
    ) -> CapabilityInventory:
        """Create an inventory by discovering capabilities from an agent.

        Uses IAM policy analysis by default. Additional discovery sources
        (e.g., live AWS API queries) can be provided.

        Args:
            agent: The agent to inventory.
            discovery_sources: Optional additional discovery sources implementing
                the DiscoverySource protocol.

        Returns:
            A fully populated CapabilityInventory instance.
        """
        # Default to static IAM policy analysis
        iam_discovery = IAMPolicyDiscovery()

        services = iam_discovery.discover_services(agent)
        resources = iam_discovery.discover_resources(agent)
        roles = iam_discovery.discover_roles(agent)
        secrets = iam_discovery.discover_secrets(agent)
        kms_keys = iam_discovery.discover_kms_keys(agent)
        endpoints = iam_discovery.discover_endpoints(agent)

        # Run additional discovery sources
        if discovery_sources:
            for source in discovery_sources:
                if hasattr(source, "discover_services"):
                    services.extend(source.discover_services(agent))
                if hasattr(source, "discover_resources"):
                    resources.extend(source.discover_resources(agent))
                if hasattr(source, "discover_roles"):
                    roles.extend(source.discover_roles(agent))

        return cls(
            agent=agent,
            services=services,
            resources=resources,
            roles=roles,
            secrets=secrets,
            kms_keys=kms_keys,
            endpoints=endpoints,
        )

    @classmethod
    def from_policies(
        cls,
        agent: Agent,
        policy_documents: list[dict[str, Any]],
    ) -> CapabilityInventory:
        """Create an inventory from explicit policy documents.

        Useful when you want to analyze specific policies rather than
        relying on the agent's attached identity_policies.

        Args:
            agent: The agent identity (used for context).
            policy_documents: IAM policy documents to analyze.

        Returns:
            A CapabilityInventory based on the provided policies.
        """
        # Temporarily set policies on agent for discovery
        # Create a copy with the provided policies
        augmented_agent = Agent(
            agent_id=agent.agent_id,
            name=agent.name,
            owner=agent.owner,
            environment=agent.environment,
            purpose=agent.purpose,
            workload_type=agent.workload_type,
            iam_role_arn=agent.iam_role_arn,
            trust_policy=agent.trust_policy,
            identity_policies=policy_documents,
            permission_boundaries=agent.permission_boundaries,
            data_classification=agent.data_classification,
            tags=agent.tags,
            created_at=agent.created_at,
            last_activity=agent.last_activity,
            status=agent.status,
        )
        return cls.from_agent(augmented_agent)

    def build_graph(self) -> CapabilityGraph:
        """Build a capability graph from the inventory.

        Constructs a directed graph with nodes for the agent, services,
        resources, roles, secrets, endpoints, and KMS keys. Edges
        represent access relationships with risk levels and conditions.

        Returns:
            A populated CapabilityGraph for analysis.
        """
        graph = CapabilityGraph()

        # Create agent node
        agent_node = GraphNode(
            node_id=self._agent.agent_id,
            node_type=NodeType.AGENT,
            label=self._agent.name,
            arn=self._agent.iam_role_arn,
            metadata={
                "environment": self._agent.environment.value,
                "workload_type": self._agent.workload_type.value,
                "data_classification": self._agent.data_classification.value,
            },
        )
        graph.add_node(agent_node)

        # Add service nodes and edges
        for svc in self._services:
            service_node_id = f"service:{svc.service_name}"
            if not graph.get_node(service_node_id):
                graph.add_node(GraphNode(
                    node_id=service_node_id,
                    node_type=NodeType.SERVICE,
                    label=svc.service_name,
                    metadata={"actions_count": len(svc.actions)},
                ))
            graph.add_edge(GraphEdge.create(
                source_id=self._agent.agent_id,
                target_id=service_node_id,
                edge_type=EdgeType.CAN_ACCESS,
                permission_source=svc.permission_source,
                conditions=svc.conditions,
                risk_level=self._service_risk_level(svc),
                actions=svc.actions,
            ))

        # Add resource nodes and edges
        for res in self._resources:
            resource_node_id = f"resource:{res.arn}"
            node_type = NodeType.DATA_STORE if res.category in (
                ResourceCategory.STORAGE, ResourceCategory.DATABASE
            ) else NodeType.RESOURCE
            if not graph.get_node(resource_node_id):
                graph.add_node(GraphNode(
                    node_id=resource_node_id,
                    node_type=node_type,
                    label=self._short_label(res.arn),
                    arn=res.arn,
                    resource_category=res.category,
                    metadata={
                        "service": res.service,
                        "resource_type": res.resource_type,
                    },
                ))

            # Determine edge type from actions
            edge_type = self._primary_edge_type(res.actions)
            graph.add_edge(GraphEdge.create(
                source_id=self._agent.agent_id,
                target_id=resource_node_id,
                edge_type=edge_type,
                permission_source=res.permission_source,
                conditions=res.conditions,
                risk_level=res.risk_level,
                actions=res.actions,
            ))

        # Add role nodes and edges
        for role in self._roles:
            role_node_id = f"role:{role.role_arn}"
            if not graph.get_node(role_node_id):
                graph.add_node(GraphNode(
                    node_id=role_node_id,
                    node_type=NodeType.ROLE,
                    label=role.role_name,
                    arn=role.role_arn,
                    metadata={
                        "is_cross_account": role.is_cross_account,
                        "attached_policies": role.attached_policies,
                    },
                ))
            risk = RiskLevel.HIGH if role.is_cross_account else RiskLevel.MEDIUM
            graph.add_edge(GraphEdge.create(
                source_id=self._agent.agent_id,
                target_id=role_node_id,
                edge_type=EdgeType.CAN_ASSUME,
                permission_source=PermissionSource.IDENTITY_POLICY,
                conditions=role.conditions,
                risk_level=risk,
                actions=["sts:AssumeRole"],
            ))

        # Add secret nodes and edges
        for secret in self._secrets:
            secret_node_id = f"secret:{secret.secret_arn}"
            if not graph.get_node(secret_node_id):
                graph.add_node(GraphNode(
                    node_id=secret_node_id,
                    node_type=NodeType.SECRET,
                    label=secret.secret_name,
                    arn=secret.secret_arn,
                    metadata={
                        "rotation_enabled": secret.rotation_enabled,
                        "kms_key_id": secret.kms_key_id,
                    },
                ))
            graph.add_edge(GraphEdge.create(
                source_id=self._agent.agent_id,
                target_id=secret_node_id,
                edge_type=EdgeType.CAN_READ,
                permission_source=PermissionSource.IDENTITY_POLICY,
                risk_level=RiskLevel.HIGH,
                actions=secret.actions,
            ))

        # Add KMS key nodes and edges
        for key in self._kms_keys:
            key_node_id = f"kms:{key.key_arn}"
            if not graph.get_node(key_node_id):
                graph.add_node(GraphNode(
                    node_id=key_node_id,
                    node_type=NodeType.KMS_KEY,
                    label=key.alias or key.key_id,
                    arn=key.key_arn,
                    metadata={
                        "key_policy_grants_access": key.key_policy_grants_access,
                    },
                ))
            graph.add_edge(GraphEdge.create(
                source_id=self._agent.agent_id,
                target_id=key_node_id,
                edge_type=EdgeType.CAN_ACCESS,
                permission_source=PermissionSource.IDENTITY_POLICY,
                risk_level=RiskLevel.HIGH,
                actions=key.actions,
            ))

        # Add endpoint nodes and edges
        for ep in self._endpoints:
            ep_node_id = f"endpoint:{ep.endpoint_url}"
            if not graph.get_node(ep_node_id):
                graph.add_node(GraphNode(
                    node_id=ep_node_id,
                    node_type=NodeType.ENDPOINT,
                    label=ep.endpoint_url,
                    metadata={
                        "endpoint_type": ep.endpoint_type,
                        "protocol": ep.protocol,
                        "port": ep.port,
                        "vpc_id": ep.vpc_id,
                    },
                ))
            graph.add_edge(GraphEdge.create(
                source_id=self._agent.agent_id,
                target_id=ep_node_id,
                edge_type=EdgeType.CAN_INVOKE,
                permission_source=PermissionSource.IDENTITY_POLICY,
                risk_level=RiskLevel.MEDIUM,
            ))

        return graph

    def generate_report(self) -> dict[str, Any]:
        """Generate a structured inventory report.

        Produces a comprehensive JSON-serializable report covering
        all discovered capabilities, risk assessment, and summary
        statistics.

        Returns:
            Dictionary suitable for JSON serialization or display.
        """
        return {
            "report_metadata": {
                "agent_id": self._agent.agent_id,
                "agent_name": self._agent.name,
                "environment": self._agent.environment.value,
                "workload_type": self._agent.workload_type.value,
                "iam_role_arn": self._agent.iam_role_arn,
                "discovered_at": self._discovered_at.isoformat(),
                "data_classification": self._agent.data_classification.value,
            },
            "summary": {
                "total_services": len(self._services),
                "total_resources": len(self._resources),
                "total_roles": len(self._roles),
                "total_secrets": len(self._secrets),
                "total_kms_keys": len(self._kms_keys),
                "total_endpoints": len(self._endpoints),
                "total_tools": len(self.tools),
                "total_data_stores": len(self.data_stores),
                "has_wildcard_access": self._has_wildcard_access(),
                "has_cross_account_roles": any(r.is_cross_account for r in self._roles),
                "risk_distribution": self._risk_distribution(),
            },
            "services": [svc.to_dict() for svc in self._services],
            "actions_by_service": self.actions_by_service,
            "resources": [res.to_dict() for res in self._resources],
            "tools": [t.to_dict() for t in self.tools],
            "data_stores": [d.to_dict() for d in self.data_stores],
            "roles": [role.to_dict() for role in self._roles],
            "secrets": [s.to_dict() for s in self._secrets],
            "kms_keys": [k.to_dict() for k in self._kms_keys],
            "endpoints": [ep.to_dict() for ep in self._endpoints],
            "network_scope": self._network_scope.to_dict(),
        }

    def generate_report_json(self, indent: int = 2) -> str:
        """Generate the inventory report as a JSON string.

        Args:
            indent: JSON indentation level.

        Returns:
            JSON-formatted report string.
        """
        return json.dumps(self.generate_report(), indent=indent, default=str)

    def _has_wildcard_access(self) -> bool:
        """Check if the agent has any wildcard (*) access."""
        for svc in self._services:
            if "*" in svc.actions:
                return True
        for res in self._resources:
            if res.arn == "*":
                return True
        return False

    def _risk_distribution(self) -> dict[str, int]:
        """Count resources by risk level."""
        dist: dict[str, int] = defaultdict(int)
        for res in self._resources:
            dist[res.risk_level.value] += 1
        return dict(dist)

    def _service_risk_level(self, svc: DiscoveredService) -> RiskLevel:
        """Determine risk level for a service based on its actions."""
        if "*" in svc.actions or any(a.endswith(":*") for a in svc.actions):
            return RiskLevel.HIGH

        max_risk = RiskLevel.INFORMATIONAL
        for action in svc.actions:
            risk = _classify_risk(action, "*")
            if list(RiskLevel).index(risk) < list(RiskLevel).index(max_risk):
                max_risk = risk
        return max_risk

    def _primary_edge_type(self, actions: list[str]) -> EdgeType:
        """Determine the primary edge type from a list of actions."""
        # Use the most permissive action to determine edge type
        for action in actions:
            edge = _determine_edge_type(action)
            if edge == EdgeType.CAN_DELETE:
                return EdgeType.CAN_DELETE
        for action in actions:
            edge = _determine_edge_type(action)
            if edge == EdgeType.CAN_WRITE:
                return EdgeType.CAN_WRITE
        for action in actions:
            edge = _determine_edge_type(action)
            if edge == EdgeType.CAN_INVOKE:
                return EdgeType.CAN_INVOKE
        for action in actions:
            edge = _determine_edge_type(action)
            if edge == EdgeType.CAN_READ:
                return EdgeType.CAN_READ
        return EdgeType.CAN_ACCESS

    def _short_label(self, arn: str) -> str:
        """Generate a short display label from an ARN."""
        if arn == "*":
            return "*"
        parts = arn.split(":")
        if len(parts) >= 6:
            resource = ":".join(parts[5:])
            # Trim to last path component
            if "/" in resource:
                return resource.split("/")[-1]
            return resource
        return arn[-40:] if len(arn) > 40 else arn


# =============================================================================
# Live AWS Discovery (Optional)
# =============================================================================


class LiveAWSDiscovery:
    """Live discovery source using AWS APIs.

    Queries AWS APIs to discover actual resources, configurations,
    and network topology. Requires appropriate IAM permissions.

    This class is designed to be used as an additional discovery source
    alongside static IAM policy analysis.

    Example:
        >>> import boto3
        >>> session = boto3.Session()
        >>> live = LiveAWSDiscovery(session)
        >>> inventory = CapabilityInventory.from_agent(
        ...     agent, discovery_sources=[live]
        ... )
    """

    def __init__(self, boto_session: Any = None, region: str = "us-east-1") -> None:
        """Initialize live AWS discovery.

        Args:
            boto_session: A boto3 Session object. If None, discovery
                methods will return empty results.
            region: AWS region for API calls.
        """
        self._session = boto_session
        self._region = region

    def discover_services(self, agent: Agent) -> list[DiscoveredService]:
        """Discover services from IAM access advisor.

        Uses IAM's GenerateServiceLastAccessedDetails to find
        services the role has actually accessed.

        Args:
            agent: The agent to query.

        Returns:
            List of services with recent access.
        """
        if not self._session:
            return []

        discovered: list[DiscoveredService] = []
        try:
            iam_client = self._session.client("iam", region_name=self._region)
            # Extract role name from ARN
            role_name = agent.iam_role_arn.split("/")[-1]

            response = iam_client.generate_service_last_accessed_details(
                Arn=agent.iam_role_arn
            )
            job_id = response.get("JobId")
            if not job_id:
                return []

            # Poll for completion (simplified - in production use waiter)
            import time
            for _ in range(10):
                result = iam_client.get_service_last_accessed_details(JobId=job_id)
                if result.get("JobStatus") == "COMPLETED":
                    for svc in result.get("ServicesLastAccessed", []):
                        if svc.get("TotalAuthenticatedEntities", 0) > 0:
                            discovered.append(DiscoveredService(
                                service_name=svc.get("ServiceNamespace", ""),
                                actions=[],  # Access advisor doesn't give action details
                                permission_source=PermissionSource.IDENTITY_POLICY,
                                conditions={"last_accessed": str(svc.get("LastAuthenticated", ""))},
                            ))
                    break
                time.sleep(1)
        except Exception:
            # Graceful degradation - live discovery is best-effort
            pass

        return discovered

    def discover_resources(self, agent: Agent) -> list[DiscoveredResource]:
        """Discover actual resources using resource tagging API.

        Uses the Resource Groups Tagging API to enumerate resources
        that are accessible.

        Args:
            agent: The agent to query.

        Returns:
            List of discovered resources.
        """
        if not self._session:
            return []

        discovered: list[DiscoveredResource] = []
        try:
            tagging_client = self._session.client(
                "resourcegroupstaggingapi", region_name=self._region
            )
            paginator = tagging_client.get_paginator("get_resources")
            for page in paginator.paginate():
                for resource in page.get("ResourceTagMappingList", []):
                    arn = resource.get("ResourceARN", "")
                    service = _extract_service_from_arn(arn)
                    category = _SERVICE_CATEGORY_MAP.get(service)
                    discovered.append(DiscoveredResource(
                        arn=arn,
                        service=service,
                        resource_type=self._infer_type_from_arn(arn),
                        actions=[],
                        permission_source=PermissionSource.IDENTITY_POLICY,
                        category=category,
                        metadata={
                            "tags": {
                                t["Key"]: t["Value"]
                                for t in resource.get("Tags", [])
                            }
                        },
                    ))
        except Exception:
            pass

        return discovered

    def discover_roles(self, agent: Agent) -> list[DiscoveredRole]:
        """Discover roles from IAM that trust this agent's role.

        Queries IAM to find roles whose trust policies allow
        assumption by the agent's role.

        Args:
            agent: The agent to query.

        Returns:
            List of assumable roles.
        """
        if not self._session:
            return []

        discovered: list[DiscoveredRole] = []
        try:
            iam_client = self._session.client("iam", region_name=self._region)
            paginator = iam_client.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    trust = role.get("AssumeRolePolicyDocument", {})
                    if self._role_trusts_agent(trust, agent.iam_role_arn):
                        discovered.append(DiscoveredRole(
                            role_arn=role["Arn"],
                            role_name=role["RoleName"],
                            trust_policy=trust,
                        ))
        except Exception:
            pass

        return discovered

    def discover_network_scope(self, agent: Agent) -> NetworkScope:
        """Discover network configuration for the agent's workload.

        Queries VPC, subnet, and security group configurations
        to determine network-level access scope.

        Args:
            agent: The agent to query.

        Returns:
            Network scope information.
        """
        if not self._session:
            return NetworkScope()

        scope = NetworkScope()
        try:
            ec2_client = self._session.client("ec2", region_name=self._region)

            # Get VPC endpoints
            endpoints_resp = ec2_client.describe_vpc_endpoints()
            for ep in endpoints_resp.get("VpcEndpoints", []):
                scope.vpc_endpoints.append(ep.get("ServiceName", ""))
                if ep.get("VpcId") and ep["VpcId"] not in scope.vpc_ids:
                    scope.vpc_ids.append(ep["VpcId"])

            # Check for NAT gateways (internet access indicator)
            nat_resp = ec2_client.describe_nat_gateways()
            for nat in nat_resp.get("NatGateways", []):
                if nat.get("State") == "available":
                    scope.nat_gateway_ids.append(nat["NatGatewayId"])
                    scope.has_internet_access = True

        except Exception:
            pass

        return scope

    def _role_trusts_agent(self, trust_policy: dict[str, Any], agent_arn: str) -> bool:
        """Check if a trust policy allows the agent's role to assume it."""
        statements = trust_policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect", "").lower() != "allow":
                continue
            principals = stmt.get("Principal", {})
            if isinstance(principals, str):
                principals = {"AWS": [principals]}
            aws_principals = principals.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for principal in aws_principals:
                if principal == "*" or principal == agent_arn:
                    return True
                # Check account-level trust
                agent_account = agent_arn.split(":")[4] if len(agent_arn.split(":")) > 4 else ""
                if agent_account and agent_account in principal:
                    return True
        return False

    def _infer_type_from_arn(self, arn: str) -> str:
        """Infer resource type from ARN structure."""
        parts = arn.split(":")
        if len(parts) >= 6:
            resource = ":".join(parts[5:])
            if "/" in resource:
                return resource.split("/")[0]
            return resource
        return "unknown"


# =============================================================================
# Module Exports
# =============================================================================


__all__ = [
    # Enums
    "NodeType",
    "EdgeType",
    "RiskLevel",
    "ResourceCategory",
    # Graph primitives
    "GraphNode",
    "GraphEdge",
    # Graph
    "CapabilityGraph",
    # Inventory
    "CapabilityInventory",
    # Discovery types
    "DiscoveredService",
    "DiscoveredResource",
    "DiscoveredRole",
    "DiscoveredEndpoint",
    "DiscoveredSecret",
    "DiscoveredKMSKey",
    "NetworkScope",
    # Discovery sources
    "IAMPolicyDiscovery",
    "LiveAWSDiscovery",
    "DiscoverySource",
]
