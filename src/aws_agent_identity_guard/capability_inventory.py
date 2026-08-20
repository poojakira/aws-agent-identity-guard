"""
aws_agent_identity_guard/capability_inventory.py
---------------------------------------------------------------------------
Agent Capability Inventory Module.

Discovers and catalogs the full range of capabilities an AI agent possesses
based on its effective permissions. Enumerates services, APIs, data stores,
secrets, external endpoints, and assumable roles. Builds a capability graph
that can be visualized as Mermaid diagrams or Graphviz DOT notation.

Security philosophy:
  - Complete visibility into what an agent CAN do is prerequisite for control.
  - The capability graph reveals lateral movement paths and data access scope.
  - Visualization enables security reviewers to quickly spot anomalies.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
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


class StoreType(str, Enum):
    """Classification of data store types."""

    S3 = "S3"
    DYNAMODB = "DYNAMODB"
    RDS = "RDS"
    REDSHIFT = "REDSHIFT"
    ELASTICACHE = "ELASTICACHE"
    OPENSEARCH = "OPENSEARCH"


class AccessLevel(str, Enum):
    """Level of access to a data store."""

    READ = "READ"
    WRITE = "WRITE"
    ADMIN = "ADMIN"


class SecretAccessType(str, Enum):
    """Type of access to a secret."""

    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    ROTATE = "ROTATE"


class EndpointType(str, Enum):
    """Classification of external endpoint types."""

    API_GATEWAY = "API_GATEWAY"
    LAMBDA_URL = "LAMBDA_URL"
    VPC_ENDPOINT = "VPC_ENDPOINT"
    EVENTBRIDGE = "EVENTBRIDGE"
    SNS = "SNS"


class RoleAccessType(str, Enum):
    """Type of access to an IAM role."""

    ASSUME = "ASSUME"
    PASS = "PASS"


class EdgeRelationship(str, Enum):
    """Type of relationship between capability graph nodes."""

    ACCESSES = "ACCESSES"
    ASSUMES = "ASSUMES"
    PASSES = "PASSES"
    INVOKES = "INVOKES"
    READS_FROM = "READS_FROM"
    WRITES_TO = "WRITES_TO"
    MANAGES = "MANAGES"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass
class DataStoreAccess:
    """
    Describes an agent's access to a specific data store.

    Attributes:
        store_type: The type of data store (S3, DynamoDB, RDS, etc.).
        resource_arn: The ARN of the data store resource.
        access_level: The level of access (READ, WRITE, ADMIN).
        actions: Specific actions available on this store.
    """

    store_type: StoreType
    resource_arn: str
    access_level: AccessLevel
    actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "store_type": self.store_type.value,
            "resource_arn": self.resource_arn,
            "access_level": self.access_level.value,
            "actions": list(self.actions),
        }


@dataclass
class SecretAccess:
    """
    Describes an agent's access to a secret or parameter.

    Attributes:
        secret_arn: The ARN of the secret or parameter.
        access_type: The type of access (READ, WRITE, DELETE, ROTATE).
        source_service: The service managing the secret (secretsmanager, ssm).
    """

    secret_arn: str
    access_type: SecretAccessType
    source_service: str = "secretsmanager"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "secret_arn": self.secret_arn,
            "access_type": self.access_type.value,
            "source_service": self.source_service,
        }


@dataclass
class ExternalEndpoint:
    """
    Describes an agent's ability to reach an external endpoint.

    Attributes:
        endpoint_type: Classification of the endpoint.
        resource: The ARN or identifier of the endpoint resource.
        actions: Specific actions available on this endpoint.
    """

    endpoint_type: EndpointType
    resource: str
    actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "endpoint_type": self.endpoint_type.value,
            "resource": self.resource,
            "actions": list(self.actions),
        }


@dataclass
class RoleAccess:
    """
    Describes an agent's ability to assume or pass an IAM role.

    Attributes:
        role_arn: The ARN of the role.
        access_type: Whether the agent can ASSUME or PASS this role.
    """

    role_arn: str
    access_type: RoleAccessType

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "role_arn": self.role_arn,
            "access_type": self.access_type.value,
        }


@dataclass
class CapabilityEdge:
    """
    An edge in the capability graph connecting two nodes.

    Attributes:
        source: Source node identifier (agent, service, or resource).
        target: Target node identifier.
        relationship: The type of relationship this edge represents.
        permissions_required: IAM permissions that enable this edge.
    """

    source: str
    target: str
    relationship: EdgeRelationship
    permissions_required: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship.value,
            "permissions_required": list(self.permissions_required),
        }


@dataclass
class AgentCapabilityGraph:
    """
    Complete capability graph for an AI agent.

    Represents all services, APIs, data stores, secrets, roles, and external
    endpoints the agent can access, plus the edges showing relationships.

    Attributes:
        agent_id: The agent this graph represents.
        services: List of AWS services accessible.
        apis: List of specific API actions available.
        data_stores: List of data stores with access details.
        secrets: List of secrets accessible.
        roles: List of roles that can be assumed or passed.
        external_endpoints: List of external endpoints reachable.
        edges: Relationship edges in the capability graph.
    """

    agent_id: str
    services: list[str] = field(default_factory=list)
    apis: list[str] = field(default_factory=list)
    data_stores: list[DataStoreAccess] = field(default_factory=list)
    secrets: list[SecretAccess] = field(default_factory=list)
    roles: list[RoleAccess] = field(default_factory=list)
    external_endpoints: list[ExternalEndpoint] = field(default_factory=list)
    edges: list[CapabilityEdge] = field(default_factory=list)

    @property
    def total_capabilities(self) -> int:
        """Total count of all discovered capabilities."""
        return (
            len(self.services)
            + len(self.apis)
            + len(self.data_stores)
            + len(self.secrets)
            + len(self.roles)
            + len(self.external_endpoints)
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "agent_id": self.agent_id,
            "services": list(self.services),
            "apis": list(self.apis),
            "data_stores": [ds.to_dict() for ds in self.data_stores],
            "secrets": [s.to_dict() for s in self.secrets],
            "roles": [r.to_dict() for r in self.roles],
            "external_endpoints": [ep.to_dict() for ep in self.external_endpoints],
            "edges": [e.to_dict() for e in self.edges],
            "total_capabilities": self.total_capabilities,
        }


# ---------------------------------------------------------------------------
# Service Classification Constants
# ---------------------------------------------------------------------------

_DATA_STORE_READ_ACTIONS: dict[str, StoreType] = {
    "s3:GetObject": StoreType.S3,
    "s3:ListBucket": StoreType.S3,
    "s3:ListAllMyBuckets": StoreType.S3,
    "s3:HeadObject": StoreType.S3,
    "dynamodb:GetItem": StoreType.DYNAMODB,
    "dynamodb:Query": StoreType.DYNAMODB,
    "dynamodb:Scan": StoreType.DYNAMODB,
    "dynamodb:BatchGetItem": StoreType.DYNAMODB,
    "dynamodb:DescribeTable": StoreType.DYNAMODB,
    "rds-data:ExecuteStatement": StoreType.RDS,
    "rds-data:BatchExecuteStatement": StoreType.RDS,
    "redshift-data:ExecuteStatement": StoreType.REDSHIFT,
    "redshift-data:GetStatementResult": StoreType.REDSHIFT,
}

_DATA_STORE_WRITE_ACTIONS: dict[str, StoreType] = {
    "s3:PutObject": StoreType.S3,
    "s3:DeleteObject": StoreType.S3,
    "s3:CopyObject": StoreType.S3,
    "dynamodb:PutItem": StoreType.DYNAMODB,
    "dynamodb:UpdateItem": StoreType.DYNAMODB,
    "dynamodb:DeleteItem": StoreType.DYNAMODB,
    "dynamodb:BatchWriteItem": StoreType.DYNAMODB,
}

_DATA_STORE_ADMIN_ACTIONS: dict[str, StoreType] = {
    "s3:DeleteBucket": StoreType.S3,
    "s3:PutBucketPolicy": StoreType.S3,
    "s3:PutBucketAcl": StoreType.S3,
    "dynamodb:DeleteTable": StoreType.DYNAMODB,
    "dynamodb:CreateTable": StoreType.DYNAMODB,
    "dynamodb:UpdateTable": StoreType.DYNAMODB,
    "rds:DeleteDBInstance": StoreType.RDS,
    "rds:ModifyDBInstance": StoreType.RDS,
    "redshift:DeleteCluster": StoreType.REDSHIFT,
    "redshift:ModifyCluster": StoreType.REDSHIFT,
}

_SECRET_READ_ACTIONS = {
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret",
    "secretsmanager:ListSecrets",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
}

_SECRET_WRITE_ACTIONS = {
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecret",
    "secretsmanager:CreateSecret",
    "ssm:PutParameter",
}

_SECRET_DELETE_ACTIONS = {
    "secretsmanager:DeleteSecret",
    "ssm:DeleteParameter",
    "ssm:DeleteParameters",
}

_SECRET_ROTATE_ACTIONS = {
    "secretsmanager:RotateSecret",
}

_ENDPOINT_ACTIONS: dict[str, EndpointType] = {
    "execute-api:Invoke": EndpointType.API_GATEWAY,
    "execute-api:ManageConnections": EndpointType.API_GATEWAY,
    "lambda:InvokeFunction": EndpointType.LAMBDA_URL,
    "lambda:InvokeFunctionUrl": EndpointType.LAMBDA_URL,
    "events:PutEvents": EndpointType.EVENTBRIDGE,
    "sns:Publish": EndpointType.SNS,
}

_ROLE_ASSUME_ACTIONS = {"sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity"}
_ROLE_PASS_ACTIONS = {"iam:PassRole"}



# ---------------------------------------------------------------------------
# Capability Inventory
# ---------------------------------------------------------------------------


class CapabilityInventory:
    """
    Discovers and catalogs the full capability set of an AI agent.

    Analyzes effective permissions to enumerate all services, APIs, data stores,
    secrets, external endpoints, and roles accessible. Builds a graph
    representation suitable for visualization and security review.

    Usage:
        inventory = CapabilityInventory()
        graph = inventory.discover(agent, effective_permissions)
        mermaid_diagram = inventory.to_mermaid(graph)
    """

    def __init__(self) -> None:
        """Initialize the capability inventory."""
        logger.info("CapabilityInventory initialized")

    def discover(
        self,
        agent: AgentIdentity,
        effective_permissions: list[EffectivePermission],
    ) -> AgentCapabilityGraph:
        """
        Discover and catalog all capabilities for the given agent.

        Analyzes the agent's effective permissions to build a complete
        capability graph showing what the agent can access and how.

        Args:
            agent: The agent identity to analyze.
            effective_permissions: The agent's resolved effective permissions.

        Returns:
            AgentCapabilityGraph with all discovered capabilities.

        Raises:
            ValueError: If agent or permissions are invalid.
        """
        if not agent:
            raise ValueError("agent cannot be None")
        if not agent.agent_id:
            raise ValueError("agent must have a valid agent_id")

        logger.info(
            "Discovering capabilities for agent '%s' (%s) with %d permissions",
            agent.name,
            agent.agent_id,
            len(effective_permissions),
        )

        # Filter to ALLOWED permissions
        allowed = [
            p for p in effective_permissions
            if p.effective_effect == EffectiveEffect.ALLOWED
        ]

        services = self._enumerate_services(allowed)
        apis = self._enumerate_apis(allowed)
        data_stores = self._enumerate_data_stores(allowed)
        secrets = self._enumerate_secrets(allowed)
        external_endpoints = self._enumerate_external_endpoints(allowed)
        roles = self._enumerate_roles(allowed)

        graph = self._build_capability_graph(
            agent_id=agent.agent_id,
            services=services,
            apis=apis,
            data_stores=data_stores,
            secrets=secrets,
            external_endpoints=external_endpoints,
            roles=roles,
            permissions=allowed,
        )

        logger.info(
            "Capability discovery complete for agent '%s': "
            "%d services, %d APIs, %d data stores, %d secrets, "
            "%d endpoints, %d roles, %d edges",
            agent.name,
            len(graph.services),
            len(graph.apis),
            len(graph.data_stores),
            len(graph.secrets),
            len(graph.external_endpoints),
            len(graph.roles),
            len(graph.edges),
        )

        return graph

    def _enumerate_services(
        self, permissions: list[EffectivePermission]
    ) -> list[str]:
        """
        Enumerate all AWS services accessible via the given permissions.

        Args:
            permissions: List of ALLOWED effective permissions.

        Returns:
            Sorted list of unique service names.
        """
        services: set[str] = set()
        for perm in permissions:
            action = perm.action
            if ":" in action:
                service = action.split(":")[0]
                services.add(service)
            elif action == "*":
                services.add("ALL_SERVICES")

        result = sorted(services)
        logger.debug("Enumerated %d services: %s", len(result), result)
        return result

    def _enumerate_apis(
        self, permissions: list[EffectivePermission]
    ) -> list[str]:
        """
        Enumerate all specific API actions available.

        Args:
            permissions: List of ALLOWED effective permissions.

        Returns:
            Sorted list of unique API action strings.
        """
        apis: set[str] = set()
        for perm in permissions:
            if perm.action != "*":
                apis.add(perm.action)

        result = sorted(apis)
        logger.debug("Enumerated %d APIs", len(result))
        return result

    def _enumerate_data_stores(
        self, permissions: list[EffectivePermission]
    ) -> list[DataStoreAccess]:
        """
        Enumerate all data stores accessible with their access levels.

        Args:
            permissions: List of ALLOWED effective permissions.

        Returns:
            List of DataStoreAccess entries.
        """
        store_map: dict[tuple[StoreType, str], set[str]] = {}

        for perm in permissions:
            action = perm.action
            resource = perm.resource

            for action_map in [
                _DATA_STORE_READ_ACTIONS,
                _DATA_STORE_WRITE_ACTIONS,
                _DATA_STORE_ADMIN_ACTIONS,
            ]:
                if action in action_map:
                    store_type = action_map[action]
                    key = (store_type, resource)
                    if key not in store_map:
                        store_map[key] = set()
                    store_map[key].add(action)

            # Handle wildcard actions for data store services
            if action.endswith(":*") or action == "*":
                service = action.split(":")[0] if ":" in action else ""
                service_to_store = {
                    "s3": StoreType.S3,
                    "dynamodb": StoreType.DYNAMODB,
                    "rds": StoreType.RDS,
                    "rds-data": StoreType.RDS,
                    "redshift": StoreType.REDSHIFT,
                    "redshift-data": StoreType.REDSHIFT,
                }
                if service in service_to_store:
                    store_type = service_to_store[service]
                    key = (store_type, resource)
                    if key not in store_map:
                        store_map[key] = set()
                    store_map[key].add(action)

        data_stores: list[DataStoreAccess] = []
        for (store_type, resource), actions in store_map.items():
            access_level = self._determine_access_level(actions)
            data_stores.append(
                DataStoreAccess(
                    store_type=store_type,
                    resource_arn=resource,
                    access_level=access_level,
                    actions=sorted(actions),
                )
            )

        logger.debug("Enumerated %d data stores", len(data_stores))
        return data_stores

    def _enumerate_secrets(
        self, permissions: list[EffectivePermission]
    ) -> list[SecretAccess]:
        """
        Enumerate all secrets and parameters accessible.

        Args:
            permissions: List of ALLOWED effective permissions.

        Returns:
            List of SecretAccess entries.
        """
        secrets: list[SecretAccess] = []
        seen: set[tuple[str, str]] = set()

        for perm in permissions:
            action = perm.action
            resource = perm.resource

            access_type: SecretAccessType | None = None
            source_service = ""

            if action in _SECRET_READ_ACTIONS:
                access_type = SecretAccessType.READ
            elif action in _SECRET_WRITE_ACTIONS:
                access_type = SecretAccessType.WRITE
            elif action in _SECRET_DELETE_ACTIONS:
                access_type = SecretAccessType.DELETE
            elif action in _SECRET_ROTATE_ACTIONS:
                access_type = SecretAccessType.ROTATE

            if access_type is not None:
                if action.startswith("secretsmanager:"):
                    source_service = "secretsmanager"
                elif action.startswith("ssm:"):
                    source_service = "ssm"

                key = (resource, access_type.value)
                if key not in seen:
                    seen.add(key)
                    secrets.append(
                        SecretAccess(
                            secret_arn=resource,
                            access_type=access_type,
                            source_service=source_service,
                        )
                    )

        logger.debug("Enumerated %d secret access entries", len(secrets))
        return secrets

    def _enumerate_external_endpoints(
        self, permissions: list[EffectivePermission]
    ) -> list[ExternalEndpoint]:
        """
        Enumerate all external endpoints the agent can reach.

        Args:
            permissions: List of ALLOWED effective permissions.

        Returns:
            List of ExternalEndpoint entries.
        """
        endpoint_map: dict[tuple[EndpointType, str], set[str]] = {}

        for perm in permissions:
            action = perm.action
            resource = perm.resource

            if action in _ENDPOINT_ACTIONS:
                ep_type = _ENDPOINT_ACTIONS[action]
                key = (ep_type, resource)
                if key not in endpoint_map:
                    endpoint_map[key] = set()
                endpoint_map[key].add(action)

        endpoints: list[ExternalEndpoint] = []
        for (ep_type, resource), actions in endpoint_map.items():
            endpoints.append(
                ExternalEndpoint(
                    endpoint_type=ep_type,
                    resource=resource,
                    actions=sorted(actions),
                )
            )

        logger.debug("Enumerated %d external endpoints", len(endpoints))
        return endpoints

    def _enumerate_roles(
        self, permissions: list[EffectivePermission]
    ) -> list[RoleAccess]:
        """
        Enumerate all IAM roles that can be assumed or passed.

        Args:
            permissions: List of ALLOWED effective permissions.

        Returns:
            List of RoleAccess entries.
        """
        roles: list[RoleAccess] = []
        seen: set[tuple[str, str]] = set()

        for perm in permissions:
            action = perm.action
            resource = perm.resource

            access_type: RoleAccessType | None = None
            if action in _ROLE_ASSUME_ACTIONS:
                access_type = RoleAccessType.ASSUME
            elif action in _ROLE_PASS_ACTIONS:
                access_type = RoleAccessType.PASS

            if access_type is not None:
                key = (resource, access_type.value)
                if key not in seen:
                    seen.add(key)
                    roles.append(
                        RoleAccess(
                            role_arn=resource,
                            access_type=access_type,
                        )
                    )

        logger.debug("Enumerated %d role access entries", len(roles))
        return roles

    def _build_capability_graph(
        self,
        agent_id: str,
        services: list[str],
        apis: list[str],
        data_stores: list[DataStoreAccess],
        secrets: list[SecretAccess],
        external_endpoints: list[ExternalEndpoint],
        roles: list[RoleAccess],
        permissions: list[EffectivePermission],
    ) -> AgentCapabilityGraph:
        """
        Build the full capability graph with edges connecting all nodes.

        Args:
            agent_id: The agent identifier.
            services: Enumerated services.
            apis: Enumerated APIs.
            data_stores: Enumerated data stores.
            secrets: Enumerated secrets.
            external_endpoints: Enumerated endpoints.
            roles: Enumerated roles.
            permissions: All ALLOWED permissions.

        Returns:
            Complete AgentCapabilityGraph.
        """
        edges: list[CapabilityEdge] = []
        agent_node = f"agent:{agent_id}"

        # Edges from agent to services
        for service in services:
            service_perms = [
                p.action for p in permissions
                if p.action.startswith(f"{service}:") or p.action == "*"
            ]
            edges.append(
                CapabilityEdge(
                    source=agent_node,
                    target=f"service:{service}",
                    relationship=EdgeRelationship.ACCESSES,
                    permissions_required=service_perms[:10],
                )
            )

        # Edges from agent to data stores
        for ds in data_stores:
            if ds.access_level == AccessLevel.ADMIN:
                relationship = EdgeRelationship.MANAGES
            elif ds.access_level == AccessLevel.WRITE:
                relationship = EdgeRelationship.WRITES_TO
            else:
                relationship = EdgeRelationship.READS_FROM

            edges.append(
                CapabilityEdge(
                    source=agent_node,
                    target=f"datastore:{ds.store_type.value}:{ds.resource_arn}",
                    relationship=relationship,
                    permissions_required=ds.actions,
                )
            )

        # Edges from agent to secrets
        for secret in secrets:
            rel = (
                EdgeRelationship.READS_FROM
                if secret.access_type == SecretAccessType.READ
                else EdgeRelationship.WRITES_TO
            )
            edges.append(
                CapabilityEdge(
                    source=agent_node,
                    target=f"secret:{secret.secret_arn}",
                    relationship=rel,
                    permissions_required=[],
                )
            )

        # Edges from agent to external endpoints
        for ep in external_endpoints:
            edges.append(
                CapabilityEdge(
                    source=agent_node,
                    target=f"endpoint:{ep.endpoint_type.value}:{ep.resource}",
                    relationship=EdgeRelationship.INVOKES,
                    permissions_required=ep.actions,
                )
            )

        # Edges from agent to roles
        for role in roles:
            rel = (
                EdgeRelationship.ASSUMES
                if role.access_type == RoleAccessType.ASSUME
                else EdgeRelationship.PASSES
            )
            edges.append(
                CapabilityEdge(
                    source=agent_node,
                    target=f"role:{role.role_arn}",
                    relationship=rel,
                    permissions_required=[],
                )
            )

        return AgentCapabilityGraph(
            agent_id=agent_id,
            services=services,
            apis=apis,
            data_stores=data_stores,
            secrets=secrets,
            roles=roles,
            external_endpoints=external_endpoints,
            edges=edges,
        )

    def to_mermaid(self, graph: AgentCapabilityGraph) -> str:
        """
        Generate a Mermaid diagram from the capability graph.

        Args:
            graph: The AgentCapabilityGraph to visualize.

        Returns:
            Mermaid diagram as a string.
        """
        lines: list[str] = []
        lines.append("graph LR")
        lines.append(f'    Agent["{_sanitize_label(graph.agent_id)}"]')
        lines.append("")

        if graph.services:
            lines.append("    subgraph Services")
            for svc in graph.services:
                node_id = _safe_node_id(f"svc_{svc}")
                lines.append(f'        {node_id}["{svc}"]')
            lines.append("    end")
            lines.append("")

        if graph.data_stores:
            lines.append("    subgraph DataStores")
            for i, ds in enumerate(graph.data_stores):
                node_id = _safe_node_id(f"ds_{i}")
                label = f"{ds.store_type.value}: {_truncate_arn(ds.resource_arn)}"
                lines.append(f'        {node_id}[("{_sanitize_label(label)}")]')
            lines.append("    end")
            lines.append("")

        if graph.secrets:
            lines.append("    subgraph Secrets")
            for i, secret in enumerate(graph.secrets):
                node_id = _safe_node_id(f"secret_{i}")
                label = _truncate_arn(secret.secret_arn)
                lines.append(f'        {node_id}["{_sanitize_label(label)}"]')
            lines.append("    end")
            lines.append("")

        if graph.roles:
            lines.append("    subgraph Roles")
            for i, role in enumerate(graph.roles):
                node_id = _safe_node_id(f"role_{i}")
                label = _truncate_arn(role.role_arn)
                lines.append(f'        {node_id}[["{_sanitize_label(label)}"]]')
            lines.append("    end")
            lines.append("")

        if graph.external_endpoints:
            lines.append("    subgraph Endpoints")
            for i, ep in enumerate(graph.external_endpoints):
                node_id = _safe_node_id(f"ep_{i}")
                label = f"{ep.endpoint_type.value}: {_truncate_arn(ep.resource)}"
                lines.append(f'        {node_id}["{_sanitize_label(label)}"]')
            lines.append("    end")
            lines.append("")

        # Edges
        lines.append("    %% Edges")
        for edge in graph.edges:
            source_id = self._resolve_mermaid_node(edge.source, graph)
            target_id = self._resolve_mermaid_node(edge.target, graph)
            label = edge.relationship.value
            lines.append(f"    {source_id} -->|{label}| {target_id}")

        return "\n".join(lines)

    def to_dot(self, graph: AgentCapabilityGraph) -> str:
        """
        Generate a Graphviz DOT representation of the capability graph.

        Args:
            graph: The AgentCapabilityGraph to visualize.

        Returns:
            Graphviz DOT notation as a string.
        """
        lines: list[str] = []
        lines.append("digraph AgentCapabilities {")
        lines.append("    rankdir=LR;")
        lines.append("    node [shape=box, style=filled];")
        lines.append("")

        agent_node = _safe_node_id(graph.agent_id)
        lines.append(
            f'    {agent_node} [label="Agent: {_escape_dot(graph.agent_id)}", '
            f"fillcolor=lightblue];"
        )
        lines.append("")

        if graph.services:
            lines.append("    // Services")
            for svc in graph.services:
                node_id = _safe_node_id(f"svc_{svc}")
                lines.append(
                    f'    {node_id} [label="{svc}", fillcolor=lightyellow, shape=ellipse];'
                )
            lines.append("")

        if graph.data_stores:
            lines.append("    // Data Stores")
            for i, ds in enumerate(graph.data_stores):
                node_id = _safe_node_id(f"ds_{i}")
                label = f"{ds.store_type.value}\\n{_truncate_arn(ds.resource_arn)}"
                color = "lightgreen" if ds.access_level == AccessLevel.READ else "lightsalmon"
                lines.append(
                    f'    {node_id} [label="{_escape_dot(label)}", '
                    f"fillcolor={color}, shape=cylinder];"
                )
            lines.append("")

        if graph.secrets:
            lines.append("    // Secrets")
            for i, secret in enumerate(graph.secrets):
                node_id = _safe_node_id(f"secret_{i}")
                label = _truncate_arn(secret.secret_arn)
                lines.append(
                    f'    {node_id} [label="{_escape_dot(label)}", '
                    f"fillcolor=plum, shape=diamond];"
                )
            lines.append("")

        if graph.roles:
            lines.append("    // Roles")
            for i, role in enumerate(graph.roles):
                node_id = _safe_node_id(f"role_{i}")
                label = _truncate_arn(role.role_arn)
                lines.append(
                    f'    {node_id} [label="{_escape_dot(label)}", '
                    f"fillcolor=lightskyblue, shape=hexagon];"
                )
            lines.append("")

        if graph.external_endpoints:
            lines.append("    // External Endpoints")
            for i, ep in enumerate(graph.external_endpoints):
                node_id = _safe_node_id(f"ep_{i}")
                label = f"{ep.endpoint_type.value}\\n{_truncate_arn(ep.resource)}"
                lines.append(
                    f'    {node_id} [label="{_escape_dot(label)}", '
                    f"fillcolor=lightyellow, shape=pentagon];"
                )
            lines.append("")

        lines.append("    // Edges")
        for edge in graph.edges:
            source_id = self._resolve_dot_node(edge.source, graph)
            target_id = self._resolve_dot_node(edge.target, graph)
            label = edge.relationship.value
            lines.append(f'    {source_id} -> {target_id} [label="{label}"];')

        lines.append("}")
        return "\n".join(lines)

    # -----------------------------------------------------------------------
    # Private Helpers
    # -----------------------------------------------------------------------

    def _determine_access_level(self, actions: set[str]) -> AccessLevel:
        """Determine the highest access level from a set of actions."""
        for action in actions:
            if action in _DATA_STORE_ADMIN_ACTIONS:
                return AccessLevel.ADMIN
            if action == "*" or action.endswith(":*"):
                return AccessLevel.ADMIN

        for action in actions:
            if action in _DATA_STORE_WRITE_ACTIONS:
                return AccessLevel.WRITE

        return AccessLevel.READ

    def _resolve_mermaid_node(self, node_ref: str, graph: AgentCapabilityGraph) -> str:
        """Resolve a node reference to a Mermaid node ID."""
        if node_ref.startswith("agent:"):
            return "Agent"
        if node_ref.startswith("service:"):
            svc = node_ref.split(":", 1)[1]
            return _safe_node_id(f"svc_{svc}")
        if node_ref.startswith("datastore:"):
            parts = node_ref.split(":", 2)
            for i, ds in enumerate(graph.data_stores):
                if ds.store_type.value == parts[1] and ds.resource_arn == parts[2]:
                    return _safe_node_id(f"ds_{i}")
            return _safe_node_id("ds_unknown")
        if node_ref.startswith("secret:"):
            arn = node_ref.split(":", 1)[1]
            for i, s in enumerate(graph.secrets):
                if s.secret_arn == arn:
                    return _safe_node_id(f"secret_{i}")
            return _safe_node_id("secret_unknown")
        if node_ref.startswith("endpoint:"):
            parts = node_ref.split(":", 2)
            for i, ep in enumerate(graph.external_endpoints):
                if ep.endpoint_type.value == parts[1] and ep.resource == parts[2]:
                    return _safe_node_id(f"ep_{i}")
            return _safe_node_id("ep_unknown")
        if node_ref.startswith("role:"):
            arn = node_ref.split(":", 1)[1]
            for i, r in enumerate(graph.roles):
                if r.role_arn == arn:
                    return _safe_node_id(f"role_{i}")
            return _safe_node_id("role_unknown")
        return _safe_node_id(node_ref)

    def _resolve_dot_node(self, node_ref: str, graph: AgentCapabilityGraph) -> str:
        """Resolve a node reference to a DOT node ID."""
        if node_ref.startswith("agent:"):
            return _safe_node_id(graph.agent_id)
        if node_ref.startswith("service:"):
            svc = node_ref.split(":", 1)[1]
            return _safe_node_id(f"svc_{svc}")
        if node_ref.startswith("datastore:"):
            parts = node_ref.split(":", 2)
            for i, ds in enumerate(graph.data_stores):
                if ds.store_type.value == parts[1] and ds.resource_arn == parts[2]:
                    return _safe_node_id(f"ds_{i}")
            return _safe_node_id("ds_unknown")
        if node_ref.startswith("secret:"):
            arn = node_ref.split(":", 1)[1]
            for i, s in enumerate(graph.secrets):
                if s.secret_arn == arn:
                    return _safe_node_id(f"secret_{i}")
            return _safe_node_id("secret_unknown")
        if node_ref.startswith("endpoint:"):
            parts = node_ref.split(":", 2)
            for i, ep in enumerate(graph.external_endpoints):
                if ep.endpoint_type.value == parts[1] and ep.resource == parts[2]:
                    return _safe_node_id(f"ep_{i}")
            return _safe_node_id("ep_unknown")
        if node_ref.startswith("role:"):
            arn = node_ref.split(":", 1)[1]
            for i, r in enumerate(graph.roles):
                if r.role_arn == arn:
                    return _safe_node_id(f"role_{i}")
            return _safe_node_id("role_unknown")
        return _safe_node_id(node_ref)


# ---------------------------------------------------------------------------
# Module-level Helpers
# ---------------------------------------------------------------------------


def _safe_node_id(raw: str) -> str:
    """Create a valid node ID from a raw string."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", raw)


def _sanitize_label(text: str) -> str:
    """Sanitize text for use inside diagram labels."""
    return text.replace('"', "'").replace("\n", " ")


def _escape_dot(text: str) -> str:
    """Escape text for use inside DOT labels."""
    return text.replace('"', '\\"').replace("\n", "\\n")


def _truncate_arn(arn: str, max_len: int = 50) -> str:
    """Truncate an ARN for display, keeping the meaningful suffix."""
    if len(arn) <= max_len:
        return arn
    parts = arn.split(":")
    if len(parts) > 1:
        suffix = parts[-1]
        if len(suffix) > max_len - 4:
            return f"...{suffix[-(max_len - 4):]}"
        return f"...:{suffix}"
    return f"...{arn[-(max_len - 3):]}"
