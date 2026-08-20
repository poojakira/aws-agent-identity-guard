"""Developer-facing Python SDK for Agent Identity Guard.

Provides synchronous and asynchronous clients for AI agent authorization,
governance, risk scoring, and policy management.
"""

from __future__ import annotations

import asyncio
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AgentGuardError(Exception):
    """Base exception for all Agent Identity Guard errors."""

    def __init__(self, message: str, status_code: Optional[int] = None, response_body: Optional[dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class AuthorizationError(AgentGuardError):
    """Raised when an authorization request is explicitly denied or malformed."""


class ConnectionError(AgentGuardError):  # noqa: A001  -  intentional shadow of builtin
    """Raised when the SDK cannot reach the Agent Identity Guard service."""


class TimeoutError(AgentGuardError):  # noqa: A001  -  intentional shadow of builtin
    """Raised when a request exceeds the configured timeout."""


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    """Authorization decision returned by the guard service.

    Attributes:
        allowed: Whether the action is permitted.
        denied: Whether the action is explicitly denied.
        step_up_required: Whether additional authentication/approval is needed.
        risk_score: Numeric risk score (0-100).
        reasons: List of human-readable reasons for the decision.
        explanation: Detailed explanation of the decision logic.
        correlation_id: Unique identifier for tracing this decision.
    """

    allowed: bool
    denied: bool
    step_up_required: bool
    risk_score: int
    reasons: list[str]
    explanation: str
    correlation_id: str


@dataclass
class Agent:
    """Registered agent representation.

    Attributes:
        agent_id: Unique identifier of the agent.
        name: Human-readable name.
        permissions: List of granted permissions.
        environment: Deployment environment.
        metadata: Additional metadata.
    """

    agent_id: str
    name: str
    permissions: list[str] = field(default_factory=list)
    environment: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RiskScore:
    """Risk score result for an agent.

    Attributes:
        agent_id: The agent evaluated.
        score: Numeric risk score (0-100).
        factors: Contributing risk factors.
    """

    agent_id: str
    score: int
    factors: list[str]


@dataclass(frozen=True)
class AttackPath:
    """An identified attack path for an agent.

    Attributes:
        path_id: Unique path identifier.
        description: Human-readable description.
        severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL).
        steps: Ordered list of steps in the attack path.
    """

    path_id: str
    description: str
    severity: str
    steps: list[str]


@dataclass(frozen=True)
class PolicyScanResult:
    """Result of a policy document scan.

    Attributes:
        compliant: Whether the policy is compliant.
        findings: List of findings/issues.
        recommendations: List of recommended changes.
    """

    compliant: bool
    findings: list[str]
    recommendations: list[str]


@dataclass(frozen=True)
class ApprovalRequest:
    """An approval request for a privileged action.

    Attributes:
        request_id: Unique request identifier.
        status: Current status (PENDING, APPROVED, DENIED, EXPIRED).
        agent: The requesting agent.
        action: The action being requested.
        resource: The target resource.
    """

    request_id: str
    status: str
    agent: str
    action: str
    resource: str


# ---------------------------------------------------------------------------
# Retry / Backoff Helpers
# ---------------------------------------------------------------------------

_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BACKOFF_BASE = 0.5
_DEFAULT_BACKOFF_MAX = 10.0
_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


def _should_retry(status_code: int) -> bool:
    return status_code in _RETRYABLE_STATUS_CODES


def _backoff_delay(attempt: int, base: float = _DEFAULT_BACKOFF_BASE, maximum: float = _DEFAULT_BACKOFF_MAX) -> float:
    """Compute exponential backoff with full jitter."""
    delay = min(base * (2 ** attempt), maximum)
    return random.uniform(0, delay)  # noqa: S311


# ---------------------------------------------------------------------------
# Synchronous Client
# ---------------------------------------------------------------------------


class AgentIdentityGuard:
    """Synchronous client for the Agent Identity Guard service.

    Example:
        ```python
        guard = AgentIdentityGuard(
            endpoint='http://localhost:8080',
            api_key='my-api-key',
            environment='production',
            timeout=5.0,
        )
        decision = guard.authorize(
            agent='invoice-agent',
            tool='s3:GetObject',
            resource='arn:aws:s3:::invoices-prod/123.pdf',
            principal='user:jane@company.com',
        )
        if decision.allowed:
            print("Access granted")
        ```

    Args:
        endpoint: Base URL of the Agent Identity Guard service.
        api_key: API key for authentication.
        environment: Deployment environment label (e.g. 'production', 'staging').
        timeout: Request timeout in seconds.
        max_retries: Maximum number of retry attempts for transient failures.
    """

    def __init__(
        self,
        endpoint: str = "http://localhost:8080",
        api_key: str = "",
        environment: str = "production",
        timeout: float = 5.0,
        max_retries: int = _DEFAULT_MAX_RETRIES,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._environment = environment
        self._timeout = timeout
        self._max_retries = max_retries

        # Connection-pooled HTTP client
        self._client = httpx.Client(
            base_url=self._endpoint,
            timeout=httpx.Timeout(timeout),
            headers=self._default_headers(),
            limits=httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20,
                keepalive_expiry=30.0,
            ),
        )

    def _default_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": "agent-identity-guard-python/0.1.0",
            "X-Environment": self._environment,
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    # ------------------------------------------------------------------
    # Internal request helper with retry
    # ------------------------------------------------------------------

    def _request(self, method: str, path: str, *, json: Optional[dict[str, Any]] = None, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Execute an HTTP request with retry and exponential backoff.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE).
            path: URL path relative to the endpoint.
            json: JSON body payload.
            params: Query parameters.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            ConnectionError: If the service is unreachable.
            TimeoutError: If the request times out.
            AuthorizationError: If the request is unauthorized (401/403).
            AgentGuardError: For other HTTP errors.
        """
        last_exception: Optional[Exception] = None

        for attempt in range(self._max_retries + 1):
            try:
                response = self._client.request(method, path, json=json, params=params)

                if response.status_code < 400:
                    return response.json()

                # Non-retryable client errors
                if response.status_code in {401, 403}:
                    raise AuthorizationError(
                        f"Authorization failed: {response.status_code}",
                        status_code=response.status_code,
                        response_body=response.json() if response.content else None,
                    )

                if _should_retry(response.status_code) and attempt < self._max_retries:
                    time.sleep(_backoff_delay(attempt))
                    continue

                raise AgentGuardError(
                    f"Request failed with status {response.status_code}: {response.text}",
                    status_code=response.status_code,
                    response_body=response.json() if response.content else None,
                )

            except httpx.ConnectError as exc:
                last_exception = exc
                if attempt < self._max_retries:
                    time.sleep(_backoff_delay(attempt))
                    continue
                raise ConnectionError(f"Unable to connect to {self._endpoint}: {exc}") from exc

            except httpx.TimeoutException as exc:
                last_exception = exc
                if attempt < self._max_retries:
                    time.sleep(_backoff_delay(attempt))
                    continue
                raise TimeoutError(f"Request timed out after {self._timeout}s: {exc}") from exc

            except (AuthorizationError, AgentGuardError):
                raise

            except Exception as exc:  # noqa: BLE001
                last_exception = exc
                if attempt < self._max_retries:
                    time.sleep(_backoff_delay(attempt))
                    continue
                raise AgentGuardError(f"Unexpected error: {exc}") from exc

        # Should not reach here, but satisfy type checker
        raise AgentGuardError(f"Request failed after {self._max_retries} retries") from last_exception

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def authorize(
        self,
        agent: str,
        tool: str,
        resource: str,
        principal: str = "",
        data_classification: str = "",
        context: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Request an authorization decision for an agent action.

        Args:
            agent: Identifier of the agent requesting access.
            tool: The tool or action being invoked (e.g. 's3:GetObject').
            resource: The target resource ARN or identifier.
            principal: The principal on whose behalf the agent acts.
            data_classification: Classification level of the data (e.g. 'CONFIDENTIAL').
            context: Additional context key-value pairs for policy evaluation.

        Returns:
            A Decision object with the authorization result.

        Raises:
            AuthorizationError: On authorization-specific failures.
            ConnectionError: If the service is unreachable.
            TimeoutError: If the request exceeds the timeout.
        """
        payload: dict[str, Any] = {
            "agent": agent,
            "tool": tool,
            "resource": resource,
            "principal": principal,
            "data_classification": data_classification,
            "context": context or {},
            "correlation_id": str(uuid.uuid4()),
        }

        data = self._request("POST", "/v1/authorize", json=payload)

        return Decision(
            allowed=data.get("allowed", False),
            denied=data.get("denied", False),
            step_up_required=data.get("step_up_required", False),
            risk_score=data.get("risk_score", 0),
            reasons=data.get("reasons", []),
            explanation=data.get("explanation", ""),
            correlation_id=data.get("correlation_id", payload["correlation_id"]),
        )

    def register_agent(
        self,
        name: str,
        permissions: Optional[list[str]] = None,
        environment: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Agent:
        """Register a new agent with the guard service.

        Args:
            name: Human-readable agent name.
            permissions: List of permissions to grant.
            environment: Deployment environment override.
            metadata: Additional agent metadata.

        Returns:
            The newly registered Agent object.
        """
        payload: dict[str, Any] = {
            "name": name,
            "permissions": permissions or [],
            "environment": environment or self._environment,
            "metadata": metadata or {},
        }

        data = self._request("POST", "/v1/agents", json=payload)

        return Agent(
            agent_id=data["agent_id"],
            name=data.get("name", name),
            permissions=data.get("permissions", []),
            environment=data.get("environment", ""),
            metadata=data.get("metadata", {}),
        )

    def get_agent(self, agent_id: str) -> Agent:
        """Retrieve details of a registered agent.

        Args:
            agent_id: Unique identifier of the agent.

        Returns:
            The Agent object.
        """
        data = self._request("GET", f"/v1/agents/{agent_id}")

        return Agent(
            agent_id=data["agent_id"],
            name=data.get("name", ""),
            permissions=data.get("permissions", []),
            environment=data.get("environment", ""),
            metadata=data.get("metadata", {}),
        )

    def list_agents(self, limit: int = 100, offset: int = 0) -> list[Agent]:
        """List all registered agents.

        Args:
            limit: Maximum number of agents to return.
            offset: Pagination offset.

        Returns:
            A list of Agent objects.
        """
        data = self._request("GET", "/v1/agents", params={"limit": limit, "offset": offset})

        agents: list[Agent] = []
        for item in data.get("agents", []):
            agents.append(
                Agent(
                    agent_id=item["agent_id"],
                    name=item.get("name", ""),
                    permissions=item.get("permissions", []),
                    environment=item.get("environment", ""),
                    metadata=item.get("metadata", {}),
                )
            )
        return agents

    def get_risk_score(self, agent_id: str) -> RiskScore:
        """Get the current risk score for an agent.

        Args:
            agent_id: Unique identifier of the agent.

        Returns:
            A RiskScore object with the score and contributing factors.
        """
        data = self._request("GET", f"/v1/agents/{agent_id}/risk")

        return RiskScore(
            agent_id=data.get("agent_id", agent_id),
            score=data.get("score", 0),
            factors=data.get("factors", []),
        )

    def get_attack_paths(self, agent_id: str) -> list[AttackPath]:
        """Identify potential attack paths for an agent.

        Args:
            agent_id: Unique identifier of the agent.

        Returns:
            A list of AttackPath objects describing potential attack vectors.
        """
        data = self._request("GET", f"/v1/agents/{agent_id}/attack-paths")

        paths: list[AttackPath] = []
        for item in data.get("attack_paths", []):
            paths.append(
                AttackPath(
                    path_id=item.get("path_id", ""),
                    description=item.get("description", ""),
                    severity=item.get("severity", "UNKNOWN"),
                    steps=item.get("steps", []),
                )
            )
        return paths

    def scan_policy(self, policy_document: dict[str, Any]) -> PolicyScanResult:
        """Scan a policy document for compliance and security issues.

        Args:
            policy_document: The IAM or custom policy document to analyze.

        Returns:
            A PolicyScanResult with compliance status and findings.
        """
        payload: dict[str, Any] = {"policy_document": policy_document}

        data = self._request("POST", "/v1/policies/scan", json=payload)

        return PolicyScanResult(
            compliant=data.get("compliant", False),
            findings=data.get("findings", []),
            recommendations=data.get("recommendations", []),
        )

    def request_approval(self, agent: str, action: str, resource: str) -> ApprovalRequest:
        """Submit a request for human approval of a privileged action.

        Args:
            agent: The agent requesting approval.
            action: The action requiring approval.
            resource: The target resource.

        Returns:
            An ApprovalRequest with the request status and ID.
        """
        payload: dict[str, Any] = {
            "agent": agent,
            "action": action,
            "resource": resource,
        }

        data = self._request("POST", "/v1/approvals", json=payload)

        return ApprovalRequest(
            request_id=data["request_id"],
            status=data.get("status", "PENDING"),
            agent=data.get("agent", agent),
            action=data.get("action", action),
            resource=data.get("resource", resource),
        )

    def check_approval(self, request_id: str) -> ApprovalRequest:
        """Check the status of a pending approval request.

        Args:
            request_id: The approval request identifier.

        Returns:
            An updated ApprovalRequest with current status.
        """
        data = self._request("GET", f"/v1/approvals/{request_id}")

        return ApprovalRequest(
            request_id=data.get("request_id", request_id),
            status=data.get("status", "UNKNOWN"),
            agent=data.get("agent", ""),
            action=data.get("action", ""),
            resource=data.get("resource", ""),
        )

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._client.close()

    def __enter__(self) -> "AgentIdentityGuard":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Asynchronous Client
# ---------------------------------------------------------------------------


class AsyncAgentIdentityGuard:
    """Asynchronous client for the Agent Identity Guard service.

    Provides the same API as AgentIdentityGuard but with async/await support,
    suitable for use in asyncio-based applications and frameworks.

    Example:
        ```python
        async with AsyncAgentIdentityGuard(
            endpoint='http://localhost:8080',
            api_key='my-api-key',
        ) as guard:
            decision = await guard.authorize(
                agent='invoice-agent',
                tool='s3:GetObject',
                resource='arn:aws:s3:::invoices-prod/123.pdf',
            )
        ```

    Args:
        endpoint: Base URL of the Agent Identity Guard service.
        api_key: API key for authentication.
        environment: Deployment environment label.
        timeout: Request timeout in seconds.
        max_retries: Maximum number of retry attempts for transient failures.
    """

    def __init__(
        self,
        endpoint: str = "http://localhost:8080",
        api_key: str = "",
        environment: str = "production",
        timeout: float = 5.0,
        max_retries: int = _DEFAULT_MAX_RETRIES,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._environment = environment
        self._timeout = timeout
        self._max_retries = max_retries

        # Connection-pooled async HTTP client
        self._client = httpx.AsyncClient(
            base_url=self._endpoint,
            timeout=httpx.Timeout(timeout),
            headers=self._default_headers(),
            limits=httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20,
                keepalive_expiry=30.0,
            ),
        )

    def _default_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": "agent-identity-guard-python/0.1.0",
            "X-Environment": self._environment,
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    # ------------------------------------------------------------------
    # Internal request helper with retry
    # ------------------------------------------------------------------

    async def _request(self, method: str, path: str, *, json: Optional[dict[str, Any]] = None, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Execute an async HTTP request with retry and exponential backoff.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE).
            path: URL path relative to the endpoint.
            json: JSON body payload.
            params: Query parameters.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            ConnectionError: If the service is unreachable.
            TimeoutError: If the request times out.
            AuthorizationError: If the request is unauthorized (401/403).
            AgentGuardError: For other HTTP errors.
        """
        last_exception: Optional[Exception] = None

        for attempt in range(self._max_retries + 1):
            try:
                response = await self._client.request(method, path, json=json, params=params)

                if response.status_code < 400:
                    return response.json()

                if response.status_code in {401, 403}:
                    raise AuthorizationError(
                        f"Authorization failed: {response.status_code}",
                        status_code=response.status_code,
                        response_body=response.json() if response.content else None,
                    )

                if _should_retry(response.status_code) and attempt < self._max_retries:
                    await asyncio.sleep(_backoff_delay(attempt))
                    continue

                raise AgentGuardError(
                    f"Request failed with status {response.status_code}: {response.text}",
                    status_code=response.status_code,
                    response_body=response.json() if response.content else None,
                )

            except httpx.ConnectError as exc:
                last_exception = exc
                if attempt < self._max_retries:
                    await asyncio.sleep(_backoff_delay(attempt))
                    continue
                raise ConnectionError(f"Unable to connect to {self._endpoint}: {exc}") from exc

            except httpx.TimeoutException as exc:
                last_exception = exc
                if attempt < self._max_retries:
                    await asyncio.sleep(_backoff_delay(attempt))
                    continue
                raise TimeoutError(f"Request timed out after {self._timeout}s: {exc}") from exc

            except (AuthorizationError, AgentGuardError):
                raise

            except Exception as exc:  # noqa: BLE001
                last_exception = exc
                if attempt < self._max_retries:
                    await asyncio.sleep(_backoff_delay(attempt))
                    continue
                raise AgentGuardError(f"Unexpected error: {exc}") from exc

        raise AgentGuardError(f"Request failed after {self._max_retries} retries") from last_exception

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def authorize(
        self,
        agent: str,
        tool: str,
        resource: str,
        principal: str = "",
        data_classification: str = "",
        context: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Request an authorization decision for an agent action.

        Args:
            agent: Identifier of the agent requesting access.
            tool: The tool or action being invoked (e.g. 's3:GetObject').
            resource: The target resource ARN or identifier.
            principal: The principal on whose behalf the agent acts.
            data_classification: Classification level of the data.
            context: Additional context key-value pairs for policy evaluation.

        Returns:
            A Decision object with the authorization result.
        """
        payload: dict[str, Any] = {
            "agent": agent,
            "tool": tool,
            "resource": resource,
            "principal": principal,
            "data_classification": data_classification,
            "context": context or {},
            "correlation_id": str(uuid.uuid4()),
        }

        data = await self._request("POST", "/v1/authorize", json=payload)

        return Decision(
            allowed=data.get("allowed", False),
            denied=data.get("denied", False),
            step_up_required=data.get("step_up_required", False),
            risk_score=data.get("risk_score", 0),
            reasons=data.get("reasons", []),
            explanation=data.get("explanation", ""),
            correlation_id=data.get("correlation_id", payload["correlation_id"]),
        )

    async def register_agent(
        self,
        name: str,
        permissions: Optional[list[str]] = None,
        environment: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Agent:
        """Register a new agent with the guard service.

        Args:
            name: Human-readable agent name.
            permissions: List of permissions to grant.
            environment: Deployment environment override.
            metadata: Additional agent metadata.

        Returns:
            The newly registered Agent object.
        """
        payload: dict[str, Any] = {
            "name": name,
            "permissions": permissions or [],
            "environment": environment or self._environment,
            "metadata": metadata or {},
        }

        data = await self._request("POST", "/v1/agents", json=payload)

        return Agent(
            agent_id=data["agent_id"],
            name=data.get("name", name),
            permissions=data.get("permissions", []),
            environment=data.get("environment", ""),
            metadata=data.get("metadata", {}),
        )

    async def get_agent(self, agent_id: str) -> Agent:
        """Retrieve details of a registered agent.

        Args:
            agent_id: Unique identifier of the agent.

        Returns:
            The Agent object.
        """
        data = await self._request("GET", f"/v1/agents/{agent_id}")

        return Agent(
            agent_id=data["agent_id"],
            name=data.get("name", ""),
            permissions=data.get("permissions", []),
            environment=data.get("environment", ""),
            metadata=data.get("metadata", {}),
        )

    async def list_agents(self, limit: int = 100, offset: int = 0) -> list[Agent]:
        """List all registered agents.

        Args:
            limit: Maximum number of agents to return.
            offset: Pagination offset.

        Returns:
            A list of Agent objects.
        """
        data = await self._request("GET", "/v1/agents", params={"limit": limit, "offset": offset})

        agents: list[Agent] = []
        for item in data.get("agents", []):
            agents.append(
                Agent(
                    agent_id=item["agent_id"],
                    name=item.get("name", ""),
                    permissions=item.get("permissions", []),
                    environment=item.get("environment", ""),
                    metadata=item.get("metadata", {}),
                )
            )
        return agents

    async def get_risk_score(self, agent_id: str) -> RiskScore:
        """Get the current risk score for an agent.

        Args:
            agent_id: Unique identifier of the agent.

        Returns:
            A RiskScore object with the score and contributing factors.
        """
        data = await self._request("GET", f"/v1/agents/{agent_id}/risk")

        return RiskScore(
            agent_id=data.get("agent_id", agent_id),
            score=data.get("score", 0),
            factors=data.get("factors", []),
        )

    async def get_attack_paths(self, agent_id: str) -> list[AttackPath]:
        """Identify potential attack paths for an agent.

        Args:
            agent_id: Unique identifier of the agent.

        Returns:
            A list of AttackPath objects describing potential attack vectors.
        """
        data = await self._request("GET", f"/v1/agents/{agent_id}/attack-paths")

        paths: list[AttackPath] = []
        for item in data.get("attack_paths", []):
            paths.append(
                AttackPath(
                    path_id=item.get("path_id", ""),
                    description=item.get("description", ""),
                    severity=item.get("severity", "UNKNOWN"),
                    steps=item.get("steps", []),
                )
            )
        return paths

    async def scan_policy(self, policy_document: dict[str, Any]) -> PolicyScanResult:
        """Scan a policy document for compliance and security issues.

        Args:
            policy_document: The IAM or custom policy document to analyze.

        Returns:
            A PolicyScanResult with compliance status and findings.
        """
        payload: dict[str, Any] = {"policy_document": policy_document}

        data = await self._request("POST", "/v1/policies/scan", json=payload)

        return PolicyScanResult(
            compliant=data.get("compliant", False),
            findings=data.get("findings", []),
            recommendations=data.get("recommendations", []),
        )

    async def request_approval(self, agent: str, action: str, resource: str) -> ApprovalRequest:
        """Submit a request for human approval of a privileged action.

        Args:
            agent: The agent requesting approval.
            action: The action requiring approval.
            resource: The target resource.

        Returns:
            An ApprovalRequest with the request status and ID.
        """
        payload: dict[str, Any] = {
            "agent": agent,
            "action": action,
            "resource": resource,
        }

        data = await self._request("POST", "/v1/approvals", json=payload)

        return ApprovalRequest(
            request_id=data["request_id"],
            status=data.get("status", "PENDING"),
            agent=data.get("agent", agent),
            action=data.get("action", action),
            resource=data.get("resource", resource),
        )

    async def check_approval(self, request_id: str) -> ApprovalRequest:
        """Check the status of a pending approval request.

        Args:
            request_id: The approval request identifier.

        Returns:
            An updated ApprovalRequest with current status.
        """
        data = await self._request("GET", f"/v1/approvals/{request_id}")

        return ApprovalRequest(
            request_id=data.get("request_id", request_id),
            status=data.get("status", "UNKNOWN"),
            agent=data.get("agent", ""),
            action=data.get("action", ""),
            resource=data.get("resource", ""),
        )

    async def close(self) -> None:
        """Close the underlying async HTTP connection pool."""
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncAgentIdentityGuard":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
