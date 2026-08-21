"""
AWS Agent Identity Guard SDK.

Production-grade Python SDK for runtime authorization of AI agents.
Provides thread-safe authorization checks, agent registration,
risk scoring, and attack path analysis.
"""

from __future__ import annotations

import functools
import logging
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

import requests
import requests.adapters

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    """Authorization decision returned by the guard service."""

    decision: str
    risk_score: int
    reasons: list[str]
    policy: str
    explanation: str
    correlation_id: str


@dataclass(frozen=True)
class AgentInfo:
    """Registered agent metadata."""

    agent_id: str
    name: str
    agent_type: str
    owner: str
    environment: str
    purpose: str
    iam_role_arn: str
    declared_capabilities: list[str]
    data_classification: str
    created_at: str = ""
    updated_at: str = ""
    status: str = "active"


@dataclass(frozen=True)
class PermissionInfo:
    """Permission granted to an agent."""

    permission_id: str
    agent_id: str
    action: str
    resource: str
    effect: str
    conditions: dict = field(default_factory=dict)
    granted_at: str = ""
    expires_at: str = ""


@dataclass(frozen=True)
class AttackPathInfo:
    """Attack path analysis result for an agent."""

    path_id: str
    agent_id: str
    severity: str
    description: str
    steps: list[str]
    mitigations: list[str]
    risk_score: int = 0
    exploitability: str = "LOW"


@dataclass(frozen=True)
class RiskScoreInfo:
    """Risk score details for an agent."""

    agent_id: str
    overall_score: int
    permission_score: int
    network_score: int
    data_score: int
    behavior_score: int
    factors: list[str]
    recommendation: str
    last_assessed: str = ""


@dataclass(frozen=True)
class ApprovalInfo:
    """Approval request status."""

    request_id: str
    agent_id: str
    action: str
    resource: str
    status: str
    approver: str = ""
    decided_at: str = ""
    expires_at: str = ""
    reason: str = ""


# ---------------------------------------------------------------------------
# Error hierarchy
# ---------------------------------------------------------------------------


class GuardError(Exception):
    """Base exception for all SDK errors."""

    def __init__(self, message: str, status_code: int = 0, response_body: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class AuthorizationError(GuardError):
    """Raised when authorization is explicitly denied."""

    pass


class ConnectionError(GuardError):  # noqa: A001
    """Raised when the guard service is unreachable."""

    pass


class TimeoutError(GuardError):  # noqa: A001
    """Raised when a request to the guard service times out."""

    pass


# ---------------------------------------------------------------------------
# Transaction context manager helper
# ---------------------------------------------------------------------------


class _Transaction:
    """Context object for guard transactions."""

    def __init__(self, guard: AgentIdentityGuard, agent: str, action: str, resource: str):
        self._guard = guard
        self.agent = agent
        self.action = action
        self.resource = resource
        self.decision: Decision | None = None
        self.correlation_id: str = str(uuid.uuid4())

    @property
    def allowed(self) -> bool:
        return self.decision is not None and self.decision.decision == "ALLOW"


# ---------------------------------------------------------------------------
# Main SDK class
# ---------------------------------------------------------------------------


class AgentIdentityGuard:
    """
    Thread-safe SDK client for the AWS Agent Identity Guard service.

    Provides authorization decisions, agent lifecycle management,
    risk analysis, and approval workflows for AI agents operating
    within AWS environments.
    """

    _MAX_RETRIES = 3
    _BACKOFF_BASE = 0.5
    _BACKOFF_MAX = 10.0
    _POOL_CONNECTIONS = 10
    _POOL_MAX_SIZE = 20

    def __init__(
        self,
        endpoint: str = "http://localhost:8000",
        api_key: str | None = None,
        timeout: float = 5.0,
        fail_open: bool = False,
    ) -> None:
        """
        Initialize the guard client.

        Args:
            endpoint: Base URL of the Agent Identity Guard service.
            api_key: Optional API key for authentication.
            timeout: Request timeout in seconds.
            fail_open: If True, allow actions when the service is unreachable.
        """
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._fail_open = fail_open
        self._lock = threading.Lock()
        self._session = self._build_session()

    def _build_session(self) -> requests.Session:
        """Create a connection-pooled requests session with retry adapter."""
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=self._POOL_CONNECTIONS,
            pool_maxsize=self._POOL_MAX_SIZE,
            max_retries=0,  # We handle retries ourselves for finer control
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        if self._api_key:
            session.headers["Authorization"] = f"Bearer {self._api_key}"

        session.headers["User-Agent"] = "aws-agent-identity-guard-sdk/1.0.0"
        session.headers["Content-Type"] = "application/json"
        session.headers["Accept"] = "application/json"

        return session

    # ------------------------------------------------------------------
    # Internal request handling
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        json_body: dict | None = None,
        params: dict | None = None,
    ) -> dict:
        """
        Execute an HTTP request with exponential backoff retry logic.

        Thread-safe via the internal lock on session usage.
        """
        url = f"{self._endpoint}{path}"
        last_exception: Exception | None = None

        for attempt in range(self._MAX_RETRIES):
            try:
                with self._lock:
                    response = self._session.request(
                        method=method,
                        url=url,
                        json=json_body,
                        params=params,
                        timeout=self._timeout,
                    )

                if response.status_code == 401:
                    raise AuthorizationError(
                        "Authentication failed - invalid or missing API key",
                        status_code=401,
                        response_body=response.text,
                    )

                if response.status_code == 403:
                    raise AuthorizationError(
                        "Authorization denied by policy",
                        status_code=403,
                        response_body=response.text,
                    )

                if response.status_code >= 500:
                    raise GuardError(
                        f"Server error: {response.status_code}",
                        status_code=response.status_code,
                        response_body=response.text,
                    )

                if response.status_code >= 400:
                    raise GuardError(
                        f"Client error: {response.status_code} - {response.text}",
                        status_code=response.status_code,
                        response_body=response.text,
                    )

                return response.json()

            except requests.exceptions.Timeout:
                last_exception = TimeoutError(
                    f"Request timed out after {self._timeout}s (attempt {attempt + 1})"
                )
                logger.warning(
                    "Timeout on attempt %d/%d for %s %s",
                    attempt + 1,
                    self._MAX_RETRIES,
                    method,
                    path,
                )

            except requests.exceptions.ConnectionError as exc:
                last_exception = ConnectionError(
                    f"Failed to connect to guard service at {self._endpoint}: {exc}"
                )
                logger.warning(
                    "Connection error on attempt %d/%d for %s %s: %s",
                    attempt + 1,
                    self._MAX_RETRIES,
                    method,
                    path,
                    exc,
                )

            except (AuthorizationError, GuardError):
                raise

            except Exception as exc:
                last_exception = GuardError(f"Unexpected error: {exc}")
                logger.error("Unexpected error on %s %s: %s", method, path, exc)

            # Exponential backoff before next retry
            if attempt < self._MAX_RETRIES - 1:
                backoff = min(
                    self._BACKOFF_BASE * (2**attempt),
                    self._BACKOFF_MAX,
                )
                time.sleep(backoff)

        # All retries exhausted
        if last_exception is not None:
            raise last_exception
        raise GuardError("All retries exhausted with no specific error")

    def _safe_request(
        self,
        method: str,
        path: str,
        json_body: dict | None = None,
        params: dict | None = None,
        fail_open_default: dict | None = None,
    ) -> dict:
        """
        Request wrapper respecting fail_open semantics.

        If fail_open is True and the service is unreachable, returns
        the provided default instead of raising.
        """
        try:
            return self._request(method, path, json_body, params)
        except (ConnectionError, TimeoutError) as exc:
            if self._fail_open and fail_open_default is not None:
                logger.warning(
                    "Guard service unreachable, fail_open=True - returning default. Error: %s",
                    exc,
                )
                return fail_open_default
            raise

    # ------------------------------------------------------------------
    # Public API: Authorization
    # ------------------------------------------------------------------

    def authorize(
        self,
        agent: str,
        tool: str | None = None,
        action: str | None = None,
        resource: str | None = None,
        principal: str | None = None,
        data_classification: str | None = None,
        context: dict | None = None,
    ) -> Decision:
        """
        Request an authorization decision for an agent action.

        Args:
            agent: The agent identifier requesting authorization.
            tool: Optional tool the agent intends to use.
            action: The action being performed (e.g., s3:GetObject).
            resource: The target resource ARN or identifier.
            principal: The principal on whose behalf the agent acts.
            data_classification: Data sensitivity level.
            context: Additional context key-value pairs.

        Returns:
            Decision object with the authorization verdict.

        Raises:
            AuthorizationError: If the request is explicitly denied.
            ConnectionError: If the service is unreachable.
            TimeoutError: If the request times out.
        """
        payload: dict[str, Any] = {"agent": agent}
        if tool is not None:
            payload["tool"] = tool
        if action is not None:
            payload["action"] = action
        if resource is not None:
            payload["resource"] = resource
        if principal is not None:
            payload["principal"] = principal
        if data_classification is not None:
            payload["data_classification"] = data_classification
        if context is not None:
            payload["context"] = context

        fail_open_default = {
            "decision": "ALLOW",
            "risk_score": 0,
            "reasons": ["fail_open: guard service unreachable"],
            "policy": "fail_open",
            "explanation": "Authorization allowed due to fail_open configuration.",
            "correlation_id": str(uuid.uuid4()),
        }

        data = self._safe_request(
            "POST", "/api/v1/authorize", json_body=payload, fail_open_default=fail_open_default
        )

        return Decision(
            decision=data.get("decision", "DENY"),
            risk_score=data.get("risk_score", 0),
            reasons=data.get("reasons", []),
            policy=data.get("policy", ""),
            explanation=data.get("explanation", ""),
            correlation_id=data.get("correlation_id", ""),
        )

    # ------------------------------------------------------------------
    # Public API: Agent management
    # ------------------------------------------------------------------

    def register_agent(
        self,
        agent_id: str,
        name: str,
        agent_type: str,
        owner: str,
        environment: str,
        purpose: str,
        iam_role_arn: str,
        declared_capabilities: list | None = None,
        data_classification: str = "INTERNAL",
    ) -> AgentInfo:
        """
        Register a new agent with the identity guard service.

        Args:
            agent_id: Unique identifier for the agent.
            name: Human-readable name.
            agent_type: Type classification (e.g., 'autonomous', 'supervised').
            owner: Team or individual responsible for the agent.
            environment: Deployment environment (e.g., 'production', 'staging').
            purpose: Description of the agent's intended purpose.
            iam_role_arn: AWS IAM role ARN the agent operates under.
            declared_capabilities: List of capabilities the agent requires.
            data_classification: Data sensitivity level (default: INTERNAL).

        Returns:
            AgentInfo with the registered agent details.
        """
        payload = {
            "agent_id": agent_id,
            "name": name,
            "agent_type": agent_type,
            "owner": owner,
            "environment": environment,
            "purpose": purpose,
            "iam_role_arn": iam_role_arn,
            "declared_capabilities": declared_capabilities or [],
            "data_classification": data_classification,
        }

        data = self._request("POST", "/api/v1/agents", json_body=payload)

        return AgentInfo(
            agent_id=data.get("agent_id", agent_id),
            name=data.get("name", name),
            agent_type=data.get("agent_type", agent_type),
            owner=data.get("owner", owner),
            environment=data.get("environment", environment),
            purpose=data.get("purpose", purpose),
            iam_role_arn=data.get("iam_role_arn", iam_role_arn),
            declared_capabilities=data.get("declared_capabilities", []),
            data_classification=data.get("data_classification", data_classification),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            status=data.get("status", "active"),
        )

    def get_agent(self, agent_id: str) -> AgentInfo:
        """
        Retrieve agent details by ID.

        Args:
            agent_id: The agent's unique identifier.

        Returns:
            AgentInfo with current agent metadata.
        """
        data = self._request("GET", f"/api/v1/agents/{agent_id}")

        return AgentInfo(
            agent_id=data.get("agent_id", agent_id),
            name=data.get("name", ""),
            agent_type=data.get("agent_type", ""),
            owner=data.get("owner", ""),
            environment=data.get("environment", ""),
            purpose=data.get("purpose", ""),
            iam_role_arn=data.get("iam_role_arn", ""),
            declared_capabilities=data.get("declared_capabilities", []),
            data_classification=data.get("data_classification", ""),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            status=data.get("status", "active"),
        )

    def list_agents(self) -> list[AgentInfo]:
        """
        List all registered agents.

        Returns:
            List of AgentInfo objects.
        """
        data = self._request("GET", "/api/v1/agents")
        agents_data = data.get("agents", data) if isinstance(data, dict) else data

        results: list[AgentInfo] = []
        for item in agents_data:
            results.append(
                AgentInfo(
                    agent_id=item.get("agent_id", ""),
                    name=item.get("name", ""),
                    agent_type=item.get("agent_type", ""),
                    owner=item.get("owner", ""),
                    environment=item.get("environment", ""),
                    purpose=item.get("purpose", ""),
                    iam_role_arn=item.get("iam_role_arn", ""),
                    declared_capabilities=item.get("declared_capabilities", []),
                    data_classification=item.get("data_classification", ""),
                    created_at=item.get("created_at", ""),
                    updated_at=item.get("updated_at", ""),
                    status=item.get("status", "active"),
                )
            )
        return results

    # ------------------------------------------------------------------
    # Public API: Permissions and risk
    # ------------------------------------------------------------------

    def get_permissions(self, agent_id: str) -> list[PermissionInfo]:
        """
        Get all permissions assigned to an agent.

        Args:
            agent_id: The agent's unique identifier.

        Returns:
            List of PermissionInfo objects.
        """
        data = self._request("GET", f"/api/v1/agents/{agent_id}/permissions")
        perms_data = data.get("permissions", data) if isinstance(data, dict) else data

        results: list[PermissionInfo] = []
        for item in perms_data:
            results.append(
                PermissionInfo(
                    permission_id=item.get("permission_id", ""),
                    agent_id=item.get("agent_id", agent_id),
                    action=item.get("action", ""),
                    resource=item.get("resource", ""),
                    effect=item.get("effect", "ALLOW"),
                    conditions=item.get("conditions", {}),
                    granted_at=item.get("granted_at", ""),
                    expires_at=item.get("expires_at", ""),
                )
            )
        return results

    def get_attack_paths(self, agent_id: str) -> list[AttackPathInfo]:
        """
        Analyze potential attack paths for an agent.

        Args:
            agent_id: The agent's unique identifier.

        Returns:
            List of AttackPathInfo objects describing potential attack vectors.
        """
        data = self._request("GET", f"/api/v1/agents/{agent_id}/attack-paths")
        paths_data = data.get("attack_paths", data) if isinstance(data, dict) else data

        results: list[AttackPathInfo] = []
        for item in paths_data:
            results.append(
                AttackPathInfo(
                    path_id=item.get("path_id", ""),
                    agent_id=item.get("agent_id", agent_id),
                    severity=item.get("severity", "LOW"),
                    description=item.get("description", ""),
                    steps=item.get("steps", []),
                    mitigations=item.get("mitigations", []),
                    risk_score=item.get("risk_score", 0),
                    exploitability=item.get("exploitability", "LOW"),
                )
            )
        return results

    def get_risk_score(self, agent_id: str) -> RiskScoreInfo:
        """
        Get the composite risk score for an agent.

        Args:
            agent_id: The agent's unique identifier.

        Returns:
            RiskScoreInfo with detailed risk breakdown.
        """
        data = self._request("GET", f"/api/v1/agents/{agent_id}/risk-score")

        return RiskScoreInfo(
            agent_id=data.get("agent_id", agent_id),
            overall_score=data.get("overall_score", 0),
            permission_score=data.get("permission_score", 0),
            network_score=data.get("network_score", 0),
            data_score=data.get("data_score", 0),
            behavior_score=data.get("behavior_score", 0),
            factors=data.get("factors", []),
            recommendation=data.get("recommendation", ""),
            last_assessed=data.get("last_assessed", ""),
        )

    # ------------------------------------------------------------------
    # Public API: Approval workflow
    # ------------------------------------------------------------------

    def request_approval(self, agent_id: str, action: str, resource: str) -> ApprovalInfo:
        """
        Submit an approval request for a privileged action.

        Args:
            agent_id: The agent requesting approval.
            action: The action requiring approval.
            resource: The target resource.

        Returns:
            ApprovalInfo with the pending request details.
        """
        payload = {
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
        }

        data = self._request("POST", "/api/v1/approvals", json_body=payload)

        return ApprovalInfo(
            request_id=data.get("request_id", ""),
            agent_id=data.get("agent_id", agent_id),
            action=data.get("action", action),
            resource=data.get("resource", resource),
            status=data.get("status", "PENDING"),
            approver=data.get("approver", ""),
            decided_at=data.get("decided_at", ""),
            expires_at=data.get("expires_at", ""),
            reason=data.get("reason", ""),
        )

    def check_approval(self, request_id: str) -> ApprovalInfo:
        """
        Check the status of an approval request.

        Args:
            request_id: The approval request ID.

        Returns:
            ApprovalInfo with current status.
        """
        data = self._request("GET", f"/api/v1/approvals/{request_id}")

        return ApprovalInfo(
            request_id=data.get("request_id", request_id),
            agent_id=data.get("agent_id", ""),
            action=data.get("action", ""),
            resource=data.get("resource", ""),
            status=data.get("status", "PENDING"),
            approver=data.get("approver", ""),
            decided_at=data.get("decided_at", ""),
            expires_at=data.get("expires_at", ""),
            reason=data.get("reason", ""),
        )

    # ------------------------------------------------------------------
    # Decorator: @guard.protect(...)
    # ------------------------------------------------------------------

    def protect(
        self,
        agent: str,
        action: str | None = None,
        tool: str | None = None,
        resource: str | None = None,
        data_classification: str | None = None,
    ) -> Callable:
        """
        Decorator that enforces authorization before function execution.

        Usage:
            guard = AgentIdentityGuard()

            @guard.protect(agent='my-agent', action='s3:GetObject')
            def read_s3_object(bucket, key):
                ...

        Args:
            agent: The agent identity to authorize.
            action: The action being performed.
            tool: The tool being used.
            resource: The target resource.
            data_classification: Data sensitivity level.

        Returns:
            Decorated function that checks authorization first.
        """

        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                decision = self.authorize(
                    agent=agent,
                    action=action,
                    tool=tool,
                    resource=resource,
                    data_classification=data_classification,
                )

                if decision.decision != "ALLOW":
                    raise AuthorizationError(
                        f"Action denied for agent '{agent}': {decision.explanation}",
                        status_code=403,
                    )

                logger.debug(
                    "Authorization granted for agent=%s action=%s (correlation_id=%s)",
                    agent,
                    action,
                    decision.correlation_id,
                )
                return func(*args, **kwargs)

            return wrapper

        return decorator

    # ------------------------------------------------------------------
    # Context manager: guard.transaction(...)
    # ------------------------------------------------------------------

    @contextmanager
    def transaction(self, agent: str, action: str, resource: str):
        """
        Context manager for authorized transactions.

        Usage:
            with guard.transaction('my-agent', 's3:PutObject', 'arn:aws:s3:::bucket') as txn:
                if txn.allowed:
                    perform_action()

        Args:
            agent: The agent identity to authorize.
            action: The action being performed.
            resource: The target resource.

        Yields:
            _Transaction object with authorization state.
        """
        txn = _Transaction(self, agent, action, resource)

        try:
            txn.decision = self.authorize(agent=agent, action=action, resource=resource)
        except (ConnectionError, TimeoutError):
            if self._fail_open:
                txn.decision = Decision(
                    decision="ALLOW",
                    risk_score=0,
                    reasons=["fail_open: guard service unreachable"],
                    policy="fail_open",
                    explanation="Allowed due to fail_open and service unavailability.",
                    correlation_id=txn.correlation_id,
                )
            else:
                raise

        try:
            yield txn
        finally:
            logger.debug(
                "Transaction complete: agent=%s action=%s resource=%s"
                " decision=%s correlation_id=%s",
                agent,
                action,
                resource,
                txn.decision.decision if txn.decision else "NONE",
                txn.correlation_id,
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP session and release resources."""
        with self._lock:
            self._session.close()

    def __enter__(self) -> AgentIdentityGuard:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"AgentIdentityGuard(endpoint='{self._endpoint}', "
            f"timeout={self._timeout}, fail_open={self._fail_open})"
        )
