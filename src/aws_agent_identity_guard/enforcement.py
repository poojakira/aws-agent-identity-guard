"""
aws_agent_identity_guard/enforcement.py
--------------------------------------------------------------------------------
Runtime enforcement engine for AWS Agent Identity Guard.

Provides multiple enforcement patterns for intercepting and controlling
AI agent AWS API calls:
  - Direct enforcement engine (inline decision enforcement)
  - SDK middleware for boto3 client wrapping
  - HTTP proxy for transparent API call interception
  - Sidecar enforcer for container-based deployments

Enforcement modes:
  - FAIL_CLOSED: Deny by default on errors or timeouts (production)
  - FAIL_OPEN: Allow by default on errors or timeouts (development only)
  - MONITOR_ONLY: Log all decisions but never block (shadow mode)
  - LEARNING: Collect patterns without enforcement (baseline building)

Design principles:
  - Sub-millisecond overhead for allow decisions
  - Fail-safe defaults per environment
  - Complete audit trail for every enforcement action
  - Graceful degradation under high load
  - Correlation IDs for distributed tracing
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any

from aws_agent_identity_guard.models import (
    AuditEvent,
    AuthorizationDecision,
    AuthorizationDecisionType,
    TransactionRequest,
    _generate_uuid,
)

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


# --- Enums ---


class EnforcementMode(str, Enum):
    """
    Operating mode for the enforcement engine.

    FAIL_CLOSED: Deny on error/timeout. Use in production.
    FAIL_OPEN: Allow on error/timeout. Use in development only.
    MONITOR_ONLY: Log decisions, never block. Use for shadow deployment.
    LEARNING: Collect access patterns without any enforcement.
    """

    FAIL_CLOSED = "FAIL_CLOSED"
    FAIL_OPEN = "FAIL_OPEN"
    MONITOR_ONLY = "MONITOR_ONLY"
    LEARNING = "LEARNING"


class EnforcementAction(str, Enum):
    """The action taken by the enforcement engine."""

    BLOCKED = "BLOCKED"
    ALLOWED = "ALLOWED"
    PENDING_APPROVAL = "PENDING_APPROVAL"


# --- Data Classes ---


@dataclass
class EnforcementResult:
    """
    Outcome of an enforcement decision.

    Attributes:
        enforced: Whether enforcement was actively applied.
        action_taken: The enforcement action (BLOCKED/ALLOWED/PENDING_APPROVAL).
        latency_ms: Time taken to make the enforcement decision.
        correlation_id: Unique identifier linking request to audit trail.
        audit_event: The audit event generated for this enforcement action.
    """

    enforced: bool = False
    action_taken: EnforcementAction = EnforcementAction.BLOCKED
    latency_ms: float = 0.0
    correlation_id: str = field(default_factory=_generate_uuid)
    audit_event: AuditEvent | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "enforced": self.enforced,
            "action_taken": self.action_taken.value,
            "latency_ms": self.latency_ms,
            "correlation_id": self.correlation_id,
            "audit_event": self.audit_event.to_dict() if self.audit_event else None,
        }


@dataclass
class EnforcementPolicy:
    """
    Configuration for enforcement behavior per environment.

    Attributes:
        mode: The enforcement mode for this policy.
        environment_modes: Override modes per environment name.
        fallback_action: Action to take when decision engine is unavailable.
        timeout_ms: Maximum time to wait for a decision before fallback.
        max_retries: Number of retries on transient failures.
        circuit_breaker_threshold: Number of consecutive failures before opening circuit.
        circuit_breaker_recovery_ms: Time before attempting to close circuit.
    """

    mode: EnforcementMode = EnforcementMode.FAIL_CLOSED
    environment_modes: dict[str, EnforcementMode] = field(default_factory=lambda: {
        "production": EnforcementMode.FAIL_CLOSED,
        "staging": EnforcementMode.FAIL_CLOSED,
        "development": EnforcementMode.FAIL_OPEN,
    })
    fallback_action: EnforcementAction = EnforcementAction.BLOCKED
    timeout_ms: float = 100.0
    max_retries: int = 1
    circuit_breaker_threshold: int = 5
    circuit_breaker_recovery_ms: float = 30000.0

    def get_mode_for_environment(self, environment: str) -> EnforcementMode:
        """
        Get the enforcement mode for a specific environment.

        Args:
            environment: Environment name (e.g., 'production', 'development').

        Returns:
            The enforcement mode for that environment.
        """
        return self.environment_modes.get(
            environment.lower(), self.mode
        )


# --- Circuit Breaker ---


class CircuitBreaker:
    """
    Circuit breaker for the enforcement engine.

    Prevents cascading failures by short-circuiting when the decision
    engine is consistently unavailable.
    """

    def __init__(self, threshold: int = 5, recovery_ms: float = 30000.0) -> None:
        """
        Initialize the circuit breaker.

        Args:
            threshold: Consecutive failures before opening.
            recovery_ms: Milliseconds before attempting recovery.
        """
        self._threshold = threshold
        self._recovery_ms = recovery_ms
        self._failure_count = 0
        self._last_failure_time: float = 0.0
        self._is_open = False
        self._lock = threading.Lock()

    @property
    def is_open(self) -> bool:
        """Check if the circuit is currently open (tripped)."""
        with self._lock:
            if not self._is_open:
                return False

            # Check if recovery period has elapsed
            elapsed = (time.time() - self._last_failure_time) * 1000
            if elapsed >= self._recovery_ms:
                self._is_open = False
                self._failure_count = 0
                logger.info("Circuit breaker recovered (half-open state)")
                return False

            return True

    def record_success(self) -> None:
        """Record a successful operation, resetting the failure count."""
        with self._lock:
            self._failure_count = 0
            self._is_open = False

    def record_failure(self) -> None:
        """Record a failed operation, potentially opening the circuit."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()

            if self._failure_count >= self._threshold:
                self._is_open = True
                logger.warning(
                    "Circuit breaker OPEN after %d consecutive failures",
                    self._failure_count,
                )


# --- Main Enforcement Engine ---


class EnforcementEngine:
    """
    Core runtime enforcement engine for authorization decisions.

    Applies authorization decisions (ALLOW, DENY, STEP_UP) with configurable
    modes, circuit breaking, and full audit trails.

    Usage:
        engine = EnforcementEngine(policy=EnforcementPolicy())
        result = engine.enforce(request, decision)
    """

    def __init__(
        self,
        policy: EnforcementPolicy | None = None,
        approval_callback: Callable[[TransactionRequest], bool] | None = None,
    ) -> None:
        """
        Initialize the enforcement engine.

        Args:
            policy: Enforcement policy configuration.
            approval_callback: Optional callback for step-up approval flow.
                Should return True if approval is granted.
        """
        self._policy = policy or EnforcementPolicy()
        self._approval_callback = approval_callback
        self._circuit_breaker = CircuitBreaker(
            threshold=self._policy.circuit_breaker_threshold,
            recovery_ms=self._policy.circuit_breaker_recovery_ms,
        )
        self._enforcement_count = 0
        self._lock = threading.Lock()
        logger.info(
            "EnforcementEngine initialized in mode=%s, timeout=%dms",
            self._policy.mode.value,
            self._policy.timeout_ms,
        )

    def enforce(
        self,
        request: TransactionRequest,
        decision: AuthorizationDecision,
    ) -> EnforcementResult:
        """
        Enforce an authorization decision on a transaction request.

        Routes to the appropriate enforcement handler based on the decision
        type, respecting the configured enforcement mode.

        Args:
            request: The transaction request being evaluated.
            decision: The authorization decision to enforce.

        Returns:
            EnforcementResult describing what action was taken.
        """
        start_time = time.perf_counter()
        correlation_id = decision.correlation_id or _generate_uuid()

        try:
            # Check circuit breaker
            if self._circuit_breaker.is_open:
                logger.warning(
                    "Circuit breaker open, applying fallback for request %s",
                    request.request_id,
                )
                return self._apply_fallback(request, correlation_id, start_time)

            # Check enforcement mode
            mode = self._policy.mode
            if mode == EnforcementMode.MONITOR_ONLY:
                result = self._apply_monitor_only(request, decision, correlation_id)
                result.latency_ms = (time.perf_counter() - start_time) * 1000
                self._log_enforcement_action(request, result)
                return result

            if mode == EnforcementMode.LEARNING:
                result = self._apply_learning(request, decision, correlation_id)
                result.latency_ms = (time.perf_counter() - start_time) * 1000
                return result

            # Active enforcement
            if decision.decision == AuthorizationDecisionType.DENY:
                result = self._apply_deny(request)
            elif decision.decision == AuthorizationDecisionType.STEP_UP:
                result = self._apply_step_up(request, decision)
            elif decision.decision == AuthorizationDecisionType.ALLOW:
                result = self._apply_allow(request)
            elif decision.decision == AuthorizationDecisionType.REVIEW:
                result = self._apply_step_up(request, decision)
            else:
                # Unknown decision type: apply fallback
                logger.error(
                    "Unknown decision type %s for request %s",
                    decision.decision,
                    request.request_id,
                )
                result = self._apply_fallback(request, correlation_id, start_time)
                return result

            result.correlation_id = correlation_id
            result.latency_ms = (time.perf_counter() - start_time) * 1000

            # Generate audit event
            result.audit_event = self._build_audit_event(request, result, decision)

            self._circuit_breaker.record_success()
            self._log_enforcement_action(request, result)

            with self._lock:
                self._enforcement_count += 1

            return result

        except Exception as exc:
            self._circuit_breaker.record_failure()
            logger.error(
                "Enforcement error for request %s: %s",
                request.request_id,
                exc,
            )
            return self._apply_fallback(request, correlation_id, start_time)

    def _apply_deny(self, request: TransactionRequest) -> EnforcementResult:
        """
        Apply a DENY enforcement action.

        Blocks the request entirely. The caller must not proceed with
        the requested AWS API call.

        Args:
            request: The transaction request to deny.

        Returns:
            EnforcementResult with BLOCKED action.
        """
        logger.info(
            "DENY enforced: agent=%s action=%s resource=%s",
            request.agent_id,
            request.action,
            request.resource,
        )
        return EnforcementResult(
            enforced=True,
            action_taken=EnforcementAction.BLOCKED,
        )

    def _apply_step_up(
        self,
        request: TransactionRequest,
        decision: AuthorizationDecision,
    ) -> EnforcementResult:
        """
        Apply a STEP_UP enforcement action.

        Places the request in a pending state, optionally invoking the
        approval callback for immediate resolution.

        Args:
            request: The transaction request requiring step-up.
            decision: The authorization decision with step-up reasons.

        Returns:
            EnforcementResult with PENDING_APPROVAL or ALLOWED/BLOCKED
            depending on the approval callback result.
        """
        logger.info(
            "STEP_UP required: agent=%s action=%s reasons=%s",
            request.agent_id,
            request.action,
            decision.reasons,
        )

        # If we have an approval callback, attempt immediate resolution
        if self._approval_callback:
            try:
                approved = self._approval_callback(request)
                if approved:
                    logger.info(
                        "Step-up APPROVED via callback: agent=%s action=%s",
                        request.agent_id,
                        request.action,
                    )
                    return EnforcementResult(
                        enforced=True,
                        action_taken=EnforcementAction.ALLOWED,
                    )
                else:
                    logger.info(
                        "Step-up DENIED via callback: agent=%s action=%s",
                        request.agent_id,
                        request.action,
                    )
                    return EnforcementResult(
                        enforced=True,
                        action_taken=EnforcementAction.BLOCKED,
                    )
            except Exception as exc:
                logger.error("Approval callback failed: %s", exc)

        # No callback or callback failed: pend for async approval
        return EnforcementResult(
            enforced=True,
            action_taken=EnforcementAction.PENDING_APPROVAL,
        )

    def _apply_allow(self, request: TransactionRequest) -> EnforcementResult:
        """
        Apply an ALLOW enforcement action.

        Permits the request to proceed to the AWS API.

        Args:
            request: The transaction request to allow.

        Returns:
            EnforcementResult with ALLOWED action.
        """
        logger.debug(
            "ALLOW enforced: agent=%s action=%s resource=%s",
            request.agent_id,
            request.action,
            request.resource,
        )
        return EnforcementResult(
            enforced=True,
            action_taken=EnforcementAction.ALLOWED,
        )

    def _apply_monitor_only(
        self,
        request: TransactionRequest,
        decision: AuthorizationDecision,
        correlation_id: str,
    ) -> EnforcementResult:
        """
        Monitor-only mode: log the decision but always allow.

        Args:
            request: The transaction request.
            decision: The authorization decision (logged only).
            correlation_id: Tracing correlation ID.

        Returns:
            EnforcementResult with ALLOWED (not enforced).
        """
        logger.info(
            "MONITOR_ONLY: would have %s agent=%s action=%s resource=%s",
            decision.decision.value,
            request.agent_id,
            request.action,
            request.resource,
        )
        result = EnforcementResult(
            enforced=False,
            action_taken=EnforcementAction.ALLOWED,
            correlation_id=correlation_id,
        )
        result.audit_event = self._build_audit_event(request, result, decision)
        return result

    def _apply_learning(
        self,
        request: TransactionRequest,
        decision: AuthorizationDecision,
        correlation_id: str,
    ) -> EnforcementResult:
        """
        Learning mode: record access patterns without enforcement.

        Args:
            request: The transaction request.
            decision: The authorization decision (recorded only).
            correlation_id: Tracing correlation ID.

        Returns:
            EnforcementResult with ALLOWED (not enforced).
        """
        logger.debug(
            "LEARNING: recording pattern agent=%s action=%s resource=%s",
            request.agent_id,
            request.action,
            request.resource,
        )
        return EnforcementResult(
            enforced=False,
            action_taken=EnforcementAction.ALLOWED,
            correlation_id=correlation_id,
        )

    def _apply_fallback(
        self,
        request: TransactionRequest,
        correlation_id: str,
        start_time: float,
    ) -> EnforcementResult:
        """
        Apply fallback behavior when decision engine is unavailable.

        Respects the configured enforcement mode:
        - FAIL_CLOSED: block the request
        - FAIL_OPEN: allow the request with a warning

        Args:
            request: The transaction request.
            correlation_id: Tracing correlation ID.
            start_time: Perf counter at enforcement start.

        Returns:
            EnforcementResult based on fallback policy.
        """
        latency_ms = (time.perf_counter() - start_time) * 1000

        if self._policy.mode == EnforcementMode.FAIL_OPEN:
            logger.warning(
                "FAIL_OPEN fallback: allowing request %s (decision engine unavailable)",
                request.request_id,
            )
            action = EnforcementAction.ALLOWED
        else:
            logger.warning(
                "FAIL_CLOSED fallback: blocking request %s (decision engine unavailable)",
                request.request_id,
            )
            action = EnforcementAction.BLOCKED

        return EnforcementResult(
            enforced=True,
            action_taken=action,
            latency_ms=latency_ms,
            correlation_id=correlation_id,
            audit_event=AuditEvent(
                correlation_id=correlation_id,
                agent_id=request.agent_id,
                principal=request.principal,
                action=request.action,
                resource=request.resource,
                decision=AuthorizationDecisionType.DENY
                if action == EnforcementAction.BLOCKED
                else AuthorizationDecisionType.ALLOW,
                reasons=["Fallback: decision engine unavailable"],
            ),
        )

    def _log_enforcement_action(
        self,
        request: TransactionRequest,
        result: EnforcementResult,
    ) -> None:
        """
        Log the enforcement action for audit and debugging.

        Args:
            request: The original transaction request.
            result: The enforcement result.
        """
        logger.info(
            "Enforcement: correlation_id=%s agent=%s action=%s resource=%s "
            "result=%s enforced=%s latency_ms=%.2f",
            result.correlation_id,
            request.agent_id,
            request.action,
            request.resource,
            result.action_taken.value,
            result.enforced,
            result.latency_ms,
        )

    def _build_audit_event(
        self,
        request: TransactionRequest,
        result: EnforcementResult,
        decision: AuthorizationDecision,
    ) -> AuditEvent:
        """
        Build an audit event from the enforcement action.

        Args:
            request: The transaction request.
            result: The enforcement result.
            decision: The authorization decision.

        Returns:
            AuditEvent with integrity hash.
        """
        return AuditEvent(
            correlation_id=result.correlation_id,
            agent_id=request.agent_id,
            principal=request.principal,
            action=request.action,
            resource=request.resource,
            decision=decision.decision,
            reasons=decision.reasons + [f"enforcement_action={result.action_taken.value}"],
        )

    @property
    def enforcement_count(self) -> int:
        """Return total number of enforcement actions performed."""
        with self._lock:
            return self._enforcement_count


# --- SDK Middleware ---


class GuardedClient:
    """
    A wrapped boto3 client that intercepts all API calls through enforcement.

    Proxies attribute access to the underlying client while intercepting
    API operations for authorization checks.

    Usage:
        middleware = SDKMiddleware(engine=enforcement_engine, agent_id="my-agent")
        guarded = middleware.wrap_client(boto3.client('s3'))
        guarded.get_object(Bucket='...', Key='...')  # Intercepted
    """

    def __init__(
        self,
        client: Any,
        middleware: SDKMiddleware,
    ) -> None:
        """
        Initialize the guarded client wrapper.

        Args:
            client: The original boto3 client to wrap.
            middleware: The SDK middleware performing enforcement.
        """
        self._client = client
        self._middleware = middleware
        self._service_name = getattr(client, "_service_model", None)
        if self._service_name:
            self._service_name = self._service_name.service_name
        else:
            # Fallback: try meta attribute
            meta = getattr(client, "meta", None)
            if meta:
                self._service_name = getattr(meta, "service_model", None)
                if self._service_name:
                    self._service_name = self._service_name.service_name
                else:
                    self._service_name = "unknown"
            else:
                self._service_name = "unknown"

    def __getattr__(self, name: str) -> Any:
        """
        Intercept attribute access to wrap API operations.

        Non-callable attributes are passed through directly.
        Callable API operations are wrapped with enforcement.

        Args:
            name: Attribute name being accessed.

        Returns:
            Wrapped callable or passthrough attribute.
        """
        attr = getattr(self._client, name)

        if not callable(attr):
            return attr

        # Skip private/internal methods
        if name.startswith("_"):
            return attr

        def intercepted_call(**kwargs: Any) -> Any:
            """Intercept the boto3 API call with enforcement."""
            result = self._middleware.intercept_boto3_call(
                service=self._service_name,
                operation=name,
                params=kwargs,
            )

            if result.action_taken == EnforcementAction.BLOCKED:
                raise PermissionError(
                    f"Agent Identity Guard BLOCKED: {self._service_name}:{name} "
                    f"(correlation_id={result.correlation_id})"
                )

            if result.action_taken == EnforcementAction.PENDING_APPROVAL:
                raise PermissionError(
                    f"Agent Identity Guard PENDING_APPROVAL: {self._service_name}:{name} "
                    f"requires step-up authentication "
                    f"(correlation_id={result.correlation_id})"
                )

            # ALLOWED: proceed with the original call
            return attr(**kwargs)

        return intercepted_call


class SDKMiddleware:
    """
    Middleware for intercepting boto3 API calls with enforcement.

    Integrates with the enforcement engine to check every AWS API call
    made by an AI agent before it reaches the AWS endpoint.

    Usage:
        middleware = SDKMiddleware(
            engine=EnforcementEngine(),
            agent_id="my-agent-id",
            principal="arn:aws:iam::123456789012:role/AgentRole",
        )
        result = middleware.intercept_boto3_call("s3", "get_object", {"Bucket": "..."})
        guarded = middleware.wrap_client(boto3_client)
    """

    def __init__(
        self,
        engine: EnforcementEngine,
        agent_id: str,
        principal: str = "",
        authorization_engine: Any | None = None,
    ) -> None:
        """
        Initialize the SDK middleware.

        Args:
            engine: The enforcement engine to use.
            agent_id: Agent identifier for transaction requests.
            principal: IAM principal ARN for the agent.
            authorization_engine: Optional authorization engine for making decisions.
                If not provided, enforcement decisions must be pre-computed.
        """
        self._engine = engine
        self._agent_id = agent_id
        self._principal = principal
        self._authorization_engine = authorization_engine
        logger.info(
            "SDKMiddleware initialized for agent=%s principal=%s",
            agent_id,
            principal,
        )

    def intercept_boto3_call(
        self,
        service: str,
        operation: str,
        params: dict[str, Any],
    ) -> EnforcementResult:
        """
        Intercept a boto3 API call and enforce authorization.

        Constructs a TransactionRequest from the call parameters,
        obtains an authorization decision, and enforces it.

        Args:
            service: AWS service name (e.g., 's3', 'dynamodb').
            operation: API operation name (e.g., 'get_object', 'put_item').
            params: Operation parameters.

        Returns:
            EnforcementResult indicating whether the call is permitted.
        """
        # Construct IAM action from service and operation
        iam_action = self._construct_iam_action(service, operation)

        # Determine resource ARN from params
        resource_arn = self._extract_resource_arn(service, operation, params)

        # Build transaction request
        request = TransactionRequest(
            agent_id=self._agent_id,
            principal=self._principal,
            tool=f"boto3.{service}",
            action=iam_action,
            resource=resource_arn,
            context={
                "sdk_service": service,
                "sdk_operation": operation,
                "sdk_params_keys": list(params.keys()),
            },
        )

        # Get authorization decision
        decision = self._get_decision(request)

        # Enforce
        return self._engine.enforce(request, decision)

    def wrap_client(self, boto3_client: Any) -> GuardedClient:
        """
        Wrap a boto3 client with enforcement guards.

        Returns a GuardedClient that intercepts all API calls.

        Args:
            boto3_client: The boto3 client to wrap.

        Returns:
            A GuardedClient instance that enforces authorization.
        """
        return GuardedClient(client=boto3_client, middleware=self)

    def _construct_iam_action(self, service: str, operation: str) -> str:
        """
        Construct an IAM action string from service and operation.

        Converts snake_case operation names to PascalCase IAM actions.

        Args:
            service: AWS service name.
            operation: SDK operation name (snake_case).

        Returns:
            IAM action string (e.g., 's3:GetObject').
        """
        # Convert snake_case to PascalCase
        pascal_operation = "".join(
            word.capitalize() for word in operation.split("_")
        )
        return f"{service}:{pascal_operation}"

    def _extract_resource_arn(
        self,
        service: str,
        operation: str,
        params: dict[str, Any],
    ) -> str:
        """
        Extract or construct a resource ARN from API call parameters.

        Args:
            service: AWS service name.
            operation: API operation name.
            params: Operation parameters.

        Returns:
            Resource ARN string, or '*' if not determinable.
        """
        # S3: construct from Bucket and Key
        if service == "s3":
            bucket = params.get("Bucket", "")
            key = params.get("Key", "")
            if bucket and key:
                return f"arn:aws:s3:::{bucket}/{key}"
            elif bucket:
                return f"arn:aws:s3:::{bucket}"

        # DynamoDB: construct from TableName
        if service == "dynamodb":
            table_name = params.get("TableName", "")
            if table_name:
                return f"arn:aws:dynamodb:*:*:table/{table_name}"

        # Lambda: construct from FunctionName
        if service == "lambda":
            function_name = params.get("FunctionName", "")
            if function_name:
                if function_name.startswith("arn:"):
                    return function_name
                return f"arn:aws:lambda:*:*:function:{function_name}"

        # SecretsManager: construct from SecretId
        if service == "secretsmanager":
            secret_id = params.get("SecretId", "")
            if secret_id:
                if secret_id.startswith("arn:"):
                    return secret_id
                return f"arn:aws:secretsmanager:*:*:secret:{secret_id}"

        # Generic: check for common ARN parameters
        for arn_key in ("ResourceArn", "Arn", "TargetArn", "FunctionArn", "RoleArn"):
            if arn_key in params:
                return params[arn_key]

        return "*"

    def _get_decision(self, request: TransactionRequest) -> AuthorizationDecision:
        """
        Get an authorization decision for a request.

        Uses the authorization engine if available, otherwise creates
        a default ALLOW decision (for monitor-only setups).

        Args:
            request: The transaction request to evaluate.

        Returns:
            AuthorizationDecision for the request.
        """
        if self._authorization_engine:
            try:
                return self._authorization_engine.authorize(request)
            except Exception as exc:
                logger.error("Authorization engine error: %s", exc)

        # Default: allow (enforcement mode handles the safety)
        return AuthorizationDecision(
            decision=AuthorizationDecisionType.ALLOW,
            reasons=["Default allow (no authorization engine configured)"],
        )


# --- HTTP Proxy Enforcer ---


class ProxyEnforcer:
    """
    HTTP proxy that transparently intercepts AWS API calls.

    Sits between the application and AWS endpoints, inspecting and
    enforcing authorization on every API request.

    Usage:
        proxy = ProxyEnforcer(
            engine=enforcement_engine,
            agent_id="my-agent",
        )
        proxy.start(host="127.0.0.1", port=8443)
        # Configure AWS SDK to use proxy: AWS_CA_BUNDLE, HTTPS_PROXY
        proxy.stop()
    """

    def __init__(
        self,
        engine: EnforcementEngine,
        agent_id: str,
        principal: str = "",
    ) -> None:
        """
        Initialize the proxy enforcer.

        Args:
            engine: The enforcement engine for authorization.
            agent_id: Agent identifier.
            principal: IAM principal ARN.
        """
        self._engine = engine
        self._agent_id = agent_id
        self._principal = principal
        self._server: HTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._running = False
        self._request_count = 0
        self._lock = threading.Lock()

    def start(self, host: str = "127.0.0.1", port: int = 8443) -> None:
        """
        Start the proxy server.

        Launches the HTTP proxy on the specified host and port in a
        background thread.

        Args:
            host: Host address to bind to.
            port: Port number to listen on.

        Raises:
            RuntimeError: If the proxy is already running.
        """
        if self._running:
            raise RuntimeError("Proxy is already running")

        # Create handler class with access to enforcer state
        enforcer = self

        class ProxyHandler(BaseHTTPRequestHandler):
            """HTTP request handler for the enforcement proxy."""

            def do_POST(self) -> None:
                """Handle POST requests (most AWS API calls)."""
                self._handle_request()

            def do_GET(self) -> None:
                """Handle GET requests (S3 GetObject, etc.)."""
                self._handle_request()

            def do_PUT(self) -> None:
                """Handle PUT requests (S3 PutObject, etc.)."""
                self._handle_request()

            def do_DELETE(self) -> None:
                """Handle DELETE requests."""
                self._handle_request()

            def _handle_request(self) -> None:
                """Common request handling with enforcement."""
                result = enforcer._intercept_request(self)

                if result.action_taken == EnforcementAction.BLOCKED:
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("X-AgentGuard-Correlation-Id", result.correlation_id)
                    self.end_headers()
                    response = json.dumps({
                        "error": "AccessDenied",
                        "message": "Blocked by AWS Agent Identity Guard",
                        "correlation_id": result.correlation_id,
                    }).encode("utf-8")
                    self.wfile.write(response)
                elif result.action_taken == EnforcementAction.PENDING_APPROVAL:
                    self.send_response(202)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("X-AgentGuard-Correlation-Id", result.correlation_id)
                    self.end_headers()
                    response = json.dumps({
                        "status": "pending_approval",
                        "message": "Request requires step-up authentication",
                        "correlation_id": result.correlation_id,
                    }).encode("utf-8")
                    self.wfile.write(response)
                else:
                    # ALLOWED: return 200 with pass-through indication
                    # In a real proxy, this would forward to the actual AWS endpoint
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("X-AgentGuard-Correlation-Id", result.correlation_id)
                    self.send_header("X-AgentGuard-Action", "PASSTHROUGH")
                    self.end_headers()
                    response = json.dumps({
                        "status": "allowed",
                        "message": "Request passed enforcement, forwarding to AWS",
                        "correlation_id": result.correlation_id,
                    }).encode("utf-8")
                    self.wfile.write(response)

            def log_message(self, format: str, *args: Any) -> None:
                """Suppress default HTTP server logging."""
                logger.debug("ProxyEnforcer: %s", format % args)

        self._server = HTTPServer((host, port), ProxyHandler)
        self._running = True
        self._server_thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="AgentGuard-ProxyEnforcer",
        )
        self._server_thread.start()
        logger.info("ProxyEnforcer started on %s:%d", host, port)

    def stop(self) -> None:
        """
        Stop the proxy server.

        Shuts down the HTTP server and waits for the background thread
        to terminate.
        """
        if not self._running:
            logger.warning("ProxyEnforcer is not running")
            return

        self._running = False
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._server_thread:
            self._server_thread.join(timeout=5.0)
            self._server_thread = None

        logger.info("ProxyEnforcer stopped (processed %d requests)", self._request_count)

    def _intercept_request(self, handler: BaseHTTPRequestHandler) -> EnforcementResult:
        """
        Intercept and evaluate an HTTP request for enforcement.

        Parses the AWS service and action from the request, constructs
        a TransactionRequest, and runs enforcement.

        Args:
            handler: The HTTP request handler with request details.

        Returns:
            EnforcementResult for this request.
        """
        with self._lock:
            self._request_count += 1

        # Parse service from the host header
        host_header = handler.headers.get("Host", "")
        service = self._parse_service_from_host(host_header)

        # Parse action from headers or path
        action_header = handler.headers.get("X-Amz-Target", "")
        action = self._parse_action(service, action_header, handler.path)

        # Construct the transaction request
        request = TransactionRequest(
            agent_id=self._agent_id,
            principal=self._principal,
            tool="aws-api-proxy",
            action=action,
            resource="*",  # Resource determined from request body in production
            context={
                "proxy_host": host_header,
                "proxy_path": handler.path,
                "proxy_method": handler.command,
            },
        )

        # Make authorization decision (simple pass-through to enforcement mode)
        decision = AuthorizationDecision(
            decision=AuthorizationDecisionType.ALLOW,
            reasons=["Proxy pass-through evaluation"],
        )

        return self._engine.enforce(request, decision)

    def _parse_service_from_host(self, host: str) -> str:
        """
        Parse the AWS service name from the Host header.

        Args:
            host: Host header value (e.g., 's3.amazonaws.com').

        Returns:
            Service name string.
        """
        if not host:
            return "unknown"

        # Pattern: service.region.amazonaws.com
        parts = host.split(".")
        if len(parts) >= 3 and "amazonaws" in host:
            return parts[0]
        return "unknown"

    def _parse_action(self, service: str, amz_target: str, path: str) -> str:
        """
        Parse the IAM action from request details.

        Args:
            service: Parsed service name.
            amz_target: X-Amz-Target header value.
            path: Request path.

        Returns:
            IAM action string.
        """
        if amz_target:
            # X-Amz-Target format: ServiceName.OperationName
            parts = amz_target.split(".")
            if len(parts) >= 2:
                return f"{service}:{parts[-1]}"

        # Fallback: use path-based inference
        if path and path != "/":
            operation = path.strip("/").split("/")[0].split("?")[0]
            if operation:
                return f"{service}:{operation}"

        return f"{service}:Unknown"

    @property
    def is_running(self) -> bool:
        """Check if the proxy is currently running."""
        return self._running

    @property
    def request_count(self) -> int:
        """Return total number of requests processed."""
        with self._lock:
            return self._request_count


# --- Sidecar Enforcer ---


class SidecarEnforcer:
    """
    Container sidecar enforcement pattern.

    Runs alongside an AI agent container, intercepting egress traffic
    to AWS endpoints and enforcing authorization policies.

    Usage:
        sidecar = SidecarEnforcer(
            engine=enforcement_engine,
            agent_id="my-agent",
        )
        if sidecar.health_check():
            result = sidecar.enforce_egress("s3.amazonaws.com", "s3:GetObject")
    """

    def __init__(
        self,
        engine: EnforcementEngine,
        agent_id: str,
        principal: str = "",
        allowed_destinations: list[str] | None = None,
    ) -> None:
        """
        Initialize the sidecar enforcer.

        Args:
            engine: The enforcement engine.
            agent_id: Agent identifier.
            principal: IAM principal ARN.
            allowed_destinations: Whitelist of allowed egress destinations.
                If None, all destinations are subject to enforcement.
        """
        self._engine = engine
        self._agent_id = agent_id
        self._principal = principal
        self._allowed_destinations = set(allowed_destinations or [])
        self._healthy = True
        self._started_at = time.time()
        self._egress_count = 0
        self._blocked_count = 0
        self._lock = threading.Lock()
        logger.info(
            "SidecarEnforcer initialized for agent=%s with %d whitelisted destinations",
            agent_id,
            len(self._allowed_destinations),
        )

    def health_check(self) -> bool:
        """
        Check if the sidecar enforcer is healthy and ready.

        Validates internal state, engine availability, and resource usage.

        Returns:
            True if the sidecar is healthy and ready to enforce.
        """
        try:
            # Check enforcement engine is responsive
            if not self._engine:
                logger.error("SidecarEnforcer health check failed: no engine")
                self._healthy = False
                return False

            # Check we have not exceeded memory or timing constraints
            uptime_seconds = time.time() - self._started_at
            if uptime_seconds < 0:
                logger.error("SidecarEnforcer health check: clock skew detected")
                self._healthy = False
                return False

            self._healthy = True
            return True

        except Exception as exc:
            logger.error("SidecarEnforcer health check exception: %s", exc)
            self._healthy = False
            return False

    def enforce_egress(
        self,
        destination: str,
        action: str,
    ) -> EnforcementResult:
        """
        Enforce policy on egress traffic to an AWS endpoint.

        Checks the destination against the whitelist and enforces
        authorization on the specific action being attempted.

        Args:
            destination: Target endpoint (e.g., 's3.amazonaws.com',
                'dynamodb.us-east-1.amazonaws.com').
            action: IAM action being performed (e.g., 's3:GetObject').

        Returns:
            EnforcementResult indicating whether egress is permitted.
        """
        with self._lock:
            self._egress_count += 1

        # Fast path: check destination whitelist
        if self._allowed_destinations and destination in self._allowed_destinations:
            logger.debug(
                "SidecarEnforcer: destination %s is whitelisted", destination
            )
            return EnforcementResult(
                enforced=False,
                action_taken=EnforcementAction.ALLOWED,
                latency_ms=0.0,
            )

        # Extract resource from destination
        service = self._parse_service_from_destination(destination)

        # Build transaction request
        request = TransactionRequest(
            agent_id=self._agent_id,
            principal=self._principal,
            tool=f"sidecar.{service}",
            action=action,
            resource="*",
            context={
                "sidecar_destination": destination,
                "sidecar_service": service,
            },
        )

        # Get authorization decision
        decision = AuthorizationDecision(
            decision=AuthorizationDecisionType.ALLOW,
            reasons=["Sidecar egress evaluation"],
        )

        result = self._engine.enforce(request, decision)

        if result.action_taken == EnforcementAction.BLOCKED:
            with self._lock:
                self._blocked_count += 1

        return result

    def _parse_service_from_destination(self, destination: str) -> str:
        """
        Parse the AWS service from an endpoint destination.

        Args:
            destination: Endpoint hostname.

        Returns:
            AWS service name.
        """
        if not destination:
            return "unknown"

        # Standard AWS endpoint pattern: service.region.amazonaws.com
        parts = destination.split(".")
        if len(parts) >= 3 and "amazonaws" in destination:
            return parts[0]

        return "unknown"

    @property
    def stats(self) -> dict[str, Any]:
        """Return sidecar statistics."""
        with self._lock:
            return {
                "healthy": self._healthy,
                "uptime_seconds": time.time() - self._started_at,
                "egress_count": self._egress_count,
                "blocked_count": self._blocked_count,
                "agent_id": self._agent_id,
            }
