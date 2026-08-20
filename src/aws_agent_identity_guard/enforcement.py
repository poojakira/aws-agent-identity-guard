"""Runtime enforcement module for AWS Agent Identity Guard.

Provides policy enforcement, circuit breaking, SDK middleware,
and proxy-based interception of AWS API calls.
"""

from __future__ import annotations

import logging
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from .models import AuthorizationRequest, AuthorizationDecision

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class EnforcementMode(Enum):
    """Operational mode for the enforcement engine."""

    MONITOR = "monitor"
    """Log only — never block requests."""

    ENFORCE = "enforce"
    """Actively block unauthorized actions."""

    DRY_RUN = "dry_run"
    """Log what *would* be blocked without actually blocking."""


class ActionTaken(Enum):
    """Result action recorded after enforcement evaluation."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"
    LOGGED = "logged"


class FailureMode(Enum):
    """Behaviour when enforcement infrastructure is unavailable."""

    FAIL_CLOSED = "fail_closed"
    """Deny all requests if enforcement is unavailable (production default)."""

    FAIL_OPEN = "fail_open"
    """Allow requests if enforcement is unavailable (development option)."""


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    """Normal operation — enforcement checks proceed."""

    OPEN = "open"
    """Enforcement service considered down — fallback behaviour active."""

    HALF_OPEN = "half_open"
    """Probing recovery — limited requests sent to enforcement service."""


class InterceptorType(Enum):
    """Supported interceptor deployment patterns."""

    SIDECAR = "sidecar"
    PROXY = "proxy"
    API_GATEWAY = "api_gateway"
    SDK_MIDDLEWARE = "sdk_middleware"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnforcementResult:
    """Outcome of an enforcement evaluation."""

    action_taken: ActionTaken
    """Whether the request was allowed, blocked, or only logged."""

    decision: AuthorizationDecision
    """The underlying authorization decision."""

    enforcement_point: str
    """Identifier of the enforcement point that processed this request."""

    latency_ms: float
    """Time taken (milliseconds) to evaluate enforcement."""


@dataclass(frozen=True)
class InterceptResult:
    """Result returned by an interceptor."""

    allow: bool
    """True if the request should proceed."""

    reason: str = ""
    """Human-readable reason for the decision."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Optional metadata from the interceptor."""


@dataclass
class CircuitBreakerConfig:
    """Configuration for the enforcement circuit breaker."""

    failure_threshold: int = 5
    """Number of consecutive failures before opening the circuit."""

    recovery_time_seconds: float = 30.0
    """Seconds to wait in OPEN state before transitioning to HALF_OPEN."""

    half_open_max_requests: int = 3
    """Number of probe requests allowed in HALF_OPEN state."""


# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------


@runtime_checkable
class Interceptor(Protocol):
    """Protocol for enforcement interceptors.

    Interceptors can be deployed as sidecars, proxies, API gateways,
    or SDK middleware layers.
    """

    interceptor_type: InterceptorType

    def intercept(self, request: AuthorizationRequest) -> InterceptResult:
        """Intercept and evaluate an authorization request.

        Args:
            request: The authorization request to evaluate.

        Returns:
            InterceptResult indicating whether the request is allowed.
        """
        ...


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------


class CircuitBreaker:
    """Circuit breaker for graceful degradation when enforcement is unavailable.

    States:
        CLOSED  — Normal operation; enforcement checks proceed.
        OPEN    — Enforcement service considered down; fallback active.
        HALF_OPEN — Probing recovery with limited requests.
    """

    def __init__(self, config: CircuitBreakerConfig | None = None) -> None:
        self._config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._failure_count: int = 0
        self._last_failure_time: float = 0.0
        self._half_open_requests: int = 0
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        """Current circuit breaker state."""
        with self._lock:
            if self._state == CircuitState.OPEN:
                elapsed = time.monotonic() - self._last_failure_time
                if elapsed >= self._config.recovery_time_seconds:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_requests = 0
                    logger.info("Circuit breaker transitioning to HALF_OPEN")
            return self._state

    def record_success(self) -> None:
        """Record a successful enforcement call."""
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._half_open_requests += 1
                if self._half_open_requests >= self._config.half_open_max_requests:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    logger.info("Circuit breaker CLOSED — service recovered")
            else:
                self._failure_count = 0

    def record_failure(self) -> None:
        """Record a failed enforcement call."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                logger.warning("Circuit breaker re-OPENED from HALF_OPEN after failure")
            elif self._failure_count >= self._config.failure_threshold:
                self._state = CircuitState.OPEN
                logger.warning(
                    "Circuit breaker OPENED after %d consecutive failures",
                    self._failure_count,
                )

    def allow_request(self) -> bool:
        """Determine if a request should be allowed through the circuit.

        Returns:
            True if the request may proceed to the enforcement service.
        """
        state = self.state
        if state == CircuitState.CLOSED:
            return True
        if state == CircuitState.HALF_OPEN:
            with self._lock:
                if self._half_open_requests < self._config.half_open_max_requests:
                    return True
            return False
        return False  # OPEN


# ---------------------------------------------------------------------------
# Enforcement Engine
# ---------------------------------------------------------------------------


class EnforcementEngine:
    """Core enforcement engine orchestrating policy decisions.

    The engine evaluates authorization requests against registered
    interceptors and the configured enforcement mode.

    Example::

        engine = EnforcementEngine(
            enforcement_point="api-gateway-east",
            failure_mode=FailureMode.FAIL_CLOSED,
        )
        engine.configure(EnforcementMode.ENFORCE)
        result = engine.enforce(request)
    """

    def __init__(
        self,
        enforcement_point: str = "default",
        failure_mode: FailureMode = FailureMode.FAIL_CLOSED,
        circuit_breaker_config: CircuitBreakerConfig | None = None,
    ) -> None:
        """Initialize the enforcement engine.

        Args:
            enforcement_point: Logical name of this enforcement point.
            failure_mode: Behaviour when enforcement service is unavailable.
            circuit_breaker_config: Circuit breaker tuning parameters.
        """
        self._mode: EnforcementMode = EnforcementMode.ENFORCE
        self._enforcement_point: str = enforcement_point
        self._failure_mode: FailureMode = failure_mode
        self._interceptors: list[Interceptor] = []
        self._circuit_breaker = CircuitBreaker(circuit_breaker_config)
        self._lock = threading.Lock()

    @property
    def mode(self) -> EnforcementMode:
        """Current enforcement mode."""
        return self._mode

    @property
    def circuit_state(self) -> CircuitState:
        """Current circuit breaker state."""
        return self._circuit_breaker.state

    def configure(self, mode: EnforcementMode) -> None:
        """Set the enforcement mode.

        Args:
            mode: The desired enforcement mode.
        """
        previous = self._mode
        self._mode = mode
        logger.info(
            "Enforcement mode changed from %s to %s on point '%s'",
            previous.value,
            mode.value,
            self._enforcement_point,
        )

    def register_interceptor(self, interceptor: Interceptor) -> None:
        """Register an interceptor with the engine.

        Args:
            interceptor: An object implementing the Interceptor protocol.

        Raises:
            TypeError: If the object does not satisfy the Interceptor protocol.
        """
        if not isinstance(interceptor, Interceptor):
            raise TypeError(
                f"Object {interceptor!r} does not implement the Interceptor protocol"
            )
        with self._lock:
            self._interceptors.append(interceptor)
        logger.info(
            "Registered interceptor type=%s on point '%s'",
            interceptor.interceptor_type.value,
            self._enforcement_point,
        )

    def enforce(self, request: AuthorizationRequest) -> EnforcementResult:
        """Evaluate an authorization request and enforce the policy decision.

        The method runs through registered interceptors, applies the
        current enforcement mode, and respects the circuit breaker state.

        Args:
            request: The authorization request to evaluate.

        Returns:
            EnforcementResult capturing the action taken.
        """
        start = time.perf_counter()

        try:
            result = self._do_enforce(request)
            self._circuit_breaker.record_success()
            return result
        except Exception as exc:
            self._circuit_breaker.record_failure()
            return self._handle_enforcement_failure(request, exc, start)

    def _do_enforce(self, request: AuthorizationRequest) -> EnforcementResult:
        """Internal enforcement logic (may raise on infrastructure failure)."""
        start = time.perf_counter()

        # Circuit breaker check
        if not self._circuit_breaker.allow_request():
            return self._fallback_decision(request, start, reason="circuit_open")

        # Run interceptors
        for interceptor in self._interceptors:
            intercept_result = interceptor.intercept(request)
            if not intercept_result.allow:
                return self._build_result(
                    request=request,
                    allowed=False,
                    reason=intercept_result.reason,
                    start=start,
                )

        # All interceptors passed — determine action based on mode
        return self._build_result(request=request, allowed=True, reason="", start=start)

    def _build_result(
        self,
        request: AuthorizationRequest,
        allowed: bool,
        reason: str,
        start: float,
    ) -> EnforcementResult:
        """Construct an EnforcementResult respecting the current mode."""
        latency_ms = (time.perf_counter() - start) * 1000.0

        if self._mode == EnforcementMode.MONITOR:
            # Log only — never block
            action = ActionTaken.LOGGED
            decision = AuthorizationDecision(
                allowed=True,
                reason=reason or "monitor_mode",
            )
            if not allowed:
                logger.warning(
                    "[MONITOR] Would have blocked request: agent=%s action=%s reason=%s",
                    request.agent_id,
                    request.action,
                    reason,
                )

        elif self._mode == EnforcementMode.DRY_RUN:
            # Log what would happen but don't block
            action = ActionTaken.LOGGED
            decision = AuthorizationDecision(
                allowed=True,
                reason=reason or "dry_run_mode",
            )
            if not allowed:
                logger.info(
                    "[DRY_RUN] Would block: agent=%s action=%s reason=%s",
                    request.agent_id,
                    request.action,
                    reason,
                )

        elif self._mode == EnforcementMode.ENFORCE:
            if allowed:
                action = ActionTaken.ALLOWED
                decision = AuthorizationDecision(allowed=True, reason="permitted")
            else:
                action = ActionTaken.BLOCKED
                decision = AuthorizationDecision(allowed=False, reason=reason)
                logger.warning(
                    "[ENFORCE] Blocked: agent=%s action=%s reason=%s",
                    request.agent_id,
                    request.action,
                    reason,
                )
        else:
            # Defensive fallback
            action = ActionTaken.LOGGED
            decision = AuthorizationDecision(allowed=True, reason="unknown_mode")

        return EnforcementResult(
            action_taken=action,
            decision=decision,
            enforcement_point=self._enforcement_point,
            latency_ms=latency_ms,
        )

    def _fallback_decision(
        self,
        request: AuthorizationRequest,
        start: float,
        reason: str,
    ) -> EnforcementResult:
        """Apply failure mode policy when enforcement service is unavailable."""
        latency_ms = (time.perf_counter() - start) * 1000.0

        if self._failure_mode == FailureMode.FAIL_CLOSED:
            action = ActionTaken.BLOCKED
            allowed = False
            logger.error(
                "Fail-closed: denying request agent=%s action=%s reason=%s",
                request.agent_id,
                request.action,
                reason,
            )
        else:
            action = ActionTaken.ALLOWED
            allowed = True
            logger.warning(
                "Fail-open: allowing request agent=%s action=%s reason=%s",
                request.agent_id,
                request.action,
                reason,
            )

        decision = AuthorizationDecision(
            allowed=allowed,
            reason=f"fallback:{reason}",
        )
        return EnforcementResult(
            action_taken=action,
            decision=decision,
            enforcement_point=self._enforcement_point,
            latency_ms=latency_ms,
        )

    def _handle_enforcement_failure(
        self,
        request: AuthorizationRequest,
        exc: Exception,
        start: float,
    ) -> EnforcementResult:
        """Handle unexpected enforcement failures with logging and fallback."""
        logger.error(
            "Enforcement failure on point '%s': %s — applying failure_mode=%s",
            self._enforcement_point,
            exc,
            self._failure_mode.value,
            exc_info=True,
        )
        return self._fallback_decision(
            request, start, reason=f"exception:{type(exc).__name__}"
        )


# ---------------------------------------------------------------------------
# SDK Middleware
# ---------------------------------------------------------------------------


@dataclass
class MiddlewareDecision:
    """Decision returned by SDK middleware before_call."""

    allow: bool
    """Whether the boto3 call should proceed."""

    reason: str = ""
    """Explanation for the decision."""


class SDKMiddleware:
    """Wraps boto3 calls with authorization enforcement.

    Designed to be integrated as event handlers on a boto3 Session
    or as a botocore event hook.

    Example::

        middleware = SDKMiddleware(engine=enforcement_engine, agent_id="agent-123")
        # Register with boto3 event system
        session.events.register('before-call.*', middleware.before_call_hook)
        session.events.register('after-call.*', middleware.after_call_hook)
    """

    def __init__(self, engine: EnforcementEngine, agent_id: str) -> None:
        """Initialize SDK middleware.

        Args:
            engine: The enforcement engine to delegate decisions to.
            agent_id: The agent identity for authorization requests.
        """
        self._engine = engine
        self._agent_id = agent_id

    def before_call(
        self, service: str, operation: str, params: dict[str, Any]
    ) -> MiddlewareDecision:
        """Evaluate authorization before a boto3 API call.

        Args:
            service: AWS service name (e.g., 's3', 'ec2').
            operation: API operation name (e.g., 'PutObject').
            params: Call parameters.

        Returns:
            MiddlewareDecision indicating allow or deny.
        """
        request = AuthorizationRequest(
            agent_id=self._agent_id,
            action=f"{service}:{operation}",
            resource=params.get("Bucket", params.get("FunctionName", "*")),
            context={"params": params, "source": "sdk_middleware"},
        )
        result = self._engine.enforce(request)

        if result.action_taken == ActionTaken.BLOCKED:
            logger.warning(
                "SDK middleware blocked: service=%s operation=%s agent=%s reason=%s",
                service,
                operation,
                self._agent_id,
                result.decision.reason,
            )
            return MiddlewareDecision(allow=False, reason=result.decision.reason)

        return MiddlewareDecision(allow=True, reason=result.decision.reason)

    def after_call(
        self, service: str, operation: str, response: dict[str, Any]
    ) -> None:
        """Audit a completed boto3 API call.

        Args:
            service: AWS service name.
            operation: API operation name.
            response: The API response.
        """
        status_code = response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
        logger.info(
            "SDK middleware audit: agent=%s service=%s operation=%s status=%d",
            self._agent_id,
            service,
            operation,
            status_code,
        )

    # Convenience hooks for boto3 event system integration

    def before_call_hook(self, **kwargs: Any) -> None:
        """boto3 event hook adapter for before-call events."""
        model = kwargs.get("model")
        params = kwargs.get("params", {})
        if model:
            service = model.service_model.service_name
            operation = model.name
        else:
            service = kwargs.get("service_name", "unknown")
            operation = kwargs.get("operation_name", "unknown")

        decision = self.before_call(service, operation, params)
        if not decision.allow:
            raise PermissionError(
                f"Blocked by enforcement: {service}:{operation} — {decision.reason}"
            )

    def after_call_hook(self, **kwargs: Any) -> None:
        """boto3 event hook adapter for after-call events."""
        http_response = kwargs.get("http_response")
        parsed_response = kwargs.get("parsed_response", {})
        model = kwargs.get("model")
        if model:
            service = model.service_model.service_name
            operation = model.name
        else:
            service = "unknown"
            operation = "unknown"

        response = parsed_response if parsed_response else {}
        if http_response:
            response.setdefault("ResponseMetadata", {})["HTTPStatusCode"] = (
                http_response.status_code
            )
        self.after_call(service, operation, response)


# ---------------------------------------------------------------------------
# Proxy Enforcer
# ---------------------------------------------------------------------------


class ProxyEnforcer:
    """HTTP proxy that intercepts AWS API calls for enforcement.

    Sits between agents and AWS endpoints, evaluating every request
    against the enforcement engine before forwarding.

    Example::

        proxy = ProxyEnforcer(
            engine=enforcement_engine,
            listen_address="127.0.0.1",
            listen_port=8443,
        )
        proxy.start()
    """

    def __init__(
        self,
        engine: EnforcementEngine,
        listen_address: str = "127.0.0.1",
        listen_port: int = 8443,
        tls_cert_path: str | None = None,
        tls_key_path: str | None = None,
    ) -> None:
        """Initialize the proxy enforcer.

        Args:
            engine: Enforcement engine for policy decisions.
            listen_address: Address to bind the proxy.
            listen_port: Port to listen on.
            tls_cert_path: Path to TLS certificate for HTTPS interception.
            tls_key_path: Path to TLS private key.
        """
        self._engine = engine
        self._listen_address = listen_address
        self._listen_port = listen_port
        self._tls_cert_path = tls_cert_path
        self._tls_key_path = tls_key_path
        self._running = False
        self._server_thread: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        """Whether the proxy is currently running."""
        return self._running

    @property
    def address(self) -> str:
        """The full listen address string."""
        return f"{self._listen_address}:{self._listen_port}"

    def start(self) -> None:
        """Start the proxy enforcer in a background thread.

        Raises:
            RuntimeError: If the proxy is already running.
        """
        if self._running:
            raise RuntimeError("ProxyEnforcer is already running")

        self._running = True
        self._server_thread = threading.Thread(
            target=self._serve, daemon=True, name="proxy-enforcer"
        )
        self._server_thread.start()
        logger.info("ProxyEnforcer started on %s", self.address)

    def stop(self) -> None:
        """Stop the proxy enforcer."""
        self._running = False
        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=5.0)
        logger.info("ProxyEnforcer stopped")

    def handle_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        """Process an intercepted HTTP request.

        Args:
            method: HTTP method (GET, POST, etc.).
            url: Target URL.
            headers: HTTP headers.
            body: Request body bytes.

        Returns:
            Tuple of (status_code, response_headers, response_body).
        """
        agent_id = headers.get("X-Agent-Id", "unknown")
        service, operation = self._parse_aws_request(method, url, headers)

        request = AuthorizationRequest(
            agent_id=agent_id,
            action=f"{service}:{operation}",
            resource=url,
            context={
                "method": method,
                "headers": headers,
                "source": "proxy",
            },
        )

        result = self._engine.enforce(request)

        if result.action_taken == ActionTaken.BLOCKED:
            logger.warning(
                "Proxy blocked: agent=%s url=%s reason=%s",
                agent_id,
                url,
                result.decision.reason,
            )
            return (
                403,
                {"Content-Type": "application/json"},
                b'{"error": "Request blocked by enforcement policy"}',
            )

        # In a real implementation, forward the request to AWS
        return (200, {"Content-Type": "application/json"}, b'{"status": "forwarded"}')

    def _parse_aws_request(
        self, method: str, url: str, headers: dict[str, str]
    ) -> tuple[str, str]:
        """Extract AWS service and operation from request metadata.

        Args:
            method: HTTP method.
            url: Target URL.
            headers: HTTP headers.

        Returns:
            Tuple of (service_name, operation_name).
        """
        # Parse from X-Amz-Target header (common for JSON protocol services)
        amz_target = headers.get("X-Amz-Target", "")
        if "." in amz_target:
            parts = amz_target.rsplit(".", 1)
            return parts[0], parts[1]

        # Parse from URL host pattern: <service>.<region>.amazonaws.com
        host = headers.get("Host", "")
        if ".amazonaws.com" in host:
            service = host.split(".")[0]
            return service, method

        return "unknown", "unknown"

    def _serve(self) -> None:
        """Internal server loop (placeholder for actual HTTP server)."""
        logger.info("ProxyEnforcer serving on %s", self.address)
        while self._running:
            time.sleep(0.1)
