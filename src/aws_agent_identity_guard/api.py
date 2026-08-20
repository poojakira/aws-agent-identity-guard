"""REST API server for AWS Agent Identity Guard.

Provides a production-grade HTTP API using Python's built-in http.server module.
No external dependencies required beyond the standard library.

Endpoints:
    POST /v1/authorize          - Authorize an agent action
    POST /v1/agents             - Register a new agent
    GET  /v1/agents             - List all registered agents
    GET  /v1/agents/{id}        - Get agent details
    GET  /v1/agents/{id}/permissions   - Get effective permissions
    GET  /v1/agents/{id}/attack-paths  - Get discovered attack paths
    GET  /v1/agents/{id}/risk          - Get risk assessment
    POST /v1/policies           - Upload security policy
    GET  /v1/policies           - List policies
    POST /v1/policies/evaluate  - Evaluate action against policies
    GET  /v1/approvals          - List pending approvals
    POST /v1/approvals/{id}/approve - Approve a pending request
    POST /v1/approvals/{id}/deny    - Deny a pending request
    GET  /v1/metrics            - Prometheus metrics
    GET  /v1/health             - Health check
    GET  /v1/health/ready       - Readiness probe
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple

from .models import (
    Agent,
    AuthorizationDecision,
    AuthorizationRequest,
    Permission,
    Policy,
    RiskAssessment,
)

__all__ = ["APIServer", "APIHandler"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_VERSION = "v1"
SERVER_VERSION = "1.0.0"
DEFAULT_RATE_LIMIT_TOKENS = 100
DEFAULT_RATE_LIMIT_REFILL = 10.0  # tokens per second
VALID_API_KEY_HEADER = "X-API-Key"
CORRELATION_ID_HEADER = "X-Correlation-ID"


# ---------------------------------------------------------------------------
# Token Bucket Rate Limiter
# ---------------------------------------------------------------------------


@dataclass
class TokenBucket:
    """Simple token bucket rate limiter.

    Attributes:
        capacity: Maximum number of tokens in the bucket.
        refill_rate: Tokens added per second.
        tokens: Current number of available tokens.
        last_refill: Timestamp of last refill.
        lock: Thread lock for concurrent access.
    """

    capacity: int = DEFAULT_RATE_LIMIT_TOKENS
    refill_rate: float = DEFAULT_RATE_LIMIT_REFILL
    tokens: float = field(init=False)
    last_refill: float = field(init=False)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        """Initialize tokens to full capacity."""
        self.tokens = float(self.capacity)
        self.last_refill = time.monotonic()

    def consume(self, tokens: int = 1) -> bool:
        """Attempt to consume tokens from the bucket.

        Args:
            tokens: Number of tokens to consume.

        Returns:
            True if tokens were available and consumed, False otherwise.
        """
        with self.lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now


# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------


@dataclass
class APIState:
    """Shared mutable state for the API server.

    Attributes:
        agents: Registered agents keyed by agent_id.
        policies: Loaded policies keyed by policy_id.
        approvals: Pending approval requests keyed by approval_id.
        metrics: Simple metrics counters.
        start_time: Server start timestamp (monotonic).
        api_keys: Set of valid API keys (placeholder).
        rate_limiters: Per-client rate limiters keyed by IP.
        lock: Thread lock for state mutations.
    """

    agents: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    policies: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    approvals: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    metrics: Dict[str, int] = field(default_factory=lambda: {
        "requests_total": 0,
        "requests_authorized": 0,
        "requests_denied": 0,
        "errors_total": 0,
        "agents_registered": 0,
        "policies_loaded": 0,
    })
    start_time: float = field(default_factory=time.monotonic)
    api_keys: set = field(default_factory=lambda: {"development-key", "test-key"})
    rate_limiters: Dict[str, TokenBucket] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def get_rate_limiter(self, client_ip: str) -> TokenBucket:
        """Get or create a rate limiter for the given client IP.

        Args:
            client_ip: The client's IP address.

        Returns:
            TokenBucket instance for the client.
        """
        with self.lock:
            if client_ip not in self.rate_limiters:
                self.rate_limiters[client_ip] = TokenBucket()
            return self.rate_limiters[client_ip]

    def increment_metric(self, metric: str, value: int = 1) -> None:
        """Thread-safe metric increment.

        Args:
            metric: Metric name to increment.
            value: Amount to increment by.
        """
        with self.lock:
            self.metrics[metric] = self.metrics.get(metric, 0) + value


# ---------------------------------------------------------------------------
# Route matching
# ---------------------------------------------------------------------------

# Route pattern: (method, regex_pattern, handler_name)
RouteEntry = Tuple[str, re.Pattern, str]


def _build_routes() -> List[RouteEntry]:
    """Build the route table with compiled regex patterns.

    Returns:
        List of (method, compiled_pattern, handler_method_name) tuples.
    """
    routes: List[Tuple[str, str, str]] = [
        # Authorization
        ("POST", r"/v1/authorize$", "handle_authorize"),
        # Agents
        ("POST", r"/v1/agents$", "handle_create_agent"),
        ("GET", r"/v1/agents$", "handle_list_agents"),
        ("GET", r"/v1/agents/(?P<agent_id>[^/]+)/permissions$", "handle_agent_permissions"),
        ("GET", r"/v1/agents/(?P<agent_id>[^/]+)/attack-paths$", "handle_agent_attack_paths"),
        ("GET", r"/v1/agents/(?P<agent_id>[^/]+)/risk$", "handle_agent_risk"),
        ("GET", r"/v1/agents/(?P<agent_id>[^/]+)$", "handle_get_agent"),
        # Policies
        ("POST", r"/v1/policies/evaluate$", "handle_evaluate_policy"),
        ("POST", r"/v1/policies$", "handle_create_policy"),
        ("GET", r"/v1/policies$", "handle_list_policies"),
        # Approvals
        ("POST", r"/v1/approvals/(?P<approval_id>[^/]+)/approve$", "handle_approve"),
        ("POST", r"/v1/approvals/(?P<approval_id>[^/]+)/deny$", "handle_deny"),
        ("GET", r"/v1/approvals$", "handle_list_approvals"),
        # Metrics
        ("GET", r"/v1/metrics$", "handle_metrics"),
        # Health
        ("GET", r"/v1/health/ready$", "handle_health_ready"),
        ("GET", r"/v1/health$", "handle_health"),
    ]
    return [(method, re.compile(pattern), handler) for method, pattern, handler in routes]


ROUTES: List[RouteEntry] = _build_routes()


# ---------------------------------------------------------------------------
# Request Handler
# ---------------------------------------------------------------------------


class APIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the Identity Guard API.

    Implements routing, authentication, rate limiting, CORS headers,
    correlation ID injection, and structured JSON logging.
    """

    server: "IdentityGuardHTTPServer"

    def log_message(self, format: str, *args: Any) -> None:
        """Override default logging to use structured JSON format.

        Args:
            format: Log format string (ignored in favor of structured logging).
            *args: Format arguments.
        """
        # Suppress default stderr logging; we use structured logging below.
        pass

    def _log_request(self, status_code: int, correlation_id: str) -> None:
        """Emit a structured JSON log entry for the request.

        Args:
            status_code: HTTP response status code.
            correlation_id: Request correlation ID.
        """
        log_entry = {
            "timestamp": time.time(),
            "level": "INFO",
            "method": self.command,
            "path": self.path,
            "status": status_code,
            "correlation_id": correlation_id,
            "client_ip": self.client_address[0],
        }
        logger.info(json.dumps(log_entry, separators=(",", ":")))

    def _get_correlation_id(self) -> str:
        """Extract or generate a correlation ID for the request.

        Returns:
            Correlation ID string.
        """
        correlation_id = self.headers.get(CORRELATION_ID_HEADER)
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
        return correlation_id

    def _set_cors_headers(self) -> None:
        """Set CORS headers on the response."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key, X-Correlation-ID")
        self.send_header("Access-Control-Max-Age", "86400")

    def _authenticate(self) -> bool:
        """Check for valid API key in request headers.

        Health and metrics endpoints are exempt from authentication.

        Returns:
            True if authenticated, False otherwise.
        """
        # Exempt health and metrics from auth
        if self.path.startswith("/v1/health") or self.path == "/v1/metrics":
            return True

        api_key = self.headers.get(VALID_API_KEY_HEADER)
        if not api_key:
            return False
        return api_key in self.server.state.api_keys

    def _check_rate_limit(self) -> bool:
        """Check if the client has exceeded their rate limit.

        Returns:
            True if within rate limit, False if exceeded.
        """
        client_ip = self.client_address[0]
        limiter = self.server.state.get_rate_limiter(client_ip)
        return limiter.consume()

    def _read_body(self) -> bytes:
        """Read the request body.

        Returns:
            Request body as bytes.
        """
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            return self.rfile.read(content_length)
        return b""

    def _parse_json_body(self) -> Optional[Dict[str, Any]]:
        """Parse the request body as JSON.

        Returns:
            Parsed JSON dictionary or None if parsing fails.
        """
        body = self._read_body()
        if not body:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _send_json_response(
        self,
        data: Any,
        status: int = 200,
        correlation_id: str = "",
    ) -> None:
        """Send a JSON response.

        Args:
            data: Response data to serialize as JSON.
            status: HTTP status code.
            correlation_id: Correlation ID to include in response headers.
        """
        response_body = json.dumps(data, default=str, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        if correlation_id:
            self.send_header(CORRELATION_ID_HEADER, correlation_id)
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(response_body)

    def _send_error_response(
        self,
        status: int,
        error: str,
        detail: str = "",
        correlation_id: str = "",
    ) -> None:
        """Send a JSON error response.

        Args:
            status: HTTP status code.
            error: Short error description.
            detail: Detailed error message.
            correlation_id: Correlation ID for the response.
        """
        self.server.state.increment_metric("errors_total")
        body: Dict[str, Any] = {
            "error": error,
            "status": status,
        }
        if detail:
            body["detail"] = detail
        if correlation_id:
            body["correlation_id"] = correlation_id
        self._send_json_response(body, status=status, correlation_id=correlation_id)

    def _send_text_response(
        self,
        text: str,
        status: int = 200,
        content_type: str = "text/plain",
        correlation_id: str = "",
    ) -> None:
        """Send a plain text response.

        Args:
            text: Response body text.
            status: HTTP status code.
            content_type: MIME type for the response.
            correlation_id: Correlation ID for the response.
        """
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if correlation_id:
            self.send_header(CORRELATION_ID_HEADER, correlation_id)
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self) -> None:
        """Route the incoming request to the appropriate handler."""
        correlation_id = self._get_correlation_id()
        self.server.state.increment_metric("requests_total")

        # Rate limiting
        if not self._check_rate_limit():
            self._send_error_response(
                HTTPStatus.TOO_MANY_REQUESTS,
                "Rate limit exceeded",
                "Too many requests. Please retry later.",
                correlation_id,
            )
            self._log_request(HTTPStatus.TOO_MANY_REQUESTS, correlation_id)
            return

        # Authentication
        if not self._authenticate():
            self._send_error_response(
                HTTPStatus.UNAUTHORIZED,
                "Unauthorized",
                "Missing or invalid API key. Provide a valid X-API-Key header.",
                correlation_id,
            )
            self._log_request(HTTPStatus.UNAUTHORIZED, correlation_id)
            return

        # Route matching
        method = self.command
        path = self.path.split("?")[0]  # Strip query string

        for route_method, pattern, handler_name in ROUTES:
            if method != route_method:
                continue
            match = pattern.match(path)
            if match:
                handler_func = getattr(self, handler_name, None)
                if handler_func:
                    try:
                        handler_func(correlation_id=correlation_id, **match.groupdict())
                    except Exception as exc:
                        logger.exception("Unhandled error in %s: %s", handler_name, exc)
                        self._send_error_response(
                            HTTPStatus.INTERNAL_SERVER_ERROR,
                            "Internal server error",
                            str(exc),
                            correlation_id,
                        )
                    self._log_request(200, correlation_id)
                    return

        # No route matched
        self._send_error_response(
            HTTPStatus.NOT_FOUND,
            "Not found",
            f"No route matched: {method} {path}",
            correlation_id,
        )
        self._log_request(HTTPStatus.NOT_FOUND, correlation_id)

    def do_GET(self) -> None:
        """Handle GET requests."""
        self._dispatch()

    def do_POST(self) -> None:
        """Handle POST requests."""
        self._dispatch()

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight requests."""
        self.send_response(HTTPStatus.NO_CONTENT)
        self._set_cors_headers()
        self.end_headers()

    # -------------------------------------------------------------------
    # Handler implementations
    # -------------------------------------------------------------------

    def handle_authorize(self, correlation_id: str, **kwargs: Any) -> None:
        """Handle POST /v1/authorize - Authorize an agent action.

        Args:
            correlation_id: Request correlation ID.
            **kwargs: Additional route parameters.
        """
        body = self._parse_json_body()
        if not body:
            self._send_error_response(
                HTTPStatus.BAD_REQUEST,
                "Invalid request body",
                "Request body must be valid JSON with authorization request fields.",
                correlation_id,
            )
            return

        # Validate required fields
        required_fields = ["agent_id", "action", "resource"]
        missing = [f for f in required_fields if f not in body]
        if missing:
            self._send_error_response(
                HTTPStatus.BAD_REQUEST,
                "Missing required fields",
                f"Missing fields: {', '.join(missing)}",
                correlation_id,
            )
            return

        agent_id = body["agent_id"]
        action = body["action"]
        resource = body["resource"]

        # Check if agent exists
        if agent_id not in self.server.state.agents:
            self._send_error_response(
                HTTPStatus.NOT_FOUND,
                "Agent not found",
                f"Agent '{agent_id}' is not registered.",
                correlation_id,
            )
            return

        # Simple authorization logic (placeholder for real policy engine)
        risk_score = self._calculate_risk_score(agent_id, action, resource)
        decision = "allow" if risk_score < 0.7 else "deny"
        reasons: List[str] = []
        explanation = ""

        if decision == "deny":
            reasons.append("Risk score exceeds threshold")
            explanation = (
                f"Action '{action}' on resource '{resource}' "
                f"has a risk score of {risk_score:.2f} which exceeds the 0.7 threshold."
            )
            self.server.state.increment_metric("requests_denied")
        else:
            reasons.append("Action permitted by policy")
            explanation = (
                f"Action '{action}' on resource '{resource}' "
                f"is permitted with risk score {risk_score:.2f}."
            )
            self.server.state.increment_metric("requests_authorized")

        # Determine applicable policy
        applicable_policy = self._find_applicable_policy(agent_id, action, resource)

        response = {
            "decision": decision,
            "risk_score": round(risk_score, 4),
            "reasons": reasons,
            "policy": applicable_policy,
            "explanation": explanation,
            "correlation_id": correlation_id,
        }
        self._send_json_response(response, correlation_id=correlation_id)

    def handle_create_agent(self, correlation_id: str, **kwargs: Any) -> None:
        """Handle POST /v1/agents - Register a new agent.

        Args:
            correlation_id: Request correlation ID.
            **kwargs: Additional route parameters.
        """
        body = self._parse_json_body()
        if not body:
            self._send_error_response(
                HTTPStatus.BAD_REQUEST,
                "Invalid request body",
                "Request body must be valid JSON with agent fields.",
                correlation_id,
            )
            return

        # Validate required fields
        required_fields = ["name", "type"]
        missing = [f for f in required_fields if f not in body]
        if missing:
            self._send_error_response(
                HTTPStatus.BAD_REQUEST,
                "Missing required fields",
                f"Missing fields: {', '.join(missing)}",
                correlation_id,
            )
            return

        agent_id = body.get("agent_id", str(uuid.uuid4()))

        # Check for duplicate
        if agent_id in self.server.state.agents:
            self._send_error_response(
                HTTPStatus.CONFLICT,
                "Agent already exists",
                f"Agent with ID '{agent_id}' is already registered.",
                correlation_id,
            )
            return

        agent_record: Dict[str, Any] = {
            "agent_id": agent_id,
            "name": body["name"],
            "type": body["type"],
            "description": body.get("description", ""),
            "permissions": body.get("permissions", []),
            "metadata": body.get("metadata", {}),
            "status": "active",
            "registered_at": time.time(),
            "risk_score": 0.0,
        }

        with self.server.state.lock:
            self.server.state.agents[agent_id] = agent_record
        self.server.state.increment_metric("agents_registered")

        response = {
            "agent_id": agent_id,
            "status": "registered",
        }
        self._send_json_response(response, status=HTTPStatus.CREATED, correlation_id=correlation_id)

    def handle_list_agents(self, correlation_id: str, **kwargs: Any) -> None:
        """Handle GET /v1/agents - List all registered agents.

        Args:
            correlation_id: Request correlation ID.
            **kwargs: Additional route parameters.
        """
        agents_list = list(self.server.state.agents.values())
        response = {"agents": agents_list, "total": len(agents_list)}
        self._send_json_response(response, correlation_id=correlation_id)

    def handle_get_agent(self, correlation_id: str, agent_id: str, **kwargs: Any) -> None:
        """Handle GET /v1/agents/{agent_id} - Get agent details with risk score.

        Args:
            correlation_id: Request correlation ID.
            agent_id: The agent identifier.
            **kwargs: Additional route parameters.
        """
        agent = self.server.state.agents.get(agent_id)
        if not agent:
            self._send_error_response(
                HTTPStatus.NOT_FOUND,
                "Agent not found",
                f"Agent '{agent_id}' is not registered.",
                correlation_id,
            )
            return

        # Include computed risk score
        agent_response = dict(agent)
        agent_response["risk_score"] = self._get_agent_risk_score(agent_id)
        self._send_json_response(agent_response, correlation_id=correlation_id)

    def handle_agent_permissions(self, correlation_id: str, agent_id: str, **kwargs: Any) -> None:
        """Handle GET /v1/agents/{agent_id}/permissions - Get effective permissions.

        Args:
            correlation_id: Request correlation ID.
            agent_id: The agent identifier.
            **kwargs: Additional route parameters.
        """
        agent = self.server.state.agents.get(agent_id)
        if not agent:
            self._send_error_response(
                HTTPStatus.NOT_FOUND,
                "Agent not found",
                f"Agent '{agent_id}' is not registered.",
                correlation_id,
            )
            return

        # Compute effective permissions from agent config and policies
        permissions = self._compute_effective_permissions(agent_id)
        response = {
            "agent_id": agent_id,
            "permissions": permissions,
            "total": len(permissions),
        }
        self._send_json_response(response, correlation_id=correlation_id)

    def handle_agent_attack_paths(self, correlation_id: str, agent_id: str, **kwargs: Any) -> None:
        """Handle GET /v1/agents/{agent_id}/attack-paths - Get discovered attack paths.

        Args:
            correlation_id: Request correlation ID.
            agent_id: The agent identifier.
            **kwargs: Additional route parameters.
        """
        agent = self.server.state.agents.get(agent_id)
        if not agent:
            self._send_error_response(
                HTTPStatus.NOT_FOUND,
                "Agent not found",
                f"Agent '{agent_id}' is not registered.",
                correlation_id,
            )
            return

        # Placeholder attack path analysis
        attack_paths = self._analyze_attack_paths(agent_id)
        response = {
            "agent_id": agent_id,
            "attack_paths": attack_paths,
            "total": len(attack_paths),
            "analyzed_at": time.time(),
        }
        self._send_json_response(response, correlation_id=correlation_id)

    def handle_agent_risk(self, correlation_id: str, agent_id: str, **kwargs: Any) -> None:
        """Handle GET /v1/agents/{agent_id}/risk - Get risk assessment.

        Args:
            correlation_id: Request correlation ID.
            agent_id: The agent identifier.
            **kwargs: Additional route parameters.
        """
        agent = self.server.state.agents.get(agent_id)
        if not agent:
            self._send_error_response(
                HTTPStatus.NOT_FOUND,
                "Agent not found",
                f"Agent '{agent_id}' is not registered.",
                correlation_id,
            )
            return

        risk_assessment = self._assess_agent_risk(agent_id)
        self._send_json_response(risk_assessment, correlation_id=correlation_id)

    def handle_create_policy(self, correlation_id: str, **kwargs: Any) -> None:
        """Handle POST /v1/policies - Upload and store a security policy.

        Args:
            correlation_id: Request correlation ID.
            **kwargs: Additional route parameters.
        """
        body = self._parse_json_body()
        if not body:
            self._send_error_response(
                HTTPStatus.BAD_REQUEST,
                "Invalid request body",
                "Request body must be valid JSON with policy fields.",
                correlation_id,
            )
            return

        # Validate required fields
        required_fields = ["name", "rules"]
        missing = [f for f in required_fields if f not in body]
        if missing:
            self._send_error_response(
                HTTPStatus.BAD_REQUEST,
                "Missing required fields",
                f"Missing fields: {', '.join(missing)}",
                correlation_id,
            )
            return

        # Validate policy structure
        rules = body.get("rules", [])
        if not isinstance(rules, list):
            self._send_error_response(
                HTTPStatus.BAD_REQUEST,
                "Invalid policy format",
                "'rules' must be a list of rule objects.",
                correlation_id,
            )
            return

        validation_errors = self._validate_policy_rules(rules)
        if validation_errors:
            self._send_error_response(
                HTTPStatus.BAD_REQUEST,
                "Policy validation failed",
                f"Validation errors: {'; '.join(validation_errors)}",
                correlation_id,
            )
            return

        policy_id = body.get("policy_id", str(uuid.uuid4()))

        policy_record: Dict[str, Any] = {
            "policy_id": policy_id,
            "name": body["name"],
            "description": body.get("description", ""),
            "version": body.get("version", "1.0.0"),
            "rules": rules,
            "metadata": body.get("metadata", {}),
            "status": "active",
            "created_at": time.time(),
        }

        with self.server.state.lock:
            self.server.state.policies[policy_id] = policy_record
        self.server.state.increment_metric("policies_loaded")

        response = {
            "policy_id": policy_id,
            "status": "created",
            "rules_count": len(rules),
        }
        self._send_json_response(response, status=HTTPStatus.CREATED, correlation_id=correlation_id)

    def handle_list_policies(self, correlation_id: str, **kwargs: Any) -> None:
        """Handle GET /v1/policies - List all loaded policies.

        Args:
            correlation_id: Request correlation ID.
            **kwargs: Additional route parameters.
        """
        policies_list = list(self.server.state.policies.values())
        response = {"policies": policies_list, "total": len(policies_list)}
        self._send_json_response(response, correlation_id=correlation_id)

    def handle_evaluate_policy(self, correlation_id: str, **kwargs: Any) -> None:
        """Handle POST /v1/policies/evaluate - Evaluate action against policies.

        Args:
            correlation_id: Request correlation ID.
            **kwargs: Additional route parameters.
        """
        body = self._parse_json_body()
        if not body:
            self._send_error_response(
                HTTPStatus.BAD_REQUEST,
                "Invalid request body",
                "Request body must be valid JSON with evaluation fields.",
                correlation_id,
            )
            return

        required_fields = ["agent_id", "action", "resource"]
        missing = [f for f in required_fields if f not in body]
        if missing:
            self._send_error_response(
                HTTPStatus.BAD_REQUEST,
                "Missing required fields",
                f"Missing fields: {', '.join(missing)}",
                correlation_id,
            )
            return

        agent_id = body["agent_id"]
        action = body["action"]
        resource = body["resource"]

        # Evaluate against all active policies
        evaluation_results = self._evaluate_against_policies(agent_id, action, resource)

        response = {
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "results": evaluation_results,
            "overall_decision": "deny" if any(
                r.get("decision") == "deny" for r in evaluation_results
            ) else "allow",
            "correlation_id": correlation_id,
        }
        self._send_json_response(response, correlation_id=correlation_id)

    def handle_list_approvals(self, correlation_id: str, **kwargs: Any) -> None:
        """Handle GET /v1/approvals - List pending approvals.

        Args:
            correlation_id: Request correlation ID.
            **kwargs: Additional route parameters.
        """
        pending = [
            a for a in self.server.state.approvals.values()
            if a.get("status") == "pending"
        ]
        response = {"approvals": pending, "total": len(pending)}
        self._send_json_response(response, correlation_id=correlation_id)

    def handle_approve(self, correlation_id: str, approval_id: str, **kwargs: Any) -> None:
        """Handle POST /v1/approvals/{id}/approve - Approve a pending request.

        Args:
            correlation_id: Request correlation ID.
            approval_id: The approval request identifier.
            **kwargs: Additional route parameters.
        """
        approval = self.server.state.approvals.get(approval_id)
        if not approval:
            self._send_error_response(
                HTTPStatus.NOT_FOUND,
                "Approval not found",
                f"Approval request '{approval_id}' not found.",
                correlation_id,
            )
            return

        if approval.get("status") != "pending":
            self._send_error_response(
                HTTPStatus.CONFLICT,
                "Invalid state",
                f"Approval '{approval_id}' is not in pending state (current: {approval.get('status')}).",
                correlation_id,
            )
            return

        with self.server.state.lock:
            approval["status"] = "approved"
            approval["resolved_at"] = time.time()
            approval["resolved_by"] = self.headers.get(VALID_API_KEY_HEADER, "unknown")

        response = {
            "approval_id": approval_id,
            "status": "approved",
            "resolved_at": approval["resolved_at"],
        }
        self._send_json_response(response, correlation_id=correlation_id)

    def handle_deny(self, correlation_id: str, approval_id: str, **kwargs: Any) -> None:
        """Handle POST /v1/approvals/{id}/deny - Deny a pending request.

        Args:
            correlation_id: Request correlation ID.
            approval_id: The approval request identifier.
            **kwargs: Additional route parameters.
        """
        approval = self.server.state.approvals.get(approval_id)
        if not approval:
            self._send_error_response(
                HTTPStatus.NOT_FOUND,
                "Approval not found",
                f"Approval request '{approval_id}' not found.",
                correlation_id,
            )
            return

        if approval.get("status") != "pending":
            self._send_error_response(
                HTTPStatus.CONFLICT,
                "Invalid state",
                f"Approval '{approval_id}' is not in pending state (current: {approval.get('status')}).",
                correlation_id,
            )
            return

        body = self._parse_json_body()
        reason = ""
        if body:
            reason = body.get("reason", "")

        with self.server.state.lock:
            approval["status"] = "denied"
            approval["resolved_at"] = time.time()
            approval["resolved_by"] = self.headers.get(VALID_API_KEY_HEADER, "unknown")
            approval["denial_reason"] = reason

        response = {
            "approval_id": approval_id,
            "status": "denied",
            "reason": reason,
            "resolved_at": approval["resolved_at"],
        }
        self._send_json_response(response, correlation_id=correlation_id)

    def handle_metrics(self, correlation_id: str, **kwargs: Any) -> None:
        """Handle GET /v1/metrics - Prometheus-format metrics.

        Args:
            correlation_id: Request correlation ID.
            **kwargs: Additional route parameters.
        """
        metrics = self.server.state.metrics
        lines: List[str] = [
            "# HELP identity_guard_requests_total Total number of API requests",
            "# TYPE identity_guard_requests_total counter",
            f"identity_guard_requests_total {metrics.get('requests_total', 0)}",
            "",
            "# HELP identity_guard_requests_authorized Total authorized requests",
            "# TYPE identity_guard_requests_authorized counter",
            f"identity_guard_requests_authorized {metrics.get('requests_authorized', 0)}",
            "",
            "# HELP identity_guard_requests_denied Total denied requests",
            "# TYPE identity_guard_requests_denied counter",
            f"identity_guard_requests_denied {metrics.get('requests_denied', 0)}",
            "",
            "# HELP identity_guard_errors_total Total errors",
            "# TYPE identity_guard_errors_total counter",
            f"identity_guard_errors_total {metrics.get('errors_total', 0)}",
            "",
            "# HELP identity_guard_agents_registered Total registered agents",
            "# TYPE identity_guard_agents_registered gauge",
            f"identity_guard_agents_registered {metrics.get('agents_registered', 0)}",
            "",
            "# HELP identity_guard_policies_loaded Total loaded policies",
            "# TYPE identity_guard_policies_loaded gauge",
            f"identity_guard_policies_loaded {metrics.get('policies_loaded', 0)}",
            "",
            "# HELP identity_guard_uptime_seconds Server uptime in seconds",
            "# TYPE identity_guard_uptime_seconds gauge",
            f"identity_guard_uptime_seconds {time.monotonic() - self.server.state.start_time:.2f}",
            "",
        ]
        self._send_text_response(
            "\n".join(lines),
            content_type="text/plain; version=0.0.4; charset=utf-8",
            correlation_id=correlation_id,
        )

    def handle_health(self, correlation_id: str, **kwargs: Any) -> None:
        """Handle GET /v1/health - Health check endpoint.

        Args:
            correlation_id: Request correlation ID.
            **kwargs: Additional route parameters.
        """
        uptime = time.monotonic() - self.server.state.start_time
        response = {
            "status": "healthy",
            "version": SERVER_VERSION,
            "uptime": round(uptime, 2),
            "agents_count": len(self.server.state.agents),
            "policies_count": len(self.server.state.policies),
        }
        self._send_json_response(response, correlation_id=correlation_id)

    def handle_health_ready(self, correlation_id: str, **kwargs: Any) -> None:
        """Handle GET /v1/health/ready - Readiness probe.

        Args:
            correlation_id: Request correlation ID.
            **kwargs: Additional route parameters.
        """
        # Check if the server is ready to serve traffic
        is_ready = True
        checks: Dict[str, str] = {}

        # Check state store availability
        try:
            _ = self.server.state.agents
            checks["state_store"] = "ok"
        except Exception:
            checks["state_store"] = "error"
            is_ready = False

        # Check rate limiter
        try:
            _ = self.server.state.get_rate_limiter("health-check")
            checks["rate_limiter"] = "ok"
        except Exception:
            checks["rate_limiter"] = "error"
            is_ready = False

        status_code = HTTPStatus.OK if is_ready else HTTPStatus.SERVICE_UNAVAILABLE
        response = {
            "ready": is_ready,
            "checks": checks,
        }
        self._send_json_response(response, status=status_code, correlation_id=correlation_id)

    # -------------------------------------------------------------------
    # Internal helper methods
    # -------------------------------------------------------------------

    def _calculate_risk_score(self, agent_id: str, action: str, resource: str) -> float:
        """Calculate a risk score for an authorization request.

        Args:
            agent_id: The requesting agent's ID.
            action: The requested action.
            resource: The target resource.

        Returns:
            Risk score between 0.0 and 1.0.
        """
        score = 0.0

        # Higher risk for destructive actions
        high_risk_actions = {"delete", "terminate", "destroy", "drop", "purge"}
        medium_risk_actions = {"write", "update", "modify", "create", "put"}

        action_lower = action.lower()
        if any(a in action_lower for a in high_risk_actions):
            score += 0.5
        elif any(a in action_lower for a in medium_risk_actions):
            score += 0.3
        else:
            score += 0.1

        # Higher risk for sensitive resources
        sensitive_patterns = ["iam", "kms", "secrets", "credentials", "prod", "production"]
        resource_lower = resource.lower()
        if any(p in resource_lower for p in sensitive_patterns):
            score += 0.3

        # Cap at 1.0
        return min(score, 1.0)

    def _get_agent_risk_score(self, agent_id: str) -> float:
        """Get the current risk score for an agent.

        Args:
            agent_id: The agent identifier.

        Returns:
            Current risk score.
        """
        agent = self.server.state.agents.get(agent_id, {})
        return agent.get("risk_score", 0.0)

    def _compute_effective_permissions(self, agent_id: str) -> List[Dict[str, Any]]:
        """Compute effective permissions for an agent from policies.

        Args:
            agent_id: The agent identifier.

        Returns:
            List of permission dictionaries.
        """
        agent = self.server.state.agents.get(agent_id, {})
        base_permissions = agent.get("permissions", [])

        # Merge with policy-granted permissions
        effective: List[Dict[str, Any]] = []
        for perm in base_permissions:
            if isinstance(perm, dict):
                effective.append(perm)
            elif isinstance(perm, str):
                effective.append({
                    "action": perm,
                    "resource": "*",
                    "effect": "allow",
                    "source": "agent_config",
                })

        # Check policies for additional permissions
        for policy in self.server.state.policies.values():
            if policy.get("status") != "active":
                continue
            for rule in policy.get("rules", []):
                applicable_agents = rule.get("agents", ["*"])
                if "*" in applicable_agents or agent_id in applicable_agents:
                    effective.append({
                        "action": rule.get("action", "*"),
                        "resource": rule.get("resource", "*"),
                        "effect": rule.get("effect", "allow"),
                        "source": f"policy:{policy['policy_id']}",
                        "conditions": rule.get("conditions", {}),
                    })

        return effective

    def _analyze_attack_paths(self, agent_id: str) -> List[Dict[str, Any]]:
        """Analyze potential attack paths for an agent.

        Args:
            agent_id: The agent identifier.

        Returns:
            List of discovered attack path descriptions.
        """
        agent = self.server.state.agents.get(agent_id, {})
        permissions = agent.get("permissions", [])
        attack_paths: List[Dict[str, Any]] = []

        # Check for privilege escalation paths
        escalation_actions = {"iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy",
                             "sts:AssumeRole", "iam:CreateUser", "iam:CreateAccessKey"}

        for perm in permissions:
            action = perm if isinstance(perm, str) else perm.get("action", "")
            if action in escalation_actions:
                attack_paths.append({
                    "type": "privilege_escalation",
                    "severity": "high",
                    "description": f"Agent has '{action}' permission which could allow privilege escalation.",
                    "action": action,
                    "mitigation": "Apply least-privilege principle. Restrict resource scope.",
                })

        # Check for lateral movement
        lateral_actions = {"ec2:RunInstances", "lambda:InvokeFunction", "ssm:SendCommand"}
        for perm in permissions:
            action = perm if isinstance(perm, str) else perm.get("action", "")
            if action in lateral_actions:
                attack_paths.append({
                    "type": "lateral_movement",
                    "severity": "medium",
                    "description": f"Agent has '{action}' permission enabling lateral movement.",
                    "action": action,
                    "mitigation": "Restrict to specific resource ARNs.",
                })

        # Check for data exfiltration
        exfil_actions = {"s3:GetObject", "s3:ListBucket", "dynamodb:Scan", "rds:CreateDBSnapshot"}
        for perm in permissions:
            action = perm if isinstance(perm, str) else perm.get("action", "")
            if action in exfil_actions:
                attack_paths.append({
                    "type": "data_exfiltration",
                    "severity": "medium",
                    "description": f"Agent has '{action}' permission which could enable data exfiltration.",
                    "action": action,
                    "mitigation": "Implement VPC endpoints and restrict network egress.",
                })

        return attack_paths

    def _assess_agent_risk(self, agent_id: str) -> Dict[str, Any]:
        """Perform a comprehensive risk assessment for an agent.

        Args:
            agent_id: The agent identifier.

        Returns:
            Risk assessment dictionary.
        """
        agent = self.server.state.agents.get(agent_id, {})
        permissions = agent.get("permissions", [])
        attack_paths = self._analyze_attack_paths(agent_id)

        # Calculate composite risk score
        base_score = 0.0

        # Permission count contributes to risk
        perm_count = len(permissions)
        if perm_count > 20:
            base_score += 0.3
        elif perm_count > 10:
            base_score += 0.2
        elif perm_count > 5:
            base_score += 0.1

        # Attack paths contribute to risk
        high_severity = sum(1 for p in attack_paths if p.get("severity") == "high")
        medium_severity = sum(1 for p in attack_paths if p.get("severity") == "medium")
        base_score += high_severity * 0.2
        base_score += medium_severity * 0.1

        # Wildcard permissions are risky
        for perm in permissions:
            action = perm if isinstance(perm, str) else perm.get("action", "")
            resource = "" if isinstance(perm, str) else perm.get("resource", "")
            if "*" in action or resource == "*":
                base_score += 0.15

        overall_score = min(base_score, 1.0)

        # Determine risk level
        if overall_score >= 0.7:
            risk_level = "critical"
        elif overall_score >= 0.5:
            risk_level = "high"
        elif overall_score >= 0.3:
            risk_level = "medium"
        else:
            risk_level = "low"

        # Update agent risk score
        with self.server.state.lock:
            if agent_id in self.server.state.agents:
                self.server.state.agents[agent_id]["risk_score"] = overall_score

        return {
            "agent_id": agent_id,
            "risk_score": round(overall_score, 4),
            "risk_level": risk_level,
            "factors": {
                "permission_count": perm_count,
                "attack_paths_found": len(attack_paths),
                "high_severity_paths": high_severity,
                "medium_severity_paths": medium_severity,
            },
            "attack_paths": attack_paths,
            "recommendations": self._generate_recommendations(agent_id, attack_paths),
            "assessed_at": time.time(),
        }

    def _generate_recommendations(
        self, agent_id: str, attack_paths: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate security recommendations based on risk analysis.

        Args:
            agent_id: The agent identifier.
            attack_paths: Discovered attack paths.

        Returns:
            List of recommendation strings.
        """
        recommendations: List[str] = []

        if any(p.get("type") == "privilege_escalation" for p in attack_paths):
            recommendations.append(
                "Remove or restrict IAM management permissions to prevent privilege escalation."
            )

        if any(p.get("type") == "lateral_movement" for p in attack_paths):
            recommendations.append(
                "Restrict compute and invocation permissions to specific resource ARNs."
            )

        if any(p.get("type") == "data_exfiltration" for p in attack_paths):
            recommendations.append(
                "Implement data loss prevention controls and restrict data access scope."
            )

        if not recommendations:
            recommendations.append("Agent permissions are within acceptable risk parameters.")

        return recommendations

    def _find_applicable_policy(self, agent_id: str, action: str, resource: str) -> Optional[str]:
        """Find the first applicable policy for a given request.

        Args:
            agent_id: The requesting agent's ID.
            action: The requested action.
            resource: The target resource.

        Returns:
            Policy ID of the applicable policy, or None.
        """
        for policy_id, policy in self.server.state.policies.items():
            if policy.get("status") != "active":
                continue
            for rule in policy.get("rules", []):
                rule_action = rule.get("action", "*")
                rule_resource = rule.get("resource", "*")
                applicable_agents = rule.get("agents", ["*"])

                # Check agent match
                if "*" not in applicable_agents and agent_id not in applicable_agents:
                    continue

                # Check action match (simple glob)
                if rule_action != "*" and not self._pattern_matches(rule_action, action):
                    continue

                # Check resource match
                if rule_resource != "*" and not self._pattern_matches(rule_resource, resource):
                    continue

                return policy_id
        return None

    def _evaluate_against_policies(
        self, agent_id: str, action: str, resource: str
    ) -> List[Dict[str, Any]]:
        """Evaluate an action against all active policies.

        Args:
            agent_id: The agent identifier.
            action: The requested action.
            resource: The target resource.

        Returns:
            List of evaluation results per policy.
        """
        results: List[Dict[str, Any]] = []

        for policy_id, policy in self.server.state.policies.items():
            if policy.get("status") != "active":
                continue

            policy_result: Dict[str, Any] = {
                "policy_id": policy_id,
                "policy_name": policy.get("name", ""),
                "decision": "allow",
                "matched_rules": [],
            }

            for rule in policy.get("rules", []):
                rule_action = rule.get("action", "*")
                rule_resource = rule.get("resource", "*")
                applicable_agents = rule.get("agents", ["*"])
                effect = rule.get("effect", "allow")

                # Check if rule applies
                agent_match = "*" in applicable_agents or agent_id in applicable_agents
                action_match = rule_action == "*" or self._pattern_matches(rule_action, action)
                resource_match = rule_resource == "*" or self._pattern_matches(rule_resource, resource)

                if agent_match and action_match and resource_match:
                    policy_result["matched_rules"].append(rule)
                    if effect == "deny":
                        policy_result["decision"] = "deny"

            results.append(policy_result)

        return results

    def _validate_policy_rules(self, rules: List[Any]) -> List[str]:
        """Validate policy rules structure.

        Args:
            rules: List of rule objects to validate.

        Returns:
            List of validation error messages (empty if valid).
        """
        errors: List[str] = []

        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                errors.append(f"Rule {i}: must be an object")
                continue

            if "effect" in rule and rule["effect"] not in ("allow", "deny"):
                errors.append(f"Rule {i}: 'effect' must be 'allow' or 'deny'")

            if "action" not in rule and "resource" not in rule:
                errors.append(f"Rule {i}: must specify at least 'action' or 'resource'")

        return errors

    @staticmethod
    def _pattern_matches(pattern: str, value: str) -> bool:
        """Simple glob-style pattern matching.

        Supports '*' as a wildcard for any sequence of characters.

        Args:
            pattern: Pattern with optional '*' wildcards.
            value: String to match against.

        Returns:
            True if the value matches the pattern.
        """
        # Convert glob pattern to regex
        regex_pattern = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
        return bool(re.match(regex_pattern, value, re.IGNORECASE))


# ---------------------------------------------------------------------------
# Custom HTTP Server
# ---------------------------------------------------------------------------


class IdentityGuardHTTPServer(HTTPServer):
    """Custom HTTPServer with shared application state.

    Attributes:
        state: Shared API state for all request handlers.
    """

    state: APIState

    def __init__(
        self,
        server_address: Tuple[str, int],
        handler_class: type,
        state: Optional[APIState] = None,
    ) -> None:
        """Initialize the HTTP server with shared state.

        Args:
            server_address: (host, port) tuple.
            handler_class: Request handler class.
            state: Shared API state (created if not provided).
        """
        self.state = state if state is not None else APIState()
        super().__init__(server_address, handler_class)


# ---------------------------------------------------------------------------
# API Server (public interface)
# ---------------------------------------------------------------------------


class APIServer:
    """High-level API server for AWS Agent Identity Guard.

    Provides start/stop lifecycle management for the HTTP server.

    Example:
        >>> server = APIServer()
        >>> server.start("0.0.0.0", 8080)
        >>> # Server is running in background thread
        >>> server.stop()
    """

    def __init__(self, state: Optional[APIState] = None) -> None:
        """Initialize the API server.

        Args:
            state: Optional shared state. Created automatically if not provided.
        """
        self._state: APIState = state if state is not None else APIState()
        self._server: Optional[IdentityGuardHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running: bool = False

    @property
    def state(self) -> APIState:
        """Access the shared API state.

        Returns:
            The APIState instance used by this server.
        """
        return self._state

    @property
    def is_running(self) -> bool:
        """Check if the server is currently running.

        Returns:
            True if the server is running, False otherwise.
        """
        return self._running

    def start(self, host: str = "0.0.0.0", port: int = 8080) -> None:
        """Start the API server in a background thread.

        Args:
            host: Host address to bind to.
            port: Port number to listen on.

        Raises:
            RuntimeError: If the server is already running.
            OSError: If the port is already in use.
        """
        if self._running:
            raise RuntimeError("Server is already running")

        self._state.start_time = time.monotonic()
        self._server = IdentityGuardHTTPServer(
            (host, port),
            APIHandler,
            state=self._state,
        )

        self._thread = threading.Thread(
            target=self._serve,
            name="identity-guard-api",
            daemon=True,
        )
        self._running = True
        self._thread.start()

        logger.info(
            json.dumps({
                "event": "server_started",
                "host": host,
                "port": port,
                "version": SERVER_VERSION,
            })
        )

    def stop(self) -> None:
        """Stop the API server gracefully.

        Shuts down the HTTP server and waits for the background thread to exit.
        """
        if not self._running:
            return

        self._running = False

        if self._server:
            self._server.shutdown()
            self._server.server_close()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

        logger.info(
            json.dumps({
                "event": "server_stopped",
                "uptime": time.monotonic() - self._state.start_time,
            })
        )

        self._server = None
        self._thread = None

    def _serve(self) -> None:
        """Internal method to run the server loop."""
        if self._server:
            self._server.serve_forever()

    def add_api_key(self, key: str) -> None:
        """Add a valid API key for authentication.

        Args:
            key: The API key string to authorize.
        """
        self._state.api_keys.add(key)

    def remove_api_key(self, key: str) -> None:
        """Remove an API key from the valid set.

        Args:
            key: The API key string to revoke.
        """
        self._state.api_keys.discard(key)

    def create_approval_request(
        self,
        agent_id: str,
        action: str,
        resource: str,
        reason: str = "",
    ) -> str:
        """Create a new approval request programmatically.

        Args:
            agent_id: The requesting agent's ID.
            action: The action requiring approval.
            resource: The target resource.
            reason: Reason for the request.

        Returns:
            The generated approval ID.
        """
        approval_id = str(uuid.uuid4())
        approval_record: Dict[str, Any] = {
            "approval_id": approval_id,
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "reason": reason,
            "status": "pending",
            "created_at": time.time(),
            "resolved_at": None,
            "resolved_by": None,
        }

        with self._state.lock:
            self._state.approvals[approval_id] = approval_record

        return approval_id
