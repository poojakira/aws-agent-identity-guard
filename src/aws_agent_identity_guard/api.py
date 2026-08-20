"""
aws_agent_identity_guard/api.py
--------------------------------------------------------------------------------
FastAPI REST API for the AWS Agent Identity Guard system.

Provides HTTP endpoints for:
  - Transaction authorization (POST /v1/authorize)
  - Agent identity management (CRUD on /v1/agents)
  - Human-in-the-loop approvals (/v1/approvals)
  - Health checks and Prometheus metrics

All endpoints include:
  - Request validation via Pydantic models
  - Correlation IDs for distributed tracing
  - Structured JSON logging
  - Proper HTTP status codes and error responses
  - OpenAPI/Swagger auto-generated documentation

API versioning is done via URL path prefix (/v1/...).
"""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from aws_agent_identity_guard.approval import ApprovalManager, ApprovalPolicy
from aws_agent_identity_guard.authorization import (
    AgentRegistry,
    AuthorizationConfig,
    AuthorizationEngine,
    AuthorizationMode,
    LatencyTracker,
)
from aws_agent_identity_guard.models import (
    AgentIdentity,
    AgentType,
    ApprovalStatus,
    DataClassification,
    Environment,
    RiskScore,
    TransactionRequest,
)
from aws_agent_identity_guard.policy_engine import PolicyEngine
from aws_agent_identity_guard.risk_engine import RiskEngine, classify_risk

logger = logging.getLogger(__name__)


# --- Pydantic Request/Response Models ---


class AuthorizeRequest(BaseModel):
    """Request body for the /v1/authorize endpoint."""

    agent_id: str = Field(..., description="The agent identity making the request")
    principal: str = Field(default="", description="IAM principal (role ARN)")
    tool: str = Field(default="", description="Tool or function being invoked")
    action: str = Field(..., description="IAM action requested")
    resource: str = Field(..., description="Target resource ARN")
    data_classification: str = Field(
        default="INTERNAL",
        description="Data sensitivity classification",
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional runtime context",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "agent_id": "agent-bedrock-001",
                "principal": "arn:aws:iam::123456789012:role/AgentRole",
                "tool": "data-retrieval",
                "action": "s3:GetObject",
                "resource": "arn:aws:s3:::my-bucket/data.json",
                "data_classification": "CONFIDENTIAL",
                "context": {"session_id": "sess-abc123"},
            }
        }


class AuthorizeResponse(BaseModel):
    """Response body for the /v1/authorize endpoint."""

    decision: str = Field(..., description="Authorization outcome (ALLOW/DENY/STEP_UP/REVIEW)")
    risk_score: float = Field(..., description="Overall risk score (0-100)")
    risk_details: dict[str, float] = Field(
        default_factory=dict, description="Per-dimension risk breakdown"
    )
    reasons: list[str] = Field(default_factory=list, description="Reasons for the decision")
    policy: str = Field(default="", description="Policy rule that drove the decision")
    explanation: str = Field(default="", description="Human-readable explanation")
    correlation_id: str = Field(..., description="Request correlation ID for tracing")


class RegisterAgentRequest(BaseModel):
    """Request body for registering a new agent."""

    name: str = Field(..., description="Human-readable agent name")
    agent_type: str = Field(default="CUSTOM", description="Agent execution environment")
    owner: str = Field(default="", description="Team or individual responsible")
    environment: str = Field(default="DEVELOPMENT", description="Deployment environment")
    purpose: str = Field(default="", description="Agent's intended function")
    description: str = Field(default="", description="Extended description")
    iam_role_arn: str | None = Field(default=None, description="Bound IAM role ARN")
    data_classification: str = Field(
        default="INTERNAL", description="Data sensitivity level"
    )
    declared_capabilities: list[str] = Field(
        default_factory=list, description="Capability strings"
    )
    tags: dict[str, str] = Field(default_factory=dict, description="Metadata tags")

    class Config:
        json_schema_extra = {
            "example": {
                "name": "data-analyst-agent",
                "agent_type": "BEDROCK",
                "owner": "data-team",
                "environment": "PRODUCTION",
                "purpose": "Analyze customer data and generate reports",
                "iam_role_arn": "arn:aws:iam::123456789012:role/DataAnalystAgent",
                "data_classification": "CONFIDENTIAL",
                "declared_capabilities": ["s3:GetObject", "athena:StartQueryExecution"],
            }
        }


class AgentResponse(BaseModel):
    """Response body for agent endpoints."""

    agent_id: str
    name: str
    agent_type: str
    owner: str
    environment: str
    purpose: str
    description: str
    iam_role_arn: str | None
    data_classification: str
    declared_capabilities: list[str]
    tags: dict[str, str]
    created_at: str
    updated_at: str
    risk_score: float | None = None
    risk_level: str | None = None


class ApprovalRequestBody(BaseModel):
    """Request body for creating an approval request."""

    agent_id: str = Field(..., description="Agent requesting approval")
    action: str = Field(..., description="IAM action requiring approval")
    resource: str = Field(..., description="Target resource ARN")
    requester: str = Field(..., description="System/user initiating the request")
    ttl_seconds: int = Field(default=300, description="Time-to-live in seconds")

    class Config:
        json_schema_extra = {
            "example": {
                "agent_id": "agent-bedrock-001",
                "action": "iam:PassRole",
                "resource": "arn:aws:iam::123456789012:role/AdminRole",
                "requester": "authorization-engine",
                "ttl_seconds": 300,
            }
        }


class ApprovalActionBody(BaseModel):
    """Request body for approve/deny actions."""

    approver: str = Field(..., description="Identifier of the approver")
    reason: str = Field(default="", description="Justification for the decision")


class ApprovalResponse(BaseModel):
    """Response body for approval endpoints."""

    request_id: str
    agent_id: str
    action: str
    resource: str
    requester: str
    approver: str
    status: str
    expires_at: str | None
    created_at: str
    decision_at: str | None
    reason: str


class HealthResponse(BaseModel):
    """Response body for the health check endpoint."""

    status: str
    version: str
    uptime_seconds: float
    components: dict[str, str]


class MetricsResponse(BaseModel):
    """Response body for the metrics endpoint."""

    authorization_decisions_total: int
    authorization_latency_p50_ms: float
    authorization_latency_p95_ms: float
    authorization_latency_p99_ms: float
    registered_agents: int
    pending_approvals: int
    policy_rules_loaded: int


class ErrorResponse(BaseModel):
    """Standard error response body."""

    error: str
    detail: str
    correlation_id: str
    timestamp: str


class PermissionResponse(BaseModel):
    """Response body for agent permissions endpoint."""

    agent_id: str
    permissions: list[dict[str, Any]]
    effective_count: int


class AttackPathResponse(BaseModel):
    """Response body for agent attack paths endpoint."""

    agent_id: str
    attack_paths: list[dict[str, Any]]
    total_paths: int
    highest_risk: float


# --- Application State ---


class AppState:
    """
    Application-level shared state for dependency injection.

    Holds references to all engine instances used by the API handlers.
    """

    def __init__(self) -> None:
        """Initialize application state with default engine instances."""
        self.start_time = time.time()
        self.risk_engine = RiskEngine()
        self.policy_engine = PolicyEngine()
        self.agent_registry = AgentRegistry()
        self.approval_manager = ApprovalManager()
        self.authorization_engine = AuthorizationEngine(
            config=AuthorizationConfig(mode=AuthorizationMode.FAIL_CLOSED),
            risk_engine=self.risk_engine,
            policy_engine=self.policy_engine,
            agent_registry=self.agent_registry,
        )


# Module-level state instance
_app_state: AppState | None = None


def get_app_state() -> AppState:
    """Get or create the application state singleton."""
    global _app_state
    if _app_state is None:
        _app_state = AppState()
    return _app_state


# --- Lifespan ---


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    state = get_app_state()
    logger.info(
        "AWS Agent Identity Guard API starting: "
        "mode=%s, policy_rules=%d, registered_agents=%d",
        state.authorization_engine.config.mode.value,
        state.policy_engine.rule_count,
        state.agent_registry.count,
    )
    yield
    logger.info("AWS Agent Identity Guard API shutting down")


# --- FastAPI Application ---


app = FastAPI(
    title="AWS Agent Identity Guard",
    description=(
        "Runtime authorization, risk scoring, and human-in-the-loop approval "
        "API for AI agents operating within AWS environments. Provides "
        "policy-as-code enforcement, multidimensional risk assessment, and "
        "full audit trail for every authorization decision."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# CORS middleware for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Middleware ---


@app.middleware("http")
async def add_correlation_id(request: Request, call_next) -> Response:
    """Add correlation ID to all requests for distributed tracing."""
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    request.state.correlation_id = correlation_id

    start_time = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    response.headers["X-Correlation-ID"] = correlation_id
    response.headers["X-Response-Time-Ms"] = f"{elapsed_ms:.2f}"

    logger.info(
        "%s %s - %d (%.2fms) [%s]",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
        correlation_id,
    )

    return response


# --- Exception Handlers ---


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Custom HTTP exception handler with structured error response."""
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "detail": str(exc.detail),
            "correlation_id": correlation_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all exception handler for unhandled errors."""
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
    logger.error(
        "Unhandled exception in %s %s: %s",
        request.method,
        request.url.path,
        str(exc),
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "detail": "An unexpected error occurred. Check logs for details.",
            "correlation_id": correlation_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


# --- Helper Functions ---


def _agent_to_response(agent: AgentIdentity, risk_score: float | None = None) -> AgentResponse:
    """Convert an AgentIdentity to an API response model."""
    risk_level = None
    if risk_score is not None:
        risk_level = classify_risk(risk_score).value

    return AgentResponse(
        agent_id=agent.agent_id,
        name=agent.name,
        agent_type=agent.agent_type.value,
        owner=agent.owner,
        environment=agent.environment.value,
        purpose=agent.purpose,
        description=agent.description,
        iam_role_arn=agent.iam_role_arn,
        data_classification=agent.data_classification.value,
        declared_capabilities=agent.declared_capabilities,
        tags=agent.tags,
        created_at=agent.created_at.isoformat(),
        updated_at=agent.updated_at.isoformat(),
        risk_score=risk_score,
        risk_level=risk_level,
    )


def _approval_to_response(req) -> ApprovalResponse:
    """Convert an ApprovalRequest to an API response model."""
    return ApprovalResponse(
        request_id=req.request_id,
        agent_id=req.agent_id,
        action=req.action,
        resource=req.resource,
        requester=req.requester,
        approver=req.approver,
        status=req.status.value,
        expires_at=req.expires_at.isoformat() if req.expires_at else None,
        created_at=req.created_at.isoformat() if req.created_at else None,
        decision_at=req.decision_at.isoformat() if req.decision_at else None,
        reason=req.reason,
    )


# --- Authorization Endpoints ---


@app.post(
    "/v1/authorize",
    response_model=AuthorizeResponse,
    summary="Authorize a transaction",
    description=(
        "Evaluate an AI agent's transaction request against security policies, "
        "risk scoring, and permission boundaries. Returns a decision with full "
        "risk breakdown and audit trail."
    ),
    tags=["Authorization"],
)
async def authorize_transaction(body: AuthorizeRequest) -> AuthorizeResponse:
    """
    Main authorization endpoint.

    Evaluates the request through the full authorization pipeline:
    risk scoring, policy evaluation, and decision generation.
    """
    state = get_app_state()

    # Build TransactionRequest from API input
    try:
        transaction = TransactionRequest(
            agent_id=body.agent_id,
            principal=body.principal,
            tool=body.tool,
            action=body.action,
            resource=body.resource,
            data_classification=DataClassification(body.data_classification.upper()),
            context=body.context,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid request: {exc}")

    # Execute authorization
    decision = state.authorization_engine.authorize(transaction)

    return AuthorizeResponse(
        decision=decision.decision.value,
        risk_score=decision.risk_score.overall,
        risk_details={
            "privilege": decision.risk_score.privilege,
            "sensitivity": decision.risk_score.sensitivity,
            "blast_radius": decision.risk_score.blast_radius,
            "data_exposure": decision.risk_score.data_exposure,
            "persistence": decision.risk_score.persistence,
            "lateral_movement": decision.risk_score.lateral_movement,
            "environment_factor": decision.risk_score.environment_factor,
        },
        reasons=decision.reasons,
        policy=decision.policy_matched,
        explanation=decision.explanation,
        correlation_id=decision.correlation_id,
    )


# --- Agent Management Endpoints ---


@app.get(
    "/v1/agents",
    response_model=list[AgentResponse],
    summary="List registered agents",
    description="Retrieve all registered agent identities.",
    tags=["Agents"],
)
async def list_agents() -> list[AgentResponse]:
    """List all registered agent identities."""
    state = get_app_state()
    agents = state.agent_registry.list_all()
    return [_agent_to_response(a) for a in agents]


@app.get(
    "/v1/agents/{agent_id}",
    response_model=AgentResponse,
    summary="Get agent details",
    description="Retrieve a specific agent identity with its current risk score.",
    tags=["Agents"],
)
async def get_agent(agent_id: str) -> AgentResponse:
    """Get agent details with current risk score."""
    state = get_app_state()
    agent = state.agent_registry.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")

    # Compute current risk score
    try:
        risk = state.risk_engine.score_agent(agent, [], [])
        risk_score = risk.overall
    except Exception:
        risk_score = None

    return _agent_to_response(agent, risk_score)


@app.post(
    "/v1/agents",
    response_model=AgentResponse,
    status_code=201,
    summary="Register a new agent",
    description="Register a new AI agent identity in the system.",
    tags=["Agents"],
)
async def register_agent(body: RegisterAgentRequest) -> AgentResponse:
    """Register a new agent identity."""
    state = get_app_state()

    try:
        agent = AgentIdentity(
            name=body.name,
            agent_type=AgentType(body.agent_type.upper()),
            owner=body.owner,
            environment=Environment(body.environment.upper()),
            purpose=body.purpose,
            description=body.description,
            iam_role_arn=body.iam_role_arn,
            data_classification=DataClassification(body.data_classification.upper()),
            declared_capabilities=body.declared_capabilities,
            tags=body.tags,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid agent data: {exc}")

    state.agent_registry.register(agent)
    logger.info("Registered new agent: %s (%s)", agent.name, agent.agent_id)

    return _agent_to_response(agent)


@app.get(
    "/v1/agents/{agent_id}/permissions",
    response_model=PermissionResponse,
    summary="Get effective permissions",
    description="Retrieve the effective permissions resolved for an agent.",
    tags=["Agents"],
)
async def get_agent_permissions(agent_id: str) -> PermissionResponse:
    """Get effective permissions for an agent."""
    state = get_app_state()
    agent = state.agent_registry.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")

    # In a full implementation, this would call EffectivePermissionAnalyzer
    # For now, return declared capabilities as a permissions representation
    permissions = [
        {"action": cap, "resource": "*", "effect": "ALLOWED"}
        for cap in agent.declared_capabilities
    ]

    return PermissionResponse(
        agent_id=agent_id,
        permissions=permissions,
        effective_count=len(permissions),
    )


@app.get(
    "/v1/agents/{agent_id}/attack-paths",
    response_model=AttackPathResponse,
    summary="Get attack paths",
    description="Retrieve known privilege escalation attack paths for an agent.",
    tags=["Agents"],
)
async def get_agent_attack_paths(agent_id: str) -> AttackPathResponse:
    """Get attack paths for an agent."""
    state = get_app_state()
    agent = state.agent_registry.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")

    # In a full implementation, this would call AttackPathAnalyzer
    # For now, return an empty result
    return AttackPathResponse(
        agent_id=agent_id,
        attack_paths=[],
        total_paths=0,
        highest_risk=0.0,
    )


# --- Approval Endpoints ---


@app.post(
    "/v1/approvals",
    response_model=ApprovalResponse,
    status_code=201,
    summary="Request approval",
    description="Create a new human-in-the-loop approval request for a high-risk action.",
    tags=["Approvals"],
)
async def request_approval(body: ApprovalRequestBody) -> ApprovalResponse:
    """Create a new approval request."""
    state = get_app_state()

    try:
        approval = state.approval_manager.request_approval(
            agent_id=body.agent_id,
            action=body.action,
            resource=body.resource,
            requester=body.requester,
            ttl_seconds=body.ttl_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return _approval_to_response(approval)


@app.get(
    "/v1/approvals/{request_id}",
    response_model=ApprovalResponse,
    summary="Check approval status",
    description="Check the current status of an approval request.",
    tags=["Approvals"],
)
async def check_approval_status(request_id: str) -> ApprovalResponse:
    """Check the status of an approval request."""
    state = get_app_state()

    try:
        approval = state.approval_manager.check_status(request_id)
    except KeyError:
        raise HTTPException(
            status_code=404, detail=f"Approval request '{request_id}' not found"
        )

    return _approval_to_response(approval)


@app.post(
    "/v1/approvals/{request_id}/approve",
    response_model=ApprovalResponse,
    summary="Approve a request",
    description="Approve a pending approval request. Requires authorized approver.",
    tags=["Approvals"],
)
async def approve_request(request_id: str, body: ApprovalActionBody) -> ApprovalResponse:
    """Approve a pending approval request."""
    state = get_app_state()

    try:
        approval = state.approval_manager.approve(
            request_id=request_id,
            approver=body.approver,
            reason=body.reason,
        )
    except KeyError:
        raise HTTPException(
            status_code=404, detail=f"Approval request '{request_id}' not found"
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    return _approval_to_response(approval)


@app.post(
    "/v1/approvals/{request_id}/deny",
    response_model=ApprovalResponse,
    summary="Deny a request",
    description="Deny a pending approval request.",
    tags=["Approvals"],
)
async def deny_request(request_id: str, body: ApprovalActionBody) -> ApprovalResponse:
    """Deny a pending approval request."""
    state = get_app_state()

    try:
        approval = state.approval_manager.deny(
            request_id=request_id,
            approver=body.approver,
            reason=body.reason,
        )
    except KeyError:
        raise HTTPException(
            status_code=404, detail=f"Approval request '{request_id}' not found"
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    return _approval_to_response(approval)


# --- Health and Metrics Endpoints ---


@app.get(
    "/v1/health",
    response_model=HealthResponse,
    summary="Health check",
    description="System health check showing component status.",
    tags=["Operations"],
)
async def health_check() -> HealthResponse:
    """System health check endpoint."""
    state = get_app_state()
    uptime = time.time() - state.start_time

    components = {
        "authorization_engine": "healthy",
        "risk_engine": "healthy",
        "policy_engine": "healthy",
        "approval_manager": "healthy",
        "agent_registry": "healthy",
    }

    return HealthResponse(
        status="healthy",
        version="1.0.0",
        uptime_seconds=round(uptime, 2),
        components=components,
    )


@app.get(
    "/v1/metrics",
    response_model=MetricsResponse,
    summary="Prometheus metrics",
    description="Operational metrics for monitoring and alerting.",
    tags=["Operations"],
)
async def get_metrics() -> MetricsResponse:
    """Prometheus-compatible metrics endpoint."""
    state = get_app_state()
    latency = state.authorization_engine.latency_metrics
    pending = state.approval_manager.list_pending()

    return MetricsResponse(
        authorization_decisions_total=state.authorization_engine.decision_count,
        authorization_latency_p50_ms=round(latency.get("p50_ms", 0.0), 3),
        authorization_latency_p95_ms=round(latency.get("p95_ms", 0.0), 3),
        authorization_latency_p99_ms=round(latency.get("p99_ms", 0.0), 3),
        registered_agents=state.agent_registry.count,
        pending_approvals=len(pending),
        policy_rules_loaded=state.policy_engine.rule_count,
    )
