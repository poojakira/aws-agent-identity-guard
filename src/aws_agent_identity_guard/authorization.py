"""
aws_agent_identity_guard/authorization.py
--------------------------------------------------------------------------------
Transaction authorization engine for AI agent runtime decisions.

This is the central decision-making component that evaluates whether an AI
agent's requested action should be ALLOWED, DENIED, require STEP_UP
authentication, or be sent for human REVIEW.

The authorization flow:
  1. Load and validate the requesting agent identity
  2. Compute the transaction risk score via RiskEngine
  3. Evaluate security policies via PolicyEngine
  4. Check explicit deny rules (always takes precedence)
  5. Check if step-up authentication is required
  6. Build explanation and audit trail
  7. Emit tamper-evident AuditEvent with integrity hash

Operating modes:
  - FAIL_CLOSED (production default): Unknown states default to DENY
  - FAIL_OPEN (development only): Unknown states default to ALLOW with warning

Every decision includes:
  - Structured reasons explaining the logic
  - A risk score with per-dimension breakdown
  - A policy identifier showing which rule drove the decision
  - A correlation ID for distributed tracing
  - An AuditEvent with SHA-256 integrity hash

Performance tracking:
  - Records latency of every authorization decision
  - Exposes p50/p95/p99 percentile metrics
"""

from __future__ import annotations

import logging
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from aws_agent_identity_guard.models import (
    AgentIdentity,
    AuditEvent,
    AuthorizationDecision,
    AuthorizationDecisionType,
    EffectivePermission,
    RiskScore,
    TransactionRequest,
    _generate_uuid,
    _now_utc,
)
from aws_agent_identity_guard.policy_engine import (
    PolicyDecision,
    PolicyEffect,
    PolicyEngine,
)
from aws_agent_identity_guard.risk_engine import RiskEngine, classify_risk

logger = logging.getLogger(__name__)


# --- Configuration ---


class AuthorizationMode(str, Enum):
    """Operating mode for the authorization engine."""

    FAIL_CLOSED = "FAIL_CLOSED"
    FAIL_OPEN = "FAIL_OPEN"


@dataclass
class AuthorizationConfig:
    """
    Configuration for the AuthorizationEngine.

    Attributes:
        mode: Operating mode (FAIL_CLOSED or FAIL_OPEN).
        step_up_threshold: Risk score above which step-up auth is required.
        deny_threshold: Risk score above which the action is auto-denied.
        max_latency_samples: Maximum number of latency samples to retain.
        enable_audit: Whether to emit audit events.
        policy_version: Current policy version identifier.
    """

    mode: AuthorizationMode = AuthorizationMode.FAIL_CLOSED
    step_up_threshold: float = 70.0
    deny_threshold: float = 90.0
    max_latency_samples: int = 10000
    enable_audit: bool = True
    policy_version: str = "1.0.0"


# --- Latency Tracker ---


class LatencyTracker:
    """
    Thread-safe latency tracking for authorization decisions.

    Maintains a sliding window of latency measurements and computes
    p50, p95, and p99 percentiles on demand.
    """

    def __init__(self, max_samples: int = 10000) -> None:
        """
        Initialize the latency tracker.

        Args:
            max_samples: Maximum number of samples to retain in the window.
        """
        self._samples: deque[float] = deque(maxlen=max_samples)
        self._lock = threading.Lock()
        self._total_count: int = 0
        self._total_time: float = 0.0

    def record(self, latency_ms: float) -> None:
        """
        Record a latency measurement.

        Args:
            latency_ms: Latency in milliseconds.
        """
        with self._lock:
            self._samples.append(latency_ms)
            self._total_count += 1
            self._total_time += latency_ms

    @property
    def count(self) -> int:
        """Return total number of measurements recorded."""
        with self._lock:
            return self._total_count

    @property
    def p50(self) -> float:
        """Return the 50th percentile (median) latency in milliseconds."""
        return self._percentile(50)

    @property
    def p95(self) -> float:
        """Return the 95th percentile latency in milliseconds."""
        return self._percentile(95)

    @property
    def p99(self) -> float:
        """Return the 99th percentile latency in milliseconds."""
        return self._percentile(99)

    @property
    def average(self) -> float:
        """Return the average latency in milliseconds."""
        with self._lock:
            if not self._samples:
                return 0.0
            return self._total_time / self._total_count

    def get_metrics(self) -> dict[str, float]:
        """
        Return all latency metrics as a dictionary.

        Returns:
            Dictionary with p50, p95, p99, average, and count.
        """
        return {
            "p50_ms": self.p50,
            "p95_ms": self.p95,
            "p99_ms": self.p99,
            "average_ms": self.average,
            "total_count": float(self.count),
        }

    def _percentile(self, pct: float) -> float:
        """
        Compute a percentile from the current samples.

        Args:
            pct: Percentile to compute (0-100).

        Returns:
            The computed percentile value, or 0.0 if no samples.
        """
        with self._lock:
            if not self._samples:
                return 0.0
            sorted_samples = sorted(self._samples)
            idx = int(len(sorted_samples) * pct / 100)
            idx = min(idx, len(sorted_samples) - 1)
            return sorted_samples[idx]


# --- Agent Registry ---


class AgentRegistry:
    """
    Registry for looking up agent identities.

    Provides a simple in-memory registry for agent identities with
    thread-safe access. Production deployments should back this with
    a persistent store (DynamoDB, PostgreSQL, etc.).
    """

    def __init__(self) -> None:
        """Initialize the agent registry."""
        self._agents: dict[str, AgentIdentity] = {}
        self._lock = threading.Lock()

    def register(self, agent: AgentIdentity) -> None:
        """
        Register an agent identity.

        Args:
            agent: The agent identity to register.
        """
        with self._lock:
            self._agents[agent.agent_id] = agent
            logger.info("Registered agent: %s (%s)", agent.name, agent.agent_id)

    def get(self, agent_id: str) -> AgentIdentity | None:
        """
        Look up an agent by ID.

        Args:
            agent_id: The agent identifier.

        Returns:
            The AgentIdentity, or None if not found.
        """
        with self._lock:
            return self._agents.get(agent_id)

    def list_all(self) -> list[AgentIdentity]:
        """Return all registered agents."""
        with self._lock:
            return list(self._agents.values())

    def remove(self, agent_id: str) -> bool:
        """
        Remove an agent from the registry.

        Args:
            agent_id: The agent to remove.

        Returns:
            True if removed; False if not found.
        """
        with self._lock:
            if agent_id in self._agents:
                del self._agents[agent_id]
                return True
            return False

    @property
    def count(self) -> int:
        """Return the number of registered agents."""
        with self._lock:
            return len(self._agents)


# --- Authorization Engine ---


class AuthorizationEngine:
    """
    Central transaction authorization engine for AI agent actions.

    Evaluates agent transaction requests by integrating risk scoring,
    policy evaluation, and audit trail generation. Supports both
    fail-closed (production) and fail-open (development) modes.

    Usage:
        engine = AuthorizationEngine(
            config=AuthorizationConfig(mode=AuthorizationMode.FAIL_CLOSED),
            risk_engine=RiskEngine(),
            policy_engine=policy_engine,
        )
        engine.agent_registry.register(agent)
        decision = engine.authorize(transaction_request)

    Thread Safety:
        All public methods are thread-safe. The engine can handle concurrent
        authorization requests without external synchronization.
    """

    def __init__(
        self,
        config: AuthorizationConfig | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        agent_registry: AgentRegistry | None = None,
    ) -> None:
        """
        Initialize the authorization engine.

        Args:
            config: Engine configuration. Defaults to FAIL_CLOSED production mode.
            risk_engine: Risk scoring engine instance.
            policy_engine: Policy evaluation engine instance.
            agent_registry: Agent identity registry.
        """
        self._config = config or AuthorizationConfig()
        self._risk_engine = risk_engine or RiskEngine()
        self._policy_engine = policy_engine or PolicyEngine()
        self._agent_registry = agent_registry or AgentRegistry()
        self._latency_tracker = LatencyTracker(
            max_samples=self._config.max_latency_samples
        )
        self._audit_events: list[AuditEvent] = []
        self._audit_lock = threading.Lock()
        self._decision_count: int = 0
        self._decision_lock = threading.Lock()

        logger.info(
            "AuthorizationEngine initialized: mode=%s, step_up_threshold=%.1f, "
            "deny_threshold=%.1f",
            self._config.mode.value,
            self._config.step_up_threshold,
            self._config.deny_threshold,
        )

    @property
    def config(self) -> AuthorizationConfig:
        """Return the engine configuration."""
        return self._config

    @property
    def agent_registry(self) -> AgentRegistry:
        """Return the agent registry."""
        return self._agent_registry

    @property
    def latency_metrics(self) -> dict[str, float]:
        """Return latency percentile metrics."""
        return self._latency_tracker.get_metrics()

    @property
    def decision_count(self) -> int:
        """Return total number of decisions made."""
        with self._decision_lock:
            return self._decision_count

    @property
    def audit_events(self) -> list[AuditEvent]:
        """Return the audit event log."""
        with self._audit_lock:
            return list(self._audit_events)

    def authorize(self, request: TransactionRequest) -> AuthorizationDecision:
        """
        Evaluate a transaction request and produce an authorization decision.

        This is the primary entry point for all authorization checks. The method:
          1. Validates the request
          2. Loads the agent identity
          3. Computes a risk score for the transaction
          4. Evaluates security policies
          5. Checks for explicit denies and step-up requirements
          6. Builds an explanation and emits an audit event

        Args:
            request: The transaction request to authorize.

        Returns:
            An AuthorizationDecision with the outcome, risk score, reasons,
            and correlation ID.

        Note:
            In FAIL_CLOSED mode, any unexpected error results in DENY.
            In FAIL_OPEN mode, unexpected errors result in ALLOW with warning.
        """
        start_time = time.perf_counter()
        correlation_id = request.request_id or _generate_uuid()

        try:
            # Step 1: Load the agent identity
            agent = self._load_agent(request.agent_id)
            if agent is None:
                decision = self._make_deny_decision(
                    correlation_id=correlation_id,
                    reasons=[f"Agent '{request.agent_id}' not found in registry"],
                    policy_matched="agent-not-found",
                )
                self._record_decision(request, decision, start_time)
                return decision

            # Step 2: Compute risk score
            risk_score, risk_score_is_fallback = self._compute_risk_score(request, agent)

            # If risk scoring failed, apply mode-based default immediately
            if risk_score_is_fallback:
                decision = self._apply_default_decision(
                    correlation_id, risk_score, request
                )
                self._record_decision(request, decision, start_time)
                return decision

            # Step 3: Check if risk score alone warrants auto-deny
            if risk_score.overall >= self._config.deny_threshold:
                decision = self._make_deny_decision(
                    correlation_id=correlation_id,
                    risk_score=risk_score,
                    reasons=[
                        f"Risk score {risk_score.overall:.1f} exceeds "
                        f"deny threshold {self._config.deny_threshold:.1f}",
                        f"Risk level: {classify_risk(risk_score.overall).value}",
                    ],
                    policy_matched="risk-threshold-auto-deny",
                )
                self._record_decision(request, decision, start_time)
                return decision

            # Step 4: Evaluate policies
            effective_permissions = self._get_effective_permissions(request, agent)
            policy_decision, policy_reasons = self._evaluate_policies(
                request, agent, effective_permissions
            )

            # Step 5: Map policy decision to authorization decision
            if policy_decision == PolicyEffect.DENY:
                decision = self._make_deny_decision(
                    correlation_id=correlation_id,
                    risk_score=risk_score,
                    reasons=policy_reasons,
                    policy_matched=", ".join(policy_reasons[:1]) if policy_reasons else "policy-deny",
                )

            elif policy_decision == PolicyEffect.REQUIRE_APPROVAL:
                decision = AuthorizationDecision(
                    decision=AuthorizationDecisionType.REVIEW,
                    risk_score=risk_score,
                    reasons=policy_reasons,
                    policy_matched="require-approval",
                    correlation_id=correlation_id,
                    explanation=self._build_explanation(
                        AuthorizationDecisionType.REVIEW,
                        request,
                        policy_reasons,
                        risk_score,
                    ),
                )

            elif self._check_step_up_required(request, risk_score):
                decision = AuthorizationDecision(
                    decision=AuthorizationDecisionType.STEP_UP,
                    risk_score=risk_score,
                    reasons=[
                        f"Risk score {risk_score.overall:.1f} exceeds "
                        f"step-up threshold {self._config.step_up_threshold:.1f}",
                        *policy_reasons,
                    ],
                    policy_matched="risk-threshold-step-up",
                    correlation_id=correlation_id,
                    explanation=self._build_explanation(
                        AuthorizationDecisionType.STEP_UP,
                        request,
                        policy_reasons,
                        risk_score,
                    ),
                )

            elif policy_decision == PolicyEffect.STEP_UP:
                decision = AuthorizationDecision(
                    decision=AuthorizationDecisionType.STEP_UP,
                    risk_score=risk_score,
                    reasons=policy_reasons,
                    policy_matched="policy-step-up",
                    correlation_id=correlation_id,
                    explanation=self._build_explanation(
                        AuthorizationDecisionType.STEP_UP,
                        request,
                        policy_reasons,
                        risk_score,
                    ),
                )

            elif policy_decision == PolicyEffect.ALLOW:
                decision = AuthorizationDecision(
                    decision=AuthorizationDecisionType.ALLOW,
                    risk_score=risk_score,
                    reasons=policy_reasons,
                    policy_matched="policy-allow",
                    correlation_id=correlation_id,
                    explanation=self._build_explanation(
                        AuthorizationDecisionType.ALLOW,
                        request,
                        policy_reasons,
                        risk_score,
                    ),
                )

            else:
                # No matching policy -- apply mode-based default
                decision = self._apply_default_decision(
                    correlation_id, risk_score, request
                )

            self._record_decision(request, decision, start_time)
            return decision

        except Exception as exc:
            logger.error(
                "Authorization error for request %s: %s",
                correlation_id,
                str(exc),
                exc_info=True,
            )
            decision = self._handle_error(correlation_id, request, exc, start_time)
            return decision

    def _load_agent(self, agent_id: str) -> AgentIdentity | None:
        """
        Load an agent identity from the registry.

        Args:
            agent_id: The agent identifier to look up.

        Returns:
            The AgentIdentity if found, or None.
        """
        agent = self._agent_registry.get(agent_id)
        if agent is None:
            logger.warning("Agent not found: %s", agent_id)
        return agent

    def _evaluate_policies(
        self,
        request: TransactionRequest,
        agent: AgentIdentity,
        effective_permissions: list[EffectivePermission],
    ) -> tuple[PolicyEffect | None, list[str]]:
        """
        Evaluate security policies against the request.

        Delegates to the PolicyEngine and also checks for explicit deny
        patterns in the effective permissions.

        Returns None as the effect when no explicit policy rule matched,
        allowing the authorization engine to apply its mode-based default.

        Args:
            request: The transaction request.
            agent: The agent identity.
            effective_permissions: The agent's resolved permissions.

        Returns:
            A tuple of (PolicyEffect or None, list of reason strings).
            None effect means no explicit policy matched.
        """
        # Check explicit deny in effective permissions first
        if self._check_explicit_deny(request, effective_permissions):
            return (
                PolicyEffect.DENY,
                [
                    f"Explicit DENY in effective permissions for "
                    f"action '{request.action}' on resource '{request.resource}'"
                ],
            )

        # Compute risk score for policy evaluation
        risk_score, _ = self._compute_risk_score(request, agent)

        # Evaluate policy rules
        policy_decision: PolicyDecision = self._policy_engine.evaluate(
            request, agent, risk_score
        )

        reasons = [policy_decision.explanation] if policy_decision.explanation else []
        if policy_decision.matched_rules:
            reasons.append(
                f"Matched rules: {', '.join(policy_decision.matched_rules)}"
            )

        # If no rules explicitly matched, return None to signal "no policy decision"
        # This allows the authorization engine to apply its mode-based default
        if not policy_decision.matched_rules:
            return (None, reasons)

        return (policy_decision.effect, reasons)

    def _check_explicit_deny(
        self,
        request: TransactionRequest,
        policies: list[EffectivePermission],
    ) -> bool:
        """
        Check if any effective permission explicitly denies this request.

        Per AWS IAM evaluation logic, an explicit DENY always overrides
        any ALLOW, regardless of source.

        Args:
            request: The transaction request.
            policies: The agent's effective permissions.

        Returns:
            True if an explicit deny exists for this action/resource.
        """
        import fnmatch

        for perm in policies:
            if perm.effective_effect.value == "DENIED":
                # Check if the action matches
                if fnmatch.fnmatch(
                    request.action.lower(), perm.action.lower()
                ):
                    # Check if the resource matches
                    if fnmatch.fnmatch(
                        request.resource.lower(), perm.resource.lower()
                    ) or perm.resource == "*":
                        return True
        return False

    def _check_step_up_required(
        self, request: TransactionRequest, risk_score: RiskScore
    ) -> bool:
        """
        Determine if the risk score requires step-up authentication.

        Step-up is required when the overall risk exceeds the configured
        threshold but is below the auto-deny threshold.

        Args:
            request: The transaction request.
            risk_score: The computed risk score.

        Returns:
            True if step-up authentication is required.
        """
        return (
            risk_score.overall >= self._config.step_up_threshold
            and risk_score.overall < self._config.deny_threshold
        )

    def _build_explanation(
        self,
        decision: AuthorizationDecisionType,
        request: TransactionRequest,
        reasons: list[str],
        risk_score: RiskScore,
    ) -> str:
        """
        Build a human-readable explanation of the authorization decision.

        Args:
            decision: The decision type.
            request: The original request.
            reasons: List of reasons that contributed to the decision.
            risk_score: The risk score assessment.

        Returns:
            A formatted explanation string suitable for audit logs.
        """
        risk_level = classify_risk(risk_score.overall).value
        parts = [
            f"Decision: {decision.value}",
            f"Agent: {request.agent_id}",
            f"Action: {request.action}",
            f"Resource: {request.resource}",
            f"Risk: {risk_score.overall:.1f}/100 ({risk_level})",
        ]

        if reasons:
            parts.append(f"Reasons: {'; '.join(reasons)}")

        return " | ".join(parts)

    def _emit_audit_event(
        self, request: TransactionRequest, decision: AuthorizationDecision
    ) -> AuditEvent:
        """
        Create and store an audit event for the authorization decision.

        The audit event includes a SHA-256 integrity hash computed over
        all event fields for tamper detection.

        Args:
            request: The original transaction request.
            decision: The authorization decision.

        Returns:
            The created AuditEvent with integrity hash.
        """
        event = AuditEvent(
            event_id=_generate_uuid(),
            correlation_id=decision.correlation_id,
            agent_id=request.agent_id,
            principal=request.principal,
            action=request.action,
            resource=request.resource,
            decision=decision.decision,
            reasons=decision.reasons,
            policy_version=self._config.policy_version,
        )

        with self._audit_lock:
            self._audit_events.append(event)

        logger.debug(
            "Audit event %s: %s for %s/%s (correlation: %s, hash: %s)",
            event.event_id,
            event.decision.value,
            event.action,
            event.resource,
            event.correlation_id,
            event.integrity_hash[:16],
        )

        return event

    def _compute_risk_score(
        self, request: TransactionRequest, agent: AgentIdentity
    ) -> tuple[RiskScore, bool]:
        """
        Compute the risk score for a transaction.

        Args:
            request: The transaction request.
            agent: The agent identity.

        Returns:
            A tuple of (RiskScore, is_fallback). is_fallback is True when
            scoring failed and a default high score was used.
        """
        try:
            score = self._risk_engine.score_transaction(
                transaction=request,
                agent=agent,
                effective_permissions=[],
            )
            return score, False
        except Exception as exc:
            logger.warning(
                "Risk scoring failed for %s, using default high score: %s",
                request.request_id,
                str(exc),
            )
            # Fail-safe: return a high risk score if scoring fails
            return RiskScore(
                overall=75.0,
                privilege=50.0,
                sensitivity=50.0,
                blast_radius=50.0,
                data_exposure=50.0,
                persistence=50.0,
                lateral_movement=50.0,
                environment_factor=1.5,
            ), True

    def _get_effective_permissions(
        self, request: TransactionRequest, agent: AgentIdentity
    ) -> list[EffectivePermission]:
        """
        Get the effective permissions for an agent.

        In a full implementation this would query the EffectivePermissionAnalyzer.
        For now, returns an empty list (policies handle authorization).

        Args:
            request: The transaction request.
            agent: The agent identity.

        Returns:
            List of effective permissions.
        """
        # In production, this would integrate with EffectivePermissionAnalyzer
        # to resolve the full IAM policy evaluation chain
        return []

    def _make_deny_decision(
        self,
        correlation_id: str,
        reasons: list[str],
        policy_matched: str = "",
        risk_score: RiskScore | None = None,
    ) -> AuthorizationDecision:
        """
        Create a DENY authorization decision.

        Args:
            correlation_id: Request correlation ID.
            reasons: List of reasons for denial.
            policy_matched: Identifier of the matching policy.
            risk_score: Optional risk score (defaults to zero-score).

        Returns:
            An AuthorizationDecision with DENY outcome.
        """
        return AuthorizationDecision(
            decision=AuthorizationDecisionType.DENY,
            risk_score=risk_score or RiskScore(),
            reasons=reasons,
            policy_matched=policy_matched,
            correlation_id=correlation_id,
            explanation=f"DENIED: {'; '.join(reasons)}",
        )

    def _apply_default_decision(
        self,
        correlation_id: str,
        risk_score: RiskScore,
        request: TransactionRequest,
    ) -> AuthorizationDecision:
        """
        Apply the mode-based default decision when no policy matches.

        In FAIL_CLOSED mode: defaults to DENY
        In FAIL_OPEN mode: defaults to ALLOW with a warning

        Args:
            correlation_id: Request correlation ID.
            risk_score: The computed risk score.
            request: The original request.

        Returns:
            The default AuthorizationDecision based on engine mode.
        """
        if self._config.mode == AuthorizationMode.FAIL_CLOSED:
            return AuthorizationDecision(
                decision=AuthorizationDecisionType.DENY,
                risk_score=risk_score,
                reasons=["No matching policy rule (fail-closed mode)"],
                policy_matched="default-deny",
                correlation_id=correlation_id,
                explanation=self._build_explanation(
                    AuthorizationDecisionType.DENY,
                    request,
                    ["No matching policy rule (fail-closed mode)"],
                    risk_score,
                ),
            )
        else:
            logger.warning(
                "FAIL_OPEN: Allowing request %s with no matching policy. "
                "This mode should ONLY be used in development.",
                correlation_id,
            )
            return AuthorizationDecision(
                decision=AuthorizationDecisionType.ALLOW,
                risk_score=risk_score,
                reasons=[
                    "No matching policy rule (fail-open development mode)",
                    "WARNING: This request would be DENIED in production",
                ],
                policy_matched="default-allow-dev",
                correlation_id=correlation_id,
                explanation=self._build_explanation(
                    AuthorizationDecisionType.ALLOW,
                    request,
                    ["No matching policy (fail-open dev mode)"],
                    risk_score,
                ),
            )

    def _handle_error(
        self,
        correlation_id: str,
        request: TransactionRequest,
        exc: Exception,
        start_time: float,
    ) -> AuthorizationDecision:
        """
        Handle an unexpected error during authorization.

        In FAIL_CLOSED mode: errors result in DENY
        In FAIL_OPEN mode: errors result in ALLOW with warning

        Args:
            correlation_id: Request correlation ID.
            request: The original request.
            exc: The exception that occurred.
            start_time: When authorization started (for latency tracking).

        Returns:
            An AuthorizationDecision appropriate for the error and mode.
        """
        error_reasons = [
            f"Internal error during authorization: {type(exc).__name__}",
            str(exc),
        ]

        if self._config.mode == AuthorizationMode.FAIL_CLOSED:
            decision = AuthorizationDecision(
                decision=AuthorizationDecisionType.DENY,
                risk_score=RiskScore(),
                reasons=error_reasons,
                policy_matched="error-fail-closed",
                correlation_id=correlation_id,
                explanation=f"DENIED due to internal error (fail-closed): {exc}",
            )
        else:
            logger.warning(
                "FAIL_OPEN: Allowing request %s despite error: %s",
                correlation_id,
                str(exc),
            )
            decision = AuthorizationDecision(
                decision=AuthorizationDecisionType.ALLOW,
                risk_score=RiskScore(),
                reasons=[
                    *error_reasons,
                    "WARNING: Allowed due to fail-open mode",
                ],
                policy_matched="error-fail-open",
                correlation_id=correlation_id,
                explanation=f"ALLOWED despite error (fail-open dev mode): {exc}",
            )

        self._record_decision(request, decision, start_time)
        return decision

    def _record_decision(
        self,
        request: TransactionRequest,
        decision: AuthorizationDecision,
        start_time: float,
    ) -> None:
        """
        Record a decision for metrics and audit.

        Args:
            request: The original transaction request.
            decision: The authorization decision.
            start_time: When authorization started (for latency).
        """
        # Track latency
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        self._latency_tracker.record(elapsed_ms)

        # Increment decision counter
        with self._decision_lock:
            self._decision_count += 1

        # Emit audit event
        if self._config.enable_audit:
            self._emit_audit_event(request, decision)

        logger.info(
            "Authorization decision: %s for agent=%s action=%s "
            "risk=%.1f latency=%.2fms (correlation: %s)",
            decision.decision.value,
            request.agent_id,
            request.action,
            decision.risk_score.overall,
            elapsed_ms,
            decision.correlation_id,
        )
