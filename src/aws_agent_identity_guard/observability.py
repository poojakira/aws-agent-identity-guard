"""
aws_agent_identity_guard/observability.py
--------------------------------------------------------------------------------
Observability stack for AWS Agent Identity Guard.

Provides metrics collection (Prometheus-compatible), distributed tracing,
and structured JSON logging for full operational visibility into the
authorization and enforcement pipeline.

Components:
  - MetricsCollector: Counters, histograms, and gauges with Prometheus export
  - TracingProvider: OpenTelemetry-compatible distributed tracing
  - StructuredLogger: JSON-formatted structured logging with correlation IDs
  - Span: Trace span data model

Design principles:
  - Zero external dependencies (stdlib only for core functionality)
  - Thread-safe metric recording
  - Prometheus exposition format compatible
  - OpenTelemetry-compatible span model
  - Minimal overhead on hot paths
  - Configurable output destinations
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TextIO

logger = logging.getLogger(__name__)


# --- Constants ---

_HISTOGRAM_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

_LATENCY_BUCKETS_MS = (1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0)


# --- Metric Data Structures ---


class MetricType(str, Enum):
    """Types of metrics supported."""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


@dataclass
class MetricSample:
    """
    A single metric sample with labels.

    Attributes:
        name: Metric name.
        labels: Label key-value pairs.
        value: Current metric value.
        timestamp_ms: Timestamp in milliseconds (optional).
    """

    name: str
    labels: dict[str, str] = field(default_factory=dict)
    value: float = 0.0
    timestamp_ms: int | None = None


class Counter:
    """
    Thread-safe monotonically increasing counter.

    Supports labeled and unlabeled counters with atomic increment.
    """

    def __init__(self, name: str, help_text: str, label_names: list[str] | None = None) -> None:
        """
        Initialize a counter metric.

        Args:
            name: Metric name (e.g., 'agent_guard_decisions_total').
            help_text: Human-readable description.
            label_names: List of label names for this counter.
        """
        self.name = name
        self.help_text = help_text
        self.label_names = label_names or []
        self._values: dict[tuple[str, ...], float] = {}
        self._lock = threading.Lock()

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        """
        Increment the counter.

        Args:
            amount: Amount to increment by (must be non-negative).
            **labels: Label values matching label_names.

        Raises:
            ValueError: If amount is negative.
        """
        if amount < 0:
            raise ValueError("Counter increment must be non-negative")

        key = self._make_key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def get(self, **labels: str) -> float:
        """
        Get the current counter value.

        Args:
            **labels: Label values to look up.

        Returns:
            Current counter value.
        """
        key = self._make_key(labels)
        with self._lock:
            return self._values.get(key, 0.0)

    def _make_key(self, labels: dict[str, str]) -> tuple[str, ...]:
        """Create a hashable key from labels."""
        return tuple(labels.get(name, "") for name in self.label_names)

    def samples(self) -> list[MetricSample]:
        """Return all metric samples for Prometheus export."""
        result = []
        with self._lock:
            for key, value in self._values.items():
                label_dict = dict(zip(self.label_names, key, strict=False))
                result.append(
                    MetricSample(
                        name=self.name,
                        labels=label_dict,
                        value=value,
                    )
                )
        return result


class Gauge:
    """
    Thread-safe gauge metric (can increase and decrease).

    Represents a value that can go up and down, such as current
    risk scores or drift scores.
    """

    def __init__(self, name: str, help_text: str, label_names: list[str] | None = None) -> None:
        """
        Initialize a gauge metric.

        Args:
            name: Metric name.
            help_text: Human-readable description.
            label_names: List of label names.
        """
        self.name = name
        self.help_text = help_text
        self.label_names = label_names or []
        self._values: dict[tuple[str, ...], float] = {}
        self._lock = threading.Lock()

    def set(self, value: float, **labels: str) -> None:
        """
        Set the gauge to a specific value.

        Args:
            value: The value to set.
            **labels: Label values.
        """
        key = self._make_key(labels)
        with self._lock:
            self._values[key] = value

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        """
        Increment the gauge.

        Args:
            amount: Amount to increment.
            **labels: Label values.
        """
        key = self._make_key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def dec(self, amount: float = 1.0, **labels: str) -> None:
        """
        Decrement the gauge.

        Args:
            amount: Amount to decrement.
            **labels: Label values.
        """
        key = self._make_key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) - amount

    def get(self, **labels: str) -> float:
        """
        Get the current gauge value.

        Args:
            **labels: Label values.

        Returns:
            Current gauge value.
        """
        key = self._make_key(labels)
        with self._lock:
            return self._values.get(key, 0.0)

    def _make_key(self, labels: dict[str, str]) -> tuple[str, ...]:
        """Create a hashable key from labels."""
        return tuple(labels.get(name, "") for name in self.label_names)

    def samples(self) -> list[MetricSample]:
        """Return all metric samples for Prometheus export."""
        result = []
        with self._lock:
            for key, value in self._values.items():
                label_dict = dict(zip(self.label_names, key, strict=False))
                result.append(
                    MetricSample(
                        name=self.name,
                        labels=label_dict,
                        value=value,
                    )
                )
        return result


class Histogram:
    """
    Thread-safe histogram for latency and distribution tracking.

    Records observations into configurable buckets and computes
    sum and count for Prometheus-compatible export.
    """

    def __init__(
        self,
        name: str,
        help_text: str,
        label_names: list[str] | None = None,
        buckets: tuple[float, ...] = _HISTOGRAM_BUCKETS,
    ) -> None:
        """
        Initialize a histogram metric.

        Args:
            name: Metric name.
            help_text: Human-readable description.
            label_names: List of label names.
            buckets: Bucket boundaries for the histogram.
        """
        self.name = name
        self.help_text = help_text
        self.label_names = label_names or []
        self.buckets = buckets
        self._bucket_counts: dict[tuple[str, ...], list[float]] = {}
        self._sums: dict[tuple[str, ...], float] = {}
        self._counts: dict[tuple[str, ...], int] = {}
        self._lock = threading.Lock()

    def observe(self, value: float, **labels: str) -> None:
        """
        Record an observation.

        Args:
            value: The observed value (e.g., latency in seconds).
            **labels: Label values.
        """
        key = self._make_key(labels)
        with self._lock:
            if key not in self._bucket_counts:
                self._bucket_counts[key] = [0.0] * len(self.buckets)
                self._sums[key] = 0.0
                self._counts[key] = 0

            self._sums[key] += value
            self._counts[key] += 1

            for i, boundary in enumerate(self.buckets):
                if value <= boundary:
                    self._bucket_counts[key][i] += 1

    def get_count(self, **labels: str) -> int:
        """Get total observation count for given labels."""
        key = self._make_key(labels)
        with self._lock:
            return self._counts.get(key, 0)

    def get_sum(self, **labels: str) -> float:
        """Get sum of all observations for given labels."""
        key = self._make_key(labels)
        with self._lock:
            return self._sums.get(key, 0.0)

    def _make_key(self, labels: dict[str, str]) -> tuple[str, ...]:
        """Create a hashable key from labels."""
        return tuple(labels.get(name, "") for name in self.label_names)

    def samples(self) -> list[MetricSample]:
        """
        Return all metric samples in Prometheus histogram format.

        Generates _bucket, _count, and _sum samples.
        """
        result = []
        with self._lock:
            for key, bucket_counts in self._bucket_counts.items():
                label_dict = dict(zip(self.label_names, key, strict=False))

                # Cumulative bucket counts
                cumulative = 0.0
                for i, boundary in enumerate(self.buckets):
                    cumulative += bucket_counts[i]
                    bucket_labels = {**label_dict, "le": str(boundary)}
                    result.append(
                        MetricSample(
                            name=f"{self.name}_bucket",
                            labels=bucket_labels,
                            value=cumulative,
                        )
                    )

                # +Inf bucket
                total_count = self._counts.get(key, 0)
                inf_labels = {**label_dict, "le": "+Inf"}
                result.append(
                    MetricSample(
                        name=f"{self.name}_bucket",
                        labels=inf_labels,
                        value=float(total_count),
                    )
                )

                # _count and _sum
                result.append(
                    MetricSample(
                        name=f"{self.name}_count",
                        labels=label_dict,
                        value=float(total_count),
                    )
                )
                result.append(
                    MetricSample(
                        name=f"{self.name}_sum",
                        labels=label_dict,
                        value=self._sums.get(key, 0.0),
                    )
                )

        return result


# --- Metrics Collector ---


class MetricsCollector:
    """
    Central metrics collector for AWS Agent Identity Guard.

    Tracks authorization decisions, enforcement actions, drift scores,
    step-up requests, and policy violations. Exports in Prometheus
    exposition format.

    Usage:
        collector = MetricsCollector()
        collector.record_decision("ALLOW", 5.2, "agent-1", 25.0)
        collector.record_enforcement("BLOCKED", True, 3.1)
        print(collector.get_prometheus_metrics())
    """

    def __init__(self) -> None:
        """Initialize all metrics for the observability stack."""
        # Counters
        self.decisions_total = Counter(
            name="agent_guard_decisions_total",
            help_text="Total authorization decisions made",
            label_names=["decision_type", "agent_type", "environment"],
        )

        self.denied_actions_total = Counter(
            name="agent_guard_denied_actions_total",
            help_text="Total denied actions by agent and action",
            label_names=["agent_id", "action"],
        )

        self.step_up_requests_total = Counter(
            name="agent_guard_step_up_requests_total",
            help_text="Total step-up authentication requests",
            label_names=["agent_id", "status"],
        )

        self.policy_violations_total = Counter(
            name="agent_guard_policy_violations_total",
            help_text="Total policy violations detected",
            label_names=["rule_name", "severity"],
        )

        # Histograms
        self.decision_latency_seconds = Histogram(
            name="agent_guard_decision_latency_seconds",
            help_text="Authorization decision latency in seconds",
            label_names=["decision_type"],
            buckets=_HISTOGRAM_BUCKETS,
        )

        self.enforcement_latency_seconds = Histogram(
            name="agent_guard_enforcement_latency_seconds",
            help_text="Enforcement action latency in seconds",
            label_names=[],
            buckets=_HISTOGRAM_BUCKETS,
        )

        # Gauges
        self.permission_drift_score = Gauge(
            name="agent_guard_permission_drift_score",
            help_text="Current permission drift score per agent",
            label_names=["agent_id"],
        )

        self.risk_score = Gauge(
            name="agent_guard_risk_score",
            help_text="Current risk score per agent",
            label_names=["agent_id"],
        )

        self.top_risky_agents = Gauge(
            name="agent_guard_top_risky_agents",
            help_text="Risk score of top risky agents",
            label_names=["agent_id"],
        )

        # Internal tracking
        self._total_decisions = 0
        self._total_enforcements = 0
        self._lock = threading.Lock()

        logger.info("MetricsCollector initialized with all metric registrations")

    def record_decision(
        self,
        decision_type: str,
        latency_ms: float,
        agent_id: str,
        risk_score: float,
        agent_type: str = "CUSTOM",
        environment: str = "PRODUCTION",
    ) -> None:
        """
        Record an authorization decision metric.

        Args:
            decision_type: Decision outcome (ALLOW, DENY, STEP_UP, REVIEW).
            latency_ms: Decision latency in milliseconds.
            agent_id: The agent that triggered the decision.
            risk_score: The risk score associated with this decision.
            agent_type: Agent type classification.
            environment: Deployment environment.
        """
        try:
            self.decisions_total.inc(
                decision_type=decision_type,
                agent_type=agent_type,
                environment=environment,
            )

            # Record latency in seconds (Prometheus convention)
            latency_seconds = latency_ms / 1000.0
            self.decision_latency_seconds.observe(
                latency_seconds,
                decision_type=decision_type,
            )

            # Update risk score gauge
            self.risk_score.set(risk_score, agent_id=agent_id)

            # Track denied actions
            if decision_type == "DENY":
                self.denied_actions_total.inc(agent_id=agent_id, action="unknown")

            # Update top risky agents
            self.top_risky_agents.set(risk_score, agent_id=agent_id)

            with self._lock:
                self._total_decisions += 1

        except Exception as exc:
            logger.error("Failed to record decision metric: %s", exc)

    def record_enforcement(
        self,
        action_taken: str,
        success: bool,
        latency_ms: float,
    ) -> None:
        """
        Record an enforcement action metric.

        Args:
            action_taken: The enforcement action (BLOCKED, ALLOWED, PENDING_APPROVAL).
            success: Whether enforcement completed successfully.
            latency_ms: Enforcement latency in milliseconds.
        """
        try:
            latency_seconds = latency_ms / 1000.0
            self.enforcement_latency_seconds.observe(latency_seconds)

            with self._lock:
                self._total_enforcements += 1

        except Exception as exc:
            logger.error("Failed to record enforcement metric: %s", exc)

    def record_drift(self, agent_id: str, drift_score: float) -> None:
        """
        Record a permission drift score for an agent.

        Args:
            agent_id: The agent whose drift was measured.
            drift_score: The drift score (0.0 to 100.0).
        """
        try:
            self.permission_drift_score.set(drift_score, agent_id=agent_id)
        except Exception as exc:
            logger.error("Failed to record drift metric: %s", exc)

    def record_step_up(self, agent_id: str, approved: bool) -> None:
        """
        Record a step-up authentication request.

        Args:
            agent_id: The agent that triggered step-up.
            approved: Whether the step-up was approved.
        """
        try:
            status = "approved" if approved else "denied"
            self.step_up_requests_total.inc(agent_id=agent_id, status=status)
        except Exception as exc:
            logger.error("Failed to record step-up metric: %s", exc)

    def record_policy_violation(
        self,
        rule_name: str,
        severity: str,
    ) -> None:
        """
        Record a policy violation.

        Args:
            rule_name: Name of the violated policy rule.
            severity: Violation severity (LOW, MEDIUM, HIGH, CRITICAL).
        """
        try:
            self.policy_violations_total.inc(rule_name=rule_name, severity=severity)
        except Exception as exc:
            logger.error("Failed to record policy violation metric: %s", exc)

    def get_prometheus_metrics(self) -> str:
        """
        Export all metrics in Prometheus exposition text format.

        Returns:
            String in Prometheus text format ready for /metrics endpoint.
        """
        lines: list[str] = []

        # Export all registered metrics
        all_metrics = [
            (self.decisions_total, MetricType.COUNTER),
            (self.denied_actions_total, MetricType.COUNTER),
            (self.step_up_requests_total, MetricType.COUNTER),
            (self.policy_violations_total, MetricType.COUNTER),
            (self.decision_latency_seconds, MetricType.HISTOGRAM),
            (self.enforcement_latency_seconds, MetricType.HISTOGRAM),
            (self.permission_drift_score, MetricType.GAUGE),
            (self.risk_score, MetricType.GAUGE),
            (self.top_risky_agents, MetricType.GAUGE),
        ]

        for metric, metric_type in all_metrics:
            lines.append(f"# HELP {metric.name} {metric.help_text}")
            lines.append(f"# TYPE {metric.name} {metric_type.value}")

            for sample in metric.samples():
                label_str = self._format_labels(sample.labels)
                lines.append(f"{sample.name}{label_str} {sample.value}")

            lines.append("")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        """
        Get internal metrics statistics.

        Returns:
            Dictionary with metric summaries for dashboards and health checks.
        """
        with self._lock:
            total_decisions = self._total_decisions
            total_enforcements = self._total_enforcements

        return {
            "total_decisions": total_decisions,
            "total_enforcements": total_enforcements,
            "decisions_by_type": {
                sample.labels.get("decision_type", "unknown"): sample.value
                for sample in self.decisions_total.samples()
            },
            "drift_scores": {
                sample.labels.get("agent_id", "unknown"): sample.value
                for sample in self.permission_drift_score.samples()
            },
            "risk_scores": {
                sample.labels.get("agent_id", "unknown"): sample.value
                for sample in self.risk_score.samples()
            },
            "step_up_counts": {
                f"{sample.labels.get('agent_id', 'unknown')}"
                f"_{sample.labels.get('status', '')}": sample.value
                for sample in self.step_up_requests_total.samples()
            },
            "policy_violations": {
                f"{sample.labels.get('rule_name', 'unknown')}"
                f"_{sample.labels.get('severity', '')}": sample.value
                for sample in self.policy_violations_total.samples()
            },
        }

    def _format_labels(self, labels: dict[str, str]) -> str:
        """
        Format labels as Prometheus label string.

        Args:
            labels: Label key-value pairs.

        Returns:
            Formatted string like '{key="value",key2="value2"}'.
        """
        if not labels:
            return ""

        parts = []
        for key, value in sorted(labels.items()):
            # Escape special characters in label values
            escaped_value = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            parts.append(f'{key}="{escaped_value}"')

        return "{" + ",".join(parts) + "}"


# --- Distributed Tracing ---


@dataclass
class Span:
    """
    A single trace span representing a unit of work.

    Compatible with OpenTelemetry span model for integration with
    distributed tracing backends (Jaeger, Zipkin, AWS X-Ray).

    Attributes:
        trace_id: Unique identifier for the overall trace.
        span_id: Unique identifier for this span.
        parent_span_id: Parent span ID (None for root spans).
        operation_name: Name of the operation being traced.
        start_time: When the span started (epoch seconds).
        end_time: When the span ended (None if still active).
        attributes: Key-value metadata attached to this span.
        events: Timestamped events that occurred during the span.
    """

    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    span_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    parent_span_id: str | None = None
    operation_name: str = ""
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def duration_ms(self) -> float | None:
        """Calculate span duration in milliseconds."""
        if self.end_time is None:
            return None
        return (self.end_time - self.start_time) * 1000

    @property
    def is_active(self) -> bool:
        """Check if the span is still active (not ended)."""
        return self.end_time is None

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        """
        Add a timestamped event to the span.

        Args:
            name: Event name.
            attributes: Optional event attributes.
        """
        self.events.append(
            {
                "name": name,
                "timestamp": time.time(),
                "attributes": attributes or {},
            }
        )

    def set_attribute(self, key: str, value: Any) -> None:
        """
        Set a span attribute.

        Args:
            key: Attribute key.
            value: Attribute value.
        """
        self.attributes[key] = value

    def to_dict(self) -> dict[str, Any]:
        """Serialize span to a JSON-compatible dictionary."""
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "operation_name": self.operation_name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "attributes": self.attributes,
            "events": self.events,
        }


@dataclass
class TracingContext:
    """
    Context propagation container for distributed tracing.

    Carries trace context across service boundaries via headers.

    Attributes:
        trace_id: The current trace ID.
        span_id: The current span ID.
        trace_flags: Sampling/recording flags.
        baggage: Key-value baggage items for cross-service propagation.
    """

    trace_id: str = ""
    span_id: str = ""
    trace_flags: int = 1  # 1 = sampled
    baggage: dict[str, str] = field(default_factory=dict)


class TracingProvider:
    """
    Distributed tracing provider for the Agent Identity Guard system.

    Manages span lifecycle, context propagation, and span export.
    Compatible with W3C Trace Context format for interoperability.

    Usage:
        tracer = TracingProvider(service_name="agent-identity-guard")
        span = tracer.start_span("authorize_request", {"agent_id": "abc"})
        # ... do work ...
        tracer.end_span(span)

        # Context propagation
        headers = tracer.inject_context({})
        context = tracer.extract_context(incoming_headers)
    """

    # W3C Trace Context header names
    TRACEPARENT_HEADER = "traceparent"
    TRACESTATE_HEADER = "tracestate"

    def __init__(
        self,
        service_name: str = "agent-identity-guard",
        sample_rate: float = 1.0,
        max_spans: int = 10000,
    ) -> None:
        """
        Initialize the tracing provider.

        Args:
            service_name: Name of this service for span metadata.
            sample_rate: Fraction of traces to sample (0.0 to 1.0).
            max_spans: Maximum completed spans to retain in memory.
        """
        self._service_name = service_name
        self._sample_rate = sample_rate
        self._max_spans = max_spans
        self._active_spans: dict[str, Span] = {}
        self._completed_spans: list[Span] = []
        self._lock = threading.Lock()
        self._current_context: threading.local = threading.local()

        logger.info(
            "TracingProvider initialized: service=%s sample_rate=%.2f",
            service_name,
            sample_rate,
        )

    def start_span(
        self,
        operation_name: str,
        attributes: dict[str, Any] | None = None,
        parent_span: Span | None = None,
    ) -> Span:
        """
        Start a new trace span.

        Creates a child span if a parent is provided, or a root span otherwise.

        Args:
            operation_name: Name of the operation (e.g., 'authorize', 'enforce').
            attributes: Initial span attributes.
            parent_span: Optional parent span for creating child spans.

        Returns:
            A new active Span instance.
        """
        # Determine trace context
        if parent_span:
            trace_id = parent_span.trace_id
            parent_span_id = parent_span.span_id
        else:
            # Check thread-local context
            ctx = getattr(self._current_context, "context", None)
            if ctx and ctx.trace_id:
                trace_id = ctx.trace_id
                parent_span_id = ctx.span_id
            else:
                trace_id = uuid.uuid4().hex
                parent_span_id = None

        span = Span(
            trace_id=trace_id,
            span_id=uuid.uuid4().hex[:16],
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            start_time=time.time(),
            attributes={
                "service.name": self._service_name,
                **(attributes or {}),
            },
        )

        with self._lock:
            self._active_spans[span.span_id] = span

        # Update thread-local context
        self._current_context.context = TracingContext(
            trace_id=span.trace_id,
            span_id=span.span_id,
        )

        logger.debug(
            "Started span: trace_id=%s span_id=%s op=%s",
            span.trace_id[:8],
            span.span_id[:8],
            operation_name,
        )

        return span

    def end_span(self, span: Span) -> None:
        """
        End an active span and record it.

        Args:
            span: The span to end. Must be currently active.
        """
        if not span.is_active:
            logger.warning("Attempted to end already-completed span %s", span.span_id)
            return

        span.end_time = time.time()

        with self._lock:
            self._active_spans.pop(span.span_id, None)
            self._completed_spans.append(span)

            # Trim completed spans if over limit
            if len(self._completed_spans) > self._max_spans:
                self._completed_spans = self._completed_spans[-self._max_spans :]

        logger.debug(
            "Ended span: trace_id=%s span_id=%s op=%s duration_ms=%.2f",
            span.trace_id[:8],
            span.span_id[:8],
            span.operation_name,
            span.duration_ms or 0.0,
        )

    def inject_context(self, headers: dict[str, str]) -> dict[str, str]:
        """
        Inject trace context into outgoing request headers.

        Uses W3C Trace Context format (traceparent header).

        Args:
            headers: Existing headers to add trace context to.

        Returns:
            Updated headers dict with trace context.
        """
        ctx = getattr(self._current_context, "context", None)
        if not ctx or not ctx.trace_id:
            return headers

        # W3C traceparent format: version-trace_id-parent_id-flags
        traceparent = f"00-{ctx.trace_id}-{ctx.span_id}-{ctx.trace_flags:02x}"
        headers[self.TRACEPARENT_HEADER] = traceparent

        # Add baggage if present
        if ctx.baggage:
            baggage_str = ",".join(f"{k}={v}" for k, v in ctx.baggage.items())
            headers["baggage"] = baggage_str

        return headers

    def extract_context(self, headers: dict[str, str]) -> TracingContext:
        """
        Extract trace context from incoming request headers.

        Parses W3C Trace Context format.

        Args:
            headers: Incoming request headers.

        Returns:
            TracingContext extracted from headers.
        """
        traceparent = headers.get(self.TRACEPARENT_HEADER, "")
        context = TracingContext()

        if traceparent:
            parts = traceparent.split("-")
            if len(parts) == 4:
                # version-trace_id-parent_id-flags
                context.trace_id = parts[1]
                context.span_id = parts[2]
                try:
                    context.trace_flags = int(parts[3], 16)
                except ValueError:
                    context.trace_flags = 1

        # Extract baggage
        baggage_str = headers.get("baggage", "")
        if baggage_str:
            for item in baggage_str.split(","):
                if "=" in item:
                    key, value = item.split("=", 1)
                    context.baggage[key.strip()] = value.strip()

        # Store in thread-local
        self._current_context.context = context

        return context

    @property
    def active_span_count(self) -> int:
        """Return number of currently active spans."""
        with self._lock:
            return len(self._active_spans)

    @property
    def completed_span_count(self) -> int:
        """Return number of completed spans in memory."""
        with self._lock:
            return len(self._completed_spans)

    def get_completed_spans(self, limit: int = 100) -> list[dict[str, Any]]:
        """
        Get recently completed spans.

        Args:
            limit: Maximum number of spans to return.

        Returns:
            List of serialized span dictionaries.
        """
        with self._lock:
            spans = self._completed_spans[-limit:]
        return [span.to_dict() for span in spans]


# --- Structured Logger ---


class LogLevel(str, Enum):
    """Log level enumeration."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogFormat(str, Enum):
    """Output format for structured logs."""

    JSON = "JSON"
    TEXT = "TEXT"


class StructuredLogger:
    """
    Structured JSON logger for the Agent Identity Guard system.

    Outputs log entries as JSON objects with consistent fields:
    timestamp, level, message, correlation_id, agent_id, action,
    service, and arbitrary extra fields.

    Supports configurable log levels, output formats, and destinations.

    Usage:
        log = StructuredLogger(service_name="enforcement", level=LogLevel.INFO)
        log.info("Request allowed", agent_id="agent-1", action="s3:GetObject")
        log.error("Enforcement failed", correlation_id="abc-123", error="timeout")
    """

    def __init__(
        self,
        service_name: str = "agent-identity-guard",
        level: LogLevel = LogLevel.INFO,
        format: LogFormat = LogFormat.JSON,  # noqa: A002
        destination: TextIO | None = None,
        correlation_id: str | None = None,
    ) -> None:
        """
        Initialize the structured logger.

        Args:
            service_name: Service name included in every log entry.
            level: Minimum log level to output.
            format: Output format (JSON or TEXT).
            destination: Output stream (defaults to sys.stdout).
            correlation_id: Default correlation ID for all entries.
        """
        self._service_name = service_name
        self._level = level
        self._format = format
        self._destination = destination or sys.stdout
        self._correlation_id = correlation_id
        self._lock = threading.Lock()

        self._level_priority = {
            LogLevel.DEBUG: 10,
            LogLevel.INFO: 20,
            LogLevel.WARNING: 30,
            LogLevel.ERROR: 40,
            LogLevel.CRITICAL: 50,
        }

    def info(self, message: str, **context: Any) -> None:
        """
        Log an informational message.

        Args:
            message: Log message.
            **context: Additional context fields (agent_id, action, etc.).
        """
        self._log(LogLevel.INFO, message, **context)

    def warning(self, message: str, **context: Any) -> None:
        """
        Log a warning message.

        Args:
            message: Log message.
            **context: Additional context fields.
        """
        self._log(LogLevel.WARNING, message, **context)

    def error(self, message: str, **context: Any) -> None:
        """
        Log an error message.

        Args:
            message: Log message.
            **context: Additional context fields.
        """
        self._log(LogLevel.ERROR, message, **context)

    def critical(self, message: str, **context: Any) -> None:
        """
        Log a critical message.

        Args:
            message: Log message.
            **context: Additional context fields.
        """
        self._log(LogLevel.CRITICAL, message, **context)

    def debug(self, message: str, **context: Any) -> None:
        """
        Log a debug message.

        Args:
            message: Log message.
            **context: Additional context fields.
        """
        self._log(LogLevel.DEBUG, message, **context)

    def _log(self, level: LogLevel, message: str, **context: Any) -> None:
        """
        Internal logging method.

        Checks log level, constructs the structured entry, and writes
        to the configured destination.

        Args:
            level: Log level for this entry.
            message: Log message.
            **context: Additional context fields.
        """
        # Check if this level should be emitted
        if self._level_priority.get(level, 0) < self._level_priority.get(self._level, 0):
            return

        # Build the structured log entry
        entry = self._build_entry(level, message, context)

        # Format and write
        if self._format == LogFormat.JSON:
            output = json.dumps(entry, default=str, ensure_ascii=False)
        else:
            output = self._format_text(entry)

        with self._lock:
            try:
                self._destination.write(output + "\n")
                self._destination.flush()
            except Exception:  # noqa: S110
                # Logging must never raise
                pass

    def _build_entry(
        self,
        level: LogLevel,
        message: str,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Build a structured log entry dictionary.

        Args:
            level: Log level.
            message: Log message.
            context: Additional context fields.

        Returns:
            Complete log entry dictionary.
        """
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level.value,
            "message": message,
            "service": self._service_name,
        }

        # Add correlation ID (from context or default)
        correlation_id = context.pop("correlation_id", None) or self._correlation_id
        if correlation_id:
            entry["correlation_id"] = correlation_id

        # Add standard fields if present
        standard_fields = ["agent_id", "action", "resource", "decision", "environment"]
        for field_name in standard_fields:
            if field_name in context:
                entry[field_name] = context.pop(field_name)

        # Add remaining context as extra fields
        if context:
            entry["extra"] = context

        return entry

    def _format_text(self, entry: dict[str, Any]) -> str:
        """
        Format a log entry as human-readable text.

        Args:
            entry: The structured log entry.

        Returns:
            Formatted text string.
        """
        timestamp = entry.get("timestamp", "")
        level = entry.get("level", "INFO")
        message = entry.get("message", "")
        service = entry.get("service", "")

        parts = [f"{timestamp} [{level}] [{service}] {message}"]

        # Add context fields
        for key in ("correlation_id", "agent_id", "action", "resource", "decision"):
            if key in entry:
                parts.append(f"  {key}={entry[key]}")

        if "extra" in entry:
            for key, value in entry["extra"].items():
                parts.append(f"  {key}={value}")

        base = " | ".join(parts[:1])
        extra = "".join(f"\n{p}" for p in parts[1:]) if len(parts) > 1 else ""
        return base + extra

    def with_context(self, **context: Any) -> StructuredLogger:
        """
        Create a child logger with additional default context.

        Args:
            **context: Context fields to include in all log entries.

        Returns:
            A new StructuredLogger with inherited and additional context.
        """
        child = StructuredLogger(
            service_name=self._service_name,
            level=self._level,
            format=self._format,
            destination=self._destination,
            correlation_id=context.get("correlation_id", self._correlation_id),
        )
        return child

    @property
    def level(self) -> LogLevel:
        """Get the current log level."""
        return self._level

    @level.setter
    def level(self, new_level: LogLevel) -> None:
        """
        Set the log level.

        Args:
            new_level: The new minimum log level.
        """
        self._level = new_level
