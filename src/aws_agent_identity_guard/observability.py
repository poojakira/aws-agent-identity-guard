"""Observability stack for AWS Agent Identity Guard.

Provides Prometheus-compatible metrics, OpenTelemetry-compatible tracing,
structured logging, tamper-evident audit trails, and dashboard aggregations.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .models import AuthorizationDecision

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class LogLevel(Enum):
    """Structured log severity levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class MetricType(Enum):
    """Prometheus metric types."""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class MetricLabels:
    """Standard label set for metrics."""

    agent_id: str = ""
    environment: str = ""
    action: str = ""
    decision: str = ""

    def as_dict(self) -> dict[str, str]:
        """Convert labels to a dictionary, excluding empty values."""
        return {k: v for k, v in self.__dict__.items() if v}

    def label_str(self) -> str:
        """Format labels in Prometheus exposition format."""
        pairs = [f'{k}="{v}"' for k, v in self.as_dict().items()]
        return "{" + ",".join(pairs) + "}" if pairs else ""


@dataclass
class HistogramBuckets:
    """Histogram bucket boundaries."""

    boundaries: list[float] = field(
        default_factory=lambda: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )


@dataclass
class Span:
    """Represents a tracing span (OpenTelemetry-compatible)."""

    trace_id: str
    """Unique trace identifier (W3C compatible hex string)."""

    span_id: str
    """Unique span identifier."""

    parent_span_id: str | None
    """Parent span ID for nested spans."""

    operation: str
    """Operation name."""

    attributes: dict[str, Any] = field(default_factory=dict)
    """Span attributes/tags."""

    start_time: float = field(default_factory=time.time)
    """Span start time (Unix timestamp)."""

    end_time: float | None = None
    """Span end time (Unix timestamp), None if still active."""

    status: str = "OK"
    """Span status: OK, ERROR, UNSET."""

    events: list[dict[str, Any]] = field(default_factory=list)
    """Span events/logs."""

    def end(self, status: str = "OK") -> None:
        """End the span.

        Args:
            status: Final span status.
        """
        self.end_time = time.time()
        self.status = status

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        """Add an event to the span.

        Args:
            name: Event name.
            attributes: Optional event attributes.
        """
        self.events.append({
            "name": name,
            "timestamp": time.time(),
            "attributes": attributes or {},
        })

    @property
    def duration_ms(self) -> float | None:
        """Span duration in milliseconds, or None if not ended."""
        if self.end_time is None:
            return None
        return (self.end_time - self.start_time) * 1000.0


@dataclass
class AuditEvent:
    """An immutable audit trail event with integrity chain."""

    event_id: str
    """Unique event identifier."""

    timestamp: str
    """ISO 8601 timestamp."""

    agent_id: str
    """Agent that triggered the event."""

    action: str
    """Action that was evaluated."""

    decision: str
    """Authorization decision (allowed/denied)."""

    reason: str
    """Reason for the decision."""

    correlation_id: str
    """Correlation ID linking related events."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Additional event metadata."""

    previous_hash: str = ""
    """Hash of the previous event in the chain (integrity chain)."""

    event_hash: str = ""
    """Hash of this event (computed from all fields + previous_hash)."""

    def compute_hash(self) -> str:
        """Compute the SHA-256 hash of this event's content.

        Returns:
            Hex-encoded SHA-256 hash.
        """
        content = (
            f"{self.event_id}|{self.timestamp}|{self.agent_id}|"
            f"{self.action}|{self.decision}|{self.reason}|"
            f"{self.correlation_id}|{json.dumps(self.metadata, sort_keys=True)}|"
            f"{self.previous_hash}"
        )
        return hashlib.sha256(content.encode("utf-8")).hexdigest()


@dataclass
class AuditQueryFilters:
    """Filters for querying the audit trail."""

    agent_id: str | None = None
    action: str | None = None
    decision: str | None = None
    correlation_id: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    limit: int = 100


@dataclass
class LogEntry:
    """Structured log entry."""

    timestamp: str
    level: str
    message: str
    correlation_id: str = ""
    agent_id: str = ""
    action: str = ""
    decision: str = ""
    latency: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize to JSON string.

        Returns:
            JSON-formatted log entry.
        """
        data = {
            "timestamp": self.timestamp,
            "level": self.level,
            "message": self.message,
        }
        if self.correlation_id:
            data["correlation_id"] = self.correlation_id
        if self.agent_id:
            data["agent_id"] = self.agent_id
        if self.action:
            data["action"] = self.action
        if self.decision:
            data["decision"] = self.decision
        if self.latency > 0:
            data["latency_ms"] = self.latency
        if self.extra:
            data.update(self.extra)
        return json.dumps(data)


# ---------------------------------------------------------------------------
# Metrics Collector
# ---------------------------------------------------------------------------


class MetricsCollector:
    """Prometheus-compatible metrics collector.

    Tracks counters, gauges, and histograms with label support.
    Exposes metrics in Prometheus text exposition format.

    Example::

        metrics = MetricsCollector()
        metrics.inc_counter("decisions_total", labels=MetricLabels(decision="allowed"))
        metrics.set_gauge("risky_agents_count", 5)
        metrics.observe_histogram("authorization_latency_seconds", 0.023)
        print(metrics.expose())
    """

    def __init__(self) -> None:
        """Initialize the metrics collector with standard metrics."""
        self._lock = threading.Lock()

        # Counters: {name: {label_str: value}}
        self._counters: dict[str, dict[str, float]] = {
            "decisions_total": {},
            "denied_actions_total": {},
            "step_up_requests_total": {},
            "policy_violations_total": {},
        }

        # Gauges: {name: {label_str: value}}
        self._gauges: dict[str, dict[str, float]] = {
            "permission_drift_count": {},
            "risky_agents_count": {},
            "pending_approvals": {},
        }

        # Histograms: {name: {label_str: [observations]}}
        self._histograms: dict[str, dict[str, list[float]]] = {
            "authorization_latency_seconds": {},
            "risk_score_distribution": {},
        }

        self._histogram_buckets: dict[str, HistogramBuckets] = {
            "authorization_latency_seconds": HistogramBuckets(
                boundaries=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0]
            ),
            "risk_score_distribution": HistogramBuckets(
                boundaries=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
            ),
        }

    def inc_counter(
        self, name: str, value: float = 1.0, labels: MetricLabels | None = None
    ) -> None:
        """Increment a counter metric.

        Args:
            name: Counter metric name.
            value: Amount to increment (must be positive).
            labels: Optional metric labels.

        Raises:
            ValueError: If value is negative or counter name is unknown.
        """
        if value < 0:
            raise ValueError("Counter increment must be non-negative")
        if name not in self._counters:
            raise ValueError(f"Unknown counter: {name}")

        label_str = labels.label_str() if labels else ""
        with self._lock:
            self._counters[name].setdefault(label_str, 0.0)
            self._counters[name][label_str] += value

    def set_gauge(
        self, name: str, value: float, labels: MetricLabels | None = None
    ) -> None:
        """Set a gauge metric value.

        Args:
            name: Gauge metric name.
            value: Current gauge value.
            labels: Optional metric labels.

        Raises:
            ValueError: If gauge name is unknown.
        """
        if name not in self._gauges:
            raise ValueError(f"Unknown gauge: {name}")

        label_str = labels.label_str() if labels else ""
        with self._lock:
            self._gauges[name][label_str] = value

    def observe_histogram(
        self, name: str, value: float, labels: MetricLabels | None = None
    ) -> None:
        """Record an observation in a histogram.

        Args:
            name: Histogram metric name.
            value: Observed value.
            labels: Optional metric labels.

        Raises:
            ValueError: If histogram name is unknown.
        """
        if name not in self._histograms:
            raise ValueError(f"Unknown histogram: {name}")

        label_str = labels.label_str() if labels else ""
        with self._lock:
            self._histograms[name].setdefault(label_str, [])
            self._histograms[name][label_str].append(value)

    def get_counter(self, name: str, labels: MetricLabels | None = None) -> float:
        """Get current counter value.

        Args:
            name: Counter metric name.
            labels: Optional metric labels.

        Returns:
            Current counter value.
        """
        label_str = labels.label_str() if labels else ""
        with self._lock:
            return self._counters.get(name, {}).get(label_str, 0.0)

    def get_gauge(self, name: str, labels: MetricLabels | None = None) -> float:
        """Get current gauge value.

        Args:
            name: Gauge metric name.
            labels: Optional metric labels.

        Returns:
            Current gauge value.
        """
        label_str = labels.label_str() if labels else ""
        with self._lock:
            return self._gauges.get(name, {}).get(label_str, 0.0)

    def expose(self) -> str:
        """Export all metrics in Prometheus text exposition format.

        Returns:
            Metrics formatted as Prometheus text exposition.
        """
        lines: list[str] = []

        with self._lock:
            # Counters
            for name, label_values in self._counters.items():
                lines.append(f"# HELP {name} Counter metric")
                lines.append(f"# TYPE {name} counter")
                for label_str, value in label_values.items():
                    metric_name = f"{name}{label_str}" if label_str else name
                    lines.append(f"{metric_name} {value}")

            # Gauges
            for name, label_values in self._gauges.items():
                lines.append(f"# HELP {name} Gauge metric")
                lines.append(f"# TYPE {name} gauge")
                for label_str, value in label_values.items():
                    metric_name = f"{name}{label_str}" if label_str else name
                    lines.append(f"{metric_name} {value}")

            # Histograms
            for name, label_values in self._histograms.items():
                buckets = self._histogram_buckets.get(name, HistogramBuckets())
                lines.append(f"# HELP {name} Histogram metric")
                lines.append(f"# TYPE {name} histogram")
                for label_str, observations in label_values.items():
                    count = len(observations)
                    total = sum(observations)
                    base = f"{name}{label_str}" if label_str else name

                    for boundary in buckets.boundaries:
                        bucket_count = sum(1 for v in observations if v <= boundary)
                        le_label = f'le="{boundary}"'
                        if label_str:
                            # Insert le into existing labels
                            combined = label_str[:-1] + f",{le_label}" + "}"
                        else:
                            combined = "{" + le_label + "}"
                        lines.append(f"{name}_bucket{combined} {bucket_count}")

                    # +Inf bucket
                    if label_str:
                        inf_label = label_str[:-1] + ',le="+Inf"}'
                    else:
                        inf_label = '{le="+Inf"}'
                    lines.append(f"{name}_bucket{inf_label} {count}")
                    lines.append(f"{name}_sum{label_str if label_str else ''} {total}")
                    lines.append(f"{name}_count{label_str if label_str else ''} {count}")

        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        """Reset all metrics to zero. Primarily for testing."""
        with self._lock:
            for name in self._counters:
                self._counters[name] = {}
            for name in self._gauges:
                self._gauges[name] = {}
            for name in self._histograms:
                self._histograms[name] = {}


# ---------------------------------------------------------------------------
# Tracing Provider
# ---------------------------------------------------------------------------


class TracingProvider:
    """OpenTelemetry-compatible tracing provider.

    Generates trace and span IDs, manages span context propagation,
    and collects completed spans for export.

    Example::

        tracer = TracingProvider(service_name="agent-identity-guard")
        span = tracer.create_span("authorize", {"agent_id": "agent-123"})
        # ... do work ...
        span.end()
    """

    def __init__(self, service_name: str = "aws-agent-identity-guard") -> None:
        """Initialize the tracing provider.

        Args:
            service_name: Logical service name for span attribution.
        """
        self._service_name = service_name
        self._active_spans: dict[str, Span] = {}
        self._completed_spans: deque[Span] = deque(maxlen=10000)
        self._current_trace_id: str | None = None
        self._lock = threading.Lock()

    @property
    def service_name(self) -> str:
        """Configured service name."""
        return self._service_name

    @staticmethod
    def generate_trace_id() -> str:
        """Generate a W3C-compatible 32-character hex trace ID.

        Returns:
            32-character hex string.
        """
        return uuid.uuid4().hex

    @staticmethod
    def generate_span_id() -> str:
        """Generate a 16-character hex span ID.

        Returns:
            16-character hex string.
        """
        return uuid.uuid4().hex[:16]

    def create_span(
        self,
        operation: str,
        attributes: dict[str, Any] | None = None,
        parent_span_id: str | None = None,
        trace_id: str | None = None,
    ) -> Span:
        """Create a new tracing span.

        Args:
            operation: Operation name for the span.
            attributes: Optional span attributes.
            parent_span_id: Optional parent span for nesting.
            trace_id: Optional trace ID for context propagation.
                      If None, uses current trace or generates new.

        Returns:
            A new Span instance.
        """
        resolved_trace_id = trace_id or self._current_trace_id or self.generate_trace_id()
        span_id = self.generate_span_id()

        span = Span(
            trace_id=resolved_trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            operation=operation,
            attributes={
                "service.name": self._service_name,
                **(attributes or {}),
            },
        )

        with self._lock:
            self._current_trace_id = resolved_trace_id
            self._active_spans[span_id] = span

        return span

    def end_span(self, span: Span, status: str = "OK") -> None:
        """End a span and move it to completed storage.

        Args:
            span: The span to end.
            status: Final span status.
        """
        span.end(status=status)
        with self._lock:
            self._active_spans.pop(span.span_id, None)
            self._completed_spans.append(span)

    def get_active_spans(self) -> list[Span]:
        """Get all currently active spans.

        Returns:
            List of active spans.
        """
        with self._lock:
            return list(self._active_spans.values())

    def get_completed_spans(self, limit: int = 100) -> list[Span]:
        """Get recently completed spans.

        Args:
            limit: Maximum number of spans to return.

        Returns:
            List of completed spans (most recent first).
        """
        with self._lock:
            spans = list(self._completed_spans)
        return spans[-limit:][::-1]

    def inject_context(self, headers: dict[str, str]) -> dict[str, str]:
        """Inject trace context into HTTP headers (W3C Trace Context format).

        Args:
            headers: Existing headers to augment.

        Returns:
            Headers with trace context injected.
        """
        with self._lock:
            if self._current_trace_id and self._active_spans:
                latest_span = list(self._active_spans.values())[-1]
                traceparent = f"00-{latest_span.trace_id}-{latest_span.span_id}-01"
                headers["traceparent"] = traceparent
        return headers

    def extract_context(self, headers: dict[str, str]) -> tuple[str | None, str | None]:
        """Extract trace context from HTTP headers.

        Args:
            headers: HTTP headers potentially containing trace context.

        Returns:
            Tuple of (trace_id, parent_span_id) or (None, None).
        """
        traceparent = headers.get("traceparent", "")
        if traceparent:
            parts = traceparent.split("-")
            if len(parts) >= 3:
                return parts[1], parts[2]
        return None, None


# ---------------------------------------------------------------------------
# Structured Logger
# ---------------------------------------------------------------------------


class StructuredLogger:
    """JSON-structured logger with correlation tracking.

    Produces machine-parseable log output with standard fields
    for agent identity guard events.

    Example::

        slogger = StructuredLogger(service="enforcement")
        slogger.info("Request authorized", agent_id="agent-123", action="s3:PutObject")
    """

    def __init__(
        self,
        service: str = "aws-agent-identity-guard",
        output_handler: Any | None = None,
    ) -> None:
        """Initialize the structured logger.

        Args:
            service: Service name included in all log entries.
            output_handler: Optional callable(str) for log output.
                           Defaults to Python logging.
        """
        self._service = service
        self._output_handler = output_handler
        self._correlation_id: str | None = None
        self._entries: deque[LogEntry] = deque(maxlen=10000)
        self._lock = threading.Lock()

    def set_correlation_id(self, correlation_id: str) -> None:
        """Set the active correlation ID for subsequent log entries.

        Args:
            correlation_id: Correlation ID to attach to log entries.
        """
        self._correlation_id = correlation_id

    def clear_correlation_id(self) -> None:
        """Clear the active correlation ID."""
        self._correlation_id = None

    def debug(self, message: str, **kwargs: Any) -> LogEntry:
        """Log at DEBUG level.

        Args:
            message: Log message.
            **kwargs: Additional structured fields.

        Returns:
            The created LogEntry.
        """
        return self._log(LogLevel.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs: Any) -> LogEntry:
        """Log at INFO level.

        Args:
            message: Log message.
            **kwargs: Additional structured fields.

        Returns:
            The created LogEntry.
        """
        return self._log(LogLevel.INFO, message, **kwargs)

    def warn(self, message: str, **kwargs: Any) -> LogEntry:
        """Log at WARN level.

        Args:
            message: Log message.
            **kwargs: Additional structured fields.

        Returns:
            The created LogEntry.
        """
        return self._log(LogLevel.WARN, message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> LogEntry:
        """Log at ERROR level.

        Args:
            message: Log message.
            **kwargs: Additional structured fields.

        Returns:
            The created LogEntry.
        """
        return self._log(LogLevel.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs: Any) -> LogEntry:
        """Log at CRITICAL level.

        Args:
            message: Log message.
            **kwargs: Additional structured fields.

        Returns:
            The created LogEntry.
        """
        return self._log(LogLevel.CRITICAL, message, **kwargs)

    def _log(self, level: LogLevel, message: str, **kwargs: Any) -> LogEntry:
        """Internal log method.

        Args:
            level: Log severity level.
            message: Log message.
            **kwargs: Additional structured fields.

        Returns:
            The created LogEntry.
        """
        entry = LogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=level.value,
            message=message,
            correlation_id=kwargs.pop("correlation_id", self._correlation_id or ""),
            agent_id=kwargs.pop("agent_id", ""),
            action=kwargs.pop("action", ""),
            decision=kwargs.pop("decision", ""),
            latency=kwargs.pop("latency", 0.0),
            extra=kwargs,
        )

        with self._lock:
            self._entries.append(entry)

        output = entry.to_json()
        if self._output_handler:
            self._output_handler(output)
        else:
            logger.log(
                getattr(logging, level.value if level.value != "WARN" else "WARNING", "INFO"),
                output,
            )

        return entry

    def get_entries(self, limit: int = 100) -> list[LogEntry]:
        """Retrieve recent log entries.

        Args:
            limit: Maximum entries to return.

        Returns:
            List of recent log entries.
        """
        with self._lock:
            entries = list(self._entries)
        return entries[-limit:]


# ---------------------------------------------------------------------------
# Audit Trail
# ---------------------------------------------------------------------------


class AuditTrail:
    """Tamper-evident audit trail with integrity chain hashing.

    Each event references the hash of the previous event, forming
    a chain that can be verified for integrity and tamper detection.

    Example::

        audit = AuditTrail()
        audit.record(AuditEvent(
            event_id="evt-1",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id="agent-123",
            action="s3:PutObject",
            decision="allowed",
            reason="policy_match",
            correlation_id="corr-abc",
        ))
        assert audit.verify_integrity()
    """

    def __init__(self, max_events: int = 100000) -> None:
        """Initialize the audit trail.

        Args:
            max_events: Maximum events to retain in memory.
        """
        self._events: deque[AuditEvent] = deque(maxlen=max_events)
        self._last_hash: str = "genesis"
        self._lock = threading.Lock()
        self._correlation_index: dict[str, list[int]] = {}

    @property
    def event_count(self) -> int:
        """Total number of events in the trail."""
        return len(self._events)

    def record(self, event: AuditEvent) -> AuditEvent:
        """Record an audit event with integrity chaining.

        The event's previous_hash and event_hash fields are set
        automatically to maintain the integrity chain.

        Args:
            event: The audit event to record.

        Returns:
            The event with hash fields populated.
        """
        with self._lock:
            event.previous_hash = self._last_hash
            event.event_hash = event.compute_hash()
            self._last_hash = event.event_hash

            index = len(self._events)
            self._events.append(event)

            # Update correlation index
            if event.correlation_id:
                self._correlation_index.setdefault(event.correlation_id, []).append(index)

        logger.debug(
            "Audit event recorded: id=%s agent=%s action=%s decision=%s",
            event.event_id,
            event.agent_id,
            event.action,
            event.decision,
        )
        return event

    def query(self, filters: AuditQueryFilters) -> list[AuditEvent]:
        """Query audit events with filters.

        Args:
            filters: Query filter criteria.

        Returns:
            List of matching audit events.
        """
        with self._lock:
            # Optimize correlation_id queries using index
            if filters.correlation_id and filters.correlation_id in self._correlation_index:
                indices = self._correlation_index[filters.correlation_id]
                candidates = [self._events[i] for i in indices if i < len(self._events)]
            else:
                candidates = list(self._events)

        results: list[AuditEvent] = []
        for event in candidates:
            if filters.agent_id and event.agent_id != filters.agent_id:
                continue
            if filters.action and event.action != filters.action:
                continue
            if filters.decision and event.decision != filters.decision:
                continue
            if filters.correlation_id and event.correlation_id != filters.correlation_id:
                continue
            if filters.start_time and event.timestamp < filters.start_time:
                continue
            if filters.end_time and event.timestamp > filters.end_time:
                continue
            results.append(event)
            if len(results) >= filters.limit:
                break

        return results

    def verify_integrity(self) -> bool:
        """Verify the integrity of the entire audit trail chain.

        Checks that each event's hash matches its computed hash and
        that the chain of previous_hash references is unbroken.

        Returns:
            True if the chain is intact, False if tampering is detected.
        """
        with self._lock:
            events = list(self._events)

        if not events:
            return True

        expected_previous = "genesis"
        for i, event in enumerate(events):
            # Verify previous hash linkage
            if event.previous_hash != expected_previous:
                logger.error(
                    "Integrity violation at event %d (%s): "
                    "expected previous_hash=%s, got=%s",
                    i,
                    event.event_id,
                    expected_previous,
                    event.previous_hash,
                )
                return False

            # Verify event hash
            computed = event.compute_hash()
            if event.event_hash != computed:
                logger.error(
                    "Integrity violation at event %d (%s): "
                    "hash mismatch (stored=%s, computed=%s)",
                    i,
                    event.event_id,
                    event.event_hash,
                    computed,
                )
                return False

            expected_previous = event.event_hash

        return True

    def get_events_by_correlation(self, correlation_id: str) -> list[AuditEvent]:
        """Get all events for a specific correlation ID.

        Args:
            correlation_id: The correlation ID to look up.

        Returns:
            List of events sharing the correlation ID.
        """
        return self.query(AuditQueryFilters(correlation_id=correlation_id))


# ---------------------------------------------------------------------------
# Dashboard Metrics
# ---------------------------------------------------------------------------


@dataclass
class DecisionRecord:
    """Internal record for dashboard aggregation."""

    timestamp: float
    agent_id: str
    action: str
    decision: str
    risk_score: float = 0.0
    latency_ms: float = 0.0


class DashboardMetrics:
    """Aggregate metrics for dashboard consumption.

    Provides pre-computed views suitable for real-time dashboards,
    including top risky agents, recent decisions, throughput, and trends.

    Example::

        dashboard = DashboardMetrics()
        dashboard.record_decision(DecisionRecord(...))
        top_risky = dashboard.top_risky_agents(10)
    """

    def __init__(self, max_records: int = 100000) -> None:
        """Initialize dashboard metrics aggregator.

        Args:
            max_records: Maximum decision records to retain.
        """
        self._records: deque[DecisionRecord] = deque(maxlen=max_records)
        self._agent_risk_scores: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def record_decision(self, record: DecisionRecord) -> None:
        """Record a decision for dashboard aggregation.

        Args:
            record: The decision record to store.
        """
        with self._lock:
            self._records.append(record)
            self._agent_risk_scores.setdefault(record.agent_id, []).append(
                record.risk_score
            )

    def top_risky_agents(self, n: int = 10) -> list[dict[str, Any]]:
        """Get the top N riskiest agents by average risk score.

        Args:
            n: Number of agents to return.

        Returns:
            List of dicts with agent_id, avg_risk_score, and decision_count.
        """
        with self._lock:
            agent_scores = {
                agent_id: {
                    "agent_id": agent_id,
                    "avg_risk_score": sum(scores) / len(scores) if scores else 0.0,
                    "decision_count": len(scores),
                }
                for agent_id, scores in self._agent_risk_scores.items()
            }

        sorted_agents = sorted(
            agent_scores.values(),
            key=lambda x: x["avg_risk_score"],
            reverse=True,
        )
        return sorted_agents[:n]

    def recent_decisions(self, n: int = 50) -> list[dict[str, Any]]:
        """Get the N most recent decisions.

        Args:
            n: Number of decisions to return.

        Returns:
            List of decision records as dicts.
        """
        with self._lock:
            records = list(self._records)

        recent = records[-n:][::-1]
        return [
            {
                "timestamp": r.timestamp,
                "agent_id": r.agent_id,
                "action": r.action,
                "decision": r.decision,
                "risk_score": r.risk_score,
                "latency_ms": r.latency_ms,
            }
            for r in recent
        ]

    def decisions_per_second(self, window_seconds: float = 60.0) -> float:
        """Calculate decision throughput over a time window.

        Args:
            window_seconds: Time window in seconds to measure.

        Returns:
            Decisions per second within the window.
        """
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            count = sum(1 for r in self._records if r.timestamp >= cutoff)

        return count / window_seconds if window_seconds > 0 else 0.0

    def risk_trend(self, time_range_seconds: float = 3600.0, buckets: int = 12) -> list[dict[str, Any]]:
        """Calculate risk score trend over a time range.

        Divides the time range into equal buckets and computes
        average risk score for each bucket.

        Args:
            time_range_seconds: Total time range to analyze.
            buckets: Number of time buckets.

        Returns:
            List of dicts with bucket_start, bucket_end, avg_risk_score, count.
        """
        now = time.time()
        start = now - time_range_seconds
        bucket_size = time_range_seconds / buckets

        with self._lock:
            records = [r for r in self._records if r.timestamp >= start]

        trend: list[dict[str, Any]] = []
        for i in range(buckets):
            bucket_start = start + (i * bucket_size)
            bucket_end = bucket_start + bucket_size
            bucket_records = [
                r for r in records if bucket_start <= r.timestamp < bucket_end
            ]
            avg_score = (
                sum(r.risk_score for r in bucket_records) / len(bucket_records)
                if bucket_records
                else 0.0
            )
            trend.append({
                "bucket_start": bucket_start,
                "bucket_end": bucket_end,
                "avg_risk_score": avg_score,
                "count": len(bucket_records),
            })

        return trend
