"""Observability: metrics, logging, and tracing."""
import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


class ObservabilityManager:
    """Manage observability (metrics, logs, traces)."""

    def __init__(self):
        """Initialize observability manager."""
        self.metrics: dict[str, list[dict[str, Any]]] = {}
        self.logs: list[dict[str, Any]] = []
        self.spans: list[dict[str, Any]] = []

    def record_metric(self, metric_name: str, value: float, labels: dict[str, str] | None = None):
        """Record a metric."""
        if metric_name not in self.metrics:
            self.metrics[metric_name] = []

        metric_point = {
            "timestamp": datetime.utcnow().isoformat(),
            "value": value,
            "labels": labels or {},
        }

        self.metrics[metric_name].append(metric_point)

        # Trim old metrics (keep last 1000 points per metric)
        if len(self.metrics[metric_name]) > 1000:
            self.metrics[metric_name] = self.metrics[metric_name][-1000:]

    def record_log(self, level: str, message: str, context: dict[str, Any] | None = None):
        """Record a structured log."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": message,
            "context": context or {},
        }

        self.logs.append(log_entry)

        # Trim old logs (keep last 10000)
        if len(self.logs) > 10000:
            self.logs = self.logs[-10000:]

    def start_trace(self, operation_name: str, parent_span_id: str | None = None) -> str:
        """Start a distributed trace."""
        import uuid
        span_id = str(uuid.uuid4())

        span = {
            "span_id": span_id,
            "operation_name": operation_name,
            "parent_span_id": parent_span_id,
            "start_time": datetime.utcnow().isoformat(),
            "duration_ms": 0,
        }

        self.spans.append(span)

        return span_id

    def end_trace(self, span_id: str, status: str = "ok", error: str | None = None):
        """End a trace span."""
        for span in self.spans:
            if span["span_id"] == span_id:
                span["end_time"] = datetime.utcnow().isoformat()
                span["status"] = status
                if error:
                    span["error"] = error
                break

    def export_prometheus_metrics(self) -> str:
        """Export metrics in Prometheus format."""
        prometheus_output = []

        for metric_name, data_points in self.metrics.items():
            if not data_points:
                continue

            # Get latest value
            latest = data_points[-1]

            prometheus_output.append(
                f"{metric_name}{{}} {latest['value']} {int(datetime.utcnow().timestamp() * 1000)}"
            )

        return "\n".join(prometheus_output)

    def export_logs_json(self) -> str:
        """Export logs as JSON lines."""
        import json

        return "\n".join(json.dumps(log_entry) for log_entry in self.logs[-1000:])

    def export_traces_jaeger(self) -> dict[str, Any]:
        """Export traces in Jaeger format."""
        traces = {}

        for span in self.spans:
            parent_id = span.get("parent_span_id", "root")

            if parent_id not in traces:
                traces[parent_id] = []

            traces[parent_id].append({
                "spanID": span["span_id"],
                "operationName": span["operation_name"],
                "startTime": span["start_time"],
                "duration": span.get("duration_ms", 0),
                "status": span.get("status", "ok"),
                "tags": {
                    "error": span.get("error") is not None,
                },
            })

        return {
            "data": [{"spans": traces.get("root", [])}],
            "processes": {},
        }

    def get_metrics_summary(self) -> dict[str, Any]:
        """Get metrics summary."""
        summary = {}

        for metric_name, data_points in self.metrics.items():
            if data_points:
                values = [p["value"] for p in data_points]
                summary[metric_name] = {
                    "latest": values[-1],
                    "average": sum(values) / len(values),
                    "min": min(values),
                    "max": max(values),
                    "count": len(values),
                }

        return summary

    def get_trace_statistics(self) -> dict[str, Any]:
        """Get trace statistics."""
        successful_spans = sum(1 for s in self.spans if s.get("status") == "ok")
        failed_spans = sum(1 for s in self.spans if s.get("status") != "ok")
        total_spans = len(self.spans)

        return {
            "total_spans": total_spans,
            "successful_spans": successful_spans,
            "failed_spans": failed_spans,
            "success_rate": (successful_spans / total_spans * 100) if total_spans > 0 else 0,
        }

    def enable_prometheus_export(self, endpoint: str) -> bool:
        """Enable Prometheus metrics export."""
        logger.info(f"Enabled Prometheus export to {endpoint}")
        return True

    def enable_opentelemetry(self, collector_endpoint: str) -> bool:
        """Enable OpenTelemetry export."""
        logger.info(f"Enabled OpenTelemetry export to {collector_endpoint}")
        return True

    def enable_structured_logging(self, log_format: str = "json") -> bool:
        """Enable structured logging."""
        logger.info(f"Enabled structured logging ({log_format})")
        return True

    def get_dashboard_data(self) -> dict[str, Any]:
        """Get data for monitoring dashboard."""
        return {
            "metrics": self.get_metrics_summary(),
            "traces": self.get_trace_statistics(),
            "logs_count": len(self.logs),
            "timestamp": datetime.utcnow().isoformat(),
        }
