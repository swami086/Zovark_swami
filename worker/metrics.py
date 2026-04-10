"""
OpenTelemetry metrics for the Zovark worker (Ticket 7 — OTLP push to SigNoz).

Counters/histograms are no-ops when OTEL is disabled or SDK is missing.
"""
from __future__ import annotations

import os
import time
_metrics_on = False
_metrics_provider_initialized = False
_meter = None
_investigations_completed = None
_llm_calls_total = None
_llm_duration = None
_tool_runs_total = None
_tool_duration = None
_pipeline_stages = None


def _env_otel_on() -> bool:
    try:
        from settings import settings as s
        return bool(s.otel_enabled)
    except Exception:
        return os.environ.get("OTEL_ENABLED", "false").lower() in ("1", "true", "yes")


def _endpoint() -> str:
    try:
        from settings import settings as s
        return str(s.otel_endpoint).rstrip("/")
    except Exception:
        return os.environ.get(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "http://zovark-signoz-collector:4318",
        ).rstrip("/")


def init_worker_metrics() -> None:
    """Register OTLP metric exporter (call after or from tracing init)."""
    global _metrics_on, _metrics_provider_initialized, _meter, _investigations_completed, _llm_calls_total
    global _llm_duration, _tool_runs_total, _tool_duration, _pipeline_stages

    if not _env_otel_on():
        return
    if _metrics_provider_initialized:
        return
    try:
        from opentelemetry import metrics
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.sdk.resources import Resource

        ep = _endpoint()
        resource = Resource.create({
            "service.name": "zovark-worker",
            "service.version": "3.2.1",
            "deployment.environment": os.environ.get("ZOVARK_ENV", "development"),
        })
        reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=f"{ep}/v1/metrics"),
            export_interval_millis=10000,
        )
        provider = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(provider)
        _meter = metrics.get_meter("zovark-worker", "3.2.1")
        _investigations_completed = _meter.create_counter(
            "zovark.worker.investigations.completed",
            description="Investigations completed by verdict/status",
        )
        _llm_calls_total = _meter.create_counter(
            "zovark.worker.llm.calls",
            description="LLM HTTP calls",
        )
        _llm_duration = _meter.create_histogram(
            "zovark.worker.llm.duration_seconds",
            description="LLM call duration",
        )
        _tool_runs_total = _meter.create_counter(
            "zovark.worker.tool.executions",
            description="Tool executions",
        )
        _tool_duration = _meter.create_histogram(
            "zovark.worker.tool.duration_seconds",
            description="Per-tool duration",
        )
        _pipeline_stages = _meter.create_histogram(
            "zovark.worker.pipeline.stage_seconds",
            description="Pipeline stage wall time (activity-local)",
        )
        _metrics_on = True
        _metrics_provider_initialized = True
        print(f"[OTEL] Worker metrics enabled → {ep}/v1/metrics", flush=True)
    except Exception as e:
        print(f"[OTEL] Worker metrics init failed (non-fatal): {e}", flush=True)
        _metrics_on = False


def record_investigation_completed(verdict: str, status: str) -> None:
    if not _metrics_on or _investigations_completed is None:
        return
    try:
        _investigations_completed.add(
            1,
            {"verdict": verdict or "unknown", "status": status or "unknown"},
        )
    except Exception:
        pass


def record_llm_call(duration_sec: float, success: bool, tokens_in: int = 0, tokens_out: int = 0) -> None:
    if not _metrics_on:
        return
    try:
        if _llm_calls_total:
            _llm_calls_total.add(
                1,
                {"success": str(success).lower()},
            )
        if _llm_duration:
            _llm_duration.record(
                max(0.0, duration_sec),
                {"success": str(success).lower()},
            )
    except Exception:
        pass


def record_tool_execution(tool_name: str, duration_sec: float, error: bool) -> None:
    if not _metrics_on:
        return
    try:
        if _tool_runs_total:
            _tool_runs_total.add(1, {"tool": tool_name or "unknown", "error": str(error).lower()})
        if _tool_duration:
            _tool_duration.record(max(0.0, duration_sec), {"tool": tool_name or "unknown"})
    except Exception:
        pass


def record_pipeline_stage(stage: str, duration_sec: float) -> None:
    if not _metrics_on or _pipeline_stages is None:
        return
    try:
        _pipeline_stages.record(max(0.0, duration_sec), {"stage": stage})
    except Exception:
        pass


def stage_timer(stage: str):
    """Context manager: record stage duration on exit."""
    class _T:
        def __enter__(self):
            self._t0 = time.perf_counter()
            return self

        def __exit__(self, *a):
            record_pipeline_stage(stage, time.perf_counter() - self._t0)
            return False

    return _T()
