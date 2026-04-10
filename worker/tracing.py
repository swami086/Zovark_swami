"""
OpenTelemetry tracing for Zovark worker.

Provides distributed tracing for the investigation pipeline.
Exports traces via OTLP HTTP to Signoz (self-hosted, ClickHouse-backed).

Usage:
    from tracing import tracer, trace_enabled

    if trace_enabled:
        with tracer.start_as_current_span("my_operation") as span:
            span.set_attribute("key", "value")
            ...

All tracing is optional — if OTEL_ENABLED=false or the collector is unreachable,
the pipeline works identically. Tracing never blocks or fails investigations.
"""
import os
from contextlib import contextmanager

try:
    from settings import settings
    OTEL_ENABLED = settings.otel_enabled
    OTEL_ENDPOINT = settings.otel_endpoint.rstrip("/")
except Exception:
    OTEL_ENABLED = os.environ.get("OTEL_ENABLED", "false").lower() in ("1", "true", "yes")
    OTEL_ENDPOINT = os.environ.get(
        "OTEL_EXPORTER_OTLP_ENDPOINT", "http://zovark-signoz-collector:4318"
    ).rstrip("/")

# Sentinel for disabled tracing
trace_enabled = False
tracer = None


class _NoOpSpan:
    """No-op span for when tracing is disabled."""
    def set_attribute(self, key, value): pass
    def set_status(self, *args, **kwargs): pass
    def record_exception(self, exc): pass
    def add_event(self, name, attributes=None): pass
    def end(self): pass
    def __enter__(self): return self
    def __exit__(self, *args): pass


class _NoOpTracer:
    """No-op tracer for when tracing is disabled."""
    def start_as_current_span(self, name, **kwargs):
        return _NoOpSpan()

    def start_span(self, name, **kwargs):
        return _NoOpSpan()


@contextmanager
def _noop_span_context(name, **kwargs):
    yield _NoOpSpan()


def init_tracing():
    """Initialize OpenTelemetry tracing. Safe to call even if deps missing."""
    global tracer, trace_enabled

    if not OTEL_ENABLED:
        tracer = _NoOpTracer()
        trace_enabled = False
        return tracer

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource

        resource = Resource.create({
            "service.name": "zovark-worker",
            "service.version": "3.0.0",
            "deployment.environment": os.environ.get("ZOVARK_ENV", "development"),
        })

        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=f"{OTEL_ENDPOINT}/v1/traces")
        provider.add_span_processor(BatchSpanProcessor(
            exporter,
            max_queue_size=2048,
            max_export_batch_size=512,
            schedule_delay_millis=5000,
        ))
        trace.set_tracer_provider(provider)

        tracer = trace.get_tracer("zovark-worker", "3.0.0")
        trace_enabled = True
        print(f"[OTEL] Tracing enabled → {OTEL_ENDPOINT}", flush=True)
        init_otel_logging()
        try:
            from metrics import init_worker_metrics
            init_worker_metrics()
        except Exception as me:
            print(f"[OTEL] metrics hook failed (non-fatal): {me}", flush=True)
        return tracer

    except ImportError:
        print("[OTEL] opentelemetry-sdk not installed, tracing disabled", flush=True)
        tracer = _NoOpTracer()
        trace_enabled = False
        return tracer
    except Exception as e:
        print(f"[OTEL] Tracing init failed (non-fatal): {e}", flush=True)
        tracer = _NoOpTracer()
        trace_enabled = False
        init_otel_logging()
        return tracer


def init_otel_logging():
    """Export worker logs to SigNoz via OTLP HTTP (/v1/logs). No-op if OTEL disabled or deps missing."""
    if not OTEL_ENABLED:
        return
    try:
        import logging

        from opentelemetry._logs import set_logger_provider
        from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
        from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
        from opentelemetry.sdk.resources import Resource

        resource = Resource.create({
            "service.name": "zovark-worker",
            "service.version": "3.0.0",
            "deployment.environment": os.environ.get("ZOVARK_ENV", "development"),
        })
        provider = LoggerProvider(resource=resource)
        provider.add_log_record_processor(
            BatchLogRecordProcessor(
                OTLPLogExporter(endpoint=f"{OTEL_ENDPOINT}/v1/logs"),
                max_export_batch_size=256,
                schedule_delay_millis=2000,
            )
        )
        set_logger_provider(provider)
        handler = LoggingHandler(logger_provider=provider, level=logging.NOTSET)
        py_log = logging.getLogger("zovark_worker")
        py_log.handlers.clear()
        py_log.setLevel(logging.DEBUG)
        py_log.propagate = False
        py_log.addHandler(handler)
        print(f"[OTEL] Log export enabled → {OTEL_ENDPOINT}/v1/logs", flush=True)
    except ImportError:
        print("[OTEL] opentelemetry log exporter not available, log export skipped", flush=True)
    except Exception as e:
        print(f"[OTEL] Log export init failed (non-fatal): {e}", flush=True)


def get_tracer():
    """Get the global tracer (initializes on first call)."""
    global tracer
    if tracer is None:
        init_tracing()
    return tracer
