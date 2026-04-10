"""
Tracing helpers for investigation pipeline stages (Ticket 7).

Spans are non-blocking — failures never affect the pipeline.
"""
from contextlib import contextmanager
from typing import Any, Dict

from tracing import get_tracer, trace_enabled


@contextmanager
def trace_investigation_pipeline(data: dict):
    """Root span for the investigation run (opened in ingest_alert — replay-safe)."""
    if not trace_enabled:
        yield
        return
    tracer = get_tracer()
    tid = str(data.get("trace_id", "") or "")
    with tracer.start_as_current_span("investigation.pipeline") as span:
        try:
            span.set_attribute("zovark.task_id", data.get("task_id", "") or "")
            span.set_attribute("zovark.tenant_id", str(data.get("tenant_id", "") or ""))
            span.set_attribute("zovark.task_type", data.get("task_type", "") or "")
            span.set_attribute("zovark.trace_id", tid)
        except Exception:
            pass
        yield


@contextmanager
def trace_stage_ingest_span(data: dict):
    """Inner ingest stage span under investigation.pipeline."""
    if not trace_enabled:
        yield
        return
    tracer = get_tracer()
    with tracer.start_as_current_span("stage.ingest") as span:
        try:
            span.set_attribute("zovark.stage", "ingest")
            span.set_attribute("zovark.task_id", data.get("task_id", "") or "")
            span.set_attribute("zovark.tenant_id", str(data.get("tenant_id", "") or ""))
            span.set_attribute("zovark.task_type", data.get("task_type", "") or "")
            span.set_attribute("zovark.trace_id", str(data.get("trace_id", "") or ""))
        except Exception:
            pass
        yield


def _plan_meta_from_result(result: Dict[str, Any]) -> tuple:
    path_taken = str(result.get("path_taken", "") or result.get("source", "") or "")
    plan_name = str(result.get("source", "") or result.get("path_taken", "") or "")
    plan = result.get("plan")
    tool_count = len(plan) if isinstance(plan, list) else 0
    return path_taken, plan_name, tool_count


@contextmanager
def trace_stage_analyze_span(data: dict):
    """stage.analyze with Ticket 7 attributes (call trace_analyze_apply_result before exit)."""
    if not trace_enabled:
        yield None
        return
    tracer = get_tracer()
    with tracer.start_as_current_span("stage.analyze") as span:
        try:
            span.set_attribute("zovark.stage", "analyze")
            span.set_attribute("zovark.task_id", data.get("task_id", "") or "")
            span.set_attribute("zovark.tenant_id", str(data.get("tenant_id", "") or ""))
            span.set_attribute("zovark.task_type", data.get("task_type", "") or "")
            span.set_attribute("zovark.trace_id", str(data.get("trace_id", "") or ""))
        except Exception:
            pass
        yield span


def trace_analyze_apply_result(span: Any, result: Dict[str, Any]) -> None:
    if span is None:
        return
    try:
        path, pname, tc = _plan_meta_from_result(result)
        span.set_attribute("plan_path", path)
        span.set_attribute("plan_name", pname)
        span.set_attribute("tool_count", int(tc))
    except Exception:
        pass


@contextmanager
def trace_stage_store_span(data: dict):
    """stage.store — call trace_store_apply_outcome before exit."""
    if not trace_enabled:
        yield None
        return
    tracer = get_tracer()
    with tracer.start_as_current_span("stage.store") as span:
        try:
            span.set_attribute("zovark.stage", "store")
            span.set_attribute("zovark.task_id", data.get("task_id", "") or "")
            span.set_attribute("zovark.tenant_id", str(data.get("tenant_id", "") or ""))
            span.set_attribute("zovark.task_type", data.get("task_type", "") or "")
            span.set_attribute("zovark.trace_id", str(data.get("trace_id", "") or ""))
        except Exception:
            pass
        yield span


def trace_store_apply_outcome(span: Any, verdict: str, risk_score: int, ioc_count: int, trace_id: str) -> None:
    if span is None:
        return
    try:
        span.set_attribute("verdict", str(verdict or ""))
        span.set_attribute("risk_score", int(risk_score or 0))
        span.set_attribute("ioc_count", int(ioc_count or 0))
        span.set_attribute("zovark.trace_id", str(trace_id or ""))
    except Exception:
        pass


def trace_stage(stage_name: str, data: dict):
    """Create and return a tracing span for a pipeline stage (legacy helper)."""
    tracer = get_tracer()
    span = tracer.start_span(f"stage.{stage_name}")
    try:
        span.set_attribute("zovark.stage", stage_name)
        span.set_attribute("zovark.task_id", data.get("task_id", ""))
        span.set_attribute("zovark.tenant_id", data.get("tenant_id", ""))
        span.set_attribute("zovark.task_type", data.get("task_type", ""))
        span.set_attribute("zovark.trace_id", data.get("trace_id", ""))
    except Exception:
        pass
    return span


def trace_tool(tool_name: str):
    """Create a span for a tool execution."""
    tracer = get_tracer()
    span = tracer.start_span(f"tool.{tool_name}")
    span.set_attribute("tool.name", tool_name)
    return span


def trace_llm_call(model_name: str, stage: str):
    """Create a span for an LLM call."""
    tracer = get_tracer()
    span = tracer.start_span("llm.call")
    span.set_attribute("llm.model", model_name)
    span.set_attribute("llm.stage", stage)
    return span
