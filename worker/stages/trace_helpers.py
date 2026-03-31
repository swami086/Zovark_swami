"""
Tracing helpers for investigation pipeline stages.

Each stage calls trace_stage() to create a span around its execution.
Tracing is non-blocking — failures are swallowed, never affect the pipeline.
"""
import time
from tracing import get_tracer, trace_enabled


def trace_stage(stage_name: str, data: dict):
    """Create and return a tracing span for a pipeline stage.

    Usage:
        span = trace_stage("ingest", data)
        try:
            # ... do work ...
            span.set_attribute("result.status", "completed")
        finally:
            span.end()
    """
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
