"""
Tool runner — executes investigation plans against SIEM events.
Supports variable resolution, conditional branching, timeouts, and error isolation.
"""
import re
import json
import time
import signal
from typing import Any

from tools.catalog import TOOL_CATALOG


# --- Condition evaluator (no eval!) ---
_COMPARISON_RE = re.compile(
    r'^\$(\w+(?:\.\w+)?)\s*(>=|<=|!=|>|<|==)\s*(.+)$'
)
_BOOL_RE = re.compile(r'^\$(\w+(?:\.\w+)?)$')


def _resolve_ref(ref: str, step_results: dict, siem_event: dict, raw_log: str,
                 history_context: dict, institutional_knowledge: dict) -> Any:
    """Resolve a variable reference like $raw_log, $siem_event.field, $stepN, $stepN.field, $stepN.count."""
    if not isinstance(ref, str) or not ref.startswith("$"):
        return ref

    var = ref[1:]  # strip leading $

    if var == "raw_log":
        return raw_log
    if var == "siem_event":
        return siem_event
    if var == "correlation_context":
        return history_context
    if var == "institutional_knowledge":
        return institutional_knowledge

    # $siem_event.field
    if var.startswith("siem_event."):
        field = var[len("siem_event."):]
        return siem_event.get(field, "")

    # $stepN or $stepN.field or $stepN.count
    step_match = re.match(r'^step(\d+)(?:\.(\w+))?$', var)
    if step_match:
        step_idx = int(step_match.group(1))
        field = step_match.group(2)
        step_val = step_results.get(step_idx)
        if step_val is None:
            return 0 if field == "count" else None

        if field is None:
            return step_val
        if field == "count":
            if isinstance(step_val, (list, dict)):
                return len(step_val)
            return step_val if isinstance(step_val, (int, float)) else 0
        if isinstance(step_val, dict):
            return step_val.get(field)
        if isinstance(step_val, list):
            return len(step_val) if field == "length" else step_val
        return step_val

    return ref  # unresolved, return as-is


def _resolve_args(args: dict, step_results: dict, siem_event: dict, raw_log: str,
                  history_context: dict, institutional_knowledge: dict) -> dict:
    """Resolve all variable references in a tool's arguments."""
    resolved = {}
    for key, val in args.items():
        if isinstance(val, str) and val.startswith("$"):
            resolved[key] = _resolve_ref(val, step_results, siem_event, raw_log,
                                         history_context, institutional_knowledge)
        elif isinstance(val, list):
            resolved[key] = [
                _resolve_ref(v, step_results, siem_event, raw_log,
                             history_context, institutional_knowledge) if isinstance(v, str) and v.startswith("$") else v
                for v in val
            ]
        else:
            resolved[key] = val
    return resolved


def _evaluate_condition(condition: str, step_results: dict, siem_event: dict,
                        raw_log: str, history_context: dict, institutional_knowledge: dict) -> bool:
    """Evaluate a condition string without eval(). Supports numeric comparisons and boolean checks."""
    condition = condition.strip()

    # Comparison: $stepN > 100, $stepN.count >= 5, etc.
    comp_match = _COMPARISON_RE.match(condition)
    if comp_match:
        var_ref = "$" + comp_match.group(1)
        op = comp_match.group(2)
        rhs_str = comp_match.group(3).strip().strip('"').strip("'")

        lhs = _resolve_ref(var_ref, step_results, siem_event, raw_log,
                           history_context, institutional_knowledge)

        # Parse RHS
        if rhs_str == "null" or rhs_str == "None":
            rhs = None
        elif rhs_str == "true":
            rhs = True
        elif rhs_str == "false":
            rhs = False
        else:
            try:
                rhs = float(rhs_str)
                if rhs == int(rhs):
                    rhs = int(rhs)
            except ValueError:
                rhs = rhs_str

        # Coerce LHS for numeric comparison
        if isinstance(rhs, (int, float)) and not isinstance(lhs, (int, float)):
            try:
                lhs = float(lhs) if lhs is not None else 0
            except (ValueError, TypeError):
                lhs = 0

        try:
            if op == ">":
                return lhs > rhs
            elif op == ">=":
                return lhs >= rhs
            elif op == "<":
                return lhs < rhs
            elif op == "<=":
                return lhs <= rhs
            elif op == "==":
                return lhs == rhs
            elif op == "!=":
                return lhs != rhs
        except TypeError:
            return False

    # Boolean check: $stepN.escalation_recommended
    bool_match = _BOOL_RE.match(condition)
    if bool_match:
        var_ref = "$" + bool_match.group(1)
        val = _resolve_ref(var_ref, step_results, siem_event, raw_log,
                           history_context, institutional_knowledge)
        return bool(val)

    return False


def execute_plan(plan: list, siem_event: dict,
                 history_context: dict = None, institutional_knowledge: dict = None,
                 total_timeout: float = 30.0, per_tool_timeout: float = 5.0,
                 task_id: str = "", tenant_id: str = "", trace_id: str = "") -> dict:
    """Execute an investigation plan — list of tool steps — against a SIEM event.

    Returns:
        dict with: findings, iocs, risk_score, verdict, tools_executed, tool_results, errors
    """
    if history_context is None:
        history_context = {}
    if institutional_knowledge is None:
        institutional_knowledge = {}

    raw_log = siem_event.get("raw_log", "")
    step_results = {}
    all_findings = []
    all_iocs = []
    risk_scores = []
    tool_names_executed = []
    errors = []
    start_time = time.monotonic()

    for i, step in enumerate(plan):
        # Total timeout check
        if time.monotonic() - start_time > total_timeout:
            errors.append(f"Total timeout ({total_timeout}s) exceeded at step {i}")
            break

        # Determine actual step (handle conditional branching)
        actual_step = step
        if "condition" in step:
            cond_result = _evaluate_condition(
                step["condition"], step_results, siem_event, raw_log,
                history_context, institutional_knowledge
            )
            if cond_result:
                actual_step = step.get("if_true", {})
            else:
                actual_step = step.get("if_false", {})
            if not actual_step or "tool" not in actual_step:
                step_results[i + 1] = None
                continue

        tool_name = actual_step.get("tool", "")
        tool_args = actual_step.get("args", {})

        # Look up tool
        tool_entry = TOOL_CATALOG.get(tool_name)
        if not tool_entry:
            errors.append(f"Step {i}: unknown tool '{tool_name}'")
            step_results[i + 1] = None
            continue

        # Resolve variable references
        resolved_args = _resolve_args(
            tool_args, step_results, siem_event, raw_log,
            history_context, institutional_knowledge
        )

        # Emit tool_started event
        if task_id:
            try:
                from events import emit_event
                emit_event(task_id, tenant_id, trace_id, "tool_started", {"tool": tool_name, "step": i})
            except Exception:
                pass

        # Execute with per-tool timeout and optional tracing
        try:
            # Start trace span for this tool
            try:
                from tracing import get_tracer
                _span = get_tracer().start_span(f"tool.{tool_name}")
                _span.set_attribute("tool.name", tool_name)
                _span.set_attribute("tool.step", i)
            except Exception:
                _span = None

            tool_start = time.monotonic()
            result = tool_entry["function"](**resolved_args)
            tool_elapsed = time.monotonic() - tool_start

            if tool_elapsed > per_tool_timeout:
                errors.append(f"Step {i}: {tool_name} took {tool_elapsed:.1f}s (limit {per_tool_timeout}s)")

            # Record tool result in span
            if _span:
                try:
                    _span.set_attribute("tool.duration_ms", int(tool_elapsed * 1000))
                    _span.set_attribute("tool.success", True)
                    if isinstance(result, dict) and "risk_score" in result:
                        _span.set_attribute("tool.risk_score", result["risk_score"])
                    if isinstance(result, list):
                        _span.set_attribute("tool.result_count", len(result))
                    _span.end()
                except Exception:
                    pass

            # Emit tool_completed event
            if task_id:
                try:
                    from events import emit_event, tool_summary
                    emit_event(task_id, tenant_id, trace_id, "tool_completed", {
                        "tool": tool_name, "step": i,
                        "duration_ms": int(tool_elapsed * 1000),
                        "summary": tool_summary(tool_name, result, int(tool_elapsed * 1000)),
                    })
                except Exception:
                    pass

            step_results[i + 1] = result
            tool_names_executed.append(tool_name)

            # Aggregate findings, IOCs, risk from detection/scoring tools
            if isinstance(result, dict):
                if "findings" in result:
                    all_findings.extend(result["findings"])
                if "iocs" in result:
                    all_iocs.extend(result["iocs"])
                if "risk_score" in result:
                    risk_scores.append(result["risk_score"])
            elif isinstance(result, int) and tool_entry["category"] == "scoring":
                risk_scores.append(result)
            elif isinstance(result, list) and tool_entry["category"] == "extraction":
                all_iocs.extend(result)

        except Exception as e:
            if _span:
                try:
                    _span.set_attribute("tool.success", False)
                    _span.record_exception(e)
                    _span.end()
                except Exception:
                    pass
            errors.append(f"Step {i}: {tool_name} error: {str(e)[:200]}")
            step_results[i + 1] = None
            continue

    # Aggregate risk score — use max from scoring/detection tools
    risk_score = max(risk_scores) if risk_scores else 0

    # Deduplicate IOCs by value
    seen_iocs = set()
    unique_iocs = []
    for ioc in all_iocs:
        val = ioc.get("value", "") if isinstance(ioc, dict) else str(ioc)
        if val and val not in seen_iocs:
            seen_iocs.add(val)
            unique_iocs.append(ioc)

    # Derive verdict
    verdict = _derive_verdict(risk_score, len(unique_iocs), len(all_findings))

    return {
        "findings": all_findings,
        "iocs": unique_iocs,
        "risk_score": risk_score,
        "verdict": verdict,
        "tools_executed": len(tool_names_executed),
        "tool_names": tool_names_executed,
        "tool_results": {k: _safe_serialize(v) for k, v in step_results.items()},
        "errors": errors,
    }


def _derive_verdict(risk_score: int, ioc_count: int, finding_count: int) -> str:
    """Derive verdict from risk score, IOC count, and finding count."""
    if risk_score <= 35:
        return "benign"
    if risk_score >= 80 and ioc_count >= 3:
        return "true_positive"
    if risk_score >= 70:
        return "true_positive"
    if risk_score >= 50:
        return "suspicious"
    if risk_score >= 36 and finding_count >= 1:
        return "suspicious"
    if finding_count == 0 and ioc_count == 0:
        return "benign"
    return "inconclusive"


def _safe_serialize(val):
    """Make a value JSON-serializable for storage."""
    if isinstance(val, (str, int, float, bool, type(None))):
        return val
    if isinstance(val, (list, tuple)):
        return [_safe_serialize(v) for v in val[:50]]  # cap at 50 items
    if isinstance(val, dict):
        return {str(k): _safe_serialize(v) for k, v in list(val.items())[:50]}
    return str(val)[:500]
