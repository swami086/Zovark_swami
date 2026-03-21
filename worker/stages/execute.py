"""
Stage 3: EXECUTE — Run investigation code in sandbox.
NO LLM calls. Security via AST prefilter + Docker isolation.

The adversarial LLM review is NOT in this stage.
Security comes from: AST analysis → Docker sandbox (read-only, no-network, seccomp).

Self-contained: uses subprocess, ast directly.
Does NOT import from _legacy_activities.py.
"""
import os
import re
import ast
import json
import time
import subprocess
from typing import List, Dict, Tuple
from dataclasses import asdict

from temporalio import activity
from stages import ExecuteOutput

import yaml
from pathlib import Path

# Load sandbox policy (YAML-driven, customer-auditable)
_POLICY_PATH = Path(__file__).parent / "sandbox_policy.yaml"
try:
    with open(_POLICY_PATH) as f:
        SANDBOX_POLICY = yaml.safe_load(f)
    _POLICY_VERSION = SANDBOX_POLICY.get("version", "unknown")
except Exception:
    SANDBOX_POLICY = None
    _POLICY_VERSION = "hardcoded-fallback"

FAST_FILL = os.environ.get("HYDRA_FAST_FILL", "false").lower() == "true"

# --- AST Prefilter (inlined from sandbox/ast_prefilter.py concepts) ---
if SANDBOX_POLICY:
    FORBIDDEN_IMPORTS = frozenset(SANDBOX_POLICY["ast_prefilter"]["blocked_imports"])
else:
    FORBIDDEN_IMPORTS = frozenset({
        'os', 'sys', 'subprocess', 'socket', 'shutil', 'importlib',
        'pickle', 'marshal', 'ctypes', 'pty', 'signal',
    })

if SANDBOX_POLICY:
    _raw_patterns = SANDBOX_POLICY["ast_prefilter"]["blocked_patterns"]
    FORBIDDEN_PATTERNS = [rf'\b{re.escape(p.rstrip("("))}\s*\(' if p.endswith("(") else rf'\b{re.escape(p)}\b'
                          for p in _raw_patterns]
else:
    FORBIDDEN_PATTERNS = [
        r'\b__import__\s*\(',
        r'\beval\s*\(',
        r'\bexec\s*\(',
    ]


def _ast_check(code: str) -> Tuple[bool, str]:
    """Static AST analysis. Returns (is_safe, reason)."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return False, f"SyntaxError at line {e.lineno}: {e.msg}"

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name.split('.')[0]
                if mod in FORBIDDEN_IMPORTS:
                    return False, f"Forbidden import: {mod}"
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                mod = node.module.split('.')[0]
                if mod in FORBIDDEN_IMPORTS:
                    return False, f"Forbidden import: {node.module}"

    for pattern in FORBIDDEN_PATTERNS:
        m = re.search(pattern, code)
        if m:
            return False, f"Forbidden pattern: {m.group()}"

    return True, ""


# --- Stdout parser ---
def _parse_stdout(stdout: str) -> Dict:
    """Parse investigation JSON from stdout."""
    if not stdout or not stdout.strip():
        return {}
    try:
        return json.loads(stdout.strip())
    except json.JSONDecodeError:
        # Try to find JSON object in output
        match = re.search(r'\{.*\}', stdout, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
    return {}


# --- Docker sandbox execution ---
def _run_in_sandbox(code: str, timeout: int = None) -> Dict:
    """Execute code in Docker sandbox. No LLM calls. Policy: v{_POLICY_VERSION}."""
    if timeout is None:
        timeout = SANDBOX_POLICY["process"]["max_execution_seconds"] if SANDBOX_POLICY else 120
    memory_mb = SANDBOX_POLICY["process"]["max_memory_mb"] if SANDBOX_POLICY else 512
    seccomp_path = "/app/sandbox/seccomp_profile.json"

    cmd = [
        "docker", "run", "--rm", "-i", "--network=none", "--read-only",
        "--tmpfs", "/tmp:size=64m,noexec,nosuid", "--workdir", "/tmp",
        "--cpus=0.5", f"--memory={memory_mb}m", f"--memory-swap={memory_mb}m",
        "--pids-limit=64", "--cap-drop=ALL",
        "--user", "65534:65534",
        "--security-opt=no-new-privileges",
        "--security-opt", f"seccomp={seccomp_path}",
        "python:3.11-slim", "python",
    ]

    start_time = time.time()
    try:
        result = subprocess.run(
            cmd, input=code, capture_output=True, text=True, timeout=timeout
        )
        execution_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "completed" if result.returncode == 0 else "failed",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode,
            "execution_ms": execution_ms,
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "stdout": "",
            "stderr": f"Execution timed out after {timeout}s",
            "exit_code": -1,
            "execution_ms": int((time.time() - start_time) * 1000),
        }


def _run_fast_fill(code: str) -> Dict:
    """Execute code directly via subprocess (no Docker). For stress tests only."""
    start_time = time.time()
    try:
        result = subprocess.run(
            ["python", "-c", code],
            capture_output=True, text=True, timeout=30,
        )
        return {
            "status": "completed" if result.returncode == 0 else "failed",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode,
            "execution_ms": int((time.time() - start_time) * 1000),
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "stdout": "",
            "stderr": "Fast-fill execution timed out",
            "exit_code": -1,
            "execution_ms": int((time.time() - start_time) * 1000),
        }


# --- Main entry point ---
@activity.defn
async def execute_investigation(data: dict) -> dict:
    """
    Stage 3: Execute investigation code in sandbox.
    NO LLM calls. Security: AST prefilter + Docker sandbox.

    Input: {"code": str, "task_type": str}
    Returns: dict (serializable ExecuteOutput fields)
    """
    code = data.get("code", "")
    task_type = data.get("task_type", "")

    if not code:
        return asdict(ExecuteOutput(
            stderr="No code provided", exit_code=1, status="failed"
        ))

    # Step 1: AST prefilter (no LLM, <1ms)
    is_safe, reason = _ast_check(code)
    if not is_safe:
        return asdict(ExecuteOutput(
            stderr=f"AST prefilter blocked: {reason}", exit_code=1, status="failed"
        ))

    activity.logger.info(f"Sandbox policy: {_POLICY_VERSION}")

    # Step 2: Execute
    if FAST_FILL:
        raw = _run_fast_fill(code)
    else:
        raw = _run_in_sandbox(code)

    # Step 3: Parse results
    parsed = _parse_stdout(raw.get("stdout", ""))

    result = ExecuteOutput(
        stdout=raw.get("stdout", ""),
        stderr=raw.get("stderr", ""),
        exit_code=raw.get("exit_code", -1),
        status=raw.get("status", "failed"),
        iocs=parsed.get("iocs", []),
        findings=parsed.get("findings", []),
        risk_score=parsed.get("risk_score", 0),
        recommendations=parsed.get("recommendations", []),
        execution_ms=raw.get("execution_ms", 0),
    )

    return asdict(result)
