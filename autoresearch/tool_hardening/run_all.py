#!/usr/bin/env python3
"""Run tool hardening for all 34 tools."""
import os
import sys
import json

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
WORKER_ROOT = os.path.join(PROJECT_ROOT, "worker")
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, WORKER_ROOT)

from worker.tools.catalog import TOOL_CATALOG

prog_dir = os.path.dirname(os.path.abspath(__file__))
venv_python = os.path.join(prog_dir, "..", ".venv", "Scripts", "python.exe")

improved_count = 0
total_tools = len(TOOL_CATALOG)
results = []

for tool_name in sorted(TOOL_CATALOG.keys()):
    tool_info = TOOL_CATALOG[tool_name]
    func = tool_info["function"]
    module = func.__module__
    func_name = func.__name__
    
    tool_code = f'''"""MUTABLE FILE — Agent tests and improves one tool at a time."""
import sys
sys.path.insert(0, r"{PROJECT_ROOT}")

from {module} import {func_name} as tool_function

TOOL_NAME = "{tool_name}"
'''
    with open(os.path.join(prog_dir, "current_tool.py"), "w", encoding="utf-8") as f:
        f.write(tool_code)
    
    import subprocess
    result = subprocess.run(
        [venv_python, "evaluate.py"],
        cwd=prog_dir,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    
    # Parse result from results.jsonl
    results_file = os.path.join(prog_dir, "results.jsonl")
    res = {"tool": tool_name, "fitness": 0.0, "passed": 0, "failed": 0, "total": 0}
    if os.path.exists(results_file):
        with open(results_file, encoding="utf-8") as f:
            lines = f.readlines()
            for line in reversed(lines):
                try:
                    d = json.loads(line)
                    if d.get("tool") == tool_name:
                        res = d
                        break
                except:
                    pass
    
    results.append(res)
    fitness = res.get("fitness", 0.0)
    failed = res.get("failed", 1)
    if fitness >= 0.95 and failed == 0:
        improved_count += 1
        print(f"OK {tool_name}: {res.get('passed',0)}/{res.get('total',0)} passed")
    else:
        print(f"FAIL {tool_name}: {res.get('passed',0)}/{res.get('total',0)} passed, fitness={fitness:.2f}")

print(f"\n{'='*50}")
print(f"Tools hardened: {improved_count}/{total_tools}")
print(f"{'='*50}")

# Save summary
with open(os.path.join(prog_dir, "summary.json"), "w", encoding="utf-8") as f:
    json.dump({"improved": improved_count, "total": total_tools, "results": results}, f, indent=2)
