"""
Preflight code validator — catches errors BEFORE sandbox execution.
Runs in <100ms. No Docker, no sandbox, no LLM call.

Catches:
  - SyntaxError (markdown fences, incomplete code)
  - NameError (undefined variables — static analysis)
  - Forbidden imports (os, subprocess, requests, etc.)
  - Missing JSON output (no print(json.dumps(...)))
  - Infinite loops (while True without break)
"""
import ast
import re
from typing import Tuple, List

FORBIDDEN_PATTERNS = [
    r'\bimport\s+os\b',
    r'\bimport\s+subprocess\b',
    r'\bimport\s+requests\b',
    r'\bimport\s+socket\b',
    r'\bimport\s+shutil\b',
    r'__import__\s*\(',
    r'\beval\s*\(',
    r'\bexec\s*\(',
]


def preflight_validate(code: str) -> Tuple[bool, str, List[str]]:
    """
    Validate generated code before sandbox execution.
    Returns: (is_valid, error_or_cleaned_code, warnings)
    Fast: <100ms, no external calls.
    """
    warnings = []

    # 0. Strip markdown fences (auto-fix)
    cleaned = code
    if '```python' in cleaned:
        cleaned = re.sub(r'```python\s*\n?', '', cleaned)
        cleaned = re.sub(r'```\s*$', '', cleaned, flags=re.MULTILINE)
        warnings.append("Stripped markdown fences from code")
    if '```' in cleaned:
        cleaned = cleaned.split('```')[0]
        warnings.append("Truncated at remaining markdown fence")

    # 1. Syntax check
    try:
        tree = ast.parse(cleaned)
    except SyntaxError as e:
        return False, f"SyntaxError at line {e.lineno}: {e.msg}", warnings

    # 2. Forbidden pattern check
    for pattern in FORBIDDEN_PATTERNS:
        match = re.search(pattern, cleaned)
        if match:
            return False, f"Forbidden pattern: {match.group()}", warnings

    # 3. Check for JSON output
    has_json_output = bool(
        re.search(r'print\s*\(\s*json\.dumps\s*\(', cleaned) or
        re.search(r'json\.dumps\s*\(', cleaned)
    )
    if not has_json_output:
        warnings.append("No json.dumps() found — output may not be parseable")

    # 4. Undefined variable detection for common patterns
    if re.search(r'\balert\b', cleaned):
        if not re.search(r'\balert\s*=', cleaned):
            return False, "NameError: 'alert' used but not defined", warnings
    if re.search(r'\braw_log\b', cleaned):
        if not re.search(r'\braw_log\s*=', cleaned):
            return False, "NameError: 'raw_log' used but not defined", warnings

    # 5. Infinite loop detection
    for node in ast.walk(tree):
        if isinstance(node, ast.While):
            if isinstance(node.test, ast.Constant) and node.test.value is True:
                has_break = any(isinstance(n, ast.Break) for n in ast.walk(node))
                if not has_break:
                    return False, "Potential infinite loop: while True without break", warnings

    return True, cleaned if cleaned != code else "", warnings


def auto_fix_code(code: str) -> Tuple[str, List[str]]:
    """
    Attempt to auto-fix common issues without LLM retry.
    Returns: (fixed_code, list_of_fixes_applied)
    """
    fixes = []
    fixed = code

    # Fix 1: Strip markdown fences
    if '```python' in fixed:
        fixed = re.sub(r'```python\s*\n?', '', fixed)
        fixed = re.sub(r'```\s*$', '', fixed, flags=re.MULTILINE)
        fixes.append("Stripped markdown fences")

    # Fix 2: Remove trailing ```
    if '```' in fixed:
        fixed = fixed.split('```')[0]
        fixes.append("Truncated at markdown fence")

    # Fix 3: Remove leading explanation text before first code line
    lines = fixed.split('\n')
    code_start = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(('import ', 'from ', 'def ', 'class ', '#', 'alert', 'raw_log', 'siem')):
            code_start = i
            break
    if code_start > 0:
        fixed = '\n'.join(lines[code_start:])
        fixes.append(f"Removed {code_start} lines of preamble text")

    return fixed, fixes
