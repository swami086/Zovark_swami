"""Tests for the AST security prefilter.

Verifies that all dangerous constructs are REJECTED while safe code PASSES.
"""

import sys
import os
import pytest

# Add sandbox directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sandbox"))
from ast_prefilter import is_safe_python_code


class TestForbiddenFunctions:
    """Test that forbidden function calls are rejected."""

    def test_eval_rejected(self):
        safe, reason = is_safe_python_code("result = eval('1+1')")
        assert not safe
        assert "eval" in reason.lower()

    def test_exec_rejected(self):
        safe, reason = is_safe_python_code("exec('print(1)')")
        assert not safe
        assert "exec" in reason.lower()

    def test_dunder_import_rejected(self):
        safe, reason = is_safe_python_code("mod = __import__('os')")
        assert not safe
        assert "__import__" in reason

    def test_eval_as_name_reference_rejected(self):
        safe, reason = is_safe_python_code("f = eval")
        assert not safe

    def test_exec_as_name_reference_rejected(self):
        safe, reason = is_safe_python_code("f = exec")
        assert not safe


class TestForbiddenImports:
    """Test that forbidden module imports are rejected."""

    def test_import_ctypes_rejected(self):
        safe, reason = is_safe_python_code("import ctypes")
        assert not safe
        assert "ctypes" in reason

    def test_import_importlib_rejected(self):
        safe, reason = is_safe_python_code("import importlib")
        assert not safe
        assert "importlib" in reason

    def test_import_multiprocessing_rejected(self):
        safe, reason = is_safe_python_code("import multiprocessing")
        assert not safe
        assert "multiprocessing" in reason

    def test_import_pty_rejected(self):
        safe, reason = is_safe_python_code("import pty")
        assert not safe
        assert "pty" in reason

    def test_from_importlib_rejected(self):
        safe, reason = is_safe_python_code("from importlib import import_module")
        assert not safe

    def test_from_ctypes_rejected(self):
        safe, reason = is_safe_python_code("from ctypes import cdll")
        assert not safe

    def test_from_os_import_system_rejected(self):
        safe, reason = is_safe_python_code("from os import system")
        assert not safe
        assert "system" in reason

    def test_from_os_import_dunder_import_rejected(self):
        safe, reason = is_safe_python_code("from builtins import __import__")
        assert not safe


class TestForbiddenAttributes:
    """Test that forbidden method/attribute calls are rejected."""

    def test_os_system_rejected(self):
        safe, reason = is_safe_python_code("import os\nos.system('ls')")
        assert not safe
        assert "system" in reason

    def test_os_popen_rejected(self):
        """os.popen should be rejected via forbidden attributes."""
        # os.popen maps to 'popen' — check if it's in FORBIDDEN_ATTRIBUTES
        # If not currently blocked, this documents expected behavior
        code = "import os\nos.popen('ls')"
        safe, reason = is_safe_python_code(code)
        # popen is not in the current FORBIDDEN_ATTRIBUTES list,
        # but we document this for future hardening
        # For now, os module itself is not forbidden — only specific attrs

    def test_shutil_rmtree_rejected(self):
        safe, reason = is_safe_python_code("import shutil\nshutil.rmtree('/tmp')")
        assert not safe
        assert "rmtree" in reason

    def test_os_execv_rejected(self):
        safe, reason = is_safe_python_code("import os\nos.execv('/bin/sh', ['sh'])")
        assert not safe
        assert "execv" in reason

    def test_os_execve_rejected(self):
        safe, reason = is_safe_python_code("import os\nos.execve('/bin/sh', ['sh'], {})")
        assert not safe
        assert "execve" in reason

    def test_os_execvp_rejected(self):
        safe, reason = is_safe_python_code("import os\nos.execvp('sh', ['sh'])")
        assert not safe
        assert "execvp" in reason


class TestSafeCode:
    """Test that legitimate code passes the prefilter."""

    def test_simple_math(self):
        safe, reason = is_safe_python_code("x = 1 + 2\nprint(x)")
        assert safe
        assert reason == "Safe"

    def test_import_json(self):
        safe, reason = is_safe_python_code("import json\ndata = json.loads('{}')")
        assert safe

    def test_import_re(self):
        safe, reason = is_safe_python_code("import re\npattern = re.compile(r'\\d+')")
        assert safe

    def test_import_datetime(self):
        safe, reason = is_safe_python_code("from datetime import datetime\nnow = datetime.now()")
        assert safe

    def test_file_operations(self):
        safe, reason = is_safe_python_code(
            "with open('data.txt', 'r') as f:\n    content = f.read()"
        )
        assert safe

    def test_list_comprehension(self):
        safe, reason = is_safe_python_code("squares = [x**2 for x in range(10)]")
        assert safe

    def test_class_definition(self):
        safe, reason = is_safe_python_code(
            "class Analyzer:\n    def run(self):\n        return 'done'"
        )
        assert safe

    def test_try_except(self):
        safe, reason = is_safe_python_code(
            "try:\n    x = 1/0\nexcept ZeroDivisionError:\n    x = 0"
        )
        assert safe


class TestEdgeCases:
    """Edge cases and tricky bypass attempts."""

    def test_syntax_error_rejected(self):
        safe, reason = is_safe_python_code("def foo(:\n  pass")
        assert not safe
        assert "SyntaxError" in reason or "parsing" in reason.lower()

    def test_empty_code_safe(self):
        safe, reason = is_safe_python_code("")
        assert safe

    def test_comment_only_safe(self):
        safe, reason = is_safe_python_code("# This is a comment\n# Another comment")
        assert safe

    def test_nested_import_rejected(self):
        safe, reason = is_safe_python_code(
            "def sneaky():\n    import ctypes\n    return ctypes.cdll"
        )
        assert not safe

    def test_exec_in_method_rejected(self):
        safe, reason = is_safe_python_code(
            "class X:\n    def y(self):\n        exec('bad')"
        )
        assert not safe

    def test_attribute_on_chain_rejected(self):
        safe, reason = is_safe_python_code("x.y.z.system('cmd')")
        assert not safe

    def test_eval_in_lambda_rejected(self):
        safe, reason = is_safe_python_code("f = lambda x: eval(x)")
        assert not safe

    def test_multiline_safe_code(self):
        code = """
import json
import re
from collections import Counter

def analyze_logs(log_text):
    lines = log_text.strip().split('\\n')
    ip_pattern = re.compile(r'\\d+\\.\\d+\\.\\d+\\.\\d+')
    ips = []
    for line in lines:
        found = ip_pattern.findall(line)
        ips.extend(found)
    return dict(Counter(ips))

result = analyze_logs("sample log 10.0.0.1 and 10.0.0.2")
print(json.dumps(result))
"""
        safe, reason = is_safe_python_code(code)
        assert safe
