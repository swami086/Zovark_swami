"""Tests for AST prefilter v2 — security boundary validation.

Covers:
  - Every forbidden module, builtin, attribute, and dunder in the prefilter sets
  - Safe code that must pass through unmodified
  - validate_code violation-list semantics (multiple violations, syntax error, empty)
"""
import sys
import os

# Insert both the project root and sandbox/ so imports resolve regardless of
# where pytest is invoked from.
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
_SANDBOX = os.path.join(_PROJECT_ROOT, "sandbox")
for _p in (_PROJECT_ROOT, _SANDBOX):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from sandbox.ast_prefilter import is_safe_python_code, validate_code
import pytest


# ---------------------------------------------------------------------------
# MUST BLOCK
# ---------------------------------------------------------------------------

BLOCKED_CODE = [
    # --- forbidden modules (import) ---
    ("import os", "forbidden module os"),
    ("import subprocess", "forbidden module subprocess"),
    ("import socket", "forbidden module socket"),
    ("import sys", "forbidden module sys"),
    ("import pickle", "forbidden module pickle"),
    ("import ctypes", "forbidden module ctypes"),
    ("import shutil", "forbidden module shutil"),
    ("import requests", "forbidden module requests"),
    ("import urllib", "forbidden module urllib"),
    ("import io", "forbidden module io"),
    ("import pathlib", "forbidden module pathlib"),
    ("import threading", "forbidden module threading"),
    ("import multiprocessing", "forbidden module multiprocessing"),
    ("import inspect", "forbidden module inspect"),
    # --- forbidden modules (from ... import) ---
    ("from os import system", "forbidden from-import os"),
    ("from subprocess import Popen", "forbidden from-import subprocess"),
    ("from importlib import import_module", "forbidden from-import importlib"),
    ("from os.path import join", "forbidden from-import os.path"),
    # --- forbidden builtins ---
    ("eval('1+1')", "forbidden builtin eval"),
    ("exec('print(1)')", "forbidden builtin exec"),
    ("compile('x=1', '', 'exec')", "forbidden builtin compile"),
    ("open('/etc/passwd')", "forbidden builtin open"),
    ("getattr(x, 'y')", "forbidden builtin getattr"),
    ("setattr(x, 'y', 1)", "forbidden builtin setattr"),
    ("delattr(x, 'y')", "forbidden builtin delattr"),
    ("globals()", "forbidden builtin globals"),
    ("locals()", "forbidden builtin locals"),
    ("vars(x)", "forbidden builtin vars"),
    ("dir(x)", "forbidden builtin dir"),
    ("breakpoint()", "forbidden builtin breakpoint"),
    # --- forbidden attributes ---
    ("x.__class__", "forbidden dunder __class__"),
    ("x.__bases__", "forbidden dunder __bases__"),
    ("x.__subclasses__()", "forbidden dunder __subclasses__"),
    ("x.__globals__", "forbidden dunder __globals__"),
    ("x.__builtins__", "forbidden dunder __builtins__"),
    ("x.__dict__", "forbidden dunder __dict__"),
    ("x.__mro__", "forbidden dunder __mro__"),
    ("x.__code__", "forbidden dunder __code__"),
    ("x.__init__()", "forbidden dunder __init__"),
    # --- forbidden string patterns ---
    ("x = '__import__'", "forbidden string pattern __import__"),
    ("x = 'eval('", "forbidden string pattern eval("),
    ("x = 'os.system'", "forbidden string pattern os.system"),
]

ALLOWED_CODE = [
    "x = 1 + 2",
    "data = [1, 2, 3]",
    "result = {'key': 'value'}",
    "for i in range(10): pass",
    "def add(a, b): return a + b",
    "class Foo: pass",
    "[x * 2 for x in range(5)]",
    "print('hello')",
    "len([1, 2, 3])",
    "sorted([3, 1, 2])",
    "sum([1, 2, 3])",
    "max(1, 2, 3)",
    "min(1, 2, 3)",
    "str(42)",
    "int('42')",
    "float('3.14')",
    "bool(1)",
    "list(range(5))",
    "dict(a=1, b=2)",
    "tuple([1, 2, 3])",
    "import json",
    "import re",
    "import math",
    "import datetime",
    "import hashlib",
    "import collections",
    "import copy",
    "import itertools",
    "import functools",
    "import typing",
]


class TestASTPrefilterBlocked:
    """Every entry in BLOCKED_CODE must be rejected by is_safe_python_code."""

    @pytest.mark.parametrize("code,reason", BLOCKED_CODE)
    def test_blocked_code(self, code, reason):
        safe, msg = is_safe_python_code(code)
        assert not safe, (
            f"Code should be BLOCKED ({reason}) but was allowed.\n"
            f"  code: {code!r}"
        )


class TestASTPrefilterAllowed:
    """Every entry in ALLOWED_CODE must pass through is_safe_python_code."""

    @pytest.mark.parametrize("code", ALLOWED_CODE)
    def test_allowed_code(self, code):
        safe, msg = is_safe_python_code(code)
        assert safe, (
            f"Code should be ALLOWED but was blocked.\n"
            f"  code: {code!r}\n"
            f"  msg:  {msg!r}"
        )


class TestIsSafePythonCodeReturnShape:
    """is_safe_python_code always returns a 2-tuple (bool, str)."""

    def test_safe_returns_true_str(self):
        safe, msg = is_safe_python_code("x = 1")
        assert safe is True
        assert isinstance(msg, str)

    def test_unsafe_returns_false_str(self):
        safe, msg = is_safe_python_code("import os")
        assert safe is False
        assert isinstance(msg, str)
        assert len(msg) > 0

    def test_empty_code_is_safe(self):
        safe, msg = is_safe_python_code("")
        assert safe is True


class TestValidateCode:
    """validate_code returns (bool, list[str]) with full violation details."""

    def test_safe_empty_violations(self):
        safe, violations = validate_code("x = 1 + 2")
        assert safe is True
        assert violations == []

    def test_multiple_violations_all_reported(self):
        code = "import os\nimport subprocess\neval('x')"
        safe, violations = validate_code(code)
        assert safe is False
        # All three violations should appear
        assert len(violations) >= 3

    def test_violation_messages_are_strings(self):
        safe, violations = validate_code("import os")
        assert safe is False
        for v in violations:
            assert isinstance(v, str)

    def test_syntax_error_reported(self):
        safe, violations = validate_code("def (:")
        assert safe is False
        assert len(violations) == 1
        lower = violations[0].lower()
        assert "syntax" in lower

    def test_empty_code_no_violations(self):
        safe, violations = validate_code("")
        assert safe is True
        assert violations == []

    def test_returns_two_tuple(self):
        result = validate_code("x = 1")
        assert len(result) == 2

    def test_forbidden_attribute_violation_message(self):
        safe, violations = validate_code("x.__dict__")
        assert safe is False
        # The message should reference the attribute name
        assert any("__dict__" in v for v in violations)

    def test_dunder_subscript_blocked(self):
        """x['__globals__'] via subscript is also blocked."""
        safe, violations = validate_code("x = obj['__globals__']")
        assert safe is False

    def test_forbidden_string_constant_blocked(self):
        """String literals containing forbidden patterns are blocked."""
        safe, violations = validate_code("x = 'os.system'")
        assert safe is False

    def test_multiline_mixed_safe_unsafe(self):
        code = "\n".join([
            "x = 1",
            "y = x + 2",
            "import pickle",
            "z = y * 3",
        ])
        safe, violations = validate_code(code)
        assert safe is False
        assert len(violations) >= 1

    def test_line_numbers_in_violations(self):
        """Violation messages should include line number information."""
        safe, violations = validate_code("x = 1\nimport os\n")
        assert safe is False
        # Line 2 import should mention line number
        assert any("line" in v.lower() or "2" in v for v in violations)
