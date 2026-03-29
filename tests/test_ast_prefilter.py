"""Tests for AST prefilter — verify 4-layer validation blocks dangerous code.

The prefilter function is _ast_check in worker/stages/execute.py.
It uses 4 layers of defense:

  Layer 1: BLOCKED_PATTERNS — fast case-insensitive string scan
           (import os, import subprocess, import requests, __import__, builtins, etc.)
  Layer 2: SyntaxError detection via ast.parse
  Layer 3: ALLOWED_IMPORTS allowlist — only 17 safe modules permitted
           (json, re, datetime, ipaddress, hashlib, base64, collections,
            urllib.parse, csv, math, statistics, string, functools,
            itertools, typing, copy)
  Layer 4: BLOCKED_BUILTINS — blocks open, eval, exec, compile, __import__, breakpoint
  Legacy:  YAML-driven FORBIDDEN_IMPORTS + FORBIDDEN_PATTERNS from sandbox_policy.yaml
"""
import sys
import os
from unittest.mock import MagicMock

# Mock temporalio before importing execute.py (not available outside Docker)
sys.modules.setdefault('temporalio', MagicMock())
sys.modules.setdefault('temporalio.activity', MagicMock())

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'worker'))

from stages.execute import _ast_check


def prefilter(code: str):
    """Wrapper that normalizes _ast_check return to (bool, str)."""
    result = _ast_check(code)
    if isinstance(result, tuple):
        return result
    return (result, "")


# ---------------------------------------------------------------------------
# Blocked imports — Layer 1 string scan + Layer 3 allowlist
# ---------------------------------------------------------------------------
class TestBlockedImports:
    """Imports on the blocklist or outside the allowlist must be rejected."""

    # Core dangerous modules (Layer 1 blocked patterns)
    def test_blocks_os(self):
        assert prefilter("import os\nos.listdir('.')")[0] is False

    def test_blocks_subprocess(self):
        assert prefilter("import subprocess")[0] is False

    def test_blocks_socket(self):
        assert prefilter("import socket")[0] is False

    def test_blocks_sys(self):
        assert prefilter("import sys")[0] is False

    def test_blocks_shutil(self):
        assert prefilter("import shutil")[0] is False

    def test_blocks_ctypes(self):
        assert prefilter("import ctypes")[0] is False

    def test_blocks_importlib(self):
        assert prefilter("import importlib")[0] is False

    def test_blocks_pickle(self):
        assert prefilter("import pickle")[0] is False

    def test_blocks_marshal(self):
        assert prefilter("import marshal")[0] is False

    def test_blocks_pty(self):
        assert prefilter("import pty")[0] is False

    def test_blocks_signal(self):
        assert prefilter("import signal")[0] is False

    # Network modules (Layer 1 blocked patterns)
    def test_blocks_requests(self):
        assert prefilter("import requests")[0] is False

    def test_blocks_http_client(self):
        assert prefilter("import http.client")[0] is False

    def test_blocks_aiohttp(self):
        assert prefilter("import aiohttp")[0] is False

    def test_blocks_ftplib(self):
        assert prefilter("import ftplib")[0] is False

    def test_blocks_urllib_request(self):
        assert prefilter("import urllib.request")[0] is False

    def test_blocks_smtplib(self):
        assert prefilter("import smtplib")[0] is False

    # From-import variants
    def test_blocks_from_os(self):
        assert prefilter("from os import path")[0] is False

    def test_blocks_from_os_path(self):
        assert prefilter("from os.path import join")[0] is False

    def test_blocks_from_subprocess(self):
        assert prefilter("from subprocess import Popen")[0] is False

    def test_blocks_from_socket(self):
        assert prefilter("from socket import create_connection")[0] is False

    # Not in allowlist (Layer 3 blocks these even though Layer 1 doesn't)
    def test_blocks_textwrap(self):
        assert prefilter("import textwrap")[0] is False

    def test_blocks_uuid(self):
        assert prefilter("import uuid")[0] is False

    def test_blocks_pathlib(self):
        assert prefilter("import pathlib")[0] is False

    def test_blocks_tempfile(self):
        assert prefilter("import tempfile")[0] is False

    def test_blocks_glob(self):
        assert prefilter("import glob")[0] is False


# ---------------------------------------------------------------------------
# Blocked patterns and builtin calls — Layer 1 + Layer 4
# ---------------------------------------------------------------------------
class TestBlockedPatterns:
    """String patterns and dangerous builtin calls must be rejected."""

    # Layer 1: string pattern scan
    def test_blocks_dunder_import_string(self):
        assert prefilter("m = __import__('os')")[0] is False

    def test_blocks_os_environ(self):
        assert prefilter("x = os.environ['SECRET']")[0] is False

    def test_blocks_dunder_builtins_string(self):
        assert prefilter("x = __builtins__['eval']")[0] is False

    def test_blocks_dunder_subclasses(self):
        assert prefilter("x = ''.__class__.__subclasses__()")[0] is False

    def test_blocks_getattr_pattern(self):
        assert prefilter("getattr(obj, 'dangerous')")[0] is False

    # Layer 4: blocked builtin calls (AST-based)
    def test_blocks_eval_call(self):
        assert prefilter("eval('1+1')")[0] is False

    def test_blocks_exec_call(self):
        assert prefilter("exec('x=1')")[0] is False

    def test_blocks_open_call(self):
        assert prefilter("f = open('/etc/passwd', 'r')")[0] is False

    def test_blocks_compile_call(self):
        assert prefilter("compile('import os', '<s>', 'exec')")[0] is False

    def test_blocks_breakpoint_call(self):
        assert prefilter("breakpoint()")[0] is False

    # Variation: eval/exec with spaces (Layer 1 substring match)
    def test_blocks_eval_with_spaces(self):
        assert prefilter("eval  ('code')")[0] is False

    def test_blocks_exec_with_spaces(self):
        assert prefilter("exec  ('code')")[0] is False


# ---------------------------------------------------------------------------
# Allowed imports — the 17 safe modules in ALLOWED_IMPORTS
# ---------------------------------------------------------------------------
class TestAllowedImports:
    """Only imports in the explicit allowlist must pass all 4 layers."""

    def test_allows_json(self):
        assert prefilter("import json\njson.loads('{}')")[0] is True

    def test_allows_re(self):
        assert prefilter("import re\nre.match('a','a')")[0] is True

    def test_allows_datetime(self):
        assert prefilter("from datetime import datetime")[0] is True

    def test_allows_ipaddress(self):
        assert prefilter("import ipaddress")[0] is True

    def test_allows_hashlib(self):
        assert prefilter("import hashlib")[0] is True

    def test_allows_base64(self):
        assert prefilter("import base64")[0] is True

    def test_allows_collections(self):
        assert prefilter("from collections import Counter")[0] is True

    def test_allows_urllib_parse(self):
        assert prefilter("from urllib.parse import urlparse")[0] is True

    def test_allows_csv(self):
        assert prefilter("import csv")[0] is True

    def test_allows_math(self):
        assert prefilter("import math")[0] is True

    def test_allows_statistics(self):
        assert prefilter("import statistics")[0] is True

    def test_allows_string(self):
        assert prefilter("import string")[0] is True

    def test_allows_functools(self):
        assert prefilter("import functools")[0] is True

    def test_allows_itertools(self):
        assert prefilter("import itertools")[0] is True

    def test_allows_copy(self):
        assert prefilter("import copy")[0] is True

    def test_allows_typing(self):
        assert prefilter("import typing")[0] is True


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------
class TestEdgeCases:
    """Boundary conditions, mixed code, syntax errors."""

    def test_blocks_mixed_allowed_blocked(self):
        assert prefilter("import json\nimport os")[0] is False

    def test_rejects_syntax_error(self):
        assert prefilter("def broken(:\n  pass")[0] is False

    def test_allows_empty_code(self):
        # Empty string parses as valid empty module — no dangerous code
        assert prefilter("")[0] is True

    def test_allows_pure_computation(self):
        assert prefilter("x = 1 + 2\ny = x * 3\nresult = {'value': y}")[0] is True

    def test_allows_investigation_pattern(self):
        code = (
            "import json\n"
            "import re\n"
            "import ipaddress\n"
            "from collections import Counter\n"
            "data = json.loads('{}')\n"
            "result = {'findings': [], 'risk_score': 85}"
        )
        assert prefilter(code)[0] is True

    def test_allows_multiline_analysis(self):
        code = (
            "import json\n"
            "import re\n"
            "from datetime import datetime\n"
            "siem = json.loads('{}')\n"
            "ips = re.findall(r'\\d+\\.\\d+\\.\\d+\\.\\d+', str(siem))\n"
            "findings = [{'title': 'Found IPs', 'details': str(ips)}]\n"
            "print(json.dumps({'findings': findings, 'risk_score': 75, 'iocs': []}))"
        )
        assert prefilter(code)[0] is True

    def test_blocked_import_in_function(self):
        code = "def malicious():\n    import os\n    os.system('pwd')"
        assert prefilter(code)[0] is False

    def test_blocks_os_in_try_block(self):
        code = "try:\n    import os\n    os.remove('/etc/hosts')\nexcept:\n    pass"
        assert prefilter(code)[0] is False

    def test_allows_variable_named_os(self):
        # Variable named 'os_type' should not trigger import block
        code = "os_type = 'linux'\nresult = {'os': os_type}"
        assert prefilter(code)[0] is True

    def test_allows_open_in_variable_name(self):
        # 'open_files' as a variable should not trigger builtin call block
        assert prefilter("open_files = 5\nresult = open_files + 1")[0] is True

    def test_allows_open_in_string(self):
        # 'open' in a string literal should not trigger block
        assert prefilter("msg = 'please open the file'\nprint(msg)")[0] is True

    def test_blocks_multiple_forbidden_imports(self):
        code = "import subprocess\nimport socket\nimport ctypes"
        assert prefilter(code)[0] is False

    def test_reason_message_on_forbidden_import(self):
        ok, reason = prefilter("import os")
        assert ok is False
        assert "os" in reason.lower()

    def test_reason_message_on_blocked_builtin(self):
        ok, reason = prefilter("eval('1+1')")
        assert ok is False
        assert "eval" in reason.lower()

    def test_reason_message_on_syntax_error(self):
        ok, reason = prefilter("def f(:\n  pass")
        assert ok is False
        assert "syntax" in reason.lower()


# ---------------------------------------------------------------------------
# Evasion attempts — verify the prefilter catches common tricks
# ---------------------------------------------------------------------------
class TestEvasionAttempts:
    """Attempts to bypass the prefilter via obfuscation or indirection."""

    def test_blocks_dunder_import_with_concat(self):
        # __import__ as a pattern match even with string concat
        code = "__import__('o' + 's')"
        assert prefilter(code)[0] is False

    def test_blocks_builtins_access(self):
        code = "x = __builtins__"
        assert prefilter(code)[0] is False

    def test_blocks_subclass_chain(self):
        code = "x = ().__class__.__bases__[0].__subclasses__()"
        assert prefilter(code)[0] is False

    def test_blocks_getattr_on_module(self):
        code = "import json\ngetattr(json, 'loads')('1')"
        assert prefilter(code)[0] is False

    def test_blocks_nested_eval(self):
        code = "x = eval(eval('\"1+1\"'))"
        assert prefilter(code)[0] is False

    def test_blocks_os_environ_access(self):
        code = "secret = os.environ['API_KEY']"
        assert prefilter(code)[0] is False

    def test_blocks_getpass(self):
        code = "import getpass\np = getpass.getpass()"
        assert prefilter(code)[0] is False

    def test_blocks_cffi(self):
        code = "import cffi"
        assert prefilter(code)[0] is False

    def test_blocks_shelve(self):
        code = "import shelve"
        assert prefilter(code)[0] is False
