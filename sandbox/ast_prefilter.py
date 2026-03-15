"""AST prefilter v2 — blocks dangerous imports, builtins, attributes, dunder traversal."""
import ast
from typing import Set, Tuple, List

FORBIDDEN_MODULES: Set[str] = {
    "eval", "exec", "subprocess", "socket", "ctypes", "importlib",
    "os", "sys", "shutil", "signal", "requests", "urllib", "http",
    "http.client", "http.server", "xmlrpc", "ftplib", "smtplib",
    "imaplib", "poplib", "telnetlib", "socketserver",
    "multiprocessing", "threading", "concurrent",
    "pickle", "shelve", "marshal", "code", "codeop",
    "compileall", "py_compile", "pty", "pipes", "resource",
    "gc", "inspect", "dis", "traceback", "linecache",
    "tokenize", "ast", "builtins", "io", "pathlib",
    "glob", "fnmatch", "tempfile", "zipfile", "tarfile",
    "gzip", "bz2", "lzma", "webbrowser", "antigravity",
    "tkinter", "cffi", "pdb", "runpy",
}

FORBIDDEN_BUILTINS: Set[str] = {
    "eval", "exec", "__import__", "compile", "open",
    "getattr", "setattr", "delattr", "globals", "locals",
    "vars", "dir", "type", "super", "memoryview",
    "breakpoint", "exit", "quit", "input",
}

FORBIDDEN_ATTRIBUTES: Set[str] = {
    "__class__", "__bases__", "__subclasses__", "__globals__",
    "__dict__", "__builtins__", "__init__", "__new__", "__del__",
    "__getattr__", "__setattr__", "__delattr__", "__getattribute__",
    "__mro__", "__code__", "__func__", "__self__",
    "__wrapped__", "__closure__", "__annotations__",
    "system", "popen", "exec_command", "spawn",
    "fork", "kill", "environ",
}

FORBIDDEN_STRING_PATTERNS = [
    "__import__", "__builtins__", "__subclasses__", "__globals__",
    "os.system", "os.popen", "subprocess", "eval(", "exec(", "compile(",
]


class SecurityASTVisitor(ast.NodeVisitor):
    def __init__(self):
        self.violations: List[str] = []

    def visit_Import(self, node):
        for alias in node.names:
            for f in FORBIDDEN_MODULES:
                if alias.name == f or alias.name.startswith(f + "."):
                    self.violations.append(f"Forbidden import: '{alias.name}' (line {node.lineno})")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            for f in FORBIDDEN_MODULES:
                if node.module == f or node.module.startswith(f + "."):
                    self.violations.append(f"Forbidden import from: '{node.module}' (line {node.lineno})")
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_BUILTINS:
            self.violations.append(f"Forbidden call: '{node.func.id}()' (line {node.lineno})")
        if isinstance(node.func, ast.Attribute) and node.func.attr in FORBIDDEN_ATTRIBUTES:
            self.violations.append(f"Forbidden method: '.{node.func.attr}()' (line {node.lineno})")
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if node.attr in FORBIDDEN_ATTRIBUTES:
            self.violations.append(f"Forbidden attribute: '.{node.attr}' (line {node.lineno})")
        self.generic_visit(node)

    def visit_Subscript(self, node):
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            if node.slice.value in FORBIDDEN_ATTRIBUTES:
                self.violations.append(f"Forbidden subscript: ['{node.slice.value}'] (line {node.lineno})")
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            for p in FORBIDDEN_STRING_PATTERNS:
                if p in node.value:
                    self.violations.append(f"Forbidden string: '{p}' (line {node.lineno})")
        self.generic_visit(node)


def validate_code(code: str) -> Tuple[bool, List[str]]:
    """Validate Python code against security rules.

    Returns (is_safe, list_of_violations).
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return False, [f"Syntax error: {e}"]
    visitor = SecurityASTVisitor()
    visitor.visit(tree)
    return (len(visitor.violations) == 0), visitor.violations


# Backwards-compatible wrapper for existing callers
def is_safe_python_code(code_string: str) -> Tuple[bool, str]:
    """Legacy API — returns (is_safe, reason_string)."""
    safe, violations = validate_code(code_string)
    if safe:
        return True, "Safe"
    return False, violations[0]
