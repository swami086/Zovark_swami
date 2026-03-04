import ast
from typing import Tuple

FORBIDDEN_MODULES = {
    'ctypes', 'multiprocessing',
    'importlib', 'pty', 'fcntl', 'resource'
}

FORBIDDEN_ATTRIBUTES = {
    'system', 'execl', 'execle', 'execlp', 'execlpe', 'execv',
    'execve', 'execvp', 'execvpe', 'rmtree'
}

FORBIDDEN_FUNCTIONS = {
    'eval', 'exec', '__import__'
}

class SecurityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.safe = True
        self.reason = ""

    def fail(self, reason: str):
        self.safe = False
        self.reason = reason

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            base_module = alias.name.split('.')[0]
            if base_module in FORBIDDEN_MODULES or alias.name in FORBIDDEN_MODULES:
                self.fail(f"Forbidden import: {alias.name}")
                return
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            base_module = node.module.split('.')[0]
            if base_module in FORBIDDEN_MODULES or node.module in FORBIDDEN_MODULES:
                self.fail(f"Forbidden import module: {node.module}")
                return
        
        # Check if importing forbidden attributes mapped from allowed modules (e.g. from os import system)
        for alias in node.names:
            if alias.name in FORBIDDEN_ATTRIBUTES or alias.name in FORBIDDEN_FUNCTIONS or alias.name == '__import__':
                self.fail(f"Forbidden import alias: {alias.name}")
                return
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Direct function calls (e.g., eval(), exec(), __import__())
        if isinstance(node.func, ast.Name):
            if node.func.id in FORBIDDEN_FUNCTIONS:
                self.fail(f"Forbidden function call: {node.func.id}")
                return
        # Method calls (e.g., os.system(), shutil.rmtree())
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in FORBIDDEN_ATTRIBUTES or node.func.attr in FORBIDDEN_FUNCTIONS or node.func.attr == '__import__':
                self.fail(f"Forbidden attribute/method call: {node.func.attr}")
                return
        self.generic_visit(node)
        
    def visit_Name(self, node: ast.Name):
        if node.id in FORBIDDEN_FUNCTIONS or node.id == '__import__':
            self.fail(f"Forbidden name reference: {node.id}")
            return
        self.generic_visit(node)
        
    def visit_Attribute(self, node: ast.Attribute):
        if node.attr in FORBIDDEN_ATTRIBUTES or node.attr in FORBIDDEN_FUNCTIONS or node.attr == '__import__':
            self.fail(f"Forbidden attribute reference: {node.attr}")
            return
        self.generic_visit(node)

def is_safe_python_code(code_string: str) -> Tuple[bool, str]:
    """
    Parses the AST of the provided Python code string and rejects it if it
    contains forbidden imports, function calls, or attribute accesses.
    """
    try:
        tree = ast.parse(code_string)
    except Exception as e:
        return False, f"Code parsing failed (SyntaxError): {e}"
        
    visitor = SecurityVisitor()
    visitor.visit(tree)
    
    if not visitor.safe:
        return False, visitor.reason
        
    return True, "Safe"
