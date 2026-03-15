# Malicious code samples — all must be blocked by AST prefilter
MALICIOUS_SAMPLES = [
    ("import os", "direct os import"),
    ("import subprocess", "subprocess import"),
    ("eval('1+1')", "eval call"),
    ("exec('print(1)')", "exec call"),
    ("open('/etc/passwd')", "file open"),
    ("__import__('os').system('ls')", "dunder import"),
    ("getattr(x, 'system')", "getattr bypass"),
    ("().__class__.__bases__[0].__subclasses__()", "MRO traversal"),
]
