"""Structured JSON logging for ZOVARC worker."""

import json
import sys
import time
import os


def log(level, message, **kwargs):
    entry = {
        "ts": time.time(),
        "level": level,
        "msg": message,
        "worker": os.environ.get("WORKER_ID", "unknown"),
    }
    entry.update(kwargs)
    print(json.dumps(entry, default=str), file=sys.stderr, flush=True)


def info(msg, **kw):
    log("info", msg, **kw)


def warn(msg, **kw):
    log("warn", msg, **kw)


def error(msg, **kw):
    log("error", msg, **kw)
