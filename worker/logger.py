"""Structured JSON logging for ZOVARK worker."""

import json
import logging
import sys
import time
import os

# Stdlib logger — propagates to root; root gets OpenTelemetry LoggingHandler (SigNoz) after init_tracing()
_pylog = logging.getLogger("zovark_worker")
_pylog.propagate = True
_pylog.setLevel(logging.DEBUG)


def log(level, message, **kwargs):
    entry = {
        "ts": time.time(),
        "level": level,
        "msg": message,
        "worker": os.environ.get("WORKER_ID", "unknown"),
    }
    entry.update(kwargs)
    print(json.dumps(entry, default=str), file=sys.stderr, flush=True)
    # Always emit to stdlib logger so OpenTelemetry root LoggingHandler (SigNoz) receives it.
    mapping = {"info": logging.INFO, "warn": logging.WARNING, "error": logging.ERROR}
    py_level = mapping.get(level.lower(), logging.INFO)
    extra = {f"zovark.{k}": str(v) for k, v in kwargs.items()}
    try:
        _pylog.log(py_level, message, extra=extra)
    except Exception:
        pass


def info(msg, **kw):
    log("info", msg, **kw)


def warn(msg, **kw):
    log("warn", msg, **kw)


def error(msg, **kw):
    log("error", msg, **kw)
