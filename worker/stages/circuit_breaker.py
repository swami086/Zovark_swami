"""
Circuit Breaker — Auto-degrades investigation paths during alert storms.

3 levels:
  GREEN:  Normal operation. All paths available.
  YELLOW: Queue > 50. Low/info/medium severity → template-only (skip Path B/C).
  RED:    Queue > 100. Only critical severity gets Path B/C.

Recovers when queue drops below 25 (hysteresis prevents flapping).
"""
import os
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

YELLOW_THRESHOLD = int(os.getenv("ZOVARK_CB_YELLOW", "50"))
RED_THRESHOLD = int(os.getenv("ZOVARK_CB_RED", "100"))
RECOVERY_THRESHOLD = int(os.getenv("ZOVARK_CB_RECOVERY", "25"))

_current_state = "GREEN"
_state_changed_at = time.time()


def get_state() -> str:
    return _current_state


def update_state(pending_count: int) -> str:
    global _current_state, _state_changed_at
    old_state = _current_state

    if pending_count >= RED_THRESHOLD:
        _current_state = "RED"
    elif pending_count >= YELLOW_THRESHOLD:
        _current_state = "YELLOW"
    elif pending_count <= RECOVERY_THRESHOLD:
        _current_state = "GREEN"

    if _current_state != old_state:
        _state_changed_at = time.time()
        logger.warning(f"Circuit breaker: {old_state} → {_current_state} (pending={pending_count})")

    return _current_state


def should_force_template_only(severity: str, state: Optional[str] = None) -> bool:
    s = state or _current_state
    if s == "GREEN":
        return False
    elif s == "YELLOW":
        return severity.lower() in ("low", "info", "medium")
    elif s == "RED":
        return severity.lower() != "critical"
    return False


def get_status_dict() -> dict:
    return {
        "state": _current_state,
        "state_since": _state_changed_at,
        "thresholds": {
            "yellow": YELLOW_THRESHOLD,
            "red": RED_THRESHOLD,
            "recovery": RECOVERY_THRESHOLD,
        },
    }
