"""
Investigation Code Cache — skip LLM for repeat alert patterns.
Key = hash(task_type + rule_name + sorted SIEM field names).
NOT based on field values — same code works for different IPs/users.
TTL: 24 hours. Flush after prompt updates via scripts/flush_code_cache.sh.
"""
import hashlib
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

CACHE_PREFIX = "zovark:code_cache:"
CACHE_TTL = int(os.getenv("ZOVARK_CODE_CACHE_TTL", "86400"))


def get_alert_signature(task_type: str, rule_name: str, siem_event: dict) -> str:
    field_names = sorted(k for k in (siem_event or {}).keys() if not k.startswith("_"))
    sig = f"{task_type}:{rule_name}:{','.join(field_names)}"
    return hashlib.sha256(sig.encode()).hexdigest()[:24]


def get_cached_code(redis_client, signature: str) -> Optional[str]:
    try:
        key = f"{CACHE_PREFIX}{signature}"
        cached = redis_client.get(key)
        if cached:
            logger.info(f"Code cache HIT: {signature}")
            try:
                redis_client.incr("zovark:cache_hits")
            except Exception:
                pass
            return cached.decode("utf-8") if isinstance(cached, bytes) else cached
        try:
            redis_client.incr("zovark:cache_misses")
        except Exception:
            pass
        return None
    except Exception as e:
        logger.warning(f"Code cache read error: {e}")
        return None


def set_cached_code(redis_client, signature: str, code: str) -> bool:
    try:
        if not code or len(code.strip()) < 50:
            return False
        key = f"{CACHE_PREFIX}{signature}"
        redis_client.setex(key, CACHE_TTL, code)
        logger.info(f"Code cache SET: {signature} ({len(code)} chars, TTL={CACHE_TTL}s)")
        return True
    except Exception as e:
        logger.warning(f"Code cache write error: {e}")
        return False
