#!/usr/bin/env python3
"""
Zovark SIEM Lab -- Elastic Detection Poller
=============================================
Polls Elasticsearch every 15 seconds for new security-relevant events,
evaluates 4 built-in detection rules, and submits matching alerts to the
Zovark API as investigation tasks.

Detection rules:
  1. Brute Force  -- 5+ auth failures from same IP in 5 min window
  2. SQL Injection -- SQL keywords in request URIs/bodies
  3. XSS           -- Script tags / event handlers in request data
  4. Path Traversal -- ../ sequences in request URIs

Usage:
    python elastic_poller.py

Environment variables:
    ELASTICSEARCH_URL   -- ES base URL            (default: http://localhost:9200)
    ES_INDEX_PATTERN    -- Index pattern to query  (default: nginx-access-*)
    POLL_INTERVAL       -- Seconds between polls   (default: 15)
    ZOVARK_API_URL      -- Zovark API base URL     (default: http://localhost:8090)
    ZOVARK_EMAIL        -- Login email             (default: admin@test.local)
    ZOVARK_PASSWORD     -- Login password          (default: TestPass2026)
    DRY_RUN             -- Log detections only     (default: false)
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import sys
import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")
ES_INDEX_PATTERN = os.environ.get("ES_INDEX_PATTERN", "nginx-access-*")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "15"))
ZOVARK_API_URL = os.environ.get("ZOVARK_API_URL", "http://localhost:8090")
ZOVARK_EMAIL = os.environ.get("ZOVARK_EMAIL", "admin@test.local")
ZOVARK_PASSWORD = os.environ.get("ZOVARK_PASSWORD", "TestPass2026")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() in ("1", "true", "yes")

# Brute force threshold
BF_THRESHOLD = int(os.environ.get("BF_THRESHOLD", "5"))
BF_WINDOW_SECONDS = int(os.environ.get("BF_WINDOW_SECONDS", "300"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("elastic_poller")

# Graceful shutdown
_running = True


def _sigterm_handler(signum, frame):
    global _running
    log.info("Received signal %d, shutting down...", signum)
    _running = False


signal.signal(signal.SIGINT, _sigterm_handler)
signal.signal(signal.SIGTERM, _sigterm_handler)


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only -- no requests/httpx dependency)
# ---------------------------------------------------------------------------
def http_get(url: str, timeout: int = 10) -> Dict[str, Any]:
    req = Request(url, method="GET", headers={"Content-Type": "application/json"})
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def http_post(url: str, body: Dict[str, Any], headers: Optional[Dict[str, str]] = None,
              timeout: int = 15) -> Dict[str, Any]:
    data = json.dumps(body).encode()
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = Request(url, data=data, headers=hdrs, method="POST")
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def es_search(index: str, query: Dict[str, Any], size: int = 500) -> List[Dict[str, Any]]:
    """Execute an Elasticsearch search and return the hits."""
    url = f"{ELASTICSEARCH_URL}/{index}/_search"
    body = {"query": query, "size": size, "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]}
    try:
        result = http_post(url, body)
        return result.get("hits", {}).get("hits", [])
    except (HTTPError, URLError, Exception) as exc:
        log.error("ES search failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Zovark API client
# ---------------------------------------------------------------------------
class ZovarkClient:
    """Handles auth and task submission to the Zovark API."""

    def __init__(self):
        self._token: Optional[str] = None
        self._token_ts: float = 0.0

    def _login(self) -> str:
        url = f"{ZOVARK_API_URL}/api/v1/auth/login"
        result = http_post(url, {"email": ZOVARK_EMAIL, "password": ZOVARK_PASSWORD})
        token = result.get("token") or result.get("access_token", "")
        if not token:
            raise RuntimeError(f"No token in login response: {list(result.keys())}")
        return token

    def _get_token(self) -> str:
        if self._token and (time.time() - self._token_ts) < 600:
            return self._token
        log.info("Authenticating with Zovark API...")
        self._token = self._login()
        self._token_ts = time.time()
        log.info("Authenticated successfully")
        return self._token

    def submit_alert(self, task_type: str, title: str, severity: str,
                     source_ip: str, rule_name: str, raw_log: str,
                     extra_fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Submit an investigation task to Zovark."""
        if DRY_RUN:
            log.info("[DRY RUN] Would submit: task_type=%s title=%s source_ip=%s",
                     task_type, title, source_ip)
            return {"dry_run": True, "task_type": task_type}

        token = self._get_token()

        siem_event: Dict[str, Any] = {
            "title": title,
            "source_ip": source_ip,
            "rule_name": rule_name,
            "severity": severity,
            "raw_log": raw_log[:10000],
        }
        if extra_fields:
            siem_event.update(extra_fields)

        payload = {
            "task_type": task_type,
            "input": {
                "prompt": title,
                "severity": severity,
                "siem_event": siem_event,
            },
        }

        url = f"{ZOVARK_API_URL}/api/v1/tasks"
        try:
            result = http_post(url, payload, {"Authorization": f"Bearer {token}"}, timeout=30)
            log.info("Task submitted: task_type=%s task_id=%s", task_type, result.get("id", "?"))
            return result
        except HTTPError as exc:
            if exc.code == 401:
                log.warning("Token expired, re-authenticating...")
                self._token = None
                token = self._get_token()
                result = http_post(url, payload, {"Authorization": f"Bearer {token}"}, timeout=30)
                log.info("Task submitted (retry): task_type=%s task_id=%s", task_type, result.get("id", "?"))
                return result
            raise

    def health_check(self) -> bool:
        try:
            req = Request(f"{ZOVARK_API_URL}/health", method="GET")
            with urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False


_client = ZovarkClient()


# ---------------------------------------------------------------------------
# Deduplication -- avoid re-alerting on the same event
# ---------------------------------------------------------------------------
class AlertDedup:
    """In-memory dedup using alert hashes with configurable TTL."""

    def __init__(self, ttl_seconds: int = 300):
        self.ttl = ttl_seconds
        self._seen: Dict[str, float] = {}

    def _cleanup(self):
        now = time.time()
        expired = [k for k, ts in self._seen.items() if now - ts > self.ttl]
        for k in expired:
            del self._seen[k]

    def is_duplicate(self, alert_hash: str) -> bool:
        self._cleanup()
        if alert_hash in self._seen:
            return True
        self._seen[alert_hash] = time.time()
        return False

    def make_hash(self, *parts: str) -> str:
        combined = "|".join(str(p) for p in parts)
        return hashlib.sha256(combined.encode()).hexdigest()[:16]


_dedup = AlertDedup(ttl_seconds=600)


# ---------------------------------------------------------------------------
# Detection Rule 1: Brute Force
# ---------------------------------------------------------------------------
# Detects 5+ HTTP 401/403 responses from the same IP within a 5-minute window.

def detect_brute_force(since: str) -> List[Dict[str, Any]]:
    """Detect brute force attempts: 5+ failed auth from same IP in window."""
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": since}}},
                {"terms": {"status": [401, 403]}},
            ]
        }
    }
    hits = es_search(ES_INDEX_PATTERN, query, size=1000)
    if not hits:
        return []

    # Group by source IP
    ip_events: Dict[str, List[Dict[str, Any]]] = {}
    for hit in hits:
        src = hit.get("_source", {})
        ip = src.get("remote_addr", src.get("source_ip", src.get("client_ip", "")))
        if ip:
            ip_events.setdefault(ip, []).append(src)

    alerts = []
    for ip, events in ip_events.items():
        if len(events) >= BF_THRESHOLD:
            alert_hash = _dedup.make_hash("brute_force", ip, since[:13])  # dedup per hour
            if _dedup.is_duplicate(alert_hash):
                continue

            raw_log_lines = []
            for e in events[:20]:
                raw_log_lines.append(
                    f"{e.get('time_local', '?')} {ip} "
                    f"{e.get('request', '?')} -> {e.get('status', '?')}"
                )
            raw_log = "\n".join(raw_log_lines)

            alerts.append({
                "task_type": "brute_force",
                "title": f"Brute force detected: {len(events)} failed auth attempts from {ip}",
                "severity": "high" if len(events) >= 20 else "medium",
                "source_ip": ip,
                "rule_name": "elastic_poller:brute_force",
                "raw_log": raw_log,
                "extra": {"failed_count": len(events), "window_seconds": BF_WINDOW_SECONDS},
            })
            log.warning(
                "DETECTION [brute_force] %d failed attempts from %s", len(events), ip
            )

    return alerts


# ---------------------------------------------------------------------------
# Detection Rule 2: SQL Injection
# ---------------------------------------------------------------------------
# Detects SQL injection patterns in request URIs and bodies.

SQL_INJECTION_PATTERNS = [
    r"(?i)(?:union\s+(?:all\s+)?select)",
    r"(?i)(?:select\s+.*\s+from\s+)",
    r"(?i)(?:insert\s+into\s+)",
    r"(?i)(?:delete\s+from\s+)",
    r"(?i)(?:drop\s+(?:table|database))",
    r"(?i)(?:update\s+\w+\s+set\s+)",
    r"(?i)(?:or\s+1\s*=\s*1)",
    r"(?i)(?:or\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)",
    r"(?i)(?:'\s*(?:or|and)\s+)",
    r"(?:--|;)\s*$",
    r"(?i)(?:benchmark\s*\(|sleep\s*\(|waitfor\s+delay)",
    r"(?i)(?:information_schema|sys\.tables|sysobjects)",
    r"(?i)(?:char\s*\(\s*\d+\s*\)|concat\s*\()",
    r"(?i)(?:load_file\s*\(|into\s+(?:out|dump)file)",
]

_sqli_compiled = [re.compile(p) for p in SQL_INJECTION_PATTERNS]


def detect_sqli(since: str) -> List[Dict[str, Any]]:
    """Detect SQL injection attempts in request URIs."""
    # Pull recent non-static requests
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": since}}},
                {"exists": {"field": "request"}},
            ],
            "must_not": [
                {"terms": {"status": [301, 302, 304]}},
            ],
        }
    }
    hits = es_search(ES_INDEX_PATTERN, query, size=500)
    if not hits:
        return []

    alerts = []
    for hit in hits:
        src = hit.get("_source", {})
        request_str = src.get("request", "")
        ip = src.get("remote_addr", src.get("source_ip", ""))

        for pattern in _sqli_compiled:
            if pattern.search(request_str):
                alert_hash = _dedup.make_hash("sqli", ip, request_str[:200])
                if _dedup.is_duplicate(alert_hash):
                    break

                raw_log = (
                    f"time={src.get('time_local', '?')} "
                    f"ip={ip} "
                    f"request={request_str} "
                    f"status={src.get('status', '?')} "
                    f"user_agent={src.get('http_user_agent', '?')}"
                )

                alerts.append({
                    "task_type": "malware",
                    "title": f"SQL injection attempt from {ip}: {request_str[:120]}",
                    "severity": "critical",
                    "source_ip": ip,
                    "rule_name": "elastic_poller:sqli",
                    "raw_log": raw_log,
                    "extra": {
                        "attack_type": "sql_injection",
                        "matched_pattern": pattern.pattern,
                        "http_status": src.get("status"),
                        "user_agent": src.get("http_user_agent", ""),
                    },
                })
                log.warning("DETECTION [sqli] %s -> %s", ip, request_str[:200])
                break  # one alert per request

    return alerts


# ---------------------------------------------------------------------------
# Detection Rule 3: Cross-Site Scripting (XSS)
# ---------------------------------------------------------------------------

XSS_PATTERNS = [
    r"<\s*script[^>]*>",
    r"javascript\s*:",
    r"on(?:error|load|click|mouseover|focus|blur|submit|change)\s*=",
    r"<\s*(?:img|svg|iframe|object|embed|video|audio|body|input)\s+[^>]*on\w+\s*=",
    r"document\s*\.\s*(?:cookie|location|write|domain)",
    r"window\s*\.\s*(?:location|open|eval)",
    r"(?:alert|confirm|prompt)\s*\(",
    r"<\s*/?\s*(?:script|iframe|object|embed|applet|form|style)",
    r"expression\s*\(",
    r"url\s*\(\s*['\"]?\s*javascript",
]

_xss_compiled = [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS]


def detect_xss(since: str) -> List[Dict[str, Any]]:
    """Detect XSS attempts in request data."""
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": since}}},
                {"exists": {"field": "request"}},
            ]
        }
    }
    hits = es_search(ES_INDEX_PATTERN, query, size=500)
    if not hits:
        return []

    alerts = []
    for hit in hits:
        src = hit.get("_source", {})
        request_str = src.get("request", "")
        referer = src.get("http_referer", "")
        check_str = f"{request_str} {referer}"
        ip = src.get("remote_addr", src.get("source_ip", ""))

        for pattern in _xss_compiled:
            if pattern.search(check_str):
                alert_hash = _dedup.make_hash("xss", ip, request_str[:200])
                if _dedup.is_duplicate(alert_hash):
                    break

                raw_log = (
                    f"time={src.get('time_local', '?')} "
                    f"ip={ip} "
                    f"request={request_str} "
                    f"referer={referer} "
                    f"status={src.get('status', '?')} "
                    f"user_agent={src.get('http_user_agent', '?')}"
                )

                alerts.append({
                    "task_type": "malware",
                    "title": f"XSS attempt from {ip}: {request_str[:120]}",
                    "severity": "high",
                    "source_ip": ip,
                    "rule_name": "elastic_poller:xss",
                    "raw_log": raw_log,
                    "extra": {
                        "attack_type": "xss",
                        "matched_pattern": pattern.pattern,
                        "http_status": src.get("status"),
                        "user_agent": src.get("http_user_agent", ""),
                    },
                })
                log.warning("DETECTION [xss] %s -> %s", ip, request_str[:200])
                break

    return alerts


# ---------------------------------------------------------------------------
# Detection Rule 4: Path Traversal
# ---------------------------------------------------------------------------

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\%2[fF]",
    r"\%2[eE]\%2[eE]/",
    r"\%2[eE]\%2[eE]\%2[fF]",
    r"/etc/(?:passwd|shadow|hosts|group)",
    r"/proc/(?:self|version|cmdline)",
    r"(?:c|C):\\\\(?:windows|winnt|boot\.ini)",
    r"/var/log/",
    r"\.\.\\\\",
]

_traversal_compiled = [re.compile(p, re.IGNORECASE) for p in PATH_TRAVERSAL_PATTERNS]


def detect_path_traversal(since: str) -> List[Dict[str, Any]]:
    """Detect path traversal attempts in request URIs."""
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": since}}},
                {"exists": {"field": "request"}},
            ]
        }
    }
    hits = es_search(ES_INDEX_PATTERN, query, size=500)
    if not hits:
        return []

    alerts = []
    for hit in hits:
        src = hit.get("_source", {})
        request_str = src.get("request", "")
        ip = src.get("remote_addr", src.get("source_ip", ""))

        for pattern in _traversal_compiled:
            if pattern.search(request_str):
                alert_hash = _dedup.make_hash("traversal", ip, request_str[:200])
                if _dedup.is_duplicate(alert_hash):
                    break

                raw_log = (
                    f"time={src.get('time_local', '?')} "
                    f"ip={ip} "
                    f"request={request_str} "
                    f"status={src.get('status', '?')} "
                    f"user_agent={src.get('http_user_agent', '?')}"
                )

                alerts.append({
                    "task_type": "data_exfiltration",
                    "title": f"Path traversal attempt from {ip}: {request_str[:120]}",
                    "severity": "high",
                    "source_ip": ip,
                    "rule_name": "elastic_poller:path_traversal",
                    "raw_log": raw_log,
                    "extra": {
                        "attack_type": "path_traversal",
                        "matched_pattern": pattern.pattern,
                        "http_status": src.get("status"),
                        "user_agent": src.get("http_user_agent", ""),
                    },
                })
                log.warning("DETECTION [path_traversal] %s -> %s", ip, request_str[:200])
                break

    return alerts


# ---------------------------------------------------------------------------
# Poll loop
# ---------------------------------------------------------------------------
ALL_RULES = [
    ("brute_force", detect_brute_force),
    ("sqli", detect_sqli),
    ("xss", detect_xss),
    ("path_traversal", detect_path_traversal),
]


def poll_once(since: str) -> int:
    """Run all detection rules once. Returns number of alerts submitted."""
    total_alerts = 0

    for rule_name, rule_fn in ALL_RULES:
        try:
            alerts = rule_fn(since)
            for alert in alerts:
                try:
                    _client.submit_alert(
                        task_type=alert["task_type"],
                        title=alert["title"],
                        severity=alert["severity"],
                        source_ip=alert["source_ip"],
                        rule_name=alert["rule_name"],
                        raw_log=alert["raw_log"],
                        extra_fields=alert.get("extra"),
                    )
                    total_alerts += 1
                except Exception as exc:
                    log.error("Failed to submit alert for rule %s: %s", rule_name, exc)
        except Exception as exc:
            log.error("Detection rule %s failed: %s", rule_name, exc, exc_info=True)

    return total_alerts


def check_elasticsearch() -> bool:
    """Verify Elasticsearch is reachable."""
    try:
        info = http_get(ELASTICSEARCH_URL, timeout=5)
        version = info.get("version", {}).get("number", "?")
        log.info("Connected to Elasticsearch %s", version)
        return True
    except Exception as exc:
        log.error("Cannot reach Elasticsearch at %s: %s", ELASTICSEARCH_URL, exc)
        return False


def check_zovark() -> bool:
    """Verify Zovark API is reachable."""
    healthy = _client.health_check()
    if healthy:
        log.info("Zovark API is reachable at %s", ZOVARK_API_URL)
    else:
        log.warning("Zovark API is NOT reachable at %s", ZOVARK_API_URL)
    return healthy


def main():
    log.info("=" * 60)
    log.info("Zovark Elastic Detection Poller")
    log.info("=" * 60)
    log.info("Elasticsearch: %s", ELASTICSEARCH_URL)
    log.info("Index pattern: %s", ES_INDEX_PATTERN)
    log.info("Poll interval: %ds", POLL_INTERVAL)
    log.info("Zovark API:    %s", ZOVARK_API_URL)
    log.info("Dry run:       %s", DRY_RUN)
    log.info("Brute force:   threshold=%d window=%ds", BF_THRESHOLD, BF_WINDOW_SECONDS)
    log.info("Detection rules: %s", ", ".join(name for name, _ in ALL_RULES))
    log.info("=" * 60)

    # Pre-flight checks
    es_ok = check_elasticsearch()
    zovark_ok = check_zovark()

    if not es_ok:
        log.error("Elasticsearch is not reachable. Will retry on each poll cycle.")
    if not zovark_ok and not DRY_RUN:
        log.error("Zovark API is not reachable. Will retry on each poll cycle.")

    poll_count = 0
    total_alerts = 0

    while _running:
        poll_count += 1
        since = (
            datetime.now(timezone.utc) - timedelta(seconds=max(POLL_INTERVAL * 2, BF_WINDOW_SECONDS))
        ).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        log.info("--- Poll #%d (since %s) ---", poll_count, since)

        try:
            count = poll_once(since)
            total_alerts += count
            if count > 0:
                log.info("Submitted %d alert(s) this cycle (total: %d)", count, total_alerts)
            else:
                log.debug("No new detections")
        except Exception as exc:
            log.error("Poll cycle failed: %s", exc, exc_info=True)

        # Sleep in small increments for responsive shutdown
        for _ in range(POLL_INTERVAL):
            if not _running:
                break
            time.sleep(1)

    log.info("Poller stopped. Total polls: %d, Total alerts: %d", poll_count, total_alerts)


if __name__ == "__main__":
    main()
