#!/usr/bin/env python3
"""
Zovark SIEM Lab -- Webhook Bridge
==================================
Receives Elasticsearch Watcher / Kibana alert webhooks and forwards them
to the Zovark API as investigation tasks.

Supports two HTTP stacks:
  1. FastAPI + uvicorn  (preferred -- auto-detected)
  2. stdlib http.server (zero-dependency fallback)

Usage:
    # FastAPI (auto)
    python webhook_bridge.py

    # Force stdlib
    WEBHOOK_BRIDGE_STDLIB=1 python webhook_bridge.py

Environment variables:
    ZOVARK_API_URL   -- Zovark API base URL       (default: http://localhost:8090)
    ZOVARK_EMAIL     -- Login email                (default: admin@test.local)
    ZOVARK_PASSWORD  -- Login password             (default: TestPass2026)
    WEBHOOK_PORT     -- Port to listen on          (default: 9000)
    WEBHOOK_BRIDGE_STDLIB -- Force stdlib fallback (default: unset)
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import threading
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ZOVARK_API_URL = os.environ.get("ZOVARK_API_URL", "http://localhost:8090")
ZOVARK_EMAIL = os.environ.get("ZOVARK_EMAIL", "admin@test.local")
ZOVARK_PASSWORD = os.environ.get("ZOVARK_PASSWORD", "TestPass2026")
WEBHOOK_PORT = int(os.environ.get("WEBHOOK_PORT", "9000"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("webhook_bridge")

# ---------------------------------------------------------------------------
# Rule-name --> task_type mapping (mirrors api/siem_ingest.go)
# ---------------------------------------------------------------------------
TASK_TYPE_PATTERNS: list[tuple[str, str]] = [
    (r"brute.?force|failed.?password|multiple.?login", "brute_force"),
    (r"malware|trojan|ransomware", "ransomware_triage"),
    (r"beacon|c2|command.?and.?control", "network_beaconing"),
    (r"phish|credential.?harvest", "phishing"),
    (r"lateral.?movement|pass.?the.?hash|pth", "lateral_movement"),
    (r"exfil|large.?transfer|dns.?tunnel", "data_exfiltration"),
    (r"privilege.?escalat|sudo|uac", "privilege_escalation"),
    (r"insider|unauthorized.?access", "insider_threat"),
    (r"sql.?inject|xss|cross.?site|command.?inject|path.?traversal", "web_attack"),
    (r"denial.?of.?service|ddos|dos", "dos_attack"),
    (r"suspicious.?process|fileless|powershell.?abuse", "endpoint_anomaly"),
]


def map_rule_to_task_type(rule_name: str) -> str:
    """Map an alert rule name to a Zovark task_type."""
    lower = rule_name.lower()
    for pattern, task_type in TASK_TYPE_PATTERNS:
        if re.search(pattern, lower):
            return task_type
    # Fallback: sanitize rule name
    sanitized = re.sub(r"[^a-z0-9_]", "", lower.replace(" ", "_").replace("-", "_"))
    return sanitized[:60] if sanitized else "log_analysis"


# ---------------------------------------------------------------------------
# Zovark API client
# ---------------------------------------------------------------------------
class ZovarkClient:
    """Thin client for Zovark API authentication and task submission."""

    def __init__(self, base_url: str, email: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.password = password
        self._token: Optional[str] = None
        self._token_ts: float = 0.0
        self._lock = threading.Lock()

    # ------ auth ------
    def _login(self) -> str:
        """Authenticate and return a JWT token."""
        url = f"{self.base_url}/api/v1/auth/login"
        body = json.dumps({"email": self.email, "password": self.password}).encode()
        req = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                token = data.get("token") or data.get("access_token", "")
                if not token:
                    raise RuntimeError(f"No token in login response: {list(data.keys())}")
                return token
        except (HTTPError, URLError) as exc:
            raise RuntimeError(f"Zovark login failed: {exc}") from exc

    def _get_token(self) -> str:
        """Return a valid JWT, refreshing if older than 10 minutes."""
        with self._lock:
            if self._token and (time.time() - self._token_ts) < 600:
                return self._token
            log.info("Authenticating with Zovark API at %s", self.base_url)
            self._token = self._login()
            self._token_ts = time.time()
            log.info("Authenticated successfully")
            return self._token

    # ------ task submission ------
    def submit_task(self, task_type: str, title: str, severity: str,
                    source_ip: str, rule_name: str, raw_log: str,
                    extra_fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """POST a new investigation task and return the API response."""
        token = self._get_token()

        siem_event: Dict[str, Any] = {
            "title": title,
            "source_ip": source_ip,
            "rule_name": rule_name,
            "severity": severity,
            "raw_log": raw_log[:10000],  # cap to prevent oversized payloads
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

        url = f"{self.base_url}/api/v1/tasks"
        body = json.dumps(payload).encode()
        req = Request(url, data=body, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }, method="POST")

        try:
            with urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read())
                log.info("Task submitted: task_type=%s task_id=%s", task_type, result.get("id", "?"))
                return result
        except HTTPError as exc:
            # Token may have expired -- retry once
            if exc.code == 401:
                log.warning("Token expired, re-authenticating...")
                with self._lock:
                    self._token = None
                token = self._get_token()
                req.remove_header("Authorization")
                req.add_header("Authorization", f"Bearer {token}")
                with urlopen(req, timeout=30) as resp:
                    result = json.loads(resp.read())
                    log.info("Task submitted (retry): task_type=%s task_id=%s", task_type, result.get("id", "?"))
                    return result
            raise

    def health_check(self) -> bool:
        """Return True if the Zovark API is reachable."""
        try:
            req = Request(f"{self.base_url}/health", method="GET")
            with urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False


# Singleton
_client = ZovarkClient(ZOVARK_API_URL, ZOVARK_EMAIL, ZOVARK_PASSWORD)


# ---------------------------------------------------------------------------
# Webhook payload parsing
# ---------------------------------------------------------------------------
def parse_elastic_watcher(body: Dict[str, Any]) -> Dict[str, Any]:
    """Parse Elasticsearch Watcher webhook payload into normalized fields."""
    # Watcher payloads vary, but generally contain:
    #   { "watch_id": "...", "payload": { "hits": {...} }, "metadata": {...} }
    watch_id = body.get("watch_id", "unknown_watch")
    metadata = body.get("metadata", {})
    ctx = body.get("ctx", body)  # some watcher configs nest under ctx

    rule_name = metadata.get("name", watch_id)
    severity = metadata.get("severity", "medium")
    title = metadata.get("title", f"Elastic Watcher: {rule_name}")
    source_ip = metadata.get("source_ip", "")

    # Try to extract hits as raw_log context
    payload_data = body.get("payload", {})
    hits = payload_data.get("hits", {}).get("hits", [])
    if hits:
        raw_log = json.dumps(hits[:5], default=str)[:10000]
    else:
        raw_log = json.dumps(body, default=str)[:10000]

    return {
        "rule_name": rule_name,
        "severity": severity,
        "title": title,
        "source_ip": source_ip,
        "raw_log": raw_log,
        "extra": {"watch_id": watch_id, "watcher_payload": True},
    }


def parse_kibana_alert(body: Dict[str, Any]) -> Dict[str, Any]:
    """Parse Kibana alerting framework webhook payload."""
    # Kibana alerts use:
    #   { "alertId": "...", "alertName": "...", "context": {...}, "state": {...} }
    alert_name = body.get("alertName", body.get("ruleName", "unknown_alert"))
    alert_id = body.get("alertId", body.get("ruleId", ""))
    context = body.get("context", {})
    state = body.get("state", {})

    severity = context.get("severity", body.get("severity", "medium"))
    source_ip = context.get("source_ip", context.get("source.ip", ""))
    title = context.get("title", f"Kibana Alert: {alert_name}")
    message = context.get("message", "")

    raw_log = message if message else json.dumps(body, default=str)[:10000]

    return {
        "rule_name": alert_name,
        "severity": severity,
        "title": title,
        "source_ip": source_ip,
        "raw_log": raw_log[:10000],
        "extra": {"alert_id": alert_id, "kibana_alert": True},
    }


def parse_generic_webhook(body: Dict[str, Any]) -> Dict[str, Any]:
    """Fallback parser for generic webhook payloads."""
    rule_name = (
        body.get("rule_name")
        or body.get("ruleName")
        or body.get("alert_name")
        or body.get("name")
        or body.get("title")
        or "unknown_alert"
    )
    severity = body.get("severity", "medium")
    source_ip = body.get("source_ip", body.get("src_ip", ""))
    title = body.get("title", body.get("message", f"Webhook alert: {rule_name}"))
    raw_log = body.get("raw_log", body.get("raw", json.dumps(body, default=str)))

    return {
        "rule_name": rule_name,
        "severity": severity,
        "title": title,
        "source_ip": source_ip,
        "raw_log": str(raw_log)[:10000],
        "extra": {},
    }


def detect_and_parse(body: Dict[str, Any]) -> Dict[str, Any]:
    """Auto-detect webhook format and parse accordingly."""
    if "watch_id" in body or ("payload" in body and "metadata" in body):
        log.info("Detected Elasticsearch Watcher format")
        return parse_elastic_watcher(body)
    elif "alertId" in body or "alertName" in body or "ruleName" in body:
        log.info("Detected Kibana alert format")
        return parse_kibana_alert(body)
    else:
        log.info("Using generic webhook parser")
        return parse_generic_webhook(body)


def handle_webhook(body: Dict[str, Any]) -> Dict[str, Any]:
    """Process a webhook payload: parse, map, and submit to Zovark."""
    parsed = detect_and_parse(body)
    task_type = map_rule_to_task_type(parsed["rule_name"])

    log.info(
        "Processing alert: rule=%s -> task_type=%s severity=%s source_ip=%s",
        parsed["rule_name"], task_type, parsed["severity"], parsed["source_ip"],
    )

    result = _client.submit_task(
        task_type=task_type,
        title=parsed["title"],
        severity=parsed["severity"],
        source_ip=parsed["source_ip"],
        rule_name=parsed["rule_name"],
        raw_log=parsed["raw_log"],
        extra_fields=parsed.get("extra"),
    )

    return {
        "status": "accepted",
        "task_type": task_type,
        "rule_name": parsed["rule_name"],
        "zovark_response": result,
    }


# ---------------------------------------------------------------------------
# Stats tracking
# ---------------------------------------------------------------------------
class Stats:
    """Simple in-memory counters for observability."""

    def __init__(self):
        self.received = 0
        self.forwarded = 0
        self.errors = 0
        self.started_at = datetime.now(timezone.utc).isoformat()
        self._lock = threading.Lock()

    def inc_received(self):
        with self._lock:
            self.received += 1

    def inc_forwarded(self):
        with self._lock:
            self.forwarded += 1

    def inc_errors(self):
        with self._lock:
            self.errors += 1

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "received": self.received,
                "forwarded": self.forwarded,
                "errors": self.errors,
                "started_at": self.started_at,
                "zovark_api": ZOVARK_API_URL,
                "zovark_healthy": _client.health_check(),
            }


_stats = Stats()


# =====================================================================
# Option A: FastAPI server (preferred)
# =====================================================================
def _try_fastapi():
    """Attempt to start with FastAPI + uvicorn. Returns False if not available."""
    try:
        from fastapi import FastAPI, HTTPException, Request as FARequest
        from fastapi.responses import JSONResponse
        import uvicorn
    except ImportError:
        return False

    app = FastAPI(
        title="Zovark Webhook Bridge",
        description="Receives SIEM webhooks and forwards to Zovark API",
        version="1.0.0",
    )

    @app.get("/health")
    async def health():
        return {"status": "ok", "bridge": "webhook_bridge", "stats": _stats.to_dict()}

    @app.get("/stats")
    async def stats():
        return _stats.to_dict()

    @app.post("/webhook")
    async def webhook(request: FARequest):
        _stats.inc_received()
        try:
            body = await request.json()
        except Exception:
            _stats.inc_errors()
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        try:
            result = handle_webhook(body)
            _stats.inc_forwarded()
            return result
        except Exception as exc:
            _stats.inc_errors()
            log.error("Failed to process webhook: %s", exc, exc_info=True)
            raise HTTPException(status_code=502, detail=f"Failed to forward to Zovark: {exc}")

    @app.post("/webhook/elastic-watcher")
    async def webhook_elastic_watcher(request: FARequest):
        """Explicit Elasticsearch Watcher endpoint."""
        _stats.inc_received()
        try:
            body = await request.json()
        except Exception:
            _stats.inc_errors()
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        try:
            parsed = parse_elastic_watcher(body)
            task_type = map_rule_to_task_type(parsed["rule_name"])
            result = _client.submit_task(
                task_type=task_type,
                title=parsed["title"],
                severity=parsed["severity"],
                source_ip=parsed["source_ip"],
                rule_name=parsed["rule_name"],
                raw_log=parsed["raw_log"],
                extra_fields=parsed.get("extra"),
            )
            _stats.inc_forwarded()
            return {"status": "accepted", "task_type": task_type, "zovark_response": result}
        except Exception as exc:
            _stats.inc_errors()
            log.error("Watcher webhook failed: %s", exc, exc_info=True)
            raise HTTPException(status_code=502, detail=str(exc))

    @app.post("/webhook/kibana-alert")
    async def webhook_kibana_alert(request: FARequest):
        """Explicit Kibana alerting endpoint."""
        _stats.inc_received()
        try:
            body = await request.json()
        except Exception:
            _stats.inc_errors()
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        try:
            parsed = parse_kibana_alert(body)
            task_type = map_rule_to_task_type(parsed["rule_name"])
            result = _client.submit_task(
                task_type=task_type,
                title=parsed["title"],
                severity=parsed["severity"],
                source_ip=parsed["source_ip"],
                rule_name=parsed["rule_name"],
                raw_log=parsed["raw_log"],
                extra_fields=parsed.get("extra"),
            )
            _stats.inc_forwarded()
            return {"status": "accepted", "task_type": task_type, "zovark_response": result}
        except Exception as exc:
            _stats.inc_errors()
            log.error("Kibana webhook failed: %s", exc, exc_info=True)
            raise HTTPException(status_code=502, detail=str(exc))

    log.info("Starting Webhook Bridge (FastAPI) on port %d", WEBHOOK_PORT)
    log.info("Zovark API: %s", ZOVARK_API_URL)
    log.info("Endpoints: POST /webhook, POST /webhook/elastic-watcher, POST /webhook/kibana-alert")
    uvicorn.run(app, host="0.0.0.0", port=WEBHOOK_PORT, log_level="info")
    return True


# =====================================================================
# Option B: stdlib http.server fallback (zero dependencies)
# =====================================================================
class WebhookHandler(BaseHTTPRequestHandler):
    """Stdlib HTTP handler for environments without FastAPI."""

    def _send_json(self, status: int, data: Any):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> Optional[Dict[str, Any]]:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return None
        raw = self.rfile.read(length)
        return json.loads(raw)

    def do_GET(self):
        if self.path in ("/health", "/stats"):
            self._send_json(200, {"status": "ok", "bridge": "webhook_bridge", "stats": _stats.to_dict()})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if not self.path.startswith("/webhook"):
            self._send_json(404, {"error": "not found"})
            return

        _stats.inc_received()
        try:
            body = self._read_body()
            if body is None:
                _stats.inc_errors()
                self._send_json(400, {"error": "empty or invalid JSON body"})
                return
        except (json.JSONDecodeError, ValueError) as exc:
            _stats.inc_errors()
            self._send_json(400, {"error": f"invalid JSON: {exc}"})
            return

        try:
            # Route to specific parser if explicit endpoint used
            if self.path == "/webhook/elastic-watcher":
                parsed = parse_elastic_watcher(body)
            elif self.path == "/webhook/kibana-alert":
                parsed = parse_kibana_alert(body)
            else:
                parsed = detect_and_parse(body)

            task_type = map_rule_to_task_type(parsed["rule_name"])
            result = _client.submit_task(
                task_type=task_type,
                title=parsed["title"],
                severity=parsed["severity"],
                source_ip=parsed["source_ip"],
                rule_name=parsed["rule_name"],
                raw_log=parsed["raw_log"],
                extra_fields=parsed.get("extra"),
            )
            _stats.inc_forwarded()
            self._send_json(200, {"status": "accepted", "task_type": task_type, "zovark_response": result})
        except Exception as exc:
            _stats.inc_errors()
            log.error("Failed to process webhook: %s", exc, exc_info=True)
            self._send_json(502, {"error": f"failed to forward to Zovark: {exc}"})

    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)


def _run_stdlib():
    """Run the webhook bridge using stdlib http.server."""
    server = HTTPServer(("0.0.0.0", WEBHOOK_PORT), WebhookHandler)
    log.info("Starting Webhook Bridge (stdlib) on port %d", WEBHOOK_PORT)
    log.info("Zovark API: %s", ZOVARK_API_URL)
    log.info("Endpoints: POST /webhook, POST /webhook/elastic-watcher, POST /webhook/kibana-alert")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down webhook bridge")
        server.shutdown()


# =====================================================================
# Entry point
# =====================================================================
if __name__ == "__main__":
    force_stdlib = os.environ.get("WEBHOOK_BRIDGE_STDLIB", "").lower() in ("1", "true", "yes")

    if not force_stdlib and _try_fastapi():
        pass  # FastAPI started successfully
    else:
        if not force_stdlib:
            log.info("FastAPI/uvicorn not installed, falling back to stdlib http.server")
        _run_stdlib()
