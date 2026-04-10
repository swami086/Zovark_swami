#!/usr/bin/env python3
"""Lightweight sidecar HTTP server for worker host metrics (Ticket 7).

OTLP metrics are pushed from the worker process via OpenTelemetry (see worker/metrics.py).
This endpoint provides liveness only — no per-request DB or Redis polling.

Endpoints:
  GET /health  → {"status": "ok", "mode": "health_only"}
  GET /metrics → short text noting OTLP export (no Prometheus scrape of DB)
"""

import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(os.environ.get("METRICS_PORT", "9093"))


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = json.dumps({"status": "ok", "mode": "health_only"})
            self._send(200, body, "application/json")
            return
        if self.path == "/metrics":
            text = (
                "# Zovark worker metrics are exported via OTLP HTTP to SigNoz "
                "(zovark.worker.* instruments in worker/metrics.py).\n"
                "# This sidecar does not scrape PostgreSQL or Redis.\n"
            )
            self._send(200, text, "text/plain; charset=utf-8")
            return
        self._send(404, '{"error":"not_found"}', "application/json")

    def _send(self, code: int, body: str, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, fmt, *args):
        pass


def main():
    print(f"Worker metrics sidecar (health-only) on port {PORT}")
    HTTPServer(("0.0.0.0", PORT), _Handler).serve_forever()


if __name__ == "__main__":
    main()
