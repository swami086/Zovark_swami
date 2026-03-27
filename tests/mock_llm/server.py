#!/usr/bin/env python3
"""Mock LLM server that mimics the LiteLLM API.

Uses only Python stdlib (http.server). Returns canned responses for:
  - POST /v1/chat/completions — investigation responses
  - POST /v1/embeddings — random 768-dim vectors
  - GET /health/liveliness — 200 OK

Usage:
    python tests/mock_llm/server.py                  # default port 4000
    python tests/mock_llm/server.py --port 4001      # custom port
"""

import json
import random
import time
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler

from responses import select_response


class MockLLMHandler(BaseHTTPRequestHandler):
    """Handles LLM API requests with canned responses."""

    def log_message(self, format, *args):
        """Override to prefix with [MockLLM]."""
        print(f"[MockLLM] {args[0]}")

    def _send_json(self, status, body):
        """Helper to send JSON response."""
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_body(self):
        """Read and parse JSON request body."""
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def do_GET(self):
        """Handle GET requests."""
        if self.path in ("/health/liveliness", "/health/liveness", "/health"):
            self._send_json(200, {"status": "healthy"})
        elif self.path == "/v1/models":
            self._send_json(200, {
                "data": [
                    {"id": "fast", "object": "model", "owned_by": "mock"},
                    {"id": "embed", "object": "model", "owned_by": "mock"},
                    {"id": "zovarc-fast", "object": "model", "owned_by": "mock"},
                    {"id": "zovarc-standard", "object": "model", "owned_by": "mock"},
                ]
            })
        else:
            self._send_json(404, {"error": f"Not found: {self.path}"})

    def do_POST(self):
        """Handle POST requests."""
        body = self._read_body()

        if self.path == "/v1/chat/completions":
            self._handle_chat_completions(body)
        elif self.path == "/v1/embeddings":
            self._handle_embeddings(body)
        elif self.path == "/chat/completions":
            # Some clients omit the /v1 prefix
            self._handle_chat_completions(body)
        elif self.path == "/embeddings":
            self._handle_embeddings(body)
        else:
            self._send_json(404, {"error": f"Not found: {self.path}"})

    def _handle_chat_completions(self, body):
        """Return canned chat completion response."""
        messages = body.get("messages", [])
        model = body.get("model", "fast")
        max_tokens = body.get("max_tokens", 1024)

        # Select response based on message content
        content = select_response(messages)

        # Simulate some latency (50-200ms)
        time.sleep(random.uniform(0.05, 0.2))

        response = {
            "id": f"mock-{int(time.time() * 1000)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content,
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": sum(len(m.get("content", "").split()) for m in messages),
                "completion_tokens": len(content.split()),
                "total_tokens": sum(len(m.get("content", "").split()) for m in messages) + len(content.split()),
            },
        }
        self._send_json(200, response)

    def _handle_embeddings(self, body):
        """Return random 768-dimensional embedding vectors."""
        input_data = body.get("input", "")
        model = body.get("model", "embed")

        # Handle both string and list inputs
        if isinstance(input_data, str):
            inputs = [input_data]
        else:
            inputs = input_data

        data = []
        for i, text in enumerate(inputs):
            # Generate deterministic-ish random vector seeded by input
            random.seed(hash(text) % (2**32))
            vector = [random.gauss(0, 1) for _ in range(768)]
            # L2 normalize
            magnitude = sum(v * v for v in vector) ** 0.5
            if magnitude > 0:
                vector = [v / magnitude for v in vector]
            data.append({
                "object": "embedding",
                "index": i,
                "embedding": vector,
            })

        response = {
            "object": "list",
            "data": data,
            "model": model,
            "usage": {
                "prompt_tokens": sum(len(t.split()) for t in inputs),
                "total_tokens": sum(len(t.split()) for t in inputs),
            },
        }
        self._send_json(200, response)


def main():
    parser = argparse.ArgumentParser(description="ZOVARC Mock LLM Server")
    parser.add_argument("--port", type=int, default=4000, help="Port to listen on")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), MockLLMHandler)
    print(f"[MockLLM] Starting mock LLM server on {args.host}:{args.port}")
    print(f"[MockLLM] Endpoints:")
    print(f"[MockLLM]   POST /v1/chat/completions")
    print(f"[MockLLM]   POST /v1/embeddings")
    print(f"[MockLLM]   GET  /health/liveliness")
    print(f"[MockLLM]   GET  /v1/models")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[MockLLM] Shutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
