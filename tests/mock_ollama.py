#!/usr/bin/env python3
"""Mock Ollama server for CI/CD testing.

Lightweight HTTP server that mimics Ollama's API with deterministic responses.
No GPU required, no model files. Pure Python stdlib.

Endpoints:
  POST /v1/chat/completions   — OpenAI-compatible chat (used by llm_gateway)
  POST /api/generate           — Ollama native generate (used by preload_ollama_model)
  POST /api/chat               — Ollama native chat
  GET  /api/tags               — List local models (Ollama native)
  GET  /v1/models              — List models (OpenAI-compatible)
  GET  /api/ps                 — Running models (Ollama native)

Usage:
    python tests/mock_ollama.py                  # default port 11434
    python tests/mock_ollama.py --port 11435     # custom port
"""

import json
import time
import hashlib
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler

# ---------------------------------------------------------------------------
# Deterministic response routing
# ---------------------------------------------------------------------------

# Attack types that should produce high-risk verdicts
ATTACK_KEYWORDS = [
    "brute_force", "brute force", "credential_stuffing",
    "phishing", "spear_phishing",
    "ransomware", "encryption", "ransom",
    "exfiltration", "data_exfil", "dns_exfil",
    "privilege_escalation", "escalation", "uac_bypass",
    "c2", "command_and_control", "beacon",
    "lateral_movement", "lateral", "psexec", "wmi_abuse",
    "insider_threat", "insider",
    "malware", "trojan", "exploit",
    "kerberoast", "golden_ticket", "dcsync", "pass_the_hash",
    "sql_injection", "sqli", "xss", "cross_site",
    "webshell", "process_injection", "dll_sideload",
    "supply_chain", "typosquat",
    "cloud_attack", "iam_change",
    "network_beaconing", "dga",
    "lolbin", "powershell_obfusc", "office_macro",
    "rdp_tunnel", "persistence", "mimikatz", "cobalt",
]

# Benign types that should produce low-risk verdicts
BENIGN_KEYWORDS = [
    "password_change", "cert_renewal", "certificate",
    "windows_update", "update", "patch",
    "backup", "scheduled_backup",
    "health_check", "heartbeat", "monitoring",
    "log_rotation", "logrotate",
    "service_restart", "maintenance",
    "ntp_sync", "time_sync",
    "dhcp_lease", "dhcp",
    "dns_cache_flush", "dns_flush",
    "gpo_refresh", "group_policy",
    "av_update", "antivirus_update",
    "user_login", "successful_login",
    "firewall_rule_update", "acl_change",
    "benign", "routine", "normal",
]


def classify_prompt(text: str) -> str:
    """Classify prompt text as 'attack', 'benign', 'code_gen', or 'assess'.

    Returns a category string used to select the deterministic response.
    """
    lower = text.lower()

    # Detect pipeline stage from prompt content
    if "generate python" in lower or "write code" in lower or "investigation code" in lower:
        return "code_gen"
    if "verdict" in lower and ("ioc" in lower or "findings" in lower or "risk_score" in lower):
        # Stage 4 ASSESS prompt asks for verdict + IOCs
        if any(kw in lower for kw in BENIGN_KEYWORDS):
            return "assess_benign"
        return "assess_attack"
    if "extract" in lower and "entity" in lower:
        return "entity_extract"

    # Classify by alert content
    if any(kw in lower for kw in ATTACK_KEYWORDS):
        return "attack"
    if any(kw in lower for kw in BENIGN_KEYWORDS):
        return "benign"

    # Default to attack (safer for SOC — never miss a real threat)
    return "attack"


def get_response(messages: list) -> str:
    """Return a deterministic response string based on message content.

    Analyzes all messages (system + user) to determine the appropriate
    canned response. Responses are valid JSON matching the V2 pipeline's
    expected output schemas.
    """
    # Combine all message content for classification
    full_text = " ".join(
        m.get("content", "") for m in messages
        if isinstance(m.get("content"), str)
    )
    category = classify_prompt(full_text)

    if category == "code_gen":
        return _CODE_GEN_RESPONSE
    elif category == "assess_attack":
        return _ASSESS_ATTACK_RESPONSE
    elif category == "assess_benign":
        return _ASSESS_BENIGN_RESPONSE
    elif category == "entity_extract":
        return _ENTITY_EXTRACT_RESPONSE
    elif category == "benign":
        return _BENIGN_RESPONSE
    elif category == "attack":
        return _ATTACK_RESPONSE
    else:
        return _ATTACK_RESPONSE


# ---------------------------------------------------------------------------
# Canned responses — deterministic, no randomness
# ---------------------------------------------------------------------------

_ATTACK_RESPONSE = json.dumps({
    "verdict": "true_positive",
    "confidence": 0.92,
    "risk_score": 85,
    "summary": (
        "Analysis confirms malicious activity. Multiple indicators of compromise "
        "detected consistent with an active attack pattern. Evidence supports "
        "high-confidence classification as a true positive security incident."
    ),
    "findings": [
        {
            "type": "attack_detected",
            "severity": "high",
            "description": "Malicious activity confirmed with multiple IOCs",
            "evidence_refs": ["log_line_1", "log_line_2"],
            "mitre_technique": "T1110.001",
        }
    ],
    "iocs": [
        {"type": "ip", "value": "185.220.101.45", "confidence": 0.95, "evidence_refs": ["log_line_1"]},
        {"type": "ip", "value": "10.0.0.50", "confidence": 0.90, "evidence_refs": ["log_line_2"]},
        {"type": "user", "value": "root", "confidence": 0.99, "evidence_refs": ["log_line_1"]},
    ],
    "mitre_techniques": ["T1110.001"],
    "remediation": [
        "Block source IP at perimeter firewall",
        "Reset compromised credentials",
        "Enable enhanced monitoring on affected systems",
    ],
})

_BENIGN_RESPONSE = json.dumps({
    "verdict": "benign",
    "confidence": 0.95,
    "risk_score": 15,
    "summary": (
        "Analysis confirms routine operational activity. No indicators of "
        "compromise or unauthorized access detected. Activity is consistent "
        "with normal system operations and maintenance procedures."
    ),
    "findings": [],
    "iocs": [],
    "mitre_techniques": [],
    "remediation": [],
})

_CODE_GEN_RESPONSE = """import json

# Analyze the SIEM event data
siem_event = json.loads(siem_event_json)

# Extract key fields
source_ip = siem_event.get("source_ip", "unknown")
username = siem_event.get("username", "unknown")
rule_name = siem_event.get("rule_name", "unknown")
raw_log = siem_event.get("raw_log", "")

# Count indicators
failed_count = raw_log.lower().count("failed")
indicators = []
if source_ip != "unknown":
    indicators.append({"type": "ip", "value": source_ip, "evidence_refs": ["raw_log"]})
if username != "unknown":
    indicators.append({"type": "user", "value": username, "evidence_refs": ["raw_log"]})

# Determine risk
risk_score = min(100, max(10, failed_count * 15 + 25))
verdict = "true_positive" if risk_score >= 70 else ("suspicious" if risk_score >= 36 else "benign")

result = {
    "verdict": verdict,
    "risk_score": risk_score,
    "confidence": 0.85,
    "findings": [
        {
            "type": rule_name,
            "severity": "high" if risk_score >= 70 else "medium",
            "description": f"Detected {failed_count} suspicious events from {source_ip}",
            "evidence_refs": ["raw_log"],
        }
    ] if risk_score >= 36 else [],
    "iocs": indicators if risk_score >= 36 else [],
    "mitre_techniques": ["T1110.001"] if risk_score >= 70 else [],
    "remediation": [f"Investigate activity from {source_ip}"] if risk_score >= 36 else [],
}
print(json.dumps(result))
"""

_ASSESS_ATTACK_RESPONSE = json.dumps({
    "verdict": "true_positive",
    "risk_score": 85,
    "confidence": 0.92,
    "summary": (
        "Investigation confirms a security incident. Attack indicators match "
        "known threat patterns. IOCs extracted with evidence citations from "
        "source log data. MITRE ATT&CK techniques identified."
    ),
    "findings": [
        {
            "type": "confirmed_attack",
            "severity": "high",
            "description": "Attack pattern confirmed with corroborating evidence from log analysis",
            "evidence_refs": ["log_line_1", "log_line_2", "log_line_3"],
            "mitre_technique": "T1110.001",
        }
    ],
    "iocs": [
        {"type": "ip", "value": "185.220.101.45", "confidence": 0.95, "evidence_refs": ["log_line_1"]},
        {"type": "user", "value": "root", "confidence": 0.99, "evidence_refs": ["log_line_2"]},
        {"type": "service", "value": "sshd", "confidence": 0.90, "evidence_refs": ["log_line_3"]},
    ],
    "mitre_techniques": ["T1110.001", "T1078"],
    "remediation": [
        "Block attacker IP at network perimeter",
        "Force credential rotation for affected accounts",
        "Deploy enhanced logging on targeted service",
    ],
})

_ASSESS_BENIGN_RESPONSE = json.dumps({
    "verdict": "benign",
    "risk_score": 15,
    "confidence": 0.96,
    "summary": (
        "Investigation confirms routine system operation. No indicators of "
        "compromise detected. All observed activity is consistent with normal "
        "maintenance and operational procedures."
    ),
    "findings": [],
    "iocs": [],
    "mitre_techniques": [],
    "remediation": [],
})

_ENTITY_EXTRACT_RESPONSE = json.dumps({
    "entities": [
        {"type": "ip", "value": "185.220.101.45", "confidence": 0.95},
        {"type": "ip", "value": "10.0.0.50", "confidence": 0.90},
        {"type": "user", "value": "root", "confidence": 0.99},
        {"type": "hostname", "value": "srv-web-01", "confidence": 0.85},
    ],
    "relationships": [
        {"source": "185.220.101.45", "target": "root", "type": "attempted_access"},
    ],
})


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class MockOllamaHandler(BaseHTTPRequestHandler):
    """Handles Ollama API requests with deterministic responses."""

    def log_message(self, format, *args):
        """Prefix log lines with [MockOllama]."""
        print(f"[MockOllama] {args[0]}")

    def _send_json(self, status: int, body: dict):
        """Send a JSON HTTP response."""
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_body(self) -> dict:
        """Read and parse JSON request body."""
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    # --- GET endpoints ---

    def do_GET(self):
        """Route GET requests."""
        if self.path == "/api/tags":
            self._handle_api_tags()
        elif self.path == "/v1/models":
            self._handle_v1_models()
        elif self.path == "/api/ps":
            self._handle_api_ps()
        elif self.path in ("/", "/health"):
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"error": f"Not found: {self.path}"})

    # --- POST endpoints ---

    def do_POST(self):
        """Route POST requests."""
        body = self._read_body()

        if self.path == "/v1/chat/completions":
            self._handle_v1_chat_completions(body)
        elif self.path == "/api/generate":
            self._handle_api_generate(body)
        elif self.path == "/api/chat":
            self._handle_api_chat(body)
        else:
            self._send_json(404, {"error": f"Not found: {self.path}"})

    # --- Endpoint implementations ---

    def _handle_v1_chat_completions(self, body: dict):
        """OpenAI-compatible chat completions (primary endpoint for llm_gateway)."""
        messages = body.get("messages", [])
        model = body.get("model", "qwen2.5:14b")

        content = get_response(messages)

        # Deterministic token counts based on content length
        prompt_tokens = sum(len(m.get("content", "").split()) for m in messages)
        completion_tokens = len(content.split())

        response = {
            "id": f"chatcmpl-mock-{hashlib.md5(content[:64].encode()).hexdigest()[:12]}",
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
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        }
        self._send_json(200, response)

    def _handle_api_generate(self, body: dict):
        """Ollama native /api/generate (used by preload_ollama_model)."""
        model = body.get("model", "qwen2.5:14b")
        prompt = body.get("prompt", "")

        # For preload requests (prompt="ok"), return minimal response
        if prompt.strip().lower() in ("ok", "hello", "hi", "test", ""):
            content = "OK"
        else:
            # Use same classification logic
            messages = [{"role": "user", "content": prompt}]
            content = get_response(messages)

        response = {
            "model": model,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "response": content,
            "done": True,
            "done_reason": "stop",
            "context": [],
            "total_duration": 150000000,       # 150ms in nanoseconds
            "load_duration": 5000000,          # 5ms
            "prompt_eval_count": len(prompt.split()),
            "prompt_eval_duration": 50000000,  # 50ms
            "eval_count": len(content.split()),
            "eval_duration": 100000000,        # 100ms
        }
        self._send_json(200, response)

    def _handle_api_chat(self, body: dict):
        """Ollama native /api/chat."""
        model = body.get("model", "qwen2.5:14b")
        messages = body.get("messages", [])

        content = get_response(messages)

        prompt_tokens = sum(len(m.get("content", "").split()) for m in messages)
        completion_tokens = len(content.split())

        response = {
            "model": model,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "message": {
                "role": "assistant",
                "content": content,
            },
            "done": True,
            "done_reason": "stop",
            "total_duration": 150000000,
            "load_duration": 5000000,
            "prompt_eval_count": prompt_tokens,
            "prompt_eval_duration": 50000000,
            "eval_count": completion_tokens,
            "eval_duration": 100000000,
        }
        self._send_json(200, response)

    def _handle_api_tags(self):
        """Ollama native /api/tags — list locally available models."""
        self._send_json(200, {
            "models": [
                {
                    "name": "qwen2.5:14b",
                    "model": "qwen2.5:14b",
                    "modified_at": "2026-01-15T10:00:00.000Z",
                    "size": 9000000000,
                    "digest": "sha256:mock1234567890abcdef",
                    "details": {
                        "parent_model": "",
                        "format": "gguf",
                        "family": "qwen2",
                        "families": ["qwen2"],
                        "parameter_size": "14.8B",
                        "quantization_level": "Q4_K_M",
                    },
                },
                {
                    "name": "llama3.1:8b",
                    "model": "llama3.1:8b",
                    "modified_at": "2026-01-15T10:00:00.000Z",
                    "size": 4700000000,
                    "digest": "sha256:mockabcdef1234567890",
                    "details": {
                        "parent_model": "",
                        "format": "gguf",
                        "family": "llama",
                        "families": ["llama"],
                        "parameter_size": "8.0B",
                        "quantization_level": "Q4_K_M",
                    },
                },
                {
                    "name": "llama3.2:3b",
                    "model": "llama3.2:3b",
                    "modified_at": "2026-01-15T10:00:00.000Z",
                    "size": 2000000000,
                    "digest": "sha256:mock0987654321fedcba",
                    "details": {
                        "parent_model": "",
                        "format": "gguf",
                        "family": "llama",
                        "families": ["llama"],
                        "parameter_size": "3.2B",
                        "quantization_level": "Q4_K_M",
                    },
                },
            ]
        })

    def _handle_v1_models(self):
        """OpenAI-compatible /v1/models."""
        self._send_json(200, {
            "object": "list",
            "data": [
                {"id": "qwen2.5:14b", "object": "model", "created": 1700000000, "owned_by": "mock-ollama"},
                {"id": "llama3.1:8b", "object": "model", "created": 1700000000, "owned_by": "mock-ollama"},
                {"id": "llama3.2:3b", "object": "model", "created": 1700000000, "owned_by": "mock-ollama"},
            ],
        })

    def _handle_api_ps(self):
        """Ollama native /api/ps — list running models."""
        self._send_json(200, {
            "models": [
                {
                    "name": "qwen2.5:14b",
                    "model": "qwen2.5:14b",
                    "size": 9000000000,
                    "digest": "sha256:mock1234567890abcdef",
                    "details": {
                        "parent_model": "",
                        "format": "gguf",
                        "family": "qwen2",
                        "families": ["qwen2"],
                        "parameter_size": "14.8B",
                        "quantization_level": "Q4_K_M",
                    },
                    "expires_at": "2026-12-31T23:59:59.000Z",
                    "size_vram": 9000000000,
                },
            ]
        })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Zovark Mock Ollama Server (CI/CD)")
    parser.add_argument("--port", type=int, default=11434, help="Port to listen on (default: 11434)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), MockOllamaHandler)
    print(f"[MockOllama] Starting mock Ollama server on {args.host}:{args.port}")
    print(f"[MockOllama] Endpoints:")
    print(f"[MockOllama]   POST /v1/chat/completions  (OpenAI-compatible)")
    print(f"[MockOllama]   POST /api/generate          (Ollama native)")
    print(f"[MockOllama]   POST /api/chat              (Ollama native)")
    print(f"[MockOllama]   GET  /api/tags              (list models)")
    print(f"[MockOllama]   GET  /v1/models             (OpenAI-compatible)")
    print(f"[MockOllama]   GET  /api/ps                (running models)")
    print(f"[MockOllama] No GPU required. Deterministic responses only.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[MockOllama] Shutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
