# HYDRA MVP

AI agent framework with code generation and sandboxed execution. Full-stack infrastructure for receiving tasks, generating Python code via local LLMs, and executing it securely.

## Tech Stack

| Layer            | Technology                              |
|------------------|-----------------------------------------|
| LLM Inference    | vLLM v0.15.1 (2 instances: chat + embed)|
| Chat Model       | Qwen2.5-1.5B-Instruct-AWQ (4-bit)      |
| Embedding Model  | nomic-embed-text-v1.5 (768-dim)         |
| LLM Gateway      | LiteLLM (unified API on port 4000)      |
| Database         | PostgreSQL 16 + pgvector                |
| Cache            | Redis 7-alpine (256MB, LRU)             |
| Workflow Engine  | Temporal 1.24.2                         |
| Object Storage   | MinIO (S3-compatible)                   |
| Observability    | Jaeger 1.57 (OTLP tracing)             |
| Sandbox          | Docker + seccomp + AST validation       |
| Orchestration    | Docker Compose V2                       |

## Project Structure

```
hydra-mvp/
├── docker-compose.yml          # 9-service stack (v1.1.1, RTX 3050 tuned)
├── .env                        # Dev credentials (POSTGRES_PASSWORD, LITELLM_MASTER_KEY, MINIO creds)
├── litellm_config.yaml         # LLM routing: "fast" -> vllm-chat, "embed" -> vllm-embed
├── litellm_config_rtx3050.yaml # RTX 3050 GPU variant config
├── download_models.py          # HuggingFace model download script
├── HYDRA_SETUP_RTX3050.md      # Comprehensive setup guide (537 lines)
├── local_models/
│   ├── chat-model/             # Qwen2.5-1.5B-Instruct-AWQ weights
│   └── embed-model/            # nomic-embed-text-v1.5 weights
├── sandbox/
│   ├── ast_prefilter.py        # Python AST security validator
│   ├── kill_timer.py           # 30-second execution timeout
│   └── seccomp_profile.json    # Syscall whitelist/blacklist
└── temporal-config/            # Workflow engine dynamic config
```

## Commands

```bash
# Start the full stack
docker compose up -d

# Stop
docker compose down

# Check service health
docker compose ps

# Test chat inference
curl http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer sk-hydra-dev-2026" \
  -H "Content-Type: application/json" \
  -d '{"model":"fast","messages":[{"role":"user","content":"Say hello"}],"max_tokens":50}'

# Test embeddings
curl http://localhost:4000/v1/embeddings \
  -H "Authorization: Bearer sk-hydra-dev-2026" \
  -H "Content-Type: application/json" \
  -d '{"model":"embed","input":"test embedding"}'

# Download models
pip install huggingface-hub
huggingface-cli download Qwen/Qwen2.5-1.5B-Instruct-AWQ --local-dir local_models/chat-model
huggingface-cli download nomic-ai/nomic-embed-text-v1.5 --local-dir local_models/embed-model
```

## Service Ports

| Service      | Port  | URL                          |
|--------------|-------|------------------------------|
| LiteLLM      | 4000  | http://localhost:4000        |
| PostgreSQL   | 5432  |                              |
| Redis        | 6379  |                              |
| Temporal     | 7233  |                              |
| Temporal UI  | 8080  | http://localhost:8080        |
| vLLM Chat    | 8000  | (internal only)              |
| vLLM Embed   | 8001  | (internal only)              |
| MinIO API    | 9000  |                              |
| MinIO Console| 9001  | http://localhost:9001        |
| Jaeger UI    | 16686 | http://localhost:16686       |

## Key Conventions

- **Model names**: Use `"fast"` for chat, `"embed"` for embeddings (routed via LiteLLM)
- **Container naming**: `hydra-{service}` (e.g., `hydra-postgres`, `hydra-vllm-chat`)
- **Network**: All services on `hydra-internal` bridge network
- **GPU budget**: 0.40 (chat) + 0.15 (embed) = ~2.2GB of 4GB VRAM (RTX 3050)
- **Auth**: LiteLLM API key is `sk-hydra-dev-2026`
- **Sandbox security layers**: AST prefilter -> seccomp profile -> Docker `--network=none` -> kill timer (30s)
- **Blocked in sandbox**: `eval`, `exec`, `subprocess`, `socket`, `ctypes`, `importlib`, `__import__`

## Architecture Notes

- Week 1 MVP: infrastructure and plumbing only
- Local inference (no cloud APIs) for privacy and cost control
- Qwen 1.5B chosen over Mistral 7B due to 4GB VRAM constraint
- Temporal provides durable, fault-tolerant workflow execution
- PostgreSQL includes pgvector extension for future RAG capabilities
- Multi-tenant design with usage metering in database schema

## Roadmap (Implied)

- Week 2: Go API Gateway with task submission endpoints
- Week 3: Python Worker with sandbox integration
- Week 4: End-to-end task -> inference -> sandbox -> result
- Weeks 5-6: RAG with pgvector, Prometheus/Grafana monitoring
- Later: Upgrade to Mistral-7B when GPU allows
