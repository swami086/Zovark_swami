# Hydra MVP — Full Setup Guide
## RTX 3050 (4GB VRAM) · Windows + Docker Desktop + WSL2 GPU Passthrough

---

## YOUR HARDWARE

| Component | Value |
|---|---|
| GPU | NVIDIA GeForce RTX 3050 Laptop, 4096 MiB VRAM |
| Driver | 555.99, CUDA 12.5 |
| Docker | Docker Desktop with WSL2 backend |
| GPU passthrough | ✅ Confirmed working |

## MODEL CHANGE FROM ORIGINAL PLAN

| | Original Plan | Your Setup |
|---|---|---|
| Chat model | Mistral-7B-AWQ (~4.5GB VRAM) | **Qwen2.5-1.5B-Instruct-AWQ (~0.9GB VRAM)** |
| Embed model | nomic-embed-text-v1.5 (~275MB) | nomic-embed-text-v1.5 (~275MB) — same |
| Total VRAM | ~16.8GB (60% of 24GB + 10% of 24GB) | ~2.2GB (see budget below) |
| GPU target | A100 40GB or RTX 4090 24GB | RTX 3050 4GB |

**VRAM Budget (4GB total):**
```
Qwen 1.5B AWQ weights:        ~0.9 GB
Nomic embed weights:           ~0.3 GB
KV cache (chat):               ~0.4 GB
KV cache (embed):              ~0.1 GB
CUDA/PyTorch overhead (×2):    ~0.8 GB
─────────────────────────────────────
Total estimated:               ~2.5 GB
Remaining headroom:            ~1.5 GB  ✓
```

**What you lose:** Qwen 1.5B is noticeably dumber than Mistral 7B — shorter
reasoning chains, worse at complex Python generation, more hallucination.
Good enough to test plumbing. Not good enough for customer demos.

**How to upgrade later:** Download bigger model → replace `local_models/chat-model/`
→ update `--quantization` flag if needed → `docker compose restart vllm-chat`. Done.
All code uses `model: "fast"` via LiteLLM. Nothing else changes.

---

## STEP 1: VERIFY YOUR SETUP

Open **PowerShell as Administrator** and confirm everything works:

```powershell
# Check Docker is running
docker version

# Check GPU passthrough works inside Docker
docker run --rm --gpus all nvidia/cuda:12.1.1-base-ubuntu22.04 nvidia-smi
# Should show your RTX 3050 — you already confirmed this ✓

# Check Docker Compose V2
docker compose version
# Expected: Docker Compose version v2.x.x
```

If any of these fail, fix Docker Desktop first. GPU passthrough requires:
Docker Desktop → Settings → Resources → WSL Integration → Enable for your distro.

---

## STEP 2: CREATE PROJECT STRUCTURE

```powershell
# Navigate to your project
cd C:\Users\vinay\Desktop\HYDRA\hydra-mvp

# Create directories (skip any that already exist)
New-Item -ItemType Directory -Force -Path temporal-config
New-Item -ItemType Directory -Force -Path sandbox
New-Item -ItemType Directory -Force -Path local_models\chat-model
New-Item -ItemType Directory -Force -Path local_models\embed-model
```

---

## STEP 3: PLACE ALL CONFIG FILES

You already downloaded these 7 files from Claude. Place them:

```
hydra-mvp\
├── docker-compose.yml          ← (we'll UPDATE this in Step 4)
├── litellm_config.yaml         ← place as-is (no changes needed)
├── init.sql                    ← place as-is (14 tables)
├── .env                        ← already created by you ✓
├── temporal-config\
│   └── development-sql.yaml    ← place as-is
└── sandbox\
    ├── seccomp_profile.json    ← place as-is (used in Week 3)
    ├── ast_prefilter.py        ← place as-is (used in Week 3)
    └── kill_timer.py           ← place as-is (used in Week 3)
```

---

## STEP 4: UPDATE docker-compose.yml FOR YOUR GPU

Open `docker-compose.yml` and make these 3 changes to the vllm services.
Everything else stays exactly the same.

**Change 1 — vllm-chat service:** Replace the entire `vllm-chat` block with:

```yaml
  vllm-chat:
    image: vllm/vllm-openai:v0.15.1
    container_name: hydra-vllm-chat
    ipc: host
    command: >
      /models/chat-model
      --served-model-name fast
      --quantization awq
      --dtype half
      --gpu-memory-utilization 0.40
      --max-model-len 2048
      --port 8000
      --disable-log-requests
    environment:
      - HF_HUB_OFFLINE=1
      - VLLM_NO_USAGE_STATS=1
      - TRANSFORMERS_OFFLINE=1
    volumes:
      - ./local_models:/models:ro
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              device_ids: ['0']
              capabilities: [gpu]
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:8000/v1/models"]
      interval: 30s
      timeout: 10s
      retries: 10
      start_period: 120s
    restart: unless-stopped
    networks:
      - hydra-internal
```

Changes from original:
- `--gpu-memory-utilization 0.60` → `0.40` (1.6GB instead of 14.4GB)
- `--max-model-len 4096` → `2048` (smaller KV cache, saves VRAM)

**Change 2 — vllm-embed service:** Replace the entire `vllm-embed` block with:

```yaml
  vllm-embed:
    image: vllm/vllm-openai:v0.15.1
    container_name: hydra-vllm-embed
    ipc: host
    command: >
      /models/embed-model
      --served-model-name embed
      --task embed
      --gpu-memory-utilization 0.15
      --max-model-len 2048
      --port 8001
      --disable-log-requests
    environment:
      - HF_HUB_OFFLINE=1
      - VLLM_NO_USAGE_STATS=1
      - TRANSFORMERS_OFFLINE=1
    volumes:
      - ./local_models:/models:ro
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              device_ids: ['0']
              capabilities: [gpu]
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:8001/v1/models"]
      interval: 30s
      timeout: 10s
      retries: 10
      start_period: 60s
    restart: unless-stopped
    networks:
      - hydra-internal
```

Changes from original:
- `--gpu-memory-utilization 0.10` → `0.15` (0.6GB — gives embed model more room)

**Change 3 — litellm_config.yaml:** Update `max_tokens` for the smaller context.
Open `litellm_config.yaml` and change:

```yaml
      max_tokens: 4096
```
to:
```yaml
      max_tokens: 2048
```

**That's it.** Everything else (postgres, redis, temporal, litellm, minio, jaeger)
is unchanged. The LiteLLM config routes `"fast"` → vllm-chat and `"embed"` →
vllm-embed regardless of what model is behind each one.

---

## STEP 5: DOWNLOAD MODEL WEIGHTS

This is the slow step. ~1.2GB total download.

```powershell
cd C:\Users\vinay\Desktop\HYDRA\hydra-mvp

# Install HuggingFace CLI (if not already installed)
pip install huggingface-hub

# Download chat model: Qwen2.5-1.5B-Instruct-AWQ (~0.9GB)
huggingface-cli download Qwen/Qwen2.5-1.5B-Instruct-AWQ --local-dir local_models\chat-model --local-dir-use-symlinks False

# Download embedding model: nomic-embed-text-v1.5 (~275MB)
huggingface-cli download nomic-ai/nomic-embed-text-v1.5 --local-dir local_models\embed-model --local-dir-use-symlinks False
```

**Verify downloads:**

```powershell
# Chat model — should have .safetensors file(s)
dir local_models\chat-model\*.safetensors
# Expected: model.safetensors (or model-00001-of-XXXXX.safetensors)

# Must also have config.json
dir local_models\chat-model\config.json
# Expected: config.json exists

# Embed model
dir local_models\embed-model\*.safetensors
# Expected: model.safetensors
```

**If download fails:** Run the same command again. It resumes automatically.

**If `Qwen/Qwen2.5-1.5B-Instruct-AWQ` doesn't exist on HuggingFace:**
Try the GPTQ variant instead:
```powershell
huggingface-cli download Qwen/Qwen2.5-1.5B-Instruct-GPTQ-Int4 --local-dir local_models\chat-model --local-dir-use-symlinks False
```
Then change `--quantization awq` to `--quantization gptq` in docker-compose.yml.

---

## STEP 6: PULL DOCKER IMAGES

```powershell
cd C:\Users\vinay\Desktop\HYDRA\hydra-mvp
docker compose pull
```

**What downloads (~15GB total, mostly the vLLM image):**

| Image | Size | What it is |
|---|---|---|
| `pgvector/pgvector:pg16` | ~400MB | Postgres 16 + pgvector |
| `redis:7-alpine` | ~30MB | Redis cache |
| `temporalio/auto-setup:1.24.2` | ~300MB | Temporal workflow engine |
| `temporalio/ui:2.26.2` | ~100MB | Temporal dashboard |
| `vllm/vllm-openai:v0.15.1` | ~12GB | vLLM + CUDA + PyTorch (LARGEST) |
| `docker.litellm.ai/berriai/litellm-database:main-stable` | ~500MB | LLM gateway |
| `minio/minio:latest` | ~200MB | Object storage |
| `jaegertracing/all-in-one:1.57` | ~60MB | Distributed tracing |

vLLM image pulls once even though two services use it (Docker deduplicates layers).

**This will take 10-30 minutes depending on your connection.**

Verify:
```powershell
docker compose images
# Should list all services with their images
```

---

## STEP 7: VERIFY DIRECTORY STRUCTURE

Before booting, confirm everything is in place:

```powershell
cd C:\Users\vinay\Desktop\HYDRA\hydra-mvp

# Check all files exist
dir docker-compose.yml
dir litellm_config.yaml
dir init.sql
dir .env
dir temporal-config\development-sql.yaml
dir sandbox\seccomp_profile.json
dir sandbox\ast_prefilter.py
dir sandbox\kill_timer.py

# Check model directories are NOT empty
dir local_models\chat-model\
dir local_models\embed-model\
```

**If any file is missing, go back to the relevant step.**
**If model directories are empty, go back to Step 5.**

---

## STEP 8: BOOT THE STACK

```powershell
cd C:\Users\vinay\Desktop\HYDRA\hydra-mvp
docker compose up -d
```

**Boot order (automatic via depends_on):**

```
1. postgres        → healthy in ~5s     (pg_isready check)
2. redis           → healthy in ~2s     (redis-cli ping)
3. minio           → healthy in ~5s     (curl health endpoint)
4. jaeger          → running in ~2s     (no healthcheck)
5. temporal        → healthy in ~30-60s (waits for postgres, creates DB)
6. temporal-ui     → running in ~5s     (waits for temporal)
7. vllm-chat       → healthy in ~60-90s (loads Qwen 1.5B onto GPU)
8. vllm-embed      → healthy in ~30-60s (loads nomic-embed onto GPU)
9. litellm         → healthy in ~10s    (waits for postgres + both vllm)
```

**Total time: ~2-3 minutes.** Bottleneck is vllm-chat loading the model.

**Watch the boot live:**

```powershell
# Follow all logs (Ctrl+C to stop watching — services keep running)
docker compose logs -f

# Or watch just vllm-chat (the critical one)
docker compose logs -f vllm-chat
```

**What to look for in vllm-chat logs:**

✅ Good: `INFO: Uvicorn running on http://0.0.0.0:8000`
❌ Bad: `FileNotFoundError: /models/chat-model does not exist`
   → Fix: model files not in local_models\chat-model\
❌ Bad: `torch.cuda.OutOfMemoryError: CUDA out of memory`
   → Fix: close all other GPU apps, reduce --gpu-memory-utilization to 0.30
❌ Bad: `ValueError: No model found` or quantization errors
   → Fix: model format doesn't match --quantization flag (see GPTQ note in Step 5)

**Check all services are up:**

```powershell
docker compose ps
```

Every service should show `healthy` or `running`. If any show `restarting`
or `unhealthy`, check logs:

```powershell
docker compose logs <service-name> --tail 50
```

---

## STEP 9: RUN VERIFICATION TESTS

### Test 1: PostgreSQL Schema (14 tables)

```powershell
docker exec hydra-postgres psql -U hydra -d hydra -c "\dt"
```

**Expected:** 14 tables listed:
```
agent_audit_log, agent_memory_episodic, agent_personas, agent_skills,
agent_skills_history, agent_tasks, document_chunks, documents,
event_triggers, notification_preferences, ragas_golden_dataset,
tenants, tool_registry, usage_metering, workflow_templates
```

(Plus the `v_tenant_usage_summary` view — run `\dv` to see it)

### Test 2: Chat Inference via LiteLLM

```powershell
curl -s http://localhost:4000/v1/chat/completions -H "Content-Type: application/json" -H "Authorization: Bearer sk-hydra-dev-2026" -d "{\"model\":\"fast\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hello in one sentence.\"}],\"max_tokens\":50}"
```

**Expected:** JSON response with `choices[0].message.content` containing text.

**What this proves:** Request → LiteLLM (:4000) → vllm-chat (internal :8000) →
Qwen 1.5B on GPU → response back through the chain. Full inference works.

If you get `connection refused`: LiteLLM isn't ready yet. Wait 2 minutes.
If you get `401`: check you're using `sk-hydra-dev-2026`.

### Test 3: Embedding (768 dimensions)

```powershell
curl -s http://localhost:4000/v1/embeddings -H "Content-Type: application/json" -H "Authorization: Bearer sk-hydra-dev-2026" -d "{\"model\":\"embed\",\"input\":\"test embedding\"}"
```

**Expected:** JSON with `data[0].embedding` array. Check the length — should be 768.

**What this proves:** LiteLLM → vllm-embed → nomic-embed-text → 768-dim vector.
This matches the `vector(768)` columns in init.sql for RAG.

### Test 4: Temporal UI

Open in your browser: **http://localhost:8080**

**Expected:** Temporal dashboard loads. No workflows yet (that's correct — we haven't
submitted any). If it loads, Temporal is working.

### Test 5: Concurrent Requests (5 parallel — conservative for 4GB GPU)

```powershell
# PowerShell parallel test (5 concurrent, not 10 — gentler on 4GB VRAM)
1..5 | ForEach-Object -Parallel {
    $i = $_
    $body = "{`"model`":`"fast`",`"messages`":[{`"role`":`"user`",`"content`":`"What is $i + $i?`"}],`"max_tokens`":20}"
    $response = Invoke-WebRequest -Uri "http://localhost:4000/v1/chat/completions" -Method POST -Headers @{"Content-Type"="application/json";"Authorization"="Bearer sk-hydra-dev-2026"} -Body $body -UseBasicParsing
    Write-Output "Request $i : HTTP $($response.StatusCode)"
} -ThrottleLimit 5
```

**Expected:** All 5 return HTTP 200. If PowerShell parallel doesn't work
(requires PS 7+), test sequentially — the important thing is they all succeed.

**Alternative sequential test (works in any PowerShell):**
```powershell
for ($i = 1; $i -le 5; $i++) {
    $body = "{`"model`":`"fast`",`"messages`":[{`"role`":`"user`",`"content`":`"What is $($i) + $($i)?`"}],`"max_tokens`":20}"
    $response = Invoke-WebRequest -Uri "http://localhost:4000/v1/chat/completions" -Method POST -Headers @{"Content-Type"="application/json";"Authorization"="Bearer sk-hydra-dev-2026"} -Body $body -UseBasicParsing
    Write-Output "Request $i : HTTP $($response.StatusCode)"
}
```

### Test 6: Check VRAM Usage

```powershell
nvidia-smi
```

**Expected:** GPU memory usage should show ~2-2.5 GB out of 4 GB.
If it's over 3.5 GB, you're cutting it close — consider reducing
`--gpu-memory-utilization` for vllm-embed to 0.10.

---

## STEP 10: VERIFY CROSS-CHECKS

Quick sanity checks that all the wiring is correct:

```powershell
# 1. LiteLLM can list models (proves it connected to both vLLM instances)
curl -s http://localhost:4000/v1/models -H "Authorization: Bearer sk-hydra-dev-2026"
# Should list "fast" and "embed"

# 2. Redis is running
docker exec hydra-redis redis-cli ping
# Expected: PONG

# 3. MinIO is running
curl -s http://localhost:9000/minio/health/live
# Expected: HTTP 200

# 4. Jaeger UI
# Open: http://localhost:16686
```

---

## COMMON FAILURES AND FIXES

| Symptom | Cause | Fix |
|---|---|---|
| vllm-chat keeps restarting | Model files missing or wrong format | Check `dir local_models\chat-model\` has .safetensors + config.json |
| `CUDA out of memory` | 4GB not enough with current settings | Reduce `--gpu-memory-utilization` to 0.30 for chat, 0.10 for embed |
| `CUDA out of memory` still | Both vLLM instances too much | Temporarily remove vllm-embed service, test chat-only first |
| LiteLLM `connection refused` | vLLM not ready yet | Wait 2-3 min. Check `docker compose logs vllm-chat` |
| LiteLLM `401 Unauthorized` | Wrong API key | Use `sk-hydra-dev-2026` from .env |
| Postgres init.sql errors | Schema syntax | `docker compose logs postgres`. If bad, `docker compose down -v` and retry |
| Temporal keeps restarting | Postgres not ready or wrong password | Check `docker compose logs temporal`. Password must match .env |
| `--quantization awq` error | Model uses different quant format | Try `--quantization gptq` or remove flag entirely for FP16 |
| `network not found` | Stale Docker state | `docker compose down` then `docker compose up -d` |
| Port already in use | Another app on 5432/4000/8080 | `netstat -ano | findstr :5432` to find it, kill the process |

**Nuclear option (clean restart):**
```powershell
docker compose down -v   # destroys all data volumes
docker compose up -d     # fresh start, init.sql runs again
```

---

## SHUTDOWN AND RESTART

```powershell
# Stop everything (data preserved in volumes)
docker compose down

# Start again (fast — images already pulled, models already loaded)
docker compose up -d

# Destroy everything including data
docker compose down -v
```

---

## WHAT'S NEXT

Once all 6 tests pass:

**Week 2:** Go API Gateway — `POST /v1/tasks` endpoint that authenticates
against the tenants table and starts a Temporal workflow.

**Week 3:** Python Worker — Temporal worker that calls LiteLLM for inference,
runs generated code in sandbox (seccomp + --network=none + kill timer).

**Week 4:** Wire end-to-end — Submit task → Temporal → Worker → vLLM → Sandbox → Result.

**When you get a bigger GPU (for demos):**
1. Download Mistral-7B-AWQ: `huggingface-cli download TheBloke/Mistral-7B-Instruct-v0.2-AWQ --local-dir local_models\chat-model --local-dir-use-symlinks False`
2. Update docker-compose.yml: `--gpu-memory-utilization 0.60` and `--max-model-len 4096`
3. Update litellm_config.yaml: `max_tokens: 4096`
4. `docker compose up -d --force-recreate vllm-chat`
5. Done. Everything else stays the same.
