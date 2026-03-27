# ZOVARC Model Deployment Guide

## Model: Qwen2.5-14B-Instruct (Q4_K_M quantization)

ZOVARC uses a local LLM for security investigation code generation. The model runs on-premise via llama.cpp — no cloud API required.

## Hardware Requirements

| Tier | GPU | VRAM | RAM | GPU Layers | Speed | Investigation Time |
|------|-----|------|-----|------------|-------|-------------------|
| Minimum | RTX 3050 | 4 GB | 16 GB | 20/49 | 3.3 tok/s | ~12 min |
| Recommended | RTX 4060 Ti | 16 GB | 32 GB | 49/49 | ~15 tok/s | ~2 min |
| Optimal | A6000 | 48 GB | 64 GB | 49/49 | ~20 tok/s | ~1 min |
| CPU Only | None | 0 | 32 GB | 0 | ~1 tok/s | ~30 min |

## Installation

### 1. Download llama.cpp

Get pre-built binaries from [GitHub Releases](https://github.com/ggml-org/llama.cpp/releases):

```bash
# Windows (CUDA 12.4)
wget https://github.com/ggml-org/llama.cpp/releases/download/b8407/llama-b8407-bin-win-cuda-12.4-x64.zip
wget https://github.com/ggml-org/llama.cpp/releases/download/b8407/cudart-llama-bin-win-cuda-12.4-x64.zip
unzip llama-*.zip -d ~/llama-cpp/
unzip cudart-*.zip -d ~/llama-cpp/

# Linux
wget https://github.com/ggml-org/llama.cpp/releases/download/b8407/llama-b8407-bin-ubuntu-x64.tar.gz
tar xzf llama-*.tar.gz -C ~/llama-cpp/
```

### 2. Download the Model (~9 GB)

```bash
mkdir -p ~/models
curl -L -o ~/models/Qwen2.5-14B-Instruct-Q4_K_M.gguf \
  https://huggingface.co/bartowski/Qwen2.5-14B-Instruct-GGUF/resolve/main/Qwen2.5-14B-Instruct-Q4_K_M.gguf
```

### 3. Start the Server

```bash
bash scripts/start_llama_server.sh
```

The script auto-detects VRAM and sets optimal `--n-gpu-layers`. Override with:

```bash
LLAMA_GPU_LAYERS=49 bash scripts/start_llama_server.sh  # Force all layers on GPU
LLAMA_PORT=8080 bash scripts/start_llama_server.sh       # Custom port
```

### 4. Verify

```bash
curl http://localhost:11434/health
# {"status":"ok"}

curl http://localhost:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen2.5","messages":[{"role":"user","content":"Hello"}],"max_tokens":10}'
```

## How ZOVARC Uses the Model

### Path A (Template) — 11 known alert types
Skill templates with hand-coded Python. LLM only fills parameters.
- 100% execution rate, ~79% IOC extraction
- Fast (~30s with template rendering)

### Path B (LLM Generated) — novel/unknown alert types
LLM generates full investigation Python script from scratch.
- 80% execution rate, 89% IOC extraction (with qwen2.5:14b)
- Slower (~12 min on 4GB VRAM, ~2 min on 16GB)

### Worker Configuration

The ZOVARC worker connects to llama.cpp via environment variables in `docker-compose.yml`:

```yaml
LITELLM_URL: http://host.docker.internal:11434/v1/chat/completions
ZOVARC_LLM_MODEL: qwen2.5:14b
```

## Performance Benchmarks (Path B)

Tested with 5 novel alert types not covered by templates:

| Test | Execution | IOCs Found | Risk Score |
|------|-----------|-----------|------------|
| APT Multi-Stage Intrusion | completed | 4/4 (100%) | 85 |
| LOLBin Abuse (certutil) | exec_failed | - | - |
| Firmware Attack (ICS/PLC) | completed | 5/5 (100%) | 80 |
| SSH Brute Force | completed | 2/4 (50%) | 80 |
| Pass-the-Hash (NTLM) | completed | 5/5 (100%) | 90 |

## Troubleshooting

| Issue | Fix |
|-------|-----|
| OOM on GPU | Reduce `--n-gpu-layers` by 2-3 |
| Concurrent request 500s | Ensure `--parallel 1` (default in start script) |
| Slow inference | Upgrade GPU to 16GB+ VRAM for full offload |
| Model not found | Check `MODEL_PATH` env var in start script |
| Docker can't reach server | Ensure `host.docker.internal` is in `NO_PROXY` |
