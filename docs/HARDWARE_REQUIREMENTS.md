# ZOVARK Hardware Requirements

**Version: v1.5.1 | Date: 2026-03-24**

## Deployment Tiers

### Developer / Demo (Current Default)
- **GPU:** NVIDIA RTX 3050 (4GB VRAM) or equivalent
- **RAM:** 16GB system
- **Model:** Qwen2.5-14B-Instruct-Q4_K_M via llama.cpp or Ollama on host (fast tier)
- **Capability:** Full investigation pipeline including triage, code generation, and verdict
- **Investigation quality:** Demo and development ready. 100% attack detection on Juice Shop benchmark.
- **Config:** `docker-compose.yml` + LLM on host (port 11434)

### Hybrid (Recommended for PoC)
- **GPU:** Any NVIDIA GPU (local triage) + cloud API keys (Groq/OpenRouter)
- **RAM:** 16GB system
- **Model:** Local 14B for triage, cloud 70B+ for investigation and reasoning
- **Capability:** Full investigation pipeline, production-quality output
- **Investigation quality:** Production-grade for standard and reasoning tiers
- **Config:** `docker-compose.yml` + `litellm_config.yaml` + API keys in `.env`
- **Cost:** ~$0.01-0.05 per investigation (varies by provider)

### Enterprise Edge (Full Sovereignty)
- **GPU:** 48GB+ VRAM — NVIDIA A6000, L40S, or dual RTX 4090
- **RAM:** 64GB system minimum, 128GB recommended
- **Storage:** 100GB SSD for model weights
- **Model:** Qwen2.5-7B (fast) + Qwen2.5-32B (standard/reasoning), all local
- **Capability:** Full investigation pipeline, zero cloud dependency
- **Investigation quality:** Production-grade, fully air-gapped
- **Config:** `docker-compose.yml` + `docker-compose.enterprise.yml` + `litellm_config_enterprise.yaml`
- **Cost:** Hardware only ($5k-15k one-time for GPU)

### Enterprise Server (Maximum Quality)
- **GPU:** NVIDIA A100 (80GB) or H100
- **RAM:** 128GB+ system
- **Model:** Qwen2.5-72B or Llama 3 70B (full precision or 8-bit)
- **Capability:** Maximum investigation quality, 128k context window
- **Investigation quality:** Matches or exceeds cloud API quality
- **Config:** Custom `litellm_config_a100.yaml` with 72B model
- **Note:** Requires custom vLLM config for tensor parallelism if using multi-GPU

## VRAM Budget

| Component | Developer | Enterprise Edge | Enterprise Server |
|-----------|-----------|----------------|-------------------|
| Fast model | ~4GB (14B Q4_K_M) | 4GB (7B AWQ) | 4GB (7B AWQ) |
| Standard model | — (cloud) | 18GB (32B AWQ) | 40GB (72B 8-bit) |
| Embedding model | 0.6GB | 0.6GB | 0.6GB |
| KV cache (32k ctx) | 0.5GB | 4GB | 8GB |
| KV cache (128k ctx) | — | — | 15GB |
| **Total VRAM** | **~5GB** | **~27GB** | **~68GB** |

## Context Window vs VRAM

The KV cache is the hidden VRAM cost. A single investigation may need to hold
proxy logs, firewall events, and AD auth events in context simultaneously.

| Context Length | KV Cache (32B model) | Use Case |
|---------------|---------------------|----------|
| 8k tokens | ~1GB | Simple alert triage |
| 32k tokens | ~4GB | Standard investigation with log context |
| 128k tokens | ~15GB | Deep investigation with 24h log window |

## Apple Silicon Alternative

For teams with Mac hardware:
- **Mac Studio M2/M3 Ultra (128GB unified memory):** Can run 70B models via Ollama
- Allocates ~90GB to LLM, leaving headroom for the rest of the stack
- Use `litellm_config.yaml` with Ollama backend instead of vLLM
- Air-gap capable without NVIDIA GPUs
- Limitation: Slower inference than A6000/A100 (~50% throughput)
