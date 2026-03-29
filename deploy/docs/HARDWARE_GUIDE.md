# Zovark Hardware & GPU Guide

## Model Tiers

Zovark uses local LLMs for investigation. Larger models produce better verdicts but require more GPU memory.

| Tier | Model Size | VRAM Required | Use Case | Investigation Time |
|------|-----------|---------------|----------|-------------------|
| Fast | 4B params (e.g., Qwen2.5-3B) | ~3 GB | Triage, classification, high-volume alert filtering | ~15s per investigation |
| Standard | 14B params (e.g., Qwen2.5-14B Q4) | ~10 GB | Full investigation with code generation and verdicts | ~50s per investigation |
| Enterprise | 70B+ params (e.g., Qwen2.5-72B Q4) | ~48 GB | Complex multi-stage analysis, low false-positive rate | ~120s per investigation |
| CPU-only | Any (14B recommended) | 0 GB | Air-gapped without GPU, dev/test environments | ~5-10 min per investigation |

## Recommended GPUs

### Consumer GPUs

| GPU | VRAM | Max Model Tier | Est. Investigation Time | Price (USD) |
|-----|------|---------------|------------------------|-------------|
| RTX 3050 | 4 GB | Fast (4B) | ~20s | $150 used |
| RTX 3060 | 12 GB | Standard (14B Q4) | ~60s | $250 used |
| RTX 3070 | 8 GB | Standard (14B Q4, tight) | ~55s | $300 used |
| RTX 3080 | 10 GB | Standard (14B Q4) | ~45s | $400 used |
| RTX 3090 | 24 GB | Standard (14B Q8) or Enterprise (70B Q2) | ~35s | $700 used |
| RTX 4060 Ti | 8/16 GB | Standard (14B Q4) | ~50s | $350-450 new |
| RTX 4070 Ti | 12 GB | Standard (14B Q4) | ~40s | $600 new |
| RTX 4080 | 16 GB | Standard (14B Q8) | ~30s | $900 new |
| RTX 4090 | 24 GB | Standard (14B Q8) or Enterprise (70B Q3) | ~20s | $1,600 new |

### Workstation / Data Center GPUs

| GPU | VRAM | Max Model Tier | Est. Investigation Time | Price (USD) |
|-----|------|---------------|------------------------|-------------|
| RTX A4000 | 16 GB | Standard (14B Q8) | ~35s | $800 used |
| RTX A5000 | 24 GB | Enterprise (70B Q3) | ~90s | $1,500 used |
| RTX A6000 | 48 GB | Enterprise (70B Q4) | ~60s | $3,000 used |
| A100 40 GB | 40 GB | Enterprise (70B Q4, tight) | ~40s | $5,000 used |
| A100 80 GB | 80 GB | Enterprise (70B Q6) | ~30s | $10,000 used |
| H100 80 GB | 80 GB | Enterprise (70B Q8) | ~15s | $25,000 new |

## Quantization and VRAM

Quantization reduces model size at the cost of some accuracy. Zovark uses GGUF format with llama.cpp.

| Quantization | Size Multiplier | Quality | Recommended For |
|-------------|----------------|---------|-----------------|
| Q2_K | ~0.3x | Low | Fitting large models in limited VRAM |
| Q3_K_M | ~0.4x | Fair | Budget setups |
| Q4_K_M | ~0.5x | Good | **Default recommendation** |
| Q5_K_M | ~0.6x | Very good | When VRAM allows |
| Q6_K | ~0.7x | Excellent | High-VRAM cards |
| Q8_0 | ~0.9x | Near-lossless | 24+ GB VRAM |
| F16 | 1.0x | Full | Data center only |

### VRAM Estimates by Model + Quantization

| Model | Q4_K_M | Q6_K | Q8_0 | F16 |
|-------|--------|------|------|-----|
| 3B | 2.5 GB | 3.2 GB | 4.0 GB | 6.5 GB |
| 7B | 4.5 GB | 6.0 GB | 8.0 GB | 14 GB |
| 14B | 9.0 GB | 12.0 GB | 15.0 GB | 28 GB |
| 32B | 20 GB | 26 GB | 34 GB | 64 GB |
| 70B | 40 GB | 52 GB | 70 GB | 140 GB |

## GPU Layer Offloading

llama.cpp supports partial GPU offloading. Load as many layers as VRAM allows; remaining layers run on CPU.

```bash
# Full GPU (all layers on GPU) — fastest
llama-server -m model.gguf --n-gpu-layers 99

# Partial GPU (e.g., 20 of 49 layers on 4GB GPU) — mixed speed
llama-server -m model.gguf --n-gpu-layers 20

# CPU-only (no GPU)
llama-server -m model.gguf --n-gpu-layers 0
```

For Qwen2.5-14B Q4_K_M (49 layers total):

| GPU VRAM | Recommended `--n-gpu-layers` | Speed vs Full GPU |
|----------|------------------------------|-------------------|
| 4 GB | 15-20 | ~3x slower |
| 8 GB | 35-40 | ~1.5x slower |
| 10-12 GB | 49 (all) | Full speed |
| 16+ GB | 49 (all) + large context | Full speed |

## System RAM Requirements

The host machine needs RAM for both Docker services and any CPU-offloaded model layers.

| Component | RAM Usage |
|-----------|----------|
| PostgreSQL | 2 GB |
| Redis | 256 MB |
| Temporal | 512 MB |
| API (Go) | 256 MB |
| Worker (Python) | 512 MB per worker |
| Dashboard | 128 MB |
| PgBouncer + Squid | 256 MB |
| LLM (CPU layers) | Varies by model |
| **Total (without LLM)** | **~4 GB** |

Add LLM memory if running CPU or partial offload:
- 14B Q4_K_M fully on CPU: +10 GB RAM
- 70B Q4_K_M fully on CPU: +42 GB RAM

## Recommended Configurations

### Minimum Viable (Lab/Dev)

- CPU: 4 cores
- RAM: 16 GB
- GPU: RTX 3060 12 GB (or CPU-only)
- Disk: 50 GB SSD
- Model: Qwen2.5-14B Q4_K_M
- Throughput: ~1 investigation/minute

### Production (Single Server)

- CPU: 8+ cores
- RAM: 32 GB
- GPU: RTX 4070 Ti 12 GB or RTX 3090 24 GB
- Disk: 200 GB NVMe SSD
- Model: Qwen2.5-14B Q4_K_M (all layers on GPU)
- Throughput: ~2 investigations/minute
- Workers: 2-3

### Enterprise (High Volume)

- CPU: 16+ cores
- RAM: 64 GB
- GPU: RTX A6000 48 GB or A100 80 GB
- Disk: 500 GB NVMe SSD
- Model: Qwen2.5-72B Q4_K_M
- Throughput: ~5 investigations/minute
- Workers: 5-10
- Kubernetes deployment recommended

## Multi-GPU

llama.cpp supports tensor splitting across multiple GPUs:

```bash
# Two GPUs, split 50/50
llama-server -m model.gguf --n-gpu-layers 99 --tensor-split 0.5,0.5

# Two GPUs, first has more VRAM
llama-server -m model.gguf --n-gpu-layers 99 --tensor-split 0.7,0.3
```

This enables running 70B models on two 24 GB GPUs (e.g., 2x RTX 3090).

## Disk Space

| Component | Size |
|-----------|------|
| Docker images (all services) | ~8 GB |
| PostgreSQL data (per 10k investigations) | ~2 GB |
| LLM model (14B Q4_K_M) | ~9 GB |
| LLM model (70B Q4_K_M) | ~40 GB |
| Logs and temporary files | ~5 GB |
| **Total (14B setup)** | **~25 GB** |

## Checking Your GPU

```bash
# Show GPU model and VRAM
nvidia-smi

# Show available VRAM
nvidia-smi --query-gpu=name,memory.total,memory.free --format=csv

# Verify Docker can see GPU
docker run --rm --gpus all nvidia/cuda:12.2.0-base-ubuntu22.04 nvidia-smi
```
