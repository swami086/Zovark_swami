#!/bin/bash
# Download enterprise-grade models for HYDRA
# Requires: pip install huggingface-hub
# Disk space: ~40GB for 7B + 32B models

set -e

echo "=== HYDRA Enterprise Model Setup ==="
echo ""
echo "This will download ~40GB of model weights."
echo "Ensure you have sufficient disk space and a fast connection."
echo ""

# Fast tier: Qwen 7B (AWQ quantized, ~4GB)
echo "[1/3] Downloading Qwen2.5-7B-Instruct-AWQ (~4GB)..."
huggingface-cli download Qwen/Qwen2.5-7B-Instruct-AWQ \
  --local-dir local_models/chat-model-7b \
  --local-dir-use-symlinks False

# Standard/Reasoning tier: Qwen 32B (AWQ quantized, ~18GB)
echo "[2/3] Downloading Qwen2.5-32B-Instruct-AWQ (~18GB)..."
huggingface-cli download Qwen/Qwen2.5-32B-Instruct-AWQ \
  --local-dir local_models/chat-model-32b \
  --local-dir-use-symlinks False

# Embedding model (same as before)
echo "[3/3] Verifying nomic-embed-text-v1.5..."
if [ ! -d "local_models/embed-model" ]; then
  huggingface-cli download nomic-ai/nomic-embed-text-v1.5 \
    --local-dir local_models/embed-model \
    --local-dir-use-symlinks False
else
  echo "  Already present, skipping."
fi

echo ""
echo "=== Download complete ==="
echo ""
echo "VRAM requirements:"
echo "  Fast (7B AWQ):      ~4GB"
echo "  Standard (32B AWQ): ~18GB"
echo "  Embed:              ~0.6GB"
echo "  Total:              ~23GB minimum"
echo ""
echo "Recommended hardware:"
echo "  NVIDIA A6000 (48GB) — runs all tiers with headroom"
echo "  NVIDIA L40S (48GB)  — same"
echo "  Dual RTX 4090 (48GB combined) — requires tensor parallelism"
echo "  Apple M2/M3 Ultra (128GB unified) — via Ollama, not vLLM"
echo ""
echo "To start:"
echo "  docker compose -f docker-compose.yml -f docker-compose.enterprise.yml up -d"
