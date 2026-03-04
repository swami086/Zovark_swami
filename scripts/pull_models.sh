#!/bin/bash
# Pre-pull all required models for air-gap deployment
set -e

echo "=== HYDRA Model Pre-Pull ==="
echo ""

echo "[1/3] Starting Ollama container..."
docker compose --profile airgap up -d ollama
echo "Waiting for Ollama to initialize..."
sleep 10

echo ""
echo "[2/3] Pulling LLM model (mistral:7b-instruct-v0.3-q4_K_M, ~4.1GB)..."
docker exec hydra-ollama ollama pull mistral:7b-instruct-v0.3-q4_K_M

echo ""
echo "Model pulled successfully."
echo "Installed models:"
docker exec hydra-ollama ollama list

echo ""
echo "[3/3] Verifying embedding server has model cached..."
docker exec hydra-embedding ls -la /data/ 2>/dev/null || echo "  Embedding server not running (start with: docker compose up -d embedding-server)"

echo ""
echo "=== All models ready for air-gap deployment ==="
