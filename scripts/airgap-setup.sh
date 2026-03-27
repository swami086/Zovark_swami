#!/usr/bin/env bash
# airgap-setup.sh — Pull models into local Ollama for air-gapped operation
set -euo pipefail

echo "=== ZOVARC Air-Gap Setup ==="
echo "Starting Ollama container..."
docker compose --profile airgap up -d ollama

echo ""
echo "Waiting for Ollama to be ready..."
for i in $(seq 1 30); do
  if docker compose exec ollama ollama list >/dev/null 2>&1; then
    echo "Ollama is ready."
    break
  fi
  sleep 2
done

echo ""
echo "Pulling qwen2.5:7b (chat model)..."
docker compose exec ollama ollama pull qwen2.5:7b

echo ""
echo "Pulling nomic-embed-text (embedding model)..."
docker compose exec ollama ollama pull nomic-embed-text

echo ""
echo "=== Models available ==="
docker compose exec ollama ollama list

echo ""
echo "Air-gap setup complete."
echo "To run in air-gap mode: docker compose --profile airgap up -d"
