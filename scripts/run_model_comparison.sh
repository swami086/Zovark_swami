#!/bin/bash
# ============================================================
# HYDRA Model Comparison — Qwen2.5-14B vs Nemotron 4B
# Runs benchmark corpus against both models and generates report.
# ============================================================
set -euo pipefail

CORPUS="scripts/benchmark_corpus_11.json"
API_URL="${HYDRA_API_URL:-http://localhost:8090}"
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== HYDRA Model Comparison ==="
echo "Corpus: $CORPUS"
echo "API: $API_URL"
echo ""

# Phase 1: Benchmark with current model (Qwen2.5-14B)
echo "Phase 1: Qwen2.5-14B benchmark"
echo "Ensure llama-server is running with Qwen2.5-14B on port 11434."
read -p "Press Enter when ready..."

python "$SCRIPTS_DIR/model_benchmark.py" \
  --model-url http://localhost:11434/v1/chat/completions \
  --model-name qwen25-14b \
  --corpus "$CORPUS" \
  --api-url "$API_URL"

echo ""
echo "Phase 1 complete. Results saved to benchmark_results_qwen25-14b.json"
echo ""

# Phase 2: Switch to Nemotron 4B
echo "Phase 2: Nemotron 4B benchmark"
echo ""
echo "=== MANUAL STEP ==="
echo "1. Stop current llama-server"
echo "2. Start Nemotron 4B:"
echo "   C:\\Users\\vinay\\llama-cpp\\llama-server.exe -m C:/Users/vinay/models/nemotron-4b/Nemotron-3-Nano-4B-Q4_K_M.gguf -ngl 99 --port 11434"
echo "3. Wait for model to load"
echo ""
read -p "Press Enter when Nemotron 4B is ready..."

python "$SCRIPTS_DIR/model_benchmark.py" \
  --model-url http://localhost:11434/v1/chat/completions \
  --model-name nemotron-4b \
  --corpus "$CORPUS" \
  --api-url "$API_URL"

echo ""
echo "Phase 2 complete. Results saved to benchmark_results_nemotron-4b.json"
echo ""

# Phase 3: Generate comparison report
echo "Phase 3: Generating comparison report..."
python "$SCRIPTS_DIR/model_comparison_report.py"

echo ""
echo "=== COMPARISON COMPLETE ==="
echo "Report saved to docs/MODEL_COMPARISON.md"
