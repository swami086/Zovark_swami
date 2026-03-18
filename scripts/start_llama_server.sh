#!/usr/bin/env bash
# Start llama.cpp server for HYDRA inference
# Replaces Ollama — provides OpenAI-compatible /v1/chat/completions endpoint
#
# Prerequisites:
#   1. llama.cpp pre-built binaries in ~/llama-cpp/ (or LLAMA_DIR)
#   2. GGUF model in ~/models/ (or MODEL_PATH)
#   Download: https://huggingface.co/bartowski/Qwen2.5-14B-Instruct-GGUF
#
# GPU layer guide (qwen2.5-14b Q4_K_M, 49 total layers):
#   RTX 3050  4GB  → --n-gpu-layers 20  (~3.9 GB VRAM, 3.3 tok/s)
#   RTX 3060  8GB  → --n-gpu-layers 40  (~7.0 GB VRAM, ~8 tok/s)
#   RTX 4060 16GB  → --n-gpu-layers 49  (full GPU, ~15 tok/s)
#   A6000    48GB  → --n-gpu-layers 49  (full GPU, ~20 tok/s)

set -euo pipefail

# Configurable paths
LLAMA_DIR="${LLAMA_DIR:-$HOME/llama-cpp}"
MODEL_PATH="${MODEL_PATH:-$HOME/models/Qwen2.5-14B-Instruct-Q4_K_M.gguf}"
LOG_FILE="${LOG_FILE:-$HOME/llama-server.log}"
PID_FILE="${PID_FILE:-$HOME/llama-server.pid}"

# Server config
PORT="${LLAMA_PORT:-11434}"
HOST="${LLAMA_HOST:-0.0.0.0}"
CTX_SIZE="${LLAMA_CTX_SIZE:-4096}"
PARALLEL="${LLAMA_PARALLEL:-1}"
THREADS="${LLAMA_THREADS:-8}"

# Auto-detect GPU layers based on VRAM
detect_gpu_layers() {
    local vram_mib
    vram_mib=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1)
    if [ -z "$vram_mib" ]; then
        echo "0"  # CPU only
        return
    fi
    # Leave ~500 MiB for KV cache and overhead
    local available=$((vram_mib - 500))
    # Each layer is ~195 MiB for qwen2.5-14b Q4_K_M
    local layers=$((available / 195))
    # Cap at 49 (total layers in qwen2.5-14b)
    if [ "$layers" -gt 49 ]; then layers=49; fi
    echo "$layers"
}

GPU_LAYERS="${LLAMA_GPU_LAYERS:-$(detect_gpu_layers)}"

# Validate
if [ ! -f "$LLAMA_DIR/llama-server" ] && [ ! -f "$LLAMA_DIR/llama-server.exe" ]; then
    echo "ERROR: llama-server not found in $LLAMA_DIR"
    echo "Download from: https://github.com/ggml-org/llama.cpp/releases"
    exit 1
fi

if [ ! -f "$MODEL_PATH" ]; then
    echo "ERROR: Model not found at $MODEL_PATH"
    echo "Download: https://huggingface.co/bartowski/Qwen2.5-14B-Instruct-GGUF"
    exit 1
fi

# Kill existing server
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "Stopping existing llama-server (PID $OLD_PID)..."
        kill "$OLD_PID" 2>/dev/null || true
        sleep 2
    fi
fi

# Detect binary name
if [ -f "$LLAMA_DIR/llama-server.exe" ]; then
    SERVER="$LLAMA_DIR/llama-server.exe"
else
    SERVER="$LLAMA_DIR/llama-server"
fi

echo "Starting llama.cpp server..."
echo "  Model: $MODEL_PATH"
echo "  GPU layers: $GPU_LAYERS / 49"
echo "  Context: $CTX_SIZE tokens"
echo "  Parallel: $PARALLEL slots"
echo "  Port: $PORT"
echo "  Log: $LOG_FILE"

"$SERVER" \
    --model "$MODEL_PATH" \
    --n-gpu-layers "$GPU_LAYERS" \
    --ctx-size "$CTX_SIZE" \
    --parallel "$PARALLEL" \
    --port "$PORT" \
    --host "$HOST" \
    --threads "$THREADS" \
    > "$LOG_FILE" 2>&1 &

echo $! > "$PID_FILE"
echo "Server PID: $(cat "$PID_FILE")"

# Wait for health
echo "Waiting for model to load..."
for i in $(seq 1 60); do
    if curl -s "http://localhost:$PORT/health" 2>/dev/null | grep -q "ok"; then
        echo "Server ready! Health: OK"
        VRAM=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader 2>/dev/null | head -1)
        echo "VRAM used: $VRAM"
        exit 0
    fi
    sleep 2
done

echo "ERROR: Server failed to start within 120s"
echo "Check logs: $LOG_FILE"
exit 1
