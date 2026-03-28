#!/bin/bash
# Convert merged HF model to GGUF Q4_K_M for llama.cpp inference
# Usage: bash scripts/convert_to_gguf.sh [merged_path]
#
# Step 1: HF safetensors → f16 GGUF (via llama.cpp convert_hf_to_gguf.py)
# Step 2: f16 GGUF → Q4_K_M GGUF (via llama-quantize)
set -e

MERGED_PATH="${1:-models/zovark-merged}"
F16_GGUF="models/zovark-dpo-f16.gguf"
GGUF_OUT="models/zovark-qwen2.5-14b-dpo-Q4_K_M.gguf"

# Find llama.cpp tools
LLAMA_CPP="${LLAMA_CPP_PATH:-/workspace/llama.cpp}"
QUANTIZE="${LLAMA_QUANTIZE:-llama-quantize}"

# Step 1: Convert HF → f16 GGUF
if [ ! -f "$F16_GGUF" ]; then
    if [ ! -f "$LLAMA_CPP/convert_hf_to_gguf.py" ]; then
        echo "llama.cpp not found at $LLAMA_CPP — cloning..."
        git clone --depth 1 https://github.com/ggerganov/llama.cpp "$LLAMA_CPP"
        pip install -e "$LLAMA_CPP/gguf-py/" -q
    fi

    echo "[1/2] Converting $MERGED_PATH → $F16_GGUF (f16)..."
    python "$LLAMA_CPP/convert_hf_to_gguf.py" "$MERGED_PATH" \
        --outfile "$F16_GGUF" \
        --outtype f16
    echo "      f16 GGUF created: $(ls -lh "$F16_GGUF" | awk '{print $5}')"
else
    echo "[1/2] f16 GGUF already exists, skipping conversion"
fi

# Step 2: Quantize f16 → Q4_K_M
echo "[2/2] Quantizing $F16_GGUF → $GGUF_OUT (Q4_K_M)..."
$QUANTIZE "$F16_GGUF" "$GGUF_OUT" Q4_K_M

echo ""
echo "Done: $GGUF_OUT"
ls -lh "$GGUF_OUT"
sha256sum "$GGUF_OUT" > "${GGUF_OUT}.sha256" 2>/dev/null || true
echo "Conversion complete."
