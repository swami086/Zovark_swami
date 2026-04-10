#!/bin/bash
# Convert merged HF model to quantized GGUF for llama.cpp (Ticket 5 quantization pipeline).
# Usage:
#   bash scripts/convert_to_gguf.sh [merged_path] [f16_out.gguf] [quant_out.gguf] [Q4_K_M|Q8_0|...]
# Env: MERGED_PATH, F16_GGUF, GGUF_OUT, QUANT_TYPE,
#      ZOVARK_RUN_IMATRIX_PREP=1  — run dpo/imatrix_calibration.py first
#      ZOVARK_IMATRIX_FILE        — path to imatrix.dat for llama-quantize --imatrix
#      ZOVARK_SKIP_VERDICT_GATE=1 — skip post-quantization verdict gate
#      ZOVARK_GATE_BASELINE_MODEL / ZOVARK_GATE_CANDIDATE_MODEL — llama-server model ids
#
# Step 0 (optional): imatrix prompt corpus
# Step 1: HF safetensors → f16 GGUF
# Step 2: f16 → quantized (with optional --imatrix when imatrix.dat exists)
# Step 3: dpo/verdict_accuracy_gate.py (blocks delivery on failure)
set -e

MERGED_PATH="${1:-${MERGED_PATH:-models/zovark-merged}}"
F16_GGUF="${2:-${F16_GGUF:-models/zovark-dpo-f16.gguf}}"
GGUF_OUT="${3:-${GGUF_OUT:-models/zovark-dpo-Q4_K_M.gguf}}"
QUANT_TYPE="${4:-${QUANT_TYPE:-Q4_K_M}}"

LLAMA_CPP="${LLAMA_CPP_PATH:-/workspace/llama.cpp}"
QUANTIZE="${LLAMA_QUANTIZE:-llama-quantize}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ "${ZOVARK_RUN_IMATRIX_PREP:-}" = "1" ]; then
    echo "[0] Building imatrix prompt corpus (dpo/imatrix_calibration.py)..."
    python3 "$REPO_ROOT/dpo/imatrix_calibration.py" || true
fi

IMATRIX_FILE="${ZOVARK_IMATRIX_FILE:-$REPO_ROOT/artifacts/imatrix.dat}"
IMATRIX_ARGS=()
if [ -f "$IMATRIX_FILE" ]; then
    echo "[imatrix] Using $IMATRIX_FILE with llama-quantize"
    IMATRIX_ARGS=(--imatrix "$IMATRIX_FILE")
else
    echo "[imatrix] No imatrix file at $IMATRIX_FILE — generic quantization (generate with llama-imatrix + prompts)"
fi

if [ ! -f "$F16_GGUF" ]; then
    if [ ! -f "$LLAMA_CPP/convert_hf_to_gguf.py" ]; then
        echo "llama.cpp not found at $LLAMA_CPP — cloning..."
        git clone --depth 1 https://github.com/ggerganov/llama.cpp "$LLAMA_CPP"
        pip install -e "$LLAMA_CPP/gguf-py/" -q
    fi

    echo "[1/3] Converting $MERGED_PATH → $F16_GGUF (f16)..."
    python "$LLAMA_CPP/convert_hf_to_gguf.py" "$MERGED_PATH" \
        --outfile "$F16_GGUF" \
        --outtype f16
    echo "      f16 GGUF created: $(ls -lh "$F16_GGUF" | awk '{print $5}')"
else
    echo "[1/3] f16 GGUF already exists, skipping conversion"
fi

echo "[2/3] Quantizing $F16_GGUF → $GGUF_OUT ($QUANT_TYPE)..."
if [ ${#IMATRIX_ARGS[@]} -gt 0 ]; then
    $QUANTIZE "${IMATRIX_ARGS[@]}" "$F16_GGUF" "$GGUF_OUT" "$QUANT_TYPE"
else
    $QUANTIZE "$F16_GGUF" "$GGUF_OUT" "$QUANT_TYPE"
fi

echo ""
echo "Done: $GGUF_OUT"
ls -lh "$GGUF_OUT"
sha256sum "$GGUF_OUT" > "${GGUF_OUT}.sha256" 2>/dev/null || true

if [ "${ZOVARK_SKIP_VERDICT_GATE:-}" = "1" ]; then
    echo "[3/3] Verdict gate skipped (ZOVARK_SKIP_VERDICT_GATE=1)"
else
    echo "[3/3] Verdict accuracy gate (dpo/verdict_accuracy_gate.py)..."
    export ZOVARK_GATE_BASELINE_MODEL="${ZOVARK_GATE_BASELINE_MODEL:-fast}"
    export ZOVARK_GATE_CANDIDATE_MODEL="${ZOVARK_GATE_CANDIDATE_MODEL:-fast}"
    python3 "$REPO_ROOT/dpo/verdict_accuracy_gate.py" \
        --baseline-model "$ZOVARK_GATE_BASELINE_MODEL" \
        --candidate-model "$ZOVARK_GATE_CANDIDATE_MODEL"
fi

echo "Conversion complete."
