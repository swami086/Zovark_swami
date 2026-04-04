#!/usr/bin/env bash
# --------------------------------------------------------------------------- #
#  Zovark Model Provisioner                                                    #
#  Downloads GGUF models for the inference container based on GPU tier.        #
#                                                                              #
#  Usage:                                                                      #
#    ZOVARK_GPU_TIER=mid ./scripts/provision-models.sh                         #
#                                                                              #
#  Tiers:                                                                      #
#    dev              — Q4_K_S quants, ~2GB + ~1.5GB  (GTX 1060 / RTX 3050)   #
#    mid              — Q5_K_M quants, ~3GB + ~2GB    (RTX 3060 / 4060)       #
#    enterprise       — Q6_K quants,   ~4GB + ~2.5GB  (RTX 4090 / A4000)     #
#    enterprise-plus  — F16 full,      ~16GB + ~6GB   (A100 / H100)          #
#                                                                              #
#  NOTE: The HuggingFace URLs below are illustrative placeholders.             #
#  Verify actual filenames on the model repos before production use.           #
# --------------------------------------------------------------------------- #
set -euo pipefail

# ---- Configuration ------------------------------------------------------- #
TIER="${ZOVARK_GPU_TIER:-dev}"
MODEL_DIR="${ZOVARK_MODEL_DIR:-./models}"
GGUF_MAGIC="47475546"  # ASCII "GGUF" = 0x47475546

# HuggingFace base URLs (placeholders — verify before production use)
HF_LLAMA_8B="https://huggingface.co/bartowski/Meta-Llama-3.1-8B-Instruct-GGUF/resolve/main"
HF_LLAMA_3B="https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF/resolve/main"

# ---- Tier → file mapping ------------------------------------------------ #
declare -A CODE_MODEL FAST_MODEL
CODE_MODEL[dev]="Meta-Llama-3.1-8B-Instruct-Q4_K_S.gguf"
CODE_MODEL[mid]="Meta-Llama-3.1-8B-Instruct-Q5_K_M.gguf"
CODE_MODEL[enterprise]="Meta-Llama-3.1-8B-Instruct-Q6_K.gguf"
CODE_MODEL[enterprise-plus]="Meta-Llama-3.1-8B-Instruct-F16.gguf"

FAST_MODEL[dev]="Llama-3.2-3B-Instruct-Q4_K_S.gguf"
FAST_MODEL[mid]="Llama-3.2-3B-Instruct-Q5_K_M.gguf"
FAST_MODEL[enterprise]="Llama-3.2-3B-Instruct-Q6_K.gguf"
FAST_MODEL[enterprise-plus]="Llama-3.2-3B-Instruct-F16.gguf"

# ---- Validate tier ------------------------------------------------------- #
if [[ -z "${CODE_MODEL[$TIER]+x}" ]]; then
    echo "ERROR: Unknown GPU tier '$TIER'"
    echo "Valid tiers: dev, mid, enterprise, enterprise-plus"
    exit 1
fi

CODE_FILE="${CODE_MODEL[$TIER]}"
FAST_FILE="${FAST_MODEL[$TIER]}"

echo "========================================="
echo "  Zovark Model Provisioner"
echo "========================================="
echo "  Tier:       $TIER"
echo "  Code model: $CODE_FILE"
echo "  Fast model: $FAST_FILE"
echo "  Output dir: $MODEL_DIR"
echo "========================================="

# ---- Create output directory --------------------------------------------- #
mkdir -p "$MODEL_DIR"

# ---- Download function --------------------------------------------------- #
download_model() {
    local url="$1"
    local dest="$2"
    local label="$3"

    if [[ -f "$dest" ]]; then
        echo "[$label] Already exists: $dest (skipping download)"
        return 0
    fi

    echo "[$label] Downloading..."
    echo "  URL: $url"

    if command -v wget &>/dev/null; then
        wget --quiet --show-progress -O "${dest}.tmp" "$url"
    elif command -v curl &>/dev/null; then
        curl -fL --progress-bar -o "${dest}.tmp" "$url"
    else
        echo "ERROR: Neither wget nor curl found. Install one and retry."
        exit 1
    fi

    mv "${dest}.tmp" "$dest"
    echo "[$label] Download complete: $dest"
}

# ---- GGUF magic byte verification --------------------------------------- #
verify_gguf() {
    local file="$1"
    local label="$2"

    if [[ ! -f "$file" ]]; then
        echo "ERROR: [$label] File not found: $file"
        return 1
    fi

    # Read first 4 bytes as hex
    local magic
    magic=$(xxd -p -l 4 "$file" 2>/dev/null || od -A n -t x1 -N 4 "$file" | tr -d ' \n')

    if [[ "$magic" == "$GGUF_MAGIC" ]]; then
        echo "[$label] GGUF magic verified (0x$GGUF_MAGIC)"
        return 0
    else
        echo "ERROR: [$label] Invalid GGUF magic: 0x$magic (expected 0x$GGUF_MAGIC)"
        echo "  File may be corrupt or not a GGUF model. Delete and re-download."
        return 1
    fi
}

# ---- SHA-256 hash -------------------------------------------------------- #
compute_sha256() {
    local file="$1"
    if command -v sha256sum &>/dev/null; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        echo "ERROR: No sha256sum or shasum found"
        exit 1
    fi
}

# ---- Download both models ------------------------------------------------ #
download_model "${HF_LLAMA_8B}/${CODE_FILE}" "${MODEL_DIR}/${CODE_FILE}" "code-model"
download_model "${HF_LLAMA_3B}/${FAST_FILE}" "${MODEL_DIR}/${FAST_FILE}" "fast-model"

# ---- Verify GGUF headers ------------------------------------------------ #
echo ""
echo "Verifying GGUF format..."
VERIFY_OK=true
verify_gguf "${MODEL_DIR}/${CODE_FILE}" "code-model" || VERIFY_OK=false
verify_gguf "${MODEL_DIR}/${FAST_FILE}" "fast-model" || VERIFY_OK=false

if [[ "$VERIFY_OK" != "true" ]]; then
    echo ""
    echo "GGUF verification FAILED. See errors above."
    exit 1
fi

# ---- Generate manifest -------------------------------------------------- #
echo ""
echo "Computing SHA-256 hashes..."
CODE_HASH=$(compute_sha256 "${MODEL_DIR}/${CODE_FILE}")
FAST_HASH=$(compute_sha256 "${MODEL_DIR}/${FAST_FILE}")

MANIFEST="${MODEL_DIR}/manifest.json"
cat > "$MANIFEST" <<EOF
{
  "version": "3.2",
  "gpu_tier": "${TIER}",
  "provisioned_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "models": {
    "code": {
      "file": "${CODE_FILE}",
      "role": "code-generation and verdict assessment (ZOVARK_MODEL_CODE)",
      "sha256": "${CODE_HASH}"
    },
    "fast": {
      "file": "${FAST_FILE}",
      "role": "parameter extraction and tool selection (ZOVARK_MODEL_FAST)",
      "sha256": "${FAST_HASH}"
    }
  }
}
EOF

echo ""
echo "========================================="
echo "  Provisioning complete"
echo "========================================="
echo "  Manifest: $MANIFEST"
echo "  Code:     $CODE_FILE (sha256:${CODE_HASH:0:16}...)"
echo "  Fast:     $FAST_FILE (sha256:${FAST_HASH:0:16}...)"
echo "========================================="
echo ""
echo "To start inference:"
echo "  docker run --gpus all -v \$(pwd)/models:/models \\"
echo "    zovark-inference:latest \\"
echo "    --model /models/${CODE_FILE} \\"
echo "    --host 0.0.0.0 --port 8080 --n-gpu-layers 999"
