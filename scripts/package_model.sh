#!/usr/bin/env bash
# Package HYDRA model artifacts for distribution
# Output: hydra-model-{VERSION}.tar.gz
#
# Contents:
#   - scripts/start_llama_server.sh
#   - model_manifest.json (checksums, version, benchmark results)
#   - docs/MODEL_DEPLOYMENT.md
#   - NOTE: GGUF model file NOT included (8.5GB, download separately)
#
# Usage:
#   bash scripts/package_model.sh

set -euo pipefail

VERSION=$(git describe --tags --always 2>/dev/null || echo "dev")
OUTPUT="hydra-model-${VERSION}.tar.gz"
TMPDIR=$(mktemp -d)

echo "Packaging HYDRA model artifacts v${VERSION}..."

# Create manifest
cat > "${TMPDIR}/model_manifest.json" << MANIFEST
{
  "version": "${VERSION}",
  "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "model": {
    "name": "qwen2.5-14b-instruct",
    "quantization": "Q4_K_M",
    "format": "GGUF",
    "size_bytes": 8988110976,
    "sha256": "download and verify with: sha256sum Qwen2.5-14B-Instruct-Q4_K_M.gguf",
    "download_url": "https://huggingface.co/bartowski/Qwen2.5-14B-Instruct-GGUF/resolve/main/Qwen2.5-14B-Instruct-Q4_K_M.gguf"
  },
  "inference_server": {
    "name": "llama.cpp",
    "version": "b8407+",
    "download_url": "https://github.com/ggml-org/llama.cpp/releases",
    "required_variant": "win-cuda-12.4-x64 or ubuntu equivalent"
  },
  "benchmarks": {
    "path_b_execution_rate": "80% (4/5)",
    "path_b_ioc_extraction": "89% on completed, 70% effective",
    "path_a_template_ioc_rate": "79%",
    "special_token_leaks": "0/5",
    "avg_inference_time_4gb_vram": "710s per investigation",
    "tested_hardware": "RTX 3050 4GB VRAM, 20/49 layers on GPU"
  },
  "hardware_requirements": {
    "minimum": {"vram_gb": 4, "ram_gb": 16, "gpu_layers": 20, "tok_per_sec": 3.3},
    "recommended": {"vram_gb": 16, "ram_gb": 32, "gpu_layers": 49, "tok_per_sec": 15},
    "optimal": {"vram_gb": 48, "ram_gb": 64, "gpu_layers": 49, "tok_per_sec": 20}
  }
}
MANIFEST

# Copy artifacts
cp scripts/start_llama_server.sh "${TMPDIR}/"
cp docs/MODEL_DEPLOYMENT.md "${TMPDIR}/" 2>/dev/null || echo "MODEL_DEPLOYMENT.md will be created"

# Create tarball (without the 8.5GB model file)
tar -czf "${OUTPUT}" -C "${TMPDIR}" .
rm -rf "${TMPDIR}"

echo "Package created: ${OUTPUT} ($(du -h "${OUTPUT}" | cut -f1))"
echo "NOTE: GGUF model file not included. Download separately:"
echo "  curl -L -o ~/models/Qwen2.5-14B-Instruct-Q4_K_M.gguf \\"
echo "    https://huggingface.co/bartowski/Qwen2.5-14B-Instruct-GGUF/resolve/main/Qwen2.5-14B-Instruct-Q4_K_M.gguf"
