# AI Model Attribution

Zovark uses locally-hosted AI models for investigation analysis.
All models run on-premise via Ollama. No data leaves the deployment.

## Models in Use

### Meta Llama 3.2 (3B)

- **Role**: Fast parameter extraction (Stage 2, Path B) and tool selection (v3)
- **Environment variable**: `ZOVARK_MODEL_FAST`
- **License**: Llama 3 Community License Agreement
- **License file**: `llama-COMMUNITY-LICENSE.txt`
- **Source**: https://github.com/meta-llama/llama-models
- **Copyright**: Copyright (c) Meta Platforms, Inc. and affiliates

### Meta Llama 3.1 (8B)

- **Role**: Code generation (Stage 2, Path C) and verdict assessment (Stage 4)
- **Environment variable**: `ZOVARK_MODEL_CODE`
- **License**: Llama 3 Community License Agreement
- **License file**: `llama-COMMUNITY-LICENSE.txt`
- **Source**: https://github.com/meta-llama/llama-models
- **Copyright**: Copyright (c) Meta Platforms, Inc. and affiliates

## Models NOT in Use

- No NVIDIA models (NIM, Nemotron, etc.) are currently used.
- Qwen/Alibaba models were removed in Sprint 2D due to provenance
  requirements from US defense and healthcare customers.

## Compliance Notes

- Both models are American-developed (Meta Platforms, Menlo Park, CA).
- Both are distributed under the Llama 3 Community License, which permits
  commercial use for products with fewer than 700 million monthly active
  users.
- Model weights are downloaded once and served locally. No telemetry,
  no external API calls, no data exfiltration.
