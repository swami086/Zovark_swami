"""
Merge a LoRA adapter into a Hugging Face causal LM base (model-agnostic).

Usage:
  python dpo/merge_adapter.py --base-model meta-llama/Llama-3.2-3B-Instruct \\
      [--adapter-path models/zovark-dpo-adapter] [--merged-path models/zovark-merged]

Environment fallback when --base-model is omitted:
  ZOVARK_MERGE_BASE_MODEL
"""
from __future__ import annotations

import argparse
import os
import subprocess
import time

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer


def main() -> None:
    p = argparse.ArgumentParser(
        description="Merge LoRA adapter into a base causal LM (Ticket 5 — configurable base model)."
    )
    p.add_argument(
        "--base-model",
        default=os.environ.get("ZOVARK_MERGE_BASE_MODEL", "").strip() or None,
        help="Hugging Face model id for base weights (or set ZOVARK_MERGE_BASE_MODEL)",
    )
    p.add_argument(
        "--adapter-path",
        default=os.environ.get("ADAPTER_PATH", "models/zovark-dpo-adapter"),
        help="Path to PEFT adapter directory",
    )
    p.add_argument(
        "--merged-path",
        default=os.environ.get("MERGED_PATH", "models/zovark-merged"),
        help="Output directory for merged HF model",
    )
    args = p.parse_args()

    base_model = (args.base_model or "").strip()
    if not base_model:
        p.error(
            "missing base model: pass --base-model <hf_id> or set ZOVARK_MERGE_BASE_MODEL"
        )

    adapter_path = args.adapter_path
    merged_path = args.merged_path

    print(f"[1/4] Loading tokenizer from {base_model}...")
    tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)

    print("[2/4] Loading base model on CPU (this may take several minutes)...")
    t0 = time.time()
    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        torch_dtype=torch.float16,
        device_map="cpu",
        trust_remote_code=True,
        low_cpu_mem_usage=True,
    )
    print(f"      Base model loaded in {(time.time() - t0) / 60:.1f} min")

    print(f"[3/4] Loading and merging LoRA adapter from {adapter_path}...")
    t1 = time.time()
    model = PeftModel.from_pretrained(model, adapter_path)
    model = model.merge_and_unload()
    print(f"      Adapter merged in {(time.time() - t1) / 60:.1f} min")

    print(f"[4/4] Saving merged model to {merged_path}...")
    os.makedirs(merged_path, exist_ok=True)
    model.save_pretrained(merged_path, safe_serialization=True, max_shard_size="4GB")
    tokenizer.save_pretrained(merged_path)

    elapsed = (time.time() - t0) / 60
    print(f"\nMerge complete in {elapsed:.1f} min. Output: {merged_path}")
    result = subprocess.run(["du", "-sh", merged_path], capture_output=True, text=True)
    print(f"Size: {result.stdout.strip()}")


if __name__ == "__main__":
    main()
