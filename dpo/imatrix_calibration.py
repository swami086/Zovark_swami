#!/usr/bin/env python3
"""
Build importance-matrix calibration inputs from DPO / SFT prompts (Ticket 5).

Reads dpo/training_dataset.jsonl (or --dataset), extracts text prompts, writes:
  - artifacts/imatrix_prompts.txt  (one prompt snippet per line, truncated)
  - artifacts/imatrix_calibration.json  (metadata: counts, source paths)

For full GGUF imatrix, run llama.cpp llama-imatrix when available:
  llama-imatrix -m model.gguf -f artifacts/imatrix_prompts.txt -o artifacts/imatrix.dat

This script does not ship llama.cpp; it prepares the prompt corpus.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone

DEFAULT_DATASET = "dpo/training_dataset.jsonl"
MAX_LINE_CHARS = 2048
OUT_DIR = "artifacts"


def main() -> None:
    ap = argparse.ArgumentParser(description="Build imatrix calibration corpus from JSONL prompts.")
    ap.add_argument("--dataset", default=DEFAULT_DATASET, help="Path to training_dataset.jsonl")
    ap.add_argument("--out-dir", default=OUT_DIR, help="Output directory")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    prompts_path = os.path.join(args.out_dir, "imatrix_prompts.txt")
    meta_path = os.path.join(args.out_dir, "imatrix_calibration.json")

    if not os.path.isfile(args.dataset):
        print(f"Dataset not found: {args.dataset} — writing empty corpus.")
        open(prompts_path, "w", encoding="utf-8").close()
        meta = {
            "schema": "zovark.imatrix_calibration.v1",
            "source": args.dataset,
            "prompt_count": 0,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "note": "empty dataset — add training_dataset.jsonl rows",
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        return

    count = 0
    with open(args.dataset, encoding="utf-8") as fin, open(
        prompts_path, "w", encoding="utf-8"
    ) as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            prompt = row.get("prompt") or row.get("instruction") or ""
            if not isinstance(prompt, str):
                continue
            snippet = prompt.strip().replace("\n", " ")[:MAX_LINE_CHARS]
            if snippet:
                fout.write(snippet + "\n")
                count += 1

    meta = {
        "schema": "zovark.imatrix_calibration.v1",
        "source": os.path.abspath(args.dataset),
        "prompts_file": os.path.abspath(prompts_path),
        "prompt_count": count,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"Wrote {count} prompt lines → {prompts_path}")
    print(f"Metadata → {meta_path}")


if __name__ == "__main__":
    main()
