"""
Merge LoRA adapter into Qwen2.5-14B base model.
Runs on CPU — no GPU needed. Takes ~5-10 min on cloud, needs ~30GB RAM + 30GB disk.
Output: models/zovarc-merged/ (HuggingFace format, ~28GB)
"""
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
import os, time

BASE_MODEL = "Qwen/Qwen2.5-14B-Instruct"
ADAPTER_PATH = os.environ.get("ADAPTER_PATH", "models/zovarc-dpo-adapter")
MERGED_PATH = os.environ.get("MERGED_PATH", "models/zovarc-merged")

print(f"[1/4] Loading tokenizer from {BASE_MODEL}...")
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)

print(f"[2/4] Loading base model on CPU (this takes ~5-10 min)...")
t0 = time.time()
model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    torch_dtype=torch.float16,
    device_map="cpu",
    trust_remote_code=True,
    low_cpu_mem_usage=True,
)
print(f"      Base model loaded in {(time.time()-t0)/60:.1f} min")

print(f"[3/4] Loading and merging LoRA adapter from {ADAPTER_PATH}...")
t1 = time.time()
model = PeftModel.from_pretrained(model, ADAPTER_PATH)
model = model.merge_and_unload()
print(f"      Adapter merged in {(time.time()-t1)/60:.1f} min")

print(f"[4/4] Saving merged model to {MERGED_PATH}...")
os.makedirs(MERGED_PATH, exist_ok=True)
model.save_pretrained(
    MERGED_PATH,
    safe_serialization=True,
    max_shard_size="4GB",
)
tokenizer.save_pretrained(MERGED_PATH)

elapsed = (time.time() - t0) / 60
print(f"\nMerge complete in {elapsed:.1f} min. Output: {MERGED_PATH}")
import subprocess
result = subprocess.run(["du", "-sh", MERGED_PATH], capture_output=True, text=True)
print(f"Size: {result.stdout.strip()}")
