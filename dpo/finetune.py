"""
ZOVARC DPO Fine-Tuning — QLoRA on Qwen2.5-14B-Instruct

Trains a LoRA adapter using Direct Preference Optimization (DPO)
on the ZOVARC investigation dataset (45 pairs across 5 attack categories).

Hardware: Requires >= 16GB VRAM for comfortable training, 8GB minimum with QLoRA.
          RTX 3050 4GB is insufficient — use cloud GPU (RunPod A100 / Lambda A10).

Usage:
    pip install trl peft transformers bitsandbytes datasets -q
    python dpo/finetune.py 2>&1 | tee dpo/training_log.txt
"""

from datasets import Dataset
from trl import DPOTrainer, DPOConfig
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import LoraConfig
import torch, json, os

MODEL_ID = "Qwen/Qwen2.5-14B-Instruct"
OUTPUT_DIR = "models/zovarc-dpo-adapter"
# Support both local (dpo/) and RunPod (/workspace/) paths
DATASET_PATH = "training_dataset.jsonl" if os.path.exists("training_dataset.jsonl") else "dpo/training_dataset.jsonl"

# Load dataset
pairs = [json.loads(l) for l in open(DATASET_PATH)]
# Filter quality >= 4.0 (quality_score lives in metadata)
total = len(pairs)
pairs = [p for p in pairs if p.get('metadata', {}).get('quality_score', p.get('quality_score', 0)) >= 4.0]
print(f"Training on {len(pairs)} pairs (filtered from {total} total, quality >= 4.0)")

dataset = Dataset.from_list([{
    'prompt': p['prompt'],
    'chosen': p['chosen'],
    'rejected': p['rejected'],
} for p in pairs])

# QLoRA 4-bit config
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type='nf4',
    bnb_4bit_compute_dtype=torch.bfloat16,
)

tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, trust_remote_code=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    quantization_config=bnb_config,
    device_map='auto',
    trust_remote_code=True,
    torch_dtype=torch.bfloat16,
)

lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=['q_proj', 'v_proj', 'k_proj', 'o_proj'],
    lora_dropout=0.05,
    bias='none',
    task_type='CAUSAL_LM',
)

training_args = DPOConfig(
    output_dir=OUTPUT_DIR,
    num_train_epochs=3,
    per_device_train_batch_size=1,
    gradient_accumulation_steps=4,
    learning_rate=5e-5,
    bf16=True,
    gradient_checkpointing=True,
    logging_steps=1,
    save_steps=50,
    beta=0.1,
    max_length=2048,
    report_to="none",
)

# trl 0.29+: pass peft_config directly, use processing_class instead of tokenizer
trainer = DPOTrainer(
    model=model,
    args=training_args,
    train_dataset=dataset,
    processing_class=tokenizer,
    peft_config=lora_config,
)

trainer.train()
trainer.save_model(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)
print(f"\nAdapter saved to {OUTPUT_DIR}")
print(f"Next steps:")
print(f"  1. Merge adapter: python scripts/merge_adapter.py")
print(f"  2. Convert to GGUF: python llama.cpp/convert_hf_to_gguf.py")
print(f"  3. Benchmark: python scripts/accuracy_benchmark.py --model zovarc_aligned_14b")
