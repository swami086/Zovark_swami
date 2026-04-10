#!/usr/bin/env python3
"""
ZOVARK DPO Forge — generates preference pairs for DPO training.

Architecture:
  NVIDIA API (Kimi K2.5) generates alerts and investigation code.
  ZOVARK sandbox validates code execution.
  LLM-as-Judge scores output quality.
  AST mutation engine creates rejected pairs.
  Log compressor ensures training pairs fit token budget.

Usage:
  export NVIDIA_API_KEY=your_key_here
  python dpo/dpo_forge.py

  # Resume from checkpoint:
  python dpo/dpo_forge.py  # auto-resumes from dpo/progress.json

  # Limit pairs:
  python dpo/dpo_forge.py --max-pairs 100
"""

import os
import sys
import json
import time
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path

import httpx

from dpo.prompts import (
    FULL_SYSTEM, ALERT_GENERATION, FULL_INVESTIGATION,
    ERROR_CORRECTION, JUDGE, MUTATION, MUTATION_TYPES,
    COMPACT_SYSTEM, COMPACT_INVESTIGATION,
)
from dpo.log_compressor import build_training_pair
from dpo.validators import (
    AlertResponse, InvestigationResponse, JudgeResponse,
    MutationResponse, parse_kimi_json,
)

logger = logging.getLogger("dpo_forge")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")


# ─── LLM API Client with Retry ───────────────────────────────────

NVIDIA_API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
NVIDIA_MODEL = "moonshotai/kimi-k2.5"


def _dpo_forge_chat_url() -> str:
    """OpenAI-compatible chat completions URL (NVIDIA cloud or local llama-server)."""
    return os.environ.get("ZOVARK_DPO_FORGE_ENDPOINT", "").strip() or NVIDIA_API_URL


def call_kimi(
    client: httpx.Client,
    messages: list,
    temperature: float = 0.7,
    _max_attempts: int = 3,
) -> dict:
    """Call NVIDIA API (Kimi K2.5) with retry logic (3 attempts, exponential backoff).

    Only retries on transient errors (429, 502-504, connection, timeout).
    Auth errors (401, 403) raise immediately.

    Set ZOVARK_DPO_FORGE_ENDPOINT to a local URL (e.g. http://zovark-inference:8080/v1/chat/completions)
    for air-gapped / on-prem models.
    """
    url = _dpo_forge_chat_url()
    for attempt in range(1, _max_attempts + 1):
        try:
            response = client.post(
                url,
                json={
                    "model": NVIDIA_MODEL,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": 16384,
                },
                timeout=300.0,
            )
            # Auth errors — fail fast, don't retry
            if response.status_code in (401, 403):
                response.raise_for_status()
            # Transient errors — retry
            if response.status_code in (429, 502, 503, 504):
                response.raise_for_status()
            response.raise_for_status()
            return response.json()
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            if attempt == _max_attempts:
                raise
            wait = min(2 * (2 ** (attempt - 1)), 30)
            logger.warning(f"LLM API attempt {attempt} failed: {e}. Retrying in {wait}s...")
            time.sleep(wait)
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (429, 502, 503, 504) and attempt < _max_attempts:
                wait = min(2 * (2 ** (attempt - 1)), 30)
                logger.warning(f"LLM API attempt {attempt} failed ({e.response.status_code}). Retrying in {wait}s...")
                time.sleep(wait)
            else:
                raise


# ─── Dead Letter Queue ────────────────────────────────────────────


class DeadLetterQueue:
    """Quarantines failed API responses instead of crashing the main loop."""

    def __init__(self, path: str = "dpo/dead_letters.jsonl"):
        self.path = Path(path)
        self.count = 0

    def push(self, stage: str, seed_entry: dict, raw_response: str | None,
             error: str, attempt_number: int):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "seed": {
                "ttp_id": seed_entry.get("ttp_id"),
                "difficulty": seed_entry.get("difficulty"),
                "environment": seed_entry.get("environment"),
            },
            "attempt": attempt_number,
            "error": error,
            "raw_response_preview": (raw_response[:500] + "...") if raw_response and len(raw_response) > 500 else raw_response,
        }
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        self.count += 1

    def summary(self) -> str:
        return f"Dead letters: {self.count} (see {self.path})"


# ─── Progress Tracker ─────────────────────────────────────────────


class ProgressTracker:
    """Saves progress after every successful pair (per-pair checkpointing)."""

    def __init__(self, path: str = "dpo/progress.json"):
        self.path = Path(path)
        self.state = {
            "total_attempts": 0,
            "pairs_saved": 0,
            "path_a_count": 0,
            "path_b_count": 0,
            "path_c_discards": 0,
            "parse_failures": 0,
            "token_budget_skips": 0,
            "api_retries": 0,
            "last_seed_index": 0,
            "started_at": None,
            "last_save_at": None,
        }
        self._load()

    def _load(self):
        if self.path.exists():
            with open(self.path) as f:
                saved = json.load(f)
                self.state.update(saved)

    def save(self):
        self.state["last_save_at"] = datetime.now(timezone.utc).isoformat()
        total = max(self.state["total_attempts"], 1)
        self.state["discard_rate"] = f"{(1 - self.state['pairs_saved'] / total) * 100:.1f}%"
        if self.state["started_at"]:
            elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(self.state["started_at"])).total_seconds()
            self.state["elapsed_hours"] = round(elapsed / 3600, 2)
        with open(self.path, "w") as f:
            json.dump(self.state, f, indent=2)

    def increment(self, field: str, amount: int = 1):
        self.state[field] = self.state.get(field, 0) + amount
        self.save()


# ─── Sandbox Token Manager ───────────────────────────────────────


class SandboxAuth:
    """Auto-refreshes JWT token before it expires (10-min refresh interval)."""

    def __init__(self, sandbox_url: str, email: str, password: str):
        self.sandbox_url = sandbox_url
        self.email = email
        self.password = password
        self.token = ""
        self._last_login = 0.0
        self._refresh_interval = 600  # 10 minutes (JWT TTL is 15 min)

    def get_token(self) -> str:
        if time.time() - self._last_login > self._refresh_interval:
            self._login()
        return self.token

    def _login(self):
        resp = httpx.post(
            f"{self.sandbox_url}/api/v1/auth/login",
            json={"email": self.email, "password": self.password},
            timeout=10.0,
        )
        self.token = resp.json().get("token", "")
        self._last_login = time.time()
        logger.info("Sandbox token refreshed")


# ─── Pipeline Core ────────────────────────────────────────────────


def process_seed_entry(
    seed: dict,
    kimi_client: httpx.Client,
    sandbox_url: str,
    sandbox_auth: SandboxAuth,
    ground_truth: dict,
    dlq: DeadLetterQueue,
    attempt_number: int,
) -> dict | None:
    """Process a single seed entry. Returns training pair or None."""

    # Step 1: Generate Alert
    try:
        alert_raw = call_kimi(kimi_client, [
            {"role": "system", "content": FULL_SYSTEM},
            {"role": "user", "content": ALERT_GENERATION.format(**seed)},
        ])
        alert_text = alert_raw["choices"][0]["message"]["content"]
        alert_json = parse_kimi_json(alert_text)
        alert = AlertResponse(**alert_json)
        alert_dict = alert.model_dump()
    except Exception as e:
        dlq.push("alert_gen", seed, None, str(e), attempt_number)
        return None

    time.sleep(2)

    # Step 2: Generate Investigation
    try:
        inv_raw = call_kimi(kimi_client, [
            {"role": "system", "content": FULL_SYSTEM},
            {"role": "user", "content": FULL_INVESTIGATION.format(
                alert_json=json.dumps(alert_dict, indent=2)
            )},
        ])
        inv_text = inv_raw["choices"][0]["message"]["content"]
        inv_json = parse_kimi_json(inv_text)
        investigation = InvestigationResponse(**inv_json)
    except Exception as e:
        dlq.push("investigation", seed, None, str(e), attempt_number)
        return None

    time.sleep(2)

    # Step 3: Sandbox Execution
    try:
        sandbox_result = httpx.post(
            f"{sandbox_url}/api/v1/sandbox/execute",
            json={"code": investigation.python_code, "context": alert_dict},
            headers={"Authorization": f"Bearer {sandbox_auth.get_token()}"},
            timeout=45.0,
        )
        sandbox_data = sandbox_result.json()
        sandbox_passed = sandbox_data.get("status") == "success"
    except Exception as e:
        dlq.push("sandbox", seed, None, str(e), attempt_number)
        return None

    if sandbox_passed:
        return _path_b(seed, alert_dict, investigation, sandbox_data,
                       kimi_client, sandbox_url, sandbox_auth, ground_truth, dlq, attempt_number)
    else:
        return _path_a(seed, alert_dict, investigation, sandbox_data,
                       kimi_client, sandbox_url, sandbox_auth, ground_truth, dlq, attempt_number)


def _path_a(seed, alert_dict, investigation, sandbox_data,
            kimi_client, sandbox_url, sandbox_auth, ground_truth, dlq, attempt_number):
    """Code failed sandbox -> try error correction -> judge -> build pair."""
    try:
        fix_raw = call_kimi(kimi_client, [
            {"role": "system", "content": FULL_SYSTEM},
            {"role": "user", "content": ERROR_CORRECTION.format(
                alert_json=json.dumps(alert_dict),
                failed_code=investigation.python_code,
                error_traceback=sandbox_data.get("error", "Unknown error"),
            )},
        ])
        fix_text = fix_raw["choices"][0]["message"]["content"]
        fix_json = parse_kimi_json(fix_text)
        fixed = InvestigationResponse(**fix_json)
    except Exception as e:
        dlq.push("correction", seed, None, str(e), attempt_number)
        return None

    time.sleep(2)

    try:
        fix_result = httpx.post(
            f"{sandbox_url}/api/v1/sandbox/execute",
            json={"code": fixed.python_code, "context": alert_dict},
            headers={"Authorization": f"Bearer {sandbox_auth.get_token()}"},
            timeout=45.0,
        )
        fix_data = fix_result.json()
        if fix_data.get("status") != "success":
            dlq.push("correction_rerun", seed, json.dumps(fix_data), "Fixed code still fails", attempt_number)
            return None
    except Exception as e:
        dlq.push("correction_sandbox", seed, None, str(e), attempt_number)
        return None

    return _judge_and_build(
        seed, alert_dict, fix_data,
        chosen_reasoning=fixed.chain_of_thought,
        chosen_code=fixed.python_code,
        rejected_reasoning=investigation.chain_of_thought,
        rejected_code=investigation.python_code,
        kimi_client=kimi_client, ground_truth=ground_truth,
        dlq=dlq, attempt_number=attempt_number, path="A",
    )


def _path_b(seed, alert_dict, investigation, sandbox_data,
            kimi_client, sandbox_url, sandbox_auth, ground_truth, dlq, attempt_number):
    """Code passed sandbox -> judge -> mutate -> build pair."""
    ttp_id = seed["ttp_id"]
    ttp_name = seed["ttp_name"]
    gt = ground_truth.get(ttp_id, {})

    try:
        judge_raw = call_kimi(kimi_client, [
            {"role": "system", "content": FULL_SYSTEM},
            {"role": "user", "content": JUDGE.format(
                alert_json=json.dumps(alert_dict),
                ttp_id=ttp_id, ttp_name=ttp_name,
                ground_truth_indicators=json.dumps(gt, indent=2),
                sandbox_output=json.dumps(sandbox_data.get("output", {})),
            )},
        ])
        judge_text = judge_raw["choices"][0]["message"]["content"]
        judge = JudgeResponse(**parse_kimi_json(judge_text))
    except Exception as e:
        dlq.push("judge", seed, None, str(e), attempt_number)
        return None

    time.sleep(2)

    if not judge.is_correct:
        return None  # Path C — judge rejected

    mutation_type = MUTATION_TYPES[attempt_number % len(MUTATION_TYPES)]
    try:
        mut_raw = call_kimi(kimi_client, [
            {"role": "system", "content": FULL_SYSTEM},
            {"role": "user", "content": MUTATION.format(
                golden_code=investigation.python_code,
                mutation_type=mutation_type,
            )},
        ])
        mut_text = mut_raw["choices"][0]["message"]["content"]
        mutation = MutationResponse(**parse_kimi_json(mut_text))
    except Exception as e:
        dlq.push("mutation", seed, None, str(e), attempt_number)
        return None

    time.sleep(2)

    pair = build_training_pair(
        alert=alert_dict,
        chosen_reasoning=investigation.chain_of_thought,
        chosen_code=investigation.python_code,
        rejected_reasoning=mutation.mutation_description,
        rejected_code=mutation.mutated_code,
        compact_system=COMPACT_SYSTEM,
        compact_investigation=COMPACT_INVESTIGATION,
    )
    return pair


def _judge_and_build(seed, alert_dict, sandbox_data,
                     chosen_reasoning, chosen_code,
                     rejected_reasoning, rejected_code,
                     kimi_client, ground_truth, dlq, attempt_number, path):
    """Shared judge + build logic for Path A."""
    ttp_id = seed["ttp_id"]
    ttp_name = seed["ttp_name"]
    gt = ground_truth.get(ttp_id, {})

    try:
        judge_raw = call_kimi(kimi_client, [
            {"role": "system", "content": FULL_SYSTEM},
            {"role": "user", "content": JUDGE.format(
                alert_json=json.dumps(alert_dict),
                ttp_id=ttp_id, ttp_name=ttp_name,
                ground_truth_indicators=json.dumps(gt, indent=2),
                sandbox_output=json.dumps(sandbox_data.get("output", {})),
            )},
        ])
        judge_text = judge_raw["choices"][0]["message"]["content"]
        judge = JudgeResponse(**parse_kimi_json(judge_text))
    except Exception as e:
        dlq.push(f"judge_path_{path}", seed, None, str(e), attempt_number)
        return None

    time.sleep(2)

    if not judge.is_correct:
        return None

    pair = build_training_pair(
        alert=alert_dict,
        chosen_reasoning=chosen_reasoning,
        chosen_code=chosen_code,
        rejected_reasoning=rejected_reasoning,
        rejected_code=rejected_code,
        compact_system=COMPACT_SYSTEM,
        compact_investigation=COMPACT_INVESTIGATION,
    )
    return pair


# ─── Main Loop ────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="ZOVARK DPO Forge")
    parser.add_argument("--max-pairs", type=int, default=3000)
    parser.add_argument("--sandbox-url", default="http://localhost:8090")
    parser.add_argument("--dataset-file", default="zovark_dpo_dataset.jsonl")
    args = parser.parse_args()

    # Validate prerequisites
    api_key = os.environ.get("NVIDIA_API_KEY") or os.environ.get("KIMI_API_KEY")
    if not api_key:
        print("ERROR: NVIDIA_API_KEY not set")
        sys.exit(1)

    # Load seed database
    with open("dpo/seed_database.json") as f:
        seeds = json.load(f)
    logger.info(f"Loaded {len(seeds)} seed entries")

    # Load ground truth anchors — restructure from array to dict keyed by technique_id
    with open("docs/ground_truth_anchors.json") as f:
        gt_raw = json.load(f)
    ground_truth = {a["technique_id"]: a for a in gt_raw.get("anchors", [])}
    logger.info(f"Loaded {len(ground_truth)} ground truth anchors")

    # Preflight: check sandbox endpoint
    try:
        resp = httpx.get(f"{args.sandbox_url}/health", timeout=5.0)
        assert resp.status_code == 200
        logger.info("Sandbox API healthy")
    except Exception:
        logger.error(f"Cannot reach sandbox at {args.sandbox_url}/health")
        sys.exit(1)

    # Auth: auto-refreshing sandbox token (JWT TTL is 15 min, refresh every 10 min)
    sandbox_auth = SandboxAuth(
        sandbox_url=args.sandbox_url,
        email=os.environ.get("ZOVARK_TEST_EMAIL", "admin@test.local"),
        password=os.environ.get("ZOVARK_TEST_PASSWORD", "TestPass2026"),
    )
    try:
        sandbox_auth.get_token()
    except Exception as e:
        logger.error(f"Cannot login for sandbox token: {e}")
        sys.exit(1)

    # Initialize components
    progress = ProgressTracker()
    dlq = DeadLetterQueue()
    dataset_path = Path(args.dataset_file)

    if not progress.state["started_at"]:
        progress.state["started_at"] = datetime.now(timezone.utc).isoformat()

    start_index = progress.state["last_seed_index"]
    logger.info(f"Resuming from seed index {start_index}, {progress.state['pairs_saved']} pairs saved")

    # LLM API client (NVIDIA endpoint — Kimi K2.5 can take 2-3min per call)
    kimi_client = httpx.Client(
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=300.0,
    )

    try:
        # Cycle through seeds multiple times to reach target pairs
        seed_index = start_index
        consecutive_failures = 0
        max_consecutive_failures = 20  # Bail out if 20 seeds fail in a row

        while progress.state["pairs_saved"] < args.max_pairs:
            seed = seeds[seed_index % len(seeds)]
            attempt = progress.state["total_attempts"]

            logger.info(
                f"[{progress.state['pairs_saved']}/{args.max_pairs}] "
                f"Seed {seed_index}: {seed['ttp_id']} / {seed['environment']} / {seed['difficulty']}"
            )

            progress.increment("total_attempts")

            try:
                pair = process_seed_entry(
                    seed, kimi_client, args.sandbox_url, sandbox_auth,
                    ground_truth, dlq, attempt,
                )
            except Exception as e:
                logger.error(f"Unhandled error: {e}")
                dlq.push("unhandled", seed, None, str(e), attempt)
                pair = None

            if pair is not None:
                # Write pair to dataset
                with open(dataset_path, "a") as f:
                    f.write(json.dumps(pair) + "\n")
                progress.increment("pairs_saved")
                consecutive_failures = 0
                logger.info(f"  ✓ Pair saved ({progress.state['pairs_saved']})")
            else:
                progress.increment("path_c_discards")
                consecutive_failures += 1
                if consecutive_failures >= max_consecutive_failures:
                    logger.error(
                        f"Bailing out: {max_consecutive_failures} consecutive failures. "
                        f"Check API key, sandbox, or network connectivity."
                    )
                    break

            progress.state["last_seed_index"] = seed_index + 1
            progress.save()
            seed_index += 1

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        kimi_client.close()
        progress.save()
        logger.info(f"Final: {progress.state['pairs_saved']} pairs saved")
        logger.info(f"Discard rate: {progress.state.get('discard_rate', 'N/A')}")
        logger.info(dlq.summary())


if __name__ == "__main__":
    main()
