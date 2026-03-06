"""SRE Diagnose — classifies failure root cause (deterministic + LLM fallback)."""

import os
import re
import time
import glob as glob_mod
from temporalio import activity

import httpx
from llm_logger import log_llm_call
from model_config import get_tier_config


def classify_error(error_message: str, stack_trace: str = '') -> dict:
    """Deterministic 4-category classifier."""
    combined = f"{error_message}\n{stack_trace}"

    # dependency_missing
    if 'ModuleNotFoundError' in combined or 'ImportError' in combined:
        module_match = re.search(r"No module named '([^']+)'", combined)
        module_name = module_match.group(1) if module_match else 'unknown'
        return {
            'category': 'dependency_missing',
            'root_cause': f'Missing module: {module_name}',
            'module_name': module_name,
            'auto_fixable': True,
        }

    # logic_bug
    logic_errors = ['TypeError', 'KeyError', 'AttributeError', 'IndexError', 'ValueError', 'NameError']
    for err_type in logic_errors:
        if err_type in combined:
            # Try to extract function and line
            func_match = re.search(r'in (\w+)\n', stack_trace)
            line_match = re.search(r'line (\d+)', stack_trace)
            func_name = func_match.group(1) if func_match else 'unknown'
            line_num = line_match.group(1) if line_match else 'unknown'
            return {
                'category': 'logic_bug',
                'root_cause': f'{err_type} in {func_name} at line {line_num}: {error_message[:200]}',
                'error_type': err_type,
                'function': func_name,
                'line': line_num,
                'auto_fixable': True,
            }

    # llm_malformed
    llm_markers = ['JSONDecodeError', 'json.decoder', 'yaml.scanner', "KeyError: 'choices'", 'Expecting value']
    for marker in llm_markers:
        if marker in combined:
            return {
                'category': 'llm_malformed',
                'root_cause': f'Malformed LLM output: {error_message[:200]}',
                'auto_fixable': True,
            }

    # resource_exhaustion
    resource_markers = ['OOMKilled', 'TimeoutError', 'ConnectionPool', 'MemoryError', 'ResourceExhausted', 'Too many connections']
    for marker in resource_markers:
        if marker in combined:
            return {
                'category': 'resource_exhaustion',
                'root_cause': f'Resource exhaustion: {error_message[:200]}',
                'auto_fixable': False,
            }

    return None


def read_activity_source(activity_name: str) -> dict:
    """Find the source file for an activity by scanning worker/*.py for @activity.defn."""
    worker_dir = '/app'
    search_dirs = [
        worker_dir,
        os.path.join(worker_dir, 'sre'),
        os.path.join(worker_dir, 'detection'),
        os.path.join(worker_dir, 'response'),
        os.path.join(worker_dir, 'finetuning'),
        os.path.join(worker_dir, 'intelligence'),
        os.path.join(worker_dir, 'reporting'),
        os.path.join(worker_dir, 'skills'),
        os.path.join(worker_dir, 'bootstrap'),
    ]

    for search_dir in search_dirs:
        for py_file in glob_mod.glob(os.path.join(search_dir, '*.py')):
            try:
                with open(py_file, 'r') as f:
                    content = f.read()
                    # Look for @activity.defn followed by the function name
                    pattern = rf'@activity\.defn\s+async\s+def\s+{re.escape(activity_name)}\s*\('
                    if re.search(pattern, content):
                        return {'file_path': py_file, 'content': content}
            except Exception:
                continue

    return {'file_path': None, 'content': None}


async def llm_diagnose(error_message: str, stack_trace: str, activity_name: str) -> dict:
    """LLM fallback diagnosis for unknown errors."""
    # Try to read source context
    source_info = read_activity_source(activity_name)
    source_context = ''
    if source_info['content']:
        # Truncate to 2000 chars
        source_context = source_info['content'][:2000]

    tier_config = get_tier_config('diagnose_failure')
    litellm_url = os.environ.get("LITELLM_URL", "http://litellm:4000/v1/chat/completions")
    api_key = os.environ.get("LITELLM_MASTER_KEY", "sk-hydra-dev-2026")

    system_prompt = (
        "You are an SRE agent diagnosing workflow failures. Classify the error into exactly one category: "
        "dependency_missing, logic_bug, llm_malformed, resource_exhaustion, or unknown. "
        "Respond with ONLY valid JSON: "
        '{"category": "...", "root_cause": "...", "auto_fixable": true/false, "suggested_fix": "..."}'
    )

    user_prompt = f"Error: {error_message}\n\nStack trace:\n{stack_trace[:1000]}"
    if source_context:
        user_prompt += f"\n\nSource code:\n{source_context}"

    start_time = time.time()
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                litellm_url,
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": tier_config["model"],
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": tier_config["temperature"],
                    "max_tokens": tier_config["max_tokens"],
                },
            )
            resp.raise_for_status()
            result = resp.json()

        latency_ms = int((time.time() - start_time) * 1000)
        usage = result.get("usage", {})
        log_llm_call(
            activity_name="diagnose_failure",
            model_tier=tier_config["tier"],
            model_id=tier_config["model"],
            prompt_name="sre_diagnosis",
            prompt_version=None,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            latency_ms=latency_ms,
            temperature=tier_config["temperature"],
            max_tokens=tier_config["max_tokens"],
        )

        import json
        content = result["choices"][0]["message"]["content"].strip()
        # Strip markdown fences if present
        if content.startswith("```"):
            content = re.sub(r'^```\w*\n?', '', content)
            content = re.sub(r'\n?```$', '', content)
        diagnosis = json.loads(content)
        return diagnosis

    except Exception as e:
        print(f"llm_diagnose failed: {e}")
        return {
            'category': 'unknown',
            'root_cause': error_message[:200],
            'auto_fixable': False,
            'suggested_fix': 'Manual investigation required',
        }


@activity.defn
async def diagnose_failure(data: dict) -> dict:
    """Diagnose a single failure — deterministic classification with LLM fallback."""
    error_message = data.get('error_message', '')
    stack_trace = data.get('stack_trace', '')
    activity_name = data.get('activity_name', '')

    # Try deterministic classification first
    result = classify_error(error_message, stack_trace)

    if result is None:
        # LLM fallback
        result = await llm_diagnose(error_message, stack_trace, activity_name)

    # Attach original failure info
    result['workflow_id'] = data.get('workflow_id', '')
    result['activity_name'] = activity_name
    result['error_message'] = error_message

    return result
