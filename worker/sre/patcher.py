"""SRE Patcher — generates category-specific patches for diagnosed failures."""

import os
import re
import time
from temporalio import activity

import psycopg2
from llm_logger import log_llm_call
from model_config import get_tier_config


def get_db_connection():
    db_url = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")
    return psycopg2.connect(db_url)


# Known safe pip packages for dependency_missing fixes
KNOWN_FIXES = {
    'yaml': 'pyyaml',
    'PIL': 'pillow',
    'cv2': 'opencv-python-headless',
    'sklearn': 'scikit-learn',
    'bs4': 'beautifulsoup4',
    'dateutil': 'python-dateutil',
    'dotenv': 'python-dotenv',
    'attr': 'attrs',
    'lxml': 'lxml',
    'magic': 'python-magic',
}

# Rate limit: max patches per hour
MAX_PATCHES_PER_HOUR = 5


def _check_rate_limit() -> bool:
    """Return True if under rate limit, False if exceeded."""
    try:
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) FROM self_healing_events
                    WHERE created_at > NOW() - INTERVAL '1 hour'
                    AND patch_type IS NOT NULL
                """)
                count = cur.fetchone()[0]
                return count < MAX_PATCHES_PER_HOUR
        finally:
            conn.close()
    except Exception:
        return True


def _patch_dependency_missing(diagnosis: dict) -> dict:
    """Generate a pip install patch for missing dependencies."""
    module_name = diagnosis.get('module_name', '')
    package = KNOWN_FIXES.get(module_name, module_name)

    if not package or not re.match(r'^[a-zA-Z0-9_-]+$', package):
        return {'type': 'no_patch', 'reason': f'Unknown or unsafe package: {module_name}'}

    return {
        'type': 'pip_install',
        'package': package,
        'module_name': module_name,
    }


async def _patch_logic_bug(diagnosis: dict) -> dict:
    """Use LLM to generate a minimal code fix for logic bugs."""
    from sre.diagnose import read_activity_source

    activity_name = diagnosis.get('activity_name', '')
    source_info = read_activity_source(activity_name)

    if not source_info['content'] or not source_info['file_path']:
        return {'type': 'no_patch', 'reason': f'Could not locate source for activity: {activity_name}'}

    from llm_client import llm_request, resolve_llm_api_key, chat_endpoint_for_model

    tier_config = get_tier_config('generate_patch')

    system_prompt = (
        "You are an SRE agent generating minimal Python code fixes. "
        "Given the source code and error diagnosis, output ONLY the complete fixed file content. "
        "Make the MINIMUM change needed to fix the bug. Do not add comments explaining the fix. "
        "Do not wrap in markdown code blocks. Output raw Python only."
    )

    user_prompt = (
        f"Error: {diagnosis.get('root_cause', '')}\n"
        f"Error type: {diagnosis.get('error_type', '')}\n"
        f"Function: {diagnosis.get('function', '')}\n"
        f"Line: {diagnosis.get('line', '')}\n\n"
        f"Source file ({source_info['file_path']}):\n{source_info['content']}"
    )

    start_time = time.time()
    try:
        m = tier_config["model"]
        result = await llm_request(
            m,
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=tier_config["temperature"],
            max_tokens=tier_config["max_tokens"],
            stage="generate_patch",
            role="verdict",
            endpoint_url=chat_endpoint_for_model(m),
            api_key=resolve_llm_api_key(None),
        )

        latency_ms = int((time.time() - start_time) * 1000)
        usage = result.get("usage", {})
        log_llm_call(
            activity_name="generate_patch",
            model_tier=tier_config["tier"],
            model_id=tier_config["model"],
            prompt_name="sre_patch_logic_bug",
            prompt_version=None,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            latency_ms=latency_ms,
            temperature=tier_config["temperature"],
            max_tokens=tier_config["max_tokens"],
        )

        patched_content = result["choices"][0]["message"]["content"].strip()
        # Strip markdown fences if present
        if patched_content.startswith("```"):
            patched_content = re.sub(r'^```\w*\n?', '', patched_content)
            patched_content = re.sub(r'\n?```$', '', patched_content)

        return {
            'type': 'code_patch',
            'file_path': source_info['file_path'],
            'original_content': source_info['content'],
            'patched_content': patched_content,
        }

    except Exception as e:
        return {'type': 'no_patch', 'reason': f'LLM patch generation failed: {e}'}


def _patch_llm_malformed(diagnosis: dict) -> dict:
    """Generate a JSON retry wrapper fix for malformed LLM output."""
    from sre.diagnose import read_activity_source

    activity_name = diagnosis.get('activity_name', '')
    source_info = read_activity_source(activity_name)

    if not source_info['content'] or not source_info['file_path']:
        return {'type': 'no_patch', 'reason': f'Could not locate source for activity: {activity_name}'}

    original = source_info['content']

    # Add a JSON sanitizer if not already present
    sanitizer = '''
def _sanitize_json_response(text):
    """Strip markdown fences and extract JSON from LLM output."""
    import re as _re
    text = text.strip()
    text = _re.sub(r'^```\\w*\\n?', '', text)
    text = _re.sub(r'\\n?```$', '', text)
    text = text.strip()
    return text
'''

    if '_sanitize_json_response' not in original:
        # Insert sanitizer after imports
        import_end = 0
        for i, line in enumerate(original.split('\n')):
            if line.startswith('import ') or line.startswith('from ') or line.startswith('with ') or line == '':
                import_end = i
            else:
                break
        lines = original.split('\n')
        patched_content = '\n'.join(lines[:import_end + 1]) + '\n' + sanitizer + '\n'.join(lines[import_end + 1:])
    else:
        patched_content = original

    return {
        'type': 'code_patch',
        'file_path': source_info['file_path'],
        'original_content': original,
        'patched_content': patched_content,
    }


@activity.defn
async def generate_patch(data: dict) -> dict:
    """Generate a patch based on the diagnosis category."""
    category = data.get('category', 'unknown')

    # Rate limit check
    if not _check_rate_limit():
        return {'type': 'no_patch', 'reason': f'Rate limit exceeded: max {MAX_PATCHES_PER_HOUR} patches/hour'}

    if category == 'dependency_missing':
        return _patch_dependency_missing(data)

    elif category == 'logic_bug':
        return await _patch_logic_bug(data)

    elif category == 'llm_malformed':
        return _patch_llm_malformed(data)

    elif category == 'resource_exhaustion':
        return {'type': 'no_patch', 'reason': 'Resource exhaustion requires infrastructure scaling, not code patches'}

    else:
        return {'type': 'no_patch', 'reason': f'Unknown error category: {category}'}
