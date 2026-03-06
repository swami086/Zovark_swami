import os
import json
import time
import httpx
import psycopg2
from psycopg2.extras import RealDictCursor
from temporalio import activity
import subprocess
import sys
import re

from llm_logger import log_llm_call
from prompt_registry import get_version
from model_config import get_tier_config

# Add the /app level to path so we can import sandbox.ast_prefilter
sys.path.append("/app")
from sandbox.ast_prefilter import is_safe_python_code

def _get_worker_id():
    """Get worker_id from main module (lazy import to avoid circular)."""
    try:
        from main import WORKER_ID
        return WORKER_ID
    except Exception:
        return None

def get_db_connection():
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    return psycopg2.connect(db_url)

def _sync_commit(cur):
    """Enable synchronous commit for this transaction (critical writes)."""
    cur.execute("SET LOCAL synchronous_commit = on")

@activity.defn
async def fetch_task(task_id: str) -> dict:
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, tenant_id, task_type, input, status FROM agent_tasks WHERE id = %s", (task_id,))
            row = cur.fetchone()
            if not row:
                raise ValueError("Task not found")
            
            row['id'] = str(row['id'])
            row['tenant_id'] = str(row['tenant_id'])
            return dict(row)
    finally:
        conn.close()

@activity.defn
async def generate_code(task_data: dict) -> dict:
    litellm_url = os.environ.get("LITELLM_URL", "http://litellm:4000/v1/chat/completions")
    api_key = os.environ.get("LITELLM_MASTER_KEY", "sk-hydra-dev-2026")
    
    prompt = task_data.get("input", {}).get("prompt", "")
    task_type = task_data.get("task_type", "Log Analysis")
    log_data = task_data.get("input", {}).get("log_data", "")
    filename = task_data.get("input", {}).get("filename", "")
    
    # If this is a file upload investigation, use a different system prompt
    if log_data:
        base_system_prompt = (
            "You are a senior security analyst. Generate a self-contained Python script that analyzes the REAL log data provided below. "
            "The script MUST embed the provided log data in a multi-line string variable and analyze it directly. "
            "Do NOT use mock data — the real data is provided. Use ONLY the Python standard library. "
            "Do NOT use input(), subprocess, socket, requests, or any network calls. Print results as valid JSON to stdout. "
            "CRITICAL: The script runs in a read-only sandbox. Write files ONLY to /tmp/. "
            "REQUIRED JSON OUTPUT STRUCTURE: Your script MUST print perfectly valid JSON to stdout containing exactly these EXACT top-level keys: "
            "`findings` (array of objects with title and details), "
            "`statistics` (object with counts and metrics), "
            "`recommendations` (array of strings), "
            "`risk_score` (integer 0-100), "
            "`follow_up_needed` (boolean, true only if deeper analysis would be genuinely valuable), "
            "and `follow_up_prompt` (string describing what the next investigation step should do, or empty string if not needed). "
            "Examples of when follow_up is needed: log analysis finds suspicious IPs -> follow up with threat intel; "
            "code audit finds vulns -> follow up with remediation script; IOC scan finds matches -> follow up with timeline reconstruction."
        )
    else:
        base_system_prompt = (
            "You are a senior security analyst. Generate a self-contained Python script. "
            "The script MUST include realistic mock/sample data inline so it produces meaningful output "
            "when executed in an isolated sandbox with no network access. Use ONLY the Python standard library. "
            "Do NOT use input(), subprocess, socket, requests, or any network calls. Print results as valid JSON to stdout. "
            "CRITICAL RESTRICTIONS: 1. You are in a read-only container. Write files ONLY to /tmp/. 2. Do NOT try to read non-existent system logs like 'auth.log'. Hardcode mock logs inline. 3. STRICTLY FORBIDDEN: 'import requests'. Use 'urllib.request' instead. 4. STRICTLY FORBIDDEN: 'input()'. It will crash the non-interactive sandbox. "
            "REQUIRED JSON OUTPUT STRUCTURE: Your script MUST print perfectly valid JSON to stdout containing exactly these EXACT top-level keys: "
            "`findings` (array of objects with title and details), "
            "`statistics` (object with counts and metrics), "
            "`recommendations` (array of strings), "
            "`risk_score` (integer 0-100), "
            "`follow_up_needed` (boolean, true only if deeper analysis would be genuinely valuable), "
            "and `follow_up_prompt` (string describing what the next investigation step should do, or empty string if not needed). "
            "Examples of when follow_up is needed: log analysis finds suspicious IPs -> follow up with threat intel; "
            "code audit finds vulns -> follow up with remediation script; IOC scan finds matches -> follow up with timeline reconstruction."
        )
    
    type_specific_prompts = {
        "Log Analysis": " Focus on parsing common log formats. Mock the log data inline instead of reading from disk.",
        "Threat Hunt": " Focus on processing hardcoded IP lists against mock threat intelligence feeds. DO NOT import requests.",
        "Incident Response": " Focus on identifying timelines of breaches. DO NOT read local files like 'auth.log', mock the logs inline!",
        "Code Audit": " Focus on static analysis. DO NOT write the mock code to disk, analyze it from a multi-line string variable inline.",
        "IOC Scan": " Focus on scanning a mock filesystem or process list. Mock everything inline. Do NOT use input(). If you must write a report, write it to /tmp/",
    }
    
    # Also support lowercase snake_case variants just in case
    for key in list(type_specific_prompts.keys()):
        type_specific_prompts[key.lower().replace(" ", "_")] = type_specific_prompts[key]
        
    system_prompt = base_system_prompt + type_specific_prompts.get(task_type, type_specific_prompts.get("Log Analysis"))
    
    playbook_system_prompt_override = task_data.get("input", {}).get("playbook_system_prompt_override")
    if playbook_system_prompt_override:
        system_prompt += f"\n\nPLAYBOOK OVERRIDE INSTRUCTIONS:\n{playbook_system_prompt_override}"

    # Build the user message
    siem_event = task_data.get("input", {}).get("siem_event")
    
    if log_data:
        # Truncate log data if extremely large (safety net)
        if len(log_data) > 50000:
            log_data = log_data[:50000] + "\n... [truncated]"
        augmented_prompt = f"Here is the log data from file '{filename}' to analyze:\n\n{log_data}\n\nTask: {prompt}\n\nIMPORTANT: Embed this EXACT log data in your script as a multi-line string variable named LOG_DATA. Analyze it directly."
    elif siem_event:
        siem_context = json.dumps(siem_event, indent=2)
        augmented_prompt = (
            f"SIEM ALERT DATA:\n{siem_context}\n\n"
            f"Task: {prompt}\n\n"
            "IMPORTANT: This is a real SIEM alert. Embed the alert data in your script and analyze it. "
            "Generate detection logic and IOC extraction based on the alert details. "
            "Include the source IP, destination IP, and rule name in your analysis."
        )
    else:
        augmented_prompt = prompt + "\n\nCRITICAL CONSTRAINTS FOR THIS SCRIPT:\n1. You MUST define a multi-line string variable containing mock mock file data instead of trying to open files.\n2. You MUST define a hardcoded mock dictionary for any web request output instead of fetching it.\n3. You MUST use 'urllib.request' if you ever need networking.\n4. You MUST hardcode user choices instead of using an input function."

    # Model tiering
    tier_config = get_tier_config("generate_code")
    llm_model = tier_config["model"]
    prompt_name = "code_generation_with_logs" if log_data else "code_generation_mock"

    payload = {
        "model": llm_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": augmented_prompt}
        ],
        "temperature": 0.7,
        "max_tokens": tier_config["max_tokens"],
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    start_time = time.time()
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(litellm_url, json=payload, headers=headers)
        response.raise_for_status()
        result = response.json()

    execution_ms = int((time.time() - start_time) * 1000)

    # Log LLM call
    usage = result.get("usage", {})
    log_llm_call(
        activity_name="generate_code",
        model_tier=tier_config["tier"],
        model_id=llm_model,
        prompt_name=prompt_name,
        prompt_version=get_version(prompt_name),
        input_tokens=usage.get("prompt_tokens", 0),
        output_tokens=usage.get("completion_tokens", 0),
        latency_ms=execution_ms,
        temperature=0.7,
        max_tokens=tier_config["max_tokens"],
        tenant_id=task_data.get("tenant_id"),
        task_id=task_data.get("task_id"),
    )

    code = result["choices"][0]["message"]["content"].strip()
    if code.startswith("```python"):
        code = code[9:]
    if code.startswith("```"):
        code = code[3:]
    if code.endswith("```"):
        code = code[:-3]
        
    # Post-generation code scrubber to remove catastrophic LLM hallucinations that crash the read-only, non-interactive sandbox
    code = code.replace("import requests", "import urllib.request as urllib2")
    code = code.replace("requests.get", "urllib2.urlopen")
    code = code.replace("input(", "print('Mocking input for: ' + ")
    
    # Safely redirect any strictly local open() calls to the writeable /tmp/ directory
    # using regex to avoid catching things like urlopen()
    code = re.sub(r'\bopen\([\'"](?!\/tmp\/)(.*?)[\'"]', r'open("/tmp/\1"', code)

    code = re.sub(r'\bopen\([\'"](?!\/tmp\/)(.*?)[\'"]', r'open("/tmp/\1"', code)

    mock_requests = """
class MockResponse:
    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code
        self.text = str(json_data)
    def json(self):
        return self._json
    def raise_for_status(self): pass

class MockRequests:
    @staticmethod
    def get(*args, **kwargs): return MockResponse({"indicator": "malicious", "confidence": 99})
    @staticmethod
    def post(*args, **kwargs): return MockResponse({"status": "success"})

import sys
sys.modules['requests'] = MockRequests()
"""
    code = mock_requests + "\n" + code

    return {
        "code": code.strip(),
        "usage": result.get("usage", {}),
        "execution_ms": execution_ms
    }

@activity.defn
async def validate_code(code: str) -> dict:
    safe, reason = is_safe_python_code(code)
    return {
        "is_safe": safe,
        "reason": reason
    }

@activity.defn
async def execute_code(code: str) -> dict:
    seccomp_path = "/app/sandbox/seccomp_profile.json"

    cmd = [
        "docker", "run", "--rm", "-i", "--network=none", "--read-only",
        "--tmpfs", "/tmp:size=64m,noexec,nosuid", "--workdir", "/tmp",
        "--cpus=0.5", "--memory=512m", "--memory-swap=512m",
        "--pids-limit=64", "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--security-opt", f"seccomp={seccomp_path}",
        "python:3.11-slim", "python"
    ]

    start_time = time.time()
    try:
        result = subprocess.run(cmd, input=code, capture_output=True, text=True, timeout=60)
        execution_ms = int((time.time() - start_time) * 1000)

        status = "completed" if result.returncode == 0 else "failed"
        return {
            "status": status,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "execution_ms": execution_ms
        }
    except subprocess.TimeoutExpired:
        execution_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "failed",
            "stdout": "",
            "stderr": "Execution timed out after 30 seconds",
            "execution_ms": execution_ms
        }

@activity.defn
async def update_task_status(task_update: dict) -> None:
    conn = get_db_connection()
    worker_id = _get_worker_id()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE agent_tasks
                SET status = %s, output = %s, error_message = %s,
                    tokens_used_input = %s, tokens_used_output = %s, execution_ms = %s,
                    severity = %s, worker_id = COALESCE(%s, worker_id),
                    completed_at = NOW()
                WHERE id = %s
            """, (
                task_update["status"],
                json.dumps(task_update.get("output", {})),
                task_update.get("error_message", None),
                task_update.get("tokens_input", 0),
                task_update.get("tokens_output", 0),
                task_update.get("execution_ms", 0),
                task_update.get("severity", None),
                worker_id,
                task_update["task_id"]
            ))
        conn.commit()
    finally:
        conn.close()

@activity.defn
async def log_audit(audit_data: dict) -> None:
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            _sync_commit(cur)
            cur.execute("""
                INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id, details)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                audit_data["tenant_id"], 
                audit_data["action"], 
                audit_data["resource_type"], 
                audit_data["resource_id"], 
                json.dumps(audit_data.get("details", {}))
            ))
        conn.commit()
    finally:
        conn.close()

@activity.defn
async def log_audit_event(event_data: dict) -> None:
    """Insert structured audit event into audit_events table."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            _sync_commit(cur)
            cur.execute("""
                INSERT INTO audit_events (tenant_id, event_type, actor_id, actor_type, resource_type, resource_id, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                event_data["tenant_id"],
                event_data["event_type"],
                event_data.get("actor_id"),
                event_data.get("actor_type", "worker"),
                event_data.get("resource_type"),
                event_data.get("resource_id"),
                json.dumps(event_data.get("metadata", {}))
            ))
        conn.commit()
    except Exception as e:
        print(f"log_audit_event non-fatal error: {e}")
    finally:
        conn.close()

@activity.defn
async def record_usage(usage_data: dict) -> None:
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO usage_records (tenant_id, task_id, record_type, model_name, tokens_input, tokens_output, execution_ms)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                usage_data["tenant_id"], 
                usage_data["task_id"], 
                usage_data["record_type"], 
                usage_data["model_name"], 
                usage_data.get("tokens_input", 0), 
                usage_data.get("tokens_output", 0), 
                usage_data.get("execution_ms", 0)
            ))
        conn.commit()
    finally:
        conn.close()

@activity.defn
async def save_investigation_step(step_data: dict) -> None:
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            _sync_commit(cur)
            cur.execute("""
                INSERT INTO public.investigation_steps (task_id, step_number, step_type, summary_prompt, generated_code, output, status, tokens_used_input, tokens_used_output, execution_ms, execution_mode, parameters_used, completed_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (task_id, step_number) DO UPDATE SET
                    generated_code = EXCLUDED.generated_code,
                    output = EXCLUDED.output,
                    status = EXCLUDED.status,
                    tokens_used_input = EXCLUDED.tokens_used_input,
                    tokens_used_output = EXCLUDED.tokens_used_output,
                    execution_ms = EXCLUDED.execution_ms,
                    execution_mode = EXCLUDED.execution_mode,
                    parameters_used = EXCLUDED.parameters_used,
                    completed_at = NOW()
            """, (
                step_data["task_id"],
                step_data["step_number"],
                step_data.get("step_type", "analysis"),
                step_data["prompt"],
                step_data.get("generated_code", ""),
                json.dumps(step_data.get("output")) if step_data.get("output") else None,
                step_data.get("status", "completed"),
                step_data.get("tokens_used_input", 0),
                step_data.get("tokens_used_output", 0),
                step_data.get("execution_ms", 0),
                step_data.get("execution_mode", "generated"),
                json.dumps(step_data.get("parameters_used", {})) if step_data.get("parameters_used") else None,
            ))
        conn.commit()
    finally:
        conn.close()

@activity.defn
async def check_followup_needed(check_data: dict) -> dict:
    """Parse JSON output and determine if follow-up is needed. Activity for Temporal determinism."""
    stdout_str = check_data.get("stdout", "")
    previous_prompt = check_data.get("previous_prompt", "")
    try:
        parsed = json.loads(stdout_str)
        if not isinstance(parsed, dict):
            return {"needed": False, "prompt": ""}
        
        needed = parsed.get("follow_up_needed", False)
        follow_prompt = parsed.get("follow_up_prompt", "")
        
        # Guard: empty or duplicate prompt means no follow-up
        if not follow_prompt or not follow_prompt.strip():
            return {"needed": False, "prompt": ""}
        if follow_prompt.strip() == previous_prompt.strip():
            return {"needed": False, "prompt": ""}
        
        return {"needed": bool(needed), "prompt": follow_prompt}
    except Exception:
        return {"needed": False, "prompt": ""}

@activity.defn
async def generate_followup_code(task_data: dict) -> dict:
    """Generate code for a follow-up step, including previous step context."""
    litellm_url = os.environ.get("LITELLM_URL", "http://litellm:4000/v1/chat/completions")
    api_key = os.environ.get("LITELLM_MASTER_KEY", "sk-hydra-dev-2026")
    
    prompt = task_data.get("prompt", "")
    previous_context = task_data.get("previous_context", "")
    task_type = task_data.get("task_type", "log_analysis")
    step_number = task_data.get("step_number", 2)
    
    step_type_label = "Enrichment" if step_number == 2 else "Deep Analysis"
    
    system_prompt = (
        f"You are a senior security analyst performing Step {step_number} ({step_type_label}) of a multi-step investigation. "
        "The previous investigation step produced findings that require deeper analysis. "
        "Generate a self-contained Python script that builds on the previous findings. "
        "The script MUST include the previous findings as inline data and perform the requested follow-up analysis. "
        "Use ONLY the Python standard library. Do NOT use input(), subprocess, socket, requests, or any network calls. "
        "CRITICAL: Read-only sandbox. Write files ONLY to /tmp/. "
        "REQUIRED JSON OUTPUT STRUCTURE: Your script MUST print perfectly valid JSON to stdout containing: "
        "`findings` (array of objects with title and details), "
        "`statistics` (object with counts and metrics), "
        "`recommendations` (array of strings), "
        "`risk_score` (integer 0-100), "
        "`follow_up_needed` (boolean), and `follow_up_prompt` (string, empty if not needed)."
    )
    
    playbook_system_prompt_override = task_data.get("playbook_system_prompt_override")
    if playbook_system_prompt_override:
        system_prompt += f"\n\nPLAYBOOK OVERRIDE INSTRUCTIONS:\n{playbook_system_prompt_override}"

    
    # Cap previous context to 2000 chars
    if len(previous_context) > 2000:
        previous_context = previous_context[:2000] + "\n... [truncated]"
    
    user_message = (
        f"PREVIOUS STEP RESULTS:\n{previous_context}\n\n"
        f"FOLLOW-UP TASK: {prompt}\n\n"
        "CRITICAL CONSTRAINTS: 1. Embed the previous findings as inline data. "
        "2. Do NOT use input(). 3. Do NOT import requests. 4. Write files only to /tmp/. "
        "5. Hardcode all data inline."
    )
    
    tier_config = get_tier_config("generate_followup_code")
    followup_model = tier_config["model"]

    payload = {
        "model": followup_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ],
        "temperature": 0.7,
        "max_tokens": tier_config["max_tokens"],
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    start_time = time.time()
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(litellm_url, json=payload, headers=headers)
        response.raise_for_status()
        result = response.json()

    execution_ms = int((time.time() - start_time) * 1000)

    # Log LLM call
    usage = result.get("usage", {})
    log_llm_call(
        activity_name="generate_followup_code",
        model_tier=tier_config["tier"],
        model_id=followup_model,
        prompt_name="code_generation_followup",
        prompt_version=get_version("code_generation_followup"),
        input_tokens=usage.get("prompt_tokens", 0),
        output_tokens=usage.get("completion_tokens", 0),
        latency_ms=execution_ms,
        temperature=0.7,
        max_tokens=tier_config["max_tokens"],
        tenant_id=task_data.get("tenant_id"),
        task_id=task_data.get("task_id"),
    )

    code = result["choices"][0]["message"]["content"].strip()
    if code.startswith("```python"):
        code = code[9:]
    if code.startswith("```"):
        code = code[3:]
    if code.endswith("```"):
        code = code[:-3]

    # Post-generation code scrubber
    code = code.replace("import requests", "import urllib.request as urllib2")
    code = code.replace("requests.get", "urllib2.urlopen")
    code = code.replace("input(", "print('Mocking input for: ' + ")
    code = re.sub(r'\bopen\([\'"](?!\/tmp\/)(.*?)[\'"]', r'open("/tmp/\1"', code)

    mock_requests = """
class MockResponse:
    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code
        self.text = str(json_data)
    def json(self):
        return self._json
    def raise_for_status(self): pass

class MockRequests:
    @staticmethod
    def get(*args, **kwargs): return MockResponse({"indicator": "malicious", "confidence": 99})
    @staticmethod
    def post(*args, **kwargs): return MockResponse({"status": "success"})

import sys
sys.modules['requests'] = MockRequests()
"""
    code = mock_requests + "\n" + code
    
    return {
        "code": code.strip(),
        "usage": result.get("usage", {}),
        "execution_ms": execution_ms
    }

@activity.defn
async def check_requires_approval(check_data: dict) -> dict:
    """Determine if a step requires human approval before execution."""
    task_type = check_data.get("task_type", "").lower().replace(" ", "_")
    risk_score = check_data.get("risk_score", 0)
    code = check_data.get("code", "")
    step_number = check_data.get("step_number", 1)
    
    # Rule 1: incident_response ALWAYS requires approval
    if task_type == "incident_response":
        return {
            "required": True,
            "reason": "Incident response scripts require manual approval before execution",
            "risk_level": "high"
        }
    
    # Rule 2: High risk score from previous step
    if risk_score >= 80:
        return {
            "required": True,
            "reason": f"Previous step produced high risk score ({risk_score}/100)",
            "risk_level": "critical"
        }
    
    # Rule 3: Dangerous code patterns
    dangerous_patterns = [
        ("open(", "'w'"),      # File write
        ("open(", "\"w\""),    # File write
        ('os.remove', ''),     # File deletion
        ('shutil.rmtree', ''), # Directory deletion
        ('subprocess', ''),    # System commands
        ('os.system', ''),     # System commands
    ]
    
    for pattern, secondary in dangerous_patterns:
        if pattern in code and (not secondary or secondary in code):
            return {
                "required": True,
                "reason": f"Generated code contains potentially dangerous operations ({pattern})",
                "risk_level": "medium"
            }
    
    return {"required": False, "reason": "", "risk_level": "low"}

@activity.defn
async def create_approval_request(request_data: dict) -> str:
    """Create an approval request in the database. Returns the approval ID."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            _sync_commit(cur)
            cur.execute("""
                INSERT INTO approval_requests (task_id, step_number, risk_level, action_summary, generated_code)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (
                request_data["task_id"],
                request_data["step_number"],
                request_data["risk_level"],
                request_data["action_summary"],
                request_data["generated_code"]
            ))
            approval_id = str(cur.fetchone()[0])
        conn.commit()
        return approval_id
    finally:
        conn.close()

@activity.defn
async def update_approval_request(update_data: dict) -> None:
    """Update an approval request with the decision."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            _sync_commit(cur)
            cur.execute("""
                UPDATE approval_requests 
                SET status = %s, decided_at = NOW(), decided_by = %s, decision_comment = %s
                WHERE id = %s
            """, (
                update_data["status"],
                update_data.get("decided_by"),
                update_data.get("comment", ""),
                update_data["approval_id"]
            ))
        conn.commit()
    finally:
        conn.close()

@activity.defn
async def retrieve_skill(task_type: str, prompt: str) -> dict:
    tei_url = os.environ.get("TEI_URL", "http://embedding-server:80/embed")
    conn = get_db_connection()
    try:
        # 1. First try keyword matching (no embeddings needed)
        prompt_words = [w.lower() for w in prompt.split() if len(w) > 2] # simple word split dropping very short words
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Match if task_type is in threat_types, OR any keyword from DB matches any word in prompt
            # Only return skills with code_template IS NOT NULL if we are matching for template mode (which we are now preferencing)
            # Actually, the requirement says "The skill must have code_template IS NOT NULL to be returned for template mode"
            # Since retrieve_skill is used generally, we'll order by has_template to prefer templates but fallback if needed,
            # or according to instructions "The skill must have code_template IS NOT NULL to be returned for template mode"
            # It's better to just require code_template IS NOT NULL for the keyword match if that's what's intended,
            # but let's just use the existing fields and prefer those with templates.
            # Actually, I will explicitly require `code_template IS NOT NULL` in the query to guarantee template mode.
            
            query = """
                SELECT id, skill_name, investigation_methodology, detection_patterns, mitre_techniques, follow_up_chain, embedding, code_template, parameters
                FROM agent_skills
                WHERE is_active = true
                AND code_template IS NOT NULL
                AND (
                    %s = ANY(threat_types) OR
                    EXISTS (
                        SELECT 1 FROM unnest(keywords) k
                        WHERE k ILIKE ANY(%s)
                    )
                )
                ORDER BY (CASE WHEN %s = ANY(threat_types) THEN 0 ELSE 1 END), times_used DESC
            """
            # Create a list of %word% for ILIKE ANY
            like_words = [f"%{w}%" for w in prompt_words] if prompt_words else ["%impossible_match_xyz%"]
            tt = task_type.lower().replace(" ", "_")
            cur.execute(query, (tt, like_words, tt))
            keyword_matches = cur.fetchall()
            
            if keyword_matches:
                print(f"DEBUG retrieve_skill: found {len(keyword_matches)} keyword matches, returning top matched by times_used.")
                best_match = keyword_matches[0]
                cur.execute("UPDATE agent_skills SET times_used = times_used + 1 WHERE id = %s", (best_match['id'],))
                conn.commit()
                return dict(best_match)

        # 2. Only try vector similarity if keyword matching returns 0 results
        print(f"DEBUG retrieve_skill: 0 keyword matches. Falling back to vector similarity.")
        
        # Fetch embedding for prompt
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(tei_url, json={"inputs": prompt})
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list) and len(data) > 0:
                prompt_embedding = data[0]
                print(f"DEBUG retrieve_skill: got prompt_embedding of length {len(prompt_embedding)}")
            else:
                print(f"DEBUG retrieve_skill: data is not a list. data={data}")
                return None

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # We filter candidates by threat_types or keywords loosely first to avoid scanning whole DB (optional, but keeping previous logic)
            query_candidates = """
                SELECT id, skill_name, investigation_methodology, detection_patterns, mitre_techniques, follow_up_chain, code_template, parameters
                FROM agent_skills
                WHERE is_active = true
                AND code_template IS NOT NULL
                ORDER BY embedding <=> %s::vector
                LIMIT 1
            """
            cur.execute(query_candidates, (prompt_embedding,))
            best_match = cur.fetchone()

            if best_match:
                print(f"DEBUG retrieve_skill: found vector match {best_match['skill_name']}")
                cur.execute("UPDATE agent_skills SET times_used = times_used + 1 WHERE id = %s", (best_match['id'],))
                conn.commit()
                return dict(best_match)
        
        return None
    except Exception as e:
        print(f"Error in retrieve_skill: {e}")
        return None
    finally:
        conn.close()

@activity.defn
async def fill_skill_parameters(data: dict) -> dict:
    import builtins
    import json
    import os
    import httpx
    
    litellm_url = os.environ.get("LITELLM_URL", "http://litellm:4000/v1/chat/completions")
    api_key = os.environ.get("LITELLM_MASTER_KEY", "sk-hydra-dev-2026")
    tier_config = get_tier_config("fill_skill_parameters")
    model_name = tier_config["model"]

    import time
    start_time = time.time()

    skill_params = data.get("skill_params", [])
    prompt = data.get("prompt", "")
    log_data = data.get("log_data", "")
    siem_event = data.get("siem_event", {})

    defaults = {p["name"]: p.get("default") for p in skill_params}

    try:
        sys_msg = (
            "You are an expert security parameter extractor. Extract parameter values for a Python detection script "
            "based strictly on the provided user prompt. Return ONLY a valid JSON object matching the requested schema. "
            "Do not include markdown blocks, explanations, or any other text. Follow the parameter types strictly."
        )

        user_msg = f"Available parameters and their types:\\n{json.dumps(skill_params, indent=2)}\\n\\nUser Prompt:\\n{prompt}\\n\\n"
        if siem_event:
            user_msg += f"Available SIEM Context:\\n{json.dumps(siem_event)}\\n\\n"
        user_msg += "Respond ONLY with a JSON object where keys are parameter names and values are the extracted values."

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                litellm_url,
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": model_name,
                    "messages": [
                        {"role": "system", "content": sys_msg},
                        {"role": "user", "content": user_msg}
                    ],
                    "temperature": tier_config["temperature"],
                    "max_tokens": tier_config["max_tokens"],
                    "response_format": {"type": "json_object"}
                }
            )
            resp.raise_for_status()

            resp_json = resp.json()
            usage = resp_json.get("usage", {})
            input_tokens = usage.get("prompt_tokens", 0)
            output_tokens = usage.get("completion_tokens", 0)

            fill_ms = int((time.time() - start_time) * 1000)
            log_llm_call(
                activity_name="fill_skill_parameters",
                model_tier=tier_config["tier"],
                model_id=model_name,
                prompt_name="parameter_extraction",
                prompt_version=get_version("parameter_extraction"),
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                latency_ms=fill_ms,
                temperature=tier_config["temperature"],
                max_tokens=tier_config["max_tokens"],
                tenant_id=data.get("tenant_id"),
                task_id=data.get("task_id"),
            )

            content = resp_json["choices"][0]["message"]["content"].strip()

            extracted = json.loads(content)
                
            for k, v in defaults.items():
                if k not in extracted or extracted[k] is None:
                    extracted[k] = v
                    
            if "log_data" in defaults and log_data:
                extracted["log_data"] = log_data
                
            return {
                "filled_parameters": extracted,
                "execution_ms": int((time.time() - start_time) * 1000),
                "input_tokens": input_tokens,
                "output_tokens": output_tokens
            }
            
    except Exception as e:
        print(f"Error in fill_skill_parameters: {e}")
        if "log_data" in defaults and log_data:
            defaults["log_data"] = log_data
        return {
            "filled_parameters": defaults,
            "execution_ms": int((time.time() - start_time) * 1000),
            "input_tokens": 0,
            "output_tokens": 0
        }

@activity.defn
async def render_skill_template(data: dict) -> str:
    import json
    
    template = data.get("template", "")
    parameters = data.get("parameters", {})
    
    rendered = template
    for key, value in parameters.items():
        placeholder = f"{{{{{key}}}}}"
        
        if isinstance(value, str):
            # Safe replacement for multiline strings / logs
            val_str = value.replace('\\', '\\\\').replace("'''", "\\'\\'\\'")
            rendered = rendered.replace(placeholder, val_str)
        elif isinstance(value, (list, dict)):
            rendered = rendered.replace(placeholder, json.dumps(value))
        else:
            rendered = rendered.replace(placeholder, str(value))
            
    return rendered

@activity.defn
async def check_rate_limit_activity(data: dict) -> bool:
    """Check if tenant is under rate limit. Returns True if OK."""
    from redis_client import check_rate_limit
    return check_rate_limit(data["tenant_id"], data["max_concurrent"])

@activity.defn
async def decrement_active_activity(tenant_id: str) -> None:
    """Decrement active count for tenant."""
    from redis_client import decrement_active
    decrement_active(tenant_id)

@activity.defn
async def write_investigation_memory(memory_data: dict) -> None:
    try:
        litellm_url = os.environ.get("LITELLM_URL", "http://litellm:4000/v1/chat/completions")
        api_key = os.environ.get("LITELLM_MASTER_KEY", "sk-hydra-dev-2026")
        tei_url = os.environ.get("TEI_URL", "http://embedding-server:80/embed")

        task_id = memory_data.get("task_id")
        tenant_id = memory_data.get("tenant_id")
        skill_used_id = memory_data.get("skill_used_id")
        threat_type = memory_data.get("threat_type", "unknown")
        final_output = memory_data.get("final_output", {})

        findings = final_output.get("findings", [])[:5]
        iocs = final_output.get("key_iocs", {})
        risk_score = final_output.get("risk_score", 0)
        recommended = final_output.get("recommendations", [])
        
        # Build synthesis prompt
        summary_prompt = (
            f"Synthesize this investigation into 2-3 sentences max. Threat: {threat_type}. "
            f"Findings: {json.dumps(findings)}. Risk: {risk_score}. Recommends: {json.dumps(recommended)}."
        )

        payload = {
            "model": "fast",
            "messages": [
                {"role": "system", "content": "You are a succinct security analyst. Synthesize the JSON data into a short 2-3 sentence memory summary: 'Investigated [threat_type] alert. Found [N findings]. Risk score [X] because [reason]. Resolution: [recommended action].'"},
                {"role": "user", "content": summary_prompt}
            ]
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(litellm_url, json=payload, headers={"Authorization": f"Bearer {api_key}"})
            resp.raise_for_status()
            memory_summary = resp.json()["choices"][0]["message"]["content"].strip()
            
            # Embed
            embed_resp = await client.post(tei_url, json={"inputs": memory_summary})
            embed_resp.raise_for_status()
            embedding = embed_resp.json()[0]

        # Save to DB
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                _sync_commit(cur)
                cur.execute("""
                    INSERT INTO investigation_memory
                    (tenant_id, task_id, skill_used_id, threat_type, memory_summary, key_findings, key_iocs, risk_score, embedding)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::vector)
                """, (
                    tenant_id, task_id, skill_used_id, threat_type, memory_summary,
                    json.dumps(findings), json.dumps(iocs), risk_score, embedding
                ))
            conn.commit()
        finally:
            conn.close()

    except Exception as e:
        print(f"Non-critical failure in write_investigation_memory: {e}")
        # Do not raise, this is fire-and-forget
        pass


