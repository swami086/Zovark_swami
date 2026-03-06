"""Sandbox deobfuscation skill — decode base64/hex/PowerShell/URL payloads."""

import json
import time
import subprocess
from temporalio import activity


DEOBFUSCATION_TEMPLATE = '''
import base64, binascii, re, json, sys

def try_base64(data):
    try:
        decoded = base64.b64decode(data).decode('utf-8', errors='replace')
        if len(decoded) > 0 and decoded.isprintable():
            return {"encoding": "base64", "decoded": decoded}
    except: pass
    return None

def try_hex(data):
    try:
        cleaned = re.sub(r'[^0-9a-fA-F]', '', data)
        if len(cleaned) % 2 == 0 and len(cleaned) >= 4:
            decoded = binascii.unhexlify(cleaned).decode('utf-8', errors='replace')
            if decoded.isprintable():
                return {"encoding": "hex", "decoded": decoded}
    except: pass
    return None

def try_powershell_encoded(data):
    try:
        decoded_bytes = base64.b64decode(data)
        decoded = decoded_bytes.decode('utf-16-le', errors='replace')
        if decoded.isprintable() and len(decoded) > 0:
            return {"encoding": "powershell_encoded", "decoded": decoded}
    except: pass
    return None

def try_url_encoding(data):
    from urllib.parse import unquote
    decoded = unquote(data)
    if decoded != data:
        return {"encoding": "url_encoded", "decoded": decoded}
    return None

input_data = sys.stdin.read().strip()
results = []
for decoder in [try_base64, try_hex, try_powershell_encoded, try_url_encoding]:
    result = decoder(input_data)
    if result:
        results.append(result)

print(json.dumps({"deobfuscation_results": results, "input_length": len(input_data)}))
'''


@activity.defn
async def run_deobfuscation(data: dict) -> dict:
    """Execute deobfuscation in sandbox.

    Input: {encoded_payload, tenant_id, task_id}
    Returns: {results, input_length, execution_ms}
    """
    encoded_payload = data.get("encoded_payload", "")
    if not encoded_payload:
        return {"results": [], "input_length": 0, "execution_ms": 0, "error": "empty payload"}

    seccomp_path = "/app/sandbox/seccomp_profile.json"
    cmd = [
        "docker", "run", "--rm", "-i", "--network=none", "--read-only",
        "--tmpfs", "/tmp:size=64m,noexec,nosuid", "--workdir", "/tmp",
        "--cpus=0.5", "--memory=512m", "--memory-swap=512m",
        "--pids-limit=64", "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--security-opt", f"seccomp={seccomp_path}",
        "python:3.11-slim", "python"
    ]

    # Feed the template script via stdin, with the payload piped through
    # We build a script that reads the payload from a variable instead of stdin
    script = f'''
import sys
# Inject payload as variable
PAYLOAD = """{encoded_payload.replace(chr(92), chr(92)*2).replace('"', chr(92)+'"')}"""

import base64, binascii, re, json

def try_base64(data):
    try:
        decoded = base64.b64decode(data).decode('utf-8', errors='replace')
        if len(decoded) > 0 and decoded.isprintable():
            return {{"encoding": "base64", "decoded": decoded}}
    except: pass
    return None

def try_hex(data):
    try:
        cleaned = re.sub(r'[^0-9a-fA-F]', '', data)
        if len(cleaned) % 2 == 0 and len(cleaned) >= 4:
            decoded = binascii.unhexlify(cleaned).decode('utf-8', errors='replace')
            if decoded.isprintable():
                return {{"encoding": "hex", "decoded": decoded}}
    except: pass
    return None

def try_powershell_encoded(data):
    try:
        decoded_bytes = base64.b64decode(data)
        decoded = decoded_bytes.decode('utf-16-le', errors='replace')
        if decoded.isprintable() and len(decoded) > 0:
            return {{"encoding": "powershell_encoded", "decoded": decoded}}
    except: pass
    return None

def try_url_encoding(data):
    from urllib.parse import unquote
    decoded = unquote(data)
    if decoded != data:
        return {{"encoding": "url_encoded", "decoded": decoded}}
    return None

results = []
for decoder in [try_base64, try_hex, try_powershell_encoded, try_url_encoding]:
    result = decoder(PAYLOAD)
    if result:
        results.append(result)

print(json.dumps({{"deobfuscation_results": results, "input_length": len(PAYLOAD)}}))
'''

    start_time = time.time()
    try:
        result = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=30)
        execution_ms = int((time.time() - start_time) * 1000)

        if result.returncode == 0 and result.stdout.strip():
            try:
                parsed = json.loads(result.stdout.strip())
                return {
                    "results": parsed.get("deobfuscation_results", []),
                    "input_length": parsed.get("input_length", 0),
                    "execution_ms": execution_ms,
                }
            except json.JSONDecodeError:
                return {"results": [], "input_length": len(encoded_payload), "execution_ms": execution_ms, "error": "invalid JSON output"}
        else:
            return {"results": [], "input_length": len(encoded_payload), "execution_ms": execution_ms, "error": result.stderr[:500]}

    except subprocess.TimeoutExpired:
        execution_ms = int((time.time() - start_time) * 1000)
        return {"results": [], "input_length": len(encoded_payload), "execution_ms": execution_ms, "error": "timeout"}
    except Exception as e:
        execution_ms = int((time.time() - start_time) * 1000)
        return {"results": [], "input_length": len(encoded_payload), "execution_ms": execution_ms, "error": str(e)}
