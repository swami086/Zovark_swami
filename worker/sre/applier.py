"""SRE Applier — safely applies verified patches with backup + audit."""

import os
import json
import subprocess
from datetime import datetime, timezone
from temporalio import activity

import psycopg2


def get_db_connection():
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    return psycopg2.connect(db_url)


# Files that must never be modified by self-healing
PROTECTED_FILES = {
    '/app/sandbox/ast_prefilter.py',
    '/app/sandbox/seccomp_profile.json',
    '/app/sandbox/kill_timer.py',
}

# Safe packages for pip install
SAFE_PACKAGES = {
    'pyyaml', 'pillow', 'opencv-python-headless', 'scikit-learn',
    'beautifulsoup4', 'python-dateutil', 'python-dotenv', 'attrs',
    'lxml', 'python-magic', 'requests', 'httpx', 'psycopg2-binary',
    'redis', 'jinja2', 'markupsafe', 'certifi', 'charset-normalizer',
    'idna', 'urllib3', 'temporalio',
}


def _log_self_healing_event(event_data: dict):
    """Insert a record into self_healing_events table."""
    try:
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO self_healing_events
                    (failure_id, workflow_id, activity_name, error_category,
                     diagnosis, patch_type, patch_content, test_result,
                     applied, rolled_back, file_path, backup_path)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    event_data.get('failure_id'),
                    event_data.get('workflow_id'),
                    event_data.get('activity_name'),
                    event_data.get('error_category'),
                    json.dumps(event_data.get('diagnosis', {})),
                    event_data.get('patch_type'),
                    event_data.get('patch_content'),
                    json.dumps(event_data.get('test_result', {})),
                    event_data.get('applied', False),
                    event_data.get('rolled_back', False),
                    event_data.get('file_path'),
                    event_data.get('backup_path'),
                ))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"_log_self_healing_event error (non-fatal): {e}")


def _log_audit_event(event_type: str, metadata: dict):
    """Insert audit event for self-healing actions."""
    try:
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                # Use the dev tenant for system-level events
                cur.execute("""
                    INSERT INTO audit_events (tenant_id, event_type, actor_type, metadata)
                    SELECT id, %s, 'system', %s
                    FROM tenants WHERE slug = 'hydra-dev' LIMIT 1
                """, (event_type, json.dumps(metadata)))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"_log_audit_event error (non-fatal): {e}")


@activity.defn
async def apply_patch(data: dict) -> dict:
    """Apply a tested patch with backup and audit logging."""
    patch_type = data.get('type', '')
    dry_run = data.get('dry_run', True)

    if patch_type == 'no_patch':
        return {'applied': False, 'reason': data.get('reason', 'No patch to apply')}

    if patch_type == 'code_patch':
        return _apply_code_patch(data, dry_run)

    elif patch_type == 'pip_install':
        return _apply_pip_install(data, dry_run)

    else:
        return {'applied': False, 'reason': f'Unknown patch type: {patch_type}'}


def _apply_code_patch(data: dict, dry_run: bool) -> dict:
    """Apply a code patch with file backup."""
    file_path = data.get('file_path', '')
    patched_content = data.get('patched_content', '')

    # Safety: file must be under /app/
    if not file_path.startswith('/app/'):
        return {'applied': False, 'reason': f'File path must start with /app/: {file_path}'}

    # Safety: protected files
    if file_path in PROTECTED_FILES:
        return {'applied': False, 'reason': f'Protected file cannot be modified: {file_path}'}

    if not patched_content.strip():
        return {'applied': False, 'reason': 'Empty patched content'}

    if dry_run:
        _log_self_healing_event({
            'workflow_id': data.get('workflow_id', ''),
            'activity_name': data.get('activity_name', ''),
            'error_category': data.get('error_category', ''),
            'diagnosis': data.get('diagnosis', {}),
            'patch_type': 'code_patch',
            'patch_content': patched_content[:5000],
            'test_result': data.get('test_result', {}),
            'applied': False,
            'file_path': file_path,
        })
        return {
            'applied': False,
            'dry_run': True,
            'file_path': file_path,
            'reason': 'Dry run — patch not applied',
        }

    # Create backup
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    backup_path = f"{file_path}.bak.{timestamp}"

    try:
        # Read current content for backup
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                current_content = f.read()
            with open(backup_path, 'w') as f:
                f.write(current_content)

        # Write patched content
        with open(file_path, 'w') as f:
            f.write(patched_content)

        # Log events
        _log_self_healing_event({
            'workflow_id': data.get('workflow_id', ''),
            'activity_name': data.get('activity_name', ''),
            'error_category': data.get('error_category', ''),
            'diagnosis': data.get('diagnosis', {}),
            'patch_type': 'code_patch',
            'patch_content': patched_content[:5000],
            'test_result': data.get('test_result', {}),
            'applied': True,
            'file_path': file_path,
            'backup_path': backup_path,
        })

        _log_audit_event('self_healing_patch_applied', {
            'file_path': file_path,
            'backup_path': backup_path,
            'patch_type': 'code_patch',
            'activity_name': data.get('activity_name', ''),
        })

        return {
            'applied': True,
            'file_path': file_path,
            'backup_path': backup_path,
        }

    except Exception as e:
        _log_audit_event('self_healing_patch_failed', {
            'file_path': file_path,
            'error': str(e),
        })
        return {'applied': False, 'reason': f'Failed to apply patch: {e}'}


def _apply_pip_install(data: dict, dry_run: bool) -> dict:
    """Install a pip package."""
    package = data.get('package', '')

    if package not in SAFE_PACKAGES:
        return {'applied': False, 'reason': f'Package {package} not in safe allowlist'}

    if dry_run:
        _log_self_healing_event({
            'workflow_id': data.get('workflow_id', ''),
            'activity_name': data.get('activity_name', ''),
            'error_category': 'dependency_missing',
            'patch_type': 'pip_install',
            'patch_content': f'pip install {package}',
            'applied': False,
        })
        return {
            'applied': False,
            'dry_run': True,
            'package': package,
            'reason': 'Dry run — package not installed',
        }

    try:
        result = subprocess.run(
            ["pip", "install", package],
            capture_output=True,
            text=True,
            timeout=120,
        )

        applied = result.returncode == 0

        _log_self_healing_event({
            'workflow_id': data.get('workflow_id', ''),
            'activity_name': data.get('activity_name', ''),
            'error_category': 'dependency_missing',
            'patch_type': 'pip_install',
            'patch_content': f'pip install {package}',
            'applied': applied,
        })

        event_type = 'self_healing_patch_applied' if applied else 'self_healing_patch_failed'
        _log_audit_event(event_type, {
            'patch_type': 'pip_install',
            'package': package,
            'exit_code': result.returncode,
        })

        return {
            'applied': applied,
            'package': package,
            'stdout': result.stdout[:500],
            'stderr': result.stderr[:500],
        }

    except Exception as e:
        return {'applied': False, 'reason': f'pip install failed: {e}'}
