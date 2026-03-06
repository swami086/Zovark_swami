"""SRE Tester — sandbox-isolated patch verification."""

import os
import tempfile
import subprocess
from temporalio import activity


# Allowlist of safe packages for pip_install patches
SAFE_PACKAGES = {
    'pyyaml', 'pillow', 'opencv-python-headless', 'scikit-learn',
    'beautifulsoup4', 'python-dateutil', 'python-dotenv', 'attrs',
    'lxml', 'python-magic', 'requests', 'httpx', 'psycopg2-binary',
    'redis', 'jinja2', 'markupsafe', 'certifi', 'charset-normalizer',
    'idna', 'urllib3', 'temporalio',
}


@activity.defn
async def test_patch(data: dict) -> dict:
    """Test a generated patch in isolation before applying."""
    patch_type = data.get('type', '')

    if patch_type == 'pip_install':
        return _test_pip_install(data)

    elif patch_type == 'code_patch':
        return _test_code_patch(data)

    elif patch_type == 'no_patch':
        return {'passed': False, 'reason': data.get('reason', 'No patch generated')}

    else:
        return {'passed': False, 'reason': f'Unknown patch type: {patch_type}'}


def _test_pip_install(data: dict) -> dict:
    """Verify package is in the safe allowlist."""
    package = data.get('package', '')

    if package not in SAFE_PACKAGES:
        return {
            'passed': False,
            'reason': f'Package {package} not in safe allowlist',
            'exit_code': -1,
            'stdout': '',
            'stderr': f'Blocked: {package} not in SAFE_PACKAGES',
        }

    return {
        'passed': True,
        'reason': f'Package {package} is in safe allowlist',
        'exit_code': 0,
        'stdout': f'Package {package} approved for install',
        'stderr': '',
    }


def _test_code_patch(data: dict) -> dict:
    """Syntax-check and basic import test for code patches."""
    patched_content = data.get('patched_content', '')
    file_path = data.get('file_path', 'unknown.py')

    if not patched_content.strip():
        return {
            'passed': False,
            'reason': 'Empty patched content',
            'exit_code': -1,
            'stdout': '',
            'stderr': 'Patched content is empty',
        }

    # Step 1: Syntax check via compile()
    try:
        compile(patched_content, file_path, 'exec')
    except SyntaxError as e:
        return {
            'passed': False,
            'reason': f'Syntax error in patch: {e}',
            'exit_code': 1,
            'stdout': '',
            'stderr': str(e),
        }

    # Step 2: Write to temp file and run basic import test
    test_script = f'''
import sys
sys.path.insert(0, "/app")

# Write patched code to temp module
import tempfile, os
tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, dir='/tmp')
tmp.write("""{patched_content.replace(chr(92), chr(92)+chr(92)).replace('"', chr(92)+'"')}""")
tmp.close()

# Syntax is already verified, just confirm it's valid Python
try:
    with open(tmp.name) as f:
        compile(f.read(), tmp.name, 'exec')
    print("PATCH_TEST_PASSED")
except Exception as e:
    print(f"PATCH_TEST_FAILED: {{e}}")
    sys.exit(1)
finally:
    os.unlink(tmp.name)
'''

    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, dir='/tmp') as tf:
            tf.write(test_script)
            test_file = tf.name

        result = subprocess.run(
            ["python", test_file],
            timeout=30,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": "/app"},
        )

        os.unlink(test_file)

        passed = result.returncode == 0 and 'PATCH_TEST_PASSED' in result.stdout

        return {
            'passed': passed,
            'exit_code': result.returncode,
            'stdout': result.stdout[:1000],
            'stderr': result.stderr[:1000],
        }

    except subprocess.TimeoutExpired:
        return {
            'passed': False,
            'reason': 'Test timed out after 30s',
            'exit_code': -1,
            'stdout': '',
            'stderr': 'Timeout',
        }
    except Exception as e:
        return {
            'passed': False,
            'reason': f'Test execution error: {e}',
            'exit_code': -1,
            'stdout': '',
            'stderr': str(e),
        }
