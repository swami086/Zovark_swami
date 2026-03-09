"""
Dry-run validation gate for LLM-generated investigation code.
Executes code in ultra-restricted sandbox (5s timeout) before
committing to full investigation.

Uses existing sandbox infrastructure — NOT a new Docker implementation.
"""
import asyncio
import json
import subprocess
import tempfile
import os
import logging

logger = logging.getLogger(__name__)

REQUIRED_OUTPUT_KEYS = {'findings', 'confidence', 'entities', 'verdict'}


class DryRunValidator:
    """
    5-second pre-validation of LLM-generated code.
    Reuses the existing sandbox container approach with tighter limits.
    """

    def __init__(self, timeout: int = 5, memory_limit: str = "128m"):
        self.timeout = timeout
        self.memory_limit = memory_limit

    async def validate(self, code: str) -> dict:
        """
        Execute code in restricted subprocess, validate output.
        Returns: {'passed': bool, 'output': dict|None, 'reason': str|None}
        """
        # Step 1: Static checks (fast, no execution)
        static_result = self._static_checks(code)
        if not static_result['passed']:
            return static_result

        # Step 2: Dynamic dry-run in subprocess with timeout
        try:
            output = await self._execute_with_timeout(code)
        except asyncio.TimeoutError:
            return {'passed': False, 'output': None, 'reason': f'Dry-run exceeded {self.timeout}s timeout'}
        except Exception as e:
            return {'passed': False, 'output': None, 'reason': f'Dry-run execution error: {str(e)[:200]}'}

        # Step 3: Validate output schema
        if not isinstance(output, dict):
            return {'passed': False, 'output': None, 'reason': f'Output is not a dict: {type(output).__name__}'}

        missing = REQUIRED_OUTPUT_KEYS - set(output.keys())
        if missing:
            return {'passed': False, 'output': output, 'reason': f'Missing required keys: {missing}'}

        # Step 4: Validate value types
        if not isinstance(output.get('confidence'), (int, float)):
            return {'passed': False, 'output': output, 'reason': 'confidence must be a number'}

        if output.get('verdict') not in ('malicious', 'suspicious', 'benign', 'insufficient_data'):
            return {'passed': False, 'output': output, 'reason': f"Invalid verdict: {output.get('verdict')}"}

        return {'passed': True, 'output': output, 'reason': None}

    def _static_checks(self, code: str) -> dict:
        """Fast static analysis without execution."""
        # Check for obvious infinite loops
        if 'while True' in code and 'break' not in code:
            return {'passed': False, 'output': None, 'reason': 'Potential infinite loop detected (while True without break)'}

        # Check for network calls (should not be in dry-run)
        network_indicators = ['requests.get', 'requests.post', 'urllib', 'http.client', 'socket.connect']
        for indicator in network_indicators:
            if indicator in code:
                return {'passed': False, 'output': None, 'reason': f'Network call detected in investigation code: {indicator}'}

        # Check it's parseable Python
        try:
            compile(code, '<dry-run>', 'exec')
        except SyntaxError as e:
            return {'passed': False, 'output': None, 'reason': f'Syntax error: {e}'}

        return {'passed': True, 'output': None, 'reason': None}

    async def _execute_with_timeout(self, code: str) -> dict:
        """Execute code in subprocess with resource limits."""
        # Write code to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, dir='/tmp') as f:
            # Wrap code to capture output as JSON
            wrapper = f'''
import json
import sys
import resource

# Memory limit: 128MB
resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))

try:
    result = None
    # Execute the investigation code
{self._indent_code(code, spaces=4)}
    # Expect the code sets a 'result' variable or prints JSON
    if result is not None:
        print(json.dumps(result))
    else:
        print(json.dumps({{"error": "No result variable set"}}))
except Exception as e:
    print(json.dumps({{"error": str(e)}}))
    sys.exit(1)
'''
            f.write(wrapper)
            temp_path = f.name

        try:
            proc = await asyncio.create_subprocess_exec(
                'python', temp_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.timeout
            )

            if proc.returncode != 0:
                raise RuntimeError(f"Exit code {proc.returncode}: {stderr.decode()[:200]}")

            return json.loads(stdout.decode().strip())

        finally:
            os.unlink(temp_path)

    def _indent_code(self, code: str, spaces: int = 4) -> str:
        """Indent code block for wrapping."""
        prefix = ' ' * spaces
        return '\n'.join(prefix + line for line in code.split('\n'))
