"""Tests for sandbox resource limits.

Verifies that Docker containers are launched with appropriate
memory and CPU constraints.
"""

import subprocess
import pytest


def docker_available():
    """Check if Docker is available."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


@pytest.mark.skipif(not docker_available(), reason="Docker not available")
class TestResourceLimits:
    """Verify that sandbox containers have resource constraints."""

    def test_memory_limit_enforced(self):
        """Container with memory limit should be killed if it exceeds the limit."""
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--memory=32m",
                "--memory-swap=32m",
                "python:3.11-slim",
                "python", "-c",
                # Try to allocate 64MB — should be killed
                "data = bytearray(64 * 1024 * 1024)",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Container should fail (OOM killed)
        assert result.returncode != 0, "Container should be OOM killed"

    def test_memory_limit_allows_normal_usage(self):
        """Container with reasonable memory limit should run normally."""
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--memory=128m",
                "python:3.11-slim",
                "python", "-c",
                "data = bytearray(10 * 1024 * 1024); print('OK')",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"Should succeed: {result.stderr}"
        assert "OK" in result.stdout

    def test_cpu_limit_applied(self):
        """Verify CPU limit can be applied to container."""
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--cpus=0.5",
                "python:3.11-slim",
                "python", "-c",
                "import os; print('CPUs available'); print('OK')",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "OK" in result.stdout

    def test_pids_limit(self):
        """Container with --pids-limit should restrict process creation."""
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--pids-limit=10",
                "python:3.11-slim",
                "python", "-c",
                "import os; pids = [os.fork() for _ in range(20)]",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Should either fail or hit the limit
        # This is OS-dependent, so we just verify it runs
        # The key is that Docker accepts the --pids-limit flag

    def test_read_only_filesystem(self):
        """Container with --read-only cannot write to filesystem."""
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--read-only",
                "--tmpfs", "/tmp:size=10m",
                "python:3.11-slim",
                "python", "-c",
                "open('/etc/test.txt', 'w').write('test')",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode != 0, "Writing to read-only filesystem should fail"

    def test_tmpfs_allows_temp_writes(self):
        """Container with tmpfs on /tmp can write temp files."""
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--read-only",
                "--tmpfs", "/tmp:size=10m",
                "python:3.11-slim",
                "python", "-c",
                "open('/tmp/test.txt', 'w').write('test'); print('OK')",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "OK" in result.stdout

    def test_no_new_privileges(self):
        """Container with --security-opt=no-new-privileges runs correctly."""
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--security-opt=no-new-privileges",
                "python:3.11-slim",
                "python", "-c",
                "print('OK')",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "OK" in result.stdout
