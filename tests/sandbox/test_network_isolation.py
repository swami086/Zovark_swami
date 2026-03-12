"""Tests for sandbox network isolation.

Verifies that sandbox containers run with --network=none,
blocking all outbound network access.
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
class TestNetworkIsolation:
    """Verify --network=none blocks all outbound traffic."""

    def test_no_network_blocks_dns(self):
        """Container with --network=none cannot resolve DNS."""
        result = subprocess.run(
            [
                "docker", "run", "--rm", "--network=none",
                "python:3.11-slim",
                "python", "-c",
                "import socket; socket.getaddrinfo('google.com', 80)",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode != 0, "DNS resolution should fail with --network=none"

    def test_no_network_blocks_http(self):
        """Container with --network=none cannot make HTTP requests."""
        result = subprocess.run(
            [
                "docker", "run", "--rm", "--network=none",
                "python:3.11-slim",
                "python", "-c",
                "import urllib.request; urllib.request.urlopen('http://1.1.1.1', timeout=5)",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode != 0, "HTTP requests should fail with --network=none"

    def test_no_network_blocks_raw_socket(self):
        """Container with --network=none cannot create network sockets."""
        result = subprocess.run(
            [
                "docker", "run", "--rm", "--network=none",
                "python:3.11-slim",
                "python", "-c",
                "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(('1.1.1.1', 80))",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode != 0, "Socket connections should fail with --network=none"

    def test_no_network_allows_localhost(self):
        """Container with --network=none can still bind to localhost."""
        result = subprocess.run(
            [
                "docker", "run", "--rm", "--network=none",
                "python:3.11-slim",
                "python", "-c",
                "import socket; s = socket.socket(); s.bind(('127.0.0.1', 0)); s.close(); print('OK')",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, "Localhost binding should work with --network=none"
        assert "OK" in result.stdout
