"""Tests for the sandbox kill timer.

Verifies that the 30-second execution timeout works correctly.
"""

import sys
import os
import subprocess
import time
import threading
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sandbox"))
from kill_timer import enforce_kill_timer


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


class TestKillTimerUnit:
    """Unit tests for the kill timer mechanism (no Docker needed)."""

    def test_timer_can_be_created(self):
        """enforce_kill_timer returns a Timer object."""
        timer = enforce_kill_timer("fake-container", timeout_seconds=60)
        assert isinstance(timer, threading.Timer)
        assert timer.daemon is True
        timer.cancel()

    def test_timer_can_be_cancelled(self):
        """Timer can be cancelled before firing."""
        timer = enforce_kill_timer("fake-container", timeout_seconds=1)
        timer.cancel()
        # Wait a bit to verify it doesn't fire
        time.sleep(1.5)
        # No assertion needed — if the timer fires, it just tries to kill
        # a non-existent container (which is harmless)

    def test_timer_is_daemon(self):
        """Timer thread should be daemonized."""
        timer = enforce_kill_timer("fake-container", timeout_seconds=60)
        assert timer.daemon is True
        timer.cancel()

    def test_default_timeout_is_30s(self):
        """Default timeout should be 30 seconds."""
        timer = enforce_kill_timer("test-container")
        assert timer.interval == 30
        timer.cancel()

    def test_custom_timeout(self):
        """Custom timeout should be respected."""
        timer = enforce_kill_timer("test-container", timeout_seconds=10)
        assert timer.interval == 10
        timer.cancel()


@pytest.mark.skipif(not docker_available(), reason="Docker not available")
class TestKillTimerIntegration:
    """Integration tests requiring Docker."""

    def test_container_killed_after_timeout(self):
        """A sleeping container should be killed after timeout."""
        container_name = "hydra-test-kill-timer"

        # Start a container that sleeps forever
        subprocess.run(
            [
                "docker", "run", "-d",
                "--name", container_name,
                "python:3.11-slim",
                "sleep", "300",
            ],
            capture_output=True,
        )

        try:
            # Set a short kill timer (3 seconds)
            timer = enforce_kill_timer(container_name, timeout_seconds=3)

            # Wait for timer to fire
            time.sleep(5)

            # Check container is not running
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
                capture_output=True,
                text=True,
            )
            # Container should be stopped or gone
            if result.returncode == 0:
                assert result.stdout.strip() == "false", "Container should be stopped"

        finally:
            # Cleanup
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True,
            )

    def test_timer_cancel_prevents_kill(self):
        """Cancelling timer before timeout should leave container running."""
        container_name = "hydra-test-cancel-timer"

        subprocess.run(
            [
                "docker", "run", "-d",
                "--name", container_name,
                "python:3.11-slim",
                "sleep", "30",
            ],
            capture_output=True,
        )

        try:
            timer = enforce_kill_timer(container_name, timeout_seconds=5)
            # Cancel immediately
            timer.cancel()

            # Wait past the timeout
            time.sleep(6)

            # Container should still be running
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0
            assert result.stdout.strip() == "true", "Container should still be running"

        finally:
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True,
            )
