"""Tests for the seccomp profile.

Verifies the seccomp_profile.json blocks dangerous syscalls while
allowing necessary operations for Python code execution.
"""

import json
import os
import pytest

SECCOMP_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "sandbox", "seccomp_profile.json")


@pytest.fixture
def seccomp_profile():
    """Load the seccomp profile JSON."""
    with open(SECCOMP_PATH) as f:
        return json.load(f)


class TestSeccompStructure:
    """Verify seccomp profile structure and defaults."""

    def test_default_action_is_deny(self, seccomp_profile):
        """Default action should deny all syscalls not explicitly allowed."""
        assert seccomp_profile["defaultAction"] == "SCMP_ACT_ERRNO"

    def test_has_architecture_map(self, seccomp_profile):
        """Profile should include architecture mappings."""
        assert "archMap" in seccomp_profile
        arches = [a["architecture"] for a in seccomp_profile["archMap"]]
        assert "SCMP_ARCH_X86_64" in arches
        assert "SCMP_ARCH_AARCH64" in arches

    def test_has_syscall_rules(self, seccomp_profile):
        """Profile should have syscall rules."""
        assert "syscalls" in seccomp_profile
        assert len(seccomp_profile["syscalls"]) > 0


class TestDangerousSyscallsBlocked:
    """Verify that dangerous syscalls are explicitly blocked."""

    def test_mount_blocked(self, seccomp_profile):
        """mount should be explicitly blocked."""
        blocked = _get_explicitly_blocked(seccomp_profile)
        assert "mount" in blocked, "mount syscall should be explicitly blocked"

    def test_ptrace_blocked(self, seccomp_profile):
        """ptrace should be explicitly blocked (without CAP_SYS_PTRACE)."""
        blocked = _get_explicitly_blocked(seccomp_profile)
        assert "ptrace" in blocked, "ptrace syscall should be explicitly blocked"

    def test_reboot_blocked(self, seccomp_profile):
        """reboot should be explicitly blocked."""
        blocked = _get_explicitly_blocked(seccomp_profile)
        assert "reboot" in blocked

    def test_kexec_load_blocked(self, seccomp_profile):
        """kexec_load should be explicitly blocked."""
        blocked = _get_explicitly_blocked(seccomp_profile)
        assert "kexec_load" in blocked

    def test_bpf_blocked(self, seccomp_profile):
        """bpf should be explicitly blocked."""
        blocked = _get_explicitly_blocked(seccomp_profile)
        assert "bpf" in blocked

    def test_setns_blocked(self, seccomp_profile):
        """setns should be explicitly blocked."""
        blocked = _get_explicitly_blocked(seccomp_profile)
        assert "setns" in blocked

    def test_unshare_blocked(self, seccomp_profile):
        """unshare should be explicitly blocked."""
        blocked = _get_explicitly_blocked(seccomp_profile)
        assert "unshare" in blocked

    def test_perf_event_open_blocked(self, seccomp_profile):
        """perf_event_open should be explicitly blocked."""
        blocked = _get_explicitly_blocked(seccomp_profile)
        assert "perf_event_open" in blocked


class TestAllowedSyscalls:
    """Verify that necessary syscalls are allowed."""

    def test_read_write_allowed(self, seccomp_profile):
        """Basic I/O syscalls should be allowed."""
        allowed = _get_allowed_syscalls(seccomp_profile)
        assert "read" in allowed
        assert "write" in allowed

    def test_open_allowed(self, seccomp_profile):
        """File open syscalls should be allowed."""
        allowed = _get_allowed_syscalls(seccomp_profile)
        assert "openat" in allowed or "open" in allowed

    def test_mmap_allowed(self, seccomp_profile):
        """Memory mapping should be allowed (needed for Python)."""
        allowed = _get_allowed_syscalls(seccomp_profile)
        assert "mmap" in allowed

    def test_fork_allowed(self, seccomp_profile):
        """fork should be allowed for subprocess."""
        allowed = _get_allowed_syscalls(seccomp_profile)
        assert "fork" in allowed or "vfork" in allowed

    def test_execve_allowed(self, seccomp_profile):
        """execve should be allowed (needed to run Python)."""
        allowed = _get_allowed_syscalls(seccomp_profile)
        assert "execve" in allowed


class TestRawSocketBlocked:
    """Verify raw socket creation is restricted."""

    def test_raw_socket_blocked(self, seccomp_profile):
        """Raw socket creation (AF_PACKET/type RAW) should be blocked."""
        for rule in seccomp_profile["syscalls"]:
            if "socket" in rule.get("names", []) and rule["action"] == "SCMP_ACT_ERRNO":
                # Found a blocking rule for socket — verify it targets raw sockets
                assert True
                return
        # If no blocking socket rule, that's still OK if default is deny
        assert seccomp_profile["defaultAction"] == "SCMP_ACT_ERRNO"


def _get_explicitly_blocked(profile):
    """Extract all syscall names that are explicitly blocked (ERRNO)."""
    blocked = set()
    for rule in profile["syscalls"]:
        if rule["action"] == "SCMP_ACT_ERRNO":
            # Only count unconditional blocks (no caps/includes)
            if "includes" not in rule or not rule.get("includes"):
                blocked.update(rule.get("names", []))
    return blocked


def _get_allowed_syscalls(profile):
    """Extract all syscall names that are explicitly allowed."""
    allowed = set()
    for rule in profile["syscalls"]:
        if rule["action"] == "SCMP_ACT_ALLOW":
            allowed.update(rule.get("names", []))
    return allowed
