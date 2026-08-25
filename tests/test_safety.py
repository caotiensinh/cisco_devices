from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cbs250_safety import (
    HARD_DENY_EXEC_ROOTS,
    READ_ONLY_EXEC_ALLOWLIST,
    SafetyViolation,
    assert_read_only_executable,
)

def blocked(command: str) -> None:
    try:
        assert_read_only_executable(command)
    except SafetyViolation:
        return
    raise AssertionError(f"Forbidden command was accepted: {command}")

def test_destructive_and_state_changing_are_blocked():
    for command in (
        "delete flash:test",
        "clear logging",
        "clear logging file",
        "reload",
        "boot system inactive-image",
        "copy running-config startup-config",
        "write memory",
        "configure terminal",
        "set system mode",
        "no logging",
        "shutdown",
        "crypto key generate rsa",
    ):
        blocked(command)

def test_exact_allowlist_only():
    for command in READ_ONLY_EXEC_ALLOWLIST:
        assert assert_read_only_executable(command) == command
    blocked("show running-config")
    blocked("show tech-support")

def test_required_hard_deny_roots_exist():
    required = {"delete", "clear", "reload", "boot", "copy", "write", "configure", "no", "shutdown"}
    assert required.issubset(HARD_DENY_EXEC_ROOTS)
