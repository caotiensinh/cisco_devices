"""Safety policy for CBS250 investigation-only discovery."""
from __future__ import annotations

VERSION = "3.0.0"

class SafetyViolation(RuntimeError):
    """Raised when execution is outside the investigation-only policy."""

READ_ONLY_EXEC_ALLOWLIST = frozenset({
    "show version",
    "show system",
    "show ip ssh",
})

HARD_DENY_EXEC_ROOTS = frozenset({
    "boot", "clear", "clock", "configure", "copy", "crypto", "debug",
    "debug-mode", "delete", "dot1x", "errdisable", "green-ethernet",
    "macro", "mkdir", "no", "reload", "rename", "renew", "rmdir",
    "set", "shutdown", "system", "test", "write",
})

def normalize_command(command: str) -> str:
    return " ".join(command.strip().split())

def command_root(command: str) -> str:
    normalized = normalize_command(command)
    return normalized.split(" ", 1)[0].lower() if normalized else ""

def assert_read_only_executable(command: str) -> str:
    normalized = normalize_command(command)
    root = command_root(normalized)
    if not normalized:
        raise SafetyViolation("Empty command is not executable")
    if root in HARD_DENY_EXEC_ROOTS:
        raise SafetyViolation(f"Hard-deny execution policy blocked: {normalized!r}")
    if normalized not in READ_ONLY_EXEC_ALLOWLIST:
        raise SafetyViolation(f"Command is not in exact read-only allowlist: {normalized!r}")
    return normalized
