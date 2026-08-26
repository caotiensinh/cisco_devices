"""Safety policy for CBS250 investigation-only discovery."""
from __future__ import annotations

VERSION = "3.1.0"


class SafetyViolation(RuntimeError):
    """Raised when execution is outside the investigation-only policy."""


# Collector/runtime execution authority. Commands enter this set only after exact-live
# output validation, parser regression coverage, and explicit promotion.
READ_ONLY_EXEC_ALLOWLIST = frozenset({
    "show version",
    "show system",
    "show ip ssh",
})

# Narrow one-shot validation authority. This is intentionally separate from the
# collector/runtime allowlist so a candidate can be live-output validated without
# silently becoming a generally executable collector command.
R0_VALIDATION_EXEC_ALLOWLIST = frozenset({
    "show vlan",
})

# Absolute deny list for any generic command executor. Discovery code may only
# *type* these words as part of a context-help query ending in '?' and must never
# submit them with CR/LF.
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


def _assert_not_hard_denied(normalized: str) -> None:
    root = command_root(normalized)
    if not normalized:
        raise SafetyViolation("Empty command is not executable")
    if root in HARD_DENY_EXEC_ROOTS:
        raise SafetyViolation(f"Hard-deny execution policy blocked: {normalized!r}")


def assert_read_only_executable(command: str) -> str:
    normalized = normalize_command(command)
    _assert_not_hard_denied(normalized)
    if normalized not in READ_ONLY_EXEC_ALLOWLIST:
        raise SafetyViolation(f"Command is not in exact read-only allowlist: {normalized!r}")
    return normalized


def assert_r0_validation_executable(command: str) -> str:
    """Authorize only an exact, temporary R0 live-output validation candidate.

    Passing this gate does not grant collector/runtime authority and does not mutate
    ``READ_ONLY_EXEC_ALLOWLIST``.
    """
    normalized = normalize_command(command)
    _assert_not_hard_denied(normalized)
    if normalized not in R0_VALIDATION_EXEC_ALLOWLIST:
        raise SafetyViolation(
            f"Command is not in exact R0 validation-only allowlist: {normalized!r}"
        )
    if normalized in READ_ONLY_EXEC_ALLOWLIST:
        raise SafetyViolation(
            f"R0 validation candidate is already collector-allowlisted: {normalized!r}"
        )
    return normalized
