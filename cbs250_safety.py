"""Safety policy for CBS250 investigation-only discovery and reviewed R0 collection."""
from __future__ import annotations

VERSION = "3.2.1"


class SafetyViolation(RuntimeError):
    """Raised when execution is outside the investigation/read-only policy."""


# Collector/runtime execution authority. Commands enter this set only after exact-live
# output validation, parser regression coverage, sanitized evidence, and explicit promotion.
READ_ONLY_EXEC_ALLOWLIST = frozenset({
    "show version",
    "show system",
    "show ip ssh",
    "show vlan",
})

# Traceability for commands promoted after controlled exact-live validation. Baseline identity
# commands predate this promotion ledger; new collector commands must carry an evidence path.
READ_ONLY_PROMOTION_EVIDENCE = {
    "show vlan": "knowledge/cbs250/live/CBS250-24T-4X_3.5.3.3_20260827_show_vlan_r0_validation.json",
}

# Narrow one-shot validation authority. It is intentionally disjoint from collector/runtime
# authority. Candidates remain here only while exact-live output/parser validation is pending.
R0_VALIDATION_EXEC_ALLOWLIST = frozenset({
    "show interfaces status",
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
    """Authorize only an exact temporary R0 live-output validation candidate.

    Validation-only authority and collector/runtime authority must never overlap.
    """
    normalized = normalize_command(command)
    _assert_not_hard_denied(normalized)
    if normalized in READ_ONLY_EXEC_ALLOWLIST:
        raise SafetyViolation(
            f"R0 validation candidate is already collector-allowlisted: {normalized!r}"
        )
    if normalized not in R0_VALIDATION_EXEC_ALLOWLIST:
        raise SafetyViolation(
            f"Command is not in exact R0 validation-only allowlist: {normalized!r}"
        )
    return normalized


if set(READ_ONLY_EXEC_ALLOWLIST) & set(R0_VALIDATION_EXEC_ALLOWLIST):
    raise RuntimeError("Collector and R0 validation-only authority must remain disjoint")
if not set(READ_ONLY_PROMOTION_EVIDENCE).issubset(READ_ONLY_EXEC_ALLOWLIST):
    raise RuntimeError("Promotion evidence registry contains a non-collector command")
