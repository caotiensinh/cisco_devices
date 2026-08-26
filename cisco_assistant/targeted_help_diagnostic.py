"""Sanitize safe-but-incomplete CBS250 targeted context-help evidence.

This module performs no network/device access. It accepts only summaries whose
transport/query safety invariants passed on the exact target. It may accept either
PASS_COMPLETE or BLOCKED_INCOMPLETE_EVIDENCE so the remaining grammar gap can be
identified without preserving hostnames, usernames, SSH metadata, credentials, or
raw transcripts.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any


EXPECTED_PRODUCT_ID = "CBS250-24T-4X"
EXPECTED_FIRMWARE_VERSION = "3.5.3.3"
EXPECTED_PREFIXES = (
    "show ip interface",
    "show ip route",
    "show ip route summary",
)
ALLOWED_STATUSES = frozenset({"PASS_COMPLETE", "BLOCKED_INCOMPLETE_EVIDENCE"})


class TargetedHelpDiagnosticError(ValueError):
    """Raised when diagnostic evidence is unsafe, malformed, or target-mismatched."""


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _require_false(mapping: dict[str, Any], key: str) -> None:
    if mapping.get(key) is not False:
        raise TargetedHelpDiagnosticError(f"Required false safety field missing or changed: {key}")


@dataclass(frozen=True, slots=True)
class TargetedHelpDiagnosticRecord:
    product_id: str
    firmware_version: str
    source_summary_sha256: str
    tool_version: str
    source_status: str
    prefixes: tuple[dict[str, object], ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "record_type": "TARGETED_CONTEXT_HELP_DIAGNOSTIC",
            "product_id": self.product_id,
            "firmware_version": self.firmware_version,
            "source_summary_sha256": self.source_summary_sha256,
            "tool_version": self.tool_version,
            "source_status": self.source_status,
            "evidence_status": "SAFE_DIAGNOSTIC_ONLY",
            "device_write_authority": False,
            "execution_authority": False,
            "collector_approval_authority": False,
            "prefixes": list(self.prefixes),
            "note": (
                "Sanitized exact-target context-help diagnostic only. Safe transport/query "
                "invariants passed, but this record does not authorize command execution or "
                "collector/allowlist promotion."
            ),
        }


def validate_targeted_help_diagnostic(payload: dict[str, Any]) -> TargetedHelpDiagnosticRecord:
    if payload.get("schema_version") != 1:
        raise TargetedHelpDiagnosticError("Unsupported targeted-help summary schema_version")
    status = str(payload.get("status", ""))
    if status not in ALLOWED_STATUSES:
        raise TargetedHelpDiagnosticError(f"Unsafe or unsupported source status: {status!r}")
    if payload.get("safety_status") != "PASS":
        raise TargetedHelpDiagnosticError("Targeted-help safety status is not PASS")

    target = payload.get("target")
    if not isinstance(target, dict):
        raise TargetedHelpDiagnosticError("Missing exact target binding")
    product_id = str(target.get("product_id", ""))
    firmware = str(target.get("firmware_version", ""))
    if product_id != EXPECTED_PRODUCT_ID or firmware != EXPECTED_FIRMWARE_VERSION:
        raise TargetedHelpDiagnosticError(
            "Targeted-help summary exact target mismatch: "
            f"received={product_id}/{firmware}, "
            f"required={EXPECTED_PRODUCT_ID}/{EXPECTED_FIRMWARE_VERSION}"
        )

    authority = payload.get("authority")
    if not isinstance(authority, dict):
        raise TargetedHelpDiagnosticError("Missing authority block")
    _require_false(authority, "device_write_authority")
    _require_false(authority, "production_network_write_authority")
    _require_false(authority, "candidate_execution_authority")

    safety = payload.get("safety")
    if not isinstance(safety, dict):
        raise TargetedHelpDiagnosticError("Missing safety block")
    _require_false(safety, "candidate_commands_executed")
    _require_false(safety, "help_query_submitted_with_enter")
    _require_false(safety, "config_mode_entered")
    if safety.get("disposable_channel_per_help_query") is not True:
        raise TargetedHelpDiagnosticError("Disposable channel safety invariant is missing")
    if safety.get("required_bytes_sent_after_help_marker") != 0:
        raise TargetedHelpDiagnosticError("Required post-help byte count is not zero")

    results = payload.get("results")
    if not isinstance(results, list) or len(results) != len(EXPECTED_PREFIXES):
        raise TargetedHelpDiagnosticError("Targeted-help results are missing or incomplete")

    by_prefix: dict[str, dict[str, Any]] = {}
    for result in results:
        if not isinstance(result, dict):
            raise TargetedHelpDiagnosticError("Malformed targeted-help result")
        prefix = str(result.get("prefix", ""))
        if prefix in by_prefix:
            raise TargetedHelpDiagnosticError(f"Duplicate targeted-help result: {prefix!r}")
        by_prefix[prefix] = result

    if set(by_prefix) != set(EXPECTED_PREFIXES):
        raise TargetedHelpDiagnosticError("Targeted-help result prefix set does not match policy")

    sanitized: list[dict[str, object]] = []
    for prefix in EXPECTED_PREFIXES:
        result = by_prefix[prefix]
        if result.get("candidate_command_executed") is not False:
            raise TargetedHelpDiagnosticError(f"Candidate execution invariant failed for {prefix}")
        if result.get("help_query_submitted_with_enter") is not False:
            raise TargetedHelpDiagnosticError(f"Help Enter invariant failed for {prefix}")
        if result.get("bytes_sent_after_help_marker") != 0:
            raise TargetedHelpDiagnosticError(f"Post-help byte invariant failed for {prefix}")
        if result.get("channel_closed_immediately") is not True:
            raise TargetedHelpDiagnosticError(f"Disposable channel close invariant failed for {prefix}")
        if result.get("error") is not None:
            raise TargetedHelpDiagnosticError(f"Targeted-help query reported an error for {prefix}")

        items = result.get("items")
        if not isinstance(items, list):
            raise TargetedHelpDiagnosticError(f"Missing help tokens for {prefix}")
        tokens: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                raise TargetedHelpDiagnosticError(f"Malformed help item for {prefix}")
            token = str(item.get("token", "")).strip()
            if not token:
                raise TargetedHelpDiagnosticError(f"Empty help token for {prefix}")
            if any(ch in token for ch in ("\r", "\n")):
                raise TargetedHelpDiagnosticError(f"Unsafe line break in help token for {prefix}")
            tokens.append(token)

        sanitized.append(
            {
                "prefix": prefix,
                "paginated": result.get("paginated") is True,
                "terminal_cr_observed": result.get("terminal_cr_observed") is True,
                "observed_tokens": tokens,
            }
        )

    digest = "sha256:" + hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return TargetedHelpDiagnosticRecord(
        product_id=product_id,
        firmware_version=firmware,
        source_summary_sha256=digest,
        tool_version=str(payload.get("tool_version", "unknown")),
        source_status=status,
        prefixes=tuple(sanitized),
    )


def ingest_targeted_help_diagnostic(path: str | Path) -> TargetedHelpDiagnosticRecord:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TargetedHelpDiagnosticError(f"Cannot read targeted-help summary {source}: {exc}") from exc
    if not isinstance(payload, dict):
        raise TargetedHelpDiagnosticError("Targeted-help summary root must be a JSON object")
    return validate_targeted_help_diagnostic(payload)
