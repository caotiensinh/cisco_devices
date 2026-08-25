"""Offline validation and sanitization of targeted CBS250 context-help summaries.

The input is a summary JSON produced by ``cbs250_targeted_help_probe.py``. This module performs
no device/network access. It accepts only exact-target ``PASS_COMPLETE`` evidence whose safety
invariants are explicit, then returns a sanitized grammar record without hostnames, usernames,
SSH fingerprints, raw transcripts, or credentials.
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


class TargetedHelpEvidenceError(ValueError):
    """Raised when targeted-help evidence is incomplete, unsafe, or target-mismatched."""


@dataclass(frozen=True, slots=True)
class TargetedHelpGrammarRecord:
    product_id: str
    firmware_version: str
    source_summary_sha256: str
    tool_version: str
    prefixes: tuple[tuple[str, tuple[str, ...]], ...]
    evidence_status: str = "OBSERVED_HELP_ONLY"
    device_write_authority: bool = False
    execution_authority: bool = False
    collector_approval_authority: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "record_type": "TARGETED_CONTEXT_HELP_GRAMMAR",
            "product_id": self.product_id,
            "firmware_version": self.firmware_version,
            "source_summary_sha256": self.source_summary_sha256,
            "tool_version": self.tool_version,
            "evidence_status": self.evidence_status,
            "device_write_authority": False,
            "execution_authority": False,
            "collector_approval_authority": False,
            "prefixes": [
                {"prefix": prefix, "observed_tokens": list(tokens)}
                for prefix, tokens in self.prefixes
            ],
            "note": (
                "Sanitized exact-target context-help evidence only. It does not prove live "
                "command execution and does not authorize collector or allowlist promotion."
            ),
        }


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _require_false(mapping: dict[str, Any], key: str) -> None:
    if mapping.get(key) is not False:
        raise TargetedHelpEvidenceError(f"Required false safety field missing or changed: {key}")


def validate_targeted_help_summary(payload: dict[str, Any]) -> TargetedHelpGrammarRecord:
    if payload.get("schema_version") != 1:
        raise TargetedHelpEvidenceError("Unsupported targeted-help summary schema_version")
    if payload.get("status") != "PASS_COMPLETE":
        raise TargetedHelpEvidenceError(
            f"Targeted-help evidence is not complete: status={payload.get('status')!r}"
        )
    if payload.get("safety_status") != "PASS" or payload.get("evidence_status") != "COMPLETE":
        raise TargetedHelpEvidenceError("Targeted-help safety/evidence status is not PASS/COMPLETE")

    target = payload.get("target")
    if not isinstance(target, dict):
        raise TargetedHelpEvidenceError("Missing exact target binding")
    product_id = str(target.get("product_id", ""))
    firmware = str(target.get("firmware_version", ""))
    if product_id != EXPECTED_PRODUCT_ID or firmware != EXPECTED_FIRMWARE_VERSION:
        raise TargetedHelpEvidenceError(
            "Targeted-help summary exact target mismatch: "
            f"received={product_id}/{firmware}, "
            f"required={EXPECTED_PRODUCT_ID}/{EXPECTED_FIRMWARE_VERSION}"
        )

    authority = payload.get("authority")
    if not isinstance(authority, dict):
        raise TargetedHelpEvidenceError("Missing authority block")
    _require_false(authority, "device_write_authority")
    _require_false(authority, "production_network_write_authority")
    _require_false(authority, "candidate_execution_authority")

    safety = payload.get("safety")
    if not isinstance(safety, dict):
        raise TargetedHelpEvidenceError("Missing safety block")
    _require_false(safety, "candidate_commands_executed")
    _require_false(safety, "help_query_submitted_with_enter")
    _require_false(safety, "config_mode_entered")
    if safety.get("disposable_channel_per_help_query") is not True:
        raise TargetedHelpEvidenceError("Disposable channel safety invariant is missing")
    if safety.get("required_bytes_sent_after_help_marker") != 0:
        raise TargetedHelpEvidenceError("Required post-help byte count is not zero")

    results = payload.get("results")
    if not isinstance(results, list) or len(results) != len(EXPECTED_PREFIXES):
        raise TargetedHelpEvidenceError("Targeted-help results are missing or incomplete")

    by_prefix: dict[str, dict[str, Any]] = {}
    for result in results:
        if not isinstance(result, dict):
            raise TargetedHelpEvidenceError("Malformed targeted-help result")
        prefix = str(result.get("prefix", ""))
        if prefix in by_prefix:
            raise TargetedHelpEvidenceError(f"Duplicate targeted-help result: {prefix!r}")
        by_prefix[prefix] = result

    if set(by_prefix) != set(EXPECTED_PREFIXES):
        raise TargetedHelpEvidenceError("Targeted-help result prefix set does not match policy")

    sanitized: list[tuple[str, tuple[str, ...]]] = []
    for prefix in EXPECTED_PREFIXES:
        result = by_prefix[prefix]
        if result.get("candidate_command_executed") is not False:
            raise TargetedHelpEvidenceError(f"Candidate execution invariant failed for {prefix}")
        if result.get("help_query_submitted_with_enter") is not False:
            raise TargetedHelpEvidenceError(f"Help Enter invariant failed for {prefix}")
        if result.get("bytes_sent_after_help_marker") != 0:
            raise TargetedHelpEvidenceError(f"Post-help byte invariant failed for {prefix}")
        if result.get("channel_closed_immediately") is not True:
            raise TargetedHelpEvidenceError(f"Disposable channel close invariant failed for {prefix}")
        if result.get("paginated") is not False:
            raise TargetedHelpEvidenceError(f"Paginated help is incomplete for {prefix}")
        if result.get("terminal_cr_observed") is not True:
            raise TargetedHelpEvidenceError(f"Terminal <CR> was not observed for {prefix}")
        if result.get("error") is not None:
            raise TargetedHelpEvidenceError(f"Targeted-help query reported an error for {prefix}")

        items = result.get("items")
        if not isinstance(items, list):
            raise TargetedHelpEvidenceError(f"Missing help tokens for {prefix}")
        tokens: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                raise TargetedHelpEvidenceError(f"Malformed help item for {prefix}")
            token = str(item.get("token", "")).strip()
            if not token:
                raise TargetedHelpEvidenceError(f"Empty help token for {prefix}")
            if any(ch in token for ch in ("\r", "\n")):
                raise TargetedHelpEvidenceError(f"Unsafe line break in help token for {prefix}")
            tokens.append(token)
        if "<CR>" not in tokens:
            raise TargetedHelpEvidenceError(f"Sanitized tokens do not contain terminal <CR> for {prefix}")
        sanitized.append((prefix, tuple(tokens)))

    digest = "sha256:" + hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return TargetedHelpGrammarRecord(
        product_id=product_id,
        firmware_version=firmware,
        source_summary_sha256=digest,
        tool_version=str(payload.get("tool_version", "unknown")),
        prefixes=tuple(sanitized),
    )


def ingest_targeted_help_summary(path: str | Path) -> TargetedHelpGrammarRecord:
    summary_path = Path(path)
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TargetedHelpEvidenceError(f"Cannot read targeted-help summary {summary_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise TargetedHelpEvidenceError("Targeted-help summary root must be a JSON object")
    return validate_targeted_help_summary(payload)
