#!/usr/bin/env python3
"""Retired one-shot R0 evidence helper for the promoted ``show vlan`` command.

The exact live validation completed successfully for CBS250-24T-4X / 3.5.3.3 and its
sanitized evidence is committed under ``knowledge/cbs250/live``. The command is now owned
by the reviewed read-only collector authority, so this former validation lane contains no
SSH/device execution path and cannot run ``show vlan`` again.

``build_sanitized_result`` is retained only to regression-test the historical schema-v2
evidence contract. It does not grant collector or validation authority.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json

from cbs250_safety import (
    READ_ONLY_EXEC_ALLOWLIST,
    READ_ONLY_PROMOTION_EVIDENCE,
    R0_VALIDATION_EXEC_ALLOWLIST,
)
from cisco_assistant.documented_output_parsers import (
    DocumentedParserError,
    parse_documented_show_vlan,
)


TOOL_VERSION = "1.2.1"
SCHEMA_VERSION = 2
EXPECTED_PRODUCT_ID = "CBS250-24T-4X"
EXPECTED_FIRMWARE = "3.5.3.3"
VALIDATION_COMMAND = "show vlan"
OUTPUT_DIGEST_SCOPE = "CLEAN_TERMINAL_TEXT_UTF8"
PROMOTION_EVIDENCE_PATH = (
    "knowledge/cbs250/live/CBS250-24T-4X_3.5.3.3_20260827_show_vlan_r0_validation.json"
)
PROMOTION_STATE = "PROMOTED_TO_COLLECTOR"


class VLANValidationError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_static_policy() -> str:
    """Verify that show vlan authority remains collector-only after promotion."""
    if VALIDATION_COMMAND not in READ_ONLY_EXEC_ALLOWLIST:
        raise VLANValidationError("show vlan is not present in the reviewed collector allowlist")
    if VALIDATION_COMMAND in R0_VALIDATION_EXEC_ALLOWLIST:
        raise VLANValidationError(
            "show vlan must not retain validation-only authority after collector promotion"
        )
    if READ_ONLY_PROMOTION_EVIDENCE.get(VALIDATION_COMMAND) != PROMOTION_EVIDENCE_PATH:
        raise VLANValidationError("show vlan collector promotion evidence binding is missing")
    return PROMOTION_STATE


def build_sanitized_result(target: dict[str, str], text: str) -> dict[str, object]:
    """Build the historical schema-v2 sanitized validation record for regression tests."""
    try:
        rows = parse_documented_show_vlan(text)
    except DocumentedParserError as exc:
        raise VLANValidationError(f"Exact live show vlan parser validation failed: {exc}") from exc

    normalized_digest = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    vlan_ids = sorted({row.vlan_id for row in rows})
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": "R0_LIVE_OUTPUT_VALIDATION",
        "tool_version": "1.1.0",
        "generated_at_utc": utc_now(),
        "status": "PASS_LIVE_PARSER_VALIDATED",
        "target": target,
        "command": VALIDATION_COMMAND,
        "risk_class": "R0",
        "normalized_output_sha256": normalized_digest,
        "output_digest_scope": OUTPUT_DIGEST_SCOPE,
        "raw_output_retained": False,
        "parser": "parse_documented_show_vlan",
        "parser_result": "PASS",
        "parsed_row_count": len(rows),
        "observed_vlan_ids": vlan_ids,
        "port_membership_exported": False,
        "vlan_names_exported": False,
        "authority": {
            "device_write_authority": False,
            "production_network_write_authority": False,
            "collector_execution_authority": False,
            "validation_only_execution_authority": True,
        },
        "safety": {
            "configuration_mode_entered": False,
            "configuration_changed": False,
            "startup_config_changed": False,
            "reboot_or_reload_performed": False,
            "firmware_or_boot_state_changed": False,
            "specific_interface_command_executed": False,
            "pager_navigation_sent": False,
        },
        "note": (
            "Historical one-shot exact-live parser validation record. Passing did not itself "
            "grant collector authority; promotion was performed separately after review."
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Retired CBS250 show vlan R0 validation lane; policy-check only"
    )
    parser.add_argument("--policy-check", action="store_true")
    return parser.parse_args()


def policy_check() -> int:
    state = validate_static_policy()
    print(f"[PASS] show vlan authority state: {state}")
    print("[PASS] show vlan is absent from validation-only authority")
    print(f"[PASS] promotion evidence: {PROMOTION_EVIDENCE_PATH}")
    return 0


def main() -> int:
    args = parse_args()
    if args.policy_check:
        return policy_check()
    print(
        "[BLOCKED] show vlan validation-only execution is retired after collector promotion; "
        "use the reviewed read-only collector path instead"
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
