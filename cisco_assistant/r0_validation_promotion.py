"""Offline fail-closed review gate for R0 live-output validation evidence.

This module never connects to a device and never mutates execution allowlists.  It only
answers whether a sanitized validation artifact is structurally eligible for a separate
human/code-review promotion decision.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping, Sequence


EXPECTED_SCHEMA_VERSION = 1
EXPECTED_RECORD_TYPE = "R0_LIVE_OUTPUT_VALIDATION"
EXPECTED_STATUS = "PASS_LIVE_PARSER_VALIDATED"
EXPECTED_COMMAND = "show vlan"
EXPECTED_PRODUCT_ID = "CBS250-24T-4X"
EXPECTED_FIRMWARE = "3.5.3.3"
EXPECTED_PARSER = "parse_documented_show_vlan"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class PromotionReviewDecision:
    eligible_for_promotion_review: bool
    reasons: tuple[str, ...]
    command: str
    product_id: str
    firmware_version: str


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _bool_is(mapping: Mapping[str, object], key: str, expected: bool) -> bool:
    return mapping.get(key) is expected


def _valid_vlan_ids(value: object) -> bool:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return False
    values = list(value)
    if not values:
        return False
    if any(type(item) is not int or not 1 <= item <= 4094 for item in values):
        return False
    return values == sorted(set(values))


def evaluate_r0_validation_evidence(payload: Mapping[str, object]) -> PromotionReviewDecision:
    """Return a fail-closed review decision for sanitized ``show vlan`` evidence.

    ``eligible_for_promotion_review`` is deliberately weaker than collector promotion.
    A true result means only that the sanitized artifact satisfies the evidence contract;
    regression fixtures, parser review, sensitivity review, and an explicit allowlist
    change are still separate required actions.
    """

    reasons: list[str] = []
    target = _mapping(payload.get("target"))
    authority = _mapping(payload.get("authority"))
    safety = _mapping(payload.get("safety"))

    command = str(payload.get("command") or "")
    product_id = str(target.get("product_id") or "")
    firmware = str(target.get("firmware_version") or "")

    if payload.get("schema_version") != EXPECTED_SCHEMA_VERSION:
        reasons.append("schema_version_mismatch")
    if payload.get("record_type") != EXPECTED_RECORD_TYPE:
        reasons.append("record_type_mismatch")
    if payload.get("status") != EXPECTED_STATUS:
        reasons.append("validation_status_not_pass")
    if command != EXPECTED_COMMAND:
        reasons.append("command_mismatch")
    if product_id != EXPECTED_PRODUCT_ID:
        reasons.append("product_id_mismatch")
    if firmware != EXPECTED_FIRMWARE:
        reasons.append("firmware_mismatch")
    if payload.get("risk_class") != "R0":
        reasons.append("risk_class_mismatch")
    if payload.get("parser") != EXPECTED_PARSER:
        reasons.append("parser_mismatch")
    if payload.get("parser_result") != "PASS":
        reasons.append("parser_result_not_pass")
    if type(payload.get("parsed_row_count")) is not int or int(payload.get("parsed_row_count", 0)) <= 0:
        reasons.append("parsed_row_count_invalid")
    if not _valid_vlan_ids(payload.get("observed_vlan_ids")):
        reasons.append("observed_vlan_ids_invalid")
    if payload.get("raw_output_retained") is not False:
        reasons.append("raw_output_retained")
    if not isinstance(payload.get("raw_output_sha256"), str) or not SHA256_RE.fullmatch(str(payload.get("raw_output_sha256"))):
        reasons.append("raw_output_sha256_invalid")
    if payload.get("port_membership_exported") is not False:
        reasons.append("port_membership_exported")
    if payload.get("vlan_names_exported") is not False:
        reasons.append("vlan_names_exported")

    required_authority = {
        "device_write_authority": False,
        "production_network_write_authority": False,
        "collector_execution_authority": False,
        "validation_only_execution_authority": True,
    }
    for key, expected in required_authority.items():
        if not _bool_is(authority, key, expected):
            reasons.append(f"authority_{key}_invalid")

    required_false_safety = (
        "configuration_mode_entered",
        "configuration_changed",
        "startup_config_changed",
        "reboot_or_reload_performed",
        "firmware_or_boot_state_changed",
        "specific_interface_command_executed",
        "pager_navigation_sent",
    )
    for key in required_false_safety:
        if not _bool_is(safety, key, False):
            reasons.append(f"safety_{key}_invalid")

    return PromotionReviewDecision(
        eligible_for_promotion_review=not reasons,
        reasons=tuple(reasons),
        command=command,
        product_id=product_id,
        firmware_version=firmware,
    )
