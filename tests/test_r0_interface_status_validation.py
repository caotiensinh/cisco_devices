from __future__ import annotations

import json

import pytest

import cbs250_r0_interface_status_validation as validation
from cbs250_safety import (
    READ_ONLY_EXEC_ALLOWLIST,
    R0_VALIDATION_EXEC_ALLOWLIST,
    SafetyViolation,
    assert_r0_validation_executable,
)


def test_validation_allowlist_is_exact_candidate_and_separate_from_collectors() -> None:
    validation.validate_static_policy()
    assert validation.VALIDATION_COMMAND == "show interfaces status"
    assert R0_VALIDATION_EXEC_ALLOWLIST == frozenset({"show interfaces status"})
    assert "show interfaces status" not in READ_ONLY_EXEC_ALLOWLIST
    assert "show vlan" in READ_ONLY_EXEC_ALLOWLIST


def test_validation_gate_rejects_selectors_other_candidates_and_mutations() -> None:
    assert assert_r0_validation_executable(" show   interfaces   status ") == "show interfaces status"
    for command in (
        "show interfaces status ge1",
        "show interfaces switchport",
        "show interfaces counters",
        "configure terminal",
        "shutdown",
        "reload",
        "write memory",
        "clear logging",
    ):
        with pytest.raises(SafetyViolation):
            assert_r0_validation_executable(command)


def test_sanitized_result_exports_only_aggregate_status_metadata() -> None:
    sample = """
Port    Type       Duplex  Speed  Neg       Flow  Link  Back      Mdix
ge1     1G-Copper  Full    1000   Enabled   Off   Up    Disabled  Off
ge2     1G-Copper  Full    1000   Enabled   Off   Down  Disabled  Off
xg1     10G-Fiber  Full    10000  Disabled  Off   Up    Disabled  --
PO      Type       Speed   Neg    Flow      Admin
Po1     1G         1000    Off    Off       Up
"""
    result = validation.build_sanitized_result(
        {"product_id": "CBS250-24T-4X", "firmware_version": "3.5.3.3"},
        sample,
    )
    rendered = json.dumps(result)
    assert result["schema_version"] == 2
    assert result["status"] == "PASS_LIVE_PARSER_VALIDATED"
    assert result["parsed_physical_row_count"] == 3
    assert result["link_state_counts"] == {"Down": 1, "Up": 2}
    assert result["interface_ids_exported"] is False
    assert result["media_details_exported"] is False
    assert result["speed_details_exported"] is False
    assert result["port_membership_exported"] is False
    assert result["authority"]["collector_execution_authority"] is False
    assert result["authority"]["validation_only_execution_authority"] is True
    assert result["safety"]["specific_interface_command_executed"] is False
    assert result["safety"]["interface_state_changed"] is False
    for sensitive in ("ge1", "ge2", "xg1", "1G-Copper", "10G-Fiber", "10000"):
        assert sensitive not in rendered


def test_parser_failure_blocks_validation_result() -> None:
    with pytest.raises(validation.InterfaceStatusValidationError, match="parser validation failed"):
        validation.build_sanitized_result(
            {"product_id": "CBS250-24T-4X", "firmware_version": "3.5.3.3"},
            "not an interface status table",
        )
