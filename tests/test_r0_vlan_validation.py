from __future__ import annotations

import json

import pytest

import cbs250_r0_vlan_validation as validation
from cbs250_safety import (
    HARD_DENY_EXEC_ROOTS,
    READ_ONLY_EXEC_ALLOWLIST,
    READ_ONLY_PROMOTION_EVIDENCE,
    R0_VALIDATION_EXEC_ALLOWLIST,
    SafetyViolation,
    assert_r0_validation_executable,
)


def test_show_vlan_authority_was_transferred_to_collector_only() -> None:
    assert validation.validate_static_policy() == "PROMOTED_TO_COLLECTOR"
    assert validation.VALIDATION_COMMAND == "show vlan"
    assert "show vlan" not in R0_VALIDATION_EXEC_ALLOWLIST
    assert READ_ONLY_EXEC_ALLOWLIST == frozenset(
        {"show system", "show version", "show ip ssh", "show vlan"}
    )
    assert READ_ONLY_PROMOTION_EVIDENCE["show vlan"] == validation.PROMOTION_EVIDENCE_PATH


def test_retired_vlan_cannot_reenter_validation_only_authority() -> None:
    with pytest.raises(SafetyViolation):
        assert_r0_validation_executable("show vlan")
    assert assert_r0_validation_executable("show interfaces status") == "show interfaces status"
    for command in (
        "show ip route",
        "show vlan 10",
        "configure terminal",
        "reload",
        "write memory",
        "clear logging",
    ):
        with pytest.raises(SafetyViolation):
            assert_r0_validation_executable(command)


def test_validation_command_root_is_read_only_and_not_hard_denied() -> None:
    assert validation.VALIDATION_COMMAND.split()[0] == "show"
    assert validation.VALIDATION_COMMAND.split()[0] not in HARD_DENY_EXEC_ROOTS


def test_historical_sanitized_result_does_not_export_names_or_port_membership() -> None:
    sample = """
Vlan       Name           Ports          Type      Authorization
---------  -------------  -------------  --------  -------------
1          default        gi1,gi2        Default   Required
100        office         gi3            Static    Required
"""
    result = validation.build_sanitized_result(
        {"product_id": "CBS250-24T-4X", "firmware_version": "3.5.3.3"},
        sample,
    )
    rendered = json.dumps(result)
    assert result["schema_version"] == 2
    assert result["status"] == "PASS_LIVE_PARSER_VALIDATED"
    assert result["observed_vlan_ids"] == [1, 100]
    assert result["parsed_row_count"] == 2
    assert result["port_membership_exported"] is False
    assert result["vlan_names_exported"] is False
    assert result["raw_output_retained"] is False
    assert result["output_digest_scope"] == "CLEAN_TERMINAL_TEXT_UTF8"
    assert result["normalized_output_sha256"].startswith("sha256:")
    assert len(result["normalized_output_sha256"]) == len("sha256:") + 64
    assert "raw_output_sha256" not in result
    assert "office" not in rendered
    assert "gi1" not in rendered
    assert result["authority"]["collector_execution_authority"] is False
    assert result["authority"]["validation_only_execution_authority"] is True


def test_historical_normalized_digest_is_stable_for_same_cleaned_text() -> None:
    sample = """
Vlan       Name           Ports          Type      Authorization
---------  -------------  -------------  --------  -------------
1          default        gi1,gi2        Default   Required
"""
    target = {"product_id": "CBS250-24T-4X", "firmware_version": "3.5.3.3"}
    first = validation.build_sanitized_result(target, sample)
    second = validation.build_sanitized_result(target, sample)
    assert first["normalized_output_sha256"] == second["normalized_output_sha256"]


def test_historical_parser_failure_blocks_validation_record() -> None:
    with pytest.raises(validation.VLANValidationError, match="parser validation failed"):
        validation.build_sanitized_result(
            {"product_id": "CBS250-24T-4X", "firmware_version": "3.5.3.3"},
            "not a vlan table",
        )


def test_retired_main_path_is_policy_check_only() -> None:
    assert validation.main.__module__ == "cbs250_r0_vlan_validation"
