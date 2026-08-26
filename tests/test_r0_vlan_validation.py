from __future__ import annotations

import json

import pytest

import cbs250_r0_vlan_validation as validation
from cbs250_safety import (
    HARD_DENY_EXEC_ROOTS,
    READ_ONLY_EXEC_ALLOWLIST,
    R0_VALIDATION_EXEC_ALLOWLIST,
    SafetyViolation,
    assert_r0_validation_executable,
)


def test_validation_allowlist_is_exactly_show_vlan_and_separate_from_collectors() -> None:
    validation.validate_static_policy()
    assert validation.VALIDATION_COMMAND == "show vlan"
    assert R0_VALIDATION_EXEC_ALLOWLIST == frozenset({"show vlan"})
    assert "show vlan" not in READ_ONLY_EXEC_ALLOWLIST
    assert READ_ONLY_EXEC_ALLOWLIST == frozenset({"show system", "show version", "show ip ssh"})


def test_validation_gate_rejects_every_other_candidate_or_mutation() -> None:
    assert assert_r0_validation_executable(" show   vlan ") == "show vlan"
    for command in (
        "show interfaces status",
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


def test_sanitized_live_result_does_not_export_names_or_port_membership() -> None:
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
    assert result["status"] == "PASS_LIVE_PARSER_VALIDATED"
    assert result["observed_vlan_ids"] == [1, 100]
    assert result["parsed_row_count"] == 2
    assert result["port_membership_exported"] is False
    assert result["vlan_names_exported"] is False
    assert "office" not in rendered
    assert "gi1" not in rendered
    assert result["authority"]["collector_execution_authority"] is False
    assert result["authority"]["validation_only_execution_authority"] is True


def test_parser_failure_blocks_validation_result() -> None:
    with pytest.raises(validation.VLANValidationError, match="parser validation failed"):
        validation.build_sanitized_result(
            {"product_id": "CBS250-24T-4X", "firmware_version": "3.5.3.3"},
            "not a vlan table",
        )
