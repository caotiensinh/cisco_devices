from __future__ import annotations

from copy import deepcopy

from cisco_assistant.r0_validation_promotion import evaluate_r0_validation_evidence


def valid_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "record_type": "R0_LIVE_OUTPUT_VALIDATION",
        "tool_version": "1.0.0",
        "status": "PASS_LIVE_PARSER_VALIDATED",
        "target": {
            "product_id": "CBS250-24T-4X",
            "firmware_version": "3.5.3.3",
        },
        "command": "show vlan",
        "risk_class": "R0",
        "raw_output_sha256": "sha256:" + "a" * 64,
        "raw_output_retained": False,
        "parser": "parse_documented_show_vlan",
        "parser_result": "PASS",
        "parsed_row_count": 2,
        "observed_vlan_ids": [1, 100],
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
    }


def test_valid_sanitized_evidence_is_only_eligible_for_separate_promotion_review() -> None:
    decision = evaluate_r0_validation_evidence(valid_payload())
    assert decision.eligible_for_promotion_review is True
    assert decision.reasons == ()
    assert decision.command == "show vlan"
    assert decision.product_id == "CBS250-24T-4X"
    assert decision.firmware_version == "3.5.3.3"


def test_wrong_exact_target_fails_closed() -> None:
    payload = valid_payload()
    payload["target"] = {"product_id": "CBS250-24T-4X", "firmware_version": "3.5.3.2"}
    decision = evaluate_r0_validation_evidence(payload)
    assert decision.eligible_for_promotion_review is False
    assert "firmware_mismatch" in decision.reasons


def test_raw_or_sensitive_exports_fail_closed() -> None:
    for key in ("raw_output_retained", "port_membership_exported", "vlan_names_exported"):
        payload = valid_payload()
        payload[key] = True
        decision = evaluate_r0_validation_evidence(payload)
        assert decision.eligible_for_promotion_review is False


def test_any_write_or_collector_authority_fails_closed() -> None:
    mutations = (
        ("device_write_authority", True),
        ("production_network_write_authority", True),
        ("collector_execution_authority", True),
        ("validation_only_execution_authority", False),
    )
    for key, value in mutations:
        payload = valid_payload()
        authority = deepcopy(payload["authority"])
        assert isinstance(authority, dict)
        authority[key] = value
        payload["authority"] = authority
        decision = evaluate_r0_validation_evidence(payload)
        assert decision.eligible_for_promotion_review is False
        assert any(key in reason for reason in decision.reasons)


def test_any_safety_side_effect_signal_fails_closed() -> None:
    payload = valid_payload()
    safety = deepcopy(payload["safety"])
    assert isinstance(safety, dict)
    safety["configuration_changed"] = True
    payload["safety"] = safety
    decision = evaluate_r0_validation_evidence(payload)
    assert decision.eligible_for_promotion_review is False
    assert "safety_configuration_changed_invalid" in decision.reasons


def test_missing_safety_field_fails_closed() -> None:
    payload = valid_payload()
    safety = deepcopy(payload["safety"])
    assert isinstance(safety, dict)
    safety.pop("pager_navigation_sent")
    payload["safety"] = safety
    decision = evaluate_r0_validation_evidence(payload)
    assert decision.eligible_for_promotion_review is False
    assert "safety_pager_navigation_sent_invalid" in decision.reasons


def test_hash_rows_and_vlan_ids_are_strictly_validated() -> None:
    bad_payloads = []

    payload = valid_payload()
    payload["raw_output_sha256"] = "sha256:not-a-real-digest"
    bad_payloads.append(payload)

    payload = valid_payload()
    payload["parsed_row_count"] = 0
    bad_payloads.append(payload)

    payload = valid_payload()
    payload["observed_vlan_ids"] = [100, 1]
    bad_payloads.append(payload)

    payload = valid_payload()
    payload["observed_vlan_ids"] = [1, 1]
    bad_payloads.append(payload)

    payload = valid_payload()
    payload["observed_vlan_ids"] = [0]
    bad_payloads.append(payload)

    for payload in bad_payloads:
        assert evaluate_r0_validation_evidence(payload).eligible_for_promotion_review is False


def test_pass_status_alone_is_not_enough() -> None:
    payload = valid_payload()
    payload["parser_result"] = "FAIL"
    payload["authority"] = {}
    decision = evaluate_r0_validation_evidence(payload)
    assert decision.eligible_for_promotion_review is False
    assert "parser_result_not_pass" in decision.reasons
    assert decision.reasons
