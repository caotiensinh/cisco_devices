import copy

import pytest

from cisco_assistant.targeted_help_evidence import (
    EXPECTED_PREFIXES,
    TargetedHelpEvidenceError,
    validate_targeted_help_summary,
)


def valid_summary():
    results = []
    for prefix in EXPECTED_PREFIXES:
        results.append(
            {
                "prefix": prefix,
                "query": f"{prefix} ?",
                "candidate_command_executed": False,
                "help_query_submitted_with_enter": False,
                "bytes_sent_after_help_marker": 0,
                "channel_closed_immediately": True,
                "paginated": False,
                "terminal_cr_observed": True,
                "items": [
                    {"token": "|", "description": "Output modifiers", "kind": "keyword", "risk": "read_only"},
                    {"token": "<CR>", "description": "", "kind": "terminal", "risk": "read_only"},
                ],
                "error": None,
            }
        )
    return {
        "schema_version": 1,
        "tool_version": "1.1.0",
        "status": "PASS_COMPLETE",
        "safety_status": "PASS",
        "evidence_status": "COMPLETE",
        "target": {
            "product_id": "CBS250-24T-4X",
            "firmware_version": "3.5.3.3",
        },
        "authority": {
            "device_write_authority": False,
            "production_network_write_authority": False,
            "candidate_execution_authority": False,
        },
        "safety": {
            "candidate_commands_executed": False,
            "help_query_submitted_with_enter": False,
            "disposable_channel_per_help_query": True,
            "required_bytes_sent_after_help_marker": 0,
            "config_mode_entered": False,
        },
        "results": results,
    }


def test_valid_summary_becomes_sanitized_help_only_record():
    record = validate_targeted_help_summary(valid_summary())
    payload = record.as_dict()

    assert record.product_id == "CBS250-24T-4X"
    assert record.firmware_version == "3.5.3.3"
    assert record.evidence_status == "OBSERVED_HELP_ONLY"
    assert record.source_summary_sha256.startswith("sha256:")
    assert payload["device_write_authority"] is False
    assert payload["execution_authority"] is False
    assert payload["collector_approval_authority"] is False
    assert [item["prefix"] for item in payload["prefixes"]] == list(EXPECTED_PREFIXES)
    assert all("<CR>" in item["observed_tokens"] for item in payload["prefixes"])
    rendered = str(payload)
    assert "username" not in rendered.casefold()
    assert "fingerprint" not in rendered.casefold()
    assert "192.168." not in rendered


def test_incomplete_top_level_status_is_rejected():
    payload = valid_summary()
    payload["status"] = "BLOCKED_INCOMPLETE_EVIDENCE"
    payload["evidence_status"] = "INCOMPLETE"
    with pytest.raises(TargetedHelpEvidenceError, match="not complete"):
        validate_targeted_help_summary(payload)


def test_exact_target_mismatch_is_rejected():
    payload = valid_summary()
    payload["target"]["firmware_version"] = "3.3.0.16"
    with pytest.raises(TargetedHelpEvidenceError, match="exact target mismatch"):
        validate_targeted_help_summary(payload)


def test_tampered_authority_is_rejected():
    for key in (
        "device_write_authority",
        "production_network_write_authority",
        "candidate_execution_authority",
    ):
        payload = valid_summary()
        payload["authority"][key] = True
        with pytest.raises(TargetedHelpEvidenceError, match="Required false safety field"):
            validate_targeted_help_summary(payload)


def test_tampered_global_safety_is_rejected():
    payload = valid_summary()
    payload["safety"]["candidate_commands_executed"] = True
    with pytest.raises(TargetedHelpEvidenceError, match="Required false safety field"):
        validate_targeted_help_summary(payload)

    payload = valid_summary()
    payload["safety"]["required_bytes_sent_after_help_marker"] = 1
    with pytest.raises(TargetedHelpEvidenceError, match="not zero"):
        validate_targeted_help_summary(payload)


def test_per_result_post_marker_bytes_are_rejected():
    payload = valid_summary()
    payload["results"][0]["bytes_sent_after_help_marker"] = 1
    with pytest.raises(TargetedHelpEvidenceError, match="Post-help byte invariant failed"):
        validate_targeted_help_summary(payload)


def test_paginated_or_missing_terminal_cr_is_rejected():
    payload = valid_summary()
    payload["results"][1]["paginated"] = True
    with pytest.raises(TargetedHelpEvidenceError, match="Paginated help is incomplete"):
        validate_targeted_help_summary(payload)

    payload = valid_summary()
    payload["results"][1]["terminal_cr_observed"] = False
    with pytest.raises(TargetedHelpEvidenceError, match="Terminal <CR> was not observed"):
        validate_targeted_help_summary(payload)

    payload = valid_summary()
    payload["results"][1]["items"] = [
        {"token": "|", "description": "Output modifiers", "kind": "keyword", "risk": "read_only"}
    ]
    with pytest.raises(TargetedHelpEvidenceError, match="tokens do not contain terminal <CR>"):
        validate_targeted_help_summary(payload)


def test_duplicate_or_missing_prefix_is_rejected():
    payload = valid_summary()
    payload["results"][1]["prefix"] = payload["results"][0]["prefix"]
    with pytest.raises(TargetedHelpEvidenceError, match="Duplicate targeted-help result"):
        validate_targeted_help_summary(payload)

    payload = valid_summary()
    payload["results"] = payload["results"][:-1]
    with pytest.raises(TargetedHelpEvidenceError, match="missing or incomplete"):
        validate_targeted_help_summary(payload)


def test_line_break_in_token_is_rejected():
    payload = valid_summary()
    payload["results"][0]["items"][0]["token"] = "unsafe\nreload"
    with pytest.raises(TargetedHelpEvidenceError, match="Unsafe line break"):
        validate_targeted_help_summary(payload)


def test_digest_changes_if_summary_content_changes():
    first = validate_targeted_help_summary(valid_summary())
    changed = copy.deepcopy(valid_summary())
    changed["tool_version"] = "1.1.1"
    second = validate_targeted_help_summary(changed)
    assert first.source_summary_sha256 != second.source_summary_sha256
