from __future__ import annotations

import json
from pathlib import Path

import pytest

from cisco_assistant.targeted_help_diagnostic import (
    TargetedHelpDiagnosticError,
    validate_targeted_help_diagnostic,
)


def _payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "tool_version": "1.1.0",
        "status": "BLOCKED_INCOMPLETE_EVIDENCE",
        "safety_status": "PASS",
        "evidence_status": "INCOMPLETE",
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
        "host": "192.0.2.10",
        "username": "secret-user",
        "ssh_fingerprint": "secret-fingerprint",
        "results": [
            {
                "prefix": "show ip interface",
                "candidate_command_executed": False,
                "help_query_submitted_with_enter": False,
                "bytes_sent_after_help_marker": 0,
                "channel_closed_immediately": True,
                "paginated": False,
                "terminal_cr_observed": True,
                "items": [{"token": "<CR>", "description": "", "kind": "terminal", "risk": "R0"}],
                "error": None,
            },
            {
                "prefix": "show ip route",
                "candidate_command_executed": False,
                "help_query_submitted_with_enter": False,
                "bytes_sent_after_help_marker": 0,
                "channel_closed_immediately": True,
                "paginated": False,
                "terminal_cr_observed": False,
                "items": [{"token": "summary", "description": "", "kind": "keyword", "risk": "R0"}],
                "error": None,
            },
            {
                "prefix": "show ip route summary",
                "candidate_command_executed": False,
                "help_query_submitted_with_enter": False,
                "bytes_sent_after_help_marker": 0,
                "channel_closed_immediately": True,
                "paginated": True,
                "terminal_cr_observed": False,
                "items": [{"token": "<CR>", "description": "", "kind": "terminal", "risk": "R0"}],
                "error": None,
            },
        ],
    }


def test_accepts_safe_incomplete_evidence_and_strips_sensitive_fields() -> None:
    record = validate_targeted_help_diagnostic(_payload()).as_dict()
    rendered = json.dumps(record)

    assert record["source_status"] == "BLOCKED_INCOMPLETE_EVIDENCE"
    assert record["device_write_authority"] is False
    assert record["execution_authority"] is False
    assert "192.0.2.10" not in rendered
    assert "secret-user" not in rendered
    assert "secret-fingerprint" not in rendered


def test_rejects_any_post_help_bytes() -> None:
    payload = _payload()
    payload["results"][1]["bytes_sent_after_help_marker"] = 1  # type: ignore[index]
    with pytest.raises(TargetedHelpDiagnosticError, match="Post-help byte invariant failed"):
        validate_targeted_help_diagnostic(payload)


def test_rejects_safety_blocked_status() -> None:
    payload = _payload()
    payload["status"] = "BLOCKED_SAFETY"
    payload["safety_status"] = "BLOCKED"
    with pytest.raises(TargetedHelpDiagnosticError, match="Unsafe or unsupported source status"):
        validate_targeted_help_diagnostic(payload)


def test_rejects_target_mismatch() -> None:
    payload = _payload()
    payload["target"]["firmware_version"] = "3.3.0.16"  # type: ignore[index]
    with pytest.raises(TargetedHelpDiagnosticError, match="exact target mismatch"):
        validate_targeted_help_diagnostic(payload)
