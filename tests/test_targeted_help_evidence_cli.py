import json

import pytest

from cbs250_targeted_help_evidence_ingest import build_sanitized_payload
from cisco_assistant.targeted_help_evidence import EXPECTED_PREFIXES, TargetedHelpEvidenceError


def write_summary(path, *, status="PASS_COMPLETE"):
    payload = {
        "schema_version": 1,
        "tool_version": "1.1.0",
        "status": status,
        "safety_status": "PASS",
        "evidence_status": "COMPLETE" if status == "PASS_COMPLETE" else "INCOMPLETE",
        "target": {
            "product_id": "CBS250-24T-4X",
            "firmware_version": "3.5.3.3",
        },
        "device": {
            "host": "192.168.11.6",
            "username": "admin",
            "ssh_fingerprint": "SHA256:not-for-export",
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
        "results": [
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
            for prefix in EXPECTED_PREFIXES
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_cli_builds_sanitized_payload_without_connection_identity(tmp_path):
    path = tmp_path / "summary.json"
    write_summary(path)
    payload = build_sanitized_payload(str(path))
    rendered = json.dumps(payload)

    assert payload["record_type"] == "TARGETED_CONTEXT_HELP_GRAMMAR"
    assert payload["evidence_status"] == "OBSERVED_HELP_ONLY"
    assert payload["execution_authority"] is False
    assert payload["device_write_authority"] is False
    assert "192.168.11.6" not in rendered
    assert "admin" not in rendered
    assert "not-for-export" not in rendered
    assert "ssh_fingerprint" not in rendered


def test_cli_blocks_incomplete_summary(tmp_path):
    path = tmp_path / "summary.json"
    write_summary(path, status="BLOCKED_INCOMPLETE_EVIDENCE")

    with pytest.raises(TargetedHelpEvidenceError, match="not complete"):
        build_sanitized_payload(str(path))
