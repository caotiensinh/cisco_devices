import json
from pathlib import Path

from cbs250_safety import READ_ONLY_EXEC_ALLOWLIST


ROOT = Path(__file__).resolve().parents[1]
DIFF_PATH = ROOT / "knowledge" / "cbs250" / "documented_vs_observed_planner_diff_3.5.3.3.json"


def load_diff():
    return json.loads(DIFF_PATH.read_text(encoding="utf-8"))


def entries_by_command():
    return {entry["collector_command"]: entry for entry in load_diff()["states"]}


def test_planner_diff_is_scoped_and_grants_no_authority():
    payload = load_diff()
    assert payload["scope"]["coverage"] == "PLANNER_CRITICAL_SUBSET"
    assert payload["scope"]["complete_family_capability_diff"] is False
    assert payload["scope"]["live_dataset_coverage"] == (
        "TRUNCATED_AT_MAX_NODES_PLUS_TARGETED_HELP_PLUS_R0_LIVE_OUTPUT"
    )

    authority = payload["authority"]
    assert authority["device_write_authority"] is False
    assert authority["execution_authority"] is False
    assert authority["documented_support_grants_execution_authority"] is False
    assert authority["missing_live_help_proves_unsupported"] is False


def test_l3_documented_commands_are_help_observed_but_still_unallowlisted():
    entries = entries_by_command()
    for command in ("show ip interface", "show ip route", "show ip route summary"):
        entry = entries[command]
        assert entry["documentation_state"] == "DOCUMENTED"
        assert entry["live_execution_state"] == "MISSING"
        assert command not in READ_ONLY_EXEC_ALLOWLIST
        assert "UNSUPPORTED" not in entry["live_help_state"]


def test_vlan_is_live_validated_and_collector_approved():
    entry = entries_by_command()["show vlan"]
    assert entry["live_help_state"] == "OBSERVED_TERMINAL_CR"
    assert entry["live_execution_state"] == "OBSERVED_AND_CURRENTLY_ALLOWLISTED"
    assert entry["parser_state"] == "EXACT_LIVE_3_5_3_3_VALIDATED"
    assert entry["planner_state"] == "READ_ONLY_COLLECTOR_APPROVED_PARTIAL_SCOPE"
    assert "show vlan" in READ_ONLY_EXEC_ALLOWLIST


def test_pending_port_commands_remain_help_observed_but_not_collectors():
    entries = entries_by_command()
    for command in ("show interfaces status", "show interfaces switchport"):
        entry = entries[command]
        assert entry["live_help_state"] == "OBSERVED_TERMINAL_CR"
        assert entry["live_execution_state"] == "MISSING"
        assert entry["parser_state"] == "DOCUMENTED_FORMAT_ONLY"
        assert entry["planner_state"] == "BLOCKED_MISSING_EXACT_LIVE_OUTPUT"
        assert command not in READ_ONLY_EXEC_ALLOWLIST


def test_current_approved_execution_subset_is_exactly_four_commands():
    entries = entries_by_command()
    assert entries["show version"]["live_execution_state"] == "OBSERVED_AND_CURRENTLY_ALLOWLISTED"
    assert entries["show ip ssh"]["live_execution_state"] == "OBSERVED_AND_CURRENTLY_ALLOWLISTED"
    assert READ_ONLY_EXEC_ALLOWLIST == frozenset(
        {"show version", "show system", "show ip ssh", "show vlan"}
    )


def test_sensitive_running_config_remains_held():
    entry = entries_by_command()["show running-config brief"]
    assert entry["live_execution_state"] == "NOT_AUTHORIZED"
    assert entry["parser_state"] == "BLOCKED_SENSITIVITY_REVIEW"
    assert entry["planner_state"] == "HOLD_SENSITIVE_OUTPUT_REVIEW"
    assert "show running-config brief" not in READ_ONLY_EXEC_ALLOWLIST
