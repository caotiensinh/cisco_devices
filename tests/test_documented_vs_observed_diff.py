import json
from pathlib import Path

from cbs250_safety import READ_ONLY_EXEC_ALLOWLIST


ROOT = Path(__file__).resolve().parents[1]
DIFF_PATH = (
    ROOT
    / "knowledge"
    / "cbs250"
    / "documented_vs_observed_planner_diff_3.5.3.3.json"
)


def load_diff():
    return json.loads(DIFF_PATH.read_text(encoding="utf-8"))


def entries_by_command():
    return {
        entry["collector_command"]: entry
        for entry in load_diff()["states"]
    }


def test_planner_diff_is_scoped_and_grants_no_authority():
    payload = load_diff()
    assert payload["scope"]["coverage"] == "PLANNER_CRITICAL_SUBSET"
    assert payload["scope"]["complete_family_capability_diff"] is False
    assert payload["scope"]["live_dataset_coverage"] == (
        "TRUNCATED_AT_MAX_NODES_PLUS_TARGETED_HELP"
    )

    authority = payload["authority"]
    assert authority["device_write_authority"] is False
    assert authority["execution_authority"] is False
    assert authority["documented_support_grants_execution_authority"] is False
    assert authority["missing_live_help_proves_unsupported"] is False


def test_l3_documented_commands_are_help_observed_but_still_unallowlisted():
    entries = entries_by_command()

    interface_entry = entries["show ip interface"]
    route_entry = entries["show ip route"]
    summary_entry = entries["show ip route summary"]

    for command, entry in (
        ("show ip interface", interface_entry),
        ("show ip route", route_entry),
        ("show ip route summary", summary_entry),
    ):
        assert entry["documentation_state"] == "DOCUMENTED"
        assert entry["live_execution_state"] == "MISSING"
        assert command not in READ_ONLY_EXEC_ALLOWLIST
        assert "UNSUPPORTED" not in entry["live_help_state"]

    assert interface_entry["live_help_state"] == (
        "OBSERVED_NONTERMINAL_HELP_REQUIRES_SELECTOR"
    )
    assert route_entry["live_help_state"] == (
        "OBSERVED_NONTERMINAL_HELP_REQUIRES_SELECTOR"
    )
    assert summary_entry["live_help_state"] == (
        "OBSERVED_FILTER_ONLY_HELP_NO_TERMINAL_CR"
    )


def test_priority_vlan_and_port_commands_are_help_observed_but_not_executable():
    entries = entries_by_command()
    for command in ("show vlan", "show interfaces status", "show interfaces switchport"):
        entry = entries[command]
        assert entry["live_help_state"] == "OBSERVED_TERMINAL_CR"
        assert entry["live_execution_state"] == "MISSING"
        assert entry["parser_state"] == "DOCUMENTED_FORMAT_ONLY"
        assert entry["planner_state"] == "BLOCKED_MISSING_EXACT_LIVE_OUTPUT"
        assert command not in READ_ONLY_EXEC_ALLOWLIST


def test_existing_three_command_inventory_remains_the_only_approved_execution_subset_here():
    entries = entries_by_command()
    assert entries["show version"]["live_execution_state"] == (
        "OBSERVED_AND_CURRENTLY_ALLOWLISTED"
    )
    assert entries["show ip ssh"]["live_execution_state"] == (
        "OBSERVED_AND_CURRENTLY_ALLOWLISTED"
    )
    assert "show version" in READ_ONLY_EXEC_ALLOWLIST
    assert "show ip ssh" in READ_ONLY_EXEC_ALLOWLIST
    assert READ_ONLY_EXEC_ALLOWLIST == frozenset(
        {"show version", "show system", "show ip ssh"}
    )


def test_sensitive_running_config_remains_held():
    entry = entries_by_command()["show running-config brief"]
    assert entry["live_execution_state"] == "NOT_AUTHORIZED"
    assert entry["parser_state"] == "BLOCKED_SENSITIVITY_REVIEW"
    assert entry["planner_state"] == "HOLD_SENSITIVE_OUTPUT_REVIEW"
    assert "show running-config brief" not in READ_ONLY_EXEC_ALLOWLIST
