import json
from pathlib import Path

from cbs250_safety import READ_ONLY_EXEC_ALLOWLIST
from cisco_assistant.read_only_collectors import COLLECTOR_COMMANDS


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "knowledge" / "cbs250" / "read_only_collector_registry.json"


def load_registry():
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def test_registry_exists_and_grants_no_write_authority():
    registry = load_registry()
    assert registry["schema_version"] == 2
    assert registry["authority"]["device_write_authority"] is False
    assert registry["authority"]["execution_class"] == "R0_ONLY"
    assert registry["authority"]["discovered_commands_are_authority"] is False
    assert registry["current_planner_scope_complete"] is False


def test_automated_collector_commands_have_registry_and_safety_approval():
    registry = load_registry()
    entries = {entry["command"]: entry for entry in registry["commands"]}
    assert set(COLLECTOR_COMMANDS) == set(entries)
    assert set(COLLECTOR_COMMANDS).issubset(READ_ONLY_EXEC_ALLOWLIST)
    for command in COLLECTOR_COMMANDS:
        entry = entries[command]
        assert entry["automation_status"] == "approved"
        assert entry["risk_class"] == "R0"
        assert entry["live_evidence"]
        assert entry["planner_scope_complete"] is False


def test_registry_cannot_silently_expand_beyond_code_and_allowlist():
    registry = load_registry()
    registered = {entry["command"] for entry in registry["commands"]}
    assert registered == set(COLLECTOR_COMMANDS)
    assert registered.issubset(READ_ONLY_EXEC_ALLOWLIST)
    assert registered == {"show system", "show version", "show ip ssh", "show vlan"}
