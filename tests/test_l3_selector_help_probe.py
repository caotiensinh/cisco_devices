from __future__ import annotations

import pytest

import cbs250_l3_selector_help_probe as probe
from cbs250_safety import READ_ONLY_EXEC_ALLOWLIST


def test_selector_help_policy_is_help_only() -> None:
    probe.validate_static_policy()
    assert probe.APPROVED_BINDING_COMMANDS == frozenset({"show system", "show version"})
    assert probe.APPROVED_BINDING_COMMANDS.issubset(READ_ONLY_EXEC_ALLOWLIST)
    assert probe.SELECTOR_HELP_PREFIXES
    assert all(prefix not in READ_ONLY_EXEC_ALLOWLIST for prefix in probe.SELECTOR_HELP_PREFIXES)
    assert all("?" not in prefix and "\r" not in prefix and "\n" not in prefix for prefix in probe.SELECTOR_HELP_PREFIXES)


def test_selector_help_avoids_specific_physical_interface_ids() -> None:
    assert "show ip interface GigabitEthernet" in probe.SELECTOR_HELP_PREFIXES
    assert "show ip interface TenGigabitEthernet" in probe.SELECTOR_HELP_PREFIXES
    assert not any("GigabitEthernet1/" in prefix for prefix in probe.SELECTOR_HELP_PREFIXES)
    assert not any("TenGigabitEthernet1/" in prefix for prefix in probe.SELECTOR_HELP_PREFIXES)


def test_validate_prefix_rejects_unlisted_or_control_markers() -> None:
    with pytest.raises(probe.SelectorProbeError):
        probe.validate_prefix("show interfaces status")
    with pytest.raises(probe.SelectorProbeError):
        probe.validate_prefix("show ip route ?")
    with pytest.raises(probe.SelectorProbeError):
        probe.validate_prefix("show ip route\nsummary")


def test_classification_requires_zero_post_help_bytes_and_immediate_close() -> None:
    results = [
        {
            "candidate_command_executed": False,
            "help_query_submitted_with_enter": False,
            "bytes_sent_after_help_marker": 0,
            "channel_closed_immediately": True,
            "error": None,
        }
        for _ in probe.SELECTOR_HELP_PREFIXES
    ]
    assert probe.classify(results)["safety_status"] == "PASS"
    results[0]["bytes_sent_after_help_marker"] = 1
    assert probe.classify(results)["safety_status"] == "BLOCKED"
