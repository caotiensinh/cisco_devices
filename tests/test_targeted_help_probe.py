from pathlib import Path
from types import SimpleNamespace

import pytest

from cbs250_safety import READ_ONLY_EXEC_ALLOWLIST
from cbs250_targeted_help_probe import (
    APPROVED_BINDING_COMMANDS,
    EXPECTED_FIRMWARE,
    EXPECTED_PRODUCT_ID,
    L3_HELP_PREFIXES,
    TargetedProbeError,
    probe_prefix,
    validate_probe_prefix,
    validate_static_policy,
    verify_exact_target,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "cbs250_targeted_help_probe.py"


class FakeInventoryCrawler:
    def __init__(self, *, firmware="3.5.3.3", product="CBS250-24T-4X"):
        self.firmware = firmware
        self.product = product
        self.executed = []

    def execute_read_only(self, command):
        self.executed.append(command)
        if command == "show system":
            return f"System Description: {self.product} 24-Port Gigabit Smart Switch\n"
        if command == "show version":
            return f"Version: {self.firmware}\n"
        raise AssertionError(f"unexpected command: {command}")


class FakeHelpCrawler:
    def __init__(self):
        self.audit = []
        self.prefixes = []

    def query_help_once(self, mode, prefix):
        self.prefixes.append((mode, prefix))
        self.audit.append(
            SimpleNamespace(
                bytes_sent_after_help_marker=0,
                channel_closed_immediately=True,
                error=None,
            )
        )
        return [
            SimpleNamespace(token="<CR>", description="", kind="terminal", risk="read_only")
        ], False


def test_static_policy_keeps_binding_commands_inside_existing_allowlist():
    validate_static_policy()
    assert APPROVED_BINDING_COMMANDS == frozenset({"show system", "show version"})
    assert APPROVED_BINDING_COMMANDS.issubset(READ_ONLY_EXEC_ALLOWLIST)
    assert all(prefix not in READ_ONLY_EXEC_ALLOWLIST for prefix in L3_HELP_PREFIXES)


def test_probe_prefix_accepts_only_exact_hardcoded_l3_targets():
    for prefix in L3_HELP_PREFIXES:
        assert validate_probe_prefix(prefix) == prefix

    for forbidden in (
        "show ip arp",
        "show running-config brief",
        "show ip route?",
        "show ip route\r",
        "show ip route\nreload",
        "",
    ):
        with pytest.raises(TargetedProbeError):
            validate_probe_prefix(forbidden)


def test_exact_target_binding_executes_only_existing_approved_inventory_commands():
    crawler = FakeInventoryCrawler()
    target = verify_exact_target(crawler)

    assert target == {
        "product_id": EXPECTED_PRODUCT_ID,
        "firmware_version": EXPECTED_FIRMWARE,
    }
    assert crawler.executed == ["show system", "show version"]
    assert set(crawler.executed).issubset(READ_ONLY_EXEC_ALLOWLIST)


def test_exact_target_binding_fails_closed_on_firmware_mismatch():
    crawler = FakeInventoryCrawler(firmware="3.3.0.16")
    with pytest.raises(TargetedProbeError, match="Exact target binding failed"):
        verify_exact_target(crawler)
    assert crawler.executed == ["show system", "show version"]


def test_candidate_probe_uses_context_help_api_and_records_zero_bytes_after_marker():
    crawler = FakeHelpCrawler()
    result = probe_prefix(crawler, "show ip route")

    assert crawler.prefixes == [("privileged_exec", "show ip route")]
    assert result["query"] == "show ip route ?"
    assert result["candidate_command_executed"] is False
    assert result["help_query_submitted_with_enter"] is False
    assert result["bytes_sent_after_help_marker"] == 0
    assert result["channel_closed_immediately"] is True
    assert result["terminal_cr_observed"] is True
    assert result["error"] is None


def test_source_does_not_use_full_crawler_or_candidate_execution_path():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "crawler.run(" not in text
    assert "execute_read_only(prefix" not in text
    assert "configure terminal" not in text.lower()
    assert "include_config_help=False" in text
    assert 'crawler.execute_read_only("show system")' in text
    assert 'crawler.execute_read_only("show version")' in text
