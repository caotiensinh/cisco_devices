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
    classify_probe_results,
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


def complete_result(prefix):
    return {
        "prefix": prefix,
        "query": f"{prefix} ?",
        "candidate_command_executed": False,
        "help_query_submitted_with_enter": False,
        "bytes_sent_after_help_marker": 0,
        "channel_closed_immediately": True,
        "paginated": False,
        "terminal_cr_observed": True,
        "items": [],
        "error": None,
    }


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


def test_classification_requires_safe_complete_three_prefix_evidence():
    results = [complete_result(prefix) for prefix in L3_HELP_PREFIXES]
    state = classify_probe_results(results)

    assert state["status"] == "PASS_COMPLETE"
    assert state["safety_status"] == "PASS"
    assert state["evidence_status"] == "COMPLETE"
    assert state["safety_pass"] is True
    assert state["evidence_complete"] is True


def test_safe_but_paginated_or_missing_cr_is_blocked_as_incomplete_evidence():
    results = [complete_result(prefix) for prefix in L3_HELP_PREFIXES]
    results[0]["paginated"] = True
    state = classify_probe_results(results)
    assert state["status"] == "BLOCKED_INCOMPLETE_EVIDENCE"
    assert state["safety_status"] == "PASS"
    assert state["evidence_status"] == "INCOMPLETE"

    results = [complete_result(prefix) for prefix in L3_HELP_PREFIXES]
    results[1]["terminal_cr_observed"] = False
    state = classify_probe_results(results)
    assert state["status"] == "BLOCKED_INCOMPLETE_EVIDENCE"
    assert state["safety_status"] == "PASS"
    assert state["evidence_status"] == "INCOMPLETE"


def test_any_post_marker_or_channel_safety_failure_blocks_safety():
    results = [complete_result(prefix) for prefix in L3_HELP_PREFIXES]
    results[2]["bytes_sent_after_help_marker"] = 1
    state = classify_probe_results(results)

    assert state["status"] == "BLOCKED_SAFETY"
    assert state["safety_status"] == "BLOCKED"
    assert state["evidence_status"] == "INCOMPLETE"
    assert state["safety_pass"] is False
    assert state["evidence_complete"] is False


def test_missing_result_is_not_misreported_as_complete():
    results = [complete_result(prefix) for prefix in L3_HELP_PREFIXES[:-1]]
    state = classify_probe_results(results)
    assert state["status"] == "BLOCKED_SAFETY"
    assert state["evidence_complete"] is False


def test_source_does_not_use_full_crawler_or_candidate_execution_path():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "crawler.run(" not in text
    assert "execute_read_only(prefix" not in text
    assert "configure terminal" not in text.lower()
    assert "include_config_help=False" in text
    assert 'crawler.execute_read_only("show system")' in text
    assert 'crawler.execute_read_only("show version")' in text
