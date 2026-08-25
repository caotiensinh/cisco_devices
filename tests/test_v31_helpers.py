from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cbs250_discovery_utils import build_help_query, has_more_prompt
from cbs250_safety import (
    READ_ONLY_EXEC_ALLOWLIST,
    SafetyViolation,
    assert_read_only_executable,
)


def blocked(command: str) -> None:
    try:
        assert_read_only_executable(command)
    except SafetyViolation:
        return
    raise AssertionError(f"Forbidden command was accepted: {command}")


def test_sharded_help_queries_are_non_submitting():
    assert build_help_query("", "") == "?"
    assert build_help_query("show", "") == "show ?"
    assert build_help_query("", "s") == "s?"
    assert build_help_query("show", "s") == "show s?"
    for query in (
        build_help_query("", "s"),
        build_help_query("show", "s"),
        build_help_query("show interfaces", "g"),
    ):
        assert query.endswith("?")
        assert "\r" not in query
        assert "\n" not in query


def test_pager_detection():
    assert has_more_prompt("More: <space>,  Quit: q or CTRL+Z, One line: <return>")
    assert not has_more_prompt("switch#")


def test_execution_policy_stays_fail_closed():
    for command in (
        "delete flash:test",
        "clear logging",
        "reload",
        "boot system inactive-image",
        "copy running-config startup-config",
        "write memory",
        "configure terminal",
        "shutdown",
    ):
        blocked(command)
    for command in READ_ONLY_EXEC_ALLOWLIST:
        assert assert_read_only_executable(command) == command
    blocked("show running-config")
