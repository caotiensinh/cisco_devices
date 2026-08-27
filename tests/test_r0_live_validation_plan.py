import json
from pathlib import Path

from cbs250_safety import READ_ONLY_EXEC_ALLOWLIST


ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "knowledge" / "cbs250" / "r0_live_validation_plan_3.5.3.3.json"
CANDIDATES_PATH = ROOT / "knowledge" / "cbs250" / "r0_candidate_review_3.5.3.3.json"
FORMATS_PATH = ROOT / "knowledge" / "cbs250" / "documented_output_formats.json"


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_live_validation_plan_grants_no_execution_or_write_authority():
    authority = load(PLAN_PATH)["authority"]
    assert authority["device_write_authority"] is False
    assert authority["production_network_write_authority"] is False
    assert authority["candidate_execution_authority"] is False
    assert authority["raw_cli_authority"] is False
    assert authority["allowlist_expansion_authority"] is False


def test_vlan_completed_and_current_priority_candidates_pending():
    plan = load(PLAN_PATH)
    review = load(CANDIDATES_PATH)
    reviewed = {item["command"]: item for item in review["candidates"]}
    completed = {item["command"]: item for item in plan["completed_validations"]}

    assert completed["show vlan"]["status"] == "PROMOTED_TO_EXACT_TARGET_READ_ONLY_COLLECTOR"
    assert reviewed["show vlan"]["review_status"] == "PROMOTED_TO_EXACT_TARGET_READ_ONLY_COLLECTOR"
    assert "show vlan" in READ_ONLY_EXEC_ALLOWLIST

    assert plan["priority_order"] == ["show interfaces status", "show interfaces switchport"]
    for command in plan["priority_order"]:
        assert reviewed[command]["review_status"] == "READY_FOR_CONTROLLED_LIVE_READ_VALIDATION"
        assert command not in READ_ONLY_EXEC_ALLOWLIST


def test_pending_priority_entries_still_require_live_output_and_regression():
    plan = load(PLAN_PATH)
    entries = {entry["command"]: entry for entry in plan["validations"]}
    assert set(entries) == set(plan["priority_order"])
    for command in plan["priority_order"]:
        entry = entries[command]
        assert entry["current_evidence"]["exact_live_help_syntax"] is True
        assert entry["current_evidence"]["documented_output_format"] is True
        assert entry["current_evidence"]["exact_live_execution_output"] is False
        assert entry["current_evidence"]["exact_live_parser_regression"] is False
        assert entry["status"] == "BLOCKED_MISSING_LIVE_EXECUTION_OUTPUT"
        assert entry["required_capture"]["repository_raw_output_allowed"] is False


def test_documented_format_registry_is_partial_after_vlan_validation():
    formats = load(FORMATS_PATH)
    authority = formats["authority"]
    assert authority["execution_authority"] is False
    assert authority["parser_promotion_authority"] is False
    assert authority["documented_examples_are_live_evidence"] is False
    assert formats["source_scope"]["exact_live_output_validation_status"] == "PARTIAL"

    parsers = {entry["command"]: entry for entry in formats["parsers"]}
    assert parsers["show vlan"]["exact_live_3_5_3_3_status"] == "VALIDATED_EXACT_LIVE_AND_REGRESSION_PASS"
    for command in ("show interfaces status", "show interfaces switchport"):
        assert parsers[command]["documented_format_status"] == "IMPLEMENTED_WITH_SYNTHETIC_FIXTURE_TESTS"
        assert parsers[command]["exact_live_3_5_3_3_status"] == "PENDING_CAPTURE_AND_REGRESSION"


def test_explicit_holds_remain_non_promotable():
    plan = load(PLAN_PATH)
    holds = {entry["command"]: entry["status"] for entry in plan["explicit_holds"]}
    assert holds["show running-config brief"] == "HOLD_SENSITIVE_OUTPUT_REVIEW"
    assert holds["show lacp"] == "HOLD_REQUIRES_SELECTOR"
    assert "show running-config brief" not in READ_ONLY_EXEC_ALLOWLIST
    assert "show lacp" not in READ_ONLY_EXEC_ALLOWLIST
