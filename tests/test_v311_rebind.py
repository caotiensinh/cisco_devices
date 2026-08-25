import json
from pathlib import Path

from cbs250_cli_discovery_v311 import classify_coverage_status
from cbs250_safety import READ_ONLY_EXEC_ALLOWLIST
from cisco_assistant.profiles import load_device_profile


ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / "knowledge" / "cbs250" / "live" / "CBS250-24T-4X_3.5.3.3_20260825_v31.json"
PROFILE = ROOT / "knowledge" / "cbs250" / "profiles" / "CBS250-24T-4X_3.5.3.3.json"
REGISTRY = ROOT / "knowledge" / "cbs250" / "read_only_collector_registry.json"
CANDIDATES = ROOT / "knowledge" / "cbs250" / "r0_candidate_review_3.5.3.3.json"


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_v31_live_evidence_is_rebound_to_active_3533_and_not_overclaimed_complete():
    evidence = load_json(LIVE)
    assert evidence["target"]["product_id"] == "CBS250-24T-4X"
    assert evidence["target"]["active_firmware"] == "3.5.3.3"
    assert evidence["target"]["inactive_firmware"] == "3.3.0.16"
    assert evidence["source_run"]["tool_reported_status"] == "COMPLETE"
    assert evidence["source_run"]["normalized_coverage_status"] == "TRUNCATED_AT_MAX_NODES"
    assert evidence["source_run"]["nodes_found"] >= 12000
    assert evidence["coverage"]["privileged_exec_top_level_count"] == 39
    assert evidence["coverage"]["privileged_exec_root_status"] == "COMPLETE_39_OF_39"
    assert evidence["coverage"]["global_config_root_status"] == "PARTIAL_DUE_TO_MAX_NODES"
    assert evidence["authority"]["device_write_authority"] is False


def test_v311_coverage_status_fails_closed_on_limits_and_errors():
    assert classify_coverage_status(nodes=12006, max_nodes=12000, error_count=0) == "TRUNCATED_MAX_NODES"
    assert classify_coverage_status(nodes=100, max_nodes=12000, error_count=1) == "INCOMPLETE_WITH_ERRORS"
    assert classify_coverage_status(nodes=100, max_nodes=12000, error_count=0) == "COMPLETE_WITHIN_DECLARED_SCOPE"


def test_exact_3533_profile_loads_without_rewriting_historical_33016_profile():
    profile = load_device_profile(PROFILE)
    assert profile.fingerprint.product_id == "CBS250-24T-4X"
    assert profile.fingerprint.firmware_version == "3.5.3.3"
    assert profile.binding_status == "LIVE_BOUND_WITH_TRUNCATED_GRAMMAR_EVIDENCE"
    assert profile.feature_states["ssh_management"].value == "documented_and_observed"
    assert profile.feature_states["vlan_8021q"].value == "documented_and_observed"
    assert profile.feature_states["management_acl"].value == "documented_and_observed"
    assert profile.feature_states["lacp"].value == "documented_and_observed"
    assert profile.feature_states["ipv4_static_routing"].value == "documented_not_observed"
    assert (ROOT / "knowledge" / "cbs250" / "profiles" / "CBS250-24T-4X_3.3.0.16.json").exists()


def test_collector_registry_is_rebound_but_does_not_silently_expand_execution():
    registry = load_json(REGISTRY)
    assert registry["target_scope"]["exact_live_reference_firmware"] == "3.5.3.3"
    registered = {entry["command"] for entry in registry["commands"]}
    assert registered == {"show system", "show version", "show ip ssh"}
    assert registered == set(READ_ONLY_EXEC_ALLOWLIST)
    assert all("3.5.3.3" in entry["live_evidence"] for entry in registry["commands"])


def test_reviewed_r0_candidates_remain_non_executable_until_live_output_and_parser_proof():
    review = load_json(CANDIDATES)
    candidates = {entry["command"]: entry for entry in review["candidates"]}

    ready = {
        "show vlan",
        "show interfaces status",
        "show interfaces switchport",
        "show spanning-tree",
        "show management access-class",
        "show management access-list",
        "show logging",
        "show logging file",
    }
    for command in ready:
        assert candidates[command]["review_status"] == "READY_FOR_CONTROLLED_LIVE_READ_VALIDATION"
        assert command not in READ_ONLY_EXEC_ALLOWLIST

    assert candidates["show running-config brief"]["review_status"] == "HOLD_SENSITIVE_OUTPUT_REVIEW"
    assert candidates["show lacp"]["review_status"] == "HOLD_REQUIRES_SELECTOR"
    assert review["authority"]["candidate_review_grants_execution_authority"] is False
