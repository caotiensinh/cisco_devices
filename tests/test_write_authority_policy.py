from copy import deepcopy
import json
from pathlib import Path

from governance.write_authority_policy import validate_write_authority_state


ROOT = Path(__file__).resolve().parents[1]


def base_scope():
    return json.loads((ROOT / "governance/project_scope.json").read_text(encoding="utf-8"))


def valid_marker():
    return {
        "schema_version": 1,
        "approved": True,
        "human_owner_approval_reference": "owner-review-123",
        "target": {
            "vendor": "Cisco",
            "family": "CBS250",
            "product_id": "CBS250-24T-4X",
            "firmware_version": "3.3.0.16",
        },
        "allowed_operations": ["CreateVlan"],
        "test_release": {"verdict": "PASS", "reference": "test-release-123"},
        "security_gate": {"verdict": "PASS", "reference": "security-gate-123"},
        "production_network_write_approved": False,
        "destructive_class_d_approved": False,
    }


def test_current_disabled_state_requires_no_marker():
    scope = base_scope()
    assert validate_write_authority_state(scope, approval=None, marker_exists=False) == ()


def test_stale_marker_is_rejected_while_disabled():
    scope = base_scope()
    errors = validate_write_authority_state(scope, approval=valid_marker(), marker_exists=True)
    assert "approval marker must not exist while write authority is disabled" in errors


def test_flag_change_alone_is_rejected():
    scope = base_scope()
    scope["current_phase"] = "P6_CONTROLLED_WRITE"
    scope["global_device_write_authority"] = True
    errors = validate_write_authority_state(scope, approval=None, marker_exists=False)
    assert "dedicated write-authority approval marker is required" in errors


def test_write_authority_is_rejected_outside_p6_even_with_marker():
    scope = base_scope()
    scope["global_device_write_authority"] = True
    errors = validate_write_authority_state(scope, approval=valid_marker(), marker_exists=True)
    assert "write authority may only be enabled in the configured P6 phase" in errors


def test_complete_nonproduction_p6_marker_passes_policy_validation():
    scope = base_scope()
    scope["current_phase"] = "P6_CONTROLLED_WRITE"
    scope["global_device_write_authority"] = True
    assert validate_write_authority_state(
        scope,
        approval=valid_marker(),
        marker_exists=True,
    ) == ()


def test_wildcard_operation_authority_is_rejected():
    scope = base_scope()
    scope["current_phase"] = "P6_CONTROLLED_WRITE"
    scope["global_device_write_authority"] = True
    marker = valid_marker()
    marker["allowed_operations"] = ["*"]
    errors = validate_write_authority_state(scope, approval=marker, marker_exists=True)
    assert "wildcard operation authority is forbidden" in errors


def test_missing_independent_gate_evidence_is_rejected():
    scope = base_scope()
    scope["current_phase"] = "P6_CONTROLLED_WRITE"
    scope["global_device_write_authority"] = True
    marker = valid_marker()
    marker["security_gate"] = {"verdict": "DEFERRED", "reference": ""}
    errors = validate_write_authority_state(scope, approval=marker, marker_exists=True)
    assert "SECURITY_GATE verdict must be PASS" in errors
    assert "SECURITY_GATE evidence reference is required" in errors


def test_production_authority_requires_global_and_explicit_production_approval():
    scope = base_scope()
    scope["current_phase"] = "P6_CONTROLLED_WRITE"
    scope["production_network_write_authority"] = True
    marker = valid_marker()
    errors = validate_write_authority_state(scope, approval=marker, marker_exists=True)
    assert "production network write authority requires global device write authority" in errors

    scope["global_device_write_authority"] = True
    errors = validate_write_authority_state(scope, approval=marker, marker_exists=True)
    assert "production write authority requires explicit production approval" in errors

    marker["production_network_write_approved"] = True
    assert validate_write_authority_state(scope, approval=marker, marker_exists=True) == ()


def test_destructive_class_d_cannot_be_enabled_by_marker():
    scope = base_scope()
    scope["current_phase"] = "P6_CONTROLLED_WRITE"
    scope["global_device_write_authority"] = True
    marker = valid_marker()
    marker["destructive_class_d_approved"] = True
    errors = validate_write_authority_state(scope, approval=marker, marker_exists=True)
    assert "approval marker cannot authorize destructive class D" in errors
