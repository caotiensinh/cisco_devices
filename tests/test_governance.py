import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_GOVERNANCE_FILES = [
    "AGENTS.md",
    "governance/project_scope.json",
    "docs/governance/AI_AGENT_HARNESS.md",
    "docs/governance/WRITE_AUTHORITY_ACTIVATION.md",
    "docs/PRODUCT_VISION.md",
    "docs/PRODUCT_SPEC.md",
    "docs/IMPLEMENTATION_CHECKLIST.md",
    "docs/CBS250/discovery_safety_v3.md",
    "docs/CBS250/automation_capability_model.md",
]


def load_scope():
    return json.loads((ROOT / "governance/project_scope.json").read_text(encoding="utf-8"))


def test_required_governance_files_exist():
    missing = [path for path in REQUIRED_GOVERNANCE_FILES if not (ROOT / path).is_file()]
    assert not missing, f"Missing mandatory governance files: {missing}"


def test_discovery_authority_remains_investigation_only():
    scope = load_scope()
    assert scope["discovery_execution_authority"]["mode"] == "INVESTIGATION_ONLY"
    assert scope["discovery_execution_authority"]["discovered_commands_executed"] is False


def test_write_authority_requires_explicit_p6_approval_marker():
    scope = load_scope()
    policy = scope["write_authority_activation_policy"]
    marker = ROOT / policy["approval_marker_path"]
    global_write = scope["global_device_write_authority"] is True
    production_write = scope["production_network_write_authority"] is True

    if not global_write and not production_write:
        assert policy["stale_marker_forbidden_when_authority_false"] is True
        assert not marker.exists(), (
            "Write authority is disabled but a stale approval marker exists; remove latent authority"
        )
        return

    assert scope["current_phase"].startswith(policy["required_phase_prefix"]), (
        "Write authority may only be enabled in the explicitly gated P6 phase"
    )
    assert marker.is_file(), (
        "Write authority cannot be enabled by project_scope flag change alone; "
        "the dedicated approval marker is required"
    )
    approval = json.loads(marker.read_text(encoding="utf-8"))

    assert approval.get("schema_version") == 1
    assert approval.get("approved") is True
    assert str(approval.get("human_owner_approval_reference", "")).strip()

    target = approval.get("target", {})
    for key in ("vendor", "family", "product_id", "firmware_version"):
        value = str(target.get(key, "")).strip()
        assert value and value not in {"*", "ALL", "any", "ANY"}, (
            f"Write approval target {key} must be exact, not empty/wildcard"
        )

    operations = approval.get("allowed_operations", [])
    assert isinstance(operations, list) and operations
    normalized_ops = {str(item).strip() for item in operations}
    assert all(normalized_ops)
    assert not ({"*", "ALL", "all"} & normalized_ops), (
        "Write approval must enumerate exact typed operations"
    )

    test_release = approval.get("test_release", {})
    security_gate = approval.get("security_gate", {})
    assert test_release.get("verdict") == "PASS"
    assert str(test_release.get("reference", "")).strip()
    assert security_gate.get("verdict") == "PASS"
    assert str(security_gate.get("reference", "")).strip()

    assert policy["destructive_class_d_allowed_by_marker"] is False
    assert approval.get("destructive_class_d_approved", False) is False

    if production_write:
        assert approval.get("production_network_write_approved") is True, (
            "Production network write authority requires an explicit marker flag"
        )


def test_required_safety_invariants_are_machine_readable():
    scope = load_scope()
    invariants = set(scope["non_negotiable_invariants"])
    required = {
        "No LLM output is directly executable CLI",
        "No UI code directly executes device CLI",
        "Discovered CLI is data, not authority",
        "Unknown capability fails closed",
        "Secrets are never committed or emitted into evidence",
        "Every future write is plan-first, diff-first, verify-before-persist",
        "Destructive lifecycle operations are never autonomous by default",
        "Write authority cannot be enabled by flag change alone",
    }
    assert required.issubset(invariants)


def test_current_phase_forbids_live_configuration_writes():
    scope = load_scope()
    forbidden = set(scope["forbidden_without_explicit_phase_change"])
    required = {
        "device_configuration_write",
        "startup_config_persist",
        "clear_or_delete_operations",
        "reload_or_reboot",
        "firmware_or_boot_image_mutation",
        "factory_reset",
        "autonomous_acl_or_management_path_change",
        "autonomous_vlan_or_interface_change",
        "autonomous_routing_change",
        "autonomous_aaa_security_change",
    }
    assert required.issubset(forbidden)
    if not scope["current_phase"].startswith("P6_"):
        assert scope["global_device_write_authority"] is False
        assert scope["production_network_write_authority"] is False


def test_agents_contract_points_to_scope_and_spec():
    text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert "governance/project_scope.json" in text
    assert "docs/PRODUCT_SPEC.md" in text
    assert "No LLM response may directly become an executable device command stream." in text
    assert "Device configuration/write authority is FALSE by default." in text
