import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_GOVERNANCE_FILES = [
    "AGENTS.md",
    "governance/project_scope.json",
    "docs/governance/AI_AGENT_HARNESS.md",
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


def test_device_write_authority_remains_disabled_in_current_phase():
    scope = load_scope()
    assert scope["global_device_write_authority"] is False
    assert scope["production_network_write_authority"] is False
    assert scope["discovery_execution_authority"]["mode"] == "INVESTIGATION_ONLY"
    assert scope["discovery_execution_authority"]["discovered_commands_executed"] is False


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


def test_agents_contract_points_to_scope_and_spec():
    text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert "governance/project_scope.json" in text
    assert "docs/PRODUCT_SPEC.md" in text
    assert "No LLM output may directly become an executable device command stream." in text
    assert "Device configuration/write authority is FALSE by default." in text
