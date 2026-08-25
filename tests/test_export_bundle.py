import hashlib
import json
from pathlib import Path

from cisco_assistant.current_state import CurrentNetworkState
from cisco_assistant.dry_run import build_device_aware_dry_run
from cisco_assistant.export_bundle import export_dry_run_bundle
from cisco_assistant.profiles import load_cbs250_24t_4x_3_3_0_16_profile
from cisco_assistant.templates import RolePortCount, TemplateRequest


def build_result():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    request = TemplateRequest(
        template_id="office_ip_cameras",
        site_name="Export Test",
        start_vlan_id=100,
        start_network="10.40.0.0/24",
        role_port_counts=(RolePortCount("office", 1), RolePortCount("camera", 1)),
        access_interfaces=("GE1", "GE2"),
        uplink_interface="XG1",
        management_source_networks=("10.40.0.0/24",),
    )
    return build_device_aware_dry_run(
        request,
        profile,
        CurrentNetworkState(basis="blank_design"),
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_export_bundle_writes_json_text_and_verified_manifest(tmp_path):
    result = build_result()
    exported = export_dry_run_bundle(result, tmp_path)

    json_path = Path(exported.json_path)
    text_path = Path(exported.text_path)
    manifest_path = Path(exported.manifest_path)

    assert json_path.is_file()
    assert text_path.is_file()
    assert manifest_path.is_file()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert manifest["plan_hash"] == result.plan.plan_hash
    assert manifest["execution_authority"] is False
    assert manifest["device_commands_generated"] is False

    files = {item["name"]: item for item in manifest["files"]}
    assert files[json_path.name]["sha256"] == sha256(json_path)
    assert files[text_path.name]["sha256"] == sha256(text_path)
    assert files[json_path.name]["bytes"] == json_path.stat().st_size
    assert files[text_path.name]["bytes"] == text_path.stat().st_size

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["current_state"]["basis"] == "blank_design"
    assert payload["change_plan"]["plan_hash"] == result.plan.plan_hash
    assert payload["plan_analysis"]["management_impact"]["safe_to_apply"] is False
    assert "Execution allowed: NO" in text_path.read_text(encoding="utf-8")


def test_export_is_deterministic_for_same_inputs(tmp_path):
    result = build_result()
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"

    first = export_dry_run_bundle(result, first_dir)
    second = export_dry_run_bundle(result, second_dir)

    assert Path(first.json_path).read_bytes() == Path(second.json_path).read_bytes()
    assert Path(first.text_path).read_bytes() == Path(second.text_path).read_bytes()
    assert Path(first.manifest_path).read_bytes() == Path(second.manifest_path).read_bytes()


def test_export_contains_no_credential_fields(tmp_path):
    result = build_result()
    exported = export_dry_run_bundle(result, tmp_path)
    combined = (
        Path(exported.json_path).read_text(encoding="utf-8")
        + Path(exported.text_path).read_text(encoding="utf-8")
        + Path(exported.manifest_path).read_text(encoding="utf-8")
    ).lower()

    assert '"password"' not in combined
    assert '"username"' not in combined
    assert "ssh password" not in combined
    assert "private key" not in combined
