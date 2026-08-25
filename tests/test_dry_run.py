from cisco_assistant.current_state import (
    CurrentAccessPortState,
    CurrentManagementState,
    CurrentNetworkState,
    CurrentTrunkState,
    CurrentVLANState,
)
from cisco_assistant.dry_run import build_device_aware_dry_run
from cisco_assistant.profiles import load_cbs250_24t_4x_3_3_0_16_profile
from cisco_assistant.security_profiles import expand_security_profile
from cisco_assistant.templates import RolePortCount, TemplateRequest


def request():
    return TemplateRequest(
        template_id="office_ip_cameras",
        site_name="Tokyo Branch",
        start_vlan_id=100,
        vlan_increment=10,
        start_network="10.50.0.0/24",
        role_port_counts=(
            RolePortCount("office", 2),
            RolePortCount("camera", 2),
        ),
        access_interfaces=("GE1", "GE2", "GE3", "GE4"),
        uplink_interface="XG1",
        management_source_networks=("10.50.0.0/24",),
    )


def test_blank_design_dry_run_reaches_semantic_plan_without_cli_or_authority():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    result = build_device_aware_dry_run(
        request(),
        profile,
        CurrentNetworkState(basis="blank_design"),
    )

    assert result.design_valid
    assert not result.provider_ready
    assert result.status == "DRY_RUN_BLOCKED_FOR_PROVIDER"
    assert result.execution_authority is False
    assert result.device_commands_generated is False
    assert result.plan.operations

    payload = result.as_dict()
    assert payload["execution_authority"] is False
    assert payload["device_commands_generated"] is False
    assert payload["design"]["device_commands_generated"] is False
    assert payload["change_plan"]["device_commands_generated"] is False
    assert "OFFLINE DEVICE-AWARE DRY RUN" in result.render_text()
    assert "Execution allowed: NO" in result.render_text()


def test_compliant_current_state_returns_no_changes():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    req = request()
    security = expand_security_profile(req.security_profile, device_profile=profile)
    applicable = tuple(
        rule.rule_id
        for rule in security.rules
        if rule.rule_id != "segmentation.ipv4_acl"
    )
    current = CurrentNetworkState(
        basis="observed_complete",
        vlans=(
            CurrentVLANState(100, "MGMT"),
            CurrentVLANState(110, "OFFICE"),
            CurrentVLANState(120, "CAMERA"),
        ),
        access_ports=(
            CurrentAccessPortState("GE1", 110),
            CurrentAccessPortState("GE2", 110),
            CurrentAccessPortState("GE3", 120),
            CurrentAccessPortState("GE4", 120),
        ),
        trunks=(CurrentTrunkState("XG1", (100, 110, 120)),),
        management=CurrentManagementState(
            vlan_id=100,
            allowed_source_networks=("10.50.0.0/24",),
            services=("ssh", "https"),
        ),
        satisfied_security_rules=applicable,
        collected_at_utc="2026-08-25T14:00:00+00:00",
        source_revision="dry-run-complete-test",
    )

    result = build_device_aware_dry_run(req, profile, current)

    assert result.design_valid
    assert result.plan.operations == ()
    assert result.status == "NO_CHANGES"
    assert result.provider_ready


def test_partial_live_current_state_can_be_previewed_but_never_provider_ready():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    current = CurrentNetworkState(
        basis="observed_partial",
        collected_at_utc="2026-08-25T14:00:00+00:00",
        source_revision="partial-live-test",
    )

    result = build_device_aware_dry_run(request(), profile, current)

    assert result.design_valid
    assert not result.provider_ready
    assert result.status == "DRY_RUN_BLOCKED_FOR_PROVIDER"
    assert any(issue.code == "CURRENT_STATE_PARTIAL" for issue in result.plan.issues)


def test_dry_run_is_deterministic_for_same_inputs():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    current = CurrentNetworkState(basis="blank_design")

    first = build_device_aware_dry_run(request(), profile, current)
    second = build_device_aware_dry_run(request(), profile, current)

    assert first == second
    assert first.as_dict() == second.as_dict()
    assert first.render_text() == second.render_text()
    assert first.plan.plan_hash == second.plan.plan_hash
