from cisco_assistant import (
    DeviceFingerprint,
    ObservedState,
    RolePortCount,
    TemplateRequest,
    load_cbs250_24t_4x_3_3_0_16_profile,
)
from cisco_assistant.workflow import build_device_aware_design_preview


def small_office_request(*, access_count=6):
    interfaces = tuple(f"GigabitEthernet{index}" for index in range(1, access_count + 1))
    return TemplateRequest(
        template_id="small_office",
        site_name="Tokyo Office",
        start_vlan_id=100,
        vlan_increment=10,
        start_network="10.50.0.0/24",
        role_port_counts=(
            RolePortCount("office", max(access_count - 2, 0)),
            RolePortCount("guest", min(2, access_count)),
        ),
        access_interfaces=interfaces,
        uplink_interface="TenGigabitEthernet1",
        management_source_networks=("10.50.0.0/24",),
    )


def exact_observed_state(*, firmware="3.3.0.16", interfaces=()):
    return ObservedState(
        fingerprint=DeviceFingerprint(
            vendor="Cisco",
            family="CBS250",
            product_id="CBS250-24T-4X",
            firmware_version=firmware,
        ),
        collected_at_utc="2026-08-25T14:00:00+00:00",
        source_revision="workflow-test",
        interfaces=interfaces,
    )


def test_small_office_preview_is_exact_device_bound_and_never_generates_cli():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    result = build_device_aware_design_preview(small_office_request(), profile)

    assert result.target.product_id == "CBS250-24T-4X"
    assert result.target.firmware_version == "3.3.0.16"
    assert result.target.profile_id == "cbs250-24t-4x_3.3.0.16"
    assert result.device_commands_generated is False
    assert result.design.device_commands_generated is False
    assert result.as_dict()["device_commands_generated"] is False
    assert "Device commands generated: NO" in result.render_text()
    assert "No device configuration was generated or executed." in result.render_text()


def test_offline_mode_keeps_unproven_capabilities_visible_as_warnings_but_design_valid():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    result = build_device_aware_design_preview(
        small_office_request(),
        profile,
        require_live_proof=False,
    )

    assert result.overall_valid
    warning_codes = {
        issue.code
        for issue in result.profile_validation.issues
        if issue.severity.value == "WARNING"
    }
    assert "PROFILE_CAPABILITY_NOT_LIVE_PROVEN" in warning_codes
    assert result.as_dict()["capability_validation"]["mode"] == "offline_design"


def test_security_profile_is_expanded_in_same_offline_design_result():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    result = build_device_aware_design_preview(
        small_office_request(),
        profile,
        require_live_proof=False,
    )

    payload = result.as_dict()["security_profile_expansion"]
    assert payload["profile"] == "BUSINESS_STANDARD"
    assert payload["version"] == "1.0.0"
    assert payload["valid"] is True
    assert any(
        rule["rule_id"] == "management.ssh"
        and rule["status"] == "proven"
        for rule in payload["rules"]
    )
    assert any(
        rule["rule_id"] == "management.https"
        and rule["status"] == "documented_unproven"
        for rule in payload["rules"]
    )
    text = result.render_text()
    assert "SECURITY PROFILE" in text
    assert "BUSINESS_STANDARD @ 1.0.0" in text
    assert "management.ssh" in text


def test_strict_future_live_proof_mode_blocks_until_required_capabilities_are_proven():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    result = build_device_aware_design_preview(
        small_office_request(),
        profile,
        require_live_proof=True,
    )

    assert not result.overall_valid
    assert any(
        issue.code == "PROFILE_CAPABILITY_NOT_LIVE_PROVEN"
        for issue in result.profile_validation.blocking
    )
    assert result.as_dict()["capability_validation"]["mode"] == "live_proof_required"
    assert result.security_expansion.blocking


def test_observed_firmware_mismatch_blocks_exact_profile_workflow():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    request = small_office_request()
    observed = exact_observed_state(
        firmware="3.5.3.3",
        interfaces=tuple(request.access_interfaces) + (request.uplink_interface,),
    )
    result = build_device_aware_design_preview(
        request,
        profile,
        observed_state=observed,
    )

    assert not result.overall_valid
    assert any(
        issue.code == "PROFILE_FINGERPRINT_MISMATCH"
        for issue in result.profile_validation.blocking
    )


def test_template_can_be_valid_generically_but_exact_profile_blocks_29_physical_interfaces():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    access_interfaces = tuple(f"Port{index}" for index in range(1, 30))
    request = TemplateRequest(
        template_id="small_office",
        site_name="Too Large",
        start_vlan_id=100,
        start_network="10.60.0.0/24",
        role_port_counts=(RolePortCount("office", 27), RolePortCount("guest", 2)),
        access_interfaces=access_interfaces,
        management_source_networks=("10.60.0.0/24",),
    )

    result = build_device_aware_design_preview(request, profile)
    assert result.design.validation_valid
    assert not result.overall_valid
    assert any(
        issue.code == "PHYSICAL_PORT_CAPACITY_EXCEEDED"
        for issue in result.profile_validation.blocking
    )


def test_exact_device_aware_preview_is_deterministic():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    request = small_office_request()

    first = build_device_aware_design_preview(request, profile)
    second = build_device_aware_design_preview(request, profile)

    assert first == second
    assert first.as_dict() == second.as_dict()
    assert first.render_text() == second.render_text()
