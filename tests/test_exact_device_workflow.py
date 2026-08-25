import pytest

from cisco_assistant.current_state import CurrentNetworkState
from cisco_assistant.exact_device_workflow import (
    build_exact_observed_design_preview,
    build_exact_observed_dry_run,
    profile_for_observed_state,
)
from cisco_assistant.models import DeviceFingerprint, ObservedState
from cisco_assistant.profiles import ProfileError
from cisco_assistant.templates import RolePortCount, TemplateRequest


def observed(*, firmware="3.5.3.3"):
    return ObservedState(
        fingerprint=DeviceFingerprint(
            vendor="Cisco",
            family="CBS250",
            product_id="CBS250-24T-4X",
            firmware_version=firmware,
        ),
        collected_at_utc="2026-08-25T11:05:48+00:00",
        source_revision="exact-observed-workflow-test",
        interfaces=("GE1", "GE2", "GE3", "GE4", "XG1"),
        partial=True,
    )


def request():
    return TemplateRequest(
        template_id="office_ip_cameras",
        site_name="Exact Device Site",
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


def test_observed_3533_selects_current_exact_profile():
    profile = profile_for_observed_state(observed())
    assert profile.profile_id == "cbs250-24t-4x_3.5.3.3"
    assert profile.fingerprint.product_id == "CBS250-24T-4X"
    assert profile.fingerprint.firmware_version == "3.5.3.3"


def test_historical_firmware_is_selected_only_when_observed_exactly():
    profile = profile_for_observed_state(observed(firmware="3.3.0.16"))
    assert profile.profile_id == "cbs250-24t-4x_3.3.0.16"
    assert profile.fingerprint.firmware_version == "3.3.0.16"


def test_unknown_observed_firmware_fails_closed_without_fallback():
    with pytest.raises(ProfileError, match="cross-firmware fallback is forbidden"):
        profile_for_observed_state(observed(firmware="3.4.0.0"))


def test_design_preview_uses_observed_3533_and_generates_no_cli():
    result = build_exact_observed_design_preview(request(), observed())
    assert result.target.product_id == "CBS250-24T-4X"
    assert result.target.firmware_version == "3.5.3.3"
    assert result.target.profile_id == "cbs250-24t-4x_3.5.3.3"
    assert result.device_commands_generated is False
    assert result.as_dict()["device_commands_generated"] is False


def test_dry_run_uses_observed_3533_and_keeps_execution_authority_false():
    result = build_exact_observed_dry_run(
        request(),
        CurrentNetworkState(basis="blank_design"),
        observed(),
    )
    assert result.design.target.firmware_version == "3.5.3.3"
    assert result.execution_authority is False
    assert result.device_commands_generated is False
    assert result.as_dict()["execution_authority"] is False
    assert result.as_dict()["device_commands_generated"] is False
