from cisco_assistant import (
    DeviceFingerprint,
    ManagementIntent,
    NetworkIntent,
    ObservedState,
    PortIntent,
    RoutingIntent,
    SecurityIntent,
    UplinkIntent,
    VLANIntent,
)
from cisco_assistant.profiles import (
    load_cbs250_24t_4x_3_3_0_16_profile,
    validate_intent_against_profile,
)


def observed_state(*, product_id="CBS250-24T-4X", firmware="3.3.0.16"):
    return ObservedState(
        fingerprint=DeviceFingerprint(
            vendor="Cisco",
            family="CBS250",
            product_id=product_id,
            firmware_version=firmware,
        ),
        collected_at_utc="2026-08-25T14:00:00+00:00",
        source_revision="test",
        interfaces=("GigabitEthernet1", "TenGigabitEthernet1"),
    )


def test_exact_profile_loads_expected_bound_resources():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    assert profile.fingerprint.product_id == "CBS250-24T-4X"
    assert profile.fingerprint.firmware_version == "3.3.0.16"
    assert profile.hardware.gigabit_access_ports == 24
    assert profile.hardware.ten_gigabit_uplink_ports == 4
    assert profile.hardware.total_physical_ports == 28
    assert profile.limits.active_vlans == 255
    assert profile.limits.ip_interfaces == 16
    assert profile.limits.ipv4_static_routes == 32


def test_profile_fingerprint_mismatch_is_blocked():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    intent = NetworkIntent(site_name="site", vlans=(VLANIntent(100, "OFFICE"),))
    result = validate_intent_against_profile(
        intent,
        profile,
        observed_state=observed_state(firmware="3.5.3.3"),
    )
    assert not result.valid
    assert any(issue.code == "PROFILE_FINGERPRINT_MISMATCH" for issue in result.blocking)


def test_active_vlan_family_limit_blocks_256_vlan_design():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    vlans = tuple(VLANIntent(vlan_id, f"V{vlan_id}") for vlan_id in range(1, 257))
    result = validate_intent_against_profile(NetworkIntent(site_name="site", vlans=vlans), profile)
    assert not result.valid
    assert any(issue.code == "ACTIVE_VLAN_CAPACITY_EXCEEDED" for issue in result.blocking)


def test_physical_interface_capacity_blocks_29_distinct_interfaces():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    vlan = VLANIntent(100, "OFFICE")
    ports = tuple(
        PortIntent(f"P{index}", "endpoint", "access", access_vlan=100)
        for index in range(1, 30)
    )
    result = validate_intent_against_profile(
        NetworkIntent(site_name="site", vlans=(vlan,), ports=ports),
        profile,
    )
    assert not result.valid
    assert any(issue.code == "PHYSICAL_PORT_CAPACITY_EXCEEDED" for issue in result.blocking)


def test_inter_vlan_routing_blocks_more_than_16_routed_vlan_interfaces():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    vlans = tuple(
        VLANIntent(
            100 + index,
            f"V{100 + index}",
            f"10.{index}.0.0/24",
            f"10.{index}.0.1",
        )
        for index in range(17)
    )
    result = validate_intent_against_profile(
        NetworkIntent(
            site_name="site",
            vlans=vlans,
            routing=RoutingIntent(inter_vlan_routing=True),
        ),
        profile,
    )
    assert not result.valid
    assert any(issue.code == "IP_INTERFACE_CAPACITY_EXCEEDED" for issue in result.blocking)


def test_offline_design_warns_but_does_not_fake_live_capability_proof():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    intent = NetworkIntent(
        site_name="site",
        vlans=(VLANIntent(100, "MGMT"), VLANIntent(110, "OFFICE")),
        ports=(PortIntent("GigabitEthernet1", "office", "access", access_vlan=110),),
        uplinks=(UplinkIntent("TenGigabitEthernet1", allowed_vlans=(100, 110), native_vlan=100),),
        management=ManagementIntent(vlan_id=100, allowed_source_networks=("10.50.0.0/24",)),
        security=SecurityIntent(profile="BUSINESS_STANDARD"),
    )
    result = validate_intent_against_profile(intent, profile, require_live_proof=False)
    assert result.valid
    warnings = [issue for issue in result.issues if issue.code == "PROFILE_CAPABILITY_NOT_LIVE_PROVEN"]
    assert warnings


def test_future_write_precheck_fails_closed_until_required_features_are_live_proven():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    intent = NetworkIntent(
        site_name="site",
        vlans=(VLANIntent(100, "MGMT"),),
        management=ManagementIntent(vlan_id=100, allowed_source_networks=("10.50.0.0/24",)),
        security=SecurityIntent(profile="BUSINESS_STANDARD"),
    )
    result = validate_intent_against_profile(intent, profile, require_live_proof=True)
    assert not result.valid
    assert any(issue.code == "PROFILE_CAPABILITY_NOT_LIVE_PROVEN" for issue in result.blocking)


def test_live_observed_ssh_does_not_create_false_proof_for_other_features():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    states = profile.feature_states
    assert states["ssh_management"].value == "documented_and_observed"
    assert states["vlan_8021q"].value == "documented_not_observed"
    assert states["management_acl"].value == "documented_not_observed"
