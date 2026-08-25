import pytest

from cisco_assistant import (
    CapabilityState,
    DeviceCapability,
    DeviceFingerprint,
    ManagementIntent,
    NetworkIntent,
    ObservedState,
    PortIntent,
    RoutingIntent,
    SecurityIntent,
    SegmentationIntent,
    SegmentationRule,
    UplinkIntent,
    VLANIntent,
    validate_network_intent,
)
from cisco_assistant.models import ModelValidationError


def fingerprint():
    return DeviceFingerprint(
        vendor="Cisco",
        family="CBS250",
        product_id="CBS250-24T-4X",
        firmware_version="3.3.0.16",
        capability_dataset="CBS250-24T-4X_3.3.0.16",
    )


def complete_intent():
    return NetworkIntent(
        site_name="Tokyo Lab",
        vlans=(
            VLANIntent(100, "MGMT", "10.50.0.0/24", "10.50.0.1", "management"),
            VLANIntent(110, "OFFICE", "10.50.1.0/24", "10.50.1.1", "office"),
            VLANIntent(120, "CAMERA", "10.50.2.0/24", "10.50.2.1", "camera"),
        ),
        ports=(
            PortIntent("GigabitEthernet1", "office", "access", access_vlan=110),
            PortIntent("GigabitEthernet9", "camera", "access", access_vlan=120),
        ),
        uplinks=(
            UplinkIntent("TenGigabitEthernet1", allowed_vlans=(100, 110, 120), native_vlan=100),
        ),
        routing=RoutingIntent(inter_vlan_routing=True),
        segmentation=SegmentationIntent(
            rules=(SegmentationRule(120, 110, "deny", "Cameras cannot initiate to office"),)
        ),
        management=ManagementIntent(
            vlan_id=100,
            allowed_source_networks=("10.50.0.0/24",),
        ),
        security=SecurityIntent(profile="BUSINESS_STANDARD"),
    )


def test_complete_normalized_intent_is_consistent():
    intent = complete_intent()
    assert intent.management is not None
    assert intent.management.vlan_id == 100
    assert intent.uplinks[0].native_vlan == 100
    assert intent.segmentation.rules[0].action.value == "deny"
    assert intent.security is not None
    assert intent.security.profile.value == "BUSINESS_STANDARD"


def test_management_vlan_must_exist():
    with pytest.raises(ModelValidationError, match="Management VLAN 200"):
        NetworkIntent(
            site_name="site",
            vlans=(VLANIntent(100, "OFFICE"),),
            management=ManagementIntent(vlan_id=200),
        )


def test_segmentation_rule_must_reference_existing_vlans():
    with pytest.raises(ModelValidationError, match="undefined VLANs"):
        NetworkIntent(
            site_name="site",
            vlans=(VLANIntent(100, "A"), VLANIntent(110, "B")),
            segmentation=SegmentationIntent(
                rules=(SegmentationRule(100, 120, "deny"),)
            ),
        )


def test_same_interface_cannot_be_port_and_uplink():
    with pytest.raises(ModelValidationError, match="both port and uplink"):
        NetworkIntent(
            site_name="site",
            vlans=(VLANIntent(100, "A"),),
            ports=(PortIntent("GE1", "office", "access", access_vlan=100),),
            uplinks=(UplinkIntent("ge1", (100,)),),
        )


def test_capability_aware_validation_passes_proven_exact_state():
    state = ObservedState(
        fingerprint=fingerprint(),
        collected_at_utc="2026-08-25T14:00:00+00:00",
        source_revision="live-v31",
        vlan_ids=(1,),
        interfaces=("GigabitEthernet1", "GigabitEthernet9", "TenGigabitEthernet1"),
        capabilities=(
            DeviceCapability(
                feature_id="vlan.create",
                state=CapabilityState.DOCUMENTED_AND_OBSERVED,
                source="Cisco CLI + live discovery",
                risk_class="W1",
            ),
        ),
    )
    result = validate_network_intent(
        complete_intent(),
        observed_state=state,
        max_active_vlans=255,
        required_capability_ids=("vlan.create",),
    )
    assert result.valid
    assert result.blocking == ()


def test_unknown_capability_fails_closed_with_human_remediation():
    state = ObservedState(
        fingerprint=fingerprint(),
        collected_at_utc="2026-08-25T14:00:00+00:00",
        source_revision="live-v31",
        interfaces=("GigabitEthernet1", "GigabitEthernet9", "TenGigabitEthernet1"),
    )
    result = validate_network_intent(
        complete_intent(),
        observed_state=state,
        required_capability_ids=("acl.ipv4.apply",),
    )
    assert not result.valid
    issue = result.blocking[0]
    assert issue.code == "CAPABILITY_UNKNOWN"
    assert "before planning" in issue.remediation


def test_unobserved_port_fails_closed():
    state = ObservedState(
        fingerprint=fingerprint(),
        collected_at_utc="2026-08-25T14:00:00+00:00",
        source_revision="live-v31",
        interfaces=("GigabitEthernet1", "TenGigabitEthernet1"),
    )
    result = validate_network_intent(complete_intent(), observed_state=state)
    assert any(issue.code == "PORT_NOT_OBSERVED" for issue in result.blocking)


def test_uplink_must_carry_access_and_management_vlans():
    intent = NetworkIntent(
        site_name="site",
        vlans=(VLANIntent(100, "MGMT"), VLANIntent(110, "OFFICE")),
        ports=(PortIntent("GE1", "office", "access", access_vlan=110),),
        uplinks=(UplinkIntent("XG1", allowed_vlans=(100,), native_vlan=100),),
        management=ManagementIntent(vlan_id=100, allowed_source_networks=("10.0.0.0/24",)),
    )
    result = validate_network_intent(intent)
    assert not result.valid
    assert result.blocking[0].code == "UPLINK_MISSING_REQUIRED_VLANS"
    assert "110" in result.blocking[0].message


def test_capability_vlan_capacity_is_enforced():
    intent = NetworkIntent(
        site_name="site",
        vlans=(VLANIntent(100, "A"), VLANIntent(110, "B"), VLANIntent(120, "C")),
    )
    result = validate_network_intent(intent, max_active_vlans=2)
    assert not result.valid
    assert result.blocking[0].code == "ACTIVE_VLAN_CAPACITY_EXCEEDED"
