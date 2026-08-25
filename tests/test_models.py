import pytest

from cisco_assistant.models import (
    DeviceFingerprint,
    ModelValidationError,
    NetworkIntent,
    PortIntent,
    PortMode,
    SecurityProfile,
    VLANIntent,
)


def test_device_fingerprint_normalizes_management_protocol():
    fingerprint = DeviceFingerprint(
        vendor="Cisco",
        family="CBS250",
        product_id="CBS250-24T-4X",
        firmware_version="3.3.0.16",
        management_protocol="SSH",
        capability_dataset="CBS250-24T-4X_3.3.0.16",
    )
    assert fingerprint.management_protocol == "ssh"


def test_device_fingerprint_rejects_empty_or_unknown_management_protocol():
    with pytest.raises(ModelValidationError, match="product_id"):
        DeviceFingerprint(
            vendor="Cisco",
            family="CBS250",
            product_id=" ",
            firmware_version="3.3.0.16",
        )

    with pytest.raises(ModelValidationError, match="management_protocol"):
        DeviceFingerprint(
            vendor="Cisco",
            family="CBS250",
            product_id="CBS250-24T-4X",
            firmware_version="3.3.0.16",
            management_protocol="telnet",
        )


def test_vlan_gateway_must_be_inside_subnet_and_not_network_or_broadcast():
    with pytest.raises(ModelValidationError, match="outside"):
        VLANIntent(
            id=100,
            name="OFFICE",
            network="10.10.0.0/24",
            gateway="10.11.0.1",
        )

    with pytest.raises(ModelValidationError, match="network/broadcast"):
        VLANIntent(
            id=100,
            name="OFFICE",
            network="10.10.0.0/24",
            gateway="10.10.0.0",
        )


def test_vlan_network_must_be_canonical():
    with pytest.raises(ModelValidationError, match="canonical"):
        VLANIntent(
            id=100,
            name="OFFICE",
            network="10.10.0.7/24",
            gateway="10.10.0.1",
        )


def test_access_and_trunk_port_semantics():
    access = PortIntent(
        interface="GigabitEthernet1",
        role="office",
        mode=PortMode.ACCESS,
        access_vlan=100,
    )
    assert access.mode is PortMode.ACCESS

    trunk = PortIntent(
        interface="TenGigabitEthernet1",
        role="core_uplink",
        mode="trunk",
        allowed_vlans=(100, 110, 120),
        native_vlan=100,
    )
    assert trunk.mode is PortMode.TRUNK

    with pytest.raises(ModelValidationError, match="requires access_vlan"):
        PortIntent(interface="GigabitEthernet2", role="office", mode="access")

    with pytest.raises(ModelValidationError, match="requires at least one allowed VLAN"):
        PortIntent(interface="TenGigabitEthernet2", role="uplink", mode="trunk")

    with pytest.raises(ModelValidationError, match="must be included"):
        PortIntent(
            interface="TenGigabitEthernet3",
            role="uplink",
            mode="trunk",
            allowed_vlans=(100, 110),
            native_vlan=120,
        )


def test_network_intent_accepts_consistent_design():
    intent = NetworkIntent(
        site_name="Tokyo Office",
        vlans=(
            VLANIntent(100, "OFFICE", "10.50.0.0/24", "10.50.0.1", "office"),
            VLANIntent(110, "CAMERA", "10.50.1.0/24", "10.50.1.1", "camera"),
        ),
        ports=(
            PortIntent("GigabitEthernet1", "office", "access", access_vlan=100),
            PortIntent("GigabitEthernet9", "camera", "access", access_vlan=110),
            PortIntent(
                "TenGigabitEthernet1",
                "core_uplink",
                "trunk",
                allowed_vlans=(100, 110),
                native_vlan=100,
            ),
        ),
        security_profile=SecurityProfile.BUSINESS_STANDARD,
    )
    assert intent.security_profile is SecurityProfile.BUSINESS_STANDARD
    assert len(intent.vlans) == 2
    assert len(intent.ports) == 3


def test_network_intent_rejects_duplicate_vlan_id():
    with pytest.raises(ModelValidationError, match="Duplicate VLAN ID"):
        NetworkIntent(
            site_name="site",
            vlans=(
                VLANIntent(100, "A"),
                VLANIntent(100, "B"),
            ),
        )


def test_network_intent_rejects_overlapping_subnets():
    with pytest.raises(ModelValidationError, match="Subnet overlap"):
        NetworkIntent(
            site_name="site",
            vlans=(
                VLANIntent(100, "A", "10.0.0.0/24", "10.0.0.1"),
                VLANIntent(110, "B", "10.0.0.128/25", "10.0.0.129"),
            ),
        )


def test_network_intent_rejects_undefined_vlan_port_reference():
    with pytest.raises(ModelValidationError, match="undefined VLANs"):
        NetworkIntent(
            site_name="site",
            vlans=(VLANIntent(100, "OFFICE"),),
            ports=(
                PortIntent(
                    "TenGigabitEthernet1",
                    "uplink",
                    "trunk",
                    allowed_vlans=(100, 200),
                ),
            ),
        )


def test_network_intent_rejects_duplicate_port_assignment_case_insensitive():
    with pytest.raises(ModelValidationError, match="Duplicate port assignment"):
        NetworkIntent(
            site_name="site",
            vlans=(VLANIntent(100, "OFFICE"),),
            ports=(
                PortIntent("GE1", "office", "access", access_vlan=100),
                PortIntent("ge1", "office-duplicate", "access", access_vlan=100),
            ),
        )
