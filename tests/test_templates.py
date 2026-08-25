import pytest

from cisco_assistant.models import SecurityProfile
from cisco_assistant.templates import (
    RolePortCount,
    TemplateError,
    TemplateId,
    TemplateRequest,
    build_template,
    get_template_definition,
    list_templates,
)


def interfaces(count: int) -> tuple[str, ...]:
    return tuple(f"GigabitEthernet{index}" for index in range(1, count + 1))


def test_registry_contains_initial_three_versioned_templates():
    definitions = list_templates()
    assert tuple(definition.template_id for definition in definitions) == (
        TemplateId.SMALL_OFFICE,
        TemplateId.OFFICE_IP_CAMERAS,
        TemplateId.AI_CAMERA_VMS,
    )
    assert all(definition.version == "1.0.0" for definition in definitions)
    assert all(definition.schema_version == 1 for definition in definitions)


def test_small_office_build_is_deterministic_and_sequential():
    request = TemplateRequest(
        template_id="small_office",
        site_name="Tokyo Office",
        start_vlan_id=100,
        vlan_increment=10,
        start_network="10.50.0.0/24",
        security_profile=SecurityProfile.BUSINESS_STANDARD,
        role_port_counts=(
            RolePortCount("guest", 2),
            RolePortCount("office", 4),
        ),
        access_interfaces=interfaces(8),
        uplink_interface="TenGigabitEthernet1",
        management_source_networks=("10.50.0.0/24",),
    )

    first = build_template(request)
    second = build_template(request)

    assert first == second
    assert [vlan.id for vlan in first.intent.vlans] == [100, 110, 120]
    assert [vlan.name for vlan in first.intent.vlans] == ["MGMT", "OFFICE", "GUEST"]
    assert [vlan.network for vlan in first.intent.vlans] == [
        "10.50.0.0/24",
        "10.50.1.0/24",
        "10.50.2.0/24",
    ]
    assert [vlan.gateway for vlan in first.intent.vlans] == [
        "10.50.0.1",
        "10.50.1.1",
        "10.50.2.1",
    ]

    # Allocation follows template role order, not input tuple order.
    assert [port.interface for port in first.intent.ports] == list(interfaces(6))
    assert [port.role for port in first.intent.ports] == [
        "office",
        "office",
        "office",
        "office",
        "guest",
        "guest",
    ]
    assert [port.access_vlan for port in first.intent.ports] == [110, 110, 110, 110, 120, 120]
    assert first.unassigned_interfaces == interfaces(8)[6:]
    assert first.intent.uplinks[0].allowed_vlans == (100, 110, 120)
    assert first.intent.management is not None
    assert first.intent.management.vlan_id == 100
    assert first.validation.valid


def test_office_camera_template_builds_expected_roles():
    result = build_template(
        TemplateRequest(
            template_id=TemplateId.OFFICE_IP_CAMERAS,
            site_name="Branch 1",
            start_vlan_id=200,
            vlan_increment=10,
            start_network="10.60.0.0/24",
            role_port_counts=(
                RolePortCount("office", 2),
                RolePortCount("camera", 3),
            ),
            access_interfaces=interfaces(5),
            uplink_interface="TenGigabitEthernet1",
            management_source_networks=("10.60.0.0/24",),
        )
    )

    assert [(vlan.id, vlan.purpose) for vlan in result.intent.vlans] == [
        (200, "management"),
        (210, "office"),
        (220, "camera"),
    ]
    assert [port.role for port in result.intent.ports] == [
        "office",
        "office",
        "camera",
        "camera",
        "camera",
    ]


def test_ai_camera_vms_template_builds_four_networks():
    result = build_template(
        TemplateRequest(
            template_id="ai_camera_vms",
            site_name="AI Site",
            start_vlan_id=300,
            vlan_increment=10,
            start_network="10.70.254.0/24",
            role_port_counts=(
                RolePortCount("camera", 2),
                RolePortCount("ai_server", 1),
                RolePortCount("vms", 1),
            ),
            access_interfaces=interfaces(4),
            uplink_interface="TenGigabitEthernet1",
            management_source_networks=("10.70.254.0/24",),
        )
    )

    assert [vlan.name for vlan in result.intent.vlans] == [
        "MGMT",
        "CAMERA",
        "AI_SERVER",
        "VMS",
    ]
    assert [vlan.network for vlan in result.intent.vlans] == [
        "10.70.254.0/24",
        "10.70.255.0/24",
        "10.71.0.0/24",
        "10.71.1.0/24",
    ]


def test_template_rejects_unknown_or_non_assignable_role():
    with pytest.raises(TemplateError, match="does not define roles"):
        build_template(
            TemplateRequest(
                template_id="small_office",
                site_name="site",
                start_vlan_id=100,
                start_network="10.0.0.0/24",
                role_port_counts=(RolePortCount("camera", 1),),
                access_interfaces=("GigabitEthernet1",),
            )
        )

    with pytest.raises(TemplateError, match="not access-port assignable"):
        build_template(
            TemplateRequest(
                template_id="small_office",
                site_name="site",
                start_vlan_id=100,
                start_network="10.0.0.0/24",
                role_port_counts=(RolePortCount("management", 1),),
                access_interfaces=("GigabitEthernet1",),
            )
        )


def test_template_rejects_port_capacity_and_vlan_overflow():
    with pytest.raises(TemplateError, match="Requested 3 access ports"):
        build_template(
            TemplateRequest(
                template_id="office_ip_cameras",
                site_name="site",
                start_vlan_id=100,
                start_network="10.0.0.0/24",
                role_port_counts=(
                    RolePortCount("office", 2),
                    RolePortCount("camera", 1),
                ),
                access_interfaces=("GigabitEthernet1", "GigabitEthernet2"),
            )
        )

    with pytest.raises(TemplateError, match="exceeds 4094"):
        build_template(
            TemplateRequest(
                template_id="ai_camera_vms",
                site_name="site",
                start_vlan_id=4090,
                vlan_increment=10,
                start_network="10.0.0.0/24",
            )
        )


def test_template_does_not_invent_interface_names_when_none_are_supplied():
    result = build_template(
        TemplateRequest(
            template_id="small_office",
            site_name="offline-only",
            start_vlan_id=100,
            start_network="10.0.0.0/24",
        )
    )
    assert result.intent.ports == ()
    assert result.intent.uplinks == ()
    assert any("No uplink is declared" in note for note in result.notes)


def test_template_definition_lookup_fails_closed():
    with pytest.raises(TemplateError, match="Unknown template_id"):
        get_template_definition("not-a-template")
