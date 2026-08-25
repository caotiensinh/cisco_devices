from cisco_assistant.preview import build_design_preview
from cisco_assistant.templates import (
    RolePortCount,
    TemplateRequest,
    build_template,
)


def test_preview_is_structured_human_readable_and_cli_free():
    result = build_template(
        TemplateRequest(
            template_id="office_ip_cameras",
            site_name="Tokyo Branch",
            start_vlan_id=100,
            vlan_increment=10,
            start_network="10.50.0.0/24",
            role_port_counts=(
                RolePortCount("office", 2),
                RolePortCount("camera", 2),
            ),
            access_interfaces=(
                "GigabitEthernet1",
                "GigabitEthernet2",
                "GigabitEthernet3",
                "GigabitEthernet4",
                "GigabitEthernet5",
            ),
            uplink_interface="TenGigabitEthernet1",
            management_source_networks=("10.50.0.0/24",),
        )
    )

    preview = build_design_preview(result)
    payload = preview.as_dict()
    text = preview.render_text()

    assert preview.device_commands_generated is False
    assert payload["device_commands_generated"] is False
    assert payload["template"] == {
        "id": "office_ip_cameras",
        "version": "1.0.0",
        "name": "Office + IP Cameras",
    }
    assert payload["validation"]["valid"] is True
    assert payload["management"]["vlan"] == 100
    assert [row["id"] for row in payload["vlans"]] == [100, 110, 120]
    assert payload["unassigned_interfaces"] == ["GigabitEthernet5"]

    assert "NETWORK DESIGN PREVIEW" in text
    assert "Device commands generated: NO" in text
    assert "VLAN 100" in text
    assert "VLAN 110" in text
    assert "VLAN 120" in text
    assert "TenGigabitEthernet1" in text
    assert "Status: PASS" in text

    lower = text.lower()
    assert "configure terminal" not in lower
    assert "write memory" not in lower
    assert "copy running-config startup-config" not in lower


def test_preview_preserves_management_warning_when_source_networks_missing():
    result = build_template(
        TemplateRequest(
            template_id="small_office",
            site_name="No Mgmt Source Yet",
            start_vlan_id=100,
            start_network="10.80.0.0/24",
        )
    )
    preview = build_design_preview(result)

    assert preview.validation_valid is True
    assert any(
        issue.code == "MANAGEMENT_SOURCES_UNDEFINED"
        and issue.severity == "WARNING"
        for issue in preview.validation_issues
    )
    assert "Allowed sources: not-declared" in preview.render_text()


def test_preview_is_deterministic_for_same_template_request():
    request = TemplateRequest(
        template_id="ai_camera_vms",
        site_name="Video Site",
        start_vlan_id=200,
        start_network="10.90.0.0/24",
        role_port_counts=(
            RolePortCount("camera", 2),
            RolePortCount("ai_server", 1),
            RolePortCount("vms", 1),
        ),
        access_interfaces=("GE1", "GE2", "GE3", "GE4"),
        uplink_interface="XG1",
        management_source_networks=("10.90.0.0/24",),
    )

    preview_a = build_design_preview(build_template(request))
    preview_b = build_design_preview(build_template(request))

    assert preview_a == preview_b
    assert preview_a.as_dict() == preview_b.as_dict()
    assert preview_a.render_text() == preview_b.render_text()
