import pytest

from cisco_assistant.documented_output_parsers import (
    LIVE_VALIDATED,
    PARSER_AUTHORITY,
    VLAN_FORMAT_LEGACY,
    VLAN_FORMAT_TAGGED_UNTAGGED,
    DocumentedParserError,
    parse_documented_show_interfaces_status,
    parse_documented_show_interfaces_switchport,
    parse_documented_show_vlan,
)


def test_parser_foundation_explicitly_has_no_live_validation_authority():
    assert PARSER_AUTHORITY == "DOCUMENTED_FORMAT_ONLY"
    assert LIVE_VALIDATED is False


def test_documented_vlan_table_parses_legacy_synthetic_rows():
    text = """
Vlan  Name       Ports              Type       Authorization
----  ---------  -----------------  ---------  -------------
1     default    ge1-ge4,Po1        other      Required
120   CAMERAS    ge5,ge6            permanent  Not Required
switch#
"""
    rows = parse_documented_show_vlan(text)
    assert [(row.vlan_id, row.name) for row in rows] == [(1, "default"), (120, "CAMERAS")]
    assert rows[0].ports == ("ge1-ge4", "Po1")
    assert rows[0].format_variant == VLAN_FORMAT_LEGACY
    assert rows[0].tagged_ports == ()
    assert rows[0].untagged_ports == ()
    assert rows[0].created_by is None
    assert rows[1].vlan_type == "permanent"
    assert rows[1].authorization == "Not Required"


def _current_vlan_table() -> str:
    header = f"{'VLAN':<8}{'Name':<18}{'Tagged Ports':<24}{'UnTagged Ports':<24}{'Created by'}"
    separator = f"{'-----':<8}{'-----------':<18}{'--------------':<24}{'--------------':<24}{'----------'}"
    rows = [
        f"{1:<8}{'Default':<18}{'':<24}{'gi1/0/1':<24}{'S'}",
        f"{10:<8}{'Marketing':<18}{'gi1/0/2':<24}{'gi1/0/2':<24}{'S'}",
        f"{91:<8}{'CAMERAS':<18}{'gi1/0/2-4':<24}{'gi1/0/2':<24}{'SGR'}",
        # A wrapped continuation has no VLAN id in the first column and must not become a row.
        f"{'':<8}{'':<18}{'gi1/0/5-8':<24}{'':<24}{''}",
        f"{92:<8}{'AI':<18}{'gi1/0/3-4':<24}{'':<24}{'G'}",
    ]
    return "\n".join(
        [
            "switch# show vlan",
            "Created by: S-Static, G-GVRP, R-Radius Assigned VLAN, V-Voice VLAN",
            header,
            separator,
            *rows,
            "switch#",
        ]
    )


def test_documented_vlan_table_parses_current_tagged_untagged_shape():
    rows = parse_documented_show_vlan(_current_vlan_table())
    assert [row.vlan_id for row in rows] == [1, 10, 91, 92]
    assert all(row.format_variant == VLAN_FORMAT_TAGGED_UNTAGGED for row in rows)

    default = rows[0]
    assert default.name == "Default"
    assert default.tagged_ports == ()
    assert default.untagged_ports == ("gi1/0/1",)
    assert default.ports == ("gi1/0/1",)
    assert default.created_by == "S"
    assert default.vlan_type == ""
    assert default.authorization == ""

    marketing = rows[1]
    assert marketing.tagged_ports == ("gi1/0/2",)
    assert marketing.untagged_ports == ("gi1/0/2",)
    assert marketing.ports == ("gi1/0/2",)

    cameras = rows[2]
    assert cameras.tagged_ports == ("gi1/0/2-4",)
    assert cameras.untagged_ports == ("gi1/0/2",)
    assert cameras.ports == ("gi1/0/2-4", "gi1/0/2")
    assert cameras.created_by == "SGR"

    ai = rows[3]
    assert ai.untagged_ports == ()
    assert ai.created_by == "G"


def test_current_vlan_parser_requires_created_by_for_every_row():
    header = f"{'VLAN':<8}{'Name':<18}{'Tagged Ports':<24}{'UnTagged Ports':<24}{'Created by'}"
    row = f"{100:<8}{'OFFICE':<18}{'gi1/0/1':<24}{'':<24}{''}"
    with pytest.raises(DocumentedParserError, match="no Created by value"):
        parse_documented_show_vlan(header + "\n" + row + "\n")


def test_documented_vlan_parser_requires_recognizable_header():
    with pytest.raises(DocumentedParserError, match="header was not found"):
        parse_documented_show_vlan("1 default ge1 permanent Required\n")


def test_documented_interface_status_parses_physical_rows_only():
    text = """
Port    Type       Duplex  Speed  Neg       Flow  Link  Back      Mdix
ge1     1G-Copper  Full    1000   Enabled   Off   Up    Disabled  Off
xg1     10G-Fiber  Full    10000  Disabled  Off   Up    Disabled  --
PO      Type       Speed   Neg    Flow      Admin
Po1     1G         1000    Off    Off       Up
"""
    rows = parse_documented_show_interfaces_status(text)
    assert [row.interface for row in rows] == ["ge1", "xg1"]
    assert rows[0].speed == "1000"
    assert rows[0].link_state == "Up"
    assert rows[1].media_type == "10G-Fiber"


def test_documented_interface_status_requires_header_and_rows():
    with pytest.raises(DocumentedParserError, match="header was not found"):
        parse_documented_show_interfaces_status("ge1 1G-Copper Full 1000 Enabled Off Up Disabled Off")

    with pytest.raises(DocumentedParserError, match="no documented physical-interface rows"):
        parse_documented_show_interfaces_status("Port Type Duplex Speed\n----- ---- ------ -----\n")


def test_documented_switchport_parser_preserves_unknown_fields():
    text = """
Name: ge1
Switchport: enable
Administrative Mode: access
Operational Mode: down
Access Mode VLAN: 120
Trunking Native Mode VLAN: 1
General PVID: 120
Future Firmware Field: retained-value
"""
    state = parse_documented_show_interfaces_switchport(text)
    assert state.name == "ge1"
    assert state.switchport == "enable"
    assert state.administrative_mode == "access"
    assert state.access_mode_vlan == "120"
    assert state.general_pvid == "120"
    assert state.field_map["Future Firmware Field"] == "retained-value"


def test_documented_switchport_parser_requires_name():
    with pytest.raises(DocumentedParserError, match="Name field was not found"):
        parse_documented_show_interfaces_switchport("Administrative Mode: access\n")
