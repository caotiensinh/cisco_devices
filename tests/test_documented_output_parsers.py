import pytest

from cisco_assistant.documented_output_parsers import (
    LIVE_VALIDATED,
    PARSER_AUTHORITY,
    DocumentedParserError,
    parse_documented_show_interfaces_status,
    parse_documented_show_interfaces_switchport,
    parse_documented_show_vlan,
)


def test_parser_foundation_explicitly_has_no_live_validation_authority():
    assert PARSER_AUTHORITY == "DOCUMENTED_FORMAT_ONLY"
    assert LIVE_VALIDATED is False


def test_documented_vlan_table_parses_synthetic_rows():
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
    assert rows[1].vlan_type == "permanent"
    assert rows[1].authorization == "Not Required"


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
