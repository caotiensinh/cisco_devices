from cisco_assistant.current_state import (
    CurrentAccessPortState,
    CurrentManagementState,
    CurrentNetworkState,
    CurrentTrunkState,
    CurrentVLANState,
)
from cisco_assistant.state_view import build_current_state_preview


def test_current_state_preview_is_structured_and_deterministic():
    state = CurrentNetworkState(
        basis="observed_complete",
        vlans=(
            CurrentVLANState(120, "CAMERA"),
            CurrentVLANState(100, "MGMT"),
        ),
        access_ports=(
            CurrentAccessPortState("GE2", 120),
            CurrentAccessPortState("GE1", 100),
        ),
        trunks=(CurrentTrunkState("XG1", (120, 100), native_vlan=100),),
        management=CurrentManagementState(
            vlan_id=100,
            allowed_source_networks=("10.0.0.0/24",),
            services=("ssh", "https"),
        ),
        satisfied_security_rules=("management.ssh",),
        collected_at_utc="2026-08-25T14:00:00+00:00",
        source_revision="state-view-test",
    )

    first = build_current_state_preview(state)
    second = build_current_state_preview(state)

    assert first == second
    assert [row["vlan_id"] for row in first.vlans] == [100, 120]
    assert [row["interface"] for row in first.access_ports] == ["GE1", "GE2"]
    assert first.absence_is_authoritative
    assert first.management["vlan_id"] == 100
    assert "CURRENT NETWORK STATE" in first.render_text()
    assert first.as_dict() == second.as_dict()


def test_partial_state_preview_explicitly_marks_absence_non_authoritative():
    state = CurrentNetworkState(
        basis="observed_partial",
        collected_at_utc="2026-08-25T14:00:00+00:00",
        source_revision="partial-state-view-test",
    )
    preview = build_current_state_preview(state)

    assert preview.absence_is_authoritative is False
    assert preview.as_dict()["absence_is_authoritative"] is False
    assert "Absence authoritative: NO" in preview.render_text()
