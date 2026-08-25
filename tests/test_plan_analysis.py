from cisco_assistant.current_state import CurrentNetworkState
from cisco_assistant.dry_run import build_device_aware_dry_run
from cisco_assistant.models import NetworkIntent, PortIntent, SecurityProfile, VLANIntent
from cisco_assistant.plan_analysis import analyze_change_plan
from cisco_assistant.planner import build_change_plan
from cisco_assistant.profiles import load_cbs250_24t_4x_3_3_0_16_profile
from cisco_assistant.templates import RolePortCount, TemplateRequest


def test_management_changes_are_never_described_as_safe_to_apply():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    request = TemplateRequest(
        template_id="small_office",
        site_name="Management Impact Site",
        start_vlan_id=100,
        start_network="10.10.0.0/24",
        role_port_counts=(RolePortCount("office", 1),),
        access_interfaces=("GE1",),
        uplink_interface="XG1",
        management_source_networks=("10.10.0.0/24",),
    )

    result = build_device_aware_dry_run(
        request,
        profile,
        CurrentNetworkState(basis="blank_design"),
    )
    impact = result.analysis.management_impact

    assert impact.management_vlan_id == 100
    assert impact.affected_operation_ids
    assert impact.lockout_analysis_complete is False
    assert impact.safe_to_apply is False
    assert impact.status == "REVIEW_REQUIRED_AND_CURRENTLY_BLOCKED"
    assert "Lockout analysis complete: NO" in result.render_text()
    assert "Safe to apply: NO" in result.render_text()


def test_risk_summary_counts_w1_and_w2_and_requires_future_safety_gate():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    request = TemplateRequest(
        template_id="office_ip_cameras",
        site_name="Risk Site",
        start_vlan_id=100,
        start_network="10.20.0.0/24",
        role_port_counts=(RolePortCount("office", 1), RolePortCount("camera", 1)),
        access_interfaces=("GE1", "GE2"),
        uplink_interface="XG1",
        management_source_networks=("10.20.0.0/24",),
    )
    result = build_device_aware_dry_run(
        request,
        profile,
        CurrentNetworkState(basis="blank_design"),
    )

    counts = dict(result.analysis.risk.counts)
    assert counts["W1"] >= 1
    assert counts["W2"] >= 1
    assert result.analysis.risk.highest_risk == "W2"
    assert result.analysis.risk.future_safety_gate_required
    assert result.analysis.risk.destructive_operation_ids == ()


def test_plan_without_management_intent_reports_no_direct_management_change():
    intent = NetworkIntent(
        site_name="No Management Change",
        vlans=(VLANIntent(200, "DATA"),),
        ports=(PortIntent("GE1", "data", "access", access_vlan=200),),
        security_profile=SecurityProfile.LAB,
    )
    plan = build_change_plan(intent, CurrentNetworkState(basis="blank_design"))
    analysis = analyze_change_plan(plan, intent)

    assert analysis.management_impact.management_vlan_id is None
    assert analysis.management_impact.affected_operation_ids == ()
    assert analysis.management_impact.status == "NO_DIRECT_MANAGEMENT_CHANGE_IDENTIFIED"
    assert analysis.management_impact.safe_to_apply is False


def test_analysis_is_deterministic():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    request = TemplateRequest(
        template_id="small_office",
        site_name="Deterministic Analysis",
        start_vlan_id=100,
        start_network="10.30.0.0/24",
        role_port_counts=(RolePortCount("office", 1),),
        access_interfaces=("GE1",),
        uplink_interface="XG1",
        management_source_networks=("10.30.0.0/24",),
    )
    current = CurrentNetworkState(basis="blank_design")

    first = build_device_aware_dry_run(request, profile, current)
    second = build_device_aware_dry_run(request, profile, current)

    assert first.analysis == second.analysis
    assert first.analysis.as_dict() == second.analysis.as_dict()
    assert first.analysis.render_text() == second.analysis.render_text()
