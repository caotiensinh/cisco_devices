from cisco_assistant.current_state import (
    CurrentAccessPortState,
    CurrentManagementState,
    CurrentNetworkState,
    CurrentStateBasis,
    CurrentTrunkState,
    CurrentVLANState,
)
from cisco_assistant.models import (
    ManagementIntent,
    NetworkIntent,
    PortIntent,
    RoutingIntent,
    SecurityProfile,
    UplinkIntent,
    VLANIntent,
)
from cisco_assistant.planner import (
    OperationReadiness,
    OperationType,
    build_change_plan,
)
from cisco_assistant.profiles import load_cbs250_24t_4x_3_3_0_16_profile
from cisco_assistant.security_profiles import expand_security_profile
from cisco_assistant.templates import RolePortCount, TemplateRequest, build_template


def small_office_intent():
    return build_template(
        TemplateRequest(
            template_id="small_office",
            site_name="Tokyo Office",
            start_vlan_id=100,
            vlan_increment=10,
            start_network="10.50.0.0/24",
            role_port_counts=(
                RolePortCount("office", 2),
                RolePortCount("guest", 1),
            ),
            access_interfaces=("GE1", "GE2", "GE3"),
            uplink_interface="XG1",
            management_source_networks=("10.50.0.0/24",),
            security_profile=SecurityProfile.BUSINESS_STANDARD,
        )
    ).intent


def test_blank_design_produces_semantic_operations_but_no_execution_authority():
    intent = small_office_intent()
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    current = CurrentNetworkState(basis=CurrentStateBasis.BLANK_DESIGN)

    plan = build_change_plan(intent, current, device_profile=profile)
    payload = plan.as_dict()

    assert plan.changes_required
    assert plan.execution_authority is False
    assert plan.device_commands_generated is False
    assert plan.implicit_removals is False
    assert payload["execution_authority"] is False
    assert payload["device_commands_generated"] is False
    assert payload["implicit_removals"] is False

    types = [operation.operation_type for operation in plan.operations]
    assert types.count(OperationType.CREATE_VLAN) == 3
    assert types.count(OperationType.ASSIGN_ACCESS_PORT) == 3
    assert types.count(OperationType.CONFIGURE_TRUNK) == 1
    assert types.count(OperationType.SET_MANAGEMENT_POLICY) == 1
    assert OperationType.APPLY_SECURITY_POLICY_RULE in types

    # Current exact profile has VLAN and most security controls documented but not live-proven.
    assert not plan.provider_ready
    assert plan.status == "DRY_RUN_BLOCKED_FOR_PROVIDER"
    assert any(
        operation.readiness is OperationReadiness.BLOCKED_CAPABILITY
        for operation in plan.operations
    )
    assert "Device commands generated: NO" in plan.render_text()
    assert "Execution authority: FALSE" in plan.render_text()


def test_fully_compliant_current_state_is_idempotent_zero_change():
    intent = small_office_intent()
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    security = expand_security_profile(
        SecurityProfile.BUSINESS_STANDARD,
        device_profile=profile,
    )
    applicable_rule_ids = tuple(
        rule.rule_id
        for rule in security.rules
        if rule.rule_id != "segmentation.ipv4_acl"
    )

    current = CurrentNetworkState(
        basis=CurrentStateBasis.OBSERVED_COMPLETE,
        vlans=(
            CurrentVLANState(100, "MGMT"),
            CurrentVLANState(110, "OFFICE"),
            CurrentVLANState(120, "GUEST"),
        ),
        access_ports=(
            CurrentAccessPortState("GE1", 110),
            CurrentAccessPortState("GE2", 110),
            CurrentAccessPortState("GE3", 120),
        ),
        trunks=(CurrentTrunkState("XG1", (100, 110, 120)),),
        management=CurrentManagementState(
            vlan_id=100,
            allowed_source_networks=("10.50.0.0/24",),
            services=("https", "ssh"),
        ),
        satisfied_security_rules=applicable_rule_ids,
        collected_at_utc="2026-08-25T14:00:00+00:00",
        source_revision="complete-test",
    )

    plan = build_change_plan(
        intent,
        current,
        device_profile=profile,
        security_expansion=security,
    )

    assert plan.operations == ()
    assert plan.changes_required is False
    assert plan.status == "NO_CHANGES"
    assert plan.provider_ready


def test_vlan_port_and_trunk_differences_produce_typed_changes():
    intent = NetworkIntent(
        site_name="Diff Site",
        vlans=(
            VLANIntent(100, "MGMT", "10.0.0.0/24", "10.0.0.1", "management"),
            VLANIntent(110, "OFFICE", "10.0.1.0/24", "10.0.1.1", "office"),
        ),
        ports=(PortIntent("GE1", "office", "access", access_vlan=110),),
        uplinks=(UplinkIntent("XG1", (100, 110)),),
        management=ManagementIntent(
            vlan_id=100,
            allowed_source_networks=("10.0.0.0/24",),
        ),
        security_profile=SecurityProfile.LAB,
    )
    current = CurrentNetworkState(
        basis="observed_complete",
        vlans=(
            CurrentVLANState(100, "OLD-MGMT"),
            CurrentVLANState(110, "OFFICE"),
        ),
        access_ports=(CurrentAccessPortState("GE1", 100),),
        trunks=(CurrentTrunkState("XG1", (100,)),),
        management=CurrentManagementState(
            vlan_id=100,
            allowed_source_networks=(),
            services=("ssh",),
        ),
        satisfied_security_rules=("management.ssh",),
        collected_at_utc="2026-08-25T14:00:00+00:00",
        source_revision="diff-test",
    )

    plan = build_change_plan(intent, current)
    types = {operation.operation_type for operation in plan.operations}

    assert OperationType.UPDATE_VLAN in types
    assert OperationType.ASSIGN_ACCESS_PORT in types
    assert OperationType.SET_ALLOWED_VLANS in types
    assert OperationType.SET_MANAGEMENT_POLICY in types
    assert all(operation.destructive is False for operation in plan.operations)


def test_new_vlan_dependencies_are_explicit_for_port_and_trunk():
    intent = NetworkIntent(
        site_name="Dependency Site",
        vlans=(VLANIntent(200, "CAMERA"),),
        ports=(PortIntent("GE5", "camera", "access", access_vlan=200),),
        uplinks=(UplinkIntent("XG1", (200,)),),
        security_profile=SecurityProfile.LAB,
    )
    current = CurrentNetworkState(basis="blank_design")

    plan = build_change_plan(intent, current)
    create = next(
        operation
        for operation in plan.operations
        if operation.operation_type is OperationType.CREATE_VLAN
    )
    access = next(
        operation
        for operation in plan.operations
        if operation.operation_type is OperationType.ASSIGN_ACCESS_PORT
    )
    trunk = next(
        operation
        for operation in plan.operations
        if operation.operation_type is OperationType.CONFIGURE_TRUNK
    )

    assert create.operation_id in access.dependencies
    assert create.operation_id in trunk.dependencies


def test_partial_observed_state_never_treats_absence_as_authoritative():
    intent = NetworkIntent(
        site_name="Partial Site",
        vlans=(VLANIntent(100, "OFFICE"),),
        ports=(PortIntent("GE1", "office", "access", access_vlan=100),),
        security_profile=SecurityProfile.LAB,
    )
    current = CurrentNetworkState(
        basis="observed_partial",
        collected_at_utc="2026-08-25T14:00:00+00:00",
        source_revision="partial-test",
    )

    plan = build_change_plan(intent, current)

    assert not plan.provider_ready
    assert any(issue.code == "CURRENT_STATE_PARTIAL" for issue in plan.issues)
    assert any(
        operation.readiness is OperationReadiness.BLOCKED_CURRENT_STATE
        for operation in plan.operations
    )


def test_extra_current_objects_are_preserved_not_implicitly_removed():
    intent = NetworkIntent(
        site_name="Preserve Site",
        vlans=(VLANIntent(100, "OFFICE"),),
        ports=(PortIntent("GE1", "office", "access", access_vlan=100),),
        security_profile=SecurityProfile.LAB,
    )
    current = CurrentNetworkState(
        basis="observed_complete",
        vlans=(
            CurrentVLANState(100, "OFFICE"),
            CurrentVLANState(999, "LEGACY"),
        ),
        access_ports=(
            CurrentAccessPortState("GE1", 100),
            CurrentAccessPortState("GE24", 999),
        ),
        collected_at_utc="2026-08-25T14:00:00+00:00",
        source_revision="preserve-test",
    )

    plan = build_change_plan(intent, current)

    assert plan.implicit_removals is False
    assert "vlan:999" in plan.preserved_current_objects
    assert "interface:GE24" in plan.preserved_current_objects
    assert all("Remove" not in operation.operation_type.value for operation in plan.operations)


def test_inter_vlan_routing_produces_w2_l3_operation_depending_on_vlan_creation():
    intent = NetworkIntent(
        site_name="Routed Site",
        vlans=(VLANIntent(100, "OFFICE", "10.1.0.0/24", "10.1.0.1"),),
        routing=RoutingIntent(inter_vlan_routing=True),
        security_profile=SecurityProfile.LAB,
    )
    current = CurrentNetworkState(basis="blank_design")

    plan = build_change_plan(intent, current)
    create = next(op for op in plan.operations if op.operation_type is OperationType.CREATE_VLAN)
    l3 = next(
        op
        for op in plan.operations
        if op.operation_type is OperationType.CONFIGURE_L3_INTERFACE
    )

    assert l3.risk_class == "W2"
    assert create.operation_id in l3.dependencies
    assert l3.desired == {
        "vlan_id": 100,
        "network": "10.1.0.0/24",
        "gateway": "10.1.0.1",
    }


def test_plan_operation_ids_and_hash_are_deterministic():
    profile = load_cbs250_24t_4x_3_3_0_16_profile()
    intent = small_office_intent()
    current = CurrentNetworkState(basis="blank_design")

    first = build_change_plan(intent, current, device_profile=profile)
    second = build_change_plan(intent, current, device_profile=profile)

    assert first == second
    assert first.plan_hash == second.plan_hash
    assert [op.operation_id for op in first.operations] == [
        op.operation_id for op in second.operations
    ]
    assert first.as_dict() == second.as_dict()
    assert first.render_text() == second.render_text()
