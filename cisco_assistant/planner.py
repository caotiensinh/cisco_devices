"""Deterministic offline desired-state / diff planner.

The planner compares normalized current state with normalized desired intent and emits only
semantic typed operations. It contains no Cisco CLI, no SSH, no provider execution, and no
implicit deletion behavior.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from typing import Any

from .current_state import (
    CurrentAccessPortState,
    CurrentNetworkState,
    CurrentStateBasis,
    CurrentTrunkState,
    CurrentVLANState,
)
from .models import CapabilityState, NetworkIntent, PortMode
from .profiles import DeviceProfile
from .security_profiles import (
    ExpandedSecurityRule,
    SecurityExpansionResult,
    expand_security_profile,
)
from .validation import ValidationIssue, ValidationSeverity


PLAN_SCHEMA_VERSION = 1


class OperationType(str, Enum):
    CREATE_VLAN = "CreateVlan"
    UPDATE_VLAN = "UpdateVlan"
    CONFIGURE_L3_INTERFACE = "ConfigureL3Interface"
    ASSIGN_ACCESS_PORT = "AssignAccessPort"
    CONFIGURE_TRUNK = "ConfigureTrunk"
    SET_ALLOWED_VLANS = "SetAllowedVlans"
    SET_MANAGEMENT_POLICY = "SetManagementPolicy"
    APPLY_SECURITY_POLICY_RULE = "ApplySecurityPolicyRule"


class OperationReadiness(str, Enum):
    READY = "ready"
    BLOCKED_CAPABILITY = "blocked_capability"
    BLOCKED_CURRENT_STATE = "blocked_current_state"
    POLICY_ONLY = "policy_only"


class RollbackStrategy(str, Enum):
    RESTORE_BEFORE_STATE = "restore_before_state"
    PROVIDER_DEFINED = "provider_defined"
    NOT_AUTOMATICALLY_DEFINED = "not_automatically_defined"


@dataclass(frozen=True, slots=True)
class VerificationSpec:
    method: str
    expected: dict[str, Any]

    def __post_init__(self) -> None:
        if not self.method.strip():
            raise ValueError("verification method must not be empty")

    def as_dict(self) -> dict[str, Any]:
        return {"method": self.method, "expected": self.expected}


@dataclass(frozen=True, slots=True)
class RollbackSpec:
    strategy: RollbackStrategy
    restore: dict[str, Any] | None
    note: str

    def __post_init__(self) -> None:
        if not self.note.strip():
            raise ValueError("rollback note must not be empty")

    def as_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy.value,
            "restore": self.restore,
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class PlannedOperation:
    operation_id: str
    operation_type: OperationType
    target: str
    risk_class: str
    readiness: OperationReadiness
    dependencies: tuple[str, ...]
    before: dict[str, Any] | None
    desired: dict[str, Any]
    capability_requirements: tuple[str, ...]
    verification: VerificationSpec
    rollback: RollbackSpec
    destructive: bool = False
    device_commands_generated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "operation_type": self.operation_type.value,
            "target": self.target,
            "risk_class": self.risk_class,
            "readiness": self.readiness.value,
            "dependencies": list(self.dependencies),
            "before": self.before,
            "desired": self.desired,
            "capability_requirements": list(self.capability_requirements),
            "verification": self.verification.as_dict(),
            "rollback": self.rollback.as_dict(),
            "destructive": self.destructive,
            "device_commands_generated": self.device_commands_generated,
        }


@dataclass(frozen=True, slots=True)
class ChangePlan:
    schema_version: int
    current_state_basis: CurrentStateBasis
    operations: tuple[PlannedOperation, ...]
    issues: tuple[ValidationIssue, ...]
    preserved_current_objects: tuple[str, ...]
    plan_hash: str
    implicit_removals: bool = False
    device_commands_generated: bool = False
    execution_authority: bool = False

    @property
    def changes_required(self) -> bool:
        return bool(self.operations)

    @property
    def provider_ready(self) -> bool:
        return (
            not any(issue.severity is ValidationSeverity.BLOCKED for issue in self.issues)
            and all(op.readiness is OperationReadiness.READY for op in self.operations)
        )

    @property
    def status(self) -> str:
        if not self.operations:
            return "NO_CHANGES"
        if self.provider_ready:
            return "PROVIDER_READY_DRY_RUN_ONLY"
        return "DRY_RUN_BLOCKED_FOR_PROVIDER"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "current_state_basis": self.current_state_basis.value,
            "status": self.status,
            "changes_required": self.changes_required,
            "provider_ready": self.provider_ready,
            "execution_authority": self.execution_authority,
            "implicit_removals": self.implicit_removals,
            "device_commands_generated": self.device_commands_generated,
            "operations": [operation.as_dict() for operation in self.operations],
            "issues": [
                {
                    "code": issue.code,
                    "severity": issue.severity.value,
                    "message": issue.message,
                    "remediation": issue.remediation,
                }
                for issue in self.issues
            ],
            "preserved_current_objects": list(self.preserved_current_objects),
            "plan_hash": self.plan_hash,
        }

    def render_text(self) -> str:
        lines = [
            "SEMANTIC CHANGE PLAN",
            "====================",
            f"Plan hash: {self.plan_hash}",
            f"Current-state basis: {self.current_state_basis.value}",
            f"Status: {self.status}",
            "Execution authority: FALSE",
            "Device commands generated: NO",
            "Implicit removals: NO",
            "",
            "OPERATIONS",
            "----------",
        ]
        if not self.operations:
            lines.append("No changes required.")
        for operation in self.operations:
            lines.append(
                f"{operation.operation_id} | {operation.operation_type.value} | "
                f"target={operation.target} | risk={operation.risk_class} | "
                f"readiness={operation.readiness.value}"
            )
            if operation.dependencies:
                lines.append(f"  depends_on: {', '.join(operation.dependencies)}")
            if operation.capability_requirements:
                lines.append(
                    "  capabilities: " + ", ".join(operation.capability_requirements)
                )
            lines.append(f"  before: {operation.before}")
            lines.append(f"  desired: {operation.desired}")
            lines.append(f"  verify: {operation.verification.method}")

        if self.issues:
            lines.extend(["", "PLAN ISSUES", "-----------"])
            for issue in self.issues:
                lines.append(f"[{issue.severity.value}] {issue.code}: {issue.message}")
                if issue.remediation:
                    lines.append(f"  Remediation: {issue.remediation}")

        if self.preserved_current_objects:
            lines.extend(["", "PRESERVED CURRENT STATE", "-----------------------"])
            lines.append(
                "The planner will not implicitly remove: "
                + ", ".join(self.preserved_current_objects)
            )

        lines.extend(
            [
                "",
                "SAFETY",
                "------",
                "This P4 plan contains semantic desired-state operations only.",
                "It cannot execute against a switch and cannot authorize a provider/executor.",
            ]
        )
        return "\n".join(lines)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _operation_id(
    operation_type: OperationType,
    target: str,
    desired: dict[str, Any],
) -> str:
    payload = {
        "operation_type": operation_type.value,
        "target": target,
        "desired": desired,
    }
    digest = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()[:16]
    return f"op-{digest}"


def _capability_readiness(
    capability_requirements: tuple[str, ...],
    device_profile: DeviceProfile | None,
) -> OperationReadiness:
    if not capability_requirements:
        return OperationReadiness.READY
    if device_profile is None:
        return OperationReadiness.BLOCKED_CAPABILITY
    states = device_profile.feature_states
    if all(
        states.get(feature_id) is CapabilityState.DOCUMENTED_AND_OBSERVED
        for feature_id in capability_requirements
    ):
        return OperationReadiness.READY
    return OperationReadiness.BLOCKED_CAPABILITY


def _merge_readiness(
    capability_readiness: OperationReadiness,
    *,
    absence_authoritative: bool,
    relies_on_absence: bool,
) -> OperationReadiness:
    if relies_on_absence and not absence_authoritative:
        return OperationReadiness.BLOCKED_CURRENT_STATE
    return capability_readiness


def _rollback_for_before(before: dict[str, Any] | None, *, created: bool = False) -> RollbackSpec:
    if created:
        return RollbackSpec(
            strategy=RollbackStrategy.PROVIDER_DEFINED,
            restore=None,
            note=(
                "Creation rollback is intentionally not inferred in P4; a future provider must "
                "define a validated recovery path before execution authority exists."
            ),
        )
    if before is not None:
        return RollbackSpec(
            strategy=RollbackStrategy.RESTORE_BEFORE_STATE,
            restore=before,
            note=(
                "The semantic before-state is retained for a future provider-specific validated rollback plan."
            ),
        )
    return RollbackSpec(
        strategy=RollbackStrategy.NOT_AUTOMATICALLY_DEFINED,
        restore=None,
        note="No authoritative before-state is available; automatic rollback is not defined.",
    )


def _make_operation(
    *,
    operation_type: OperationType,
    target: str,
    risk_class: str,
    readiness: OperationReadiness,
    dependencies: tuple[str, ...] = (),
    before: dict[str, Any] | None,
    desired: dict[str, Any],
    capability_requirements: tuple[str, ...],
    verification_method: str,
    created: bool = False,
    rollback: RollbackSpec | None = None,
) -> PlannedOperation:
    operation_id = _operation_id(operation_type, target, desired)
    return PlannedOperation(
        operation_id=operation_id,
        operation_type=operation_type,
        target=target,
        risk_class=risk_class,
        readiness=readiness,
        dependencies=tuple(sorted(set(dependencies))),
        before=before,
        desired=desired,
        capability_requirements=tuple(sorted(set(capability_requirements))),
        verification=VerificationSpec(
            method=verification_method,
            expected=desired,
        ),
        rollback=rollback or _rollback_for_before(before, created=created),
    )


def _current_vlan_dict(vlan: CurrentVLANState) -> dict[str, Any]:
    return {
        "vlan_id": vlan.vlan_id,
        "name": vlan.name,
        "network": vlan.network,
        "gateway": vlan.gateway,
    }


def _current_access_dict(port: CurrentAccessPortState) -> dict[str, Any]:
    return {"mode": "access", "interface": port.interface, "access_vlan": port.access_vlan}


def _current_trunk_dict(trunk: CurrentTrunkState) -> dict[str, Any]:
    return {
        "mode": "trunk",
        "interface": trunk.interface,
        "allowed_vlans": list(trunk.allowed_vlans),
        "native_vlan": trunk.native_vlan,
    }


def _desired_trunk_dict(interface: str, allowed_vlans: tuple[int, ...], native_vlan: int | None) -> dict[str, Any]:
    return {
        "mode": "trunk",
        "interface": interface,
        "allowed_vlans": sorted(allowed_vlans),
        "native_vlan": native_vlan,
    }


def _security_rule_applies(rule: ExpandedSecurityRule, intent: NetworkIntent) -> bool:
    security = intent.security
    management = intent.management
    if rule.rule_id == "management.ssh":
        return management is not None and "ssh" in management.services
    if rule.rule_id == "management.https":
        return management is not None and "https" in management.services
    if rule.rule_id == "management.restrict_sources":
        return management is not None and bool(management.allowed_source_networks)
    if rule.rule_id == "logging.remote_syslog":
        return security is not None and security.remote_logging_required
    if rule.rule_id == "monitoring.snmpv3":
        return security is not None and security.snmpv3_preferred
    if rule.rule_id == "segmentation.ipv4_acl":
        return bool(intent.segmentation.rules)
    if rule.rule_id == "management.disable_telnet_policy":
        return security is not None and security.disable_telnet
    if rule.rule_id == "management.disable_http_when_safe_policy":
        return security is not None and security.disable_http_when_safe
    return rule.requirement == "required"


def _security_readiness(rule: ExpandedSecurityRule) -> OperationReadiness:
    if rule.status == "proven":
        return OperationReadiness.READY
    if rule.status == "unmapped":
        return OperationReadiness.POLICY_ONLY
    return OperationReadiness.BLOCKED_CAPABILITY


def _plan_hash_payload(
    *,
    current_state_basis: CurrentStateBasis,
    operations: tuple[PlannedOperation, ...],
    issues: tuple[ValidationIssue, ...],
    preserved_current_objects: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "schema_version": PLAN_SCHEMA_VERSION,
        "current_state_basis": current_state_basis.value,
        "implicit_removals": False,
        "device_commands_generated": False,
        "execution_authority": False,
        "operations": [operation.as_dict() for operation in operations],
        "issues": [
            {
                "code": issue.code,
                "severity": issue.severity.value,
                "message": issue.message,
                "remediation": issue.remediation,
            }
            for issue in issues
        ],
        "preserved_current_objects": list(preserved_current_objects),
    }


def build_change_plan(
    intent: NetworkIntent,
    current_state: CurrentNetworkState,
    *,
    device_profile: DeviceProfile | None = None,
    security_expansion: SecurityExpansionResult | None = None,
) -> ChangePlan:
    """Build a deterministic semantic diff without producing device commands.

    Safety properties:

    - no unspecified current object is removed;
    - partial observed state never treats absence as authoritative;
    - capability-unproven operations remain visible but provider-blocked;
    - management/connectivity-affecting operations are risk class W2;
    - operation IDs and plan hash are deterministic.
    """
    if security_expansion is None:
        security_expansion = expand_security_profile(
            intent.security_profile,
            device_profile=device_profile,
            require_live_proof=False,
        )

    issues: list[ValidationIssue] = []
    operations: list[PlannedOperation] = []
    preserved: set[str] = set()

    if current_state.basis is CurrentStateBasis.OBSERVED_PARTIAL:
        issues.append(
            ValidationIssue(
                code="CURRENT_STATE_PARTIAL",
                severity=ValidationSeverity.BLOCKED,
                message=(
                    "Current live state is partial; absence cannot prove that a VLAN, port, trunk, "
                    "management rule, or security control is missing."
                ),
                remediation=(
                    "Complete the read-only current-state collection before any provider-ready plan is accepted."
                ),
            )
        )

    current_vlans = {vlan.vlan_id: vlan for vlan in current_state.vlans}
    desired_vlan_ids = {vlan.id for vlan in intent.vlans}
    vlan_create_ids: dict[int, str] = {}
    l3_operation_ids: dict[int, str] = {}

    for vlan in sorted(intent.vlans, key=lambda item: item.id):
        current = current_vlans.get(vlan.id)
        if current is None:
            desired = {"vlan_id": vlan.id, "name": vlan.name}
            readiness = _merge_readiness(
                _capability_readiness(("vlan_8021q",), device_profile),
                absence_authoritative=current_state.absence_is_authoritative,
                relies_on_absence=True,
            )
            operation = _make_operation(
                operation_type=OperationType.CREATE_VLAN,
                target=f"vlan:{vlan.id}",
                risk_class="W1",
                readiness=readiness,
                before=None,
                desired=desired,
                capability_requirements=("vlan_8021q",),
                verification_method="observe_vlan_identity",
                created=True,
            )
            operations.append(operation)
            vlan_create_ids[vlan.id] = operation.operation_id
        elif current.name != vlan.name:
            before = {"vlan_id": current.vlan_id, "name": current.name}
            desired = {"vlan_id": vlan.id, "name": vlan.name}
            operations.append(
                _make_operation(
                    operation_type=OperationType.UPDATE_VLAN,
                    target=f"vlan:{vlan.id}",
                    risk_class="W1",
                    readiness=_capability_readiness(("vlan_8021q",), device_profile),
                    before=before,
                    desired=desired,
                    capability_requirements=("vlan_8021q",),
                    verification_method="observe_vlan_identity",
                )
            )

        if intent.routing.inter_vlan_routing and vlan.network is not None and vlan.gateway is not None:
            l3_matches = (
                current is not None
                and current.network == vlan.network
                and current.gateway == vlan.gateway
            )
            if not l3_matches:
                before = (
                    {
                        "vlan_id": current.vlan_id,
                        "network": current.network,
                        "gateway": current.gateway,
                    }
                    if current is not None
                    else None
                )
                desired = {
                    "vlan_id": vlan.id,
                    "network": vlan.network,
                    "gateway": vlan.gateway,
                }
                readiness = _capability_readiness(("ipv4_static_routing",), device_profile)
                if current is None:
                    readiness = _merge_readiness(
                        readiness,
                        absence_authoritative=current_state.absence_is_authoritative,
                        relies_on_absence=True,
                    )
                operation = _make_operation(
                    operation_type=OperationType.CONFIGURE_L3_INTERFACE,
                    target=f"vlan-l3:{vlan.id}",
                    risk_class="W2",
                    readiness=readiness,
                    dependencies=(vlan_create_ids[vlan.id],) if vlan.id in vlan_create_ids else (),
                    before=before,
                    desired=desired,
                    capability_requirements=("ipv4_static_routing",),
                    verification_method="observe_vlan_l3_interface",
                )
                operations.append(operation)
                l3_operation_ids[vlan.id] = operation.operation_id

    for vlan_id, current in sorted(current_vlans.items()):
        if vlan_id not in desired_vlan_ids:
            preserved.add(f"vlan:{vlan_id}")
        elif not intent.routing.inter_vlan_routing and (current.network or current.gateway):
            preserved.add(f"vlan-l3:{vlan_id}")

    current_access = {port.interface.casefold(): port for port in current_state.access_ports}
    current_trunks = {trunk.interface.casefold(): trunk for trunk in current_state.trunks}
    desired_interfaces: set[str] = set()
    trunk_operation_ids: dict[str, str] = {}

    desired_port_objects = sorted(intent.ports, key=lambda item: item.interface.casefold())
    for port in desired_port_objects:
        key = port.interface.casefold()
        desired_interfaces.add(key)
        if port.mode is PortMode.ACCESS:
            current_port = current_access.get(key)
            current_trunk = current_trunks.get(key)
            matches = current_port is not None and current_port.access_vlan == port.access_vlan
            if matches and current_trunk is None:
                continue
            before = (
                _current_access_dict(current_port)
                if current_port is not None
                else _current_trunk_dict(current_trunk)
                if current_trunk is not None
                else None
            )
            desired = {
                "mode": "access",
                "interface": port.interface,
                "access_vlan": port.access_vlan,
                "role": port.role,
            }
            readiness = _capability_readiness(("vlan_8021q",), device_profile)
            if before is None:
                readiness = _merge_readiness(
                    readiness,
                    absence_authoritative=current_state.absence_is_authoritative,
                    relies_on_absence=True,
                )
            dependencies = (
                (vlan_create_ids[port.access_vlan],)
                if port.access_vlan in vlan_create_ids
                else ()
            )
            operations.append(
                _make_operation(
                    operation_type=OperationType.ASSIGN_ACCESS_PORT,
                    target=f"interface:{port.interface}",
                    risk_class="W2",
                    readiness=readiness,
                    dependencies=dependencies,
                    before=before,
                    desired=desired,
                    capability_requirements=("vlan_8021q",),
                    verification_method="observe_access_port_membership",
                )
            )
        else:
            desired = _desired_trunk_dict(
                port.interface,
                port.allowed_vlans,
                port.native_vlan,
            )
            current_trunk = current_trunks.get(key)
            current_port = current_access.get(key)
            if current_trunk is not None:
                current_dict = _current_trunk_dict(current_trunk)
                if (
                    tuple(sorted(port.allowed_vlans)) == current_trunk.allowed_vlans
                    and port.native_vlan == current_trunk.native_vlan
                ):
                    continue
                operation_type = OperationType.SET_ALLOWED_VLANS
                before = current_dict
            else:
                operation_type = OperationType.CONFIGURE_TRUNK
                before = _current_access_dict(current_port) if current_port is not None else None
            readiness = _capability_readiness(("vlan_8021q",), device_profile)
            if before is None:
                readiness = _merge_readiness(
                    readiness,
                    absence_authoritative=current_state.absence_is_authoritative,
                    relies_on_absence=True,
                )
            dependencies = tuple(
                vlan_create_ids[vlan_id]
                for vlan_id in sorted(port.allowed_vlans)
                if vlan_id in vlan_create_ids
            )
            operation = _make_operation(
                operation_type=operation_type,
                target=f"interface:{port.interface}",
                risk_class="W2",
                readiness=readiness,
                dependencies=dependencies,
                before=before,
                desired=desired,
                capability_requirements=("vlan_8021q",),
                verification_method="observe_trunk_membership",
            )
            operations.append(operation)
            trunk_operation_ids[key] = operation.operation_id

    for uplink in sorted(intent.uplinks, key=lambda item: item.interface.casefold()):
        key = uplink.interface.casefold()
        desired_interfaces.add(key)
        desired = _desired_trunk_dict(
            uplink.interface,
            uplink.allowed_vlans,
            uplink.native_vlan,
        )
        current_trunk = current_trunks.get(key)
        current_port = current_access.get(key)
        if current_trunk is not None:
            if (
                tuple(sorted(uplink.allowed_vlans)) == current_trunk.allowed_vlans
                and uplink.native_vlan == current_trunk.native_vlan
            ):
                continue
            operation_type = OperationType.SET_ALLOWED_VLANS
            before = _current_trunk_dict(current_trunk)
        else:
            operation_type = OperationType.CONFIGURE_TRUNK
            before = _current_access_dict(current_port) if current_port is not None else None

        readiness = _capability_readiness(("vlan_8021q",), device_profile)
        if before is None:
            readiness = _merge_readiness(
                readiness,
                absence_authoritative=current_state.absence_is_authoritative,
                relies_on_absence=True,
            )
        dependencies = tuple(
            vlan_create_ids[vlan_id]
            for vlan_id in sorted(uplink.allowed_vlans)
            if vlan_id in vlan_create_ids
        )
        operation = _make_operation(
            operation_type=operation_type,
            target=f"interface:{uplink.interface}",
            risk_class="W2",
            readiness=readiness,
            dependencies=dependencies,
            before=before,
            desired=desired,
            capability_requirements=("vlan_8021q",),
            verification_method="observe_trunk_membership",
        )
        operations.append(operation)
        trunk_operation_ids[key] = operation.operation_id

    for key, port in sorted(current_access.items()):
        if key not in desired_interfaces:
            preserved.add(f"interface:{port.interface}")
    for key, trunk in sorted(current_trunks.items()):
        if key not in desired_interfaces:
            preserved.add(f"interface:{trunk.interface}")

    management_operation_id: str | None = None
    if intent.management is not None:
        desired_management = {
            "vlan_id": intent.management.vlan_id,
            "allowed_source_networks": sorted(intent.management.allowed_source_networks),
            "services": sorted(intent.management.services),
        }
        current_management = current_state.management
        before_management = (
            {
                "vlan_id": current_management.vlan_id,
                "allowed_source_networks": list(current_management.allowed_source_networks),
                "services": list(current_management.services),
            }
            if current_management is not None
            else None
        )
        if before_management != desired_management:
            requirements: list[str] = []
            if intent.management.allowed_source_networks:
                requirements.append("management_acl")
            if "ssh" in intent.management.services:
                requirements.append("ssh_management")
            if "https" in intent.management.services:
                requirements.append("https_management")
            readiness = _capability_readiness(tuple(requirements), device_profile)
            if before_management is None:
                readiness = _merge_readiness(
                    readiness,
                    absence_authoritative=current_state.absence_is_authoritative,
                    relies_on_absence=True,
                )
            dependencies: list[str] = []
            if intent.management.vlan_id in vlan_create_ids:
                dependencies.append(vlan_create_ids[intent.management.vlan_id])
            if intent.management.vlan_id is not None:
                for uplink in intent.uplinks:
                    if intent.management.vlan_id in uplink.allowed_vlans:
                        operation_id = trunk_operation_ids.get(uplink.interface.casefold())
                        if operation_id:
                            dependencies.append(operation_id)
            operation = _make_operation(
                operation_type=OperationType.SET_MANAGEMENT_POLICY,
                target="management-policy",
                risk_class="W2",
                readiness=readiness,
                dependencies=tuple(dependencies),
                before=before_management,
                desired=desired_management,
                capability_requirements=tuple(requirements),
                verification_method="observe_management_reachability_and_policy",
            )
            operations.append(operation)
            management_operation_id = operation.operation_id
    elif current_state.management is not None:
        preserved.add("management-policy")

    satisfied_security_rules = set(current_state.satisfied_security_rules)
    for rule in sorted(security_expansion.rules, key=lambda item: item.rule_id):
        if not _security_rule_applies(rule, intent):
            continue
        if rule.rule_id in satisfied_security_rules:
            continue
        readiness = _security_readiness(rule)
        if not current_state.absence_is_authoritative:
            readiness = OperationReadiness.BLOCKED_CURRENT_STATE
        dependencies: list[str] = []
        if rule.rule_id.startswith("management.") and management_operation_id is not None:
            dependencies.append(management_operation_id)
        if rule.rule_id == "segmentation.ipv4_acl":
            dependencies.extend(vlan_create_ids.values())
            dependencies.extend(l3_operation_ids.values())
        desired = {
            "rule_id": rule.rule_id,
            "intent": rule.intent,
            "requirement": rule.requirement,
            "applicability": rule.applicability,
        }
        operations.append(
            _make_operation(
                operation_type=OperationType.APPLY_SECURITY_POLICY_RULE,
                target=f"security-rule:{rule.rule_id}",
                risk_class=rule.risk_class,
                readiness=readiness,
                dependencies=tuple(dependencies),
                before={"satisfied": False} if current_state.absence_is_authoritative else None,
                desired=desired,
                capability_requirements=(rule.capability_id,) if rule.capability_id else (),
                verification_method="verify_normalized_security_rule",
                rollback=RollbackSpec(
                    strategy=RollbackStrategy.NOT_AUTOMATICALLY_DEFINED,
                    restore=None,
                    note=(
                        "Security-policy rollback remains provider/control-specific and is not inferred by the P4 planner."
                    ),
                ),
            )
        )

    for rule_id in satisfied_security_rules:
        if not any(rule.rule_id == rule_id and _security_rule_applies(rule, intent) for rule in security_expansion.rules):
            preserved.add(f"security-rule:{rule_id}")

    for operation in operations:
        if operation.readiness is OperationReadiness.BLOCKED_CAPABILITY:
            issues.append(
                ValidationIssue(
                    code="OPERATION_CAPABILITY_NOT_PROVEN",
                    severity=ValidationSeverity.BLOCKED,
                    message=(
                        f"Operation {operation.operation_id} ({operation.operation_type.value}) "
                        "depends on capability that is not live-proven for provider execution."
                    ),
                    remediation=(
                        "Keep the operation in dry-run only until every capability requirement is documented_and_observed."
                    ),
                )
            )
        elif operation.readiness is OperationReadiness.BLOCKED_CURRENT_STATE:
            issues.append(
                ValidationIssue(
                    code="OPERATION_CURRENT_STATE_UNPROVEN",
                    severity=ValidationSeverity.BLOCKED,
                    message=(
                        f"Operation {operation.operation_id} relies on absence/difference that cannot be proven from partial current state."
                    ),
                    remediation="Complete read-only current-state collection and rebuild the plan.",
                )
            )
        elif operation.readiness is OperationReadiness.POLICY_ONLY:
            issues.append(
                ValidationIssue(
                    code="OPERATION_POLICY_ONLY_UNMAPPED",
                    severity=ValidationSeverity.BLOCKED,
                    message=(
                        f"Operation {operation.operation_id} represents policy only and has no exact provider mapping."
                    ),
                    remediation=(
                        "Map the policy to a typed provider capability/operation before any future execution phase."
                    ),
                )
            )

    preserved_tuple = tuple(sorted(preserved))
    operations_tuple = tuple(operations)
    issues_tuple = tuple(issues)
    payload = _plan_hash_payload(
        current_state_basis=current_state.basis,
        operations=operations_tuple,
        issues=issues_tuple,
        preserved_current_objects=preserved_tuple,
    )
    plan_hash = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()

    return ChangePlan(
        schema_version=PLAN_SCHEMA_VERSION,
        current_state_basis=current_state.basis,
        operations=operations_tuple,
        issues=issues_tuple,
        preserved_current_objects=preserved_tuple,
        plan_hash=plan_hash,
    )
