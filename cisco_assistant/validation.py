"""Human-readable deterministic validation for normalized network intent.

This module is offline-only. It does not connect to or modify devices.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .models import CapabilityState, NetworkIntent, ObservedState, PortMode


class ValidationSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    code: str
    severity: ValidationSeverity
    message: str
    remediation: str | None = None


@dataclass(frozen=True, slots=True)
class ValidationResult:
    issues: tuple[ValidationIssue, ...]

    @property
    def blocking(self) -> tuple[ValidationIssue, ...]:
        return tuple(
            issue
            for issue in self.issues
            if issue.severity in {ValidationSeverity.ERROR, ValidationSeverity.BLOCKED}
        )

    @property
    def valid(self) -> bool:
        return not self.blocking


def validate_network_intent(
    intent: NetworkIntent,
    *,
    observed_state: ObservedState | None = None,
    min_vlan_id: int = 1,
    max_vlan_id: int = 4094,
    max_active_vlans: int | None = None,
    required_capability_ids: tuple[str, ...] = (),
) -> ValidationResult:
    """Validate operational/capability constraints not enforced by model construction.

    Structural contradictions such as overlapping subnets or undefined VLAN references are
    rejected while constructing NetworkIntent. This function adds human-readable checks that
    depend on device inventory/capability policy.
    """
    issues: list[ValidationIssue] = []

    if min_vlan_id < 1 or max_vlan_id > 4094 or min_vlan_id > max_vlan_id:
        raise ValueError("Invalid capability VLAN range")

    for vlan in intent.vlans:
        if vlan.id < min_vlan_id or vlan.id > max_vlan_id:
            issues.append(
                ValidationIssue(
                    code="VLAN_OUTSIDE_CAPABILITY_RANGE",
                    severity=ValidationSeverity.BLOCKED,
                    message=(
                        f"VLAN {vlan.id} is outside the target capability range "
                        f"{min_vlan_id}..{max_vlan_id}."
                    ),
                    remediation="Choose a VLAN ID supported by the exact target device capability dataset.",
                )
            )

    if max_active_vlans is not None and len(intent.vlans) > max_active_vlans:
        issues.append(
            ValidationIssue(
                code="ACTIVE_VLAN_CAPACITY_EXCEEDED",
                severity=ValidationSeverity.BLOCKED,
                message=(
                    f"Design requests {len(intent.vlans)} VLANs but target capability permits "
                    f"at most {max_active_vlans}."
                ),
                remediation="Reduce VLAN count or select a target device with sufficient capacity.",
            )
        )

    if observed_state is not None:
        observed_interfaces = {name.casefold(): name for name in observed_state.interfaces}
        for port in intent.ports:
            if port.interface.casefold() not in observed_interfaces:
                issues.append(
                    ValidationIssue(
                        code="PORT_NOT_OBSERVED",
                        severity=ValidationSeverity.BLOCKED,
                        message=f"Port {port.interface} was not found in the current device inventory.",
                        remediation="Refresh inventory or choose an interface observed on the exact switch.",
                    )
                )
        for uplink in intent.uplinks:
            if uplink.interface.casefold() not in observed_interfaces:
                issues.append(
                    ValidationIssue(
                        code="UPLINK_NOT_OBSERVED",
                        severity=ValidationSeverity.BLOCKED,
                        message=f"Uplink {uplink.interface} was not found in the current device inventory.",
                        remediation="Refresh inventory or choose an observed uplink interface.",
                    )
                )

        capability_by_id = {cap.feature_id: cap for cap in observed_state.capabilities}
        for feature_id in required_capability_ids:
            capability = capability_by_id.get(feature_id)
            if capability is None:
                issues.append(
                    ValidationIssue(
                        code="CAPABILITY_UNKNOWN",
                        severity=ValidationSeverity.BLOCKED,
                        message=f"Required capability {feature_id!r} is absent from the exact capability dataset.",
                        remediation="Complete live/documented capability mapping before planning this feature.",
                    )
                )
                continue
            if capability.state is not CapabilityState.DOCUMENTED_AND_OBSERVED:
                issues.append(
                    ValidationIssue(
                        code="CAPABILITY_NOT_PROVEN",
                        severity=ValidationSeverity.BLOCKED,
                        message=(
                            f"Required capability {feature_id!r} is in state "
                            f"{capability.state.value!r}, not documented_and_observed."
                        ),
                        remediation="Do not generate write operations until exact support is proven.",
                    )
                )

        if observed_state.partial:
            issues.append(
                ValidationIssue(
                    code="OBSERVED_STATE_PARTIAL",
                    severity=ValidationSeverity.WARNING,
                    message="Current device inventory is partial; absence of an object is not proof of unsupported capability.",
                    remediation="Refresh or complete read-only collection before final planning.",
                )
            )

    vlan_ids = {vlan.id for vlan in intent.vlans}
    required_on_uplink: set[int] = set()
    for port in intent.ports:
        if port.mode is PortMode.ACCESS and port.access_vlan is not None:
            required_on_uplink.add(port.access_vlan)
    if intent.management is not None and intent.management.vlan_id is not None:
        required_on_uplink.add(intent.management.vlan_id)

    if intent.uplinks and required_on_uplink:
        carried = set().union(*(set(uplink.allowed_vlans) for uplink in intent.uplinks))
        missing = sorted((required_on_uplink & vlan_ids) - carried)
        if missing:
            issues.append(
                ValidationIssue(
                    code="UPLINK_MISSING_REQUIRED_VLANS",
                    severity=ValidationSeverity.BLOCKED,
                    message=f"No declared uplink carries required VLANs {missing}.",
                    remediation="Add the missing VLANs to at least one intended uplink after validating topology.",
                )
            )

    if intent.management is not None:
        if intent.management.require_dedicated_vlan and intent.management.vlan_id is None:
            issues.append(
                ValidationIssue(
                    code="MANAGEMENT_VLAN_REQUIRED",
                    severity=ValidationSeverity.BLOCKED,
                    message="The selected management policy requires a dedicated management VLAN but none is defined.",
                    remediation="Choose an existing intent VLAN as the management VLAN.",
                )
            )
        if not intent.management.allowed_source_networks:
            issues.append(
                ValidationIssue(
                    code="MANAGEMENT_SOURCES_UNDEFINED",
                    severity=ValidationSeverity.WARNING,
                    message="No management source network is declared, so lockout analysis cannot prove an allowed administrator path.",
                    remediation="Declare the administrator/management source network before any future management-policy apply.",
                )
            )

    return ValidationResult(tuple(issues))
