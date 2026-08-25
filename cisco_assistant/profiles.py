"""Typed, offline capability profiles bound to exact device identity.

This module loads repository knowledge only. It performs no device access and grants no
execution authority. Family-documented limits and live-observed facts remain distinguishable.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from .ipam import GatewayStrategy, generate_vlan_series
from .models import (
    CapabilityState,
    DeviceFingerprint,
    NetworkIntent,
    ObservedState,
    VLANIntent,
)
from .validation import (
    ValidationIssue,
    ValidationResult,
    ValidationSeverity,
    validate_network_intent,
)


class ProfileError(ValueError):
    """Raised when a capability profile is malformed or cannot be safely used."""


@dataclass(frozen=True, slots=True)
class HardwareCapacity:
    gigabit_access_ports: int
    ten_gigabit_uplink_ports: int
    total_physical_ports: int

    def __post_init__(self) -> None:
        if min(
            self.gigabit_access_ports,
            self.ten_gigabit_uplink_ports,
            self.total_physical_ports,
        ) < 0:
            raise ProfileError("Hardware port capacities cannot be negative")
        if self.gigabit_access_ports + self.ten_gigabit_uplink_ports != self.total_physical_ports:
            raise ProfileError("Hardware port capacity components do not match total_physical_ports")


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    vlan_id_min: int
    vlan_id_max: int
    active_vlans: int
    ip_interfaces: int
    ipv4_static_routes: int
    lag_groups: int
    active_ports_per_lag: int
    acl_rules: int
    hardware_qos_queues: int

    def __post_init__(self) -> None:
        if not 1 <= self.vlan_id_min <= self.vlan_id_max <= 4094:
            raise ProfileError("Invalid VLAN ID range in capability profile")
        for name in (
            "active_vlans",
            "ip_interfaces",
            "ipv4_static_routes",
            "lag_groups",
            "active_ports_per_lag",
            "acl_rules",
            "hardware_qos_queues",
        ):
            if getattr(self, name) <= 0:
                raise ProfileError(f"Capability limit {name} must be greater than zero")


@dataclass(frozen=True, slots=True)
class DeviceProfile:
    profile_id: str
    fingerprint: DeviceFingerprint
    binding_status: str
    hardware: HardwareCapacity
    limits: ResourceLimits
    features: tuple[tuple[str, CapabilityState], ...]
    authority_note: str

    def __post_init__(self) -> None:
        if not self.profile_id.strip():
            raise ProfileError("profile_id must not be empty")
        if not self.binding_status.strip():
            raise ProfileError("binding_status must not be empty")
        if not self.authority_note.strip():
            raise ProfileError("authority_note must not be empty")
        keys = [key for key, _ in self.features]
        if len(keys) != len(set(keys)):
            raise ProfileError("Duplicate feature ID in capability profile")

    @property
    def feature_states(self) -> dict[str, CapabilityState]:
        return dict(self.features)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_device_profile(path: str | Path) -> DeviceProfile:
    profile_path = Path(path)
    if not profile_path.is_absolute():
        profile_path = _repo_root() / profile_path

    try:
        payload = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileError(f"Cannot load capability profile {profile_path}: {exc}") from exc

    if payload.get("schema_version") != 1:
        raise ProfileError("Unsupported capability profile schema_version")

    scope = payload.get("scope", {})
    hardware = payload.get("hardware", {})
    limits = payload.get("limits", {})
    feature_payload = payload.get("features", {})

    try:
        fingerprint = DeviceFingerprint(
            vendor=scope["vendor"],
            family=scope["family"],
            product_id=scope["product_id"],
            firmware_version=scope["firmware_version"],
            capability_dataset=payload["profile_id"],
        )
        hardware_capacity = HardwareCapacity(
            gigabit_access_ports=int(hardware["gigabit_access_ports"]),
            ten_gigabit_uplink_ports=int(hardware["ten_gigabit_uplink_ports"]),
            total_physical_ports=int(hardware["total_physical_ports"]),
        )
        resource_limits = ResourceLimits(
            vlan_id_min=int(limits["vlan_id_min"]),
            vlan_id_max=int(limits["vlan_id_max"]),
            active_vlans=int(limits["active_vlans"]),
            ip_interfaces=int(limits["ip_interfaces"]),
            ipv4_static_routes=int(limits["ipv4_static_routes"]),
            lag_groups=int(limits["lag_groups"]),
            active_ports_per_lag=int(limits["active_ports_per_lag"]),
            acl_rules=int(limits["acl_rules"]),
            hardware_qos_queues=int(limits["hardware_qos_queues"]),
        )
        features = tuple(
            (str(feature_id), CapabilityState(state))
            for feature_id, state in sorted(feature_payload.items())
        )
        return DeviceProfile(
            profile_id=str(payload["profile_id"]),
            fingerprint=fingerprint,
            binding_status=str(payload["binding_status"]),
            hardware=hardware_capacity,
            limits=resource_limits,
            features=features,
            authority_note=str(payload["authority_note"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProfileError(f"Malformed capability profile {profile_path}: {exc}") from exc


def load_cbs250_24t_4x_3_3_0_16_profile() -> DeviceProfile:
    return load_device_profile(
        "knowledge/cbs250/profiles/CBS250-24T-4X_3.3.0.16.json"
    )


def generate_vlan_series_for_profile(
    profile: DeviceProfile,
    *,
    start_vlan_id: int,
    count: int,
    vlan_increment: int,
    start_network: str,
    gateway_strategy: GatewayStrategy | str = GatewayStrategy.FIRST_USABLE,
    name_prefix: str = "VLAN",
    purpose_prefix: str = "custom",
) -> tuple[VLANIntent, ...]:
    """Generate a sequential VLAN/IP design constrained by the selected device profile.

    This is still pure offline calculation. It does not inspect current switch state and does
    not reserve resources. The desired design is constrained by profile limits before any
    provider/compiler stage exists.
    """
    if count > profile.limits.active_vlans:
        raise ProfileError(
            f"Requested {count} VLANs exceeds profile active VLAN limit "
            f"{profile.limits.active_vlans}"
        )

    last_vlan_id = start_vlan_id + ((count - 1) * vlan_increment) if count > 0 else start_vlan_id
    if start_vlan_id < profile.limits.vlan_id_min or last_vlan_id > profile.limits.vlan_id_max:
        raise ProfileError(
            f"Requested VLAN series {start_vlan_id}..{last_vlan_id} is outside profile range "
            f"{profile.limits.vlan_id_min}..{profile.limits.vlan_id_max}"
        )

    return generate_vlan_series(
        start_vlan_id=start_vlan_id,
        count=count,
        vlan_increment=vlan_increment,
        start_network=start_network,
        gateway_strategy=gateway_strategy,
        name_prefix=name_prefix,
        purpose_prefix=purpose_prefix,
    )


def _required_semantic_features(intent: NetworkIntent) -> set[str]:
    required: set[str] = set()

    if intent.vlans or intent.ports or intent.uplinks:
        required.add("vlan_8021q")
    if intent.routing.inter_vlan_routing:
        required.add("ipv4_static_routing")
    if intent.management is not None:
        if intent.management.allowed_source_networks:
            required.add("management_acl")
        if "ssh" in intent.management.services:
            required.add("ssh_management")
        if "https" in intent.management.services:
            required.add("https_management")
    if intent.security is not None:
        if intent.security.remote_logging_required:
            required.add("remote_syslog")
        if intent.security.snmpv3_preferred:
            required.add("snmpv3")

    return required


def validate_intent_against_profile(
    intent: NetworkIntent,
    profile: DeviceProfile,
    *,
    observed_state: ObservedState | None = None,
    require_live_proof: bool = False,
) -> ValidationResult:
    """Validate a design against a typed device profile without generating or executing CLI.

    `require_live_proof=False` is suitable for offline design: documented-but-not-observed
    features generate warnings. `require_live_proof=True` is the stricter future provider
    precondition: any required capability not documented_and_observed becomes BLOCKED.
    """
    base = validate_network_intent(
        intent,
        observed_state=observed_state,
        min_vlan_id=profile.limits.vlan_id_min,
        max_vlan_id=profile.limits.vlan_id_max,
        max_active_vlans=profile.limits.active_vlans,
    )
    issues = list(base.issues)

    if observed_state is not None:
        observed = observed_state.fingerprint
        expected = profile.fingerprint
        if (
            observed.vendor.casefold() != expected.vendor.casefold()
            or observed.family.casefold() != expected.family.casefold()
            or observed.product_id.casefold() != expected.product_id.casefold()
            or observed.firmware_version != expected.firmware_version
        ):
            issues.append(
                ValidationIssue(
                    code="PROFILE_FINGERPRINT_MISMATCH",
                    severity=ValidationSeverity.BLOCKED,
                    message=(
                        "Observed device identity does not match the selected capability profile: "
                        f"observed={observed.product_id}/{observed.firmware_version}, "
                        f"profile={expected.product_id}/{expected.firmware_version}."
                    ),
                    remediation="Select or build a capability profile bound to the exact observed model and firmware.",
                )
            )

    declared_interfaces = {
        port.interface.casefold() for port in intent.ports
    } | {uplink.interface.casefold() for uplink in intent.uplinks}
    if len(declared_interfaces) > profile.hardware.total_physical_ports:
        issues.append(
            ValidationIssue(
                code="PHYSICAL_PORT_CAPACITY_EXCEEDED",
                severity=ValidationSeverity.BLOCKED,
                message=(
                    f"Design declares {len(declared_interfaces)} distinct physical interfaces but "
                    f"{profile.fingerprint.product_id} has capacity for "
                    f"{profile.hardware.total_physical_ports}."
                ),
                remediation="Reduce physical-port requirements or select a switch with sufficient ports.",
            )
        )

    if intent.routing.inter_vlan_routing:
        routed_vlan_count = sum(1 for vlan in intent.vlans if vlan.gateway is not None)
        if routed_vlan_count > profile.limits.ip_interfaces:
            issues.append(
                ValidationIssue(
                    code="IP_INTERFACE_CAPACITY_EXCEEDED",
                    severity=ValidationSeverity.BLOCKED,
                    message=(
                        f"Design requests inter-VLAN routing for {routed_vlan_count} VLAN interfaces "
                        f"but the CBS250 family limit is {profile.limits.ip_interfaces} IP interfaces."
                    ),
                    remediation="Reduce routed VLAN interfaces or move routing to an upstream router/firewall.",
                )
            )

    feature_states = profile.feature_states
    for feature_id in sorted(_required_semantic_features(intent)):
        state = feature_states.get(feature_id)
        if state is None:
            issues.append(
                ValidationIssue(
                    code="PROFILE_CAPABILITY_UNKNOWN",
                    severity=ValidationSeverity.BLOCKED,
                    message=f"Required semantic capability {feature_id!r} is absent from the profile.",
                    remediation="Map the capability from Cisco documentation and live evidence before provider compilation.",
                )
            )
            continue

        if state is CapabilityState.NOT_APPLICABLE_OR_UNSUPPORTED:
            issues.append(
                ValidationIssue(
                    code="PROFILE_CAPABILITY_UNSUPPORTED",
                    severity=ValidationSeverity.BLOCKED,
                    message=f"Required semantic capability {feature_id!r} is marked unsupported.",
                    remediation="Change the design or use a supported device/profile.",
                )
            )
        elif state is not CapabilityState.DOCUMENTED_AND_OBSERVED:
            severity = ValidationSeverity.BLOCKED if require_live_proof else ValidationSeverity.WARNING
            issues.append(
                ValidationIssue(
                    code="PROFILE_CAPABILITY_NOT_LIVE_PROVEN",
                    severity=severity,
                    message=(
                        f"Required semantic capability {feature_id!r} is {state.value!r}; "
                        "exact live support has not yet been proven by the current evidence set."
                    ),
                    remediation="Complete safe live capability mapping before enabling any write-capable provider path.",
                )
            )

    return ValidationResult(tuple(issues))
