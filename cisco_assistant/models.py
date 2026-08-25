"""Normalized device, observed-state, and network-intent models.

These models contain no SSH/device execution logic. They are the stable boundary between
frontend/user intent, deterministic planning, and later provider-specific compilation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from typing import Iterable


class ModelValidationError(ValueError):
    """Raised when normalized intent is internally inconsistent."""


class SecurityProfile(str, Enum):
    LAB = "LAB"
    BASIC = "BASIC"
    BUSINESS_STANDARD = "BUSINESS_STANDARD"
    STRICT = "STRICT"
    CUSTOM = "CUSTOM"


class PortMode(str, Enum):
    ACCESS = "access"
    TRUNK = "trunk"


class CapabilityState(str, Enum):
    DOCUMENTED_AND_OBSERVED = "documented_and_observed"
    DOCUMENTED_NOT_OBSERVED = "documented_not_observed"
    OBSERVED_NOT_YET_MAPPED = "observed_not_yet_mapped"
    NOT_APPLICABLE_OR_UNSUPPORTED = "not_applicable_or_unsupported"
    BLOCKED_BY_PRIVILEGE = "blocked_by_privilege"
    BLOCKED_BY_MODE = "blocked_by_mode"
    UNKNOWN_DUE_TO_CRAWL_LIMIT = "unknown_due_to_crawl_limit"


class SegmentationAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


def _required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ModelValidationError(f"{field_name} must not be empty")
    return normalized


def _ipv4_network(value: str) -> IPv4Network:
    try:
        network = ip_network(value, strict=True)
    except ValueError as exc:
        raise ModelValidationError(f"Invalid canonical IPv4 network {value!r}: {exc}") from exc
    if not isinstance(network, IPv4Network):
        raise ModelValidationError("Only IPv4 is supported in the initial intent model")
    return network


def _ipv4_address(value: str) -> IPv4Address:
    try:
        address = ip_address(value)
    except ValueError as exc:
        raise ModelValidationError(f"Invalid IPv4 address {value!r}: {exc}") from exc
    if not isinstance(address, IPv4Address):
        raise ModelValidationError("Only IPv4 is supported in the initial intent model")
    return address


@dataclass(frozen=True, slots=True)
class DeviceFingerprint:
    vendor: str
    family: str
    product_id: str
    firmware_version: str
    management_protocol: str = "ssh"
    capability_dataset: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "vendor", _required_text(self.vendor, "vendor"))
        object.__setattr__(self, "family", _required_text(self.family, "family"))
        object.__setattr__(self, "product_id", _required_text(self.product_id, "product_id"))
        object.__setattr__(
            self,
            "firmware_version",
            _required_text(self.firmware_version, "firmware_version"),
        )
        protocol = _required_text(self.management_protocol, "management_protocol").lower()
        if protocol not in {"ssh", "https"}:
            raise ModelValidationError(
                f"Unsupported management_protocol {protocol!r}; expected ssh or https"
            )
        object.__setattr__(self, "management_protocol", protocol)
        if self.capability_dataset is not None:
            object.__setattr__(
                self,
                "capability_dataset",
                _required_text(self.capability_dataset, "capability_dataset"),
            )


@dataclass(frozen=True, slots=True)
class DeviceCapability:
    feature_id: str
    state: CapabilityState | str
    source: str
    risk_class: str = "R0"
    detail: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "feature_id", _required_text(self.feature_id, "feature_id"))
        object.__setattr__(self, "source", _required_text(self.source, "source"))
        object.__setattr__(self, "risk_class", _required_text(self.risk_class, "risk_class"))
        try:
            state = self.state if isinstance(self.state, CapabilityState) else CapabilityState(self.state)
        except ValueError as exc:
            raise ModelValidationError(f"Unsupported capability state {self.state!r}") from exc
        object.__setattr__(self, "state", state)
        if self.detail is not None:
            object.__setattr__(self, "detail", _required_text(self.detail, "detail"))

    @property
    def supports_planning(self) -> bool:
        return self.state is CapabilityState.DOCUMENTED_AND_OBSERVED


@dataclass(frozen=True, slots=True)
class ObservedState:
    fingerprint: DeviceFingerprint
    collected_at_utc: str
    source_revision: str
    vlan_ids: tuple[int, ...] = field(default_factory=tuple)
    interfaces: tuple[str, ...] = field(default_factory=tuple)
    capabilities: tuple[DeviceCapability, ...] = field(default_factory=tuple)
    partial: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "collected_at_utc", _required_text(self.collected_at_utc, "collected_at_utc")
        )
        object.__setattr__(
            self, "source_revision", _required_text(self.source_revision, "source_revision")
        )
        vlans = tuple(self.vlan_ids)
        if len(vlans) != len(set(vlans)):
            raise ModelValidationError("ObservedState contains duplicate VLAN IDs")
        if any(vlan_id < 1 or vlan_id > 4094 for vlan_id in vlans):
            raise ModelValidationError("ObservedState contains VLAN ID outside 1..4094")
        object.__setattr__(self, "vlan_ids", vlans)

        interfaces = tuple(_required_text(value, "interface") for value in self.interfaces)
        folded = [value.casefold() for value in interfaces]
        if len(folded) != len(set(folded)):
            raise ModelValidationError("ObservedState contains duplicate interfaces")
        object.__setattr__(self, "interfaces", interfaces)
        object.__setattr__(self, "capabilities", tuple(self.capabilities))


@dataclass(frozen=True, slots=True)
class VLANIntent:
    id: int
    name: str
    network: str | None = None
    gateway: str | None = None
    purpose: str = "custom"

    def __post_init__(self) -> None:
        if not 1 <= self.id <= 4094:
            raise ModelValidationError(f"VLAN ID {self.id} is outside 1..4094")
        object.__setattr__(self, "name", _required_text(self.name, "VLAN name"))
        object.__setattr__(self, "purpose", _required_text(self.purpose, "VLAN purpose"))

        if self.network is None:
            if self.gateway is not None:
                raise ModelValidationError("gateway requires network")
            return

        network = _ipv4_network(self.network)
        object.__setattr__(self, "network", str(network))

        if self.gateway is None:
            return

        gateway = _ipv4_address(self.gateway)
        if gateway not in network:
            raise ModelValidationError(
                f"Gateway {gateway} is outside VLAN {self.id} network {network}"
            )
        if network.prefixlen <= 30 and gateway in {network.network_address, network.broadcast_address}:
            raise ModelValidationError(
                f"Gateway {gateway} cannot be network/broadcast address for {network}"
            )
        object.__setattr__(self, "gateway", str(gateway))

    @property
    def ipv4_network(self) -> IPv4Network | None:
        return _ipv4_network(self.network) if self.network is not None else None

    @property
    def ipv4_gateway(self) -> IPv4Address | None:
        return _ipv4_address(self.gateway) if self.gateway is not None else None


@dataclass(frozen=True, slots=True)
class PortIntent:
    interface: str
    role: str
    mode: PortMode | str
    access_vlan: int | None = None
    allowed_vlans: tuple[int, ...] = field(default_factory=tuple)
    native_vlan: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "interface", _required_text(self.interface, "interface"))
        object.__setattr__(self, "role", _required_text(self.role, "role"))

        try:
            mode = self.mode if isinstance(self.mode, PortMode) else PortMode(self.mode)
        except ValueError as exc:
            raise ModelValidationError(f"Unsupported port mode {self.mode!r}") from exc
        object.__setattr__(self, "mode", mode)

        allowed = tuple(self.allowed_vlans)
        if len(set(allowed)) != len(allowed):
            raise ModelValidationError(f"Duplicate allowed VLAN on {self.interface}")
        for vlan_id in allowed:
            if not 1 <= vlan_id <= 4094:
                raise ModelValidationError(f"Invalid allowed VLAN {vlan_id} on {self.interface}")
        object.__setattr__(self, "allowed_vlans", allowed)

        if self.access_vlan is not None and not 1 <= self.access_vlan <= 4094:
            raise ModelValidationError(f"Invalid access VLAN {self.access_vlan}")
        if self.native_vlan is not None and not 1 <= self.native_vlan <= 4094:
            raise ModelValidationError(f"Invalid native VLAN {self.native_vlan}")

        if mode is PortMode.ACCESS:
            if self.access_vlan is None:
                raise ModelValidationError(f"Access port {self.interface} requires access_vlan")
            if allowed:
                raise ModelValidationError(f"Access port {self.interface} cannot have allowed_vlans")
            if self.native_vlan is not None:
                raise ModelValidationError(f"Access port {self.interface} cannot have native_vlan")
        else:
            if self.access_vlan is not None:
                raise ModelValidationError(f"Trunk port {self.interface} cannot have access_vlan")
            if not allowed:
                raise ModelValidationError(
                    f"Trunk port {self.interface} requires at least one allowed VLAN"
                )
            if self.native_vlan is not None and self.native_vlan not in allowed:
                raise ModelValidationError(
                    f"Native VLAN {self.native_vlan} must be included in allowed_vlans"
                )


@dataclass(frozen=True, slots=True)
class UplinkIntent:
    interface: str
    allowed_vlans: tuple[int, ...]
    native_vlan: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "interface", _required_text(self.interface, "uplink interface"))
        allowed = tuple(self.allowed_vlans)
        if not allowed:
            raise ModelValidationError(f"Uplink {self.interface} requires allowed_vlans")
        if len(allowed) != len(set(allowed)):
            raise ModelValidationError(f"Uplink {self.interface} contains duplicate VLAN IDs")
        if any(vlan_id < 1 or vlan_id > 4094 for vlan_id in allowed):
            raise ModelValidationError(f"Uplink {self.interface} contains invalid VLAN ID")
        object.__setattr__(self, "allowed_vlans", allowed)
        if self.native_vlan is not None:
            if not 1 <= self.native_vlan <= 4094:
                raise ModelValidationError(f"Invalid uplink native VLAN {self.native_vlan}")
            if self.native_vlan not in allowed:
                raise ModelValidationError(
                    f"Uplink native VLAN {self.native_vlan} must be present in allowed_vlans"
                )


@dataclass(frozen=True, slots=True)
class RoutingIntent:
    inter_vlan_routing: bool = False
    default_gateway: str | None = None

    def __post_init__(self) -> None:
        if self.default_gateway is not None:
            object.__setattr__(self, "default_gateway", str(_ipv4_address(self.default_gateway)))


@dataclass(frozen=True, slots=True)
class SegmentationRule:
    source_vlan: int
    destination_vlan: int
    action: SegmentationAction | str
    description: str = ""

    def __post_init__(self) -> None:
        if not 1 <= self.source_vlan <= 4094 or not 1 <= self.destination_vlan <= 4094:
            raise ModelValidationError("Segmentation rule VLAN IDs must be inside 1..4094")
        if self.source_vlan == self.destination_vlan:
            raise ModelValidationError("Segmentation rule source and destination VLAN must differ")
        try:
            action = self.action if isinstance(self.action, SegmentationAction) else SegmentationAction(self.action)
        except ValueError as exc:
            raise ModelValidationError(f"Unsupported segmentation action {self.action!r}") from exc
        object.__setattr__(self, "action", action)
        if self.description:
            object.__setattr__(self, "description", self.description.strip())


@dataclass(frozen=True, slots=True)
class SegmentationIntent:
    rules: tuple[SegmentationRule, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        rules = tuple(self.rules)
        seen: set[tuple[int, int]] = set()
        for rule in rules:
            key = (rule.source_vlan, rule.destination_vlan)
            if key in seen:
                raise ModelValidationError(
                    f"Duplicate segmentation rule {rule.source_vlan}->{rule.destination_vlan}"
                )
            seen.add(key)
        object.__setattr__(self, "rules", rules)


@dataclass(frozen=True, slots=True)
class ManagementIntent:
    vlan_id: int | None = None
    allowed_source_networks: tuple[str, ...] = field(default_factory=tuple)
    services: tuple[str, ...] = ("ssh", "https")
    require_dedicated_vlan: bool = True

    def __post_init__(self) -> None:
        if self.vlan_id is not None and not 1 <= self.vlan_id <= 4094:
            raise ModelValidationError("Management VLAN ID must be inside 1..4094")
        networks = tuple(str(_ipv4_network(value)) for value in self.allowed_source_networks)
        if len(networks) != len(set(networks)):
            raise ModelValidationError("Duplicate management source network")
        object.__setattr__(self, "allowed_source_networks", networks)
        services = tuple(value.strip().lower() for value in self.services)
        if not services:
            raise ModelValidationError("At least one management service is required")
        unsupported = set(services) - {"ssh", "https"}
        if unsupported:
            raise ModelValidationError(f"Unsupported management services: {sorted(unsupported)}")
        if len(services) != len(set(services)):
            raise ModelValidationError("Duplicate management service")
        object.__setattr__(self, "services", services)


@dataclass(frozen=True, slots=True)
class SecurityIntent:
    profile: SecurityProfile | str = SecurityProfile.BUSINESS_STANDARD
    remote_logging_required: bool = True
    snmpv3_preferred: bool = True
    disable_telnet: bool = True
    disable_http_when_safe: bool = True

    def __post_init__(self) -> None:
        try:
            profile = self.profile if isinstance(self.profile, SecurityProfile) else SecurityProfile(self.profile)
        except ValueError as exc:
            raise ModelValidationError(f"Unsupported security profile {self.profile!r}") from exc
        object.__setattr__(self, "profile", profile)


@dataclass(frozen=True, slots=True)
class NetworkIntent:
    site_name: str
    vlans: tuple[VLANIntent, ...] = field(default_factory=tuple)
    ports: tuple[PortIntent, ...] = field(default_factory=tuple)
    security_profile: SecurityProfile | str = SecurityProfile.BUSINESS_STANDARD
    template: str = "custom"
    uplinks: tuple[UplinkIntent, ...] = field(default_factory=tuple)
    routing: RoutingIntent = field(default_factory=RoutingIntent)
    segmentation: SegmentationIntent = field(default_factory=SegmentationIntent)
    management: ManagementIntent | None = None
    security: SecurityIntent | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "site_name", _required_text(self.site_name, "site_name"))
        object.__setattr__(self, "template", _required_text(self.template, "template"))

        try:
            profile = (
                self.security_profile
                if isinstance(self.security_profile, SecurityProfile)
                else SecurityProfile(self.security_profile)
            )
        except ValueError as exc:
            raise ModelValidationError(
                f"Unsupported security profile {self.security_profile!r}"
            ) from exc
        object.__setattr__(self, "security_profile", profile)

        vlans = tuple(self.vlans)
        ports = tuple(self.ports)
        uplinks = tuple(self.uplinks)
        object.__setattr__(self, "vlans", vlans)
        object.__setattr__(self, "ports", ports)
        object.__setattr__(self, "uplinks", uplinks)

        security = self.security or SecurityIntent(profile=profile)
        if security.profile is not profile:
            raise ModelValidationError(
                "security.profile must match legacy security_profile until security_profile is removed"
            )
        object.__setattr__(self, "security", security)

        self._validate_vlan_uniqueness(vlans)
        self._validate_networks(vlans)
        self._validate_ports(vlans, ports)
        self._validate_uplinks(vlans, ports, uplinks)
        self._validate_segmentation(vlans, self.segmentation)
        self._validate_management(vlans, self.management)

    @staticmethod
    def _validate_vlan_uniqueness(vlans: Iterable[VLANIntent]) -> None:
        ids: set[int] = set()
        names: set[str] = set()
        for vlan in vlans:
            if vlan.id in ids:
                raise ModelValidationError(f"Duplicate VLAN ID {vlan.id}")
            ids.add(vlan.id)
            normalized_name = vlan.name.casefold()
            if normalized_name in names:
                raise ModelValidationError(f"Duplicate VLAN name {vlan.name!r}")
            names.add(normalized_name)

    @staticmethod
    def _validate_networks(vlans: Iterable[VLANIntent]) -> None:
        routed = [vlan for vlan in vlans if vlan.ipv4_network is not None]
        gateways: set[IPv4Address] = set()
        for index, left in enumerate(routed):
            left_network = left.ipv4_network
            assert left_network is not None
            gateway = left.ipv4_gateway
            if gateway is not None:
                if gateway in gateways:
                    raise ModelValidationError(f"Duplicate gateway address {gateway}")
                gateways.add(gateway)
            for right in routed[index + 1 :]:
                right_network = right.ipv4_network
                assert right_network is not None
                if left_network.overlaps(right_network):
                    raise ModelValidationError(
                        f"Subnet overlap: VLAN {left.id} {left_network} overlaps "
                        f"VLAN {right.id} {right_network}"
                    )

    @staticmethod
    def _validate_ports(vlans: Iterable[VLANIntent], ports: Iterable[PortIntent]) -> None:
        vlan_ids = {vlan.id for vlan in vlans}
        interfaces: set[str] = set()
        for port in ports:
            interface_key = port.interface.casefold()
            if interface_key in interfaces:
                raise ModelValidationError(f"Duplicate port assignment {port.interface}")
            interfaces.add(interface_key)
            referenced = set(port.allowed_vlans)
            if port.access_vlan is not None:
                referenced.add(port.access_vlan)
            if port.native_vlan is not None:
                referenced.add(port.native_vlan)
            missing = referenced - vlan_ids
            if missing:
                raise ModelValidationError(
                    f"Port {port.interface} references undefined VLANs {sorted(missing)}"
                )

    @staticmethod
    def _validate_uplinks(
        vlans: Iterable[VLANIntent], ports: Iterable[PortIntent], uplinks: Iterable[UplinkIntent]
    ) -> None:
        vlan_ids = {vlan.id for vlan in vlans}
        port_interfaces = {port.interface.casefold() for port in ports}
        uplink_interfaces: set[str] = set()
        for uplink in uplinks:
            key = uplink.interface.casefold()
            if key in uplink_interfaces:
                raise ModelValidationError(f"Duplicate uplink assignment {uplink.interface}")
            if key in port_interfaces:
                raise ModelValidationError(
                    f"Interface {uplink.interface} cannot be declared as both port and uplink intent"
                )
            uplink_interfaces.add(key)
            missing = set(uplink.allowed_vlans) - vlan_ids
            if missing:
                raise ModelValidationError(
                    f"Uplink {uplink.interface} references undefined VLANs {sorted(missing)}"
                )

    @staticmethod
    def _validate_segmentation(vlans: Iterable[VLANIntent], segmentation: SegmentationIntent) -> None:
        vlan_ids = {vlan.id for vlan in vlans}
        for rule in segmentation.rules:
            missing = {rule.source_vlan, rule.destination_vlan} - vlan_ids
            if missing:
                raise ModelValidationError(
                    f"Segmentation rule references undefined VLANs {sorted(missing)}"
                )

    @staticmethod
    def _validate_management(vlans: Iterable[VLANIntent], management: ManagementIntent | None) -> None:
        if management is None or management.vlan_id is None:
            return
        vlan_ids = {vlan.id for vlan in vlans}
        if management.vlan_id not in vlan_ids:
            raise ModelValidationError(
                f"Management VLAN {management.vlan_id} is not defined in network intent"
            )
