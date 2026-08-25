"""Normalized device and network-intent models.

These models contain no SSH/device execution logic. They are the stable boundary between
frontend/user intent and later provider-specific planning/compilation.
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
        # For conventional broadcast IPv4 subnets (/30 and larger), network and
        # broadcast addresses are never acceptable gateway addresses.
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
                raise ModelValidationError(
                    f"Access port {self.interface} cannot have allowed_vlans"
                )
            if self.native_vlan is not None:
                raise ModelValidationError(
                    f"Access port {self.interface} cannot have native_vlan"
                )
        else:
            if self.access_vlan is not None:
                raise ModelValidationError(
                    f"Trunk port {self.interface} cannot have access_vlan"
                )
            if not allowed:
                raise ModelValidationError(
                    f"Trunk port {self.interface} requires at least one allowed VLAN"
                )
            if self.native_vlan is not None and self.native_vlan not in allowed:
                raise ModelValidationError(
                    f"Native VLAN {self.native_vlan} must be included in allowed_vlans"
                )


@dataclass(frozen=True, slots=True)
class NetworkIntent:
    site_name: str
    vlans: tuple[VLANIntent, ...] = field(default_factory=tuple)
    ports: tuple[PortIntent, ...] = field(default_factory=tuple)
    security_profile: SecurityProfile | str = SecurityProfile.BUSINESS_STANDARD
    template: str = "custom"

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
        object.__setattr__(self, "vlans", vlans)
        object.__setattr__(self, "ports", ports)

        self._validate_vlan_uniqueness(vlans)
        self._validate_networks(vlans)
        self._validate_ports(vlans, ports)

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

            referenced: set[int] = set(port.allowed_vlans)
            if port.access_vlan is not None:
                referenced.add(port.access_vlan)
            if port.native_vlan is not None:
                referenced.add(port.native_vlan)
            missing = referenced - vlan_ids
            if missing:
                raise ModelValidationError(
                    f"Port {port.interface} references undefined VLANs {sorted(missing)}"
                )
