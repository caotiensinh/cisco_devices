"""Normalized current network state used by the offline diff planner.

This module contains no collector, SSH, provider, or CLI logic. A future read-only collector
must normalize live evidence into these types before the planner can compare current state
with desired ``NetworkIntent``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network


class CurrentStateError(ValueError):
    """Raised when normalized current state is internally inconsistent."""


class CurrentStateBasis(str, Enum):
    BLANK_DESIGN = "blank_design"
    OBSERVED_COMPLETE = "observed_complete"
    OBSERVED_PARTIAL = "observed_partial"


def _required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise CurrentStateError(f"{field_name} must not be empty")
    return normalized


def _canonical_network(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        network = ip_network(value, strict=True)
    except ValueError as exc:
        raise CurrentStateError(f"Invalid canonical IPv4 network {value!r}: {exc}") from exc
    if not isinstance(network, IPv4Network):
        raise CurrentStateError("Only IPv4 current-state networks are supported initially")
    return str(network)


def _canonical_address(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        address = ip_address(value)
    except ValueError as exc:
        raise CurrentStateError(f"Invalid IPv4 address {value!r}: {exc}") from exc
    if not isinstance(address, IPv4Address):
        raise CurrentStateError("Only IPv4 current-state addresses are supported initially")
    return str(address)


@dataclass(frozen=True, slots=True)
class CurrentVLANState:
    vlan_id: int
    name: str
    network: str | None = None
    gateway: str | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.vlan_id <= 4094:
            raise CurrentStateError(f"VLAN ID {self.vlan_id} is outside 1..4094")
        object.__setattr__(self, "name", _required_text(self.name, "VLAN name"))
        network = _canonical_network(self.network)
        gateway = _canonical_address(self.gateway)
        if gateway is not None and network is None:
            raise CurrentStateError("Current VLAN gateway requires a current VLAN network")
        if gateway is not None and network is not None:
            parsed_network = ip_network(network)
            parsed_gateway = ip_address(gateway)
            if parsed_gateway not in parsed_network:
                raise CurrentStateError(
                    f"Current VLAN gateway {gateway} is outside network {network}"
                )
        object.__setattr__(self, "network", network)
        object.__setattr__(self, "gateway", gateway)


@dataclass(frozen=True, slots=True)
class CurrentAccessPortState:
    interface: str
    access_vlan: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "interface", _required_text(self.interface, "access interface")
        )
        if not 1 <= self.access_vlan <= 4094:
            raise CurrentStateError(f"Invalid access VLAN {self.access_vlan}")


@dataclass(frozen=True, slots=True)
class CurrentTrunkState:
    interface: str
    allowed_vlans: tuple[int, ...]
    native_vlan: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "interface", _required_text(self.interface, "trunk interface")
        )
        allowed = tuple(self.allowed_vlans)
        if not allowed:
            raise CurrentStateError(f"Trunk {self.interface} requires allowed_vlans")
        if len(allowed) != len(set(allowed)):
            raise CurrentStateError(f"Trunk {self.interface} contains duplicate VLAN IDs")
        if any(vlan_id < 1 or vlan_id > 4094 for vlan_id in allowed):
            raise CurrentStateError(f"Trunk {self.interface} contains invalid VLAN ID")
        object.__setattr__(self, "allowed_vlans", tuple(sorted(allowed)))
        if self.native_vlan is not None:
            if not 1 <= self.native_vlan <= 4094:
                raise CurrentStateError(f"Invalid native VLAN {self.native_vlan}")
            if self.native_vlan not in allowed:
                raise CurrentStateError(
                    f"Native VLAN {self.native_vlan} is not carried by trunk {self.interface}"
                )


@dataclass(frozen=True, slots=True)
class CurrentManagementState:
    vlan_id: int | None
    allowed_source_networks: tuple[str, ...] = field(default_factory=tuple)
    services: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.vlan_id is not None and not 1 <= self.vlan_id <= 4094:
            raise CurrentStateError("Management VLAN must be inside 1..4094")
        networks = tuple(_canonical_network(value) for value in self.allowed_source_networks)
        if len(networks) != len(set(networks)):
            raise CurrentStateError("Duplicate current management source network")
        object.__setattr__(self, "allowed_source_networks", tuple(sorted(networks)))
        services = tuple(sorted(_required_text(value, "management service").lower() for value in self.services))
        if len(services) != len(set(services)):
            raise CurrentStateError("Duplicate current management service")
        object.__setattr__(self, "services", services)


@dataclass(frozen=True, slots=True)
class CurrentNetworkState:
    """Complete or partial normalized basis for deterministic diff planning.

    `BLANK_DESIGN` means the user intentionally wants a green-field comparison and absence
    is authoritative. `OBSERVED_COMPLETE` means a read-only collector has proven the included
    state is complete for the planner's managed scope. `OBSERVED_PARTIAL` means absence must
    never be treated as proof that a live object does not exist.
    """

    basis: CurrentStateBasis | str
    vlans: tuple[CurrentVLANState, ...] = field(default_factory=tuple)
    access_ports: tuple[CurrentAccessPortState, ...] = field(default_factory=tuple)
    trunks: tuple[CurrentTrunkState, ...] = field(default_factory=tuple)
    management: CurrentManagementState | None = None
    satisfied_security_rules: tuple[str, ...] = field(default_factory=tuple)
    collected_at_utc: str | None = None
    source_revision: str | None = None

    def __post_init__(self) -> None:
        try:
            basis = self.basis if isinstance(self.basis, CurrentStateBasis) else CurrentStateBasis(self.basis)
        except ValueError as exc:
            raise CurrentStateError(f"Unsupported current-state basis {self.basis!r}") from exc
        object.__setattr__(self, "basis", basis)

        if basis in {CurrentStateBasis.OBSERVED_COMPLETE, CurrentStateBasis.OBSERVED_PARTIAL}:
            if self.collected_at_utc is None or self.source_revision is None:
                raise CurrentStateError(
                    "Observed current state requires collected_at_utc and source_revision"
                )
        if self.collected_at_utc is not None:
            object.__setattr__(
                self,
                "collected_at_utc",
                _required_text(self.collected_at_utc, "collected_at_utc"),
            )
        if self.source_revision is not None:
            object.__setattr__(
                self,
                "source_revision",
                _required_text(self.source_revision, "source_revision"),
            )

        vlans = tuple(self.vlans)
        vlan_ids = [vlan.vlan_id for vlan in vlans]
        if len(vlan_ids) != len(set(vlan_ids)):
            raise CurrentStateError("Duplicate VLAN IDs in current network state")
        object.__setattr__(self, "vlans", vlans)

        access_ports = tuple(self.access_ports)
        trunks = tuple(self.trunks)
        access_names = [port.interface.casefold() for port in access_ports]
        trunk_names = [trunk.interface.casefold() for trunk in trunks]
        if len(access_names) != len(set(access_names)):
            raise CurrentStateError("Duplicate current access-port interface")
        if len(trunk_names) != len(set(trunk_names)):
            raise CurrentStateError("Duplicate current trunk interface")
        overlap = set(access_names) & set(trunk_names)
        if overlap:
            raise CurrentStateError(
                f"Interfaces cannot be both access and trunk in current state: {sorted(overlap)}"
            )
        object.__setattr__(self, "access_ports", access_ports)
        object.__setattr__(self, "trunks", trunks)

        rules = tuple(_required_text(rule, "security rule ID") for rule in self.satisfied_security_rules)
        if len(rules) != len(set(rules)):
            raise CurrentStateError("Duplicate satisfied security rule ID")
        object.__setattr__(self, "satisfied_security_rules", tuple(sorted(rules)))

    @property
    def absence_is_authoritative(self) -> bool:
        return self.basis in {
            CurrentStateBasis.BLANK_DESIGN,
            CurrentStateBasis.OBSERVED_COMPLETE,
        }
