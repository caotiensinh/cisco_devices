"""Deterministic IPv4/IPAM and VLAN-series generation.

No device access exists in this module. All operations are pure calculations that can be
validated offline before any provider/compiler phase.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network

from .models import ModelValidationError, VLANIntent


class IPAMError(ModelValidationError):
    """Raised when deterministic IP/VLAN generation cannot produce a valid result."""


class GatewayStrategy(str, Enum):
    FIRST_USABLE = "first_usable"
    LAST_USABLE = "last_usable"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class IPv4SubnetFacts:
    network: str
    prefix_length: int
    netmask: str
    broadcast: str
    first_usable: str | None
    last_usable: str | None
    usable_host_count: int
    gateway: str | None


def _parse_network(value: str) -> IPv4Network:
    try:
        network = ip_network(value, strict=True)
    except ValueError as exc:
        raise IPAMError(f"Invalid canonical IPv4 network {value!r}: {exc}") from exc
    if not isinstance(network, IPv4Network):
        raise IPAMError("Only IPv4 is supported by the initial IPAM engine")
    return network


def _host_bounds(network: IPv4Network) -> tuple[IPv4Address | None, IPv4Address | None, int]:
    # ipaddress implements RFC 3021 semantics for /31 and returns the single address for /32.
    hosts = list(network.hosts()) if network.prefixlen >= 31 else None
    if hosts is not None:
        if not hosts:
            return None, None, 0
        return hosts[0], hosts[-1], len(hosts)

    usable_count = max(network.num_addresses - 2, 0)
    if usable_count == 0:
        return None, None, 0
    return network.network_address + 1, network.broadcast_address - 1, usable_count


def _gateway_for_network(
    network: IPv4Network,
    strategy: GatewayStrategy | str,
    explicit_gateway: str | None = None,
) -> IPv4Address | None:
    try:
        strategy = strategy if isinstance(strategy, GatewayStrategy) else GatewayStrategy(strategy)
    except ValueError as exc:
        raise IPAMError(f"Unsupported gateway strategy {strategy!r}") from exc

    first, last, _ = _host_bounds(network)

    if explicit_gateway is not None:
        try:
            gateway = ip_address(explicit_gateway)
        except ValueError as exc:
            raise IPAMError(f"Invalid explicit gateway {explicit_gateway!r}: {exc}") from exc
        if not isinstance(gateway, IPv4Address):
            raise IPAMError("Only IPv4 gateways are supported")
        if gateway not in network:
            raise IPAMError(f"Gateway {gateway} is outside {network}")
        if network.prefixlen <= 30 and gateway in {
            network.network_address,
            network.broadcast_address,
        }:
            raise IPAMError(f"Gateway {gateway} cannot be network/broadcast address for {network}")
        return gateway

    if strategy is GatewayStrategy.NONE:
        return None
    if strategy is GatewayStrategy.FIRST_USABLE:
        if first is None:
            raise IPAMError(f"No usable gateway address exists in {network}")
        return first
    if last is None:
        raise IPAMError(f"No usable gateway address exists in {network}")
    return last


def subnet_facts(
    network: str,
    gateway_strategy: GatewayStrategy | str = GatewayStrategy.FIRST_USABLE,
    explicit_gateway: str | None = None,
) -> IPv4SubnetFacts:
    parsed = _parse_network(network)
    first, last, usable_count = _host_bounds(parsed)
    gateway = _gateway_for_network(parsed, gateway_strategy, explicit_gateway)
    return IPv4SubnetFacts(
        network=str(parsed),
        prefix_length=parsed.prefixlen,
        netmask=str(parsed.netmask),
        broadcast=str(parsed.broadcast_address),
        first_usable=str(first) if first is not None else None,
        last_usable=str(last) if last is not None else None,
        usable_host_count=usable_count,
        gateway=str(gateway) if gateway is not None else None,
    )


def generate_sequential_networks(start_network: str, count: int) -> tuple[IPv4Network, ...]:
    """Generate same-size consecutive networks using integer IP arithmetic.

    Example: 10.10.255.0/24 -> 10.11.0.0/24 crosses the octet boundary correctly.
    """
    if count <= 0:
        raise IPAMError("count must be greater than zero")

    start = _parse_network(start_network)
    step = start.num_addresses
    max_address = (1 << 32) - 1
    results: list[IPv4Network] = []

    for index in range(count):
        network_int = int(start.network_address) + (index * step)
        broadcast_int = network_int + step - 1
        if network_int > max_address or broadcast_int > max_address:
            raise IPAMError(
                f"IPv4 address space exhausted while generating network #{index + 1}"
            )
        generated = IPv4Network((network_int, start.prefixlen))
        results.append(generated)

    return tuple(results)


def generate_vlan_series(
    *,
    start_vlan_id: int,
    count: int,
    vlan_increment: int,
    start_network: str,
    gateway_strategy: GatewayStrategy | str = GatewayStrategy.FIRST_USABLE,
    name_prefix: str = "VLAN",
    purpose_prefix: str = "custom",
) -> tuple[VLANIntent, ...]:
    """Generate a deterministic VLAN + IPv4 sequence without any device assumptions.

    Capability-specific limits (for example active-VLAN capacity) are validated later by
    the capability-aware planner. This function only enforces the protocol VLAN-ID range.
    """
    if count <= 0:
        raise IPAMError("count must be greater than zero")
    if vlan_increment <= 0:
        raise IPAMError("vlan_increment must be greater than zero")
    if not name_prefix.strip():
        raise IPAMError("name_prefix must not be empty")
    if not purpose_prefix.strip():
        raise IPAMError("purpose_prefix must not be empty")

    vlan_ids = tuple(start_vlan_id + (index * vlan_increment) for index in range(count))
    if any(vlan_id < 1 or vlan_id > 4094 for vlan_id in vlan_ids):
        raise IPAMError(
            f"Generated VLAN IDs exceed 1..4094: first={vlan_ids[0]}, last={vlan_ids[-1]}"
        )
    if len(set(vlan_ids)) != len(vlan_ids):
        raise IPAMError("Generated VLAN IDs are not unique")

    networks = generate_sequential_networks(start_network, count)
    results: list[VLANIntent] = []
    for vlan_id, network in zip(vlan_ids, networks, strict=True):
        gateway = _gateway_for_network(network, gateway_strategy)
        results.append(
            VLANIntent(
                id=vlan_id,
                name=f"{name_prefix.strip()}_{vlan_id}",
                network=str(network),
                gateway=str(gateway) if gateway is not None else None,
                purpose=purpose_prefix.strip(),
            )
        )
    return tuple(results)
