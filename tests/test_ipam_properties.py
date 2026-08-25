import random
from ipaddress import IPv4Address, IPv4Network

import pytest

from cisco_assistant.ipam import (
    GatewayStrategy,
    IPAMError,
    generate_sequential_networks,
    generate_vlan_series,
    subnet_facts,
)


RNG = random.Random(0xCB5250)


def random_aligned_network(prefix_min=16, prefix_max=30):
    prefix = RNG.randint(prefix_min, prefix_max)
    network = IPv4Network((RNG.getrandbits(32), prefix), strict=False)
    return network


def test_randomized_subnet_facts_match_ipv4_invariants():
    for _ in range(500):
        network = random_aligned_network()
        facts = subnet_facts(str(network), GatewayStrategy.FIRST_USABLE)

        assert facts.network == str(network)
        assert facts.prefix_length == network.prefixlen
        assert facts.netmask == str(network.netmask)
        assert facts.broadcast == str(network.broadcast_address)
        assert facts.usable_host_count == network.num_addresses - 2
        assert facts.first_usable == str(network.network_address + 1)
        assert facts.last_usable == str(network.broadcast_address - 1)
        assert facts.gateway == facts.first_usable
        assert IPv4Address(facts.gateway) in network
        assert facts.gateway not in {
            str(network.network_address),
            str(network.broadcast_address),
        }


def test_randomized_last_usable_gateway_is_always_last_host():
    for _ in range(300):
        network = random_aligned_network()
        facts = subnet_facts(str(network), GatewayStrategy.LAST_USABLE)
        assert facts.gateway == str(network.broadcast_address - 1)
        assert facts.gateway == facts.last_usable


def test_randomized_explicit_gateway_round_trips_when_usable():
    for _ in range(300):
        network = random_aligned_network()
        usable_count = network.num_addresses - 2
        offset = RNG.randint(1, usable_count)
        gateway = network.network_address + offset
        facts = subnet_facts(
            str(network),
            GatewayStrategy.NONE,
            explicit_gateway=str(gateway),
        )
        assert facts.gateway == str(gateway)
        assert IPv4Address(facts.gateway) in network


def test_randomized_sequential_networks_are_adjacent_unique_and_nonoverlapping():
    for _ in range(300):
        network = random_aligned_network(prefix_min=20, prefix_max=30)
        # Keep enough room to avoid deliberately testing overflow in this property.
        available = ((1 << 32) - int(network.network_address)) // network.num_addresses
        count = min(RNG.randint(1, 20), max(1, available))
        generated = generate_sequential_networks(str(network), count)

        assert len(generated) == count
        assert len(set(generated)) == count
        for index, item in enumerate(generated):
            assert item.prefixlen == network.prefixlen
            assert int(item.network_address) == (
                int(network.network_address) + index * network.num_addresses
            )
            if index:
                previous = generated[index - 1]
                assert int(item.network_address) == int(previous.broadcast_address) + 1
                assert not previous.overlaps(item)


def test_randomized_vlan_series_preserves_vlan_and_subnet_arithmetic():
    for _ in range(250):
        count = RNG.randint(1, 20)
        increment = RNG.randint(1, 20)
        max_start = 4094 - ((count - 1) * increment)
        if max_start < 1:
            continue
        start_vlan = RNG.randint(1, max_start)
        network = random_aligned_network(prefix_min=20, prefix_max=30)
        available = ((1 << 32) - int(network.network_address)) // network.num_addresses
        if available < count:
            continue

        series = generate_vlan_series(
            start_vlan_id=start_vlan,
            count=count,
            vlan_increment=increment,
            start_network=str(network),
            gateway_strategy=GatewayStrategy.FIRST_USABLE,
            name_prefix="AUTO",
            purpose_prefix="property-test",
        )

        assert len(series) == count
        assert len({item.id for item in series}) == count
        assert len({item.network for item in series}) == count
        for index, item in enumerate(series):
            expected_network = IPv4Network(
                (
                    int(network.network_address) + index * network.num_addresses,
                    network.prefixlen,
                )
            )
            assert item.id == start_vlan + index * increment
            assert item.network == str(expected_network)
            assert item.gateway == str(expected_network.network_address + 1)
            assert item.name == f"AUTO_{item.id}"


def test_boundary_crossing_is_integer_arithmetic_not_string_manipulation():
    generated = generate_sequential_networks("10.255.255.0/24", 3)
    assert tuple(str(item) for item in generated) == (
        "10.255.255.0/24",
        "11.0.0.0/24",
        "11.0.1.0/24",
    )


def test_ipv4_exhaustion_fails_closed_instead_of_wrapping():
    with pytest.raises(IPAMError, match="address space exhausted"):
        generate_sequential_networks("255.255.254.0/24", 3)


def test_vlan_id_overflow_fails_closed_for_bulk_generation():
    with pytest.raises(IPAMError, match="exceed 1..4094"):
        generate_vlan_series(
            start_vlan_id=4090,
            count=3,
            vlan_increment=3,
            start_network="10.0.0.0/24",
        )


def test_31_and_32_prefix_semantics_are_deterministic_and_do_not_crash():
    p31 = subnet_facts("192.0.2.0/31", GatewayStrategy.FIRST_USABLE)
    assert p31.usable_host_count == 2
    assert p31.first_usable == "192.0.2.0"
    assert p31.last_usable == "192.0.2.1"
    assert p31.gateway == "192.0.2.0"

    p32 = subnet_facts("192.0.2.9/32", GatewayStrategy.FIRST_USABLE)
    assert p32.usable_host_count == 1
    assert p32.first_usable == "192.0.2.9"
    assert p32.last_usable == "192.0.2.9"
    assert p32.gateway == "192.0.2.9"
