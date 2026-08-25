from ipaddress import IPv4Network

import pytest

from cisco_assistant.ipam import (
    GatewayStrategy,
    IPAMError,
    generate_sequential_networks,
    generate_vlan_series,
    subnet_facts,
)


def test_product_example_generates_expected_five_vlans():
    vlans = generate_vlan_series(
        start_vlan_id=100,
        count=5,
        vlan_increment=10,
        start_network="10.50.0.0/24",
        gateway_strategy=GatewayStrategy.FIRST_USABLE,
        name_prefix="SITE",
        purpose_prefix="office",
    )

    assert [(v.id, v.network, v.gateway) for v in vlans] == [
        (100, "10.50.0.0/24", "10.50.0.1"),
        (110, "10.50.1.0/24", "10.50.1.1"),
        (120, "10.50.2.0/24", "10.50.2.1"),
        (130, "10.50.3.0/24", "10.50.3.1"),
        (140, "10.50.4.0/24", "10.50.4.1"),
    ]


def test_sequential_networks_cross_octet_boundary_using_ip_arithmetic():
    networks = generate_sequential_networks("10.10.255.0/24", 3)
    assert tuple(map(str, networks)) == (
        "10.10.255.0/24",
        "10.11.0.0/24",
        "10.11.1.0/24",
    )


def test_sequential_networks_preserve_prefix_size():
    networks = generate_sequential_networks("172.16.0.0/20", 3)
    assert tuple(map(str, networks)) == (
        "172.16.0.0/20",
        "172.16.16.0/20",
        "172.16.32.0/20",
    )


def test_16_progression_and_facts():
    networks = generate_sequential_networks("10.0.0.0/16", 3)
    assert tuple(map(str, networks)) == (
        "10.0.0.0/16",
        "10.1.0.0/16",
        "10.2.0.0/16",
    )
    facts = subnet_facts("10.0.0.0/16")
    assert facts.netmask == "255.255.0.0"
    assert facts.first_usable == "10.0.0.1"
    assert facts.last_usable == "10.0.255.254"
    assert facts.usable_host_count == 65534


def test_subnet_facts_for_30():
    facts = subnet_facts("192.0.2.0/30")
    assert facts.netmask == "255.255.255.252"
    assert facts.broadcast == "192.0.2.3"
    assert facts.first_usable == "192.0.2.1"
    assert facts.last_usable == "192.0.2.2"
    assert facts.usable_host_count == 2
    assert facts.gateway == "192.0.2.1"


def test_last_usable_gateway_strategy():
    facts = subnet_facts("10.0.0.0/24", GatewayStrategy.LAST_USABLE)
    assert facts.gateway == "10.0.0.254"


def test_explicit_gateway_is_validated():
    facts = subnet_facts(
        "10.0.0.0/24",
        GatewayStrategy.NONE,
        explicit_gateway="10.0.0.10",
    )
    assert facts.gateway == "10.0.0.10"

    with pytest.raises(IPAMError, match="outside"):
        subnet_facts(
            "10.0.0.0/24",
            GatewayStrategy.NONE,
            explicit_gateway="10.0.1.1",
        )

    with pytest.raises(IPAMError, match="network/broadcast"):
        subnet_facts(
            "10.0.0.0/24",
            GatewayStrategy.NONE,
            explicit_gateway="10.0.0.255",
        )


def test_noncanonical_network_is_rejected_instead_of_silently_rewritten():
    with pytest.raises(IPAMError, match="canonical"):
        generate_sequential_networks("10.0.0.7/24", 2)


def test_invalid_count_and_increment_are_rejected():
    with pytest.raises(IPAMError, match="count"):
        generate_sequential_networks("10.0.0.0/24", 0)
    with pytest.raises(IPAMError, match="count"):
        generate_vlan_series(
            start_vlan_id=100,
            count=0,
            vlan_increment=10,
            start_network="10.0.0.0/24",
        )
    with pytest.raises(IPAMError, match="vlan_increment"):
        generate_vlan_series(
            start_vlan_id=100,
            count=2,
            vlan_increment=0,
            start_network="10.0.0.0/24",
        )


def test_vlan_range_overflow_is_rejected():
    with pytest.raises(IPAMError, match="1..4094"):
        generate_vlan_series(
            start_vlan_id=4090,
            count=2,
            vlan_increment=10,
            start_network="10.0.0.0/24",
        )


def test_ipv4_address_space_overflow_is_rejected():
    with pytest.raises(IPAMError, match="exhausted"):
        generate_sequential_networks("255.255.255.0/24", 2)


def test_deterministic_repeat_produces_identical_values():
    kwargs = dict(
        start_vlan_id=10,
        count=8,
        vlan_increment=5,
        start_network="192.168.0.0/27",
    )
    first = generate_vlan_series(**kwargs)
    second = generate_vlan_series(**kwargs)
    assert first == second
    assert all(isinstance(IPv4Network(v.network), IPv4Network) for v in first)
