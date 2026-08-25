"""Core deterministic models and planning helpers for Cisco Network Configuration Assistant.

This package is intentionally device-write-free. It contains only normalized data models,
network arithmetic, and offline validation primitives.
"""

from .ipam import (
    GatewayStrategy,
    IPv4SubnetFacts,
    generate_sequential_networks,
    generate_vlan_series,
    subnet_facts,
)
from .models import (
    DeviceFingerprint,
    NetworkIntent,
    PortIntent,
    PortMode,
    SecurityProfile,
    VLANIntent,
)

__all__ = [
    "DeviceFingerprint",
    "GatewayStrategy",
    "IPv4SubnetFacts",
    "NetworkIntent",
    "PortIntent",
    "PortMode",
    "SecurityProfile",
    "VLANIntent",
    "generate_sequential_networks",
    "generate_vlan_series",
    "subnet_facts",
]
