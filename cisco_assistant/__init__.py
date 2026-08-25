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
    CapabilityState,
    DeviceCapability,
    DeviceFingerprint,
    ManagementIntent,
    NetworkIntent,
    ObservedState,
    PortIntent,
    PortMode,
    RoutingIntent,
    SecurityIntent,
    SecurityProfile,
    SegmentationAction,
    SegmentationIntent,
    SegmentationRule,
    UplinkIntent,
    VLANIntent,
)
from .validation import (
    ValidationIssue,
    ValidationResult,
    ValidationSeverity,
    validate_network_intent,
)

__all__ = [
    "CapabilityState",
    "DeviceCapability",
    "DeviceFingerprint",
    "GatewayStrategy",
    "IPv4SubnetFacts",
    "ManagementIntent",
    "NetworkIntent",
    "ObservedState",
    "PortIntent",
    "PortMode",
    "RoutingIntent",
    "SecurityIntent",
    "SecurityProfile",
    "SegmentationAction",
    "SegmentationIntent",
    "SegmentationRule",
    "UplinkIntent",
    "VLANIntent",
    "ValidationIssue",
    "ValidationResult",
    "ValidationSeverity",
    "generate_sequential_networks",
    "generate_vlan_series",
    "subnet_facts",
    "validate_network_intent",
]
