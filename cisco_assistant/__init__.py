"""Core deterministic models and planning helpers for Cisco Network Configuration Assistant.

This package is intentionally device-write-free. It contains only normalized data models,
network arithmetic, offline capability profiles, and validation primitives.
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
from .profiles import (
    DeviceProfile,
    HardwareCapacity,
    ProfileError,
    ResourceLimits,
    load_cbs250_24t_4x_3_3_0_16_profile,
    load_device_profile,
    validate_intent_against_profile,
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
    "DeviceProfile",
    "GatewayStrategy",
    "HardwareCapacity",
    "IPv4SubnetFacts",
    "ManagementIntent",
    "NetworkIntent",
    "ObservedState",
    "PortIntent",
    "PortMode",
    "ProfileError",
    "ResourceLimits",
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
    "load_cbs250_24t_4x_3_3_0_16_profile",
    "load_device_profile",
    "subnet_facts",
    "validate_intent_against_profile",
    "validate_network_intent",
]
