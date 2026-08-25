"""Pure validator for repository write-authority activation state.

This module grants no authority. It only validates whether machine-readable governance state
satisfies the activation contract. The current repository state is expected to remain fully
disabled with no approval marker.
"""
from __future__ import annotations

from typing import Mapping, Sequence


WILDCARDS = {"*", "ALL", "all", "ANY", "any"}


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def validate_write_authority_state(
    scope: Mapping[str, object],
    *,
    approval: Mapping[str, object] | None,
    marker_exists: bool,
) -> tuple[str, ...]:
    """Return deterministic validation errors for one proposed governance state."""
    errors: list[str] = []
    policy_obj = scope.get("write_authority_activation_policy")
    if not isinstance(policy_obj, Mapping):
        return ("write_authority_activation_policy is missing or malformed",)
    policy = policy_obj

    global_write = scope.get("global_device_write_authority") is True
    production_write = scope.get("production_network_write_authority") is True

    if production_write and not global_write:
        errors.append("production network write authority requires global device write authority")

    if not global_write and not production_write:
        if policy.get("stale_marker_forbidden_when_authority_false") is not True:
            errors.append("stale-marker prohibition must remain enabled")
        if marker_exists:
            errors.append("approval marker must not exist while write authority is disabled")
        return tuple(errors)

    phase = str(scope.get("current_phase", ""))
    required_prefix = str(policy.get("required_phase_prefix", ""))
    if not required_prefix or not phase.startswith(required_prefix):
        errors.append("write authority may only be enabled in the configured P6 phase")

    if not marker_exists or approval is None:
        errors.append("dedicated write-authority approval marker is required")
        return tuple(errors)

    if approval.get("schema_version") != 1:
        errors.append("approval marker schema_version must be 1")
    if approval.get("approved") is not True:
        errors.append("approval marker must set approved=true")
    if not _nonempty(approval.get("human_owner_approval_reference")):
        errors.append("human owner approval reference is required")

    target_obj = approval.get("target")
    if not isinstance(target_obj, Mapping):
        errors.append("exact target binding is required")
    else:
        for key in ("vendor", "family", "product_id", "firmware_version"):
            value = target_obj.get(key)
            if not _nonempty(value) or str(value).strip() in WILDCARDS:
                errors.append(f"target {key} must be exact and non-wildcard")

    operations_obj = approval.get("allowed_operations")
    if not isinstance(operations_obj, Sequence) or isinstance(operations_obj, (str, bytes)):
        errors.append("allowed_operations must be an explicit non-empty list")
    else:
        operations = [str(value).strip() for value in operations_obj]
        if not operations or any(not value for value in operations):
            errors.append("allowed_operations must be an explicit non-empty list")
        if any(value in WILDCARDS for value in operations):
            errors.append("wildcard operation authority is forbidden")
        if len(operations) != len(set(operations)):
            errors.append("allowed_operations contains duplicates")

    for gate_name, label in (
        ("test_release", "TEST_RELEASE"),
        ("security_gate", "SECURITY_GATE"),
    ):
        gate_obj = approval.get(gate_name)
        if not isinstance(gate_obj, Mapping):
            errors.append(f"{label} PASS evidence is required")
            continue
        if gate_obj.get("verdict") != "PASS":
            errors.append(f"{label} verdict must be PASS")
        if not _nonempty(gate_obj.get("reference")):
            errors.append(f"{label} evidence reference is required")

    if policy.get("destructive_class_d_allowed_by_marker") is not False:
        errors.append("governance policy must prohibit class D marker authority")
    if approval.get("destructive_class_d_approved", False) is not False:
        errors.append("approval marker cannot authorize destructive class D")

    if production_write and approval.get("production_network_write_approved") is not True:
        errors.append("production write authority requires explicit production approval")

    return tuple(errors)
