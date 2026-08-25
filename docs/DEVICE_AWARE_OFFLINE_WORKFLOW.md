# Exact-Device-Aware Offline Design Workflow

## Objective

This workflow is the first end-to-end product path that closely matches the intended beginner experience while remaining completely device-write-free.

```text
Template / user parameters
        -> normalized NetworkIntent
        -> deterministic IP/VLAN/port plan
        -> generic intent validation
        -> exact target DeviceProfile binding
        -> resource/capability validation
        -> human-readable + structured preview
```

No Cisco CLI is generated or executed.

## Current target

The first exact target profile is:

```text
Cisco CBS250-24T-4X
Firmware 3.3.0.16
Profile cbs250-24t-4x_3.3.0.16
```

The profile distinguishes exact live identity, exact-model hardware facts, and CBS250 family-documented resource limits. Capabilities not yet proven by exact live evidence remain explicitly `documented_not_observed` or another non-proven capability state.

## API

```python
from cisco_assistant import (
    RolePortCount,
    TemplateRequest,
    build_device_aware_design_preview,
    load_cbs250_24t_4x_3_3_0_16_profile,
)

profile = load_cbs250_24t_4x_3_3_0_16_profile()

request = TemplateRequest(
    template_id="small_office",
    site_name="Tokyo Office",
    start_vlan_id=100,
    vlan_increment=10,
    start_network="10.50.0.0/24",
    role_port_counts=(
        RolePortCount("office", 4),
        RolePortCount("guest", 2),
    ),
    access_interfaces=(
        "GigabitEthernet1",
        "GigabitEthernet2",
        "GigabitEthernet3",
        "GigabitEthernet4",
        "GigabitEthernet5",
        "GigabitEthernet6",
    ),
    uplink_interface="TenGigabitEthernet1",
    management_source_networks=("10.50.0.0/24",),
)

preview = build_device_aware_design_preview(
    request,
    profile,
    require_live_proof=False,
)
```

## Offline design mode

`require_live_proof=False` is the normal design experience.

The system may accept a structurally valid design while displaying warnings that an exact CBS250 capability has Cisco documentation support but has not yet been proven by the current live evidence set.

Example conceptual output:

```text
TARGET DEVICE
CBS250-24T-4X / 3.3.0.16

DESIGN
VLAN 100 -> 10.50.0.0/24 -> 10.50.0.1
VLAN 110 -> 10.50.1.0/24 -> 10.50.1.1
VLAN 120 -> 10.50.2.0/24 -> 10.50.2.1

CAPABILITY VALIDATION
WARNING: VLAN capability is documented but not yet exact-live proven.
WARNING: Management ACL capability is documented but not yet exact-live proven.

OVERALL RESULT
PASS FOR OFFLINE DESIGN
Device commands generated: NO
```

A warning is not converted into execution authority.

## Strict future provider precheck

`require_live_proof=True` models a future compiler/provider safety gate.

If a required capability is not `documented_and_observed`, the same design becomes `BLOCKED` even if the design is otherwise logically valid.

This allows one deterministic workflow to support both:

- beginner-friendly offline planning now; and
- strict future provider preconditions later.

Current governance still keeps all device write authority disabled.

## Exact identity protection

When `ObservedState` is supplied, the selected profile must match the observed vendor/family/product/firmware.

For example, a switch observed as firmware `3.5.3.3` cannot silently use the exact profile bound to `3.3.0.16`; validation returns `PROFILE_FINGERPRINT_MISMATCH` and blocks the exact-profile workflow.

## Resource protection

The current exact-profile workflow also blocks designs that exceed known resource limits, including:

- more physical interfaces than the exact SKU can provide;
- more active VLANs than the documented CBS250 family ceiling;
- generated VLAN IDs outside the allowed profile range;
- more routed VLAN interfaces than the documented IP-interface limit.

These checks happen before provider/compiler work.

## Safety boundary

`cisco_assistant/workflow.py` is included in the repository offline-core harness.

It may not import SSH/socket/subprocess/network-execution libraries and may not expose raw CLI execution APIs. CI also scans the template/preview/workflow layers for dangerous Cisco write-command fragments.

The workflow therefore ends at:

```text
validated preview
```

not:

```text
CLI execution
```

## Next product step

The next major layer is the deterministic desired-state/diff planner:

```text
ObservedState + NetworkIntent
        -> typed change operations
        -> dependency/risk/verification metadata
        -> dry-run plan
```

That planner must also remain compile-only/offline initially. Device execution authority remains a later, separately approved phase.
