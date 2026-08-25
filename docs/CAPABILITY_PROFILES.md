# Capability Profiles

## Purpose

Capability profiles bind the normalized design engine to an exact device identity without granting any device execution authority.

The current first profile is:

```text
CBS250-24T-4X / firmware 3.3.0.16
```

The profile is stored at:

```text
knowledge/cbs250/profiles/CBS250-24T-4X_3.3.0.16.json
```

## Authority separation

A profile must distinguish three different kinds of facts:

1. **Exact live-observed identity** — model and firmware observed from the physical switch.
2. **Exact-model hardware facts** — port layout/capacity tied to the exact SKU.
3. **CBS250 family documented limits/features** — Cisco documentation that applies at family level but may not yet have exact live CLI proof in the current evidence set.

The current profile therefore uses:

```text
binding_status = LIVE_BOUND_WITH_FAMILY_DOCUMENTED_LIMITS
```

It must not be described as a complete live-proven command capability registry.

## Conservative feature states

Features use the existing capability state model:

```text
documented_and_observed
documented_not_observed
observed_not_yet_mapped
not_applicable_or_unsupported
blocked_by_privilege
blocked_by_mode
unknown_due_to_crawl_limit
```

The existing v3 evidence directly proves SSH management. Other semantic features such as 802.1Q VLAN, management ACL, remote syslog and static routing are documented by Cisco but remain `documented_not_observed` until the safe live discovery/collector evidence proves exact syntax/state.

This prevents a family-level documentation fact from silently becoming write authority.

## Two validation stages

The same profile supports two intentionally different validation modes.

### Offline design validation

```python
validate_intent_against_profile(
    intent,
    profile,
    require_live_proof=False,
)
```

Documented-but-not-live-proven capabilities produce warnings. This allows a technician to create and review a network design offline without pretending the design is ready to execute.

### Future provider/write precheck

```python
validate_intent_against_profile(
    intent,
    profile,
    require_live_proof=True,
)
```

Any required feature that is not `documented_and_observed` becomes `BLOCKED`.

Current project governance still keeps global device write authority disabled, so this strict mode is only a future safety contract and test target.

## Profile-bound VLAN generation

The user-facing sequential VLAN workflow can now be constrained before provider compilation:

```python
profile = load_cbs250_24t_4x_3_3_0_16_profile()

vlans = generate_vlan_series_for_profile(
    profile,
    start_vlan_id=100,
    count=5,
    vlan_increment=10,
    start_network="10.50.0.0/24",
)
```

The generated result is deterministic:

```text
VLAN 100 -> 10.50.0.0/24 -> 10.50.0.1
VLAN 110 -> 10.50.1.0/24 -> 10.50.1.1
VLAN 120 -> 10.50.2.0/24 -> 10.50.2.1
VLAN 130 -> 10.50.3.0/24 -> 10.50.3.1
VLAN 140 -> 10.50.4.0/24 -> 10.50.4.1
```

The wrapper rejects a desired VLAN count above the profile's active-VLAN ceiling and rejects a generated VLAN-ID series outside the profile range.

## Resource checks currently implemented

For the CBS250-24T-4X profile, offline validation currently checks:

- exact product/firmware match when `ObservedState` is supplied;
- VLAN ID range;
- maximum active VLAN count;
- total declared physical-interface capacity;
- maximum IP-interface count when inter-VLAN routing is requested;
- required semantic feature state;
- observed port/uplink existence when exact observed interface inventory is available;
- required VLAN presence on declared uplinks;
- management intent completeness.

The family resource values currently used include 255 active VLANs, 16 IP interfaces, 32 IPv4 static routes, 4 LAG groups and 512 ACL rules. Not all of these resource types have corresponding intent objects yet; unused limits are retained in the profile for later deterministic planner work.

## Offline-only harness

`cisco_assistant/profiles.py` is part of the offline-core harness.

CI rejects imports of device/network execution libraries such as Paramiko, socket, subprocess, Netmiko, Scrapli, Requests or HTTPX from this module. It also rejects raw CLI execution API names in the offline core.

Therefore the capability profile layer may answer:

```text
SUPPORTED FOR OFFLINE DESIGN
WARNING: NOT LIVE PROVEN
BLOCKED BY RESOURCE LIMIT
BLOCKED BY FINGERPRINT MISMATCH
```

but it cannot send commands to a switch.
