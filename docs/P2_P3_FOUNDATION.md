# P2/P3 Foundation — Normalized Intent and Deterministic IPAM

## Status

This foundation implements offline-only data models and IPv4/VLAN arithmetic for the Cisco Network Configuration Assistant.

Current device write authority remains **FALSE**. Nothing in `cisco_assistant/models.py` or `cisco_assistant/ipam.py` can open SSH, create a socket, spawn a command, call HTTP, or execute device CLI.

## Implemented models

### `DeviceFingerprint`

Represents the minimum normalized identity needed to bind future planning to an exact device/capability dataset:

```text
vendor
family
product_id
firmware_version
management_protocol
capability_dataset
```

### `VLANIntent`

Represents semantic VLAN intent:

```text
id
name
network
gateway
purpose
```

Validation currently includes:

- VLAN ID 1..4094 protocol range;
- canonical IPv4 network syntax;
- gateway must be inside subnet;
- conventional network/broadcast addresses cannot be gateways.

Exact CBS250 active-VLAN limits remain a later capability-aware validation step.

### `PortIntent`

Represents semantic access/trunk intent without device CLI.

Access ports require an access VLAN and reject trunk-only fields. Trunks require an allowed-VLAN set; a native VLAN, when specified, must belong to the allowed set.

### `NetworkIntent`

Combines site-level VLAN and port intent and rejects:

- duplicate VLAN IDs;
- duplicate VLAN names;
- overlapping IPv4 networks;
- duplicate port assignments;
- port references to undefined VLAN IDs.

## Deterministic IPAM engine

`cisco_assistant/ipam.py` uses Python integer/IP network arithmetic, never string concatenation, for network progression.

Supported foundation operations include:

- canonical IPv4 CIDR parsing;
- netmask/broadcast calculation;
- first/last usable address;
- usable-host count;
- gateway strategies: explicit, first usable, last usable, none;
- same-prefix sequential subnet generation;
- cross-octet progression;
- IPv4 address-space overflow detection;
- sequential VLAN-ID + subnet generation;
- VLAN-ID overflow validation.

Example:

```python
from cisco_assistant import generate_vlan_series

vlans = generate_vlan_series(
    start_vlan_id=100,
    count=5,
    vlan_increment=10,
    start_network="10.50.0.0/24",
)
```

Produces deterministically:

```text
100 -> 10.50.0.0/24 -> 10.50.0.1
110 -> 10.50.1.0/24 -> 10.50.1.1
120 -> 10.50.2.0/24 -> 10.50.2.1
130 -> 10.50.3.0/24 -> 10.50.3.1
140 -> 10.50.4.0/24 -> 10.50.4.1
```

Cross-octet example:

```text
10.10.255.0/24
10.11.0.0/24
10.11.1.0/24
```

## Safety harness

`tests/test_offline_core_boundary.py` parses the Python AST and fails CI if the normalized model/IPAM layer starts importing device/network execution libraries such as:

```text
paramiko
socket
subprocess
requests
httpx
netmiko
scrapli
```

It also rejects raw CLI execution API names in this offline core.

This is intentionally an architectural guardrail, not just a code-style preference.

## Tests

Coverage includes:

- the five-VLAN product example;
- /30 and /16 subnet facts;
- /27 and /20 progression;
- cross-octet /24 progression;
- first/last/explicit gateways;
- non-canonical CIDR rejection;
- IPv4 exhaustion;
- VLAN range overflow;
- duplicate VLANs/ports;
- overlapping networks;
- undefined VLAN references;
- access/trunk semantic conflicts;
- deterministic repeat behavior;
- offline architecture boundary.

## Explicitly not implemented yet

This foundation does **not** yet provide:

- live port existence validation;
- `DeviceCapability` / `ObservedState` models;
- Uplink/Routing/Segmentation/Management/Security intent schemas;
- CBS250 active-VLAN capacity enforcement;
- management lockout analysis;
- templates;
- desired-state diff/planner;
- provider command compilation;
- device writes.

## Next implementation slice

The next coherent slice should add:

1. `DeviceCapability` and `ObservedState` schemas for P2;
2. `UplinkIntent`, `RoutingIntent`, `SegmentationIntent`, `ManagementIntent`, and `SecurityIntent` for P3;
3. capability-aware validation (exact interfaces, VLAN capacity, feature availability);
4. structured validation results with machine codes + beginner-readable explanations;
5. additional boundary/property tests.

Do not add any live write path while implementing those items.
