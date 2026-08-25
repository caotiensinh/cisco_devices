# CBS250 Switching, Routing and Service Behavior

This document translates Cisco's feature documentation into automation-relevant operational behavior.

## VLAN model

CBS250 supports port-based and 802.1Q VLANs, management VLAN, guest VLAN and voice VLAN functions. Cisco documents up to 255 active VLANs simultaneously, while VLAN IDs are in the normal 802.1Q space (2-4094 for user-created VLANs in the GUI workflow).

Automation must treat these as separate concepts:

- VLAN existence;
- VLAN interface administrative state;
- port mode;
- tagged/untagged membership;
- native/PVID behavior;
- Layer-3 SVI/addressing;
- management VLAN;
- voice VLAN.

Creating a VLAN alone does not make a port a member of it and does not imply that an L3 interface exists.

Recommended model objects:

```text
vlan
  id
  name
  interface_state
  management_role
  voice_role

interface_vlan_membership
  interface
  mode
  pvid
  tagged_vlans
  untagged_vlan
```

Before changing VLAN membership remotely, verify that the management path will remain reachable after the change.

## Spanning Tree

Cisco documents five selectable STP modes:

- STP
- RSTP
- MSTP
- PVST+
- Rapid-PVST+

RSTP is the documented default. CBS250 supports up to 8 MST instances and up to 126 PVST+/Rapid-PVST+ instances.

Automation guidance:

- do not change the global STP mode as part of unrelated port changes;
- identify the current root bridge and port roles before modifying uplinks;
- treat edge/PortFast-like behavior and BPDU-related protections as topology-sensitive;
- retain STP globally unless a documented topology specifically requires otherwise;
- use loopback detection as an additional mechanism, not as a replacement for a deliberate STP design.

## Link Aggregation

CBS250 supports IEEE 802.3ad LACP with up to four LAG groups and up to eight active ports per group. A dynamic LAG can have up to 16 candidate ports according to the data sheet.

Automation must validate before adding/removing a LAG member:

- peer LACP state;
- member speed/duplex compatibility;
- VLAN/trunk consistency;
- STP impact;
- whether the management path depends on the LAG;
- minimum operational member count required by the service.

Never apply independent VLAN configuration to physical LAG members if the platform expects configuration at the port-channel/LAG layer.

## MAC learning and port security

The data sheet documents an 8K MAC table. CBS250 also supports source-MAC locking / learned-address limits through port security.

Useful automation telemetry:

- dynamic/static MAC count per port/VLAN;
- MAC move frequency;
- unexpected multiple endpoints on access ports;
- port-security violation state;
- table utilization.

Do not automatically clear MAC tables as a troubleshooting first step; `clear` is state-changing and can temporarily increase flooding.

## IPv4/IPv6 Layer-3 routing

Cisco documents static Layer-3 routing, including up to 32 IPv4 static routes and 16 IP interfaces. L3 interfaces may be physical ports, LAGs, VLAN interfaces or loopback interfaces. IPv6 routing is also documented.

Use CBS250 static routing for bounded use cases such as:

- inter-VLAN routing for a small number of segments;
- management routing;
- simple default/static paths;
- DHCP/UDP relay across locally routed segments.

Do not assume support for dynamic routing protocols from the data-sheet description. Only enable a routing feature if it is both documented for the exact firmware and observed in the live capability tree.

### Route automation rules

Before adding a route:

- confirm the destination does not overlap incorrectly with connected/local routes;
- confirm next-hop reachability;
- capture the existing routing table;
- calculate longest-prefix-match impact;
- verify the management return path;
- stage rollback commands.

Cisco's Administration Guide states that static-route selection uses longest-prefix match.

## Multicast

CBS250 supports IGMP snooping v1/v2/v3, an IGMP snooping querier and MLD v1/v2 snooping. The data sheet documents up to 255 multicast groups.

Cisco's Administration Guide states that IGMP snooping operation requires bridge multicast filtering to be enabled, and snooping must be enabled both globally and for the relevant VLAN.

For video-surveillance and other multicast-heavy deployments, model at least:

```text
multicast_global
bridge_filtering
igmp_snooping_global
igmp_querier_global

multicast_vlan
vlan_id
igmp_snooping
querier
mrouter_ports
learned_groups
```

Do not enable an IGMP querier blindly when a proper multicast router/querier already exists. Duplicate queriers are not automatically catastrophic, but election and topology behavior must be understood.

## QoS

CBS250 exposes Basic and Advanced QoS modes, and Cisco documents eight hardware queues.

Basic mode focuses on class-of-service treatment using externally assigned QoS values such as 802.1p and DSCP. Advanced mode supports class maps/policy behavior and policing.

Important operational warning: Cisco documents that changing QoS modes can remove or reset parts of the existing QoS configuration. Examples include policy/class-map deletion when leaving Advanced mode and trust-state reset when moving from Basic to Advanced.

Therefore the automation framework must classify global QoS mode changes as **high impact**.

For voice/video networks, a safe approach is:

- preserve DSCP/CoS trust boundaries intentionally;
- prioritize latency-sensitive traffic only where markings are trustworthy;
- use shaping/policing to protect uplinks from oversubscription;
- verify queue counters after policy changes;
- avoid blanket strict-priority assignment that can starve best-effort traffic.

## PoE / PoE+

Applicable CBS250 models support 802.3af and 802.3at PoE+, up to 30 W per supported port subject to the model's total budget. Power budgets vary by SKU.

Cisco exposes per-port administrative PoE state, priority and statistics. Time-based PoE is also documented.

Automation must discover:

- exact PoE-capable SKU;
- total power budget;
- current consumed/available power;
- port power state;
- powered-device class/demand;
- configured priority.

Never cycle PoE automatically as a generic troubleshooting action unless the affected endpoint and outage impact have been explicitly authorized.

## LLDP, LLDP-MED, CDP and Smartport

CBS250 supports LLDP/LLDP-MED and CDP. These are valuable for topology discovery and role inference.

Smartport can apply role-oriented configuration profiles. This is convenient but also means the switch may change multiple settings as a consequence of one Smartport action.

For deterministic automation, first inventory whether Smartport is enabled and what role is applied to each interface. Avoid fighting Smartport by separately enforcing conflicting low-level settings.

## Green Ethernet / EEE

The family supports Energy Efficient Ethernet (802.3az), energy detect and cable-length-based power adjustment.

EEE can be useful for energy savings, but for latency-sensitive or problematic links the actual operational behavior should be measured before enforcing it globally. The automation system should collect EEE state and link-flap history before recommending changes.

## Official Cisco basis

See `official_sources.md`, especially:

- CBS250 Data Sheet
- Administration Guide — VLAN Management
- Administration Guide — Spanning Tree
- Administration Guide — Port Management
- Administration Guide — Multicast
- Administration Guide — IPv4 Configuration
- CLI Guide — Spanning Tree Commands
- CLI Guide — IGMP Snooping Commands
- CLI Guide — QoS Commands
