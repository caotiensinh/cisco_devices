# CBS250 Platform and Resource Baseline

This document records family-level facts from Cisco's official Business 250 documentation. Exact SKU-specific values must still be bound to a live `show version` / `show system` inventory.

## Platform position

Cisco positions the Business 250 Series as affordable smart switches for small-business networks. The family combines wire-speed switching, security, QoS and static Layer-3 routing with multiple management methods. Selected models provide 10-Gigabit uplinks and PoE+.

The platform is therefore best modeled as:

- a managed Layer-2 switch with substantial control-plane services;
- a static-routing Layer-3 device for limited inter-VLAN routing;
- an edge/access aggregation platform with QoS, multicast control and security policy;
- a scriptable management target, but not a Catalyst IOS/IOS-XE compatibility target.

Do not assume IOS/IOS-XE syntax merely because a command name looks familiar.

## Switching performance

Cisco states that CBS250 models are wire-speed and nonblocking. Capacity varies by SKU. Examples from the current data sheet:

| Model | Forwarding rate (mpps, 64-byte) | Switching capacity |
|---|---:|---:|
| CBS250-8T-E-2G | 14.88 | 20 Gbps |
| CBS250-16T-2G | 26.78 | 36 Gbps |
| CBS250-24T-4G | 41.66 | 56 Gbps |
| CBS250-48T-4G | 77.38 | 104 Gbps |
| CBS250-24T-4X | 95.23 | 128 Gbps |
| CBS250-48T-4X | 130.94 | 176 Gbps |

The exact model must be discovered before using any performance value in monitoring or capacity planning.

## Layer-2 limits and features

Cisco documents the following family-level capabilities:

- up to **255 active VLANs simultaneously**;
- 802.1Q tagged VLANs, port-based VLANs, management VLAN and guest VLAN;
- STP, RSTP, MSTP, PVST+ and Rapid-PVST+;
- RSTP is the documented default STP mode;
- up to **8 MST instances**;
- up to **126 PVST+/Rapid-PVST+ instances**;
- IEEE 802.3ad LACP;
- up to **4 LAG groups**;
- up to **8 active ports per LAG**, with up to 16 candidates for dynamic LAG;
- IGMP v1/v2/v3 snooping and IGMP querier;
- up to **255 multicast groups** documented in the data sheet;
- MLD v1/v2 snooping for IPv6 multicast;
- loopback detection independent of STP;
- an **8K MAC address table**;
- jumbo frames up to **9K**; the data sheet states a 2K default MTU.

These are resource ceilings, not recommended design targets. Automation should monitor utilization and maintain headroom.

## Layer-3 capabilities and limits

The CBS250 family includes static routing features:

- wire-speed IPv4 routing;
- wire-speed IPv6 routing;
- up to **32 IPv4 static routes**;
- up to **16 IP interfaces**;
- Layer-3 interface support on physical ports, LAGs, VLAN interfaces and loopback interfaces;
- CIDR;
- DHCP relay at Layer 3;
- UDP relay.

This is appropriate for modest inter-VLAN routing and management reachability. It should not be modeled as a dynamic-routing campus core unless exact firmware documentation and live capabilities prove otherwise.

## Security resources

Cisco documents:

- IEEE 802.1X authenticator functionality with RADIUS;
- single-host, multi-host and multi-session access modes;
- port security (source MAC locking/learning limits);
- management RADIUS client support;
- storm control for broadcast, multicast and unknown unicast;
- DoS prevention;
- CLI privilege levels 1, 7 and 15;
- up to **512 ACL rules**;
- MAC, IPv4 and IPv6 matching, protocol/port matching, DSCP/IP precedence, TCP flags, ICMP/IGMP and other criteria;
- ingress and egress ACL application;
- time-based ACLs.

## QoS resources

Cisco documents:

- **8 hardware queues**;
- Strict Priority and Weighted Round Robin scheduling;
- classification by port, 802.1p/CoS, IPv4/IPv6 precedence/ToS/DSCP and DiffServ;
- ACL-based classification and remarking;
- ingress policing;
- egress shaping/rate control;
- per-VLAN, per-port and flow-based rate limiting;
- Basic and Advanced QoS modes.

QoS mode is global. Changing modes can delete or reset parts of the existing QoS configuration, so mode changes must never be treated as harmless toggles.

## Management and observability

Cisco documents the following management surfaces:

- web UI over HTTP/HTTPS;
- scriptable full CLI and menu CLI;
- SSH and SCP;
- SNMPv1/v2c/v3 with traps and SNMPv3 USM;
- RMON history, statistics, alarms and events;
- local and remote syslog;
- SPAN / VLAN mirroring;
- Cisco Business Dashboard embedded probe;
- Cisco Network Plug and Play;
- Cisco Business mobile app;
- LLDP/LLDP-MED and CDP;
- TFTP and SCP file operations;
- dual firmware images.

For this project, SSH/CLI, SCP, SNMPv3 and remote syslog are the preferred automation primitives. HTTP, Telnet and SNMPv1/v2c should not be default automation transports.

## PoE family behavior

PoE-capable models support IEEE 802.3af and 802.3at PoE+. Cisco documents up to 30 W per supported copper port until the switch's total PoE budget is exhausted. Power budgets vary significantly by SKU (for example, 100 W, 195 W or 370 W on different 24/48-port models).

Automation must discover the exact SKU and current power budget before calculating headroom or enforcing port policy.

## Source basis

Primary Cisco sources:

- Business 250 Series Smart Switches Data Sheet (updated 21-Mar-2025)
- Cisco Business 250 Series Switches Administration Guide (updated 27-Feb-2025)
- Cisco Business switches 250 Series CLI Guide (updated 28-Feb-2025)

See `official_sources.md` for URLs and release-note references.
