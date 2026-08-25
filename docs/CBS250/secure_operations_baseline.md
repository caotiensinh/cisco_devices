# CBS250 Secure Operations Baseline

This file defines a project baseline derived from Cisco's official CBS250 security, AAA, management ACL, SSH, SNMP and web-management documentation. It is a recommended operating policy for automation; it is not a statement of factory defaults unless explicitly noted.

## Factory-management behavior that matters

Cisco's Administration Guide states the following factory service defaults:

- HTTP: enabled
- HTTPS: enabled
- SNMP: disabled
- Telnet: disabled
- SSH: disabled

The project should not preserve these defaults blindly. After bootstrap access is proven, prefer encrypted management only.

## Recommended management-plane policy

### Transport

Preferred:

- SSH for interactive/scripted CLI;
- SCP for configuration/file transfer;
- HTTPS when the web UI is required;
- SNMPv3 for monitoring/telemetry;
- remote syslog for durable event history.

Disable or avoid where operationally possible:

- Telnet;
- plaintext HTTP;
- SNMPv1/v2c for production monitoring.

Cisco explicitly recommends SSH instead of Telnet. Cisco's SNMP documentation recommends SNMPv3 because of security weaknesses in older SNMP versions.

### Management network isolation

Use a dedicated management VLAN or dedicated management path when the deployment architecture permits it. Assign predictable management addressing rather than relying on an uncontrolled DHCP lease for long-term automation targets.

Restrict management-plane reachability with a CBS250 management ACL. Cisco's management ACL can match:

- source IPv4/IPv6 address;
- Ethernet port, VLAN or port-channel;
- management service: Telnet, SSH, HTTP, HTTPS or SNMP.

An active management ACL is selected using `management access-class`.

Important semantics from Cisco:

- if an ACL has no matching permit, traffic is implicitly denied;
- the active management ACL cannot be updated or removed directly;
- a bad management ACL can lock out remote administration.

Therefore automation must never activate a management ACL until it has proven a permit rule for the current trusted management source and verified console recovery access.

## Authentication and authorization

CBS250 supports multiple CLI privilege levels (1, 7 and 15), local users, RADIUS and AAA method lists.

Project policy:

1. Use a dedicated automation identity rather than a shared human administrator where practical.
2. Give the automation account only the privilege required by the operation phase.
3. Separate read-only discovery/monitoring from write-capable configuration execution.
4. For larger deployments, prefer centralized RADIUS/TACACS+ where supported and operationally appropriate, while retaining a controlled local break-glass path.
5. Enable login history/accounting where it improves traceability.

Cisco AAA commands include login authentication method lists, login blocking/delay, quiet-mode ACLs, password complexity, password aging/history, login history, and RADIUS/TACACS+ accounting.

## SSH policy

Cisco documents SSH as the secure replacement for Telnet and SCP as using SSH.

Some CBS250 firmware presents legacy SSH host-key algorithms such as `ssh-rsa`. The project currently allows `ssh-rsa` only as a device-specific compatibility exception for discovery where required. Do not globally weaken the workstation/server SSH policy, and do not enable `ssh-dss` as a convenience fallback.

For each device, inventory:

- SSH server enabled/disabled;
- SSH port;
- password authentication state;
- public-key authentication state;
- negotiated host-key algorithm;
- current firmware version.

Treat legacy crypto as technical debt to be correlated with firmware support before making any security change.

## HTTPS policy

Use HTTPS for the GUI. Disable HTTP after validating HTTPS access unless a documented operational dependency requires HTTP.

Cisco exposes web-server controls in the CLI, including HTTP/HTTPS server state, ports and HTTPS session logging.

Do not change web ports or certificate configuration in bulk without first validating the exact CLI tree and retaining a recovery path.

## SNMP policy

CBS250 supports SNMPv1, SNMPv2c and SNMPv3 with traps. Cisco's Administration Guide recommends SNMPv3 because of security vulnerabilities in the older versions.

Preferred production profile:

- SNMPv3 USM;
- authentication enabled;
- privacy/encryption enabled where supported by the running image;
- restrict the NMS source through management ACLs/firewalling;
- use read-only views for monitoring whenever write access is unnecessary;
- send traps for meaningful state changes rather than polling everything at high frequency.

Do not allow an automation discovery tool to issue SNMP SET operations by default.

## Port security and edge protection

Depending on endpoint role, consider:

- port security / learned-MAC limits;
- 802.1X for controlled user/device access;
- guest VLAN where policy requires it;
- storm control for broadcast/multicast/unknown-unicast;
- STP protections on edge/uplink ports;
- loopback detection as an additional independent loop mechanism;
- ACLs for sensitive VLAN boundaries.

These controls are topology-sensitive. Automation must not mass-apply them without device role and interface role data.

## Configuration-write safety

Every configuration write workflow should follow:

1. identify exact SKU and firmware;
2. discover live CLI capability;
3. capture running configuration;
4. capture startup configuration;
5. collect relevant state (`show` evidence);
6. build a proposed diff;
7. pre-validate commands against the exact live capability tree;
8. apply the smallest coherent change set;
9. verify operational state;
10. persist only after verification;
11. retain backup and rollback metadata.

`copy running-config startup-config` is a persistence action, not an innocuous read. It belongs behind the write authorization gate.

## Never-auto-execute class

At minimum, the following root command families must remain blocked from autonomous execution unless an explicit policy has authorized a specific validated operation:

- `boot`
- `clear`
- `copy`
- `debug-mode`
- `delete`
- `reload`
- `rename`
- `rmdir`
- `set`
- `write`
- `no`
- configuration commands that can shut ports, alter VLAN membership, modify routing, change management access, erase logs, or alter firmware/images.

The fact that a command appears in `?` only establishes availability, not safety.

## Official Cisco basis

See:

- Cisco Business 250 Series Administration Guide — Security
- Cisco Business 250 Series CLI Guide — AAA Commands
- Cisco Business 250 Series CLI Guide — Management ACL Commands
- Cisco Business 250 Series CLI Guide — Telnet, SSH and Slogin Commands
- Cisco Business 250 Series CLI Guide — Web Server Commands
- Cisco Business 250 Series Administration Guide — SNMP

URLs are collected in `official_sources.md`.
