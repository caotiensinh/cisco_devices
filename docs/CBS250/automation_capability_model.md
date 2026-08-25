# CBS250 Automation Capability Model

## Why live discovery and Cisco documentation are both required

The official CBS250 CLI guide is large and contains command families for AAA, ACL, 802.1X, DHCP relay, IPv4/IPv6, LACP, LLDP, management ACLs, SNMP, PoE, QoS, RMON, SPAN/RSPAN, STP, syslog, SSH, VLAN, Voice VLAN, web management and many other areas.

A live privileged-EXEC `?` on the current device shows only root commands such as `show`, `configure`, `copy`, `system`, `terminal`, `test`, `ssh`, `dot1x`, `green-ethernet`, etc. That does not contradict the CLI guide: most functional commands live below `show`, under configuration mode, or inside submodes.

Therefore this project does not equate a root command list with the complete device capability set.

## Observed privileged-EXEC root baseline

The current live session observed the following 39 root commands:

```text
boot
cbd
cd
clear
clock
configure
copy
crypto
debug-mode
delete
dir
disable
do
dot1x
errdisable
exit
green-ethernet
help
login
macro
mkdir
more
no
ping
pwd
reload
rename
renew
resume
rmdir
set
show
ssh
system
telnet
terminal
test
traceroute
write
```

This is recorded structurally in `knowledge/cbs250/observed_exec_root.json`.

## Official CLI command families

Cisco's 2025 CBS250 CLI Guide includes the following major command chapters:

```text
802.1X
ACL
Address Table
AAA
Auto-Update / Auto-Configuration
Bonjour
CA Certificate
CDP
Clock
DoS
DHCP Relay / DHCPv6
DNS Client
EEE
Ethernet Configuration
CBD Probe
File System
GVRP / Green Ethernet
IGMP / IGMP Snooping
IP Addressing / Routing / System Management
IPv6 / Prefix List / Tunnel
LACP
Loopback Detection
LLDP
Macro
Management ACL
MLD / MLD Snooping
SNMP
PHY
PnP
PoE
Port Channel
QoS
RADIUS
Rate Limit / Storm
RMON
Router Resources
RSA / Certificate
Smartport
SPAN / RSPAN
Spanning Tree
SSH Client
SSD
SYSLOG
System Management
Telnet / SSH / Slogin
User Interface
VLAN
Voice VLAN
Web Server
```

The crawler should map the live command tree to these semantic families.

## Capability state machine

Every command or feature should be normalized to one of these states:

```text
documented_and_observed
documented_not_observed
observed_not_yet_mapped
not_applicable_or_unsupported
blocked_by_privilege
blocked_by_mode
unknown_due_to_crawl_limit
```

### `documented_and_observed`

Safe to treat as syntactically available, but not automatically safe to execute.

### `documented_not_observed`

Possible causes:

- feature is absent on the exact SKU;
- firmware difference;
- privilege restriction;
- wrong command mode;
- crawler recursion/placeholder boundary;
- documentation covers a wider family than the exact device.

Do not infer unsupported until these possibilities are checked.

### `observed_not_yet_mapped`

A live capability exists but has not yet been semantically classified. Keep it read-only/blocked until mapped.

## Command risk classes

### Class R0 — passive read

Examples:

```text
show ...
dir
pwd
help
```

Expected effect: no configuration/state change beyond ordinary management-plane load.

### Class R1 — active diagnostic

Examples:

```text
ping
traceroute
copper/PHY tests where non-disruptive is documented
```

May generate traffic or consume resources. Requires target/rate limits.

### Class R2 — session-local change

Examples:

```text
terminal datadump
cd
```

Changes only the current management session, not device persistent configuration.

### Class W1 — reversible configuration

Examples include VLAN descriptions, logging destinations, SNMP settings, QoS parameters, interface descriptions. These are still production-impacting and require plan/apply/verify/rollback.

### Class W2 — connectivity-impacting configuration

Examples:

```text
management ACL
interface VLAN membership
IP addressing/static routes
STP mode/priority
LAG membership
802.1X
port security
shutdown
PoE administrative state
```

Requires out-of-band recovery or a proven alternate management path.

### Class D — destructive/lifecycle

Examples:

```text
reload
delete
clear logging
clear logging file
firmware/image operations
filesystem deletion
factory reset/erase operations
```

Never autonomous by default.

## Placeholder handling

Context-sensitive help may expose placeholders such as:

```text
<1-4094>
WORD
A.B.C.D
interface-id
```

The crawler must record placeholders but not brute-force them. Expansion should come from live inventory objects:

- actual interfaces from `show interfaces` / inventory;
- actual VLANs from VLAN state;
- actual LAGs from port-channel state;
- configured ACL names from `show` output.

This prevents combinatorial crawling and accidental stateful commands.

## Mode-aware crawling

CBS250 CLI has separate command modes, including:

- privileged EXEC;
- global configuration;
- interface configuration;
- line configuration;
- VLAN database;
- management ACL;
- MAC ACL;
- IPv4 ACL;
- IPv6 ACL;
- other feature-specific submodes.

The crawler must store the mode with every command path. A command path without its mode is incomplete knowledge.

Suggested schema:

```json
{
  "mode": "global_config",
  "path": "logging host <ip-address>",
  "documented": true,
  "observed": true,
  "risk": "W1",
  "semantic_feature": "syslog.remote_server",
  "source": "Cisco CLI Guide / SYSLOG Commands"
}
```

## Device fingerprint

Every crawl must be bound to a fingerprint:

```text
vendor
family
product_id
hardware_revision
firmware_version
boot_version
serial/asset identifier (optional/private inventory)
management_protocol
privilege_level
crawl_timestamp
```

Do not merge command trees from different firmware versions as if they were identical.

## Read-only inventory phase

Before any configuration automation, collect at least:

```text
show version
show system
show running-config
show startup-config
show interfaces / interface status
show vlan state
show spanning-tree state
show port-channel/LACP state
show logging
show logging file
show ip ssh
show management access-class/list
show route/IP interface state
show SNMP state
show clock/SNTP state
```

The exact syntax must come from the live tree. The list above expresses semantic goals, not a promise that every literal command exists on every firmware.

## Transaction model for writes

A write-capable module should use this transaction sequence:

```text
DISCOVER
  -> SNAPSHOT
  -> PLAN
  -> STATIC VALIDATE
  -> LIVE PRECHECK
  -> APPLY (small change set)
  -> VERIFY
  -> PERSIST
  -> POST-SNAPSHOT
  -> AUDIT RECORD
```

If verification fails, do not blindly persist. Roll back only with a validated rollback path.

## Idempotency

Configuration automation should compare desired state to observed state and emit no command when already compliant.

Avoid scripts that repeatedly push a full configuration regardless of current state. CBS250 has running/startup configuration semantics and feature interactions that make blind replay risky.

## Evidence format

Every action should produce machine-readable evidence:

```json
{
  "device_fingerprint": {},
  "operation": "...",
  "risk_class": "R0|R1|R2|W1|W2|D",
  "pre_state": {},
  "commands": [],
  "raw_output_refs": [],
  "post_state": {},
  "persisted": false,
  "result": "PASS|FAIL|DEFERRED"
}
```

Secrets must never be included in evidence.

## Next crawler milestones

1. Finish full EXEC and global-config help crawl.
2. Parse and normalize the exact device fingerprint.
3. Add mode-safe discovery for interface, line, VLAN database and ACL submodes using only live-known objects.
4. Build a documented-vs-observed diff against the official CLI family map.
5. Add read-only collectors.
6. Add configuration planners with no execution.
7. Only after test evidence, add gated execution modules.
