# CBS250 Observability, Logging, Backup and Lifecycle

## Local logging architecture

CBS250 has two local syslog stores that must be treated separately.

### Internal/RAM buffer

Cisco's CLI guide documents `show logging` as displaying syslog messages stored in the internal buffer.

`logging buffered` controls the displayed severity threshold and buffer size. Cisco documents a buffer-size range of **20-1000 messages**, with a default of **1000** and default severity **informational**.

Operational consequence:

- the RAM buffer is finite;
- older messages roll out as the buffer fills;
- reboot does not provide durable historical retention;
- automation must not treat `show logging` as an audit archive.

### Flash logging file

Cisco documents `show logging file` as displaying syslog messages stored in the logging file.

`logging file <level>` controls what severity is written to that file. The documented default severity is **errors**, which is materially different from the RAM buffer default.

This explains a common operational surprise: a GUI may show many informational/warning events in RAM, but after reboot only the smaller persistent subset remains if Flash logging was left at the default `errors` level.

`clear logging file` explicitly deletes the logging-file messages and is therefore a destructive command for evidence preservation.

### Remote syslog

`logging host` sends messages to one or more remote syslog servers. Cisco supports IPv4/IPv6/hostname targets, a configurable port (default 514), severity and facility.

For durable operations, remote syslog should be the primary history store. Local RAM/Flash logs are diagnostic caches, not the authoritative long-term event archive.

Recommended production model:

```text
CBS250
  -> RAM buffer: immediate troubleshooting
  -> Flash log: reboot-surviving local fallback
  -> remote syslog: durable centralized history
```

## Recommended logging policy

The appropriate severity depends on log volume and operational needs. A reasonable baseline to evaluate is:

- RAM: debugging or informational for short-term diagnosis, subject to noise;
- Flash: informational if retention/flash-write tradeoffs are acceptable;
- remote syslog: informational for operational history;
- console: warnings/errors to avoid interactive-console noise.

This is a project recommendation, not a universal Cisco requirement. Measure event volume before enabling high-volume debugging persistently.

Always collect the counters reported by `show logging` / `show logging file`, including:

- logged messages;
- displayed messages;
- maximum buffer size;
- dropped messages;
- messages not logged;
- application filtering state.

Dropped-message counters are an observability health signal.

## RMON and SNMP

CBS250 includes embedded RMON support for four groups:

- history;
- statistics;
- alarms;
- events.

This is useful for lightweight local thresholding and trend collection.

SNMP supports v1, v2c and v3, plus traps. Cisco's Administration Guide recommends SNMPv3 because of security weaknesses in older versions.

For an automation/NMS project, SNMPv3 is useful for structured telemetry such as:

- interface counters and state;
- LLDP/CDP neighbor information where exposed through MIBs;
- PoE state and power consumption;
- CPU/environment/resource metrics;
- VLAN/bridge state;
- traps for link/STP/authentication events.

CLI remains useful for feature areas that are difficult to model by SNMP or for configuration evidence.

## SPAN and packet-level diagnostics

CBS250 supports port mirroring and VLAN mirroring. Cisco documents up to four source ports or four source VLANs mirrored to one destination port.

SPAN should be treated as a diagnostic operation with explicit lifecycle:

1. capture pre-state;
2. configure a bounded mirror session;
3. collect traffic;
4. remove the session;
5. verify the destination port returned to its intended role.

Do not leave ad-hoc SPAN sessions indefinitely without inventorying them.

## Device-health evidence

The Administration Guide exposes operational pages for:

- CPU utilization;
- port utilization;
- interface/Etherlike statistics;
- hardware resource utilization;
- health and power;
- PoE power information;
- optical module status;
- copper diagnostics;
- tech-support information;
- RMON;
- RAM and Flash logs.

The project collector should eventually normalize these into a single device-health snapshot.

## Configuration backup

Cisco supports configuration/file operations over TFTP and SCP. SCP is preferred for automation because it runs over SSH.

Before any write-capable automation:

- export running configuration;
- export startup configuration;
- record firmware/image state;
- hash and timestamp the backups;
- store them outside the switch;
- associate them with the planned change transaction.

Do not rely solely on startup-config as rollback evidence: it can be overwritten by `copy running-config startup-config`.

## Firmware architecture

Cisco documents dual firmware images for resilient firmware upgrades and supports web, TFTP and SCP-based firmware transfer.

Firmware must be managed as a dedicated workflow, not as an ordinary configuration change.

## Current release-notes baseline

Cisco's current release-notes page covers firmware 3.0.0.61 through **3.5.3.3**. Release 3.5.3.3 resolves a documented defect in which the switch could reboot with a fatal error from the DNSC process.

This does **not** mean every device should be blindly upgraded to 3.5.3.3. First identify:

- exact SKU;
- current firmware;
- hardware/ACT2/MCU considerations;
- release path;
- current configuration backup;
- downtime window.

## Critical upgrade/downgrade caveats

Cisco warns that upgrades from older releases into the 3.2+ train can take roughly 15 minutes and may reboot multiple times. Interrupting the process can permanently damage the device.

Cisco also documents that downgrading from 3.2.0.84 or later to 3.1.1.7 or lower deletes the startup configuration as part of the downgrade operation.

For some upgrade paths, the MCU version is visible only during console boot and cannot be obtained from normal CLI/support files. Cisco documents MCU mismatch after an upgrade as a condition that can require hardware replacement.

Therefore firmware automation must include console/out-of-band recovery planning and must never power-cycle a device merely because it appears idle during the documented upgrade window.

## Lifecycle

Cisco's support page reports the CBS250 family as end-of-sale and provides an end-of-support horizon. Exact notices can differ by SKU, including later select-model announcements.

The automation project should store per-device lifecycle metadata:

```text
product_id
hardware_revision
serial_or_asset_reference
firmware
firmware_release_date
latest_supported_firmware
end_of_sale
end_of_support
replacement_family
```

Never derive exact lifecycle status only from the family name.

## Official Cisco basis

See `official_sources.md`, especially:

- CLI Guide — SYSLOG Commands
- Administration Guide — Status and Statistics
- Administration Guide — SNMP
- Administration Guide — Administration/File Operations
- Business 250 Data Sheet
- Release Notes 3.0.0.61 through 3.5.3.3
- Recommended Practices for Firmware Update in CBS 250/350
