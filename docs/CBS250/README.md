# Cisco Business 250 (CBS250) Knowledge Base

This directory is the project knowledge base for Cisco Business 250 Series Smart Switches.

## Authority model

The project intentionally separates **what Cisco documents** from **what an exact live switch exposes**.

For automation, use this precedence:

1. **Exact live device capability** — model, firmware, privilege, CLI mode and context-sensitive `?` output.
2. **Exact firmware release notes** — version-specific caveats, upgrade/downgrade restrictions and defects.
3. **Cisco CBS250 CLI Guide** — command syntax, command modes, defaults and semantics.
4. **Cisco CBS250 Administration Guide** — operational behavior, GUI mapping and feature workflows.
5. **Cisco CBS250 Data Sheet** — family-level capabilities and resource limits.

A command documented by Cisco is not automatically assumed to be usable on every CBS250 SKU/firmware/mode. A command discovered live is not automatically considered safe to execute.

## Key conclusions

CBS250 is a smart-switch platform with a substantial feature set, not a simple unmanaged Layer-2 switch. Family documentation includes VLANs, RSTP/MSTP/PVST+/Rapid-PVST+, LACP, static IPv4/IPv6 routing, ACLs, 802.1X, RADIUS, QoS, IGMP/MLD snooping, SNMP, RMON, SPAN, syslog, SCP, LLDP/CDP, PoE/PoE+ on applicable SKUs, Cisco Business Dashboard integration and Cisco Network Plug and Play.

The CLI is explicitly described by Cisco as scriptable. The official CLI guide contains command families for AAA, ACL, 802.1X, DHCP relay, IPv4/IPv6, LACP, LLDP, management ACL, SNMP, PoE, QoS, RMON, SPAN/RSPAN, STP, syslog, SSH, VLAN, Voice VLAN and many other areas.

## Project documents

- `platform_and_limits.md` — hardware/family capabilities, Layer 2/Layer 3 resources and management features.
- `secure_operations_baseline.md` — secure management and operational baseline for automation.
- `switching_routing_services.md` — VLAN, STP, LAG, multicast, routing, QoS, PoE and discovery behavior.
- `observability_lifecycle.md` — logging, RMON/SNMP, SPAN, backups and firmware lifecycle.
- `automation_capability_model.md` — how official knowledge and live CLI discovery are merged safely.
- `official_sources.md` — Cisco-only reference set used by this knowledge base.

Structured data is under `knowledge/cbs250/`.

## Important lifecycle note

Cisco's Business 250 support page reports the family as end-of-sale, with support continuing beyond sale end. Exact lifecycle dates and notices can vary by SKU, so automation must identify the exact product ID before making lifecycle decisions.

## Live discovery integration

The repository crawler (`cbs250_cli_discovery.py`) should produce the exact command tree from the device. The crawler output is then compared against the documented command families in this knowledge base.

The intended result is a capability record with four states for each feature/command:

- `documented_and_observed`
- `documented_not_observed`
- `observed_not_yet_mapped`
- `not_applicable_or_unsupported`

This prevents static-document assumptions from becoming production configuration writes.
