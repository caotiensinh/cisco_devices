# P4 Template Engine + Design Preview Foundation

## Status

This milestone introduces the first versioned, offline configuration-template layer for the Cisco Network Configuration Assistant.

**Device write authority remains FALSE.**

The template layer:

```text
beginner parameters
  -> versioned template
  -> normalized NetworkIntent
  -> deterministic validation
  -> structured DesignPreview
```

It does **not** produce Cisco CLI and does not connect to a switch.

## Why templates are normalized intent, not scripts

A reusable product template must describe the desired network design, not replay vendor-specific commands.

Correct architecture:

```text
Template + Site Parameters
        -> NetworkIntent
        -> Validation / Exact Device Profile
        -> Future Planner
        -> Future CBS250 Provider Compiler
```

Forbidden architecture:

```text
Template -> hard-coded Cisco command script -> switch
```

This separation allows the same high-level design to be validated before a provider/compiler exists and prevents a beginner-mode template from bypassing safety controls.

## Template schema

Current machine schema:

```text
TEMPLATE_SCHEMA_VERSION = 1
```

Each template definition has:

- stable `template_id`;
- semantic `version`;
- display name;
- description;
- ordered network roles;
- explicit assumptions;
- schema version.

Initial versions are `1.0.0`.

A future incompatible template change must create a new version. Existing saved intent must not silently change because a template definition changed.

Migration tooling is intentionally not implemented yet and remains a checklist item.

## Initial templates

### Small Office

Normalized roles:

```text
management
office
guest
```

The template creates three sequential VLAN/IP networks. Guest isolation is not silently implemented; it remains an explicit security/segmentation policy decision.

### Office + IP Cameras

Normalized roles:

```text
management
office
camera
```

Camera/office reachability and Internet policy are not guessed by the template.

### AI Camera / VMS

Normalized roles:

```text
management
camera
ai_server
vms
```

The template does not guess camera-to-AI/VMS ACLs, bandwidth policy, or routing placement. Those remain separate validated decisions.

## User parameters

The first shared `TemplateRequest` accepts:

```text
site_name
start_vlan_id
vlan_increment
start_network
gateway_strategy
security_profile
role_port_counts
access_interfaces
uplink_interface
management_source_networks
inter_vlan_routing
```

Example conceptual beginner input:

```text
Template: Office + IP Cameras
Site: Tokyo Branch
Start VLAN: 100
VLAN increment: 10
Start network: 10.50.0.0/24
Office ports: 8
Camera ports: 12
Uplink: XG1
Security: BUSINESS_STANDARD
Management source: 10.50.0.0/24
```

The deterministic output begins as:

```text
VLAN 100 MGMT   -> 10.50.0.0/24 -> 10.50.0.1
VLAN 110 OFFICE -> 10.50.1.0/24 -> 10.50.1.1
VLAN 120 CAMERA -> 10.50.2.0/24 -> 10.50.2.1
```

No string-based IP arithmetic is used.

## Physical interface authority

Templates deliberately do **not** invent interface names.

`access_interfaces` and `uplink_interface` must be supplied by the UI/inventory layer or by an explicit offline design input.

This avoids assumptions such as treating all CBS models as having the same port naming/layout.

Port counts are allocated deterministically in template role order. If the requested count exceeds supplied interfaces, template construction fails closed.

## Design Preview

`DesignPreview` is structured presentation data for UI/API/export.

It contains:

- template ID/version/name;
- site name;
- security profile;
- routing intent;
- VLAN/IP plan;
- access-port plan;
- uplink plan;
- management VLAN/source networks;
- unassigned interfaces;
- validation result/issues/remediation;
- template assumptions/notes;
- `device_commands_generated = false`.

It can be rendered as a deterministic text preview or converted to a JSON-compatible dictionary.

## Example preview

```text
NETWORK DESIGN PREVIEW
======================
Site: Tokyo Branch
Template: Office + IP Cameras (office_ip_cameras@1.0.0)
Security profile: BUSINESS_STANDARD
Inter-VLAN routing requested: NO
Device commands generated: NO

VLAN / IP PLAN
--------------
VLAN 100  MGMT         network=10.50.0.0/24     gateway=10.50.0.1 purpose=management
VLAN 110  OFFICE       network=10.50.1.0/24     gateway=10.50.1.1 purpose=office
VLAN 120  CAMERA       network=10.50.2.0/24     gateway=10.50.2.1 purpose=camera
```

The exact port/uplink sections depend on supplied inventory/site parameters.

## Safety harness

CI treats these files as part of the offline core:

```text
cisco_assistant/models.py
cisco_assistant/ipam.py
cisco_assistant/validation.py
cisco_assistant/profiles.py
cisco_assistant/templates.py
cisco_assistant/preview.py
```

The harness blocks device/network execution libraries from these modules and checks that template/preview sources do not embed destructive/write CLI sequences.

The template engine therefore cannot gain device execution simply by being called from a frontend.

## Current limitations

This milestone does not yet implement:

- template migration tooling;
- full security-profile expansion;
- automatic segmentation/ACL design;
- current-state diff/planner;
- frontend wizard;
- device configuration compilation;
- device writes.

The next safe milestone is to build versioned security profiles and/or an offline desired-state planner while keeping execution authority disabled.
