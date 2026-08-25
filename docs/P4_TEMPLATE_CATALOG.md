# P4 Beginner Template Catalog and Versioning Contract

## Purpose

Templates are guided design accelerators for users who understand basic networking concepts but do not want to manually build every VLAN/IP/port relationship.

A template is **not** a Cisco command macro.

```text
Beginner parameters
    -> versioned template
    -> normalized NetworkIntent
    -> deterministic validation
    -> device profile validation
    -> security expansion
    -> dry-run planner
```

No template contains executable CLI and no template grants device write authority.

## Shared input model

The initial templates accept the same core parameters:

- site name;
- starting VLAN ID;
- VLAN increment;
- starting canonical IPv4 network;
- gateway strategy;
- security profile;
- role-based access-port counts;
- exact access-interface identities supplied by inventory/UI;
- optional exact uplink interface supplied by inventory/UI;
- management source networks;
- explicit inter-VLAN-routing intent.

The template engine never invents physical interface names.

## Shared generated model

Each template deterministically creates:

- a dedicated management role/VLAN;
- one VLAN/network/gateway per declared role;
- sequential VLAN IDs according to the requested increment;
- sequential same-prefix IPv4 networks using integer arithmetic;
- access-port intent only for exact interfaces supplied by inventory/UI;
- optional uplink intent containing every generated VLAN;
- management intent;
- selected security profile intent;
- notes for unresolved design questions.

Unresolved questions remain unresolved; a template does not silently invent topology, ACL, routing, Internet or trust policy.

## Built-in templates

All current built-ins use template schema `1` and template version `1.0.0`.

### Small Office

Roles:

```text
Management
Office
Guest
```

Purpose: fast foundation for a small general office.

The guest segment is separate, but isolation/firewall behavior remains an explicit later policy decision.

### Office + Guest Wi-Fi

Roles:

```text
Management
Office
Guest Wi-Fi
```

Purpose: sites where guest wireless must not inherit office trust.

Important limitation: the template does **not** assume how an access point maps tagged/native VLANs. An AP may require a trunk or vendor-specific management/data behavior. That is handled by later topology intent using exact observed interfaces/capabilities.

### Office + IP Cameras

Roles:

```text
Management
Office
IP Cameras
```

Purpose: mixed business/camera networks.

The template does not decide:

- whether cameras may reach the Internet;
- whether office clients may reach cameras;
- whether cameras may initiate connections to office systems;
- where inter-VLAN routing/firewall enforcement lives.

Those are later explicit segmentation/routing/security decisions.

### Camera + VMS

Roles:

```text
Management
IP Cameras
VMS
```

Purpose: recording/monitoring deployments without a separate AI-server tier.

The template does not silently grant camera-to-VMS reachability. That relationship must be represented by explicit segmentation/security intent so the planner can explain and validate it.

Multicast/IGMP and QoS are also separate design concerns.

### AI Camera / AI Server

Roles:

```text
Management
IP Cameras
AI Servers
```

Purpose: edge video analytics deployments without a separate VMS segment.

The template does not assume:

- camera-to-AI-server security policy;
- AI-server Internet/update access;
- QoS/bandwidth policy.

### AI Camera / VMS

Roles:

```text
Management
IP Cameras
AI Servers
VMS
```

Purpose: composite video-analytics architecture containing both AI processing and VMS roles.

Communication among camera, AI and VMS segments remains explicit policy rather than template magic.

## Why role ordering is deterministic

The template definition owns role order. `role_port_counts` input ordering does not change VLAN order or access-port allocation order.

This guarantees that the same input parameters produce the same normalized intent, preview and later plan hash.

## Version storage contract

A stored template design must record at least:

```text
schema_version
template_id
template_version
parameters
```

The implementation represents this as `TemplateDocument`.

A stored document is not silently reinterpreted using whatever template version happens to be current later.

## Migration contract

`cisco_assistant/template_migrations.py` implements explicit version migration.

Current production migration registry is empty because all built-in templates start at `1.0.0`.

A future version change, for example:

```text
small_office 1.0.0 -> 1.1.0
```

requires an explicit registered migration edge plus regression tests.

If no path exists, migration fails closed:

```text
No explicit migration path
```

The migration system also rejects a migration function that:

- changes `template_id`;
- produces a version other than the registered target;
- uses an unsupported document schema;
- cannot reach the requested target version.

Multi-hop migration is allowed only through explicit registered edges.

## What templates may never do

Templates and migrations may never:

- generate raw device CLI;
- execute device commands;
- invent physical port names;
- assume IOS/IOS-XE syntax for CBS250;
- bypass exact-device capability checks;
- automatically delete current device objects;
- imply management lockout safety;
- turn an unresolved topology/security question into a guessed configuration.

## Next template families

The checklist still reserves future templates for:

- Retail Store;
- R&D Laboratory;
- Secure Management Network;
- IP-KVM Management Network;
- Custom guided design.

They should be added only when their user questions and policy assumptions are clear enough to explain deterministically.
