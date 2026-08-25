# Product Vision — Cisco Network Configuration Assistant

## 1. Product idea

Build a practical assistant for Cisco Business networks that allows a technician to describe the network they need in business/networking concepts rather than memorizing hundreds of device-specific CLI commands.

The product converts intent into a validated design, checks that design against the exact live switch capability, produces a human-readable plan, and eventually applies approved changes through a controlled transaction engine.

The core idea is:

```text
NETWORK INTENT
  -> VALIDATED NETWORK DESIGN
  -> DEVICE-SPECIFIC CONFIGURATION PLAN
```

not:

```text
USER TEXT -> AI-GENERATED CLI -> SWITCH
```

## 2. Practical problem

Cisco Business switches are powerful but configuration quality depends heavily on operator knowledge. A technician may understand VLANs, IP addresses, gateways, access/trunk concepts and basic security, yet still spend substantial time:

- calculating subnets;
- creating repetitive VLAN structures;
- assigning ports consistently;
- remembering device-specific syntax;
- checking whether a feature exists on the exact model/firmware;
- avoiding overlapping networks;
- preventing management lockout;
- building a secure baseline;
- checking the final state;
- preserving evidence/backups.

The product should compress hours of repetitive, error-prone work into a guided workflow that still exposes the final design and consequences to the operator.

## 3. Primary practical objective

A technician with basic networking competence should be able to configure a good-quality CBS250 network without needing to memorize the CBS250 CLI.

The software should calculate and validate the technical details that can be deterministic, while keeping high-impact decisions visible to the human.

Example user input:

```text
I need 5 VLANs.
Start VLAN ID: 100
Start subnet: 10.50.0.0/24
Gateway: first usable address
VLAN increment: 10
Subnet increment: next /24
Security profile: Business Standard
Ports 1-8: Office
Ports 9-20: Cameras
Ports 21-24: Servers
XG1: Core uplink
```

Expected system output:

```text
VLAN 100 -> 10.50.0.0/24 -> GW 10.50.0.1
VLAN 110 -> 10.50.1.0/24 -> GW 10.50.1.1
VLAN 120 -> 10.50.2.0/24 -> GW 10.50.2.1
VLAN 130 -> 10.50.3.0/24 -> GW 10.50.3.1
VLAN 140 -> 10.50.4.0/24 -> GW 10.50.4.1
```

The system then validates capacity, overlap, gateway correctness, port roles, trunk membership, security policy, management reachability and exact device capability.

## 4. Target users

### Primary user: junior field/network technician

Knowledge level:

- understands what a VLAN is;
- understands IP address, subnet, gateway;
- understands access vs trunk at a basic level;
- can identify endpoint roles such as PC, camera, AP, server and uplink;
- does not need deep CBS250 CLI knowledge.

Goal:

- deploy a correct and repeatable small/medium network safely and quickly.

### Secondary user: experienced network technician/engineer

Needs:

- faster repetitive configuration;
- deterministic IP/VLAN planning;
- reusable templates;
- exact device capability awareness;
- dry-run/diff;
- audit evidence;
- advanced custom mode without losing safety controls.

### Secondary user: IT support / system integrator

Typical environment:

- retail branch;
- office;
- camera/VMS installation;
- AI edge server deployment;
- Wi-Fi/guest network;
- small factory;
- R&D lab;
- IP-KVM/management network.

Goal:

- standardize branch deployments even when every technician has a different skill level.

### Reviewer/manager

Needs:

- see what will change before deployment;
- compare intended vs current state;
- verify compliance with a company security profile;
- export evidence and audit history.

## 5. What the product should make easy

The user should be able to select or describe:

- number of VLANs;
- starting VLAN ID and increment;
- starting subnet and subnet progression;
- gateway strategy;
- network purpose/role;
- port roles;
- uplinks/trunks;
- allowed VLANs;
- segmentation relationships;
- security level;
- monitoring/logging profile;
- optional advanced parameters.

The software should automatically derive:

- VLAN IDs;
- CIDRs and masks;
- usable ranges;
- gateway addresses;
- broadcast/network addresses;
- duplicate/overlap detection;
- trunk VLAN membership;
- access-port assignments;
- high-level ACL/segmentation intent;
- security recommendations;
- configuration ordering;
- device-specific plan;
- verification plan.

## 6. Configuration templates

Initial templates should include:

- Small Office
- Office + Guest Wi-Fi
- Office + IP Cameras
- Camera + VMS
- AI Camera / AI Server
- Retail Store
- R&D Laboratory
- Secure Management Network
- IP-KVM Management Network
- Custom

A template is a starting policy/model, not a hard-coded CLI script.

## 7. Security profiles

Initial conceptual profiles:

### LAB

Optimized for temporary/internal testing with visible warnings and minimal production assumptions.

### BASIC

Reasonable minimum controls for a small trusted environment.

### BUSINESS_STANDARD

Recommended default for normal production deployments. Intended areas include secure management, isolated management plane, logging, sensible port protections and segmentation defaults where supported.

### STRICT

More restrictive policy for environments that need stronger segmentation and management restrictions. This profile must never be applied without clear lockout/impact analysis.

Profiles must compile into typed desired-state rules and be validated against exact live capability. They are not bundles of blindly replayed CLI commands.

## 8. User experience principle

The beginner UI asks business/network questions.

Example:

```text
What is connected to ports 9-20?
[ Cameras ]

Should cameras reach the Internet?
[ No ]

Should office PCs reach the camera network?
[ No ]

Which workstation/network may administer the switch?
[ Management network ]
```

The expert UI exposes VLAN, CIDR, tagged/untagged membership, native VLAN, LAG, STP, ACL, QoS and other advanced controls.

Both modes produce the same normalized intent model and pass through the same validators.

## 9. Example practical scenario

A technician installs:

- 20 cameras;
- 3 AI servers;
- 20 office PCs;
- guest Wi-Fi;
- one management laptop/network.

They state:

- cameras must not reach the Internet;
- guests must not reach cameras or servers;
- office PCs may reach selected servers;
- switch administration must be limited to the management network.

The assistant should propose:

- network/VLAN plan;
- IP plan;
- port-role plan;
- segmentation matrix;
- management policy;
- security profile;
- exact-device capability warnings;
- deterministic validation results;
- dry-run change plan.

The user reviews the design before any device write exists.

## 10. Product value

The value is not simply fewer CLI keystrokes.

The product should provide:

- less configuration time;
- lower entry barrier for technicians;
- fewer arithmetic and repetition mistakes;
- consistent company standards;
- safer management-plane changes;
- explainable changes;
- reusable branch templates;
- exact-model/firmware awareness;
- auditability;
- a path from beginner workflows to expert workflows.

## 11. Product boundaries

The assistant is not a substitute for network engineering judgment in complex/high-risk networks.

It must never promise that a template is universally correct. It must identify assumptions, validate exact capability, show impact, and block unsafe or unsupported plans.

The first production target is Cisco Business CBS250. Additional vendors/families may be added later through separate provider/capability modules, not by assuming CLI compatibility.

## 12. Long-term direction

The architecture should allow the product to evolve from a CBS250 assistant into a broader intent-driven network deployment platform while preserving the same central model:

```text
Intent -> Validation -> Desired State -> Provider Plan -> Controlled Execution -> Verification
```
