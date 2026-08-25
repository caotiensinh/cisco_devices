# Product Specification — Cisco Network Configuration Assistant

## 1. Status

- Initial target: Cisco Business CBS250
- Current implementation phase: knowledge + safe discovery
- Device write authority: disabled until explicitly promoted by governance
- Product model: intent-driven, deterministic validation, provider-specific compilation

## 2. Product goals

### G1 — Reduce configuration complexity

A user with basic networking knowledge should be able to build a valid CBS250 design without memorizing the CBS250 CLI.

### G2 — Automate repetitive reasoning

The product must deterministically calculate repetitive network details such as sequential VLAN IDs, subnets, gateways, usable ranges, trunk membership and validation results.

### G3 — Preserve expert visibility

The system must always expose the resulting design, assumptions, impact, warnings and exact planned changes.

### G4 — Prevent common high-impact mistakes

The product must detect and block invalid/unsafe plans including overlap, duplicates, invalid gateways, unsupported capability and likely management lockout.

### G5 — Be explainable and auditable

Every plan and future execution must be reproducible from normalized input and produce evidence.

## 3. Non-goals for initial product

- fully autonomous network architecture decisions for complex enterprise networks;
- arbitrary natural-language-to-CLI execution;
- automatic firmware changes;
- factory reset/destructive lifecycle automation;
- treating Cisco IOS/IOS-XE syntax as CBS250 syntax;
- multi-vendor support before the provider abstraction is proven with CBS250.

## 4. Primary user journeys

### UJ1 — Connect and inspect

1. User enters switch address, username and password/session credential.
2. System establishes secure management session.
3. System identifies exact model and firmware.
4. System checks known capability data/live capability.
5. System displays device summary and current network state.

Acceptance:

- no secret is persisted in plaintext logs/repository;
- wrong credentials fail clearly;
- unsupported model/firmware is identified rather than guessed;
- no configuration is changed during inspection.

### UJ2 — Build from a template

1. User chooses a template.
2. User supplies site-specific parameters.
3. System generates normalized desired state.
4. System validates it.
5. System presents topology/configuration plan.
6. User adjusts if needed.

### UJ3 — Custom sequential VLAN/IP design

Input example:

```text
count = 5
start_vlan_id = 100
vlan_increment = 10
start_network = 10.50.0.0/24
network_increment = next_subnet
gateway_strategy = first_usable
```

Output:

```text
100 -> 10.50.0.0/24 -> 10.50.0.1
110 -> 10.50.1.0/24 -> 10.50.1.1
120 -> 10.50.2.0/24 -> 10.50.2.1
130 -> 10.50.3.0/24 -> 10.50.3.1
140 -> 10.50.4.0/24 -> 10.50.4.1
```

The engine must use IP arithmetic, never string-based address manipulation.

### UJ4 — Port-role assignment

User assigns semantic roles:

```text
Office
Camera
Server
Access Point
Guest AP
Management
Core Uplink
Unused
Custom
```

The system derives access/trunk intent and validates conflicting assignments.

### UJ5 — Security profile

User selects `LAB`, `BASIC`, `BUSINESS_STANDARD`, `STRICT`, or custom.

The system expands the profile into normalized security requirements, checks exact device capability and shows every resulting recommendation/change.

### UJ6 — Dry run

Before any write:

```text
CURRENT STATE
DESIRED STATE
DIFF
RISK
DEPENDENCIES
MANAGEMENT IMPACT
VERIFICATION PLAN
```

must be visible.

### UJ7 — Controlled apply (future authorized phase)

Only after write authority exists:

1. snapshot;
2. precheck;
3. explicit approval;
4. apply small coherent step;
5. verify;
6. continue/stop;
7. final verify;
8. persist only after PASS;
9. audit evidence.

## 5. Functional architecture

```text
Frontend
  -> API/Orchestrator
      -> Credential Session Manager
      -> Device Discovery
      -> Capability Registry
      -> Current-State Collector
      -> Network Intent Engine
      -> IPAM/Subnet Engine
      -> Topology Validator
      -> Security Profile Engine
      -> Template Engine
      -> Desired-State Builder
      -> Diff/Planner
      -> Provider Compiler
      -> Safety Gate
      -> Transaction Executor (future gated)
      -> Verifier
      -> Evidence Store
```

## 6. Normalized data model

### 6.1 DeviceFingerprint

Minimum fields:

```json
{
  "vendor": "Cisco",
  "family": "CBS250",
  "product_id": "CBS250-24T-4X",
  "firmware_version": "...",
  "management_protocol": "ssh",
  "capability_dataset": "..."
}
```

Sensitive identifiers may be stored only in private operational inventory, not public knowledge files.

### 6.2 NetworkIntent

Minimum conceptual fields:

```json
{
  "site_name": "...",
  "template": "custom",
  "vlans": [],
  "port_roles": [],
  "uplinks": [],
  "routing_intent": {},
  "segmentation_intent": {},
  "management_intent": {},
  "security_profile": "BUSINESS_STANDARD"
}
```

### 6.3 VLANIntent

```json
{
  "id": 100,
  "name": "OFFICE",
  "network": "10.50.0.0/24",
  "gateway": "10.50.0.1",
  "purpose": "office"
}
```

### 6.4 PortIntent

```json
{
  "interface": "GigabitEthernet1",
  "role": "camera",
  "mode": "access",
  "access_vlan": 120,
  "allowed_vlans": []
}
```

### 6.5 SecurityIntent

Conceptual fields include:

- management services;
- management source networks;
- management VLAN;
- segmentation rules;
- logging requirements;
- SNMP policy;
- port security policy;
- storm-control policy;
- edge/STP policy;
- authentication policy where applicable.

## 7. Deterministic IPAM requirements

The IPAM engine must support:

- IPv4 CIDR parsing;
- network/broadcast calculation;
- first/last usable address;
- arbitrary valid prefix lengths in supported product scope;
- next subnet calculation;
- sequential N-network generation;
- configurable VLAN-ID increments;
- gateway strategy: explicit / first usable / last usable;
- duplicate network detection;
- overlapping subnet detection;
- duplicate gateway detection;
- gateway inside subnet validation;
- network/broadcast address rejection for gateway;
- exhaustion/overflow detection;
- reserved/range policy hooks.

All calculations must have unit tests and property/edge-case tests.

## 8. VLAN planner requirements

Must validate:

- valid VLAN range from capability data;
- duplicate VLAN IDs;
- reserved/unsupported IDs where applicable;
- maximum supported active VLAN count;
- unique or policy-valid names;
- VLAN references from ports/uplinks exist;
- management VLAN safety constraints.

## 9. Port planner requirements

Must:

- discover exact physical/logical interfaces;
- reject nonexistent interfaces;
- prevent incompatible simultaneous role assignments;
- differentiate access/trunk/uplink intent;
- validate allowed/native/access VLAN relationships;
- detect loss of required VLAN on uplink;
- identify current management-path dependency;
- support semantic role groups and bulk assignment.

## 10. Security profile requirements

Profiles must be versioned, inspectable data models.

A profile may recommend/require behaviors, but must not silently generate unsupported configuration.

Each expanded rule must carry:

```text
rule_id
intent
severity
required/recommended
capability_state
risk_class
planned_operation(s)
explanation
```

`BUSINESS_STANDARD` is intended as the primary production default after it is validated against supported device capabilities.

## 11. Template requirements

Templates must contain normalized intent defaults, not raw CLI.

Minimum initial templates:

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

Templates must be parameterizable and versioned.

## 12. Capability registry requirements

Every semantic feature used by the planner/provider must have a capability state:

```text
documented_and_observed
documented_not_observed
observed_not_yet_mapped
not_applicable_or_unsupported
blocked_by_privilege
blocked_by_mode
unknown_due_to_crawl_limit
```

Unknown/unsupported state must block writes depending on that capability.

## 13. Planner and diff requirements

The planner must compare current state and desired state and emit typed operations such as conceptual:

```text
CreateVlan
UpdateVlanName
CreateL3Interface
AssignAccessPort
ConfigureTrunk
AddAllowedVlan
SetManagementPolicy
ConfigureLogging
ApplySecurityRule
```

Each operation includes:

- stable operation ID;
- dependencies;
- risk class;
- before state;
- desired state;
- verification method;
- rollback metadata where applicable.

The planner must be idempotent: compliant desired state produces zero-change operations.

## 14. Provider compiler requirements

The CBS250 provider converts typed operations into exact device-specific commands only after:

- exact device/firmware is known;
- required capability is verified;
- operation validates;
- write authority exists.

Compiler output alone does not imply authorization to execute.

## 15. Management lockout protection

Any operation affecting management path is protected.

The lockout engine must consider at least:

- current management source IP/network;
- management VLAN;
- management interface/port/uplink;
- management ACL;
- SSH/HTTPS availability;
- AAA/local account path;
- routing/default gateway dependency;
- trunk/native VLAN dependency.

If continued access cannot be proven, plan status is `BLOCKED` unless an explicitly approved recovery path exists.

## 16. Transaction executor requirements

Future executor must:

- accept typed authorized operations only;
- never accept arbitrary UI/LLM raw CLI;
- snapshot before writes;
- enforce dependency order;
- apply small coherent steps;
- verify each step;
- stop on failure;
- avoid persistence after failed verification;
- support explicit rollback where a validated rollback path exists;
- create audit evidence.

Destructive class `D` operations remain outside normal autonomous configuration workflow.

## 17. Persistence semantics

Desired workflow:

```text
apply to running state
-> verify
-> final verify
-> persist startup configuration
```

Persistence must be a distinct operation and recorded in evidence.

## 18. Frontend requirements

### Beginner mode

Must use guided concepts and visual port roles instead of CLI terminology where possible.

### Expert mode

Must expose detailed network parameters while retaining deterministic validation and safety gates.

Both modes use the same backend intent model.

Frontend must provide:

- connection state;
- exact device identity;
- capability warnings;
- template selection;
- custom VLAN/IP generator;
- visual port map;
- validation panel;
- security profile selection;
- plan/diff view;
- impact/risk view;
- apply state only when authorized;
- evidence/export view.

## 19. Credentials and secrets

- passwords must not be stored in Git;
- credentials must not appear in logs/evidence;
- UI must mask secrets;
- backend should use session-scoped secret handling;
- future persistent credential storage requires a separate secure secret-management design.

## 20. Non-functional requirements

### Safety

Fail closed on uncertainty.

### Determinism

Network calculations, validation, planning and command compilation must be deterministic and testable.

### Explainability

Every warning/block must explain why and how to resolve it.

### Auditability

Plans/evidence need stable hashes/revisions.

### Idempotency

Repeated plan/apply against compliant state should result in no additional configuration changes.

### Compatibility

Do not assume compatibility across model/firmware families.

### Recoverability

High-impact writes require an explicit recovery strategy.

## 21. MVP definition

The first useful MVP is intentionally read-only/planning-first:

1. connect to CBS250;
2. identify model/firmware;
3. collect read-only state;
4. create network intent;
5. generate sequential VLAN/subnet design;
6. validate VLAN/IP/ports;
7. choose a template/security profile;
8. compare desired intent against capability/current state;
9. generate a human-readable dry-run plan;
10. export the plan/evidence;
11. perform **no device writes**.

This MVP proves the difficult reasoning and safety layers before execution authority exists.

## 22. Future write-enabled release acceptance

A write-enabled release is not allowed until all relevant checklist gates are complete and independent test/security reviews confirm:

- executor containment;
- management lockout protection;
- snapshot/diff/verify/persist sequencing;
- negative tests;
- failure recovery behavior;
- exact CBS250 live-device evidence;
- no raw LLM/UI command path.
