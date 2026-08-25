# Implementation Checklist

This checklist is the execution roadmap and phase gate for the Cisco Network Configuration Assistant.

A checkbox is not complete because code exists. Completion requires implementation + tests + evidence + documentation.

## P0 — Governance and project harness

### P0.1 Governance

- [x] Root `AGENTS.md` exists and defines project-wide boundaries.
- [x] Machine-readable `governance/project_scope.json` exists.
- [x] AI agent harness exists.
- [x] Product vision exists.
- [x] Product specification exists.
- [x] Implementation checklist exists.
- [x] Add CI check that required governance documents exist.
- [ ] Add CI check that `global_device_write_authority=false` cannot be silently changed without a dedicated approval marker/review rule.
- [ ] Add test/lint rule preventing secrets in committed evidence/examples.
- [x] Add task-template contract for agents/issues.

### P0 exit criteria

- [x] Governance CI passes.
- [x] Safety policy tests pass.
- [x] No code path grants device write authority.

---

## P1 — CBS250 knowledge and safe discovery

### P1.1 Cisco official knowledge

- [x] CBS250 official source index.
- [x] Platform/resource baseline.
- [x] Switching/routing services notes.
- [x] Secure operations baseline.
- [x] Observability/lifecycle notes.
- [x] Capability state model.

### P1.2 Live device discovery

- [x] Exact model/firmware inventory collection.
- [x] v3 disposable-channel help discovery.
- [x] v3.1 safe pagination sharding.
- [x] Hard-deny policy for destructive/state-changing execution in discovery tool.
- [x] Read-only execution exact allowlist.
- [x] Progress/checkpoint support.
- [x] Duplicate `do` recursion suppression.
- [ ] Complete v3.1 live run.
- [ ] Confirm complete privileged EXEC root coverage against known 39-command baseline.
- [ ] Analyze every v3.1 error/warning.
- [ ] Normalize v3.1 dataset into `knowledge/cbs250/live/`.
- [ ] Build documented-vs-observed capability diff.
- [x] Add exact firmware-bound capability registry/profile with conservative capability states.
- [ ] Add coverage metrics: observed/documented/unknown/blocked.

### P1.3 Read-only collector syntax

- [ ] Discover/confirm exact syntax for current configuration/state collectors.
- [ ] Running configuration collector reviewed.
- [ ] Startup configuration collector reviewed.
- [ ] Interface/status collector reviewed.
- [ ] VLAN state collector reviewed.
- [ ] STP state collector reviewed.
- [ ] LAG/LACP state collector reviewed.
- [ ] IP/L3 interface collector reviewed.
- [ ] Route state collector reviewed.
- [ ] Management-plane state collector reviewed.
- [ ] Logging state collector reviewed.
- [ ] SNMP state collector reviewed.
- [ ] Time/NTP/SNTP state collector reviewed.

### P1 exit criteria

- [x] Exact target CBS250 capability registry/profile is versioned and exact-identity bound.
- [ ] Read-only collectors have negative/safety tests.
- [ ] No collector changes device configuration.
- [x] Unknown/unproven capability states are represented explicitly and fail closed for future write precheck.

---

## P2 — Read-only inventory and device dashboard

### P2.1 Backend

- [x] Define `DeviceFingerprint` schema.
- [x] Define `DeviceCapability` schema.
- [x] Define `ObservedState` schema.
- [ ] Implement credential-session abstraction.
- [ ] Implement connection/authentication error model.
- [ ] Implement read-only collector orchestration.
- [ ] Normalize collector output.
- [x] Add required collection timestamps/source revision fields to normalized state.
- [ ] Add evidence export.

### P2.2 Frontend

- [ ] Connect-switch screen.
- [ ] Masked credential input.
- [ ] Connection/auth status.
- [ ] Device identity card.
- [ ] Firmware/capability warning panel.
- [ ] 24xGE + 4x10G visual port map for applicable model.
- [ ] Current VLAN summary.
- [ ] Current port state summary.
- [ ] Current management state summary.
- [ ] Current routing summary.
- [ ] Logging/health summary.

### P2.3 Tests

- [ ] Wrong password.
- [ ] SSH unreachable.
- [x] Exact profile/product/firmware mismatch validation.
- [ ] Unsupported/unknown product discovery behavior.
- [ ] Unsupported/unknown firmware discovery behavior.
- [ ] Partial collector failure.
- [ ] No-secret logging test.
- [x] Offline intent/profile core cannot import device/network execution libraries.

### P2 exit criteria

- [ ] User can connect and inspect without any write.
- [ ] Exact device/firmware shown in product UI/API.
- [ ] Collector failures are explicit, not hidden.

---

## P3 — Network Intent + deterministic IPAM/VLAN engine

### P3.1 Schemas

- [x] `NetworkIntent` schema.
- [x] `VLANIntent` schema.
- [x] `PortIntent` schema.
- [x] `UplinkIntent` schema.
- [x] `RoutingIntent` schema.
- [x] `SegmentationIntent` / `SegmentationRule` schema.
- [x] `ManagementIntent` schema.
- [x] `SecurityIntent` schema.

### P3.2 IPv4/IPAM engine

- [x] CIDR parser.
- [x] Netmask conversion.
- [x] Network address calculation.
- [x] Broadcast calculation.
- [x] First/last usable calculation.
- [x] Gateway strategy: explicit.
- [x] Gateway strategy: first usable.
- [x] Gateway strategy: last usable.
- [x] Sequential subnet generation.
- [x] Cross-octet progression.
- [x] Prefix-size aware progression.
- [x] Duplicate detection.
- [x] Overlap detection.
- [x] Gateway-in-subnet validation.
- [x] Reject gateway=network address.
- [x] Reject gateway=broadcast address where applicable.
- [x] Overflow/exhaustion errors.
- [x] Unit tests for /30-/16 representative ranges.
- [ ] Broader randomized/property tests.

### P3.3 VLAN generator

- [x] Start VLAN ID.
- [x] Count.
- [x] Increment.
- [x] Naming pattern.
- [x] Duplicate prevention.
- [x] Capability-profile-bound VLAN range.
- [x] Capability-profile-bound max active VLAN count.
- [x] Sequential VLAN + subnet combined generator.

### P3.4 Intent validation

- [x] VLAN references exist.
- [x] Declared port/uplink can be checked against `ObservedState` interfaces.
- [x] Duplicate physical-interface/role assignment conflict detection.
- [x] Trunk/access semantic validation.
- [x] Uplink includes required access/management VLANs.
- [x] Management intent completeness checks.
- [x] Human-readable validation codes/messages/remediation.
- [x] Exact profile fingerprint mismatch blocks validation.
- [x] Physical port capacity validation.
- [x] Active VLAN resource validation.
- [x] Routed IP-interface resource validation.
- [x] Offline design distinguishes documented capability from live-proven capability.
- [x] Future write precheck fails closed when required capability is not `documented_and_observed`.

### P3 exit criteria

- [ ] User can build every selected MVP design through a stable external API/UI.
- [ ] Broader IPAM property/boundary test suite complete.
- [x] No device CLI generation or device access is required for P3 validation.

---

## P4 — Templates, security profiles, desired-state planner

### P4.1 Template framework

- [ ] Versioned template schema.
- [ ] Template parameters.
- [ ] Template preview.
- [ ] Template migration/versioning rules.
- [ ] Small Office.
- [ ] Office + Guest Wi-Fi.
- [ ] Office + IP Cameras.
- [ ] Camera + VMS.
- [ ] AI Camera / AI Server.
- [ ] Retail Store.
- [ ] R&D Laboratory.
- [ ] Secure Management Network.
- [ ] IP-KVM Management Network.
- [ ] Custom.

### P4.2 Security profiles

- [ ] Versioned security-profile schema.
- [ ] LAB profile.
- [ ] BASIC profile.
- [ ] BUSINESS_STANDARD profile.
- [ ] STRICT profile.
- [ ] Each rule has explanation/severity/capability/risk.
- [ ] Exact capability validation for expanded security rules.
- [ ] Unsupported rule blocks or clearly degrades according to policy.

### P4.3 Planner

- [ ] Current-state to desired-state diff.
- [ ] Stable typed operation IDs.
- [ ] Operation dependency graph.
- [ ] Risk class per operation.
- [ ] Verification method per operation.
- [ ] Idempotency test: compliant state => zero changes.
- [ ] Human-readable plan.
- [ ] Machine-readable plan.
- [ ] Stable plan hash.

### P4.4 Dry run UX

- [ ] Current state view.
- [ ] Desired state view.
- [ ] Add/change/remove distinction.
- [ ] Risk summary.
- [ ] Capability warnings.
- [ ] Management-impact summary.
- [ ] Export plan.

### P4 exit criteria

- [ ] Templates compile to normalized intent, never raw CLI.
- [ ] Security profiles compile to normalized rules, never raw CLI.
- [ ] Dry-run plan can be fully generated with write authority still FALSE.

---

## P5 — CBS250 provider/compiler (NO EXECUTION first)

### P5.1 Typed operations

- [ ] `CreateVlan`.
- [ ] `UpdateVlan`.
- [ ] `ConfigureL3Interface` where exact capability exists.
- [ ] `AssignAccessPort`.
- [ ] `ConfigureTrunk`.
- [ ] `SetAllowedVlans`.
- [ ] `ConfigureManagementPolicy`.
- [ ] `ConfigureLogging`.
- [ ] Security operations required by selected profiles.

### P5.2 Compiler

- [ ] Exact CBS250 syntax from exact capability registry.
- [ ] Firmware-binding tests.
- [ ] Command ordering tests.
- [ ] Unknown capability hard-block.
- [ ] Placeholder substitution validation.
- [ ] Free-form command input rejected.
- [ ] LLM output cannot enter compiler as raw CLI.

### P5.3 Golden tests

- [ ] Intent -> desired state.
- [ ] Desired state + current state -> operations.
- [ ] Operations -> expected CBS250 command plan.
- [ ] No SSH/device execution in compiler tests.

### P5 exit criteria

- [ ] Deterministic compile-only provider complete for selected MVP features.
- [ ] Device write authority remains FALSE.

---

## P6 — Safety gate, lockout protection, transaction engine

**This phase requires explicit HUMAN OWNER approval before enabling live writes.**

### P6.1 Management lockout engine

- [ ] Determine current management source path.
- [ ] Determine management VLAN dependency.
- [ ] Determine management port/uplink dependency.
- [ ] Determine SSH/HTTPS dependency.
- [ ] Determine management ACL dependency.
- [ ] Determine routing/default gateway dependency.
- [ ] Determine AAA/local credential dependency.
- [ ] Block unsafe plan.
- [ ] Recovery-path model.
- [ ] Negative tests for self-lockout.

### P6.2 Snapshot

- [ ] Pre-change running configuration evidence.
- [ ] Pre-change startup configuration evidence.
- [ ] VLAN/interface/routing/security state evidence.
- [ ] Snapshot hash.

### P6.3 Executor containment

- [ ] Executor only accepts typed authorized operations.
- [ ] Raw CLI API not exposed to frontend.
- [ ] Raw CLI API not exposed to LLM layer.
- [ ] Per-operation authority checks.
- [ ] W1/W2 explicit confirmation.
- [ ] D blocked from normal workflow.

### P6.4 Transaction

- [ ] Precheck.
- [ ] Apply one coherent step.
- [ ] Verify step.
- [ ] Stop on verify failure.
- [ ] Dependency-aware continuation.
- [ ] Final verify.
- [ ] Explicit persist operation.
- [ ] Post snapshot.
- [ ] Audit evidence.

### P6.5 Failure tests

- [ ] SSH disconnect mid-plan.
- [ ] Command rejected.
- [ ] Unexpected prompt.
- [ ] Verification mismatch.
- [ ] Management-path risk discovered late.
- [ ] Partial apply.
- [ ] Persist failure.
- [ ] Reconnect/reconcile current state.

### P6 exit criteria

- [ ] Independent TEST_RELEASE PASS.
- [ ] Independent SECURITY_GATE PASS.
- [ ] Exact physical CBS250 evidence.
- [ ] Write authority enabled only for explicitly accepted feature set.

---

## P7 — Beginner/Expert product UX

### P7.1 Beginner mode

- [ ] Guided setup wizard.
- [ ] Plain-language network-purpose questions.
- [ ] Template recommendations.
- [ ] Sequential VLAN/IP generator.
- [ ] Visual switch/port assignment.
- [ ] Security profile explanation.
- [ ] Validation score/status.
- [ ] Warnings with remediation steps.
- [ ] Plan confirmation.

### P7.2 Expert mode

- [ ] Direct VLAN/CIDR editing.
- [ ] Tagged/untagged/native VLAN controls.
- [ ] LAG controls.
- [ ] STP controls for supported scope.
- [ ] ACL/segmentation controls for supported scope.
- [ ] QoS controls for supported scope.
- [ ] Advanced management/security controls.
- [ ] Same validators/safety gates as beginner mode.

### P7 exit criteria

- [ ] Beginner can complete common deployment without CLI knowledge.
- [ ] Expert can inspect/override advanced intent without bypassing safety.

---

## P8 — Operational readiness

- [ ] Installer/package strategy.
- [ ] Windows target packaging.
- [ ] Ubuntu target packaging if required.
- [ ] Local database/config storage design.
- [ ] Secret-management design.
- [ ] Backup/export/import.
- [ ] Audit log retention.
- [ ] Offline planning mode.
- [ ] Versioned migrations.
- [ ] Support bundle generation.
- [ ] User documentation.
- [ ] Recovery documentation.
- [ ] Security hardening review.
- [ ] Performance/load tests.
- [ ] Upgrade/rollback strategy for the application.

---

## P9 — Additional device families (future)

Only after CBS250 provider contracts are stable:

- [ ] Define provider SDK/interface.
- [ ] Separate capability registry per family/model/firmware.
- [ ] CBS350 evaluation.
- [ ] Other Cisco family evaluation.
- [ ] Multi-vendor feasibility.
- [ ] Never reuse CBS250 commands by assumption.

---

# Cross-cutting release gates

Every release candidate must answer:

- [ ] What exact spec requirements changed?
- [ ] What exact tests prove them?
- [ ] What negative/safety tests exist?
- [ ] What exact model/firmware evidence applies?
- [ ] What remains unsupported/unknown?
- [ ] Does this release change device write authority?
- [ ] Can UI/AI bypass typed planner/executor boundaries?
- [ ] Are credentials absent from evidence/logs?
- [ ] Is management lockout possible?
- [ ] Is persistence separated from verification?
- [ ] Is rollback/recovery documented where required?

If any required answer is unknown, release status is `DEFERRED` or `BLOCKED`, not fabricated PASS.
