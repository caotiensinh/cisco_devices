# AGENTS.md — Project-Wide AI/Automation Governance

This file is the mandatory entry point for every AI agent, automation agent, developer agent, reviewer, or code-generation system working in this repository.

## 1. Product mission

Build a safe Cisco network configuration assistant that converts user intent into a validated network design and, only after explicit safety gates are satisfied, into device-specific configuration for supported Cisco Business switches.

The product is **not** a raw CLI command generator.

Canonical flow:

```text
USER INTENT
  -> NORMALIZED NETWORK MODEL
  -> STATIC VALIDATION
  -> LIVE DEVICE CAPABILITY CHECK
  -> CONFIGURATION PLAN
  -> DRY RUN / DIFF
  -> SAFETY REVIEW
  -> APPLY SMALL CHANGE SETS
  -> VERIFY
  -> PERSIST ONLY AFTER VERIFY
  -> AUDIT EVIDENCE
```

## 2. Mandatory pre-read

Before changing code or architecture, read:

1. `AGENTS.md`
2. `docs/PRODUCT_VISION.md`
3. `docs/PRODUCT_SPEC.md`
4. `docs/IMPLEMENTATION_CHECKLIST.md`
5. `docs/governance/AI_AGENT_HARNESS.md`
6. `governance/project_scope.json`
7. `docs/CBS250/discovery_safety_v3.md`
8. `docs/CBS250/automation_capability_model.md`
9. relevant Cisco knowledge/evidence under `docs/CBS250/` and `knowledge/cbs250/`

If these documents conflict, the stricter safety rule wins unless the HUMAN OWNER explicitly updates the governing documents.

## 3. Current authority boundary

Current repository write authority applies to source code and documentation only.

**Device configuration/write authority is FALSE by default.**

Discovery components may:

- identify a device;
- execute explicitly reviewed read-only inventory commands;
- query context-sensitive CLI help with `?` under the disposable-channel safety model;
- parse/normalize capability data;
- produce evidence and analysis.

Discovery components must not:

- execute discovered commands;
- clear logs/counters/state;
- delete files/configuration;
- reload/reboot a switch;
- alter firmware/image selection;
- write running/startup configuration;
- change VLAN, interface, routing, ACL, STP, QoS, security, management, PoE, AAA, SNMP, syslog, or other device state.

A future write-capable provider must be a separate subsystem and cannot inherit authority from the discovery crawler.

## 4. Product scope guardrails

In scope:

- CBS250 capability knowledge and exact-device discovery;
- read-only inventory and health/status collection;
- network-intent modeling;
- VLAN/IP/subnet/gateway planning;
- deterministic IPAM calculations;
- topology and configuration validation;
- reusable configuration templates;
- security profiles;
- port-role planning;
- deterministic configuration compilation;
- dry-run and human-readable diff;
- safe transactional apply/verify/rollback when that phase is explicitly authorized;
- audit evidence;
- beginner and expert UX.

Out of scope unless explicitly added to the product spec:

- autonomous production network redesign;
- arbitrary AI-generated CLI execution;
- unsupported Cisco product families being treated as equivalent to CBS250;
- undocumented capability invention;
- silent firmware upgrades;
- factory reset or destructive maintenance;
- credential harvesting or storing plaintext secrets in logs/repository;
- bypassing safety gates to make a demo pass.

## 5. AI agent behavioral contract

Every AI agent must:

- distinguish fact, live evidence, Cisco documentation, inference, and proposal;
- never claim a capability is supported only because a similar Cisco platform supports it;
- never convert a discovered command into execution authority;
- never fabricate test results, device output, PASS status, or production readiness;
- fail closed when model/firmware/mode/capability is uncertain;
- preserve deterministic business logic outside the LLM where possible;
- use AI for intent interpretation/explanation, not as the final authority for IP math, safety checks, or CLI validity;
- keep credentials out of repository files, logs, test fixtures, examples, and evidence;
- make the smallest coherent change set;
- add/update tests with every behavior change;
- update the implementation checklist when a milestone materially changes.

## 6. Mandatory architecture separation

The repository must preserve these conceptual boundaries:

```text
Discovery/Knowledge
Intent Model
Validation/IPAM
Template Engine
Planner/Diff
Device Provider/Compiler
Transaction Executor
Verifier
Audit/Evidence
Frontend/API
```

No UI component may directly construct and execute raw device CLI.

No LLM response may directly become an executable device command stream.

The execution provider accepts only a typed, validated plan produced by deterministic application code.

## 7. Risk classes

Use the repository risk model:

- `R0`: passive read
- `R1`: active diagnostic
- `R2`: session-local change
- `W1`: reversible configuration
- `W2`: connectivity-impacting configuration
- `D`: destructive/lifecycle operation

Rules:

- R0 may be automated when exact syntax is reviewed and tested.
- R1 requires explicit rate/target safety constraints.
- R2 must be session-scoped and revert automatically.
- W1/W2 require plan, pre-state, validation, explicit authorization, verify, and audit.
- D is never autonomous by default.

## 8. Write transaction contract

When write authority is eventually enabled for a specific task/device, every operation must follow:

```text
DISCOVER
-> SNAPSHOT
-> BUILD DESIRED STATE
-> DIFF
-> STATIC VALIDATE
-> LIVE PRECHECK
-> LOCKOUT/IMPACT CHECK
-> USER/OWNER APPROVAL
-> APPLY SMALL STEP
-> VERIFY STEP
-> CONTINUE OR STOP
-> FINAL VERIFY
-> PERSIST
-> POST-SNAPSHOT
-> AUDIT RECORD
```

If any verification fails, stop. Do not continue blindly and do not persist blindly.

## 9. Management lockout rule

Any planned change touching management VLAN, management IP, management ACL, SSH/HTTPS, AAA/RADIUS, trunk/native VLAN, routing, or the current management port is `W2` until proven otherwise.

The system must block apply if it cannot prove that an authorized management path remains available or that an approved recovery path exists.

## 10. Definition of done

A feature is not done because code exists.

It is done only when:

- spec requirement is identified;
- implementation exists;
- unit tests exist;
- negative/safety tests exist;
- deterministic validation exists where applicable;
- evidence is captured;
- documentation is updated;
- checklist item is updated;
- unsupported/unknown states fail closed.

## 11. Current phase rule

The authoritative current phase and write authority are stored in `governance/project_scope.json`.

Agents must not skip ahead from discovery/planning directly to production writes. Phase advancement requires explicit checklist evidence and an update to the governing scope file.