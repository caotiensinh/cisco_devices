# AI Agent Harness

## Purpose

This harness prevents AI agents and automation agents from drifting outside the product mission, safety boundary, evidence requirements, or current development phase.

`AGENTS.md` is the repository entry point. This document expands the operational contract.

## 1. Agent roles

An agent must declare one primary role per task:

- `ARCHITECT`: architecture, schemas, interfaces, threat/risk model; no device writes.
- `DISCOVERY`: live read-only inventory/capability discovery; no device writes.
- `BACKEND`: deterministic engines, APIs, persistence, tests; no device writes unless task explicitly grants provider write authority.
- `FRONTEND`: UX, visualization, input validation, plans/diffs; no direct device CLI.
- `PROVIDER`: device-specific compiler/provider. Write path remains disabled until an explicitly authorized phase.
- `TEST_RELEASE`: independent validation of exact code/evidence; cannot invent acceptance.
- `SECURITY_GATE`: independent safety/security review; cannot inherit PASS from another role.
- `DOCS`: documentation/knowledge normalization; no device writes.

One agent may perform multiple roles only if the task explicitly says so. Independent acceptance roles must remain logically independent from the implementation claim.

## 2. Task contract

Every meaningful task must define:

```text
TASK_ID
ROLE
OBJECTIVE
IN_SCOPE
OUT_OF_SCOPE
INPUTS
CURRENT_PHASE
DEVICE_WRITE_AUTHORITY
PRODUCTION_NETWORK_WRITE_AUTHORITY
EXPECTED_OUTPUTS
TEST_REQUIREMENTS
STOP_CONDITIONS
HANDOFF_TARGET
```

If authority fields are absent, treat both write authorities as `FALSE`.

## 3. Mandatory task start sequence

Before editing:

1. Read governance and spec documents.
2. Read current phase in `governance/project_scope.json`.
3. Inspect relevant implementation and tests.
4. Inspect exact device/firmware evidence when the task depends on live capability.
5. State assumptions explicitly in task notes.
6. Refuse to infer support from a different Cisco family/model.

## 4. Source-of-truth precedence

For device capability:

1. exact live evidence for exact model/firmware/mode;
2. exact firmware release notes;
3. Cisco CBS250 CLI documentation;
4. Cisco CBS250 administration documentation;
5. Cisco family data sheet;
6. internal inference only when clearly labeled and never used as write authority.

For product behavior:

1. `AGENTS.md` / `governance/project_scope.json` safety boundary;
2. `docs/PRODUCT_SPEC.md`;
3. `docs/IMPLEMENTATION_CHECKLIST.md`;
4. architecture/feature documents;
5. code/tests.

A test that contradicts the spec does not silently redefine the spec.

## 5. AI containment rule

LLMs may:

- interpret natural-language user intent;
- explain networking concepts;
- propose a normalized intent structure;
- recommend a template;
- explain validation failures;
- summarize a deterministic plan.

LLMs must not be final authority for:

- subnet arithmetic;
- VLAN ranges;
- duplicate/overlap detection;
- gateway validity;
- device resource limits;
- management lockout determination;
- command syntax availability;
- command ordering;
- whether a write is safe;
- whether persistence is allowed.

Those decisions must come from deterministic code plus live capability evidence.

## 6. Command execution containment

The system must contain device command execution behind a single provider/executor boundary.

Forbidden architecture:

```text
Frontend -> raw CLI
LLM -> raw CLI -> SSH
Template string -> SSH
```

Required architecture:

```text
Frontend/AI
 -> Intent DTO
 -> Validator
 -> Desired State
 -> Planner
 -> Typed Operations
 -> Device Compiler
 -> Safety Gate
 -> Executor
```

The executor must reject free-form command strings from untrusted layers.

## 7. Safety gates for future writes

A write-capable task is blocked unless all are true:

- exact model and firmware identified;
- capability state is `documented_and_observed` or equivalently reviewed;
- current state snapshot exists;
- desired state validates;
- diff exists;
- operation risk class exists;
- management lockout check passes;
- rollback/recovery strategy exists when required;
- user/owner approval exists for W1/W2;
- executor is operating under explicit write authority;
- verification commands are defined before apply;
- persistence happens only after verification.

## 8. High-risk protected domains

The following areas require dedicated tests and explicit review:

- management VLAN/IP;
- management ACL;
- SSH/HTTPS/Telnet management plane;
- AAA/RADIUS/local accounts;
- trunk/native VLAN;
- STP root/port behavior;
- LAG membership;
- routing/default route;
- ACL/firewall-like segmentation;
- 802.1X/port security;
- PoE power changes;
- firmware/image/boot state;
- configuration persistence;
- logging/evidence deletion.

## 9. Evidence contract

Every validation or future execution must emit machine-readable evidence containing at least:

```json
{
  "task_id": "...",
  "device_fingerprint": {},
  "source_revision": "...",
  "intent_hash": "...",
  "plan_hash": "...",
  "risk_classes": [],
  "pre_state_refs": [],
  "operations": [],
  "verification": [],
  "post_state_refs": [],
  "persisted": false,
  "result": "PASS|FAIL|DEFERRED|BLOCKED"
}
```

No password, token, private key, SNMP secret, RADIUS secret, or reusable credential may appear in evidence.

## 10. Stop conditions

An agent must stop and report `BLOCKED` or `DEFERRED` rather than improvising when:

- exact capability is unknown;
- device mode is uncertain;
- live evidence conflicts with documentation;
- management connectivity could be lost and no recovery path exists;
- a test requires destructive production behavior;
- credentials/authority are unavailable;
- a requested feature is outside the current product spec;
- a change would require bypassing deterministic validation;
- the only way to proceed is to fabricate evidence.

## 11. Change discipline

Each coherent change must:

- be scoped to one objective;
- preserve backward safety invariants;
- add regression coverage;
- update docs if contracts change;
- not quietly expand write authority;
- not mark checklist items complete without evidence.

## 12. Phase promotion

The project may move to a later phase only when all exit criteria for the current phase in `docs/IMPLEMENTATION_CHECKLIST.md` are satisfied.

Promoting a phase that enables device writes requires explicit HUMAN OWNER approval and an update to `governance/project_scope.json` in the same coherent change set.
