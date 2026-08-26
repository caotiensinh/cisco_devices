# P1 R0 Live Validation and Promotion Contract

## Purpose

This contract governs the narrow transition from a documented/read-only CBS250 command candidate to a collector-approved command. It does **not** grant device write authority and it does **not** permit generic CLI execution.

Current exact target:

- Product: `CBS250-24T-4X`
- Firmware: `3.5.3.3`
- Current R0 validation candidate: `show vlan`

## Authority separation

Collector/runtime execution authority and temporary validation authority are separate.

```text
READ_ONLY_EXEC_ALLOWLIST
  show version
  show system
  show ip ssh

R0_VALIDATION_EXEC_ALLOWLIST
  show vlan
```

A command in `R0_VALIDATION_EXEC_ALLOWLIST` is **not** collector-approved. The validation lane exists only to obtain exact-live parser evidence for one literal R0 command.

Global device write authority and production network write authority remain `false` throughout this process.

## Required live-validation sequence

The one-shot lane must fail closed in this order:

1. Resolve secret-backed connection credentials without logging their values.
2. Run all offline policy checks and the full test suite before opening SSH.
3. Assert `global_device_write_authority == false` and `production_network_write_authority == false`.
4. Establish the exact target using only already-approved identity commands.
5. Require product `CBS250-24T-4X` and firmware `3.5.3.3`.
6. Execute exactly `show vlan` and no other validation candidate.
7. If output paginates, send no pager navigation and return BLOCKED.
8. Parse the output in memory with `parse_documented_show_vlan`.
9. If parsing fails, return BLOCKED.
10. Export only sanitized schema-v2 evidence and delete temporary local evidence.

No configuration mode, interface mutation, clear/delete operation, reboot/reload, boot/firmware mutation, or startup/running-config write is authorized by this lane.

## Sanitized evidence schema v2

Promotion review accepts only schema v2. The output digest is explicitly a digest of cleaned terminal text, not raw transport bytes.

Required fields include:

```text
schema_version = 2
record_type = R0_LIVE_OUTPUT_VALIDATION
status = PASS_LIVE_PARSER_VALIDATED
command = show vlan
risk_class = R0
normalized_output_sha256 = sha256:<64 lowercase hex>
output_digest_scope = CLEAN_TERMINAL_TEXT_UTF8
raw_output_retained = false
parser = parse_documented_show_vlan
parser_result = PASS
port_membership_exported = false
vlan_names_exported = false
```

The artifact may retain normalized VLAN IDs because they are required to prove that rows were parsed, but it must not export VLAN names or port membership.

Legacy schema-v1 evidence using the field `raw_output_sha256` is not eligible for promotion review because that field historically described a digest of cleaned terminal text rather than raw transport bytes.

## Promotion-review gate

`cisco_assistant.r0_validation_promotion.evaluate_r0_validation_evidence()` is an offline-only fail-closed structural gate. It never connects to a switch and never modifies an allowlist.

A result of:

```text
eligible_for_promotion_review = true
```

means only that the sanitized evidence satisfies this contract. It does **not** promote the command.

The gate must reject at least:

- wrong schema version;
- legacy ambiguous digest fields;
- wrong command/product/firmware;
- parser failure;
- invalid/empty parsed rows or invalid VLAN IDs;
- malformed digest or wrong digest scope;
- retained raw output;
- exported VLAN names or port membership;
- any device/production write authority;
- collector execution authority already granted;
- missing/true side-effect safety flags;
- pager navigation.

## Collector promotion requirements

`show vlan` may be added to `READ_ONLY_EXEC_ALLOWLIST` only after all of the following are independently satisfied:

1. Exact-target schema-v2 live-validation run completed.
2. All pre-SSH policy/tests and no-write gates passed in that same run.
3. Sanitized artifact passes the offline promotion-review gate.
4. Parser behavior and evidence sensitivity are reviewed.
5. Regression coverage proves rejected/malformed/paginated inputs fail closed.
6. An explicit coherent code change promotes only the exact literal command.
7. Governance/Safety CI passes on the promotion successor SHA.

Promotion must remove the command from the temporary validation-only allowlist or otherwise prove there is no ambiguous dual authority.

## Current status

At the time this contract was written:

- `show vlan` remains **validation-only**;
- collector authority remains limited to `show version`, `show system`, and `show ip ssh`;
- no VLAN collector promotion has been claimed;
- live schema-v2 evidence is still required;
- write authority remains false.
