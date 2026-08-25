---
name: Governed task contract
about: Create a scoped implementation/review task under the project harness
title: "[TASK] "
labels: []
assignees: []
---

## TASK_ID

`<unique-task-id>`

## ROLE

`ARCHITECT | DISCOVERY | BACKEND | FRONTEND | PROVIDER | TEST_RELEASE | SECURITY_GATE | DOCS`

## OBJECTIVE

Describe one concrete outcome.

## IN_SCOPE

- 

## OUT_OF_SCOPE

- 

## INPUTS / DEPENDENCIES

- Exact repository/base SHA:
- Device model/firmware evidence if relevant:
- Source documents/contracts:

## CURRENT_PHASE

Copy from `governance/project_scope.json`.

## DEVICE_WRITE_AUTHORITY

`FALSE` unless explicitly approved by the HUMAN OWNER and current phase permits it.

## PRODUCTION_NETWORK_WRITE_AUTHORITY

`FALSE` unless explicitly approved by the HUMAN OWNER and current phase permits it.

## EXPECTED_OUTPUTS

- 

## TEST_REQUIREMENTS

- Unit tests:
- Negative/safety tests:
- Integration/live evidence if applicable:

## STOP_CONDITIONS

Stop as `BLOCKED` or `DEFERRED` if:

- exact capability is unknown;
- required authority is absent;
- management lockout cannot be excluded;
- only destructive testing could proceed;
- evidence cannot be produced without guessing.

Additional task-specific stop conditions:

- 

## HANDOFF_TARGET

`<role/person/task>`

## ACCEPTANCE EVIDENCE

Do not mark complete without exact tests/evidence and the relevant checklist update.
