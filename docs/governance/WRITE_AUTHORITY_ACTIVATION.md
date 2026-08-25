# Write Authority Activation Contract

## Purpose

Changing `global_device_write_authority` or `production_network_write_authority` in `governance/project_scope.json` is **not sufficient** to authorize a device write.

The repository intentionally requires a second, explicit governance artifact before CI accepts any enabled write authority.

## Current state

```text
global_device_write_authority = false
production_network_write_authority = false
approval marker = MUST NOT EXIST
```

A stale approval marker is forbidden while write authority is disabled.

## Future activation prerequisites

Write authority may be considered only in a phase whose name begins with `P6_` and only after the relevant P6 safety gates are complete.

When either write-authority flag becomes `true`, the same change set must add:

```text
governance/write_authority_approval.json
```

The marker is scoped approval evidence, not a reusable master switch.

Minimum required marker shape:

```json
{
  "schema_version": 1,
  "approved": true,
  "human_owner_approval_reference": "<explicit-reference>",
  "target": {
    "vendor": "Cisco",
    "family": "CBS250",
    "product_id": "<exact-product-id>",
    "firmware_version": "<exact-firmware>"
  },
  "allowed_operations": [
    "<typed-operation-name>"
  ],
  "test_release": {
    "verdict": "PASS",
    "reference": "<independent-test-release-evidence>"
  },
  "security_gate": {
    "verdict": "PASS",
    "reference": "<independent-security-gate-evidence>"
  },
  "production_network_write_approved": false
}
```

## CI rules

CI must reject activation when any of the following is true:

- phase is not a `P6_...` phase;
- approval marker is missing;
- `approved` is not `true`;
- human owner approval reference is empty;
- target model or firmware is wildcard/empty;
- `allowed_operations` is empty or contains `*`/`ALL`;
- TEST_RELEASE verdict/reference is missing or not PASS;
- SECURITY_GATE verdict/reference is missing or not PASS;
- production write authority is enabled while `production_network_write_approved` is not explicitly true;
- marker attempts to authorize destructive class `D` as a general capability.

## Scope rule

Approval is limited to the exact typed operations and exact target identity in the marker.

It does not authorize:

- arbitrary CLI;
- newly discovered commands;
- another firmware version;
- another switch family;
- destructive cleanup;
- firmware/image changes;
- factory reset;
- implicit deletion.

A provider/executor must still enforce per-operation capability, plan, diff, lockout, snapshot, verification and audit contracts.

## Revocation

When write authority is returned to `false`, the approval marker must be removed in the same governance state. CI rejects a dormant marker because stale approval must not survive as latent authority.

## Security limitation

This repository marker cannot cryptographically prove that a human review happened. Its purpose is defense-in-depth against accidental/silent authority changes and to make required review evidence machine-checkable. Branch protection and independent review remain required operational controls for a future write-enabled release.
