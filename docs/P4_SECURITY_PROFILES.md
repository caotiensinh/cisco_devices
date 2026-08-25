# P4 Security Profile Engine

## Status

The first security-profile engine is implemented as **offline policy expansion only**.

It does not generate Cisco CLI and does not gain device write authority.

```text
SecurityProfile
  -> versioned SecurityProfileDefinition
  -> explainable SecurityRuleDefinition[]
  -> exact DeviceProfile capability check
  -> warnings / BLOCKED findings
  -> future planner input
```

## Built-in profiles

Initial versioned profiles:

```text
LAB@1.0.0
BASIC@1.0.0
BUSINESS_STANDARD@1.0.0
STRICT@1.0.0
```

`CUSTOM` intentionally has no built-in definition. A custom profile must be explicitly modeled rather than guessed.

## Rule contract

Every rule contains:

```text
rule_id
intent
requirement
severity
risk_class
capability_id
explanation
applicability
```

Requirements:

```text
required
recommended
conditional
```

Risk remains expressed using repository classes such as `W1` and `W2`.

## Initial policy controls

The initial engine models policy for:

- SSH management;
- HTTPS management;
- management-source restriction;
- remote syslog;
- SNMPv3 monitoring;
- IPv4 ACL based segmentation where applicable;
- no-Telnet production policy;
- plaintext HTTP disable-when-safe policy.

The last two are intentionally **policy-only/unmapped** until exact capability/provider syntax is proven. They cannot silently become commands.

## Exact CBS250 profile behavior

For the current exact CBS250-24T-4X / 3.3.0.16 profile:

```text
ssh_management   = documented_and_observed
https_management = documented_not_observed
management_acl   = documented_not_observed
remote_syslog    = documented_not_observed
snmpv3           = documented_not_observed
ipv4_acl         = documented_not_observed
```

Therefore offline design can retain the latter rules as explicit assumptions/warnings, but future live-write precheck must fail closed until required capability is live-proven.

## Offline vs future live-proof mode

### Offline design

```text
require_live_proof = false
```

- `documented_and_observed` -> proven;
- documented but unobserved -> warning;
- policy-only unmapped -> warning;
- unsupported/unknown required control -> blocked.

### Future provider precheck

```text
require_live_proof = true
```

Any mapped capability that is not `documented_and_observed` blocks the dependent rule. Required policy-only/unmapped controls also block until provider capability mapping exists.

This means choosing `STRICT` can never bypass missing evidence.

## Integration with device-aware design workflow

The offline workflow now returns all of these in one result:

```text
Target Device
Template / NetworkIntent
VLAN/IP/Port Design Preview
Capability + Resource Validation
Security Profile Expansion
Overall Result
```

The final output still states:

```text
Device commands generated: NO
No device configuration was generated or executed.
```

## Next work

The next safe P4 layer is a desired-state/diff planner that consumes normalized intent + security rules and produces **typed operations only**.

That planner must still stop before device-specific CLI compilation or execution.
