# CBS250-24T-4X Firmware 3.5.3.3 — Live Discovery v3.1 Review

## Scope

This document records the normalized review of the CBS250 CLI discovery v3.1 run captured on 2026-08-25. It is evidence for knowledge/capability mapping only. It grants no device write authority and does not promote discovered grammar into the executable read-only collector allowlist by itself.

## Exact live identity

- Product: `CBS250-24T-4X`
- Active firmware: `3.5.3.3`
- Inactive firmware: `3.3.0.16`
- Management protocol used by the discovery run: SSH
- Exact deployment identifiers are intentionally omitted from the public repository record.

The former 3.3.0.16 capability profile remains historical evidence. The current exact-live reference is `knowledge/cbs250/profiles/CBS250-24T-4X_3.5.3.3.json`.

## Safety verdict

The v3.1 disposable-channel design passed the safety review for the supplied evidence:

- investigation-only mode;
- discovered commands were not submitted for execution;
- help queries were not submitted with Enter;
- zero bytes were sent after the literal `?` help marker;
- one disposable channel was used per help query;
- no pager navigation, Enter, or Ctrl+C was sent after a help query;
- no persistent configuration change was observed;
- known v2.1 side-effect signatures were not observed.

Global-configuration help used ephemeral `configure terminal` mode entry. This is a session-mode transition only; it does not authorize submitting discovered configuration commands and does not authorize configuration submode entry.

## Coverage result

The original v3.1.0 summary reported `COMPLETE`, but that label overstates grammar coverage.

Observed counters:

- nodes found: 12,006;
- help queries: 4,698;
- pager events: 4;
- shard queries: 148;
- transport recycles: 39;
- runtime errors: 0.

`--full-safe` sets a minimum node ceiling of 12,000, and the v3.1.0 crawler stops additional recursion/root insertion when `nodes >= max_nodes`. Therefore this run reached the declared node boundary. The normalized coverage status is:

```text
TRUNCATED_AT_MAX_NODES
```

This distinction is important:

- process/runtime completion: PASS;
- safety: PASS;
- runtime errors: 0;
- privileged EXEC root inventory: COMPLETE, 39/39;
- overall deep grammar: PARTIAL due to max-node truncation;
- global-config grammar: PARTIAL due to max-node truncation.

New runs should use `cbs250_cli_discovery_v311.py`, which reports `TRUNCATED_MAX_NODES`, `INCOMPLETE_WITH_ERRORS`, or `COMPLETE_WITHIN_DECLARED_SCOPE` rather than unconditionally reporting `COMPLETE`.

## Privileged EXEC root result

All 39 known privileged EXEC roots were recovered:

```text
boot cbd cd clear clock configure copy crypto debug-mode delete dir disable do
 dot1x errdisable exit green-ethernet help login macro mkdir more no ping pwd
 reload rename renew resume rmdir set show ssh system telnet terminal test
 traceroute write
```

The pagination-sharding strategy therefore solved the v3 root-coverage problem without sending a pager key after `?`.

## Exact live read-only grammar candidates

The following exact syntax was exposed by live context help on firmware 3.5.3.3. These are candidate observations only; they are not executable authority.

| Candidate | Help has terminal `<CR>` | Review state | Intended use |
|---|---:|---|---|
| `show vlan` | yes | READY_FOR_CONTROLLED_LIVE_READ_VALIDATION | VLAN inventory |
| `show interfaces status` | yes | READY_FOR_CONTROLLED_LIVE_READ_VALIDATION | physical/link status |
| `show interfaces switchport` | yes | READY_FOR_CONTROLLED_LIVE_READ_VALIDATION | access/trunk/VLAN state |
| `show spanning-tree` | yes | READY_FOR_CONTROLLED_LIVE_READ_VALIDATION | STP state |
| `show management access-class` | yes | READY_FOR_CONTROLLED_LIVE_READ_VALIDATION | management ACL binding |
| `show management access-list` | yes | READY_FOR_CONTROLLED_LIVE_READ_VALIDATION | management ACL definitions |
| `show logging` | yes | READY_FOR_CONTROLLED_LIVE_READ_VALIDATION | volatile operational logs |
| `show logging file` | yes | READY_FOR_CONTROLLED_LIVE_READ_VALIDATION | persistent operational logs |
| `show running-config brief` | yes | HOLD_SENSITIVE_OUTPUT_REVIEW | configuration snapshot |
| `show lacp` | no | HOLD_REQUIRES_SELECTOR | LAG/LACP state |

### Why `show running-config brief` remains on hold

Live help states that `brief` omits binary data such as SSL and SSH keys, while `detailed` includes such binary data. That statement is not enough to prove that the brief output contains no password hashes, communities, addresses, usernames, AAA material, or other sensitive configuration. A sanitizer/redaction test must exist before this command can become an automated evidence collector.

### Why bare `show lacp` remains on hold

Live help did not expose terminal `<CR>` for bare `show lacp`; it exposed interface/port-channel selectors. The collector must first derive deterministic selectors from observed interfaces rather than guessing them.

## L3 status

No exact `show ip interface` or `show ip route` grammar was proven by the supplied transcript. The only `show ip ...` command present in the evidence is the already approved `show ip ssh`. L3 collector syntax therefore remains unknown and must not be invented from IOS/IOS-XE knowledge.

## Execution boundary after this review

The actual executable read-only allowlist remains exactly:

```text
show ip ssh
show system
show version
```

The candidate list lives in `knowledge/cbs250/r0_candidate_review_3.5.3.3.json`. Promotion requires, per candidate:

1. exact-target controlled live read output;
2. parser fixture and regression tests;
3. secret/evidence-sensitivity review;
4. registry approval;
5. exact `cbs250_safety.READ_ONLY_EXEC_ALLOWLIST` update;
6. Governance and Safety Gate PASS.

Until all six exist, a discovered read-only-looking command remains data, not authority.
