# CBS250 Targeted L3 Context-Help Probe

## Purpose

`cbs250_targeted_help_probe.py` closes narrow Layer-3 grammar gaps on the exact current target without rerunning the full 12,000-node discovery crawl.

Exact target:

- Product: `CBS250-24T-4X`
- Firmware: `3.5.3.3`

This tool is a **context-help probe**, not an L3 state collector.

It does not authorize or execute `show ip interface`, `show ip route`, or `show ip route summary` as commands.

## Safety model

The tool first binds the session to the exact target using only the existing reviewed read-only execution allowlist:

```text
show system
show version
```

If the observed product or firmware differs from `CBS250-24T-4X / 3.5.3.3`, the probe fails closed before any candidate help query is performed.

The only candidate prefixes accepted by the targeted-help policy are:

```text
show ip interface
show ip route
show ip route summary
```

Each candidate is queried as context help on a disposable SSH channel:

```text
show ip interface ?
show ip route ?
show ip route summary ?
```

The literal `?` is sent **without Enter**. After the `?` marker the channel receives zero additional bytes and is then destroyed after output is read.

The probe does not:

- submit the candidate command with CR/LF;
- enter configuration mode;
- execute the full discovery crawler;
- send pager navigation after `?`;
- expand the executable read-only allowlist;
- grant device write authority;
- grant production network write authority.

## Policy self-test

Run without network access:

```powershell
python .\cbs250_targeted_help_probe.py --policy-check
```

This is also mandatory in `.github/workflows/governance-safety.yml`.

## Physical exact-target invocation

On a machine that can reach the switch management address:

```powershell
python .\cbs250_targeted_help_probe.py `
  --host 192.168.11.6 `
  --username admin
```

The SSH password is requested interactively unless supplied through the configured password environment variable. Do not put a password on the command line or in committed files.

By default, output is written under the user's Downloads directory in a timestamped folder:

```text
CBS250_Targeted_L3_Help_<timestamp>/
├── targeted_l3_help_summary.json
└── targeted_l3_help_transcript.txt
```

The transcript is operational evidence and should remain local/private until sensitivity review determines what can be committed.

## Result semantics

The probe intentionally separates **transport/query safety** from **grammar evidence completeness**.

### `PASS_COMPLETE`

Required for every targeted prefix:

- exact target binding passed;
- candidate command was not executed;
- help query was not submitted with Enter;
- bytes sent after `?` = `0`;
- disposable channel closed correctly;
- no query error;
- output was not paginated;
- terminal `<CR>` was observed.

This means the exact 3.5.3.3 device exposed a terminal form for the targeted command prefix under the safe context-help mechanism.

It still does **not** authorize executing that command as a collector.

### `BLOCKED_INCOMPLETE_EVIDENCE`

Safety succeeded, but grammar evidence is incomplete, for example:

- help output paginated; or
- terminal `<CR>` was not observed.

Do not reinterpret this as unsupported. A narrower safe help investigation may still be required.

### `BLOCKED_SAFETY`

One or more mandatory safety invariants were not satisfied, including:

- post-`?` bytes were sent;
- disposable channel close evidence was missing;
- a candidate was recorded as executed;
- a query error occurred;
- one of the expected targeted results was missing.

Do not promote any evidence from that run.

### `BLOCKED_EXCEPTION`

The probe could not complete because exact target binding, transport, authentication, parsing, or another precondition failed.

Again, this does not prove the candidate command is unsupported.

## Sanitized evidence handoff

Only after the probe returns `PASS_COMPLETE`, convert the local summary into a sanitized evidence record:

```powershell
python .\cbs250_targeted_help_evidence_ingest.py `
  --input-summary "C:\path\to\CBS250_Targeted_L3_Help_<timestamp>\targeted_l3_help_summary.json" `
  --output "C:\path\to\targeted_l3_help.sanitized.json"
```

The ingester is offline-only. It validates:

- schema and `PASS_COMPLETE` status;
- exact `CBS250-24T-4X / 3.5.3.3` binding;
- false device/write/candidate-execution authority flags;
- zero bytes after each `?`;
- disposable channel close evidence;
- no pagination;
- terminal `<CR>` for all three prefixes;
- exact expected prefix set.

The sanitized record retains only:

- exact product and firmware;
- targeted help prefixes;
- observed help tokens;
- canonical SHA-256 of the source summary;
- tool version;
- `OBSERVED_HELP_ONLY` evidence status;
- explicit false execution/write/collector-approval authority.

It does not copy the probe's host address, username, SSH fingerprint, raw transcript, credentials, or connection metadata into the sanitized record.

The raw `targeted_l3_help_transcript.txt` remains local/private by default. Do not commit it merely because the sanitized evidence passed.

## What a successful targeted-help run changes

A `PASS_COMPLETE` run plus successful sanitized-evidence ingestion may change the planner-critical capability record from:

```text
DOCUMENTED_NOT_OBSERVED_IN_CURRENT_DATASET
```

to an exact-firmware state equivalent to:

```text
OBSERVED_HELP_ONLY
```

It must **not** change directly to:

```text
LIVE_EXECUTION_VALIDATED
APPROVED_COLLECTOR
READ_ONLY_EXEC_ALLOWLIST
```

Those require a separate controlled R0 live-output validation contract.

## Current L3 boundary

Cisco documentation establishes family-level semantics for `show ip interface`, `show ip route`, and `show ip route summary`. The existing full v3.1 dataset was truncated at `max_nodes`, so the absence of exact help records in that dataset cannot be interpreted as unsupported capability.

The targeted probe exists specifically to close that evidence gap safely and efficiently.
