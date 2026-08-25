# CBS250 R0 Live Validation Workflow

## Purpose

This document defines the evidence workflow for expanding the Cisco CBS250 read-only inventory safely.

Current exact target:

- Product: `CBS250-24T-4X`
- Firmware: `3.5.3.3`
- Device write authority: **FALSE**
- Production network write authority: **FALSE**
- Candidate command execution authority: **FALSE**

A command appearing in discovery output, Cisco documentation, or the R0 candidate review is **not** sufficient authority to execute or automate it.

## Current priority candidates

The current planner-minimum validation order is:

1. `show vlan`
2. `show interfaces status`
3. `show interfaces switchport`

Live v3.1 context-help evidence confirms that these exact command forms exist on the target firmware. Cisco documentation also describes their display formats. However, no exact 3.5.3.3 execution output for these commands is currently retained in the project evidence set.

Therefore all three remain:

`BLOCKED_MISSING_LIVE_EXECUTION_OUTPUT`

## Evidence boundary

Raw live command output can disclose internal topology, VLAN membership, port state, management addressing, peer identity, usernames or operational details depending on the command.

Policy:

- raw output remains local by default;
- raw output is not committed to the public repository by default;
- repository evidence uses digest-only metadata;
- metadata ingestion does not prove that a capture is genuinely live;
- metadata ingestion does not promote a command into `READ_ONLY_EXEC_ALLOWLIST`;
- exact-live parser fixtures require a separate sensitivity review before they are committed;
- credentials must never appear in metadata, fixtures, comments or logs.

## Offline metadata ingestion

After an authorized operator or separately authorized validation runner has produced a raw capture file, create digest-only metadata with:

```powershell
python .\cbs250_r0_evidence_ingest.py `
  --command "show vlan" `
  --input-file "C:\path\to\local\show_vlan.txt" `
  --product-id "CBS250-24T-4X" `
  --firmware "3.5.3.3" `
  --source-label "physical-switch-controlled-validation" `
  --metadata-output "C:\path\to\local\show_vlan.metadata.json"
```

The tool does **not** connect to the switch. It only reads an existing UTF-8 text capture and produces metadata containing:

- exact target product and firmware;
- exact candidate command;
- SHA-256 of the text exactly supplied to the ingester;
- SHA-256 of LF-normalized canonical text;
- byte lengths;
- sensitivity class;
- `INGESTED_UNVERIFIED` status;
- explicit false execution/write/promotion authority flags.

The raw command output itself is not copied into the metadata record.

## Parser authority levels

`cisco_assistant/documented_output_parsers.py` currently provides parser foundations for:

- `show vlan`
- `show interfaces status`
- `show interfaces switchport`

Their authority is exactly:

`DOCUMENTED_FORMAT_ONLY`

and:

`LIVE_VALIDATED = False`

The current tests use synthetic fixtures derived from documented field structure. They do not constitute exact-firmware live evidence.

## Exact-live promotion sequence

A candidate may be promoted only in this order:

```text
reviewed candidate
    -> controlled exact-target live capture
    -> digest-only evidence ingestion
    -> sensitivity review
    -> exact-live parser fixture
    -> parser negative/regression PASS
    -> normalized current-state mapping review
    -> read-only collector registry approval
    -> exact cbs250_safety allowlist approval
    -> CI PASS on exact HEAD
```

Skipping any stage is forbidden.

## Explicit holds

### `show running-config brief`

Status: `HOLD_SENSITIVE_OUTPUT_REVIEW`

Cisco documentation states that the `brief` form omits SSL/SSH key material, but that does not prove that all credential hashes, communities, management addresses, ACL information or other sensitive configuration is absent. Do not automate, capture for repository evidence, or promote it until a dedicated redaction/sensitivity contract exists.

### `show lacp`

Status: `HOLD_REQUIRES_SELECTOR`

The exact live help for the bare command did not expose terminal `<CR>`. A deterministic interface or port-channel selector strategy must be derived from observed interfaces before automation can be reviewed.

## Secondary candidates

The following remain after planner-minimum VLAN/port state:

- `show management access-class`
- `show management access-list`
- `show spanning-tree`
- `show logging`
- `show logging file`

Management and logging output require stricter sensitivity handling. Logging evidence is classified `HIGH_OPERATIONAL` and must not be treated like ordinary low-sensitivity inventory output.

## Fail-closed rule

If exact model, exact firmware, exact command, output provenance, sensitivity status, parser behavior, or registry status is unknown, the state is `BLOCKED` or `PENDING`.

It is never promoted by inference from IOS, IOS-XE, another CBS firmware, Cisco family documentation alone, or an LLM-generated command.
