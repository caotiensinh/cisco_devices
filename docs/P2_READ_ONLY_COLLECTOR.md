# P2 CBS250 Read-Only Collector Foundation

## Status

The repository now has the first live-device connection path for the product MVP.

It is intentionally **read-only and partial**.

Device write authority remains **FALSE**.

The only CLI commands this collector may submit are the exact commands already authorized by `cbs250_safety.py`:

```text
show system
show version
show ip ssh
```

No discovered command becomes executable merely because it exists in the CLI tree.

## Architecture

```text
User credentials (session scoped)
        |
        v
ParamikoCBS250ReadOnlySession
        |
        | exact allowlist enforcement
        | disposable shell per command
        | no config mode
        | no raw-shell API
        | no pager continuation
        v
ReadOnlyCommandResult
        |
        v
CBS250 read-only parsers
        |
        +--> DeviceFingerprint
        +--> SSH management facts
        +--> ObservedState(partial=True)
        +--> CurrentNetworkState(observed_partial)
        |
        v
Safe inventory JSON/TXT
```

The transport and parser/orchestrator layers are intentionally separate. Parsers cannot submit commands. The transport cannot bypass `assert_read_only_executable()`.

## Credential handling

`SessionCredentials` is session-scoped.

Its representation is redacted:

```text
SessionCredentials(username=<redacted>, password=<redacted>)
```

The CLI has **no password command-line option**. Password input uses `getpass`.

Safe export contains neither username nor password values.

Persistent credential storage is not implemented in this phase.

## SSH compatibility and containment

The transport preserves the live CBS250 compatibility behavior proven during discovery:

- `ssh-dss` is excluded;
- `ssh-rsa` remains available for the current device;
- password authentication is attempted first;
- keyboard-interactive password fallback is supported;
- optional SHA-256 host-key pinning is available.

Each read-only command uses a disposable shell channel.

The collector never exposes a generic shell object to callers.

## Exact allowlist rule

Every command is checked by:

```text
cbs250_safety.assert_read_only_executable
```

Policy validation happens before command network activity.

Examples that remain blocked include:

```text
clear logging
clear logging file
delete ...
reload
boot ...
copy ...
write ...
configure terminal
no ...
shutdown
```

The current collector registry is a strict subset of the authoritative allowlist.

If a future collector needs another command, the required process is:

1. prove exact syntax from Cisco documentation/live investigation;
2. classify it as `R0`;
3. confirm it has no side effect on the exact target platform/firmware;
4. add negative/safety tests;
5. explicitly extend `cbs250_safety.READ_ONLY_EXEC_ALLOWLIST`;
6. only then add the collector.

## Pager behavior

The read-only collector does **not** press Space, Enter, or another pager-navigation key when output paginates.

If `More:` or `--More--` is detected, collection fails explicitly with:

```text
pagination_detected
```

A non-paginating reviewed collection method must be designed before such a command can be automated.

This preserves the same fail-closed philosophy learned from the v2.1 discovery incident.

## Error model

The session exposes structured error categories:

```text
connection_failed
authentication_failed
host_key_mismatch
prompt_not_established
command_rejected
pagination_detected
transport_failed
```

Errors intentionally do not include supplied password values.

Collector-level failures are retained in the normalized snapshot instead of being silently hidden.

## Current normalized output

When exact model and firmware are parsed, the collector emits:

```text
DeviceFingerprint
ObservedState(partial=True)
CurrentNetworkState(basis=observed_partial)
```

`CurrentNetworkState` currently has no authoritative VLAN/port/trunk/L3 absence information because those collectors are not yet reviewed.

Therefore:

```text
complete_for_planner_scope = false
absence_is_authoritative = false
```

This is mandatory. A missing VLAN in this dataset cannot be interpreted as proof that the live switch lacks that VLAN.

## SSH management normalization

If `show ip ssh` proves the SSH server enabled, the normalized observed state can record:

```text
ssh_management = documented_and_observed
```

and current management services may include `ssh`.

Management VLAN, ACL, HTTPS, AAA and routing state remain unknown until separate exact collectors exist.

## Safe CLI entry point

The repository entry point is:

```text
cbs250_readonly_inventory.py
```

Example:

```powershell
python .\cbs250_readonly_inventory.py `
    --host 192.0.2.10 `
    --username operator
```

The password is prompted interactively.

Default local output:

```text
Downloads/
  CBS250_READONLY_INVENTORY_YYYYMMDD_HHMMSS/
    cbs250_readonly_inventory.json
    cbs250_readonly_inventory.txt
```

The files are sanitized summaries. Raw command output is not exported by this MVP collector.

## Current limitations

This foundation does not yet collect:

- running configuration;
- startup configuration;
- VLAN membership;
- interface/access/trunk state;
- L3 interfaces;
- routing;
- STP;
- LAG/LACP;
- management ACL;
- HTTPS state;
- SNMP;
- remote logging;
- time/NTP/SNTP.

Those items remain blocked on exact read-only syntax/evidence and must not be guessed from IOS/IOS-XE knowledge.

## Tests

Current tests prove at least:

- exact collector registry only uses the reviewed allowlist;
- CBS250-24T-4X / firmware parsing from representative observed-format fixtures;
- SSH management normalization;
- output remains `observed_partial`;
- missing exact identity withholds planner state instead of guessing;
- credential object representation is redacted;
- forbidden commands are rejected before transport execution;
- sanitized export omits operational MAC/hostname fixture values and raw output.

A physical-device run is still required before this parser set can be called live-validated for the P2 MVP.

## Next gate

After v3.1 live discovery completes, inspect the `show` grammar and add the next collectors one at a time, starting with the smallest read-only state needed by the planner:

```text
VLAN inventory
interface inventory/status
VLAN membership / access-trunk state
L3 interface state
management state
```

Do not expand the executable allowlist simply to accelerate development.
