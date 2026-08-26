# Self-Hosted CBS250 Targeted L3 Help Workflow

## Purpose

`.github/workflows/cbs250-targeted-l3-live.yml` is the only GitHub Actions lane for exact-target L3 context-help probing on the current production CBS250.

It is intentionally **manual-only** and does not run on push, pull request, schedule, or repository events.

## Safety boundary

The workflow:

- runs only on the Windows self-hosted runner;
- is restricted to the repository owner actor;
- uses `contents: read` GitHub permissions;
- checks out without persisted repository credentials;
- validates both discovery and targeted-help policies before any switch access;
- verifies global and production write authority remain `false`;
- executes only `show system` and `show version` for exact target binding;
- submits `show ip interface ?`, `show ip route ?`, and `show ip route summary ?` only as context-help queries without Enter;
- uploads only sanitized grammar evidence;
- never uploads the raw SSH transcript;
- removes raw local evidence from the runner temp directory with an `always()` cleanup step.

It does not authorize configuration mode, reload/reboot, firmware mutation, save/write operations, clear/delete operations, or any other device state mutation.

## Required GitHub Actions secrets

Create these repository or protected-environment secrets before running the workflow:

```text
CBS250_HOST
CBS250_USERNAME
CBS250_PASSWORD
```

Do not place these values in workflow-dispatch inputs, repository files, issue comments, chat messages, or command-line arguments.

The password is passed only through the `CBS_PASSWORD` environment variable consumed by `cbs250_targeted_help_probe.py`.

## Manual run

From GitHub:

```text
Actions
→ CBS250 Targeted L3 Help Live
→ Run workflow
```

The workflow must be run only when the current switch target is expected to be `CBS250-24T-4X / 3.5.3.3`.

If exact target binding fails, the probe stops before candidate help queries.

## Evidence handling

On `PASS_COMPLETE`, the workflow creates a sanitized artifact named:

```text
cbs250-targeted-l3-sanitized
```

The artifact contains only the sanitized JSON record produced by `cbs250_targeted_help_evidence_ingest.py`.

It does not contain the switch management address, username, password, SSH fingerprint, raw transcript, or connection metadata.

Artifact retention is limited to seven days.

## Promotion rule

A successful targeted-help run changes only grammar evidence to `OBSERVED_HELP_ONLY`.

It does **not** authorize:

```text
LIVE_EXECUTION_VALIDATED
APPROVED_COLLECTOR
READ_ONLY_EXEC_ALLOWLIST
DEVICE_WRITE_AUTHORITY
```

Any collector execution requires a separate controlled R0 live-output validation contract.
