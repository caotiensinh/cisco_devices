# Cisco Devices Automation

Tools and knowledge for discovering, understanding and automating Cisco device capabilities safely.

## CBS250 knowledge base

Cisco-official documentation baseline:

```text
docs/CBS250/
├── README.md
├── platform_and_limits.md
├── secure_operations_baseline.md
├── switching_routing_services.md
├── observability_lifecycle.md
├── automation_capability_model.md
├── discovery_safety_v3.md
└── official_sources.md

knowledge/cbs250/
├── observed_exec_root.json
└── platform_baseline.json
```

The knowledge model separates Cisco-documented semantics/resource limits, firmware caveats, exact live CLI capability, and automation risk classification.

## CBS250 CLI Capability Discovery v3

**Mode: `INVESTIGATION_ONLY`**

v2.1 is retired for live discovery. Captured evidence showed that reuse of an interactive channel could leave partial CLI input behind and a later synchronization input could cross an execution boundary.

v3 removes that architecture.

For every context-help query:

```text
OPEN brand-new SSH shell channel
        ↓
obtain clean prompt
        ↓
type: <prefix> ?
        ↓
NO Enter
        ↓
read help output
        ↓
CLOSE entire channel
```

After literal `?`, v3 sends **zero additional bytes** on that channel. It sends no `Ctrl+C`, no Enter, no synchronization command, and no follow-up command.

### Absolute execution policy

Discovered command text is data only and is never executed.

The generic executor accepts exactly:

```text
show version
show system
show ip ssh
```

State-changing/destructive roots are hard-denied, including:

```text
boot
clear
configure
copy
crypto
delete
reload
set
no
shutdown
write
```

The deny list is implemented in `cbs250_safety.py` and covered by tests in `tests/test_safety.py`.

### Install

```powershell
python -m pip install -r .\requirements.txt
```

### Verify safety policy locally

```powershell
python .\cbs250_cli_discovery.py --policy-check
python -m pytest -q
```

### Recommended first live run

Global configuration help is disabled by default:

```powershell
python .\cbs250_cli_discovery.py `
    --host 192.168.11.6 `
    --username admin `
    --max-depth 7 `
    --max-nodes 4000
```

### Optional global configuration help

Only for contextual `?` discovery. Each query still uses a new disposable channel; no configuration command is submitted.

```powershell
python .\cbs250_cli_discovery.py `
    --host 192.168.11.6 `
    --username admin `
    --max-depth 7 `
    --max-nodes 4000 `
    --include-config-help
```

### Output

```text
C:\Users\<USER>\Downloads\CBS250_CLI_Discovery_v3_YYYYMMDD_HHMMSS\
├── cbs250_command_tree_v3.json
├── cbs250_capability_summary_v3.json
└── cbs250_raw_transcript_v3.txt
```

Each successful help query has an audit record proving:

```json
{
  "bytes_sent_after_help_marker": 0,
  "channel_closed_immediately": true
}
```

## Security boundary

This repository currently grants the crawler **no configuration/write authority**. A future configuration engine, if created, must be a separate component with explicit authorization, prechecks, rollback and independent safety review.
