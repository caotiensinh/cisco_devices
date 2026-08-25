# Cisco Devices Automation

Tools and knowledge for discovering, understanding and automating Cisco device capabilities safely.

## CBS250 knowledge base

Cisco-official documentation and normalized live evidence live under:

```text
docs/CBS250/
knowledge/cbs250/
```

The knowledge model separates Cisco-documented semantics/resource limits, firmware caveats, exact live CLI capability, and automation risk classification.

## CBS250 CLI Capability Discovery v3.1

**Mode: `INVESTIGATION_ONLY`**

v2.1 is retired for live discovery. v3 introduced disposable SSH channels. v3.1 keeps that safety model and fixes the CBS250 help-pagination gap found in live evidence.

### Core invariant

For every context-help query:

```text
OPEN brand-new SSH shell channel
        ↓
obtain clean prompt
        ↓
type help query ending in ?
        ↓
NO Enter / NO Ctrl+C / NO pager key
        ↓
read help output
        ↓
CLOSE entire channel
```

After literal `?`, v3.1 sends **zero additional bytes** on that channel.

### Safe pagination recovery

CBS250 context help can stop at:

```text
More: <space>, Quit: q or CTRL+Z, One line: <return>
```

v3.1 never presses Space or Enter after `?`. Instead it opens new disposable channels and uses Cisco partial-keyword help:

```text
?
  → pager detected

a?
b?
c?
...
s?
...

show ?
  → pager detected

show a?
show b?
show c?
...
```

If an individual shard still paginates, the crawler refines that shard again up to `--max-shard-depth`.

### Duplicate wrapper suppression

`do` mirrors the EXEC command tree and produced a large duplicate subtree in v3. v3.1 records the `do` capability but does not recurse through it.

### Absolute execution policy

Discovered command text is data only and is never executed.

The generic executor accepts exactly:

```text
show version
show system
show ip ssh
```

State-changing/destructive execution roots are hard-denied, including:

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

### Install and safety test

```powershell
python -m pip install -r .\requirements.txt
python .\cbs250_cli_discovery.py --policy-check
python -m pytest -q
```

### One-run maximum safe discovery

```powershell
python .\cbs250_cli_discovery.py `
    --host 192.168.11.6 `
    --username admin `
    --full-safe
```

`--full-safe` performs, in one program invocation:

- privileged EXEC context-help discovery;
- automatic safe pagination sharding;
- global-configuration context-help discovery using ephemeral mode entry only;
- progress output;
- periodic checkpoints;
- SSH transport recycling/backoff to reduce channel exhaustion.

It intentionally does **not** instantiate dynamic placeholders such as arbitrary VLAN IDs, IP addresses, filenames or interface values, and it does not enter potentially state-changing configuration submodes. Therefore `full-safe` means the maximum grammar that can be investigated without granting configuration/write authority.

### Faster EXEC-only run

```powershell
python .\cbs250_cli_discovery.py `
    --host 192.168.11.6 `
    --username admin `
    --max-depth 7 `
    --max-nodes 8000
```

### Output

```text
C:\Users\<USER>\Downloads\CBS250_CLI_Discovery_v31_YYYYMMDD_HHMMSS\
├── cbs250_command_tree_v31.json
├── cbs250_capability_summary_v31.json
├── cbs250_raw_transcript_v31.txt
├── cbs250_checkpoint_v31.json                  # while running
└── cbs250_raw_transcript_v31.partial.txt       # while running
```

Each help-query audit record includes:

```json
{
  "query": "show s?",
  "bytes_sent_after_help_marker": 0,
  "channel_closed_immediately": true
}
```

## Security boundary

This repository grants the crawler **no configuration/write authority**. A future configuration engine must remain a separate component with explicit authorization, prechecks, rollback and independent safety review.
