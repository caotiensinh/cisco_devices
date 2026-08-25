# Cisco Devices Automation

Tools and knowledge for discovering, understanding and automating Cisco device capabilities safely.

## CBS250 knowledge base

The repository now contains a Cisco-official documentation baseline for Cisco Business 250 Series Smart Switches under:

```text
docs/CBS250/
├── README.md
├── platform_and_limits.md
├── secure_operations_baseline.md
├── switching_routing_services.md
├── observability_lifecycle.md
├── automation_capability_model.md
└── official_sources.md

knowledge/cbs250/
├── observed_exec_root.json
└── platform_baseline.json
```

The knowledge model deliberately separates:

- Cisco-documented feature semantics and resource limits;
- exact firmware release caveats;
- exact live CLI capability observed from the target switch;
- automation safety/risk classification.

Start with `docs/CBS250/README.md`.

## CBS250 CLI Capability Discovery v2.1

`cbs250_cli_discovery.py` inventories the live CLI command tree exposed by Cisco CBS250/CBS350-style firmware over SSH.

The design intentionally prefers **live capability discovery** over assuming every command in a static CLI manual is supported by the exact model, firmware, privilege level, and CLI mode in use.

### Safety model

The crawler does **not execute commands it discovers**.

For context-sensitive discovery it types commands such as:

```text
show ?
show logging ?
```

without submitting the partial command with Enter. After reading the help output it sends `Ctrl+C` to cancel the line.

Automatically executed commands are limited to:

```text
terminal datadump
show version
show system
configure terminal
configure
end
```

`configure terminal` / `configure` are used only to enter global configuration mode for help discovery. The crawler does not execute discovered configuration commands.

It does not automatically execute commands such as `reload`, `delete`, `clear`, `copy`, `write`, `set`, `no`, or `shutdown`.

### Legacy CBS250 SSH compatibility

Some CBS250/CBS350 firmware exposes an `ssh-rsa` server host key and may authenticate through either SSH password authentication or keyboard-interactive authentication.

v2.1 therefore:

- keeps `ssh-rsa` host-key support available for this connection;
- does **not** enable `ssh-dss`;
- tries password authentication once;
- if needed, tries keyboard-interactive authentication once with the same password;
- does not retry indefinitely;
- distinguishes SSH negotiation failures from authentication failures.

### Requirements

- Python 3.9+
- Paramiko 3.4+

Install:

```powershell
python -m pip install -r .\requirements.txt
```

### Run

```powershell
python .\cbs250_cli_discovery.py `
    --host 192.168.11.6 `
    --username admin `
    --max-depth 7 `
    --max-nodes 4000
```

The password is requested with a hidden prompt and is not written to the output files.

### Output

By default the crawler writes to:

```text
C:\Users\<USER>\Downloads\CBS250_CLI_Discovery_YYYYMMDD_HHMMSS\
```

with:

```text
cbs250_command_tree.json
cbs250_capability_summary.json
cbs250_raw_transcript.txt
```

### Discovery limits

Default limits prevent uncontrolled recursion:

- maximum depth: `5`
- maximum nodes: `1500`

Example with larger limits:

```powershell
python .\cbs250_cli_discovery.py `
    --host 192.168.11.6 `
    --username admin `
    --max-depth 7 `
    --max-nodes 4000
```

To discover privileged EXEC mode only:

```powershell
python .\cbs250_cli_discovery.py `
    --host 192.168.11.6 `
    --username admin `
    --no-config-mode
```

## Security notes

- Do not commit device passwords or private keys.
- Prefer a dedicated read-only/least-privilege automation account where supported.
- Treat capability discovery as separate from configuration execution.
- Keep destructive and state-changing commands behind explicit policy and authorization gates.
