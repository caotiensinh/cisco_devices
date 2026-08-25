# CBS250-24T-4X Live Discovery Evidence — 2026-08-25

## Status

- Evidence source: CBS250 CLI Capability Discovery v3.0.0.
- Exact observed model: **CBS250-24T-4X**.
- Exact observed firmware: **3.3.0.16**.
- Discovery mode: privileged EXEC only.
- Global configuration discovery: **not run**.
- Safety verdict for this run: **PASS** for the v3 investigation-only contract.
- Completeness verdict: **PARTIAL**.

## Safety evidence

The run recorded 679 help queries and 774 discovered nodes. The v3 contract reports that discovered commands were not executed, help queries were not submitted with Enter, zero bytes were sent after the help marker, and each help query used a disposable SSH channel.

Only the reviewed read-only inventory commands `show ip ssh`, `show system`, and `show version` were executable by policy. State-changing/destructive roots such as `boot`, `clear`, `configure`, `copy`, `delete`, `reload`, `set`, `shutdown`, and `write` were hard-denied.

## Device facts learned from the live switch

- System description: `CBS250-24T-4X 24-Port Gigabit Smart Switch with 10G Uplinks`.
- Unit temperature during the run: **52 °C**, status **OK**.
- SSH server: enabled on TCP/22.
- SSH host key type: `ssh-rsa`, 2048 bits.
- Password authentication: enabled.
- Public-key authentication: disabled.
- SSH session logging: disabled.
- Active and alternate firmware images both report version **3.3.0.16** with MD5 `7decdf94fd5999afb7b07509896c693b`.
- The running image was marked `Inactive after reboot`, while the alternate image was marked `Active after reboot`. Treat this as an operational boot-selection observation, not a recommended configuration.

## Discovery coverage

The run found **774 nodes** via **679 help queries**, with **2 transport/query setup errors**. The observed root help returned 22 commands before the CBS pager stopped output at `more`. Earlier complete manual root help established 39 privileged EXEC root commands, so this dataset is not authoritative for root completeness.

The two recorded discovery errors were:

1. `boot system tftp://` — clean EXEC prompt was not established.
2. `boot system scp://` — SSH channel opening timed out.

These are transport/discovery setup failures; they are not evidence that the CLI branches are unsupported.

## Important parser/coverage findings

- Root `?` pagination is the primary completeness defect in v3.
- The `do` subtree duplicated approximately **388** nodes and should be represented as an EXEC wrapper rather than recursively crawled.
- The next crawler revision should preserve the zero-byte-after-`?` invariant while using safe prefix sharding to avoid pager truncation.

## Repository data policy

This repository stores reusable platform knowledge, not deployment identifiers. The normalized JSON therefore omits the management IP, administrator username, switch MAC address, SSH fingerprint, and active-session source IP. Raw source files are not committed; SHA-256 digests are stored in the normalized evidence file for provenance.

## Authority

This live dataset proves behavior observed on one CBS250-24T-4X running firmware 3.3.0.16. It complements Cisco official documentation but does not replace model/firmware-specific validation. Features not observed here remain `UNKNOWN` until supported by official documentation and/or exact live evidence.
