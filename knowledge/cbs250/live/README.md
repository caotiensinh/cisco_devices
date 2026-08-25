# CBS250 Live Evidence

This directory stores normalized, model/firmware-bound knowledge derived from live Cisco CBS250 discovery runs.

## Evidence rules

- Live evidence is scoped to the exact observed model, firmware, privilege level and CLI mode.
- A discovered command is evidence of syntax exposure, not permission to execute it.
- Safety evidence and discovery completeness are stored with every dataset.
- Transport/parser failures do not prove a command is unsupported.
- Partial datasets must remain explicitly marked `PARTIAL`.
- Public repository records omit deployment identifiers such as management IPs, usernames, device MAC addresses, SSH fingerprints and active-session source addresses.
- Raw transcripts are not required in the public repository. Their SHA-256 digests may be retained in normalized records for provenance verification.

## Current datasets

- `CBS250-24T-4X_3.3.0.16_20260825_v3.json` — v3 investigation-only discovery evidence; 774 nodes, 679 help queries, safety PASS, completeness PARTIAL because root `?` output paged after the 22nd command.

The related human-readable analysis is in `docs/CBS250/live_discovery_20260825.md`.
